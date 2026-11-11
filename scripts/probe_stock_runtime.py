"""Clean-image install and real reboot witness. No product source is copied to this VM."""

import argparse
import hashlib
import json
import os
import pwd
import re
import secrets
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from ci_tty import native_terminal
from probe_poweroff_restore import PoweroffRestore

ROOT = Path("/opt/mano-lab")
OUT = ROOT / "evidence"
RUNTIME = Path("/run/mano-stock-human")
PRIVATE = Path("/root/mano-stock-private.json")
ACTOR = "lab"


def command(*argv, timeout=40, **kwargs):
    return subprocess.run(
        argv, check=True, capture_output=True, text=True, timeout=timeout, **kwargs
    )


def guard():
    assert os.geteuid() == 0
    assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
    assert command("systemd-detect-virt", "--vm").stdout.strip() in {"kvm", "qemu"}
    assert not (ROOT / "src").exists() and not Path("/usr/local/lib/mano-core").exists()


def python(program, body=None, actor=None, *, timeout=40):
    argv = [
        "env",
        "-i",
        "PATH=/usr/sbin:/usr/bin:/bin",
        "LANG=C.UTF-8",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONPATH=/usr/lib/mano-os:/usr/lib/mano-runtime/vendor",
        "/usr/bin/python3",
        "-P",
        "-c",
        program,
    ]
    if actor:
        argv = ["/usr/sbin/runuser", "-u", actor, "--", *argv]
    return json.loads(command(*argv, input=json.dumps(body), timeout=timeout).stdout)


def public(operation, body, actor):
    return python(
        """import json,sys
from mano_core.broker import BrokerClient
value=json.load(sys.stdin);client=BrokerClient()
try:print(json.dumps(client(value)))
finally:client.close()
""",
        dict(schema_version="1.0", operation=operation, body=body),
        actor,
    )


def query(mode, identifier):
    return python(
        """import json,sys
from mano_prompt.approve import rpc,view_packet
from mano_prompt.mode import read_profile_status
mode,identifier=json.load(sys.stdin)
try:result=(read_profile_status(identifier) if mode=='status' else rpc(view_packet(identifier)))
except (PermissionError,ValueError):result={'denied':True}
print(json.dumps(result))
""",
        [mode, identifier],
        ACTOR,
    )


def wait(check, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError("Fresh Debian workflow stage timed out")


def baseline():
    assert not Path("/usr/lib/mano-os").exists() and not Path("/etc/mano").exists()
    assert not Path("/usr/lib/mano-runtime").exists()
    assert not any(account.pw_name.startswith("mano-") for account in pwd.getpwall())
    os_release = Path("/etc/os-release").read_text()
    assert "ID=debian" in os_release and 'VERSION_ID="13"' in os_release
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "stock-before-packages.tsv").write_text(command("dpkg-query", "-W").stdout)
    value = dict(
        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        no_mano_accounts_config_code_or_dependencies=True,
        no_product_source_tree=True,
        human_name=ACTOR,
        human_uid=pwd.getpwnam(ACTOR).pw_uid,
    )
    assert value["human_uid"] >= 1000
    (OUT / "stock-baseline.json").write_text(json.dumps(value, indent=2) + "\n")


def gui(password, label):
    account = pwd.getpwnam(ACTOR)
    try:
        pwd.getpwnam("mano-human")
    except KeyError:
        pass
    else:
        raise AssertionError("This fresh test must not depend on a mano-human login account")
    RUNTIME.mkdir(mode=0o700)
    os.chown(RUNTIME, account.pw_uid, account.pw_gid)

    def human(*arguments):
        return [
            "/usr/sbin/runuser",
            "-u",
            ACTOR,
            "--",
            "env",
            "-i",
            "PATH=/usr/bin:/bin",
            "HOME=" + account.pw_dir,
            "LANG=C.UTF-8",
            "XDG_RUNTIME_DIR=" + str(RUNTIME),
            *arguments,
        ]

    log = (OUT / ("stock-sway-" + label + ".txt")).open("w")
    proc = subprocess.Popen(
        [
            "/usr/bin/unshare",
            "--net",
            *human(
                "WLR_BACKENDS=headless",
                "WLR_RENDERER=pixman",
                "WLR_HEADLESS_OUTPUTS=1",
                "GSK_RENDERER=cairo",
                "GSK_DEBUG=full-redraw",
                "WLR_SCENE_DEBUG_DAMAGE=rerender",
                "GDK_BACKEND=wayland",
                "GTK_A11Y=atspi",
                "dbus-run-session",
                "--",
                "sway",
                "-c",
                "/usr/share/mano-runtime/human-sway.conf",
            ),
        ],
        stdout=log,
        stderr=log,
    )
    ipc = None
    duration = 900 if label == "before" else 120
    try:
        ipc = wait(lambda: next(RUNTIME.glob("sway-ipc.*.sock"), None))
        command(
            *human(
                "SWAYSOCK=" + str(ipc),
                "swaymsg",
                "exec /usr/bin/python3 /opt/mano-lab/tests/desktop/stock_prompt_contract.py "
                + "--duration "
                + str(duration)
                + " > /run/mano-stock-human/driver.txt 2>&1",
            )
        )
        wait(lambda: (RUNTIME / "received.json").exists())
        receipt = json.loads((RUNTIME / "received.json").read_text())
        factory = command(
            "/usr/sbin/mano-task", input=json.dumps(dict(prompt_id=receipt["prompt_id"]))
        )
        managed = json.loads(factory.stdout)["task"]
        assert managed["prompt_id"] == receipt["prompt_id"]
        assert managed["context"]["prompt"] == "Clean Debian runtime reboot witness"
        (RUNTIME / "provisioned").touch()
        wait(lambda: (RUNTIME / "pending.json").exists())
        pending = json.loads((RUNTIME / "pending.json").read_text())
        assert pending["task_id"] == managed["context"]["task_id"]
        view = query("view", pending["approval_id"])["view"]
        assert view["human_uid"] == account.pw_uid and view["task_id"] == pending["task_id"]
        assert view["args"] == dict(
            mode="auto", duration_seconds=duration, max_actions=3, max_timeout_seconds=10
        )
        for answer, credential in (("n", None), ("y", "wrong-stock-ci"), ("y", password)):
            answers = ((b"Approve this exact operation?", answer),)
            if credential is not None:
                answers += ((b"OS authentication password:", credential),)
            code, output = native_terminal(
                "mano_prompt.approve", (pending["approval_id"],), actor=ACTOR, answers=answers
            )
            if credential == password:
                assert code == 0 and b"Approval recorded:" in output
            else:
                assert code == (0 if answer == "n" else 1), (
                    answer,
                    code,
                    dict(
                        permission_denied=b"Permission denied" in output,
                        permission_error=b"PermissionError" in output,
                    ),
                )
                assert query("status", receipt["prompt_id"])["profile"]["automatic"] is False
            if credential:
                assert credential.encode() not in output
        (RUNTIME / "approved").touch()
        wait(lambda: (RUNTIME / "result.json").exists())
        result = json.loads((RUNTIME / "result.json").read_text())
        assert result["unmodified_packaged_prompt"] and not result["app_observer_injected"]
        assert result["automatic_task_status_updates"] is True
        effective = query("status", receipt["prompt_id"])["profile"]
        assert effective["automatic"] and effective["remaining_actions"] == 3
        assert effective["mode"] == "auto" and 0 < effective["seconds_remaining"] <= duration
        result["native_effective_status"] = effective
        result["artifact_sha256"] = {}
        for name in ("stock-permissions-pending.png", "stock-permissions-effective.png"):
            data = (RUNTIME / name).read_bytes()
            target = label + "-" + name
            (OUT / target).write_bytes(data)
            result["artifact_sha256"][target] = hashlib.sha256(data).hexdigest()
        (OUT / ("stock-gui-" + label + ".json")).write_text(json.dumps(result, indent=2) + "\n")
        return managed, result
    finally:
        if ipc is not None and proc.poll() is None:
            subprocess.run(
                human("SWAYSOCK=" + str(ipc), "swaymsg", "exit"),
                check=False,
                capture_output=True,
                timeout=10,
            )
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        log.close()
        if (RUNTIME / "driver.txt").exists():
            text = (RUNTIME / "driver.txt").read_text()
            (OUT / ("stock-driver-" + label + ".txt")).write_text(text)
            if text:
                print(text, file=sys.stderr)


def mock_effect(managed, filename):
    fixture = ""
    if filename == "before-reboot":
        fixture = (
            ";Path('/workspace/nested').mkdir();"
            "Path('/workspace/nested/binary').write_bytes(bytes([0,255,1])+b'poweroff'+bytes([0]));"
            "Path('/workspace/run.sh').write_bytes(b'#!/bin/sh\\necho saved-source\\n');"
            "Path('/workspace/run.sh').chmod(0o755)"
        )
    packet = dict(
        prompt_id=managed["prompt_id"],
        plan=dict(
            args=dict(
                argv=[
                    "/usr/bin/python3",
                    "-c",
                    "import sys;print('stock-console');sys.stderr.write('stock-note');"
                    "from pathlib import Path;"
                    + "Path('/workspace/"
                    + filename
                    + "').write_text('stock-ok')" + fixture,
                ],
                cwd=".",
                timeout_seconds=2,
            ),
            reason="Explicit fresh Debian mock witness",
        ),
    )
    deadline = time.monotonic() + 30
    while True:
        result = json.loads(
            command("/usr/sbin/mano-core-step", "--mock", input=json.dumps(packet)).stdout
        )["task"]
        if result["status"] == "verifying":
            break
        assert result["status"] in {"queued", "running"} and time.monotonic() < deadline, result
        time.sleep(0.1)
    assert (Path(managed["workspace"]) / filename).read_text() == "stock-ok"
    output = result["terminal_output"]
    assert output["return_code"] == 0 and output["reason"] == "completed"
    assert output["effect_verified"] is False and output["output_limit_reached"] is False
    for stream, expected in (("stdout", b"stock-console\n"), ("stderr", b"stock-note")):
        assert output["streams"][stream] == dict(
            size=len(expected), sha256=hashlib.sha256(expected).hexdigest())
    (OUT / ("stock-terminal-output-" + filename + ".json")).write_text(
        json.dumps(dict(output=output, metadata_only=True, provider_disclosure=False),
                   indent=2) + "\n")
    read_context = managed | dict(context=managed["context"] | dict(
        operation_key="typed-read-" + filename))
    read_packet = dict(managed=read_context, plan=dict(capability="files.read",
        args=dict(path=filename), reason="Read the packaged mock result as a typed action"))
    deadline = time.monotonic() + 30
    while True:
        read = json.loads(command("/usr/sbin/mano-core-step", "--mock",
                                 input=json.dumps(read_packet)).stdout)["task"]
        if read["status"] == "read_ready":
            break
        assert read["status"] in {"queued", "running"} and time.monotonic() < deadline, read
    assert read["read_result"]["sha256"] == hashlib.sha256(b"stock-ok").hexdigest()
    assert read["read_result"]["size"] == len(b"stock-ok")
    assert read["read_result"]["effect_verified"] is False
    assert "stock-ok" not in json.dumps(read)
    replay = json.loads(command("/usr/sbin/mano-core-step", "--mock",
                                input=json.dumps(read_packet)).stdout)["task"]
    assert replay["status"] == "read_ready" and replay["action_id"] == read["action_id"]
    assert replay["read_result"] == read["read_result"]
    (OUT / ("stock-typed-read-" + filename + ".json")).write_text(
        json.dumps(dict(status="read_ready", artifact=read["read_result"],
            replay_no_execution=True, provider_disclosure=False,
            scope="packaged core CLI/native broker/PAM-approved profile on stock Debian"),
            indent=2) + "\n")
    return result


def packaged_private_desktop(managed, password, label, boot, approvals):
    """Exercise the installed worker through the real approval and Task UID paths."""
    worker = Path('/usr/lib/mano-desktop/session.py')
    protocol = worker.with_name('protocol.py')
    installed = {}
    for path in (worker, protocol):
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
        assert command('dpkg-query', '-S', str(path)).stdout.strip() == f'mano-runtime: {path}'
        installed[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    actor = managed['caller_name']
    proposed = python(
        """import json,sys
from mano_core.desktop import proposal
context=json.load(sys.stdin)
print(json.dumps(proposal(task_id=context['task_id'],resource_id=context['resource_id'],
 key='stock-private-desktop',reason='Exercise the packaged private desktop')))
""", managed['context'], actor)
    grant, view = approvals.approval(managed, proposed, password)
    assert view['boot_id'] == boot
    result = command('/usr/sbin/runuser', '-u', actor, '--', 'env', '-i',
        'PATH=/usr/bin:/bin', 'LANG=C.UTF-8', 'PYTHONPATH=/usr/lib/mano-os',
        'PYTHONDONTWRITEBYTECODE=1', '/usr/bin/python3', '-P',
        str(ROOT / 'scripts/probe_private_desktop_client.py'),
        input=json.dumps(dict(proposal=proposed, grant_id=grant)), timeout=60)
    report = json.loads(result.stdout)
    action = report['action_id']
    assert re.fullmatch(r'[0-9a-f]{32}', action)
    workspace = Path(managed['workspace'])
    uid = pwd.getpwnam(actor).pw_uid
    paths = (workspace / 'desktop-input.txt', workspace / 'private-desktop.png')
    for path, maximum in zip(paths, (64, 4 * 1024**2), strict=True):
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
        assert 0 < info.st_size <= maximum
    assert paths[0].read_bytes() == b'private-wayland-input\n'
    image = paths[1].read_bytes()
    assert image.startswith(b'\x89PNG\r\n\x1a\n')
    assert len(image) == report['screenshot']['bytes']
    assert hashlib.sha256(image).hexdigest() == report['screenshot']['sha256']
    group = Path('/sys/fs/cgroup/system.slice/mano-launcher.service') / ('task-' + action)
    wait(lambda: not group.exists(), timeout=8)
    target = 'stock-private-desktop-' + label
    (OUT / (target + '.png')).write_bytes(image)
    report.update(boot_id=boot, installed_worker_hashes=installed,
                  input_independently_verified=True, descendants_drained=True,
                  native_tty_pam=True, package_owned_worker=True)
    (OUT / (target + '.json')).write_text(json.dumps(report, indent=2) + '\n')
    return report


def build_private_website(managed, password, boot, approvals):
    """Build and test a static site with separate approved terminal actions."""
    actor = managed['caller_name']
    context = managed['context']
    workspace = Path(managed['workspace'])
    document = workspace / 'private-browser.html'
    build = """from html import escape
from pathlib import Path
title = escape('mano private Chromium')
page = f'<!doctype html><html><head><title>{title}</title></head><body>'
page += '<button onclick="this.nextElementSibling.textContent=42">Verify</button>'
page += '<p data-testid="result">waiting</p></body></html>'
with Path('private-browser.html').open('x') as stream:
    stream.write(page)
print('website built')
"""
    test = """from html.parser import HTMLParser
from pathlib import Path
class Site(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements = {}
    def handle_starttag(self, tag, attrs):
        self.elements[tag] = dict(attrs)
site = Site()
site.feed(Path('private-browser.html').read_text())
assert site.elements['p']['data-testid'] == 'result'
assert 'onclick' in site.elements['button']
assert {'html', 'head', 'title', 'body'} <= site.elements.keys()
print('website tests passed')
"""
    assert not document.exists()
    actions = {}
    for step, program, marker in (('build', build, 'website built'),
                                  ('test', test, 'website tests passed')):
        # Exceed this fixture's Auto profile limit to exercise exact native approval.
        proposal = dict(schema_version='1.0', task_id=context['task_id'],
                        resource_id=context['resource_id'], capability='terminal.run',
                        args=dict(argv=['/usr/bin/python3', '-I', '-c', program],
                                  cwd='.', timeout_seconds=15),
                        idempotency_key='stock-private-site-' + step,
                        reason=step.capitalize() + ' the private browser website')
        grant, view = approvals.approval(managed, proposal, password)
        assert view['boot_id'] == boot
        response = public('propose', proposal | dict(grant_id=grant), actor)
        assert response['ok'] and response['fresh']
        action_id = response['action']['id']
        result = python(
            """import json,sys,time
from mano_core.broker import BrokerClient,read_terminal_output
body=json.load(sys.stdin)
client=BrokerClient()
try:
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        action=client(dict(schema_version='1.0',operation='status',body=body))['action']
        if action['state'] in {'done','failed','unknown'}:
            break
        time.sleep(.15)
    assert action['state']=='done',action
    output=read_terminal_output(client,**body)
    print(json.dumps(dict(metadata=output['metadata'],stdout=output['stdout'].decode())))
finally:
    client.close()
""", dict(task_id=context['task_id'], action_id=action_id), actor)
        assert result['stdout'] == marker + '\n'
        assert result['metadata']['return_code'] == 0
        actions[step] = dict(action_id=action_id, output=result['metadata'])
    return dict(actions=actions, html_sha256=hashlib.sha256(document.read_bytes()).hexdigest())


def packaged_private_browser(managed, password, boot, approvals):
    """Exercise the approved browser through the installed runtime and Task UID."""
    actor = managed['caller_name']
    workspace = Path(managed['workspace'])
    site = build_private_website(managed, password, boot, approvals)
    proposed = python(
        """import json,sys
from mano_core.desktop import proposal
context=json.load(sys.stdin)
print(json.dumps(proposal(task_id=context['task_id'],resource_id=context['resource_id'],
 key='stock-private-browser',reason='Verify the workspace page in the private browser',
 browser_path='private-browser.html')))
""", managed['context'], actor)
    grant, view = approvals.approval(managed, proposed, password)
    assert view['boot_id'] == boot
    assert view['args']['browser_path'] == 'private-browser.html'
    changed = proposed | dict(grant_id=grant, args=proposed['args'] |
                              dict(browser_path='different.html'))
    assert public('propose', changed, actor)['ok'] is False
    report = python(
        """import json,sys,time
from mano_core.broker import BrokerClient
from mano_core.desktop import DesktopSession
proposal,grant=json.load(sys.stdin)
desktop=DesktopSession.open(BrokerClient(), proposal=proposal, grant_id=grant)
try:
    desktop.wait_ready(timeout=40)
    deadline=time.monotonic()+8
    while time.monotonic()<deadline:
        status=desktop.command('status')['result']
        if any('chromium' in w['app_id'].lower() and 'mano private Chromium' in w['title']
               for w in status['windows']):
            break
        time.sleep(.2)
    else:
        raise AssertionError('Chromium window was not mapped')
    browser=status['browser']
    assert browser['renderer_filters_verified'] is True and browser['local_pipe'] is True
    assert browser['renderer_filter_counts'] and all(
        count>browser['browser_filter_count'] for count in browser['renderer_filter_counts'])
    assert desktop.command('browser_text', test_id='result')['result']['text']=='waiting'
    desktop.command('browser_click', name='Verify')
    assert desktop.command('browser_text', test_id='result')['result']['text']=='42'
    image=desktop.command('screenshot', path='private-browser.png')['result']
    desktop.command('close')
    print(json.dumps(dict(action_id=desktop.transport.action_id, status=status,
                          locator_text='42', screenshot=image)))
finally:
    if not desktop.closed:
        desktop.stop()
""", [proposed, grant], actor, timeout=70)
    image = workspace / 'private-browser.png'
    info = image.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == pwd.getpwnam(actor).pw_uid
    assert info.st_nlink == 1 and 33 <= info.st_size <= 4 * 1024**2
    pixels = image.read_bytes()
    assert pixels.startswith(b'\x89PNG\r\n\x1a\n')
    assert hashlib.sha256(pixels).hexdigest() == report['screenshot']['sha256']
    assert re.fullmatch(r'[0-9a-f]{32}', report['action_id'])
    launcher = Path('/sys/fs/cgroup/system.slice/mano-launcher.service')
    group = launcher / ('task-' + report['action_id'])
    wait(lambda: not group.exists(), timeout=8)
    assert hashlib.sha256((workspace / 'private-browser.html').read_bytes()).hexdigest() == (
        site['html_sha256'])
    report.update(website=site, changed_page_denied=True, descendants_drained=True)
    report['summary'] = 'Built and tested the website, then verified its button in Chromium.'
    (OUT / 'stock-private-browser.png').write_bytes(pixels)
    (OUT / 'stock-private-browser.json').write_text(json.dumps(report, indent=2) + '\n')


def phase(after_reboot):
    if not after_reboot:
        denied_code, denied_output = native_terminal("mano_runtime.recovery", ("create",))
        assert denied_code != 0 and b"btrfs subvolume required" in denied_output, denied_output
        assert not Path("/.snapshots/.mano-package-recovery").exists()
        (OUT / "stock-root-recovery-denial.json").write_text(
            json.dumps(
                dict(
                    installed_cli=True,
                    native_root_tty=True,
                    unsupported_ext4_denied=True,
                    no_snapshot_created=True,
                ),
                indent=2,
            )
            + "\n"
        )
    original = json.loads((OUT / "stock-baseline.json").read_text())
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    assert original["human_uid"] == pwd.getpwnam(ACTOR).pw_uid
    assert Path("/etc/mano/human.uid").read_text() == str(original["human_uid"]) + "\n"
    command("systemctl", "is-enabled", "--quiet", "mano-runtime.target")
    for unit in ("mano-runtime.target", "mano-stopd.service"):
        wait(
            lambda unit=unit: subprocess.run(
                ["systemctl", "is-active", "--quiet", unit], check=False, timeout=5
            ).returncode
            == 0
        )
    for name in ("provider", "pricing", "controller", "egress"):
        assert json.loads(Path("/etc/mano/" + name + ".json").read_text())["enabled"] is False
    assert not Path("/etc/mano/credentials/openai").exists()
    if after_reboot:
        assert boot != original["boot_id"]
        info = PRIVATE.stat()
        assert info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
        previous = json.loads(PRIVATE.read_text())
        assert query("status", previous["managed"]["prompt_id"]) == dict(denied=True)
        replay = public(
            "propose",
            previous["proposal"] | {"grant_id": previous["grant_id"]},
            previous["managed"]["caller_name"],
        )
        assert replay["ok"] is False
        with sqlite3.connect(
            "file:/var/lib/mano-broker/runtime/state.sqlite3?mode=ro", uri=True
        ) as database:
            row = database.execute(
                "SELECT expires,revoked,used FROM grants WHERE id=?", (previous["grant_id"],)
            ).fetchone()
        assert row[0] > time.monotonic() and row[1:] == (1, 0)
        assert (Path(previous["managed"]["workspace"]) / "before-reboot").read_text() == "stock-ok"
    else:
        assert boot == original["boot_id"] and not PRIVATE.exists()
    password = secrets.token_hex(24)
    command("chpasswd", input=ACTOR + ":" + password + "\n")
    try:
        managed, result = gui(password, "after" if after_reboot else "before")
        mock_effect(managed, "after-reboot" if after_reboot else "before-reboot")
        restoration = PoweroffRestore(python, public, query, ACTOR)
        from probe_package_plans import CLIENT as package_client

        proposed_package = python(
            """import json,sys
from mano_core.broker import BrokerClient
from mano_core.packages import catalog,proposal
managed=json.load(sys.stdin);client=BrokerClient()
try:
 context=managed['context'];observed=catalog(client,task_id=context['task_id'],
  resource_id=context['resource_id'])
 value=proposal(task_id=context['task_id'],resource_id=context['resource_id'],names=['sl'],
  catalog_id=observed['catalog_id'],key='stock-package-preview',
  reason='Preview only; no installation')
 print(json.dumps(value))
finally:client.close()
""", managed, managed['caller_name'])
        package_grant,package_view = restoration.approval(managed,proposed_package,password)
        assert package_view['package_scope']['installation_authorized'] is False
        status_before = hashlib.sha256(Path('/var/lib/dpkg/status').read_bytes()).hexdigest()
        package_result = python(package_client,
                                dict(proposal=proposed_package,grant_id=package_grant),
                                managed['caller_name'],timeout=75)
        assert package_result['state'] == 'done'
        assert package_result['result']['plan']['install_authorized'] is False
        root_resolution_denial = python("""import json,sys
from mano_runtime.package_resolution import current_plan
plan=json.load(sys.stdin)
try:
 with current_plan(plan):raise AssertionError('Unsupported Root layout admitted')
except ValueError as error:
 assert 'btrfs' in str(error)
 print(json.dumps(dict(installed_module=True,unsupported_ext4_denied=True)))
""", package_result['result']['plan'])
        non_root_resolution_denial = python("""import json,sys
from mano_runtime.package_resolution import current_plan
plan=json.load(sys.stdin)
try:
 with current_plan(plan):raise AssertionError('Unprivileged Root resolution admitted')
except PermissionError:
 print(json.dumps(dict(non_root_denied=True)))
""", package_result['result']['plan'], managed['caller_name'])
        assert root_resolution_denial['unsupported_ext4_denied'] is True
        assert non_root_resolution_denial['non_root_denied'] is True
        status_after = hashlib.sha256(Path('/var/lib/dpkg/status').read_bytes()).hexdigest()
        assert status_after == status_before
        label = 'after' if after_reboot else 'before'
        (OUT/('stock-package-plan-'+label+'.json')).write_text(json.dumps(dict(
            result=package_result,actual_native_tty_pam=True,dpkg_state_unchanged=True,
            install_authorized=False,model_disclosure=False,
            root_resolution_denial=root_resolution_denial,
            non_root_resolution_denial=non_root_resolution_denial),indent=2)+'\n')
        package_context = managed|dict(context=managed['context']|dict(
            operation_key='typed-package-'+label))
        package_packet = dict(managed=package_context,plan=dict(capability='packages.plan_install',
            args=proposed_package['args'],reason='Preview package changes through typed core'))
        queued_package = json.loads(command('/usr/sbin/mano-core-step','--mock',
            input=json.dumps(package_packet)).stdout)['task']
        assert queued_package['status'] == 'awaiting_grant'
        expected_package = queued_package['proposal']
        typed_grant,_ = restoration.approval(managed,expected_package,password)
        assert typed_grant  # Consumed only by the core's original exact proposal.
        deadline = time.monotonic()+75
        while time.monotonic()<deadline:
            typed_package = json.loads(command('/usr/sbin/mano-core-step','--mock',
                input=json.dumps(package_packet)).stdout)['task']
            if typed_package['status'] == 'package_plan_ready':
                break
            assert typed_package['status'] in {'queued','running'},typed_package
            time.sleep(.12)
        assert typed_package['status'] == 'package_plan_ready'
        receipt = typed_package['package_result']
        assert receipt['names'] == ['sl'] and receipt['install_authorized'] is False
        assert receipt['effect_verified'] is False
        assert receipt['sha256'] == package_result['result']['sha256']
        typed_status = hashlib.sha256(Path('/var/lib/dpkg/status').read_bytes()).hexdigest()
        assert typed_status == status_before
        (OUT/('stock-typed-package-'+label+'.json')).write_text(json.dumps(dict(
            status=typed_package['status'],receipt=receipt,dpkg_state_unchanged=True,
            live_model_connected=False),indent=2)+'\n')
        if not after_reboot:
            saved_source = restoration.before(managed, password)
            packaged_private_desktop(managed, password, label, boot, restoration)
            packaged_private_browser(managed, password, boot, restoration)
            proposal = dict(
                schema_version="1.0",
                task_id=managed["context"]["task_id"],
                resource_id=managed["context"]["resource_id"],
                capability="files.read",
                args=dict(path="before-reboot"),
                idempotency_key="unused-before-real-reboot",
                reason="Synthetic unused exact grant before real boot change",
            )
            approved = public("request_approval", proposal, managed["caller_name"])["approval"]
            assert approved["state"] == "approved"
            with sqlite3.connect(
                "file:/var/lib/mano-broker/runtime/state.sqlite3?mode=ro", uri=True
            ) as database:
                row = database.execute(
                    "SELECT expires,revoked,used FROM grants WHERE id=?", (approved["grant_id"],)
                ).fetchone()
            assert row[0] > time.monotonic() and row[1:] == (0, 0)
            fd = os.open(PRIVATE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump(
                    dict(managed=managed, proposal=proposal, grant_id=approved["grant_id"],
                         source_restore=saved_source), stream
                )
                stream.flush()
                os.fsync(stream.fileno())
        else:
            recovered_source = restoration.after(previous, managed, password)
            after_desktop = packaged_private_desktop(managed, password, label, boot, restoration)
            before_desktop = json.loads((OUT / 'stock-private-desktop-before.json').read_text())
            assert before_desktop['boot_id'] == original['boot_id']
            assert (before_desktop['installed_worker_hashes']
                    == after_desktop['installed_worker_hashes'])
            assert before_desktop['action_id'] != after_desktop['action_id']
            from probe_root_package_stop import human_client
            from probe_root_package_stop import run as stop_root_package

            def installed_stop_snapshot():
                value = python('''import json
from mano_protocol.stop_state import snapshot
value=snapshot()
print(json.dumps(dict(generation=value.generation,latched=value.latched)))
''')
                return SimpleNamespace(**value)

            root_stop = stop_root_package(human_client(ACTOR), password,
                int(command('systemctl', 'show', 'mano-broker.service',
                            '--property=MainPID', '--value').stdout),
                int(command('systemctl', 'show', 'mano-launcher.service',
                            '--property=MainPID', '--value').stdout),
                Path('/usr/libexec/mano-stop'), actor=ACTOR, snapshot=installed_stop_snapshot)
            stopped = command("/usr/sbin/runuser", "-u", ACTOR, "--", "/usr/libexec/mano-stop")
            assert "Emergency Stop acknowledged" in stopped.stdout
            assert Path("/var/lib/mano-stopd/state").read_text().endswith(":latched\n")
            report = dict(
                schema_version="1.0",
                root_package_stop=root_stop,
                boot_id_before=original["boot_id"],
                boot_id_after=boot,
                pristine_baseline=original,
                runtime_started_on_boot_without_setup=True,
                generic_login_without_mano_human_account=True,
                unmodified_packaged_gui_before_and_after_boot=True,
                package_owned_private_desktop_before_and_after_boot=True,
                app_observer_injected=False,
                native_pam_before_and_after_boot=True,
                package_owned_mock_effect_before_and_after_boot=True,
                package_owned_typed_core_read_before_and_after_boot=True,
                package_owned_terminal_output_before_and_after_boot=True,
                effect_verified=False,
                unexpired_unused_old_grant_revoked_after_real_boot=True,
                old_grant_replay_denied=True,
                previous_workspace_data_preserved=True,
                configured_human_native_stop=True,
                defaults_disabled_no_key=True,
                external_source_tree_or_lab_environment_copied=False,
                paid_model_execution=False,
                physical_input_provenance=None,
                gui_start_mode="manual headless user session; no physical/display-manager test",
                rendering_profile="headless pixman / GTK cairo; full-frame redraw",
                incremental_software_redraw_visual_acceptance=False,
                source_restoration=recovered_source,
                package_plan_native_pam_before_and_after_boot=True,
            )
            (OUT / "stock-runtime-reboot.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report))
    finally:
        command("usermod", "--lock", ACTOR)


def main():
    guard()
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("baseline", "before", "after"))
    args = parser.parse_args()
    if args.phase == "baseline":
        baseline()
    else:
        phase(args.phase == "after")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print((error.stdout or "")[-8000:], file=sys.stderr)
        print((error.stderr or "")[-8000:], file=sys.stderr)
        raise
