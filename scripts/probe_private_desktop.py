"""Native approval and private GUI witness, disposable Linux Root coordinator only."""

import hashlib
import json
import os
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path


def seed_writer_document(path, uid):
    mime = 'application/vnd.oasis.opendocument.text'
    office = 'urn:oasis:names:tc:opendocument:xmlns:office:1.0'
    text = 'urn:oasis:names:tc:opendocument:xmlns:text:1.0'
    manifest = 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0'
    content = (
        f'<office:document-content xmlns:office="{office}" xmlns:text="{text}" '
        'office:version="1.2"><office:body><office:text>'
        '<text:p>Original private Writer document</text:p>'
        '</office:text></office:body></office:document-content>'
    )
    with zipfile.ZipFile(path, 'x') as archive:
        archive.writestr('mimetype', mime)
        archive.writestr('content.xml', content)
        archive.writestr('META-INF/manifest.xml',
            f'<manifest:manifest xmlns:manifest="{manifest}" manifest:version="1.2">'
            f'<manifest:file-entry manifest:full-path="/" manifest:media-type="{mime}"/>'
            '<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>'
            '</manifest:manifest>')
    os.chown(path, uid, -1)
    path.chmod(0o600)


def require_guest():
    """Require the protected marker and a disposable Linux VM."""
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise PermissionError('Disposable Linux Root coordinator required')
    if Path('/etc/mano-lab-disposable').read_text().strip() != 'mano-phase0-ci':
        raise PermissionError('Disposable CI marker required')
    assert subprocess.check_output(['systemd-detect-virt', '--vm'], text=True).strip() in {
        'qemu', 'kvm'}


def resolve_task_pid(statuses, namespace_pid, uid):
    """Resolve a namespace PID using independently captured kernel status fields."""
    matches = []
    for pid, source in statuses.items():
        fields = dict(line.split(':', 1) for line in source.splitlines() if ':' in line)
        identifiers = [int(value) for value in fields.get('NSpid', '').split()]
        owners = [int(value) for value in fields.get('Uid', '').split()]
        if (len(identifiers) >= 2 and identifiers[0] == pid
                and identifiers[-1] == namespace_pid and owners == [uid] * 4):
            matches.append(pid)
    if len(matches) != 1:
        raise ValueError('Expected one owned child in the private PID namespace')
    return matches[0]


def run(*, rpc, human, password, identity, task, workspace):
    """Exercise and independently verify the private desktop in the disposable VM."""
    require_guest()
    from mano_core.desktop import proposal

    value = proposal(task_id=task['task_id'], resource_id=task['resource_id'],
        key='private-desktop', reason='Approve a private agent desktop and its resource budget')
    pending = rpc('request', dict(schema_version='1.0', operation='request_approval', body=value),
                  actor=identity.name)['approval']
    assert pending['state'] == 'pending'  # Auto profile must not grant GUI authority.
    denied = dict(schema_version='1.0', ok=False, error='denied')
    unapproved = dict(schema_version='1.0', operation='propose',
                      body=value | dict(grant_id='0' * 32))
    assert rpc('request', unapproved, actor=identity.name) == denied
    view = human(dict(mode='view', id=pending['approval_id']))['view']
    assert view['args'] == value['args']
    assert human(dict(mode='confirm', view=view, password='wrong-ci-password')) == {'ok': False}
    grant = human(dict(mode='confirm', view=view, password=password))
    assert grant['ok'] is True
    opened = dict(schema_version='1.0', operation='propose',
                  body=value | dict(grant_id=grant['grant_id']))
    changed = opened | dict(body=opened['body'] | dict(args=value['args'] | dict(width=640)))
    assert rpc('request', changed, actor=identity.name) == denied
    action = rpc('request', opened, actor=identity.name)['action']['id']
    query = dict(schema_version='1.0', operation='pty_status',
                 body=dict(task_id=task['task_id'], action_id=action))
    assert rpc('request', query) == denied
    group = Path('/sys/fs/cgroup/system.slice/mano-launcher.service') / ('task-' + action)
    deadline = time.monotonic() + 8
    limits = None
    while time.monotonic() < deadline:
        try:
            limits = dict(memory_bytes=int((group / 'memory.max').read_text()),
                          pids=int((group / 'pids.max').read_text()),
                          cpu_percent=int((group / 'cpu.max').read_text().split()[0]) // 1000)
        except FileNotFoundError:
            # A startup failure can drain the cgroup before we sample it.
            # Still run the owning client below to collect the PTY failure.
            time.sleep(.1)
        else:
            break
    writer_path = workspace / 'private-writer.odt'
    seed_writer_document(writer_path, identity.uid)
    # The Task UID opens the original proposal through the real production SDK.
    result = subprocess.run(['/usr/sbin/runuser', '-u', identity.name, '--', 'env',
        'PYTHONPATH=/usr/lib/mano-os', 'PYTHONDONTWRITEBYTECODE=1', '/usr/bin/python3',
        '/opt/mano-lab/scripts/probe_private_desktop_client.py'],
        input=json.dumps(dict(proposal=value, grant_id=grant['grant_id'],
                              writer_fixture_path=str(writer_path))),
        capture_output=True, text=True, timeout=80)
    assert result.returncode == 0, (result.stdout[-8192:], result.stderr[-8192:])
    assert limits is not None, 'Desktop cgroup vanished before kernel limit evidence'
    assert limits == {key: value['args'][key] for key in limits}
    report = json.loads(result.stdout)
    assert report['action_id'] == action
    report['kernel_limits'] = limits
    assert (workspace / 'desktop-input.txt').read_bytes() == b'private-wayland-input\n'
    image_path = workspace / 'private-desktop.png'
    info = image_path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == identity.uid and info.st_nlink == 1
    image = image_path.read_bytes()
    assert hashlib.sha256(image).hexdigest() == report['screenshot']['sha256']
    assert len(image) == report['screenshot']['bytes']
    assert report['screenshot']['width'] == value['args']['width']
    assert report['screenshot']['height'] == value['args']['height']
    replay = rpc('request', opened, actor=identity.name)
    assert replay['fresh'] is False and replay['action']['id'] == report['action_id']
    group = Path('/sys/fs/cgroup/system.slice/mano-launcher.service') / (
        'task-' + report['action_id'])
    deadline = time.monotonic() + 5
    while group.exists() and time.monotonic() < deadline:
        time.sleep(.1)
    assert not group.exists(), 'Private desktop descendants did not drain'
    destination = Path('/opt/mano-lab/evidence/private-desktop.png')
    with destination.open('xb') as output:
        output.write(image)
    info = writer_path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == identity.uid and info.st_nlink == 1
    assert 0 < info.st_size <= 2 * 1024**2
    writer_bytes = writer_path.read_bytes()
    with zipfile.ZipFile(writer_path) as archive:
        with archive.open('content.xml') as source:
            content = source.read(1024**2 + 1)
    assert len(content) <= 1024**2
    tag = '{urn:oasis:names:tc:opendocument:xmlns:text:1.0}p'
    paragraphs = [''.join(node.itertext()) for node in ET.fromstring(content).iter(tag)]
    assert paragraphs == ['Original private Writer document',
                          'Saved through the private Wayland session']
    writer_image = workspace / 'private-writer.png'
    info = writer_image.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == identity.uid and info.st_nlink == 1
    assert 33 <= info.st_size <= 4 * 1024**2
    writer_image_bytes = writer_image.read_bytes()
    assert hashlib.sha256(writer_image_bytes).hexdigest() == report['writer_image']['sha256']
    evidence = destination.parent
    with (evidence / 'private-writer.png').open('xb') as output:
        output.write(writer_image_bytes)
    with (evidence / 'private-writer.odt').open('xb') as output:
        output.write(writer_bytes)
    report['writer_document'] = dict(sha256=hashlib.sha256(writer_bytes).hexdigest(),
                                     paragraphs=paragraphs)
    return report | dict(native_pam_required=True, changed_args_denied=True,
        workspace_input_independently_observed=True, screenshot_independently_hashed=True,
        replay_did_not_relaunch=True, descendants_drained=True,
        browser_implemented=False, writer_edit_independently_verified=True, full_mvp_accepted=False)


def start_for_stop(*, rpc, human, password, identity, task, workspace):
    require_guest()
    from mano_core.desktop import proposal

    value = proposal(task_id=task['task_id'], resource_id=task['resource_id'],
        key='private-desktop-stop', reason='Approve private GUI for frozen native Stop exercise')
    approval = rpc('request', dict(schema_version='1.0', operation='request_approval', body=value),
                   actor=identity.name)['approval']
    assert approval['state'] == 'pending'
    view = human(dict(mode='view', id=approval['approval_id']))['view']
    assert view['args'] == value['args']
    grant = human(dict(mode='confirm', view=view, password=password))
    assert grant['ok'] is True
    result = subprocess.run(['/usr/sbin/runuser', '-u', identity.name, '--', 'env',
        'PYTHONPATH=/usr/lib/mano-os', 'PYTHONDONTWRITEBYTECODE=1', '/usr/bin/python3',
        '/opt/mano-lab/scripts/probe_private_desktop_client.py'],
        input=json.dumps(dict(proposal=value, grant_id=grant['grant_id'], hold_for_stop=True)),
        capture_output=True, text=True, timeout=40)
    assert result.returncode == 0, (result.stdout[-8192:], result.stderr[-8192:])
    report = json.loads(result.stdout)
    assert report['held_for_native_stop'] is True
    action = report['action_id']
    from mano_protocol.actions import identifier

    identifier(action)
    group = Path('/sys/fs/cgroup/system.slice/mano-launcher.service') / ('task-' + action)
    marker = workspace / 'private-desktop-stop'
    deadline = time.monotonic() + 5
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(.1)
    info = marker.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == identity.uid and info.st_nlink == 1
    namespace_pid = int(marker.read_text())
    pids = [int(pid) for pid in (group / 'cgroup.procs').read_text().split()]
    assert len(pids) >= 6
    statuses = {pid: Path(f'/proc/{pid}/status').read_text() for pid in pids}
    detached_pid = resolve_task_pid(statuses, namespace_pid, identity.uid)
    assert os.getsid(detached_pid) == detached_pid
    processes = {str(pid): Path(f'/proc/{pid}/comm').read_text().strip() for pid in pids}
    assert 'sway' in processes.values() and 'foot' in processes.values()
    return report | dict(cgroup=str(group), pids=pids, processes=processes,
                         detached_pid=detached_pid, namespace_pid=namespace_pid,
                         detached_child_in_owned_cgroup=True,
                         native_pam_required=True, capability=value['capability'])
