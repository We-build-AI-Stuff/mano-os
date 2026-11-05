"""Native approval and private GUI witness, disposable Linux Root coordinator only."""

import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path


def require_guest():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise PermissionError('Disposable Linux Root coordinator required')
    if Path('/etc/mano-lab-disposable').read_text().strip() != 'mano-phase0-ci':
        raise PermissionError('Disposable CI marker required')
    assert subprocess.check_output(['systemd-detect-virt', '--vm'], text=True).strip() in {
        'qemu', 'kvm'}


def run(*, rpc, human, password, identity, task, workspace):
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
    while not group.exists() and time.monotonic() < deadline:
        time.sleep(.1)
    limits = dict(memory_bytes=int((group / 'memory.max').read_text()),
                  pids=int((group / 'pids.max').read_text()),
                  cpu_percent=int((group / 'cpu.max').read_text().split()[0]) // 1000)
    assert limits == {key: value['args'][key] for key in limits}
    # The Task UID opens the original proposal through the real production SDK.
    result = subprocess.run(['/usr/sbin/runuser', '-u', identity.name, '--', 'env',
        'PYTHONPATH=/usr/lib/mano-os', 'PYTHONDONTWRITEBYTECODE=1', '/usr/bin/python3',
        '/opt/mano-lab/scripts/probe_private_desktop_client.py'],
        input=json.dumps(dict(proposal=value, grant_id=grant['grant_id'])),
        capture_output=True, text=True, timeout=55)
    assert result.returncode == 0, (result.stdout[-8192:], result.stderr[-8192:])
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
    return report | dict(native_pam_required=True, changed_args_denied=True,
        workspace_input_independently_observed=True, screenshot_independently_hashed=True,
        replay_did_not_relaunch=True, descendants_drained=True,
        browser_implemented=False, writer_implemented=False, full_mvp_accepted=False)


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
    detached_pid = int(marker.read_text())
    pids = [int(pid) for pid in (group / 'cgroup.procs').read_text().split()]
    assert len(pids) >= 6 and detached_pid in pids
    assert os.getsid(detached_pid) == detached_pid
    processes = {str(pid): Path(f'/proc/{pid}/comm').read_text().strip() for pid in pids}
    assert 'sway' in processes.values() and 'foot' in processes.values()
    return report | dict(cgroup=str(group), pids=pids, processes=processes,
                         detached_pid=detached_pid, detached_child_in_owned_cgroup=True,
                         native_pam_required=True, capability=value['capability'])
