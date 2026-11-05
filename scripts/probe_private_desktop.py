"""Native approval and private GUI witness, disposable Linux Root coordinator only."""

import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path


def run(*, rpc, human, password, identity, task, workspace):
    """Exercise and independently verify the private desktop in the disposable VM."""
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise PermissionError('Disposable Linux Root coordinator required')
    if Path('/etc/mano-lab-disposable').read_text().strip() != 'mano-phase0-ci':
        raise PermissionError('Disposable CI marker required')
    assert subprocess.check_output(['systemd-detect-virt', '--vm'], text=True).strip() in {
        'qemu', 'kvm'}
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
    # The Task UID opens the original proposal through the real production SDK.
    result = subprocess.run(['/usr/sbin/runuser', '-u', identity.name, '--', 'env',
        'PYTHONPATH=/usr/lib/mano-os', 'PYTHONDONTWRITEBYTECODE=1', '/usr/bin/python3',
        '/opt/mano-lab/scripts/probe_private_desktop_client.py'],
        input=json.dumps(dict(proposal=value, grant_id=grant['grant_id'])),
        capture_output=True, text=True, timeout=55)
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
    return report | dict(native_pam_required=True, changed_args_denied=True,
        workspace_input_independently_observed=True, screenshot_independently_hashed=True,
        replay_did_not_relaunch=True, descendants_drained=True,
        browser_implemented=False, writer_implemented=False, full_mvp_accepted=False)
