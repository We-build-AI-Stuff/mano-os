"""Installed-runtime OOM trial; called only by the disposable guest harness."""

import base64
import hashlib
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

GROUP = Path('/sys/fs/cgroup/system.slice/mano-launcher.service')
SERVICES = ('mano-broker.service', 'mano-launcher.service', 'mano-approve.service',
            'mano-stopd.service')


def events(raw):
    result = {}
    for line in raw.splitlines():
        key, value = line.split()
        if key in result or not value.isascii() or not value.isdigit():
            raise ValueError('Invalid kernel memory event counters')
        result[key] = int(value)
    if not {'oom', 'oom_kill'} <= result.keys():
        raise ValueError('Required kernel OOM counters absent')
    return result


def services():
    result = {}
    for unit in SERVICES:
        value = subprocess.check_output(['systemctl', 'show', unit,
            '--property=MainPID', '--property=ActiveState', '--property=NRestarts'],
            text=True)
        fields = dict(line.split('=', 1) for line in value.splitlines())
        if fields['ActiveState'] != 'active' or int(fields['MainPID']) <= 0:
            raise AssertionError('Runtime service is not active')
        # PID plus start time prevents treating PID reuse as service survival.
        pid = int(fields['MainPID'])
        start = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
        result[unit] = dict(pid=pid, start_ticks=int(start), restarts=int(fields['NRestarts']))
    return result


def run(rpc, human, identity, password, task, prompt_id):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise PermissionError('Disposable Linux Root harness required')
    if Path('/etc/mano-lab-disposable').read_text().strip() != 'mano-phase0-ci':
        raise PermissionError('Disposable guest marker required')
    if subprocess.check_output(['systemd-detect-virt', '--vm'], text=True).strip() not in {
            'kvm', 'qemu'}:
        raise PermissionError('Disposable QEMU guest required')
    if list(GROUP.glob('task-*')):
        raise AssertionError('OOM trial requires no other launcher task groups')
    before_services = services()
    before = events((GROUP / 'memory.events').read_text())
    prefix = 'oom-ci-' + secrets.token_hex(6)
    approvals = []

    def submit(program, suffix):
        proposal = dict(schema_version='1.0', task_id=task['task_id'],
            resource_id=task['resource_id'], capability='terminal.run',
            args=dict(argv=['/usr/bin/python3', '-c', program], cwd='.', timeout_seconds=30),
            idempotency_key=prefix + '-' + suffix,
            reason='Disposable CI installed-runtime OOM ' + suffix)
        pending = rpc('request', dict(schema_version='1.0', operation='request_approval',
            body=proposal), actor=identity.name)['approval']
        view = human(dict(mode='view', id=pending['approval_id']))['view']
        grant = human(dict(mode='confirm', view=view, password=password))
        assert grant['ok']
        approvals.append(pending['approval_id'])
        action = rpc('request', dict(schema_version='1.0', operation='propose',
            body=proposal | dict(grant_id=grant['grant_id'])), actor=identity.name)
        assert action['ok'] and action['fresh']
        return action['action']['id']

    def status(action_id):
        return rpc('request', dict(schema_version='1.0', operation='status', body=dict(
            task_id=task['task_id'], action_id=action_id)), actor=identity.name)['action']

    started = time.monotonic()
    # The configured task ceiling remains unchanged; the allocation occurs
    # through the production launcher, never in this Root observer process.
    oom_action = submit('a=bytearray(2*1024**3)', 'allocation')
    observed_oom = None
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        current = events((GROUP / 'memory.events').read_text())
        if current['oom_kill'] > before['oom_kill'] and observed_oom is None:
            observed_oom = time.monotonic()
        assert all(path.name == 'task-' + oom_action for path in GROUP.glob('task-*'))
        outcome = status(oom_action)
        if outcome['state'] in {'done', 'failed', 'unknown'}:
            break
        time.sleep(.02)
    assert observed_oom is not None, 'No kernel-confirmed OOM kill'
    assert outcome['state'] == 'failed', outcome
    assert not list(GROUP.glob('task-*')), 'OOM task descendants remain'
    after = events((GROUP / 'memory.events').read_text())
    assert after['oom_kill'] > before['oom_kill'] and after['oom'] > before['oom']
    assert services() == before_services
    human_status = human(dict(mode='task_status', id=prompt_id))
    assert human_status['snapshot']['prompt']['task_id'] == task['task_id']
    responsive = time.monotonic()
    nonce = secrets.token_hex(16)
    follow_action = submit('print(' + repr(nonce) + ')', 'follow-up')
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        follow = status(follow_action)
        if follow['state'] in {'done', 'failed', 'unknown'}:
            break
        time.sleep(.05)
    assert follow['state'] == 'done', follow
    output = rpc('request', dict(schema_version='1.0', operation='terminal_output', body=dict(
        task_id=task['task_id'], action_id=follow_action)), actor=identity.name)
    assert output['ok']
    metadata = output['output']
    assert metadata['return_code'] == 0
    expected_stdout = (nonce + '\n').encode()
    assert metadata['streams']['stdout']['sha256'] == hashlib.sha256(expected_stdout).hexdigest()
    assert metadata['streams']['stdout']['size'] == len(nonce) + 1
    assert metadata['streams']['stderr']['size'] == 0
    chunk = rpc('request', dict(schema_version='1.0', operation='terminal_output_read',
        body=dict(task_id=task['task_id'], action_id=follow_action,
                  stream='stdout', offset=0, length=4096)), actor=identity.name)
    assert chunk['ok'] and chunk['eof'] and chunk['output'] == metadata
    assert base64.b64decode(chunk['data'], validate=True) == (nonce + '\n').encode()
    assert services() == before_services
    finished = time.monotonic()
    return dict(scope='single approved installed-runtime task OOM in disposable VM',
        task_id=task['task_id'], oom_action_id=oom_action, follow_action_id=follow_action,
        native_pam_approval_ids=approvals, memory_events_before=before, memory_events_after=after,
        services_before=before_services, services_after=services(),
        first_kernel_oom_observed_seconds=observed_oom-started,
        broker_and_human_transport_response_seconds=responsive-observed_oom,
        approved_follow_up_complete_seconds=finished-observed_oom,
        timing='monotonic; OOM time is first observation, not exact kernel event time; '
               'follow-up includes synthetic CI PAM interaction',
        follow_up_output=metadata, follow_up_stdout=nonce + '\n',
        service_restart=False, trials=1,
        physical_hardware=False, full_human_desktop_responsiveness=None,
        model_disclosure=False)
