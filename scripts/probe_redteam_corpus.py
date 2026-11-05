"""Four named attack fixtures through existing native-granted paths; CI only."""

import base64
import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path('/opt/mano-lab')
FILES = {
    'AGENTS.md': 'tests/redteam/repository-instructions.txt',
    'repo_attack.py': 'tests/redteam/repo_attack.py',
    'setup.py': 'tests/redteam/setup.py',
    'pyproject.toml': 'tests/redteam/pyproject.toml',
    'postinstall.sh': 'tests/redteam/postinstall.sh',
    'attacks.py': 'tests/redteam/attacks.py',
}
CASES = ('repository-instructions', 'deceptive-dependency', 'malicious-shell')
CASE_SOURCES = {
    'repository-instructions': [FILES['AGENTS.md'], FILES['repo_attack.py']],
    'deceptive-dependency': [FILES['setup.py'], FILES['pyproject.toml']],
    'malicious-shell': [FILES['postinstall.sh']],
    'malicious-mcp': ['tests/fixtures/mcp_sdk_server.py'],
}
ATTEMPTS = {'protected-policy-write', 'private-journal-read', 'synthetic-host-secret-read',
            'human-config-write', 'network'}
PROTECTED = ('/etc/mano/human.uid', '/etc/mano/controller.json', '/etc/mano/provider.json',
            '/home/mano-human/.gemini/antigravity-cli/settings.json')
DRIVER = """import json,os,subprocess,sys
from pathlib import Path
assert sys.platform=='linux' and os.geteuid()!=0
value=json.loads(''.join(sys.argv[1:]))
root=Path('/workspace')/value['directory'];root.mkdir()
for name,source in value['files'].items():
 with (root/name).open('x') as f:f.write(source)
env=dict(os.environ,MANO_REDTEAM_CI='granted-guest-fixture',MANO_REDTEAM_CANARY=value['canary'])
commands=([sys.executable,'repo_attack.py'],[sys.executable,'setup.py','--name'],
          ['/bin/sh','postinstall.sh'])
records=[]
for argv in commands:
 p=subprocess.run(argv,cwd=root,env=env,capture_output=True,text=True,timeout=5)
 assert p.returncode==0,(argv,p.returncode,p.stdout,p.stderr)
 records.append(json.loads(p.stdout))
print(json.dumps(dict(records=records)),flush=True)
"""


def decode(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('Duplicate corpus observation key')
            value[key] = item
        return value

    def invalid_constant(_):
        raise ValueError('Nonfinite corpus observation')

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)


def read_fixture(relative):
    path = ROOT / relative
    if not path.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError('Fixture must remain inside the tracked checkout')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & 0o022):
            raise ValueError('Immutable owned regular fixture required')
        value = os.read(fd, 16385)
        if len(value) > 16384:
            raise ValueError('Oversized corpus fixture')
        return value
    finally:
        os.close(fd)


def workspace_controls(workspace, directory, uid):
    fd = os.open(workspace / directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        assert os.fstat(fd).st_uid == uid
        for case in CASES:
            marker = os.open(case + '.workspace-control', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                info = os.fstat(marker)
                assert stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
                assert os.read(marker, 64) == b'allowed workspace write\n'
            finally:
                os.close(marker)
    finally:
        os.close(fd)


def payload(files, directory, canary):
    if (set(files) != set(FILES) or not directory.startswith('redteam-')
            or len(directory) != 24 or any(c not in '0123456789abcdef' for c in directory[8:])
            or not all(isinstance(v, str) and len(v.encode()) <= 4096 for v in files.values())):
        raise ValueError('Fixed bounded corpus files and fresh directory required')
    data = json.dumps(dict(files=files, directory=directory, canary=canary), ensure_ascii=True)
    argv = ['/usr/bin/python3', '-c', DRIVER, *[data[i:i+4000] for i in range(0, len(data), 4000)]]
    if len(argv) > 16 or any(len(arg.encode()) > 4096 for arg in argv):
        raise ValueError('Corpus exceeds approved argument bounds')
    return argv


def snapshot():
    result = {}
    for name in PROTECTED:
        path = Path(name)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('Expected protected regular fixture file')
        result[name] = dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode))
    return result


def read_stdout(rpc, identity, task_id, action_id):
    query = dict(task_id=task_id, action_id=action_id)
    metadata = rpc('request', dict(schema_version='1.0', operation='terminal_output',
        body=query), actor=identity.name)['output']
    assert metadata['return_code'] == 0 and metadata['reason'] == 'completed'
    assert metadata['streams']['stderr']['size'] == 0
    assert 1 <= metadata['streams']['stdout']['size'] <= 16384
    data = bytearray()

    while len(data) < metadata['streams']['stdout']['size']:
        piece = rpc('request', dict(schema_version='1.0', operation='terminal_output_read',
            body=query | dict(stream='stdout', offset=len(data), length=4096)),
            actor=identity.name)
        assert piece['ok'] and piece['output'] == metadata
        chunk = base64.b64decode(piece['data'], validate=True)
        assert chunk and len(chunk) <= 4096
        data.extend(chunk)
        assert len(data) <= metadata['streams']['stdout']['size'] <= 16384
        assert piece['eof'] == (len(data) == metadata['streams']['stdout']['size'])
    assert hashlib.sha256(data).hexdigest() == metadata['streams']['stdout']['sha256']
    return bytes(data), metadata


def run(rpc, human, identity, password, task, workspace, mcp_records):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise PermissionError('Disposable Linux Root harness required')
    if Path('/etc/mano-lab-disposable').read_text().strip() != 'mano-phase0-ci':
        raise PermissionError('Disposable guest marker required')
    if subprocess.check_output(['systemd-detect-virt', '--vm'], text=True).strip() not in {
            'qemu', 'kvm'}:
        raise PermissionError('Disposable QEMU guest required')
    declaration = read_fixture('tests/redteam/corpus.json')
    assert len(declaration) <= 16384
    assert decode(declaration) == dict(schema_version='1.0', cases=CASE_SOURCES)
    sources = {name: read_fixture(relative).decode() for name, relative in FILES.items()}
    before = snapshot()
    mcp = mcp_records['official-sdk']
    result = mcp['result']
    assert result['untrusted'] is True and result['invocation_authorized'] is False
    assert result['status'] == 'discovered' and result['effect_verified'] is False
    assert 'run root' in result['manifest']['tools'][0]['descriptor']['description']
    assert 'readonly network and host IPC denied' in result['stderr']
    server = read_fixture('tests/fixtures/mcp_sdk_server.py')
    assert Path('/usr/lib/mano-mcp-ci/server.py').read_bytes() == server
    directory = 'redteam-' + secrets.token_hex(8)
    with tempfile.TemporaryDirectory(prefix='mano-redteam-', dir='/run') as temp:
        canary = Path(temp) / 'canary'
        secret = secrets.token_hex(32).encode()
        canary.write_bytes(secret)
        canary.chmod(0o600)
        proposed = dict(schema_version='1.0', task_id=task['task_id'],
            resource_id=task['resource_id'], capability='terminal.run',
            args=dict(argv=payload(sources, directory, str(canary)), cwd='.', timeout_seconds=20),
            idempotency_key=directory, reason='Run named untrusted attack fixtures in CI')
        pending = rpc('request', dict(schema_version='1.0', operation='request_approval',
            body=proposed), actor=identity.name)['approval']
        assert pending['state'] == 'pending'
        view = human(dict(mode='view', id=pending['approval_id']))['view']
        assert view['args'] == proposed['args']
        grant = human(dict(mode='confirm', view=view, password=password))
        assert grant['ok']
        request = proposed | dict(grant_id=grant['grant_id'])
        action = rpc('request', dict(schema_version='1.0', operation='propose', body=request),
                     actor=identity.name)
        assert action['ok'] and action['fresh']
        action_id = action['action']['id']
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            state = rpc('request', dict(schema_version='1.0', operation='status', body=dict(
                task_id=task['task_id'], action_id=action_id)), actor=identity.name)['action']
            if state['state'] in {'done', 'failed', 'unknown'}:
                break
            time.sleep(.05)
        assert state['state'] == 'done', state
        raw, metadata = read_stdout(rpc, identity, task['task_id'], action_id)
        assert secret not in raw and canary.read_bytes() == secret
        records = decode(raw)['records']
        assert len(records) == 3 and {r['case'] for r in records} == set(CASES)
        for record in records:
            assert set(record['attempts']) == ATTEMPTS
            assert all(value['blocked_or_unavailable'] is True
                       for value in record['attempts'].values())
            assert record['workspace_positive_control'] is True
            assert record['host_environment_absent'] is True
        workspace_controls(workspace, directory, identity.uid)
        group = Path('/sys/fs/cgroup/system.slice/mano-launcher.service') / ('task-' + action_id)
        assert not group.exists() or 'populated 0' in (group / 'cgroup.events').read_text()
        after = snapshot()
        assert before == after
        replay = rpc('request', dict(schema_version='1.0', operation='propose', body=request),
                     actor=identity.name)
        assert replay['fresh'] is False and replay['action']['id'] == action_id
        assert replay['action']['state'] == 'done'
        assert not group.exists() or 'populated 0' in (group / 'cgroup.events').read_text()
    return dict(scope='four named CI attack fixtures; not live-model prompt-injection testing',
        case_count=4, declared_cases=CASE_SOURCES, terminal_cases=records,
        terminal_action_id=action_id,
        task_id=task['task_id'], native_approval_id=pending['approval_id'],
        source_sha256={FILES[name]: hashlib.sha256(text.encode()).hexdigest()
                       for name, text in sources.items()} | {
                           'tests/fixtures/mcp_sdk_server.py': hashlib.sha256(server).hexdigest(),
                           'tests/redteam/corpus.json': hashlib.sha256(declaration).hexdigest()},
        mcp_case=mcp, protected_before=before, protected_after=after,
        protected_policy_and_human_config_unchanged=True, workspace_controls_observed=True,
        terminal_output=metadata,
        synthetic_host_secret_unreadable=True, replay_no_execution=True,
        task_effect_verified=False, live_model_test=False, physical_input_provenance=None)
