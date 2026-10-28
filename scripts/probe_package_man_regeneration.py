"""Fixed fresh-cache experiment for disposable CI, never publication authority.

The controller supplies a read-only baseline, a drained candidate manual tree,
and a fresh size-limited private tmpfs. Only baseline executables/configuration
run; the parser runs as man with no capabilities. Retain failures before checks.
"""
import ast
import base64
import hashlib
import json
import re
import sys
import time
from pathlib import Path

HEADER = '''import base64,ctypes,errno,hashlib,json,os,selectors,subprocess,sys,time
from pathlib import Path
'''
BODY = r'''
verify_no_inherited_fds()
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines())
state=dict(uid=list(os.getresuid()),gid=list(os.getresgid()),groups=sorted(os.getgroups()),
    caps={k:int(status[k].strip(),16) for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')},
    nnp=int(status['NoNewPrivs']),
    namespaces={k:os.readlink('/proc/self/ns/'+k) for k in
                ('mnt','pid','net','ipc','uts','cgroup')})
assert state['uid']==[6]*3 and state['gid']==[12]*3
assert 0 not in state['groups'] and set(state['groups'])<={12}
assert state['nnp']==1 and set(state['caps'].values())=={0}
assert len(sys.argv)==2 and len(sys.argv[1])==64
config=Path('/etc/manpath.config').read_bytes()
assert len(config)<=65536 and hashlib.sha256(config).hexdigest()==sys.argv[1]
assert list(Path('/var/cache/man').iterdir())==[]
env={'PATH':'/usr/sbin:/usr/bin:/bin','LANG':'C.UTF-8','TZ':'UTC0',
     'PYTHONDONTWRITEBYTECODE':'1','HOME':'/nonexistent'}
result=run_observed(['/usr/bin/mandb','--create','--quiet','/usr/share/man'],env,60)
print(json.dumps(dict(state=state,config_sha256=hashlib.sha256(config).hexdigest(),
    initial_cache_empty=True,result=result)))
'''


def program(capture_source):
    tree = ast.parse(capture_source)
    capture = next(node for node in tree.body
                   if isinstance(node, ast.FunctionDef) and node.name == 'run_observed')
    fd_guard = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef)
                    and node.name == 'verify_no_inherited_fds')
    data = (HEADER + ast.get_source_segment(capture_source, fd_guard) + '\n'
            + ast.get_source_segment(capture_source, capture) + '\n' + BODY)
    compile(data, 'man-regeneration-ci-worker', 'exec')
    return data.encode()


def config_profile(raw):
    """Check the fixed target mapping; retain all config bytes separately."""
    if type(raw) is not bytes or not 0 < len(raw) <= 65536 or b'\0' in raw:
        raise ValueError('Bounded baseline manpath configuration required')
    mappings = []
    for line in raw.decode('utf8').splitlines():
        fields = line.split('#', 1)[0].split()
        if not fields or fields[0] != 'MANDB_MAP':
            continue
        if len(fields) != 3:
            raise ValueError('Explicit manpath mapping required')
        source, target = fields[1:]
        if source == '/usr/share/man' or source.startswith('/usr/share/man/'):
            mappings.append((source, target))
    if mappings != [('/usr/share/man', '/var/cache/man')]:
        raise ValueError('Unique fixed manual-root to private-cache mapping required')
    return hashlib.sha256(raw).hexdigest()


def sandbox(base, state_masks, empty, config_sha256):
    if re.fullmatch('[a-f0-9]{64}', config_sha256) is None:
        raise ValueError('Configuration digest required')
    return ['/usr/bin/bwrap', '--die-with-parent', '--new-session', '--unshare-pid',
            '--unshare-net', '--unshare-ipc', '--unshare-uts', '--unshare-cgroup',
            '--ro-bind', str(base / 'baseline'), '/',
            '--ro-bind', str(base / 'candidate/usr/share/man'), '/usr/share/man',
            '--bind', str(base / 'regenerated-man-cache'), '/var/cache/man',
            '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/run', '--tmpfs', '/tmp', '--tmpfs', '/home', '--tmpfs', '/root',
            '--tmpfs', '/opt', '--tmpfs', '/mnt', '--tmpfs', '/media', '--tmpfs', '/srv',
            *[arg for path in state_masks for arg in ('--tmpfs', path)],
            '--tmpfs', '/.snapshots',
            '--ro-bind', str(base / 'man-regeneration.py'), '/run/man-regeneration.py',
            '--ro-bind', str(empty), '/etc/shadow', '--ro-bind', str(empty), '/etc/gshadow',
            '--clearenv', '--setenv', 'PATH', '/usr/sbin:/usr/bin:/bin',
            '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC0',
            '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
            '--cap-drop', 'ALL', '--cap-add', 'CAP_SETUID', '--cap-add', 'CAP_SETGID',
            '--cap-add', 'CAP_SETPCAP', '--chdir', '/',
            '/usr/bin/setpriv', '--no-new-privs', '--reuid', '6', '--regid', '12',
            '--clear-groups', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
            '/usr/bin/python3', '-I', '-B', '/run/man-regeneration.py', config_sha256]


def validate(row, host, config_sha256):
    state = row['state']
    for key in ('uid', 'gid', 'groups'):
        if type(state[key]) is not list or any(type(v) is not int for v in state[key]):
            raise ValueError('Exact numeric credentials required')
    if (state['uid'] != [6]*3 or state['gid'] != [12]*3
            or state['groups'] != sorted(set(state['groups']))
            or not set(state['groups']) <= {12}
            or type(state['nnp']) is not int or state['nnp'] != 1
            or set(state['caps']) != {'CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb'}
            or any(type(v) is not int or v != 0 for v in state['caps'].values())
            or set(state['namespaces']) != set(host)
            or any(not isinstance(v, str) or v == host[k]
                   for k, v in state['namespaces'].items())
            or row['domain_drained'] is not True or row['initial_cache_empty'] is not True
            or row['config_sha256'] != config_sha256):
        raise ValueError('Drained private capability-free man regeneration required')
    result = row['result']
    if (type(result['returncode']) is not int or result['returncode'] != 0
            or result['capture_complete'] is not True):
        raise ValueError('Fresh mandb must finish within output/time bounds')
    for label in ('stdout', 'stderr'):
        field = result[label]
        if type(field['base64']) is not str or len(field['base64']) > 87384:
            raise ValueError('Bounded regeneration diagnostic required')
        raw = base64.b64decode(field['base64'], validate=True)
        if (len(raw) > 65536 or type(field['bytes']) is not int or field['bytes'] != len(raw)
                or field['sha256'] != hashlib.sha256(raw).hexdigest()):
            raise ValueError('Exact regeneration diagnostic bytes/hash required')


def regenerate(base, capture_source, host, state_masks, empty, config, run):
    """Called only after the staging controller's Linux/Root/disposable guard."""
    if sys.platform != 'linux':
        raise PermissionError('Disposable Debian CI only')
    from probe_package_plans import guard

    from mano_runtime import recovery
    guard()
    recovery.root_guard()
    if base != Path('/.snapshots/.mano-staged-package-ci'):
        raise ValueError('Fixed private CI directory required')
    digest = config_profile(config)
    data = program(capture_source)
    source = base / 'man-regeneration.py'
    with source.open('xb') as stream:
        stream.write(data)
    source.chmod(0o444)  # Fixed source is readable through the child's RO bind.
    cache = base / 'regenerated-man-cache'
    cache.mkdir(mode=0o700)
    # This mount exists only in the disposable VM. Its 16 MiB ceiling also
    # bounds aggregate cache writes, including a malicious manual-parser input.
    run(['/usr/bin/mount', '-t', 'tmpfs', '-o',
         'size=16777216,nosuid,nodev,noexec,mode=0755,uid=6,gid=12',
         'mano-man-cache-ci', str(cache)])
    run(['/usr/bin/mount', '--make-private', str(cache)])
    unit = 'mano-man-regeneration-ci.service'
    argv = ['/usr/bin/systemd-run', '--quiet', '--pipe', '--wait', '--collect',
            '--unit='+unit, '--slice=mano-package.slice',
            '--property=NoNewPrivileges=yes',
            '--property=CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID '
            'CAP_SETGID CAP_SETPCAP CAP_DAC_READ_SEARCH',
            '--property=MemoryMax=268435456', '--property=TasksMax=32',
            '--property=RuntimeMaxSec=70', '--property=KillMode=control-group',
            '--property=Restart=no', '--property=LimitCORE=0', '--property=LimitNOFILE=128',
            '--property=LimitFSIZE=2097152']
    evidence = Path('/opt/mano-lab/evidence')
    for name, content in (('staged-man-regeneration-program.py', data),
                          ('staged-man-regeneration-config', config)):
        with (evidence / name).open('xb') as stream:
            stream.write(content)
    raw = run(argv + sandbox(base, state_masks, empty, digest), timeout=80)
    # Save raw output before decoding/checking. Failure evidence is never success.
    with (evidence / 'staged-man-regeneration-worker.json').open('xb') as stream:
        stream.write(raw)
    group = Path('/sys/fs/cgroup/mano.slice/mano-package.slice') / unit
    deadline = time.monotonic() + 5
    while True:
        try:
            events = dict(line.split() for line in
                          (group / 'cgroup.events').read_text().splitlines())
        except FileNotFoundError:
            break
        if events.get('populated') == '0':
            break
        if time.monotonic() >= deadline:
            raise ValueError('Fresh cache process domain did not drain')
        time.sleep(.02)
    row = json.loads(raw)
    row['domain_drained'] = True
    validate(row, host, digest)
    return data, config, raw, row
