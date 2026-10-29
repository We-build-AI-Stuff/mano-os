"""Fixed fresh-cache experiment for disposable CI, never publication authority.

The controller supplies a read-only baseline, a drained candidate manual tree,
and a fresh size-limited private tmpfs. Only baseline executables/configuration
run; the parser runs as man with no capabilities. Retain failures before checks.
"""
import ast
import base64
import hashlib
import json
import os
import re
import subprocess
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
assert len(sys.argv)==3 and len(sys.argv[1])==64 and sys.argv[2] in {'control','restricted'}
config=Path('/etc/manpath.config').read_bytes()
assert len(config)<=65536 and hashlib.sha256(config).hexdigest()==sys.argv[1]
assert list(Path('/var/cache/man').iterdir())==[]
env={'PATH':'/usr/sbin:/usr/bin:/bin','LANG':'C.UTF-8','TZ':'UTC0',
     'PYTHONDONTWRITEBYTECODE':'1','HOME':'/nonexistent'}
mode=sys.argv[2]
command=(['/run/man-cache-guard'] if mode=='restricted' else
         ['/usr/bin/mandb','--create','--quiet','/usr/share/man'])
result=run_observed(command,env,60)
input_guard=None
if mode=='restricted' and result['returncode']==0 and result['capture_complete']:
    header,separator,_=base64.b64decode(result['stdout']['base64']).partition(b'\n')
    assert separator and len(header)<=4096
    input_guard=json.loads(header)
print(json.dumps(dict(state=state,config_sha256=hashlib.sha256(config).hexdigest(),
    initial_cache_empty=True,mode=mode,input_guard=input_guard,result=result)))
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


def sandbox(base, state_masks, empty, config_sha256, *, mode='restricted'):
    if re.fullmatch('[a-f0-9]{64}', config_sha256) is None or mode not in {'control', 'restricted'}:
        raise ValueError('Configuration digest required')
    return ['/usr/bin/bwrap', '--die-with-parent', '--new-session', '--unshare-pid',
            '--unshare-net', '--unshare-ipc', '--unshare-uts', '--unshare-cgroup',
            '--ro-bind', str(base / 'baseline'), '/',
            '--ro-bind', str(base / 'candidate/usr/share/man'), '/usr/share/man',
            '--bind', str(base / ('man-cache-control' if mode == 'control'
                                  else 'regenerated-man-cache')), '/var/cache/man',
            '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/run', '--perms', '1777', '--tmpfs', '/tmp',
            '--tmpfs', '/home', '--tmpfs', '/root',
            '--tmpfs', '/opt', '--tmpfs', '/mnt', '--tmpfs', '/media', '--tmpfs', '/srv',
            *[arg for path in state_masks for arg in ('--tmpfs', path)],
            '--tmpfs', '/.snapshots',
            '--ro-bind', str(base / 'man-regeneration.py'), '/run/man-regeneration.py',
            '--ro-bind', str(base / 'man-cache-guard'), '/run/man-cache-guard',
            '--bind', str(base / 'man-cache-control-file'), '/run/man-cache-control',
            '--ro-bind', str(empty), '/etc/shadow', '--ro-bind', str(empty), '/etc/gshadow',
            '--clearenv', '--setenv', 'PATH', '/usr/sbin:/usr/bin:/bin',
            '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC0',
            '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
            '--cap-drop', 'ALL', '--cap-add', 'CAP_SETUID', '--cap-add', 'CAP_SETGID',
            '--cap-add', 'CAP_SETPCAP', '--chdir', '/',
            '/usr/bin/setpriv', '--no-new-privs', '--reuid', '6', '--regid', '12',
            '--clear-groups', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
            '/usr/bin/python3', '-I', '-B', '/run/man-regeneration.py', config_sha256, mode]


def validate(row, host, config_sha256, *, require_input_guard=False):
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
    if require_input_guard:
        require_guard(row)


def require_guard(row):
    if row['mode'] != 'restricted':
        raise ValueError('Restricted worker mode required')
    guard = row['input_guard']
    validate_native_guard(guard, role='mandb')
    raw = base64.b64decode(row['result']['stdout']['base64'], validate=True)
    first, separator, _ = raw.partition(b'\n')
    if not separator or len(first) > 4096 or json.loads(first) != guard:
        raise ValueError('Guard report must bind the captured command bytes')


def validate_native_guard(guard, *, role):
    expected = {'groups_empty', 'nnp', 'all_capability_sets_zero',
        'control_read_before_allowed', 'control_write_before_allowed',
        'control_read_denied', 'control_write_denied', 'tmp_exec_before_allowed',
        'tmp_exec_denied', 'cache_write_allowed', 'namespace_change_denied',
        'identity_change_denied', 'child_exec_inheritance_verified', 'seccomp_enforced'}
    if (role not in {'mandb', 'source-bytes', 'source-content'} or type(guard) is not dict
            or set(guard) != expected | {'profile', 'role', 'landlock_abi', 'uid', 'gid'}
            or guard['profile'] != 'man-cache-landlock-seccomp-v3' or guard['role'] != role
            or type(guard['landlock_abi']) is not int or not 5 <= guard['landlock_abi'] <= 4096
            or type(guard['uid']) is not int or guard['uid'] != 6
            or type(guard['gid']) is not int or guard['gid'] != 12
            or any(guard[key] is not True for key in expected)):
        raise ValueError('Exact native input guard and inherited denial controls required')


def unit_command(*, mode='restricted'):
    # NET_ADMIN is needed only to initialize loopback in the private network
    # namespace. Bubblewrap drops it before setpriv; the man guard requires
    # every capability set, including the bounding set, to be exactly zero.
    if mode not in {'control', 'restricted'}:
        raise ValueError('Fixed man-cache unit mode required')
    unit = ('mano-man-regeneration-control-ci.service' if mode == 'control'
            else 'mano-man-regeneration-ci.service')
    return ['/usr/bin/systemd-run', '--quiet', '--pipe', '--wait', '--collect',
            '--unit='+unit, '--slice=mano-package.slice',
            '--property=NoNewPrivileges=yes',
            '--property=CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID '
            'CAP_SETGID CAP_SETPCAP CAP_DAC_READ_SEARCH CAP_NET_ADMIN',
            '--property=MemoryMax=268435456', '--property=TasksMax=32',
            '--property=RuntimeMaxSec=70', '--property=KillMode=control-group',
            '--property=Restart=no', '--property=LimitCORE=0', '--property=LimitNOFILE=128',
            '--property=LimitFSIZE=2097152']


def launch_failure(error):
    streams = {}
    for label in ('stdout', 'stderr'):
        original = getattr(error, label) or b''
        if type(original) is not bytes:
            raise ValueError('Binary launch diagnostics required')
        raw = original[:65536]
        streams[label] = dict(base64=base64.b64encode(raw).decode(), bytes=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(), complete=len(original) <= 65536)
    return dict(schema_version='1.0', launch_failed=True, returncode=error.returncode,
                streams=streams, fresh_generation_observed=False, publication_authorized=False)


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
    evidence = Path('/opt/mano-lab/evidence')
    native_source = Path('/opt/mano-lab/native/mano_man_cache_guard.c').read_bytes()
    binary = base / 'man-cache-guard'
    run(['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
         '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2',
         '/opt/mano-lab/native/mano_man_cache_guard.c', '-lseccomp',
         '-Wl,-z,relro,-z,now', '-o', str(binary)])
    binary.chmod(0o555)
    for name, content in (('staged-man-regeneration-program.py', data),
                          ('staged-man-regeneration-config', config),
                          ('staged-man-cache-guard.c', native_source),
                          ('staged-man-cache-guard', binary.read_bytes())):
        with (evidence / name).open('xb') as stream:
            stream.write(content)
    control = base / 'man-cache-control-file'
    with control.open('xb') as stream:
        stream.write(b'mano public disposable cache-policy control\n')
    os.chown(control, 6, 12)
    control.chmod(0o600)

    def control_identity():
        info = control.lstat()
        return (control.read_bytes(), info.st_dev, info.st_ino, info.st_mode,
                info.st_uid, info.st_gid, info.st_nlink, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)

    original = control_identity()
    observations = {}
    for mode in ('control', 'restricted'):
        role = 'man-cache-control' if mode == 'control' else 'regenerated-man-cache'
        cache = base / role
        cache.mkdir(mode=0o700)
        # Separate fresh caches; the control is never a publication fallback.
        run(['/usr/bin/mount', '-t', 'tmpfs', '-o',
             'size=16777216,nosuid,nodev,noexec,mode=0755,uid=6,gid=12',
             'mano-man-cache-ci', str(cache)])
        run(['/usr/bin/mount', '--make-private', str(cache)])
        unit = ('mano-man-regeneration-control-ci.service' if mode == 'control'
                else 'mano-man-regeneration-ci.service')
        stem = ('staged-man-regeneration-control' if mode == 'control'
                else 'staged-man-regeneration-worker')
        try:
            raw = run(unit_command(mode=mode) +
                      sandbox(base, state_masks, empty, digest, mode=mode), timeout=80)
        except subprocess.CalledProcessError as error:
            with (evidence / (stem + '-launch-failure.json')).open('x') as stream:
                json.dump(launch_failure(error), stream, sort_keys=True)
            raise
        # Preserve captured worker bytes before parsing or asserting success.
        with (evidence / (stem + '.json')).open('xb') as stream:
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
        validate(row, host, digest, require_input_guard=mode == 'restricted')
        if (row['mode'] != mode or (mode == 'control' and row['input_guard'] is not None)
                or control_identity() != original):
            raise ValueError('Fixed comparison mode and unchanged control fixture required')
        observations[mode] = (raw, row)
    raw, row = observations['restricted']
    return data, config, raw, row
