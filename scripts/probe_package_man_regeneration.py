"""Fixed fresh-cache experiment for disposable CI, never publication authority.

The controller supplies a read-only baseline, a drained candidate manual tree,
and a fresh size-limited private tmpfs. Only baseline executables/configuration
run; the parser runs as man with no capabilities. Retain failures before checks.
"""
import ast
import base64
import contextlib
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


def program(capture_source, *, runtime_view_source=None, runtime_origin_source=None,
            mapping_controls=False, execmem_profile_source=None, executable_source=False):
    if (type(mapping_controls) is not bool
            or (mapping_controls and runtime_origin_source is None)):
        raise ValueError('Mapping controls require the source-identity worker')
    if (execmem_profile_source is not None and (
            not mapping_controls or type(execmem_profile_source) is not bytes
            or not 0 < len(execmem_profile_source) <= 16384)):
        raise ValueError('Memory mode requires bounded fixed profile and mapping controls')
    if type(executable_source) is not bool or (
            executable_source and execmem_profile_source is None):
        raise ValueError('Executable source mode requires memory-enforced fixed generation')
    tree = ast.parse(capture_source)
    capture = next(node for node in tree.body
                   if isinstance(node, ast.FunctionDef) and node.name == 'run_observed')
    fd_guard = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef)
                    and node.name == 'verify_no_inherited_fds')
    body, view_program, origin_program = BODY, '', ''
    if runtime_origin_source is not None:
        if (runtime_view_source is None or type(runtime_origin_source) is not str
                or not 0 < len(runtime_origin_source.encode()) <= 65536):
            raise ValueError('Bounded origin source requires the runtime view')
        origin_nodes = [node for node in ast.parse(runtime_origin_source).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'identity']
        if len(origin_nodes) != 1:
            raise ValueError('One fixed source identity serializer required')
        serializer = ast.get_source_segment(runtime_origin_source, origin_nodes[0])
        serializer = serializer.replace('def identity(', 'def runtime_source_identity(', 1)
        origin_program = ('import stat\n' + serializer + '\nRUNTIME_ORIGIN_SOURCE_SHA256 = '
                          + repr(hashlib.sha256(runtime_origin_source.encode()).hexdigest())
                          + '\n')
    if runtime_view_source is not None:
        if (type(runtime_view_source) is not str
                or not 0 < len(runtime_view_source.encode()) <= 65536):
            raise ValueError('Bounded fixed runtime-view source required')
        view_tree = ast.parse(runtime_view_source)
        names = [node.name for node in view_tree.body if isinstance(node, ast.FunctionDef)]
        if any(names.count(name) != 1 for name in ('path_field', 'parse', 'verify', 'capture')):
            raise ValueError('Complete fixed runtime-view helper functions required')
        # This is trusted repository source, not a parser for untrusted code.
        # Embed it so the isolated -I worker never imports task/candidate modules.
        source_sha = hashlib.sha256(runtime_view_source.encode()).hexdigest()
        view_program = (runtime_view_source + '\nRUNTIME_VIEW_SOURCE_SHA256 = '
                        + repr(source_sha) + '\n')
        marker = "config=Path('/etc/manpath.config').read_bytes()"
        frame = 'print(json.dumps(dict(state=state,'
        if body.count(marker) != 1 or body.count(frame) != 1:
            raise ValueError('Fixed generation worker insertion points changed')
        preflight = ("runtime_view=capture()\ntry:\n"
            "    runtime_view_proof=verify(runtime_view)\n"
            "except (ValueError, KeyError, TypeError, UnicodeError):\n"
            "    print('MANO_MAN_RUNTIME_VIEW=' + json.dumps(runtime_view, sort_keys=True),"
            " file=sys.stderr, flush=True)\n    raise\n")
        if runtime_origin_source is not None:
            preflight = preflight.replace('runtime_view=capture()',
                'runtime_view, runtime_source_identities=capture('
                'identity_function=runtime_source_identity)')
        body = body.replace(marker, preflight+marker)
        body = body.replace(frame, 'print(json.dumps(dict(runtime_view=runtime_view,'
            'runtime_view_proof=runtime_view_proof,'
            'runtime_view_source_sha256=RUNTIME_VIEW_SOURCE_SHA256,state=state,')
        if runtime_origin_source is not None:
            body = body.replace('print(json.dumps(dict(runtime_view=runtime_view,',
                'print(json.dumps(dict(runtime_source_identities=runtime_source_identities,'
                'runtime_origin_source_sha256=RUNTIME_ORIGIN_SOURCE_SHA256,'
                'runtime_view=runtime_view,')
    if mapping_controls:
        marker = 'result=run_observed(command,env,60)'
        if body.count(marker) != 1:
            raise ValueError('Fixed native generation marker required')
        body = body.replace(marker,
            "mapping_result=run_observed(['/run/man-cache-guard','--mapping-controls'],env,5)\n"
            "if (type(mapping_result['returncode']) is not int or mapping_result['returncode']!=0\n"
            "        or mapping_result['capture_complete'] is not True):\n"
            "    print('MANO_MAN_MAPPING_RESULT='+json.dumps(mapping_result,sort_keys=True),"
            "file=sys.stderr,flush=True)\n"
            "    raise ValueError('Complete successful mapping controls required')\n"+marker)
        body = body.replace('print(json.dumps(dict(runtime_source_identities=',
            'print(json.dumps(dict(mapping_controls_result=mapping_result,'
            'runtime_source_identities=')
    if execmem_profile_source is not None:
        marker = "config=Path('/etc/manpath.config').read_bytes()"
        preflight = (
            "execmem_context=None\nif sys.argv[2]=='restricted':\n"
            "    execmem_context=Path('/proc/self/attr/current').read_bytes()\n"
            "    if execmem_context!=b'mano-man-cache-execmem (enforce)\\n':\n"
            "        raise ValueError('Exact enforcing manual-memory profile required')\n"
            "execmem_profile_sha256=" + repr(hashlib.sha256(execmem_profile_source).hexdigest())
            + "\n")
        if body.count(marker) != 1 or body.count("['/run/man-cache-guard']") != 1:
            raise ValueError('Fixed actual-generation insertion points required')
        body = body.replace(marker, preflight + marker)
        body = body.replace("['/run/man-cache-guard']",
                            "['/run/man-cache-guard','--mandb-enforced']")
        body = body.replace('print(json.dumps(dict(mapping_controls_result=',
            "print(json.dumps(dict(execmem_profile_sha256=execmem_profile_sha256,"
            "execmem_context=(None if execmem_context is None else "
            "execmem_context.decode('ascii').rstrip('\\n')),"
            'mapping_controls_result=')
    if executable_source:
        marker = "['/run/man-cache-guard','--mandb-enforced']"
        if body.count(marker) != 1:
            raise ValueError('One fixed source-bound generation command required')
        body = body.replace(marker, "['/run/man-cache-guard','--mandb-enforced-source']")
    data = (HEADER + view_program + origin_program
            + ast.get_source_segment(capture_source, fd_guard) + '\n'
            + ast.get_source_segment(capture_source, capture) + '\n' + body)
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


def sandbox(base, state_masks, empty, config_sha256, *, mode='restricted', execmem=False):
    if (type(execmem) is not bool or re.fullmatch('[a-f0-9]{64}', config_sha256) is None
            or mode not in {'control', 'restricted'}):
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
            *(['/usr/bin/aa-exec', '-p', 'mano-man-cache-execmem', '--']
              if execmem and mode == 'restricted' else []),
            '/usr/bin/python3', '-I', '-B', '/run/man-regeneration.py', config_sha256, mode]


def validate(row, host, config_sha256, *, require_input_guard=False,
             runtime_view_source_sha256=None, require_execmem=False,
             require_executable_source=False):
    if type(require_execmem) is not bool or (require_execmem and not require_input_guard):
        raise ValueError('Memory enforcement requires explicit native input-guard validation')
    if type(require_executable_source) is not bool or (
            require_executable_source and not require_execmem):
        raise ValueError('Executable source requires actual native memory enforcement')
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
    if runtime_view_source_sha256 is not None:
        from mano_runtime.package_man_runtime_view import verify
        if (re.fullmatch('[a-f0-9]{64}', runtime_view_source_sha256) is None
                or row.get('runtime_view_source_sha256') != runtime_view_source_sha256):
            raise ValueError('Exact runtime-view helper source binding required')
        expected_view = verify(row['runtime_view'])
        if (json.dumps(row['runtime_view_proof'], sort_keys=True, allow_nan=False) !=
                json.dumps(expected_view, sort_keys=True, allow_nan=False)):
            raise ValueError('Exact bounded runtime-view proof required')
    if require_input_guard:
        require_guard(row, execmem=require_execmem, executable_source=require_executable_source)


def require_guard(row, *, execmem=False, executable_source=False):
    if row['mode'] != 'restricted':
        raise ValueError('Restricted worker mode required')
    guard = row['input_guard']
    validate_native_guard(guard, role='mandb', execmem=execmem,
                          executable_source=executable_source)
    raw = base64.b64decode(row['result']['stdout']['base64'], validate=True)
    first, separator, _ = raw.partition(b'\n')
    if not separator or len(first) > 4096 or json.loads(first) != guard:
        raise ValueError('Guard report must bind the captured command bytes')


def validate_native_guard(guard, *, role, execmem=False, executable_source=False):
    if type(execmem) is not bool or (execmem and role != 'mandb'):
        raise ValueError('Memory enforcement is fixed to the actual mandb mode')
    if type(executable_source) is not bool or (executable_source and not execmem):
        raise ValueError('Executable source requires the fixed memory-enforced mandb mode')
    expected = {'groups_empty', 'nnp', 'all_capability_sets_zero',
        'control_read_before_allowed', 'control_write_before_allowed',
        'control_read_denied', 'control_write_denied', 'tmp_exec_before_allowed',
        'tmp_exec_denied', 'cache_write_allowed', 'namespace_change_denied',
        'identity_change_denied', 'child_exec_inheritance_verified', 'seccomp_enforced'}
    if (role not in {'mandb', 'source-bytes', 'source-content'} or type(guard) is not dict
            or set(guard) != expected | {'profile', 'role', 'landlock_abi', 'uid', 'gid'}
                | ({'execmem'} if execmem else set())
                | ({'executable_source'} if executable_source else set())
            or guard['profile'] != ('man-cache-landlock-seccomp-v5' if executable_source else
                                    'man-cache-landlock-seccomp-v4' if execmem else
                                    'man-cache-landlock-seccomp-v3') or guard['role'] != role
            or type(guard['landlock_abi']) is not int or not 5 <= guard['landlock_abi'] <= 4096
            or type(guard['uid']) is not int or guard['uid'] != 6
            or type(guard['gid']) is not int or guard['gid'] != 12
            or any(guard[key] is not True for key in expected)):
        raise ValueError('Exact native input guard and inherited denial controls required')
    if execmem:
        from mano_runtime.package_man_execmem import inspect
        inspect(json.dumps(guard['execmem'], sort_keys=True, allow_nan=False).encode())
    if executable_source:
        from mano_runtime.package_man_executable_origin import checked_native
        checked_native(guard['executable_source'])


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
    timed_out = isinstance(error, subprocess.TimeoutExpired)
    return dict(schema_version='1.0', launch_failed=True,
                returncode=None if timed_out else error.returncode, timed_out=timed_out,
                streams=streams, fresh_generation_observed=False, publication_authorized=False)


def compare_source_identities(row, before, after, source_sha):
    from mano_runtime import package_man_runtime_origin

    if (re.fullmatch('[a-f0-9]{64}', source_sha) is None
            or row.get('runtime_origin_source_sha256') != source_sha
            or row.get('domain_drained') is not True):
        raise ValueError('Drained source-bound runtime identity worker required')
    worker = row['runtime_source_identities']
    proof = package_man_runtime_origin.compare(before, after, worker)
    for target, identity in worker.items():
        observed = row['runtime_view']['paths'][target]
        fields = ('device', 'uid', 'mode', 'kind')
        if (json.dumps({key: identity[key] for key in fields}, sort_keys=True, allow_nan=False)
                != json.dumps({key: observed[key] for key in fields},
                              sort_keys=True, allow_nan=False)):
            raise ValueError('Mount and source observations must describe the same FD')
    return proof


def inspect_mapping_result(result):
    from mano_runtime.package_man_mapping_controls import inspect

    if (type(result) is not dict or set(result) != {
            'returncode', 'capture_complete', 'stdout', 'stderr'}
            or type(result['returncode']) is not int or result['returncode'] != 0
            or result['capture_complete'] is not True):
        raise ValueError('Complete successful mapping control capture required')
    streams = {}
    for label, maximum in (('stdout', 4096), ('stderr', 0)):
        field = result[label]
        if (type(field) is not dict or set(field) != {'base64', 'bytes', 'sha256'}
                or type(field['base64']) is not str
                or len(field['base64']) > 4*((maximum+2)//3)
                or type(field['bytes']) is not int):
            raise ValueError('Bounded exact mapping control stream required')
        data = base64.b64decode(field['base64'], validate=True)
        if (base64.b64encode(data).decode() != field['base64']
                or len(data) > maximum or field['bytes'] != len(data)
                or field['sha256'] != hashlib.sha256(data).hexdigest()):
            raise ValueError('Retained mapping control stream custody differs')
        streams[label] = data
    return inspect(streams['stdout'])


def regenerate(base, capture_source, host, state_masks, empty, config, run, *, baseline_tree=None):
    """Called only after the staging controller's Linux/Root/disposable guard."""
    if sys.platform != 'linux':
        raise PermissionError('Disposable Debian CI only')
    from probe_package_plans import guard

    from mano_runtime import recovery
    guard()
    recovery.root_guard()
    if base != Path('/.snapshots/.mano-staged-package-ci'):
        raise ValueError('Fixed private CI directory required')
    if type(baseline_tree) is not dict:
        raise ValueError('Observed fixed baseline tree required for descriptor execution')
    from mano_runtime import package_man_executable_origin as executable_origin
    executable_capture_source = (Path('/opt/mano-lab/src/mano_runtime') /
                                 'package_man_executable_origin.py').read_bytes()
    executable_elf_source = (Path('/opt/mano-lab/src/mano_runtime') /
                             'package_man_elf_memory.py').read_bytes()
    digest = config_profile(config)
    runtime_view_source = (Path('/opt/mano-lab/src/mano_runtime') /
                           'package_man_runtime_view.py').read_text()
    runtime_view_sha = hashlib.sha256(runtime_view_source.encode()).hexdigest()
    from mano_runtime import package_man_runtime_origin as runtime_origin
    runtime_origin_source = (Path('/opt/mano-lab/src/mano_runtime') /
                             'package_man_runtime_origin.py').read_text()
    origin_sha = hashlib.sha256(runtime_origin_source.encode()).hexdigest()
    profile_path = Path('/opt/mano-lab/packaging/apparmor/mano-man-cache-execmem')
    profile_source = profile_path.read_bytes()
    profile_sha = hashlib.sha256(profile_source).hexdigest()
    execmem_parser_source = (Path('/opt/mano-lab/src/mano_runtime') /
                             'package_man_execmem.py').read_bytes()
    data = program(capture_source, runtime_view_source=runtime_view_source,
                   runtime_origin_source=runtime_origin_source, mapping_controls=True,
                   execmem_profile_source=profile_source, executable_source=True)
    # Fixed repository profile, loaded only after all disposable/Root guards.
    # Never fall back to an unconfined restricted worker if this fails.
    run(['/usr/sbin/apparmor_parser', '--replace', '--skip-cache', str(profile_path)])
    mapping_source = (Path('/opt/mano-lab/src/mano_runtime') /
                       'package_man_mapping_controls.py').read_bytes()
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
    observations, source_receipts, mapping_receipts = {}, {}, {}
    executable_packet = None
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
        executable_context = (executable_origin.hold(baseline_tree) if mode == 'restricted'
                              else contextlib.nullcontext(None))
        with runtime_origin.hold() as held, executable_context as executable_held:
            source_before = held.observe()
            executable_before = (executable_held.observe()
                                 if executable_held is not None else None)
            executable_after = None
            executable_capture = (dict(before=executable_before,
                raw_base64=base64.b64encode(executable_held.raw).decode(),
                raw_bytes=len(executable_held.raw),
                raw_sha256=hashlib.sha256(executable_held.raw).hexdigest())
                if executable_held is not None else None)
            try:
                raw = run(unit_command(mode=mode) +
                          sandbox(base, state_masks, empty, digest, mode=mode, execmem=True),
                          timeout=80)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                    OSError, ValueError) as error:
                failed = (launch_failure(error) if isinstance(error, (
                    subprocess.CalledProcessError, subprocess.TimeoutExpired)) else
                    dict(stage='source-launch', error_type=type(error).__name__,
                         launch_failed=True, streams_available=False,
                         fresh_generation_observed=False, publication_authorized=False))
                with (evidence / (stem + '-launch-failure.json')).open('x') as stream:
                    json.dump(dict(failed, runtime_source_before=source_before,
                                   runtime_source_after=held.observe(), domain_drained=False,
                                   executable_source_capture=executable_capture),
                              stream, sort_keys=True)
                raise
            # Preserve captured worker bytes before parsing or asserting success.
            with (evidence / (stem + '.json')).open('xb') as stream:
                stream.write(raw)
            drained, source_after = False, None
            try:
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
                drained = True
                row = json.loads(raw)
                row['domain_drained'] = True
                validate(row, host, digest, require_input_guard=mode == 'restricted',
                         runtime_view_source_sha256=runtime_view_sha,
                         require_execmem=mode == 'restricted',
                         require_executable_source=mode == 'restricted')
                if (row['mode'] != mode or (mode == 'control' and row['input_guard'] is not None)
                        or control_identity() != original):
                    raise ValueError('Fixed comparison mode and unchanged control fixture required')
                if (row.get('execmem_profile_sha256') != profile_sha
                        or row.get('execmem_context') != (
                            'mano-man-cache-execmem (enforce)' if mode == 'restricted' else None)):
                    raise ValueError('Fixed profile digest and enforced worker context required')
                if executable_held is not None:
                    executable_after = executable_held.observe()
                    executable_packet = executable_origin.compare(executable_held.raw,
                        baseline_tree, executable_before, executable_after,
                        row['input_guard']['executable_source'])
                    executable_packet.update(domain_drained=True,
                        generation_command_returned_zero=True,
                        source_capture_sha256=hashlib.sha256(executable_capture_source).hexdigest(),
                        elf_parser_source_sha256=hashlib.sha256(executable_elf_source).hexdigest())
                source_after = held.observe()
                source_proof = compare_source_identities(row, source_before, source_after,
                                                         origin_sha)
                mapping_receipts[mode] = inspect_mapping_result(row['mapping_controls_result'])
                source_receipts[mode] = dict(before=source_before, after=source_after,
                                             comparison=source_proof, domain_drained=True)
                observations[mode] = (raw, row)
            except (OSError, ValueError, KeyError, TypeError) as error:
                with (evidence / (stem + '-launch-failure.json')).open('x') as stream:
                    json.dump(dict(stage='source-validation', error_type=type(error).__name__,
                        runtime_source_before=source_before, runtime_source_after=source_after,
                        domain_drained=drained, worker_artifact=stem+'.json',
                        executable_source_capture=executable_capture,
                        executable_source_after=executable_after),
                        stream, sort_keys=True)
                raise
    raw, row = observations['restricted']
    source_packet = dict(
        profile='man-runtime-source-identities-pair-v1', source_sha256=origin_sha,
        workers=source_receipts, collector_authentication_verified=False,
        complete_runtime_closure_verified=False, loader_selection_verified=False,
        generated_state_validated=False, changes_authorized=False,
        publication_authorized=False)
    if len(json.dumps(source_packet, sort_keys=True, allow_nan=False).encode()) > 65536:
        raise ValueError('Bounded embedded runtime source identity evidence required')
    kernel = os.uname().release
    if any(proof['kernel_release'] != kernel for proof in mapping_receipts.values()):
        raise ValueError('Mapping controls must report the actual controller kernel')
    mapping_packet = dict(profile='man-executable-mapping-pair-v1', kernel_release=kernel,
        parser_source_sha256=hashlib.sha256(mapping_source).hexdigest(),
        guard_source_sha256=hashlib.sha256(native_source).hexdigest(),
        guard_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        workers=mapping_receipts, diagnostic_mapping_bytes_executed=False,
        complete_runtime_closure_verified=False, loader_selection_verified=False,
        generated_state_validated=False, changes_authorized=False, publication_authorized=False)
    if len(json.dumps(mapping_packet, sort_keys=True, allow_nan=False).encode()) > 16384:
        raise ValueError('Bounded embedded mapping controls required')
    execmem_packet = dict(profile='man-execmem-generation-v1',
        profile_source_base64=base64.b64encode(profile_source).decode(),
        profile_source_sha256=profile_sha,
        parser_source_sha256=hashlib.sha256(execmem_parser_source).hexdigest(),
        guard_source_sha256=hashlib.sha256(native_source).hexdigest(),
        guard_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        generation_guard=row['input_guard'],
        worker_context=row['execmem_context'],
        control_context=observations['control'][1]['execmem_context'],
        diagnostic_mapping_bytes_executed=False,
        complete_runtime_closure_verified=False, loader_selection_verified=False,
        generated_state_validated=False, changes_authorized=False, publication_authorized=False)
    if len(json.dumps(execmem_packet, sort_keys=True, allow_nan=False).encode()) > 16384:
        raise ValueError('Bounded embedded executable-memory enforcement evidence required')
    if (executable_packet is None or len(json.dumps(executable_packet, sort_keys=True,
            allow_nan=False).encode()) > executable_origin.MAX_PACKET_BYTES):
        raise ValueError('Bounded retained actual executable source required')
    return (data, config, raw, row, source_packet, mapping_packet, execmem_packet,
            executable_packet)
