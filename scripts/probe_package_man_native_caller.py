"""Controlled mandb caller observation in the existing disposable UID6 domain.

No additional native grant, artifact, configuration or actual-source input.
Raw diagnostics do not authorize generated content or establish full semantics.
"""
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

from probe_package_man_reference_fixtures import BASE, drained, encoded
from probe_package_man_regeneration import validate_native_guard
from probe_package_man_source_bytes import fixture_identity
from probe_package_man_source_content import bounded_capture, content_sandbox, content_unit

from mano_runtime import package_man_source_content as worker

CORPUS_SHA256 = '8f56a13ded65f857120fda94270e5bddb3226cd915976a7748acdf925f095269'
CORPUS_PATH = Path('/opt/mano-lab/tests/fixtures/man-native-reference-corpus-v1.json')
ROOT = BASE / 'man-native-reference-corpus'
CACHE = BASE / 'man-content-cache/native-caller-cache'
MAX_CAPTURE = 600*1024


def corpus(data):
    if type(data) is not bytes or len(data) > 32768 or hashlib.sha256(data).hexdigest() != (
            CORPUS_SHA256):
        raise ValueError('Exact literal native-caller corpus required')
    value = json.loads(data)
    if (value['profile'] != 'man-native-reference-corpus-v1'
            or value['only_literal_synthetic_inputs'] is not True
            or value['native_conformance_verified'] is not False
            or value['publication_authorized'] is not False
            or len(value['files']) != 37 or len(value['cases']) != 13
            or value['hardlinks'] != {'man1/b-hard.1': 'man1/a-hard.1'}
            or value['symlinks'] != {'man1/soft-hard.1': 'b-hard.1'}):
        raise ValueError('Complete fixed synthetic corpus declaration required')
    for name, row in value['files'].items():
        if re.fullmatch(r'(?:man[12]/)?[a-z0-9.-]+', name) is None:
            raise ValueError('Fixed bounded corpus leaf names required')
        raw = base64.b64decode(row['content_base64'], validate=True)
        if (type(row['bytes']) is not int or row['bytes'] != len(raw) or len(raw) > 512
                or row['sha256'] != hashlib.sha256(raw).hexdigest()):
            raise ValueError('Fixed synthetic corpus bytes/hash required')
    if not set(value['cases'].values()) <= (
            value['files'].keys() | value['hardlinks'].keys() | value['symlinks'].keys()):
        raise ValueError('Every fixed case must name a declared corpus leaf')
    return value


def inventory(spec):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise PermissionError('Disposable Root corpus inventory only')
    names = {'', 'man1', 'man2'} | spec['files'].keys() | spec['hardlinks'].keys() | (
        spec['symlinks'].keys())
    result = {}
    for name in sorted(names):
        path = ROOT/name
        info = path.lstat()
        if os.listxattr(path, follow_symlinks=False):
            raise ValueError('Synthetic corpus must have no security attributes')
        kind = ('directory' if stat.S_ISDIR(info.st_mode) else
                'file' if stat.S_ISREG(info.st_mode) else
                'symlink' if stat.S_ISLNK(info.st_mode) else None)
        row = dict(kind=kind, uid=info.st_uid, gid=info.st_gid,
            mode=stat.S_IMODE(info.st_mode), nlink=info.st_nlink,
            bytes=info.st_size, device=info.st_dev, inode=info.st_ino,
            mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns, xattrs={})
        if row['uid'] != 0 or row['gid'] != 0:
            raise ValueError('Root-owned corpus required')
        if name in {'', 'man1', 'man2'}:
            children = {n[len(name)+bool(name):].split('/')[0] for n in names
                        if n != name and (not name or n.startswith(name+'/'))}
            row['children'] = sorted(os.listdir(path))
            if kind != 'directory' or row['mode'] != 0o755 or set(row['children']) != children:
                raise ValueError('Exact corpus directory and children required')
        elif name in spec['symlinks']:
            if (kind != 'symlink' or row['mode'] != 0o777 or row['nlink'] != 1
                    or os.readlink(path) != spec['symlinks'][name]):
                raise ValueError('Exact corpus symlink required')
            row['target'] = spec['symlinks'][name]
        else:
            target = spec['hardlinks'].get(name, name)
            expected = spec['files'][target]
            links = 2 if name in {'man1/a-hard.1', 'man1/b-hard.1'} else 1
            if (kind != 'file' or row['mode'] != 0o644 or row['nlink'] != links
                    or row['bytes'] != expected['bytes']):
                raise ValueError('Exact corpus regular file required')
            raw = path.read_bytes()
            if raw != base64.b64decode(expected['content_base64'], validate=True):
                raise ValueError('Corpus regular bytes changed')
            row['sha256'] = hashlib.sha256(raw).hexdigest()
        result[name] = row
    if tuple(result['man1/a-hard.1'][key] for key in ('device', 'inode')) != tuple(
            result['man1/b-hard.1'][key] for key in ('device', 'inode')):
        raise ValueError('Actual same-inode hardlink fixture required')
    return result


def caller_command(base, masks, empty, config_digest):
    if base != BASE:
        raise ValueError('Fixed caller namespace base required')
    command = content_sandbox(base, masks, empty, config_digest)
    replacements = (
        ('--ro-bind', base/'candidate/usr/share/man', ROOT, '/usr/share/man'),
        ('--bind', base/'man-content-cache', CACHE, '/var/cache/man'),
        ('--ro-bind', base/'man-source-paths.json', base/'man-native-caller-request.json',
         '/run/man-source-paths.json'),
    )
    for option, original, replacement, target in replacements:
        position = command.index(str(original))
        if command[position-1] != option or command[position+1] != target:
            raise ValueError('Only fixed source/cache/request mount sources may change')
        command[position] = str(replacement)
    if command[-2:] != ['/run/man-cache-guard', '--source-content']:
        raise ValueError('Existing content native role must remain unchanged')
    unit = content_unit()
    unit[unit.index('--property=RuntimeMaxSec=190')] = '--property=RuntimeMaxSec=30'
    return unit+command


def validate_capture(raw, spec, baseline, config_digest):
    header, separator, body = raw.partition(b'\n')
    if not separator or len(header) > 4096 or len(body) > MAX_CAPTURE:
        raise ValueError('Bounded native caller framing required')
    native = json.loads(header)
    validate_native_guard(native, role='source-content')
    value = json.loads(body)
    executable = baseline['entries']['usr/bin/mandb']
    if (value['profile'] != 'man-native-reference-caller-capture-v1'
            or type(value['uid']) is not int or type(value['gid']) is not int
            or (value['uid'], value['gid'], value['groups']) != (6, 12, [])
            or value['command'] != list(worker.CALLER_COMMAND)
            or value['environment'] != dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C',
                                          TZ='UTC0', HOME='/nonexistent')
            or value['mandb_executable_sha256'] != executable['sha256']
            or executable['kind'] != 'file' or executable['mode'] != 0o755
            or executable['uid'] != 0 or executable['gid'] != 0 or executable['nlink'] != 1
            or value['manpath_configuration_sha256'] != config_digest
            or value['fixed_command_and_configuration_unchanged'] is not True):
        raise ValueError('Exact fixed native caller/configuration binding required')
    if (type(value['returncode']) is not int or value['returncode'] != 0
            or value['capture_complete'] is not True or value['capture_failure'] is not None):
        raise ValueError('Complete normal native caller observation required')
    diagnostics = {}
    for label, maximum in (('stdout', 128*1024), ('stderr', 256*1024)):
        row = value[label]
        if type(row['base64']) is not str or len(row['base64']) > 4*((maximum+2)//3):
            raise ValueError('Bounded native caller stream required')
        data = base64.b64decode(row['base64'], validate=True)
        if (type(row['bytes']) is not int or row['bytes'] != len(data) or len(data) > maximum
                or row['sha256'] != hashlib.sha256(data).hexdigest()):
            raise ValueError('Exact native caller stream bytes/hash required')
        diagnostics[label] = data
    for name in spec['cases'].values():
        token = b'test_manfile: considering /usr/share/man/'+name.encode()+b'\n'
        if token not in diagnostics['stderr']:
            raise ValueError('Every fixed primary case must be considered by the real caller')
    for key in ('native_man_db_caller_semantics_verified', 'full_source_semantics_verified',
                'generated_state_validated', 'changes_authorized', 'publication_authorized'):
        if value[key] is not False:
            raise ValueError('Raw caller diagnostics cannot authorize generated state')
    return native, value


def capture_reference_caller(base, baseline, masks, empty, config_digest, run):
    if sys.platform != 'linux' or os.geteuid() != 0 or base != BASE:
        raise PermissionError('Fixed disposable Debian Root caller controller required')
    from probe_package_plans import guard

    guard()
    drained()
    with CORPUS_PATH.open('rb') as stream:
        declaration = stream.read(32769)
    spec = corpus(declaration)
    ROOT.mkdir(mode=0o755)
    ROOT.chmod(0o755)
    for name in ('man1', 'man2'):
        (ROOT/name).mkdir(mode=0o755)
        (ROOT/name).chmod(0o755)
    for name, row in spec['files'].items():
        with (ROOT/name).open('xb') as stream:
            stream.write(base64.b64decode(row['content_base64'], validate=True))
        (ROOT/name).chmod(0o644)
    for name, target in spec['hardlinks'].items():
        os.link(ROOT/target, ROOT/name)
    for name, target in spec['symlinks'].items():
        os.symlink(target, ROOT/name)
    for name in {'', 'man1', 'man2'} | spec['files'].keys() | spec['hardlinks'].keys() | (
            spec['symlinks'].keys()):
        os.chown(ROOT/name, 0, 0, follow_symlinks=False)
    before = inventory(spec)
    CACHE.mkdir(mode=0o755)
    os.chown(CACHE, 6, 12)
    CACHE.chmod(0o755)
    cache_info = CACHE.lstat()
    cache_initial = dict(uid=cache_info.st_uid, gid=cache_info.st_gid,
        mode=stat.S_IMODE(cache_info.st_mode), device=cache_info.st_dev,
        inode=cache_info.st_ino, children=sorted(path.name for path in CACHE.iterdir()))
    if (cache_initial['children'] or (cache_initial['uid'], cache_initial['gid'],
            cache_initial['mode']) != (6, 12, 0o755)):
        raise ValueError('Fresh empty private caller cache required')
    packet = base/'man-native-caller-request.json'
    with packet.open('xb') as stream:
        stream.write(worker.CALLER_REQUEST)
    packet.chmod(0o444)
    packet_before = fixture_identity(packet)
    control = base/'man-cache-control-file'
    control_before = fixture_identity(control)
    command = caller_command(base, masks, empty, config_digest)
    try:
        raw = bounded_capture(command, timeout=40,
                              stdout_limit=MAX_CAPTURE+4097)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(json.dumps(dict(man_native_caller_failure={label: base64.b64encode(
            (getattr(error, label) or b'')[:MAX_CAPTURE if label == 'stdout' else 65536]).decode()
            for label in ('stdout', 'stderr')})), file=sys.stderr, flush=True)
        run(['/usr/bin/systemctl', 'stop', 'mano-man-content-ci.service'], timeout=10)
        raise
    print(json.dumps(dict(man_native_caller_capture_base64=base64.b64encode(raw).decode())),
          file=sys.stderr, flush=True)
    drained()
    after = inventory(spec)
    cache_after = CACHE.lstat()
    cache_identity_after = dict(device=cache_after.st_dev, inode=cache_after.st_ino)
    if cache_identity_after != {key: cache_initial[key] for key in ('device', 'inode')}:
        raise ValueError('Private caller cache inode changed')
    if (after != before or fixture_identity(packet) != packet_before
            or fixture_identity(control) != control_before):
        raise ValueError('Caller corpus/request/control changed during observation')
    native, _observed = validate_capture(raw, spec, baseline, config_digest)
    return dict(profile='man-native-reference-caller-custody-v1', guard=native,
        launch_command=command,
        capture_base64=base64.b64encode(raw).decode(), capture_bytes=len(raw),
        capture_sha256=hashlib.sha256(raw).hexdigest(), corpus_declaration=spec,
        corpus_declaration_sha256=hashlib.sha256(declaration).hexdigest(), inventory=before,
        inventory_before_sha256=hashlib.sha256(encoded(before)).hexdigest(),
        inventory_after_sha256=hashlib.sha256(encoded(after)).hexdigest(),
        fixed_request_sha256=hashlib.sha256(worker.CALLER_REQUEST).hexdigest(),
        worker_program_sha256=hashlib.sha256((base/'man-source-content.py').read_bytes()).hexdigest(),
        controller_program_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        baseline_sha256=baseline['manifest_sha256'],
        mandb_metadata=baseline['entries']['usr/bin/mandb'],
        manpath_configuration_sha256=config_digest, case_count=len(spec['cases']),
        native_caller_considered_all_fixed_cases=True, corpus_unchanged=True,
        request_unchanged=True, control_fixture_unchanged=True, domain_drained=True,
        private_cache_initially_empty=True, private_cache_initial=cache_initial,
        private_cache_identity_after=cache_identity_after,
        fixed_source_and_cache_mounts_only=True,
        native_filesystem_grants_changed=False, native_man_db_caller_semantics_verified=False,
        full_source_semantics_verified=False, generated_state_validated=False,
        changes_authorized=False, publication_authorized=False)
