"""Fixed synthetic path probes in the disposable UID6 source-content domain.

No additional artifact or native filesystem grant. Witnesses are bounded data
for embedding in the existing Root report, not generated-state authority.
"""
import base64
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

from probe_package_man_regeneration import validate_native_guard
from probe_package_man_source_bytes import fixture_identity
from probe_package_man_source_content import bounded_capture, content_sandbox, content_unit

from mano_runtime import package_man_source_content as worker
from mano_runtime.package_man_reference_lookup import ROOT, Namespace

BASE = Path('/.snapshots/.mano-staged-package-ci')
MAX_EMBEDDED_BYTES = 1024**2


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def inventory(root):
    if sys.platform != 'linux' or os.geteuid() != 0 or root != (
            BASE / 'man-content-cache/reference-fixtures'):
        raise PermissionError('Fixed disposable Root fixture observation only')
    result = {}
    names = set(worker.REFERENCE_DIRECTORIES) | set(worker.REFERENCE_FILES) | set(
        worker.REFERENCE_LINKS)
    for name in sorted(names):
        path = root / name
        info = path.lstat()
        if os.listxattr(path, follow_symlinks=False):
            raise ValueError('Fixed fixture security attributes must remain empty')
        kind = ('directory' if stat.S_ISDIR(info.st_mode) else
                'symlink' if stat.S_ISLNK(info.st_mode) else
                'file' if stat.S_ISREG(info.st_mode) else None)
        row = dict(kind=kind, device=info.st_dev, inode=info.st_ino,
            mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid,
            nlink=info.st_nlink, mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns,
            size=info.st_size, xattrs={})
        if name in worker.REFERENCE_DIRECTORIES:
            expected = worker.REFERENCE_DIRECTORIES[name]
            children = {other[len(name)+bool(name):].split('/')[0] for other in names
                        if other != name and (not name or other.startswith(name+'/'))}
            if (kind != 'directory' or (row['uid'], row['gid'], row['mode']) != expected
                    or set(os.listdir(path)) != children):
                raise ValueError('Exact fixed fixture directory and child set required')
        elif name in worker.REFERENCE_LINKS:
            target = os.readlink(path)
            if (kind != 'symlink' or target != worker.REFERENCE_LINKS[name]
                    or (row['uid'], row['gid'], row['mode'], row['nlink']) != (0, 0, 0o777, 1)):
                raise ValueError('Exact fixed fixture symlink required')
            row['target'] = target
        else:
            mode = 0 if name == 'unreadable.1' else 0o644
            if (kind != 'file' or (row['uid'], row['gid'], row['mode'], row['nlink'])
                    != (0, 0, mode, 1)):
                raise ValueError('Exact fixed regular fixture required')
            raw = path.read_bytes()
            if raw != b'fixed-reference-fixture:'+name.encode()+b'\n':
                raise ValueError('Fixed inert fixture bytes changed')
            row.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        result[name] = row
    return result


def model_tree(observed, baseline):
    """Normalize this declared fixture root; never normalize untrusted paths."""
    entries = {'.': baseline['entries']['.'], 'usr': baseline['entries']['var'],
               'usr/share': baseline['entries']['var/cache']}
    for name, info in observed.items():
        path = ROOT+('/'+name if name else '')
        row = {key: info[key] for key in ('kind', 'uid', 'gid', 'mode', 'nlink',
                                          'mtime_ns', 'ctime_ns', 'xattrs')}
        if row['kind'] == 'file':
            row.update(bytes=info['bytes'], sha256=info['sha256'], hardlink_anchor=path)
        elif row['kind'] == 'symlink':
            target = info['target']
            if target.startswith(worker.REFERENCE_ROOT+'/'):
                target = '/'+ROOT+target[len(worker.REFERENCE_ROOT):]
            row['target'] = target
        entries[path] = row
    return dict(schema_version='1.0', entries=entries, excluded_subtrees=['.snapshots'],
                manifest_sha256=hashlib.sha256(encoded(entries)).hexdigest())


def compare(value, observed, tree):
    """Compare fixed witness identity/error data with the conditional model."""
    if (value['profile'] != 'man-fixed-reference-fixtures-v1'
            or value['fixture_root'] != worker.REFERENCE_ROOT
            or value['configured_extensions'] != ['gz', 'xz']
            or value['uid'] != 6 or value['gid'] != 12 or value['groups'] != []):
        raise ValueError('Fixed fixture identity and configuration required')
    for flag in ('source_inputs_opened', 'source_content_interpreted',
                 'native_man_db_library_executed', 'native_man_db_caller_semantics_verified',
                 'complete_source_graph_verified', 'generated_state_validated',
                 'changes_authorized', 'publication_authorized'):
        if value[flag] is not False:
            raise ValueError('Kernel fixtures cannot grant additional authority')
    namespace = Namespace(tree, tree)

    def outcome(native, modeled, *, access_only=False):
        if modeled['state'] not in ('exists', 'unavailable') or native['state'] != modeled['state']:
            raise ValueError('Fixed kernel fixture state disagrees with model')
        if modeled['state'] == 'unavailable':
            expected = {'state': 'unavailable'}
            if not access_only:
                expected['errno'] = worker.REFERENCE_ERRNO[modeled['reason']]
        else:
            name = modeled['terminal_path'][len(ROOT):].removeprefix('/')
            row = observed[name]
            expected = dict(state='exists', **{key: row[key] for key in
                            ('device', 'inode', 'kind', 'uid', 'gid', 'mode')})
        if native != expected:
            raise ValueError('Exact fixture errno/inode/type/permissions required')

    queries = [(path, follow) for path in worker.REFERENCE_PATHS for follow in (True, False)]
    if len(value['queries']) != len(queries) or len(value['selections']) != len(
            worker.REFERENCE_OPERANDS):
        raise ValueError('Complete fixed query/selection witness set required')
    for row, (path, follow) in zip(value['queries'], queries, strict=True):
        if row['path'] != path or row['follow_final'] is not follow:
            raise ValueError('Fixed ordered stat/lstat queries required')
        outcome(row['outcome'], namespace.stat(ROOT+'/'+path, follow_final=follow))
    for row, operand in zip(value['selections'], worker.REFERENCE_OPERANDS, strict=True):
        if row['operand'] != operand:
            raise ValueError('Fixed ordered selection operands required')
        modeled = namespace.select(ROOT, ROOT+'/man1/original.1', operand.encode(), ['gz', 'xz'])
        if len(row['attempts']) != len(modeled['attempts']):
            raise ValueError('No fixture compression/fallback attempt may be skipped')
        for native, attempt in zip(row['attempts'], modeled['attempts'], strict=True):
            path = worker.REFERENCE_ROOT+attempt['path'][len(ROOT):]
            if (native['path'] != path or native['context'] != attempt['context']
                    or native['extension'] != attempt['extension']):
                raise ValueError('Fixed fixture attempt context/order/path required')
            plain = attempt['extension'] == ''
            if plain and native['access_f_ok'] is not (attempt['outcome']['state'] == 'exists'):
                raise ValueError('Exact uncompressed F_OK result required')
            outcome(native['outcome'], attempt['outcome'], access_only=plain)
        selected = next((a['outcome'] for a in reversed(modeled['attempts'])
                         if a['outcome']['state'] == 'exists'), None)
        if selected is None:
            if row['selected'] is not None:
                raise ValueError('Unresolved fixture cannot have a selected target')
        else:
            outcome(row['selected'], selected)
    return dict(stat_lstat_queries=len(queries), selection_queries=len(worker.REFERENCE_OPERANDS),
                declared_kernel_fixture_matches_metadata_model=True,
                actual_source_namespace_equivalence_verified=False,
                native_man_db_caller_semantics_verified=False)


def drained():
    group = Path('/sys/fs/cgroup/mano.slice/mano-package.slice/mano-man-content-ci.service')
    deadline = time.monotonic()+5
    while True:
        try:
            values = dict(line.split() for line in (group/'cgroup.events').read_text().splitlines())
        except FileNotFoundError:
            return
        if values.get('populated') == '0':
            return
        if time.monotonic() >= deadline:
            raise ValueError('Source-content fixture domain did not drain')
        time.sleep(.02)


def fixture_command(base, masks, empty, config_digest):
    command = content_sandbox(base, masks, empty, config_digest)
    position = command.index(str(base/'man-source-paths.json'))
    if (command[position-1] != '--ro-bind' or command[position+1] != '/run/man-source-paths.json'
            or command[-2:] != ['/run/man-cache-guard', '--source-content']):
        raise ValueError('Only fixed read-only request binding may change')
    command[position] = str(base/'man-reference-fixture-request.json')
    unit = content_unit()
    unit[unit.index('--property=RuntimeMaxSec=190')] = '--property=RuntimeMaxSec=30'
    return unit+command


def capture_reference_fixtures(base, baseline, masks, empty, config_digest, run):
    if sys.platform != 'linux' or os.geteuid() != 0 or base != BASE:
        raise PermissionError('Fixed disposable Debian Root fixture controller required')
    from probe_package_plans import guard

    guard()
    drained()
    root = base/'man-content-cache/reference-fixtures'
    root.mkdir(mode=0o755)
    for name in sorted(worker.REFERENCE_DIRECTORIES, key=lambda name: (name.count('/'), name)):
        path = root/name
        if name:
            path.mkdir(mode=0o755)
    for name in worker.REFERENCE_FILES:
        path = root/name
        with path.open('xb') as stream:
            stream.write(b'fixed-reference-fixture:'+name.encode()+b'\n')
        path.chmod(0 if name == 'unreadable.1' else 0o644)
    for name, target in worker.REFERENCE_LINKS.items():
        os.symlink(target, root/name)
    for name, (uid, gid, mode) in worker.REFERENCE_DIRECTORIES.items():
        os.chown(root/name, uid, gid)
        (root/name).chmod(mode)
    observed = inventory(root)
    # This extra native component is omitted in the normalized model, so its
    # search permission and empty attributes are explicit preconditions.
    cache = root.parent
    cache_info = cache.lstat()
    if ((cache_info.st_uid, cache_info.st_gid, stat.S_IMODE(cache_info.st_mode)) != (6, 12, 0o755)
            or os.listxattr(cache, follow_symlinks=False)):
        raise ValueError('Known searchable private cache prefix required')
    packet = base/'man-reference-fixture-request.json'
    with packet.open('xb') as stream:
        stream.write(worker.REFERENCE_REQUEST)
    packet.chmod(0o444)
    request_before = fixture_identity(packet)
    control = base/'man-cache-control-file'
    control_before = fixture_identity(control)
    try:
        raw = bounded_capture(fixture_command(base, masks, empty, config_digest),
                              timeout=40, stdout_limit=256*1024+4097)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        # Keep bounded failure bytes in existing CI stderr custody; no 65th file.
        print(json.dumps(dict(man_reference_fixture_failure={label: base64.b64encode(
            (getattr(error, label) or b'')[:256*1024 if label == 'stdout' else 65536]).decode()
            for label in ('stdout', 'stderr')})), file=sys.stderr, flush=True)
        run(['/usr/bin/systemctl', 'stop', 'mano-man-content-ci.service'], timeout=10)
        raise
    # Preserve the bounded raw witness before parsing/comparison too. A failed
    # validation must not erase it; existing CI stderr custody needs no new file.
    print(json.dumps(dict(man_reference_fixture_capture_base64=base64.b64encode(raw).decode())),
          file=sys.stderr, flush=True)
    drained()
    after = inventory(root)
    if (after != observed or fixture_identity(packet) != request_before
            or fixture_identity(control) != control_before):
        raise ValueError('Fixed reference fixtures/request/control changed during probe')
    header, separator, body = raw.partition(b'\n')
    if not separator or len(header) > 4096 or len(body) > 256*1024:
        raise ValueError('Bounded fixed fixture framing required')
    native = json.loads(header)
    validate_native_guard(native, role='source-content')
    tree = model_tree(observed, baseline)
    comparison = compare(json.loads(body), observed, tree)
    report = dict(profile='man-fixed-reference-fixture-custody-v1',
        capture_base64=base64.b64encode(raw).decode(), capture_bytes=len(raw),
        capture_sha256=hashlib.sha256(raw).hexdigest(), guard=native,
        inventory=observed, inventory_before_sha256=hashlib.sha256(encoded(observed)).hexdigest(),
        inventory_after_sha256=hashlib.sha256(encoded(after)).hexdigest(), normalized_tree=tree,
        baseline_sha256=baseline['manifest_sha256'], fixed_request_sha256=hashlib.sha256(
            worker.REFERENCE_REQUEST).hexdigest(), domain_drained=True,
        fixtures_unchanged=True, request_unchanged=True, control_fixture_unchanged=True,
        cache_prefix_uid=6, cache_prefix_gid=12, cache_prefix_mode=0o755,
        cache_prefix_security_attributes_empty=True, native_filesystem_grants_changed=False,
        separate_process_after_source_content_drain=True,
        worker_program_sha256=hashlib.sha256((base/'man-source-content.py').read_bytes()).hexdigest(),
        controller_program_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        comparison=comparison, source_inputs_opened=False, full_source_semantics_verified=False,
        generated_state_validated=False, changes_authorized=False, publication_authorized=False)
    if len(json.dumps(report, sort_keys=True, allow_nan=False).encode()) > MAX_EMBEDDED_BYTES:
        raise ValueError('Embedded fixture evidence budget')
    return report
