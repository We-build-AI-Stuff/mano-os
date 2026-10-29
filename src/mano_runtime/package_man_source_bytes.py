"""Bound opaque manual-source acquisition; source interpretation is separate.

The fixed worker entrypoint is intended for an unprivileged confined Linux CI
process. Preparation consumes retained metadata, and never opens its paths.
The worker reads only a fixed Root-owned manifest and manual directory. It
follows no filesystem symlinks and never decompresses or executes source bytes.
"""
import base64
import hashlib
import json
import os
import re
import stat
import sys

MAX_FILES = 8192
MAX_FILE_BYTES = 1024**2
MAX_TOTAL_BYTES = 16 * 1024**2
MAX_MANIFEST_BYTES = 4 * 1024**2
MAX_OUTPUT_BYTES = 24 * 1024**2
PROFILE = 'man-source-opaque-bytes-v2'
SCOPE = 'observed-manual-root-regular-files'
STAT_FIELDS = ('uid', 'gid', 'mode', 'nlink', 'bytes', 'mtime_ns', 'ctime_ns')


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate manual source manifest field')
        result[key] = value
    return result


def relative_path(path):
    if (type(path) is not str or not path or len(path.encode()) > 4096
            or any(c in path for c in '\0\\\n\r\t')):
        raise ValueError('Bounded relative manual source path required')
    parts = path.split('/')
    if (len(parts) > 128 or any(p in {'', '.', '..'} or len(p.encode()) > 255 for p in parts)):
        raise ValueError('Canonical manual source components required')
    return parts


def manifest(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_MANIFEST_BYTES:
        raise ValueError('Bounded manual source manifest required')
    value = json.loads(raw, object_pairs_hook=unique)
    if (type(value) is not dict or set(value) !=
            {'profile', 'scope', 'baseline_sha256', 'candidate_sha256', 'indexed_files', 'files'}
            or value['profile'] != PROFILE or type(value['files']) is not dict
            or value['scope'] != SCOPE
            or not 1 <= len(value['files']) <= MAX_FILES):
        raise ValueError('Fixed opaque manual source profile required')
    for key in ('baseline_sha256', 'candidate_sha256'):
        if type(value[key]) is not str or re.fullmatch('[a-f0-9]{64}', value[key]) is None:
            raise ValueError('Exact source input layer digests required')
    total = 0
    for path, row in value['files'].items():
        relative_path(path)
        if (type(row) is not dict or set(row) != set(STAT_FIELDS) |
                {'sha256', 'observed_metadata_sha256'}
                or any(type(row[k]) is not int for k in STAT_FIELDS)
                or row['uid'] != 0 or not 0 <= row['gid'] < 2**32
                or not 0 <= row['mode'] <= 0o7777 or row['mode'] & 0o7022
                or not 1 <= row['nlink'] < 2**32
                or not 0 <= row['bytes'] <= MAX_FILE_BYTES
                or any(not -2**63 <= row[k] < 2**63 for k in ('mtime_ns', 'ctime_ns'))):
            raise ValueError('Plain bounded Root-owned source metadata required')
        for key in ('sha256', 'observed_metadata_sha256'):
            if type(row[key]) is not str or re.fullmatch('[a-f0-9]{64}', row[key]) is None:
                raise ValueError('Exact observed source metadata/content digests required')
        total += row['bytes']
        if total > MAX_TOTAL_BYTES:
            raise ValueError('Aggregate manual source byte budget')
    indexed = value['indexed_files']
    if (type(indexed) is not list or not indexed or len(indexed) > MAX_FILES
            or any(type(path) is not str for path in indexed)
            or indexed != sorted(set(indexed)) or not set(indexed) <= value['files'].keys()):
        raise ValueError('Complete distinct indexed source subset required')
    for path in indexed:
        relative_path(path)
    return value


def prepare(index_files, baseline, candidate):
    """Recompute chains from actual index bytes, rather than accept green claims."""
    from mano_runtime.package_man_source_links import inspect, metadata_hash

    graph = inspect(index_files, candidate, baseline=baseline)
    if graph['all_primary_symlink_chains_bound'] is not True:
        raise ValueError('All indexed primary source chains must bind before broad capture')
    indexed = sorted({row['terminal_path'].removeprefix('usr/share/man/')
                      for row in graph['sources'].values()
                      if row['primary_symlink_chain_bound'] is True})
    paths = sorted(path for path, row in candidate['entries'].items()
                   if path.startswith('usr/share/man/') and row['kind'] == 'file')
    files = {}
    for path in paths:
        if not path.startswith('usr/share/man/'):
            raise ValueError('Terminal source escaped the manual hierarchy')
        row = candidate['entries'][path]
        if row['kind'] != 'file':
            raise ValueError('Observed terminal regular source required')
        files[path.removeprefix('usr/share/man/')] = dict(
            **{key: row[key] for key in STAT_FIELDS}, sha256=row['sha256'],
            observed_metadata_sha256=metadata_hash(row))
    packet = json.dumps(dict(profile=PROFILE, scope=SCOPE, indexed_files=indexed,
        baseline_sha256=baseline['manifest_sha256'],
        candidate_sha256=candidate['manifest_sha256'], files=files),
        sort_keys=True, allow_nan=False).encode()
    manifest(packet)
    return packet


def observed(info):
    return dict(uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode),
                nlink=info.st_nlink, bytes=info.st_size,
                mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns)


def read_file(fd, expected):
    """Read an already opened descriptor, checking exact metadata and content."""
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or observed(before) !=
            {key: expected[key] for key in STAT_FIELDS}
            or not 0 <= before.st_size <= MAX_FILE_BYTES):
        raise ValueError('Source descriptor differs from retained metadata')
    chunks, total = [], 0
    while True:
        chunk = os.read(fd, min(65536, before.st_size + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > before.st_size:
            raise ValueError('Source grew beyond its observed size')
        chunks.append(chunk)
    after = os.fstat(fd)
    if ((before.st_dev, before.st_ino, observed(before)) !=
            (after.st_dev, after.st_ino, observed(after))):
        raise ValueError('Source identity changed during acquisition')
    raw = b''.join(chunks)
    if len(raw) != before.st_size or hashlib.sha256(raw).hexdigest() != expected['sha256']:
        raise ValueError('Source bytes differ from retained content hash')
    return raw


def read_relative(root, path, expected):
    parts = relative_path(path)
    directory = os.dup(root)
    try:
        for component in parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
            info = os.fstat(directory)
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise ValueError('Trusted real manual source parent required')
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     os.O_CLOEXEC, dir_fd=directory)
        try:
            return read_file(fd, expected)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def acquire(root, packet):
    value = manifest(packet)
    info = os.fstat(root)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022):
        raise ValueError('Trusted manual root descriptor required')
    files, total = {}, 0
    for path, expected in sorted(value['files'].items()):
        raw = read_relative(root, path, expected)
        total += len(raw)
        files[path] = base64.b64encode(raw).decode('ascii')
    result = dict(profile=PROFILE, manifest_sha256=hashlib.sha256(packet).hexdigest(),
                  files=files, source_files=len(files), source_bytes=total,
                  all_file_stat_fields_verified=True, source_content_interpreted=False,
                  changes_authorized=False, publication_authorized=False)
    encoded = json.dumps(result, sort_keys=True, allow_nan=False).encode()
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ValueError('Opaque manual source output budget')
    return encoded


def validate_capture(packet, raw):
    """Bind retained opaque bytes to every requested source, without parsing them."""
    requested = manifest(packet)
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_OUTPUT_BYTES:
        raise ValueError('Bounded opaque source worker output required')
    value = json.loads(raw, object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != {'profile', 'manifest_sha256', 'files',
            'source_files', 'source_bytes', 'all_file_stat_fields_verified',
            'source_content_interpreted', 'changes_authorized', 'publication_authorized'}
            or value['profile'] != PROFILE
            or value['manifest_sha256'] != hashlib.sha256(packet).hexdigest()
            or type(value['files']) is not dict or set(value['files']) != set(requested['files'])
            or type(value['source_files']) is not int
            or value['source_files'] != len(requested['files'])
            or value['all_file_stat_fields_verified'] is not True
            or any(value[k] is not False for k in ('source_content_interpreted',
                                                 'changes_authorized', 'publication_authorized'))):
        raise ValueError('Exact nonauthoritative opaque source capture required')
    total = 0
    for path, expected in requested['files'].items():
        encoded = value['files'][path]
        if type(encoded) is not str or len(encoded) > 4 * ((expected['bytes'] + 2) // 3):
            raise ValueError('Bounded observed source payload required')
        data = base64.b64decode(encoded, validate=True)
        if (len(data) != expected['bytes'] or hashlib.sha256(data).hexdigest() != expected['sha256']
                or base64.b64encode(data).decode('ascii') != encoded):
            raise ValueError('Captured source differs from its observed bytes')
        total += len(data)
    if type(value['source_bytes']) is not int or value['source_bytes'] != total:
        raise ValueError('Exact aggregate captured byte count required')
    return dict(profile=PROFILE, manifest_sha256=hashlib.sha256(packet).hexdigest(),
                worker_sha256=hashlib.sha256(raw).hexdigest(), worker_bytes=len(raw),
                source_files=len(requested['files']), source_bytes=total,
                scope=SCOPE, indexed_source_files=len(requested['indexed_files']),
                additional_manual_files=len(requested['files'])-len(requested['indexed_files']),
                all_captured_content_hashes_match=True, source_content_interpreted=False,
                changes_authorized=False, publication_authorized=False)


def main():
    if (sys.platform != 'linux' or os.getresuid() != (6, 6, 6)
            or os.getresgid() != (12, 12, 12) or os.getgroups() != [] or len(sys.argv) != 1):
        raise PermissionError('Fixed unprivileged Linux manual source worker required')
    fd = os.open('/run/man-source-paths.json', os.O_RDONLY | os.O_NOFOLLOW |
                 os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o444
                or not 0 < before.st_size <= MAX_MANIFEST_BYTES):
            raise ValueError('Fixed immutable Root-owned source manifest required')
        packet = stream.read(MAX_MANIFEST_BYTES + 1)
        after = os.fstat(stream.fileno())
        if (len(packet) != before.st_size or
                (before.st_dev, before.st_ino, observed(before)) !=
                (after.st_dev, after.st_ino, observed(after))):
            raise ValueError('Source manifest changed during acquisition')
    root = os.open('/usr/share/man', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        encoded = acquire(root, packet)
    finally:
        os.close(root)
    sys.stdout.buffer.write(encoded + b'\n')


if __name__ == '__main__':
    main()
