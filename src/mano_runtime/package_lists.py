"""Validate generated new-package file lists against authenticated payloads.

No arbitrary path authorization, extraction or publication. Caller must drain all
candidate writers and retain private descriptor custody throughout observation.
"""
import base64
import hashlib
import json
import os
import stat

from mano_runtime.package_candidate import identity, parent_fd
from mano_runtime.package_payload import MAX_ENTRIES, MAX_METADATA, path_name

MAX_LIST = 4 * 1024**2


def validate(data, payload, *, checkpoint=None):
    if checkpoint is not None and not callable(checkpoint):
        raise ValueError('Callable interruption checkpoint required')
    check = checkpoint if checkpoint is not None else (lambda: None)
    check()
    if (type(data) is not bytes or not 0 < len(data) <= MAX_LIST or not data.endswith(b'\n')
            or b'\0' in data or b'\r' in data):
        raise ValueError('Bounded LF-terminated dpkg file list required')
    entries = payload['entries']
    if (payload.get('schema_version') != '1.0' or not isinstance(entries, dict)
            or not 1 <= len(entries) <= MAX_ENTRIES or payload.get('unsupported_metadata') != {}):
        raise ValueError('Supported authenticated payload inventory required')
    if data.count(b'\n') != len(entries):
        raise ValueError('Generated file list entry count differs from payload')
    canonical = json.dumps(entries, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=True, allow_nan=False).encode()
    if (len(canonical) > MAX_METADATA or hashlib.sha256(canonical).hexdigest()
            != payload['manifest_sha256']):
        raise ValueError('Payload inventory integrity changed')
    expected = set()
    for path, row in entries.items():
        check()
        if (path_name(path, directory=row['kind'] == 'directory') != path
                or any(character in path for character in ('\n', '\r', '\0'))):
            raise ValueError('Unambiguous canonical payload paths required')
        expected.add('/.' if path == '.' else '/' + path)
    paths = data.decode('utf8', errors='strict').split('\n')[:-1]
    if len(paths) != len(set(paths)) or set(paths) != expected:
        raise ValueError('Generated file list differs from authenticated payload paths')
    check()
    return dict(schema_version='1.0', payload_paths_verified=len(paths),
                list_sha256=hashlib.sha256(data).hexdigest(), list_bytes=len(data),
                payload_manifest_sha256=payload['manifest_sha256'],
                file_list_paths_verified=True, all_generated_state_validated=False,
                changes_authorized=False, publication_authorized=False)


def read_owned(root_fd, path, expected, *, checkpoint=None):
    """Read one stable regular list, refusing aliases and observation drift."""
    if checkpoint is not None and not callable(checkpoint):
        raise ValueError('Callable interruption checkpoint required')
    check = checkpoint if checkpoint is not None else (lambda: None)
    if (path_name(path) != path or expected['kind'] != 'file'
            or any(type(expected[key]) is not int for key in (
                'uid', 'gid', 'mode', 'nlink', 'bytes', 'mtime_ns', 'ctime_ns'))
            or (expected['mode'], expected['nlink']) != (0o644, 1) or expected['xattrs']
            or expected['hardlink_anchor'] != path
            or not 0 < expected['bytes'] <= MAX_LIST):
        raise ValueError('Private plain generated list required')
    check()
    parent = parent_fd(root_fd, path)
    try:
        fd = os.open(path.rsplit('/', 1)[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_dev != os.fstat(root_fd).st_dev
                    or any(value != expected[key] for key, value in (
                        ('uid', info.st_uid), ('gid', info.st_gid),
                        ('mode', stat.S_IMODE(info.st_mode)), ('nlink', info.st_nlink),
                        ('bytes', info.st_size), ('mtime_ns', info.st_mtime_ns),
                        ('ctime_ns', info.st_ctime_ns)))):
                raise ValueError('Generated list no longer matches drained tree metadata')
            data = bytearray()
            while piece := os.read(fd, min(65536, expected['bytes'] - len(data) + 1)):
                check()
                data.extend(piece)
                if len(data) > expected['bytes']:
                    raise ValueError('Generated list grew during observation')
            if (len(data) != expected['bytes'] or identity(os.fstat(fd)) != identity(info)
                    or identity(os.stat(path.rsplit('/', 1)[-1], dir_fd=parent,
                                        follow_symlinks=False)) != identity(info)
                    or hashlib.sha256(data).hexdigest() != expected['sha256']):
                raise ValueError('Generated list bytes or identity changed')
            check()
            return bytes(data)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def observe(root_fd, tree, records, observations, *, checkpoint=None):
    reports = {}
    for record in records:
        if record['name'] in reports:
            raise ValueError('Distinct generated list package identities required')
        fields = observations[record['name']]['control']['fields']
        if (fields['package'], fields['architecture'], fields['version']) != (
                record['name'], record['architecture'], record['version']):
            raise ValueError('Bound authenticated list identity required')
        prefix = fields['package'] + (':' + fields['architecture']
                                     if fields.get('multi-arch') == 'same' else '')
        path = 'var/lib/dpkg/info/' + prefix + '.list'
        expected = tree['entries'][path]
        if (expected['uid'], expected['gid']) != (0, 0):
            raise ValueError('Root-owned package file list required')
        data = read_owned(root_fd, path, expected, checkpoint=checkpoint)
        reports[record['name']] = validate(data, observations[record['name']]['payload'],
                                            checkpoint=checkpoint) | {
            'path': path, 'data_base64': base64.b64encode(data).decode('ascii')}
    return dict(schema_version='1.0', packages=reports, all_generated_state_validated=False,
                changes_authorized=False, candidate_filesystem_verified=False,
                publication_authorized=False)
