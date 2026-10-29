"""Retain bounded changed man-index bytes as data, never generated-state authority.

Readers belong to the controller's immutable baseline and drained candidate.
No database library is imported, no cache record is parsed and nothing executes.
"""
import hashlib
import os
import re
import stat

from mano_runtime.package_candidate import identity, parent_fd
from mano_runtime.package_tree import delta

MAX_DATABASES = 8
MAX_DATABASE_BYTES = 2 * 1024**2
MAX_TOTAL_BYTES = 8 * 1024**2


def index_path(path):
    return (isinstance(path, str)
            and re.fullmatch(r'var/cache/man/(?:[A-Za-z0-9_@.+-]{1,64}/)?index\.db', path)
            is not None and all(part not in {'.', '..'} for part in path.split('/')))


def read_index(root_fd, path, maximum, expected):
    """Read only the observed regular file through an owned snapshot descriptor."""
    if not index_path(path) or type(maximum) is not int or not 0 < maximum <= MAX_DATABASE_BYTES:
        raise ValueError('Fixed bounded man-index path required')
    return _read_index(root_fd, path, maximum, expected)


def read_regenerated_index(root_fd, path, maximum, expected):
    """The root descriptor is the separate drained fresh-cache tmpfs."""
    if (not index_path('var/cache/man/' + path) or type(maximum) is not int
            or not 0 < maximum <= MAX_DATABASE_BYTES):
        raise ValueError('Fixed bounded regenerated index path required')
    return _read_index(root_fd, path, maximum, expected)


def _read_index(root_fd, path, maximum, expected):
    parent = parent_fd(root_fd, path)
    try:
        leaf = path.rsplit('/', 1)[-1]
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            actual = (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode),
                      before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            if (not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= maximum
                    or actual != tuple(expected[k] for k in
                        ('uid', 'gid', 'mode', 'nlink', 'bytes', 'mtime_ns', 'ctime_ns'))):
                raise ValueError('Man-index metadata differs from observed tree')
            data = bytearray()
            while len(data) <= before.st_size:
                piece = os.read(fd, min(65536, before.st_size + 1 - len(data)))
                if not piece:
                    break
                data.extend(piece)
            if (len(data) != before.st_size or identity(before) != identity(os.fstat(fd))
                    or identity(before) != identity(os.stat(leaf, dir_fd=parent,
                                                           follow_symlinks=False))):
                raise ValueError('Man-index changed while reading')
            return bytes(data)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def collect(baseline, candidate, read_baseline, read_candidate):
    changes = delta(baseline, candidate)['changes']
    paths = sorted(path for path in changes if index_path(path))
    if len(paths) > MAX_DATABASES:
        raise ValueError('Changed man-index count budget')
    artifacts, databases, total = {}, {}, 0
    for number, path in enumerate(paths):
        rows = {}
        for role, tree, read in (('baseline', baseline, read_baseline),
                                 ('candidate', candidate, read_candidate)):
            row = tree['entries'].get(path)
            rows[role] = None
            if row is None:
                continue
            if (row.get('kind') != 'file' or any(type(row[k]) is not int for k in
                    ('uid', 'gid', 'mode', 'nlink', 'bytes'))
                    or (row['uid'], row['gid'], row['mode'], row['nlink']) != (6, 12, 0o644, 1)
                    or row['xattrs'] != {} or row['hardlink_anchor'] != path
                    or not 0 <= row['bytes'] <= MAX_DATABASE_BYTES
                    or total + row['bytes'] > MAX_TOTAL_BYTES):
                raise ValueError('Bounded plain single-link man-index observation required')
            data = read(path, MAX_DATABASE_BYTES)
            if (type(data) is not bytes or len(data) != row['bytes']
                    or hashlib.sha256(data).hexdigest() != row['sha256']):
                raise ValueError('Man-index bytes differ from observed tree')
            artifact = f'staged-man-index-{number}-{role}.db'
            artifacts[artifact] = data
            rows[role] = dict(artifact=artifact, bytes=len(data), sha256=row['sha256'])
            total += len(data)
        databases[path] = rows
    return dict(schema_version='1.0', profile='changed-man-index-bytes-v1',
                baseline_sha256=baseline['manifest_sha256'],
                candidate_sha256=candidate['manifest_sha256'], databases=databases,
                files=len(artifacts), bytes=total, database_records_decoded=False,
                cache_sources_verified=False, cache_regeneration_verified=False,
                generated_state_validated=False, changes_authorized=False,
                publication_authorized=False), artifacts
