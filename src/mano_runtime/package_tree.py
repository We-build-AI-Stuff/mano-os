"""Linux descriptor-relative tree observation; no extraction or publication.

The caller must own an immutable/drained private root. Controller snapshots under
.snapshots are explicitly excluded, not silently considered verified. Captures
content, link relationships and xattr hashes; never interprets xattrs as policy.
"""
import hashlib
import json
import os
import stat
import sys

from mano_runtime.package_candidate import identity
from mano_runtime.package_payload import path_name

MAX_ENTRIES = 200_000
MAX_BYTES = 4 * 1024**3
MAX_METADATA = 64 * 1024**2
EXCLUDED = {'.snapshots'}


def xattrs(target, *, symlink=False):
    names = os.listxattr(target, follow_symlinks=not symlink)
    if len(names) > 64:
        raise ValueError('Extended attribute count budget')
    result, total = {}, 0
    for name in sorted(names):
        if len(name.encode('utf8')) > 255:
            raise ValueError('Extended attribute name budget')
        value = os.getxattr(target, name, follow_symlinks=not symlink)
        if len(value) > 65536:
            raise ValueError('Extended attribute byte budget')
        total += len(value)
        result[name] = dict(bytes=len(value), sha256=hashlib.sha256(value).hexdigest())
    return result, total


def scan(root_fd, *, checkpoint=None):
    if sys.platform != 'linux' or not hasattr(os, 'listxattr'):
        raise PermissionError('Linux tree metadata observation required')
    if checkpoint is not None and not callable(checkpoint):
        raise ValueError('Callable interruption checkpoint required')
    check = checkpoint if checkpoint is not None else (lambda: None)
    root = os.dup(root_fd)
    entries, links = {}, {}
    total, metadata, attribute_bytes = 0, 0, 0
    try:
        root_info = os.fstat(root)
        if not stat.S_ISDIR(root_info.st_mode):
            raise ValueError('Owned directory descriptor required')

        def visit(parent, leaf, name, depth):
            nonlocal total, metadata, attribute_bytes
            # No caller-selected exclusions or pathname-based recursion.
            check()
            if depth > 128 or len(entries) >= MAX_ENTRIES:
                raise ValueError('Tree entry/depth budget')
            info = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            if info.st_dev != root_info.st_dev:
                raise ValueError('Unexpected filesystem boundary in candidate tree')
            row = dict(uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode),
                       mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns,
                       nlink=info.st_nlink)
            fd = None
            try:
                if stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode):
                    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                    if stat.S_ISDIR(info.st_mode):
                        flags |= os.O_DIRECTORY
                    fd = os.open(leaf, flags, dir_fd=parent)
                    if identity(os.fstat(fd)) != identity(info):
                        raise ValueError('Tree object changed before observation')
                    row['xattrs'], size = xattrs(fd)
                else:
                    target = '/proc/self/fd/' + str(parent) + '/' + leaf
                    row['xattrs'], size = xattrs(target, symlink=True)
                attribute_bytes += size
                if attribute_bytes > MAX_METADATA:
                    raise ValueError('Tree extended attribute aggregate budget')
                if stat.S_ISREG(info.st_mode):
                    if info.st_size < 0 or total + info.st_size > MAX_BYTES:
                        raise ValueError('Tree content byte budget')
                    digest, count = hashlib.sha256(), 0
                    while piece := os.read(fd, min(65536, info.st_size-count+1)):
                        check()
                        count += len(piece)
                        if count > info.st_size:
                            raise ValueError('Tree file grew during observation')
                        digest.update(piece)
                    if count != info.st_size:
                        raise ValueError('Tree file truncated during observation')
                    total += count
                    row.update(kind='file', bytes=count, sha256=digest.hexdigest())
                    links.setdefault((info.st_dev, info.st_ino), []).append(name)
                elif stat.S_ISDIR(info.st_mode):
                    row['kind'] = 'directory'
                elif stat.S_ISLNK(info.st_mode):
                    target = os.readlink(leaf, dir_fd=parent)
                    if len(target.encode('utf8')) > 4096 or '\0' in target:
                        raise ValueError('Tree symlink target budget')
                    row.update(kind='symlink', target=target)
                elif stat.S_ISFIFO(info.st_mode):
                    row['kind'] = 'fifo'
                elif stat.S_ISSOCK(info.st_mode):
                    row['kind'] = 'socket'
                elif stat.S_ISCHR(info.st_mode) or stat.S_ISBLK(info.st_mode):
                    row.update(kind='character' if stat.S_ISCHR(info.st_mode) else 'block',
                               device_major=os.major(info.st_rdev),
                               device_minor=os.minor(info.st_rdev))
                else:
                    raise ValueError('Unsupported tree object type')
                metadata += len(name.encode('utf8')) + len(json.dumps(row, sort_keys=True).encode())
                if metadata > MAX_METADATA:
                    raise ValueError('Tree metadata byte budget')
                entries[name] = row
                if row['kind'] == 'directory':
                    children = []
                    with os.scandir(fd) as iterator:
                        for child in iterator:
                            children.append(child.name)
                            if len(children) + len(entries) > MAX_ENTRIES:
                                raise ValueError('Tree directory listing budget')
                    for child in sorted(children):
                        relative = child if name == '.' else name + '/' + child
                        if relative in EXCLUDED:
                            continue
                        if path_name(relative) != relative:
                            raise ValueError('Canonical tree path required')
                        visit(fd, child, relative, depth+1)
                if (identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) != identity(info)
                        or (fd is not None and identity(os.fstat(fd)) != identity(info))):
                    raise ValueError('Tree object changed during observation')
            finally:
                if fd is not None:
                    os.close(fd)

        visit(root, '.', '.', 0)
        external_links = []
        for paths in links.values():
            anchor = min(paths)
            for name in paths:
                entries[name]['hardlink_anchor'] = anchor
                if entries[name]['nlink'] != len(paths):
                    external_links.append(name)
        canonical = json.dumps(entries, sort_keys=True, separators=(',', ':'),
                               ensure_ascii=True, allow_nan=False).encode()
        if len(canonical) > MAX_METADATA:
            raise ValueError('Final tree manifest budget')
        check()
        return dict(schema_version='1.0', entries=entries,
                    manifest_sha256=hashlib.sha256(canonical).hexdigest(),
                    file_bytes=total, xattr_value_bytes=attribute_bytes,
                    excluded_subtrees=sorted(EXCLUDED), unobserved_hardlinks=sorted(external_links),
                    full_root_verified=False, immutable_root_verified=False,
                    candidate_filesystem_verified=False, publication_authorized=False)
    finally:
        os.close(root)


def delta(before, after):
    """Report every observed addition/removal/change; never whitelist effects."""
    for value in (before, after):
        entries = value['entries']
        if (value.get('schema_version') != '1.0' or not isinstance(entries, dict)
                or not 1 <= len(entries) <= MAX_ENTRIES
                or value.get('excluded_subtrees') != sorted(EXCLUDED)):
            raise ValueError('Compatible bounded tree observations required')
        canonical = json.dumps(entries, sort_keys=True, separators=(',', ':'),
                               ensure_ascii=True, allow_nan=False).encode()
        if (len(canonical) > MAX_METADATA or
                hashlib.sha256(canonical).hexdigest() != value['manifest_sha256']):
            raise ValueError('Tree observation integrity changed')
    changed, added, removed, modified = {}, 0, 0, 0
    for name in sorted(before['entries'].keys() | after['entries'].keys()):
        left, right = before['entries'].get(name), after['entries'].get(name)
        if left == right:
            continue
        changed[name] = dict(before=left, after=right)
        added += left is None
        removed += right is None
        modified += left is not None and right is not None
    return dict(schema_version='1.0', before_sha256=before['manifest_sha256'],
                after_sha256=after['manifest_sha256'], changes=changed,
                added=added, removed=removed, modified=modified,
                excluded_subtrees=sorted(EXCLUDED), changes_authorized=False,
                baseline_custody_verified=False, candidate_filesystem_verified=False,
                publication_authorized=False)
