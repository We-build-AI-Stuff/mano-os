"""Compare inventoried payload paths through an already-owned directory FD.

The caller must first drain every candidate writer and keep the candidate private.
This observes listed paths only: it cannot certify extra/generated files, merged
package conflicts, baseline changes, signature trust or publication authority.
"""

import hashlib
import json
import os
import stat

from mano_runtime.package_payload import MAX_ENTRIES, MAX_FILE, MAX_PAYLOAD, path_name


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def parent_fd(root, name):
    """Own one descriptor at a time, refusing every intermediate symlink."""
    current = os.dup(root)
    try:
        for part in name.split('/')[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def compare_payload(root_fd, manifest, *, checkpoint=None):
    """Require listed payload bytes/link targets/ownership/modes to agree.

    Directory ownership/modes/times and all timestamps are deliberately outside
    this comparison. Dpkg can reuse shared directories; those need baseline-aware
    policy. An agreement here is never complete candidate filesystem validation.
    """
    if checkpoint is not None and not callable(checkpoint):
        raise ValueError('Callable interruption checkpoint required')
    check = checkpoint if checkpoint is not None else (lambda: None)
    entries = manifest['entries']
    if (not isinstance(entries, dict) or not 1 <= len(entries) <= MAX_ENTRIES
            or manifest.get('unsupported_metadata') != {}):
        raise ValueError('Bounded supported payload inventory required')
    canonical = json.dumps(entries, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=True, allow_nan=False).encode()
    if hashlib.sha256(canonical).hexdigest() != manifest['manifest_sha256']:
        raise ValueError('Payload manifest integrity changed')
    root = os.dup(root_fd)
    total, observed, hardlinks = 0, {}, []
    try:
        if not stat.S_ISDIR(os.fstat(root).st_mode):
            raise ValueError('Owned candidate directory descriptor required')
        for name, entry in entries.items():
            check()
            kind = entry['kind']
            if path_name(name, directory=kind == 'directory') != name:
                raise ValueError('Canonical inventoried path required')
            if kind not in {'directory', 'file', 'hardlink', 'symlink'}:
                raise ValueError('Unsupported candidate payload object')
            parent = parent_fd(root, name)
            leaf = name.split('/')[-1]
            try:
                info = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                if kind == 'directory':
                    if not stat.S_ISDIR(info.st_mode):
                        raise ValueError('Candidate directory type differs')
                else:
                    if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (
                            entry['uid'], entry['gid'], entry['mode']):
                        raise ValueError('Candidate payload ownership or mode differs')
                    if kind == 'symlink':
                        if (not stat.S_ISLNK(info.st_mode) or
                                os.readlink(leaf, dir_fd=parent) != entry['target']):
                            raise ValueError('Candidate literal symlink differs')
                    else:
                        if not stat.S_ISREG(info.st_mode):
                            raise ValueError('Candidate regular payload type differs')
                        if kind == 'hardlink':
                            hardlinks.append((name, entry['content_path']))
                        else:
                            size = entry['bytes']
                            if (type(size) is not int or not 0 <= size <= MAX_FILE
                                    or info.st_size != size or total + size > MAX_PAYLOAD):
                                raise ValueError('Candidate payload size or budget differs')
                            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                         dir_fd=parent)
                            try:
                                if identity(os.fstat(fd)) != identity(info):
                                    raise ValueError('Candidate object changed before reading')
                                digest, count = hashlib.sha256(), 0
                                while piece := os.read(fd, min(65536, size - count + 1)):
                                    check()
                                    count += len(piece)
                                    if count > size:
                                        raise ValueError('Candidate payload grew while reading')
                                    digest.update(piece)
                                if (count != size or digest.hexdigest() != entry['sha256']
                                        or identity(os.fstat(fd)) != identity(info)):
                                    raise ValueError('Candidate payload bytes or identity differ')
                                total += count
                            finally:
                                os.close(fd)
                if identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) != identity(info):
                    raise ValueError('Candidate path changed during observation')
                observed[name] = info
            finally:
                os.close(parent)
        for name, target in hardlinks:
            check()
            if (target not in entries or entries[target]['kind'] != 'file'
                    or (observed[name].st_dev, observed[name].st_ino) != (
                        observed[target].st_dev, observed[target].st_ino)):
                raise ValueError('Candidate hardlink provenance differs')
        check()
    finally:
        os.close(root)
    return dict(schema_version='1.0', payload_paths_match=True,
                observed_paths=len(observed), observed_file_bytes=total,
                manifest_sha256=manifest['manifest_sha256'],
                timestamps_compared=False, directory_metadata_compared=False,
                unlisted_mutations_checked=False, baseline_changes_checked=False,
                archive_signature_verified=False, candidate_filesystem_verified=False,
                publication_authorized=False)
