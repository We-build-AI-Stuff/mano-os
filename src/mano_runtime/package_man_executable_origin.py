"""Hold the fixed baseline mandb object across disposable-CI generation.

Only hold() opens files and it requires the disposable Linux Root guard before
any filesystem access. Pure identity/content comparisons grant no publication,
collector authentication, transitive runtime or loader-selection authority.
"""
import base64
import contextlib
import hashlib
import json
import os
import stat

from mano_runtime import package_man_runtime_origin as origin
from mano_runtime.package_man_elf_memory import bind

PATH = 'usr/bin/mandb'
MAX_BYTES = 512 * 1024
MAX_PACKET_BYTES = 1024**2


def checked_identity(row):
    if (type(row) is not dict or set(row) != origin.FIELDS
            or type(row['device']) is not list or len(row['device']) != 2
            or any(type(v) is not int or not 0 <= v < 2**32 for v in row['device'])
            or any(type(row[k]) is not int for k in (
                'inode', 'uid', 'gid', 'mode', 'bytes', 'nlink', 'mtime_ns', 'ctime_ns'))
            or not 0 < row['inode'] < 2**64 or row['uid'] != 0
            or not 0 <= row['gid'] < 2**32 or not 0 <= row['mode'] <= 0o7777
            or row['mode'] & 0o022 or row['kind'] != 'file'
            or not row['mode'] & (0o010 if row['gid'] == 12 else 0o001)
            or not 64 <= row['bytes'] <= MAX_BYTES or not 0 < row['nlink'] < 2**64
            or any(not -2**63 <= row[k] < 2**63 for k in ('mtime_ns', 'ctime_ns'))):
        raise ValueError('Exact Root-owned nonwritable executable identity required')
    return row


def checked_native(value):
    if (type(value) is not dict or set(value) != {'profile', 'path', 'execution_method',
            'descriptor_cloexec', 'readonly_mount', 'identity'}
            or value['profile'] != 'man-fixed-mandb-execfd-v1'
            or value['path'] != '/'+PATH or value['execution_method'] != 'execveat-empty-path'
            or value['descriptor_cloexec'] is not True or value['readonly_mount'] is not True):
        raise ValueError('Fixed readonly close-on-exec mandb descriptor launch required')
    checked_identity(value['identity'])
    return value


def bind_held_bytes(raw, baseline, identity):
    if type(raw) is not bytes or not 64 <= len(raw) <= MAX_BYTES:
        raise ValueError('Bounded retained fixed executable bytes required')
    checked_identity(identity)
    bound = bind(raw, baseline, PATH)
    observed = baseline['entries'][PATH]
    if any(identity[key] != observed[key] for key in (
            'uid', 'gid', 'mode', 'kind', 'bytes', 'nlink', 'mtime_ns', 'ctime_ns')):
        raise ValueError('Held executable metadata differs from observed baseline entry')
    return bound


def compare(raw, baseline, before, after, native):
    """Bind byte evidence and the actual native descriptor to held Root identity.

    The caller must retain the Root FD and require successful, fully drained
    native generation. This comparison alone cannot prove that exec completed.
    """
    if type(raw) is not bytes or not 64 <= len(raw) <= MAX_BYTES:
        raise ValueError('Bounded retained fixed executable bytes required')
    checked_identity(before)
    checked_identity(after)
    checked_native(native)
    if before != after or before != native['identity'] or before['bytes'] != len(raw):
        raise ValueError('Native executable descriptor differs from stable held baseline object')
    bound = bind_held_bytes(raw, baseline, before)
    packet = dict(profile='man-fixed-executable-source-binding-v1',
        raw_base64=base64.b64encode(raw).decode(), raw_bytes=len(raw),
        raw_sha256=hashlib.sha256(raw).hexdigest(), root_before=before, root_after=after,
        native_source=native, baseline_binding=bound,
        held_source_identity_stable=True, native_source_identity_matches=True,
        collector_authentication_verified=False, complete_runtime_closure_verified=False,
        loader_selection_verified=False, generated_state_validated=False,
        changes_authorized=False, publication_authorized=False)
    if len(json.dumps(packet, sort_keys=True, allow_nan=False).encode()) > MAX_PACKET_BYTES:
        raise ValueError('Bounded embedded executable source packet required')
    return packet


class HeldExecutable:
    def __init__(self, fd, raw, before):
        self.fd, self.raw, self.before = fd, raw, before

    def observe(self):
        origin._readonly_snapshot()
        return checked_identity(origin.identity(os.fstat(self.fd)))


@contextlib.contextmanager
def hold(baseline):
    """Read and hold one fixed regular source FD; never execute the file."""
    origin.root_guard()  # Must precede even the first filesystem operation.
    from mano_runtime.package_candidate import parent_fd

    base = snapshot = parent = fd = None
    try:
        base = os.open(origin.BASE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(base)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise PermissionError('Fixed private Root staging directory required')
        snapshot = os.open('baseline', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                           | os.O_CLOEXEC, dir_fd=base)
        origin._readonly_snapshot()
        parent = parent_fd(snapshot, PATH)
        fd = os.open('mandb', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        before = checked_identity(origin.identity(os.fstat(fd)))
        parts, count = [], 0
        while data := os.read(fd, min(65536, before['bytes']-count+1)):
            parts.append(data)
            count += len(data)
            if count > before['bytes']:
                raise ValueError('Fixed executable grew during retained read')
        raw = b''.join(parts)
        if count != before['bytes'] or origin.identity(os.fstat(fd)) != before:
            raise ValueError('Fixed executable changed during retained read')
        bind_held_bytes(raw, baseline, before)
        holder = HeldExecutable(fd, raw, before)
        if holder.observe() != before:
            raise ValueError('Executable source changed before launch')
        yield holder
    finally:
        for descriptor in (fd, parent, snapshot, base):
            if descriptor is not None:
                os.close(descriptor)
