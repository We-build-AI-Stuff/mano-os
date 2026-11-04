"""Hold baseline interpreter bytes across disposable-CI cache generation.

This captures a Root-held source, not the object selected by the kernel loader.
No execution, namespace grants or publication authority are supplied here.
"""
import base64
import contextlib
import hashlib
import json
import os
import stat

from mano_runtime import package_man_executable_origin as executable
from mano_runtime import package_man_interpreter as interpreter
from mano_runtime import package_man_runtime_origin as origin

MAX_BYTES = executable.MAX_BYTES
MAX_PACKET_BYTES = 1024**2


def bind_held_bytes(main_raw, raw, baseline, identity):
    if type(raw) is not bytes or not 64 <= len(raw) <= MAX_BYTES:
        raise ValueError('Bounded retained interpreter bytes required')
    executable.checked_identity(identity)
    binding = interpreter.bind(main_raw, raw, baseline)
    metadata = binding['selection']['resolved_metadata']
    if any(identity[key] != metadata[key] for key in (
            'uid', 'gid', 'mode', 'kind', 'bytes', 'nlink', 'mtime_ns', 'ctime_ns')):
        raise ValueError('Held interpreter metadata differs from observed baseline')
    return binding


def compare(main_raw, raw, baseline, before, after):
    executable.checked_identity(before)
    executable.checked_identity(after)
    if before != after:
        raise ValueError('Held interpreter object changed across generation')
    binding = bind_held_bytes(main_raw, raw, baseline, before)
    packet = dict(profile='man-held-interpreter-source-v1',
        main_raw_sha256=hashlib.sha256(main_raw).hexdigest(),
        raw_base64=base64.b64encode(raw).decode(), raw_bytes=len(raw),
        raw_sha256=hashlib.sha256(raw).hexdigest(), root_before=before, root_after=after,
        interpreter_binding=binding, held_source_identity_stable=True,
        interpreter_bytes_bound=True, actual_kernel_loading_verified=False,
        readonly_kernel_source_verified=False, collector_authentication_verified=False,
        complete_runtime_closure_verified=False, loader_selection_verified=False,
        generated_state_validated=False, changes_authorized=False, publication_authorized=False)
    if len(json.dumps(packet, sort_keys=True, allow_nan=False).encode()) > MAX_PACKET_BYTES:
        raise ValueError('Bounded embedded interpreter packet required')
    return packet


class HeldInterpreter:
    def __init__(self, fd, raw, before):
        self.fd, self.raw, self.before = fd, raw, before

    def observe(self):
        origin._readonly_snapshot()
        return executable.checked_identity(origin.identity(os.fstat(self.fd)))


@contextlib.contextmanager
def hold(baseline, main_raw):
    origin.root_guard()  # Must precede every filesystem operation.
    from mano_runtime.package_candidate import parent_fd

    selected = interpreter.resolve(main_raw, baseline)
    path = selected['resolved_path']
    base = snapshot = parent = fd = None
    try:
        base = os.open(origin.BASE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(base)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise PermissionError('Fixed private Root staging directory required')
        snapshot = os.open('baseline', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                           | os.O_CLOEXEC, dir_fd=base)
        origin._readonly_snapshot()
        parent = parent_fd(snapshot, path)
        fd = os.open(path.rsplit('/', 1)[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | os.O_CLOEXEC, dir_fd=parent)
        before = executable.checked_identity(origin.identity(os.fstat(fd)))
        parts, count = [], 0
        while data := os.read(fd, min(65536, before['bytes']-count+1)):
            parts.append(data)
            count += len(data)
            if count > before['bytes']:
                raise ValueError('Interpreter grew during retained read')
        raw = b''.join(parts)
        if count != before['bytes'] or origin.identity(os.fstat(fd)) != before:
            raise ValueError('Interpreter changed during retained read')
        bind_held_bytes(main_raw, raw, baseline, before)
        held = HeldInterpreter(fd, raw, before)
        if held.observe() != before:
            raise ValueError('Interpreter changed before generation')
        yield held
    finally:
        for descriptor in (fd, parent, snapshot, base):
            if descriptor is not None:
                os.close(descriptor)
