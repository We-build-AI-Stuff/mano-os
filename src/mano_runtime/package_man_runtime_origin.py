"""Fixed descriptor identity comparison for the CI manual-generation sources.

The Root controller must hold the source descriptors across a fully drained
worker. Matching observations bind the ten named objects only; they do not
establish transitive runtime, loader, plugin or publication authority.
Capture is disposable-Linux-Root only. Pure comparison never opens paths.
"""
import contextlib
import os
import stat
import subprocess
import sys
from pathlib import Path

BASE = Path('/.snapshots/.mano-staged-package-ci')
BASELINE = ('/usr/bin', '/usr/lib', '/etc/manpath.config', '/etc/ld.so.cache',
            '/etc/nsswitch.conf', '/etc/passwd', '/etc/group', '/etc/locale.alias')
INJECTED = {'/run/man-cache-guard': 'man-cache-guard',
            '/run/man-regeneration.py': 'man-regeneration.py'}
TARGETS = set(BASELINE) | set(INJECTED)
FIELDS = {'device', 'inode', 'uid', 'gid', 'mode', 'kind', 'bytes', 'nlink',
          'mtime_ns', 'ctime_ns'}


def identity(info):
    """Serialize fstat identity, deliberately excluding read-sensitive atime."""
    return dict(device=[os.major(info.st_dev), os.minor(info.st_dev)],
        inode=info.st_ino, uid=info.st_uid, gid=info.st_gid,
        mode=stat.S_IMODE(info.st_mode),
        kind='directory' if stat.S_ISDIR(info.st_mode) else
             'file' if stat.S_ISREG(info.st_mode) else 'unsupported',
        bytes=info.st_size, nlink=info.st_nlink,
        mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns)


def checked(value):
    if type(value) is not dict or set(value) != TARGETS:
        raise ValueError('All ten fixed descriptor source identities required')
    for target, row in value.items():
        if (type(row) is not dict or set(row) != FIELDS
                or type(row['device']) is not list or len(row['device']) != 2
                or any(type(v) is not int or not 0 <= v < 2**32 for v in row['device'])
                or any(type(row[k]) is not int for k in
                       ('inode', 'uid', 'gid', 'mode', 'bytes', 'nlink',
                        'mtime_ns', 'ctime_ns'))
                or not 0 < row['inode'] < 2**64 or row['uid'] != 0
                or not 0 <= row['gid'] < 2**32
                or not 0 <= row['mode'] <= 0o7777 or row['mode'] & 0o022
                or not 0 <= row['bytes'] < 2**63 or not 0 < row['nlink'] < 2**64
                or any(not -2**63 <= row[k] < 2**63 for k in ('mtime_ns', 'ctime_ns'))
                or row['kind'] != ('directory' if target in {'/usr/bin', '/usr/lib'}
                                   else 'file')):
            raise ValueError('Exact Root-owned nonwritable descriptor identity required')
    return value


def compare(before, after, worker):
    """Compare retained source FDs with actual child FDs, never nominal names.

    The caller supplies trusted Root-captured before/after observations and the
    source-bound worker's raw fstat observations, under the existing readonly
    mount check. This function alone does not authenticate those collectors.
    """
    checked(before)
    checked(after)
    checked(worker)
    if before != after or before != worker:
        raise ValueError('Worker source object or held source identity differs')
    return dict(profile='man-named-runtime-descriptor-identities-v1',
        named_objects=10, baseline_objects=8, injected_objects=2,
        held_source_identities_stable=True, worker_source_identities_match=True,
        collector_authentication_verified=False,
        complete_runtime_closure_verified=False, loader_selection_verified=False,
        generated_state_validated=False, changes_authorized=False,
        publication_authorized=False)


def root_guard():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise PermissionError('Disposable Linux Root source holder only')
    from probe_package_plans import guard

    from mano_runtime import recovery

    guard()
    recovery.root_guard()


def _readonly_snapshot():
    # Keep the controller's Btrfs snapshot-property contract distinct from
    # the worker's per-mount VFS readonly contract. The source directory is
    # reached through the controller's existing writable root mount.
    raw = subprocess.check_output(['/usr/bin/btrfs', 'property', 'get',
                                   str(BASE / 'baseline'), 'ro'], timeout=5)
    if raw.strip() != b'ro=true':
        raise PermissionError('Read-only Btrfs baseline snapshot required')


class HeldSources:
    def __init__(self, descriptors):
        self.descriptors = descriptors

    def observe(self):
        return checked({target: identity(os.fstat(fd))
                        for target, fd in self.descriptors.items()})


@contextlib.contextmanager
def hold():
    """Hold fixed source FDs; never create files or run candidate code.

    The controller creates its fixed helper artifacts before entering and keeps
    this context alive until the worker domain has drained. Parent traversal
    refuses every symlink; unsupported baseline layouts must fail closed.
    """
    root_guard()  # Must precede all filesystem access, including on this Mac.
    from mano_runtime.package_candidate import parent_fd

    base = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    baseline = None
    descriptors = {}
    try:
        info = os.fstat(base)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise PermissionError('Fixed private Root source directory required')
        baseline = os.open('baseline', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                           | os.O_CLOEXEC, dir_fd=base)
        _readonly_snapshot()
        for target in sorted(TARGETS):
            root = baseline if target in BASELINE else base
            relative = target[1:] if target in BASELINE else INJECTED[target]
            parent = parent_fd(root, relative)
            try:
                descriptors[target] = os.open(relative.rsplit('/', 1)[-1],
                    os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            finally:
                os.close(parent)
        holder = HeldSources(descriptors)
        holder.observe()
        yield holder
    finally:
        for fd in descriptors.values():
            os.close(fd)
        if baseline is not None:
            os.close(baseline)
        os.close(base)
