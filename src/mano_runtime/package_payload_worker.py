"""Disposable CI unprivileged payload observation; never an apply authority.

The supervisor must set an empty capability bounding set, NoNewPrivileges and
memory/task/runtime limits. This worker additionally bounds address space/CPU.
It never extracts archive members or runs maintainer scripts.
"""

import fcntl
import json
import os
import resource
import subprocess
import sys
from pathlib import Path

from mano_runtime.package_container import MAX_ARCHIVE, bind
from mano_runtime.package_payload import inventory


def guard():
    if (sys.platform != 'linux' or os.geteuid() == 0
            or os.environ.get('MANO_DISPOSABLE_CI') != '1'):
        raise PermissionError('Unprivileged disposable Linux CI observer required')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
    caps = {key: int(status[key].strip(), 16) for key in
            ('CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb')}
    if any(caps.values()) or status['NoNewPrivs'].strip() != '1':
        raise PermissionError('Empty capability sets and NoNewPrivileges required')
    return caps


def observe(raw, *, expected_sha256, expected_bytes):
    container = bind(raw, expected_sha256=expected_sha256, expected_bytes=expected_bytes)
    fd = os.memfd_create('mano-ci-payload-observation', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    try:
        with os.fdopen(os.dup(fd), 'wb', closefd=True) as output:
            output.write(raw)
        os.lseek(fd, 0, os.SEEK_SET)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals != seals:
            raise ValueError('Immutable observer archive custody required')
        process = subprocess.Popen(
            ['/usr/bin/dpkg-deb', '--fsys-tarfile', '/proc/self/fd/' + str(fd)],
            pass_fds=(fd,), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, cwd='/',
            env={'PATH': '/usr/sbin:/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        try:
            with process.stdout:
                result = inventory(process.stdout)
                tail = process.stdout.read(1024**2 + 1)
                if len(tail) > 1024**2 or any(tail):
                    raise ValueError('Unsupported data after payload tar terminator')
            if process.wait(timeout=5) != 0:
                raise ValueError('Payload decompression failed')
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        return dict(payload=result, container=container, sealed_archive_observed=True,
                    archive_signature_verified=False, publication_authorized=False)
    finally:
        os.close(fd)


def main():
    caps = guard()  # Refuse Mac/root/unbounded capability contexts before input IO.
    resource.setrlimit(resource.RLIMIT_AS, (384 * 1024**2, 384 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (12, 12))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_ARCHIVE, MAX_ARCHIVE))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if len(sys.argv) != 3:
        raise ValueError('Expected fixed archive hash and size')
    size = int(sys.argv[2])
    if not 0 < size <= MAX_ARCHIVE:
        raise ValueError('Bounded observer input required')
    raw = sys.stdin.buffer.read(size + 1)
    result = observe(raw, expected_sha256=sys.argv[1], expected_bytes=size)
    result.update(capabilities=caps, uid=os.geteuid(), no_new_privileges=True,
                  address_space_limit_bytes=384 * 1024**2, cpu_limit_seconds=12,
                  production_guard_used=False, production_pam_used=False)
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    main()
