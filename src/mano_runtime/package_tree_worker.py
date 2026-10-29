"""Fixed trusted Root metadata collector for disposable CI only.

This is trusted controller code, not an adversarial executor sandbox. SYS_ADMIN
is retained only to observe trusted.* xattr names; the collector executes no
candidate files, interprets no scripts and accepts only fixed CI tree roles.
"""
import json
import os
import resource
import stat
import subprocess
import sys
from pathlib import Path

from mano_runtime.package_tree import scan

BASE = Path('/.snapshots/.mano-staged-package-ci')
REQUIRED_CAPS = (1 << 2) | (1 << 21)  # DAC_READ_SEARCH and SYS_ADMIN for xattr visibility.


def guard():
    if (sys.platform != 'linux' or os.geteuid() != 0
            or os.environ.get('MANO_DISPOSABLE_CI') != '1'):
        raise PermissionError('Trusted disposable Linux CI collector required')
    if Path('/etc/mano-lab-disposable').read_text().strip() != 'mano-phase0-ci':
        raise PermissionError('Disposable CI marker required')
    machine = subprocess.check_output(['/usr/bin/systemd-detect-virt', '--vm'],
                                      text=True, timeout=5).strip()
    if machine not in {'qemu', 'kvm'}:
        raise PermissionError('Disposable VM collector required')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
    caps = {key: int(status[key].strip(), 16) for key in
            ('CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb')}
    if (any(value != REQUIRED_CAPS for value in caps.values())
            or status['NoNewPrivs'].strip() != '1'):
        print(json.dumps(dict(event='tree-collector-privilege-denied',
                              expected_capabilities=REQUIRED_CAPS, capabilities=caps,
                              no_new_privileges=status['NoNewPrivs'].strip())),
              file=sys.stderr, flush=True)
        raise PermissionError('Fixed collector capability sets and NoNewPrivileges required')
    return caps


def main():
    caps = guard()
    if (len(sys.argv) not in {2, 3} or sys.argv[1] not in
            {'baseline', 'candidate', 'regenerated-man-cache', 'man-cache-control'}
            or (len(sys.argv) == 3 and sys.argv[2] != '--admission-only')):
        raise ValueError('Fixed snapshot role required')
    role = sys.argv[1]
    admission = len(sys.argv) == 3
    resource.setrlimit(resource.RLIMIT_AS, (384 * 1024**2, 384 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    cgroup = Path('/proc/self/cgroup').read_text().strip()
    expected = '0::/mano.slice/mano-package.slice/mano-tree-' + role + '-ci.service'
    if cgroup != expected:
        raise PermissionError('Fixed protected collector cgroup required')
    group = Path('/sys/fs/cgroup') / cgroup[3:].lstrip('/')
    memory = int((group / 'memory.max').read_text().strip())
    tasks = int((group / 'pids.max').read_text().strip())
    if memory != 512 * 1024**2 or tasks != 8:
        raise PermissionError('Kernel collector resource limits required')
    result = dict(schema_version='1.0', full_root_verified=False, immutable_root_verified=False,
                  candidate_filesystem_verified=False, publication_authorized=False)
    if not admission:
        base = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(base)
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                raise PermissionError('Private Root-owned collector directory required')
            root = os.open(role, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=base)
            try:
                result = scan(root)
            finally:
                os.close(root)
        finally:
            os.close(base)
    result.update(observed_role=role, capabilities=caps, uid=os.geteuid(),
                  no_new_privileges=True, address_space_limit_bytes=384 * 1024**2,
                  cpu_limit_seconds=60, trusted_controller_collector=True,
                  cgroup_path=cgroup[3:], memory_max_bytes=memory, pids_max=tasks,
                  production_guard_used=False, adversarial_confinement_verified=False)
    result['admission_only'] = admission
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    main()
