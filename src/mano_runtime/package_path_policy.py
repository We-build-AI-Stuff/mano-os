"""Fixed package-worker path policy; no model-selected policy or loader command."""

import hashlib
import os
import stat
from pathlib import Path

PROFILE = 'mano-package-worker'
SOURCE = Path('/etc/apparmor.d/mano-package-worker')
POLICY_SHA256 = 'b47c85168d80744ac296b9a3f3ab5c4de669dc331b6683400428cb6623beb97b'
MAX_POLICY = 8192


def validate_source(data, info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or info.st_mode & 0o022 or not 0 < len(data) == info.st_size <= MAX_POLICY
            or hashlib.sha256(data).hexdigest() != POLICY_SHA256):
        raise PermissionError('Exact trusted package path policy required')
    return data


def read_source():
    for parent in SOURCE.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError('Trusted package policy parent required')
    fd = os.open(SOURCE, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        return validate_source(os.read(fd, MAX_POLICY + 1), os.fstat(fd))
    finally:
        os.close(fd)


def verify_label():
    if Path('/proc/self/attr/current').read_text().strip() != PROFILE + ' (enforce)':
        raise PermissionError('Enforced package path policy required')
