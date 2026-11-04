"""Frame fixed staging artifact basenames for tar; no shell glob expansion."""

import json
import re
import sys
from pathlib import Path


def names(report):
    if not isinstance(report, dict):
        raise ValueError('Staged report object required')
    mapping = report.get('artifact_sha256')
    if not isinstance(mapping, dict) or not 1 <= len(mapping) <= 64:
        raise ValueError('Bounded staged artifact manifest required')
    for name, digest in mapping.items():
        if (not isinstance(name, str)
                or not re.fullmatch('staged-[A-Za-z0-9_.+-]{1,200}', name)
                or not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest)):
            raise ValueError('Fixed staged basename and SHA256 required')
    return b''.join(name.encode('ascii') + b'\0' for name in sorted(mapping))


if __name__ == '__main__':
    report = Path(sys.argv[1])
    if report.stat().st_size > 32 * 1024**2:
        raise ValueError('Bounded staging report required')
    sys.stdout.buffer.write(names(json.loads(report.read_bytes())))
