"""Bind Debian ar member boundaries to an externally verified archive identity.

No decompression, extraction, subprocesses or signature authority. Caller-owned
immutable bytes must come from bounded sealed archive custody. All supported
Debian payload compression names are retained for a resource-limited worker.
"""

import hashlib
import re

MAX_ARCHIVE = 64 * 1024**2
MAX_MEMBERS = 64
CONTROL = {'control.tar', 'control.tar.gz', 'control.tar.xz', 'control.tar.zst'}
DATA = {'data.tar', 'data.tar.gz', 'data.tar.xz', 'data.tar.zst',
        'data.tar.bz2', 'data.tar.lzma'}


def bind(raw, *, expected_sha256, expected_bytes, checkpoint=None):
    """Observe exact member framing only after the whole archive hash agrees.

    Expected hash/size must be supplied by the signed-plan custodian, not a model.
    An agreement does not itself establish where those expectations originated.
    Forward-compatible underscore/trailing members are recorded, never executed
    or treated as approved filesystem changes.
    """
    if (type(raw) is not bytes or type(expected_bytes) is not int
            or not 0 < expected_bytes <= MAX_ARCHIVE or len(raw) != expected_bytes
            or not isinstance(expected_sha256, str)
            or not re.fullmatch('[a-f0-9]{64}', expected_sha256)):
        raise ValueError('Bounded immutable archive identity required')
    if checkpoint is not None and not callable(checkpoint):
        raise ValueError('Callable interruption checkpoint required')
    check = checkpoint if checkpoint is not None else (lambda: None)
    digest = hashlib.sha256()
    view = memoryview(raw)
    for offset in range(0, len(raw), 65536):
        check()
        digest.update(view[offset:offset+65536])
    if digest.hexdigest() != expected_sha256:
        raise ValueError('Archive bytes differ from expected identity')
    if raw[:8] != b'!<arch>\n':
        raise ValueError('Common Debian ar container required')
    offset, members, names, required, extra = 8, [], set(), [], []
    while offset < len(raw):
        check()
        if len(members) >= MAX_MEMBERS:
            raise ValueError('Archive member count budget')
        header = raw[offset:offset+60]
        if len(header) != 60 or header[58:] != b'`\n':
            raise ValueError('Truncated or invalid ar member header')
        try:
            name = header[:16].decode('ascii').rstrip(' ')
        except UnicodeError as error:
            raise ValueError('ASCII common ar member name required') from error
        if name.endswith('/'):
            name = name[:-1]
        if not re.fullmatch('[A-Za-z0-9_.+-]{1,15}', name) or name in names:
            raise ValueError('Unique common ar member names required')
        for field, pattern in ((header[16:28], rb'[0-9]+'),
                               (header[28:34], rb'[0-9]+'),
                               (header[34:40], rb'[0-9]+'),
                               (header[40:48], rb'[0-7]+'),
                               (header[48:58], rb'[0-9]+')):
            if not re.fullmatch(pattern, field.strip(b' ')):
                raise ValueError('Canonical numeric ar header required')
        size = int(header[48:58])
        start, end = offset + 60, offset + 60 + size
        if end > len(raw) or (size % 2 and raw[end:end+1] != b'\n'):
            raise ValueError('Truncated ar member or invalid odd-byte padding')
        row = dict(name=name, offset=start, bytes=size,
                   sha256=hashlib.sha256(view[start:end]).hexdigest())
        names.add(name)
        members.append(row)
        if name == 'debian-binary' or name in CONTROL or name in DATA:
            required.append(row)
        elif len(required) < 3 and not name.startswith('_'):
            raise ValueError('Unknown required Debian container member')
        else:
            extra.append(name)
        offset = end + size % 2
    if (len(required) != 3 or not members or members[0]['name'] != 'debian-binary'
            or required[0]['name'] != 'debian-binary'
            or required[1]['name'] not in CONTROL or required[2]['name'] not in DATA):
        raise ValueError('Ordered Debian version/control/data members required')
    version = required[0]
    if version['bytes'] > 1024 or not re.match(
            rb'2\.[0-9]+\n', raw[version['offset']:version['offset']+version['bytes']]):
        raise ValueError('Compatible Debian container major version required')
    check()
    return dict(schema_version='1.0', archive_sha256=expected_sha256,
                archive_bytes=expected_bytes, expected_identity_matched=True,
                members=members, control=required[1], data=required[2],
                additional_members=extra, archive_signature_verified=False,
                payload_inventory_verified=False, candidate_filesystem_verified=False,
                publication_authorized=False)
