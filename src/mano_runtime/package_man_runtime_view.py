"""Read-only mount evidence for the fixed baseline manual-generation worker.

Pure verification is portable. Capture may run only as the dropped Linux worker;
it reads its own namespace and does not create files or execute native helpers.
This establishes named code/configuration mount protection, not full loader or
plugin selection, candidate mutation policy or publication authority.
"""
import base64
import hashlib
import os
import re
import sys
from pathlib import Path

MAX_MOUNT_BYTES = 256*1024
MAX_MOUNTS = 2048
TARGETS = ('/usr/bin', '/usr/lib', '/etc/manpath.config', '/etc/ld.so.cache',
           '/etc/nsswitch.conf', '/etc/passwd', '/etc/group', '/etc/locale.alias',
           '/run/man-cache-guard', '/run/man-regeneration.py')
TREES = {'/usr/bin', '/usr/lib'}


def path_field(raw):
    """Decode only the four escapes defined by Linux proc mountinfo."""
    if re.search(rb'\\(?!040|011|012|134)', raw):
        raise ValueError('Unknown mountinfo pathname escape')
    decoded = re.sub(rb'\\(040|011|012|134)',
                     lambda match: bytes([int(match[1], 8)]), raw).decode('utf8')
    if (not decoded.startswith('/') or '\0' in decoded
            or (decoded != '/' and any(part in {'', '.', '..'}
                                      for part in decoded[1:].split('/')))):
        raise ValueError('Absolute canonical mount pathname required')
    return decoded


def parse(raw):
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_MOUNT_BYTES
            or not raw.endswith(b'\n') or b'\0' in raw):
        raise ValueError('Bounded complete mountinfo bytes required')
    records = {}
    for line in raw.splitlines():
        before, separator, after = line.partition(b' - ')
        fields, tail = before.split(), after.split()
        if not separator or len(fields) < 6 or len(tail) != 3:
            raise ValueError('Complete Linux mountinfo record required')
        if (not re.fullmatch(rb'[1-9][0-9]*', fields[0])
                or not re.fullmatch(rb'[0-9]+', fields[1])
                or not re.fullmatch(rb'[0-9]+:[0-9]+', fields[2])):
            raise ValueError('Exact numeric mount identity required')
        mount = int(fields[0])
        if mount in records or len(records) >= MAX_MOUNTS:
            raise ValueError('Unique bounded mount IDs required')
        options = fields[5].decode('ascii').split(',')
        if (len(options) != len(set(options)) or
                (('ro' in options)+('rw' in options)) != 1):
            raise ValueError('Unambiguous per-mount readonly state required')
        records[mount] = dict(parent=int(fields[1]), device=list(map(int, fields[2].split(b':'))),
            root=path_field(fields[3]), target=path_field(fields[4]), options=options,
            filesystem=tail[0].decode('ascii'))
    return records


def verify(value):
    if type(value) is not dict or set(value) != {'mountinfo', 'paths'}:
        raise ValueError('Exact fixed runtime-view witness required')
    field = value['mountinfo']
    if (type(field) is not dict or set(field) != {'base64', 'bytes', 'sha256'}
            or type(field['base64']) is not str
            or not 0 < len(field['base64']) <= 4*((MAX_MOUNT_BYTES+2)//3)
            or type(field['bytes']) is not int or not 0 < field['bytes'] <= MAX_MOUNT_BYTES
            or type(field['sha256']) is not str
            or re.fullmatch('[a-f0-9]{64}', field['sha256']) is None):
        raise ValueError('Bounded canonical mountinfo stream required')
    raw = base64.b64decode(field['base64'], validate=True)
    if base64.b64encode(raw).decode() != field['base64']:
        raise ValueError('Canonical mountinfo base64 required')
    if (type(value['mountinfo']['bytes']) is not int or value['mountinfo']['bytes'] != len(raw)
            or value['mountinfo']['sha256'] != hashlib.sha256(raw).hexdigest()):
        raise ValueError('Exact mountinfo byte custody required')
    mounts = parse(raw)
    if type(value['paths']) is not dict or set(value['paths']) != set(TARGETS):
        raise ValueError('Complete fixed runtime code/configuration targets required')
    btrfs_devices = {}
    for target, observed in value['paths'].items():
        if (type(observed) is not dict or set(observed) != {
                'mount_id', 'device', 'resolved_path', 'readonly', 'uid', 'mode', 'kind'}
                or type(observed['mount_id']) is not int or observed['mount_id'] not in mounts
                or observed['readonly'] is not True or type(observed['uid']) is not int
                or observed['uid'] != 0 or type(observed['mode']) is not int
                or not 0 <= observed['mode'] <= 0o7777
                or type(observed['resolved_path']) is not str
                or observed['mode'] & 0o022
                or observed['kind'] != ('directory' if target in TREES else 'file')):
            raise ValueError('Root-owned read-only fixed runtime object required')
        row = mounts[observed['mount_id']]
        resolved = path_field(observed['resolved_path'].encode())
        if (type(observed['device']) is not list or len(observed['device']) != 2
                or any(type(v) is not int for v in observed['device'])
                or any(v < 0 for v in observed['device']) or 'ro' not in row['options']
                or not (row['target'] == '/' or resolved == row['target']
                        or resolved.startswith(row['target']+'/'))):
            raise ValueError('Open-FD mount identity and VFS readonly state must agree')
        # Btrfs stat() reports a subvolume anon_dev, while proc mountinfo
        # reports the filesystem superblock device. The kernel FD's mnt_id,
        # not false equality of those device numbers, binds the selected mount.
        if row['filesystem'] == 'btrfs':
            previous = btrfs_devices.setdefault(observed['mount_id'], observed['device'])
            if observed['device'] != previous:
                raise ValueError('Nested Btrfs subvolumes in trusted runtime view are unsupported')
        elif observed['device'] != row['device']:
            raise ValueError('Non-Btrfs object device differs from its FD mount')
        for other in mounts.values():
            if (len(other['target']) > len(row['target'])
                    and (resolved == other['target'] or resolved.startswith(other['target']+'/'))):
                raise ValueError('More specific mount contradicts open-FD mount identity')
        if target in TREES:
            # Refuse ambiguous covered writable descendants as well. The fixed
            # generation namespace needs no such overlays beneath trusted code.
            for child in mounts.values():
                if ((child['target'] == resolved or child['target'].startswith(resolved+'/'))
                        and 'ro' not in child['options']):
                    raise ValueError('Writable submount beneath trusted runtime tree')
    return dict(profile='man-baseline-runtime-mounts-v1',
        mountinfo_sha256=hashlib.sha256(raw).hexdigest(), mount_records=len(mounts),
        fixed_targets_readonly=len(TARGETS), named_code_configuration_mounts_readonly=True,
        complete_runtime_closure_verified=False, filesystem_object_origin_verified=False,
        loader_selection_verified=False,
        generated_state_validated=False, changes_authorized=False, publication_authorized=False)


def capture():
    if sys.platform != 'linux':
        raise PermissionError('Dropped Linux manual-generation worker only')
    if (os.getresuid() != (6, 6, 6) or os.getresgid() != (12, 12, 12)
            or not set(os.getgroups()) <= {12}):
        raise PermissionError('Complete dropped manual worker credentials required')

    def mount_bytes():
        with Path('/proc/self/mountinfo').open('rb') as stream:
            data = stream.read(MAX_MOUNT_BYTES+1)
        parse(data)
        return data

    before = mount_bytes()
    paths = {}
    for target in TARGETS:
        fd = os.open(target, os.O_PATH | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            lines = Path('/proc/self/fdinfo/'+str(fd)).read_text().splitlines()
            identifiers = [line.split(':', 1)[1].strip() for line in lines
                           if line.startswith('mnt_id:')]
            if len(identifiers) != 1 or not identifiers[0].isdigit():
                raise ValueError('One kernel FD mount identifier required')
            paths[target] = dict(mount_id=int(identifiers[0]),
                device=[os.major(info.st_dev), os.minor(info.st_dev)],
                resolved_path=os.readlink('/proc/self/fd/'+str(fd)),
                readonly=bool(os.statvfs('/proc/self/fd/'+str(fd)).f_flag & os.ST_RDONLY),
                uid=info.st_uid, mode=info.st_mode & 0o7777,
                kind='directory' if info.st_mode & 0o170000 == 0o040000 else
                     'file' if info.st_mode & 0o170000 == 0o100000 else 'unsupported')
        finally:
            os.close(fd)
    if mount_bytes() != before:
        raise ValueError('Worker mount topology changed during evidence capture')
    value = dict(mountinfo=dict(base64=base64.b64encode(before).decode(), bytes=len(before),
                               sha256=hashlib.sha256(before).hexdigest()), paths=paths)
    # Return raw evidence first. The fixed caller verifies it before generation
    # and can retain a refused witness without treating it as authority.
    return value
