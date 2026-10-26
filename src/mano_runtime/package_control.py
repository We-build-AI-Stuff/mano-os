"""Observe bounded uncompressed control tar bytes without extracting or executing.

Run in the same resource-limited unprivileged worker as payload parsing. Expected
archive identity comes from sealed, authenticated custody outside this module.
"""
import hashlib
import io
import re
import tarfile
from email.parser import Parser

from mano_runtime.package_payload import inventory, path_name
from mano_runtime.package_postconditions import database_records

MAX_TAR = 16 * 1024**2
MAX_CONTROL = 1024**2
COPIED = frozenset({'md5sums', 'shlibs', 'symbols', 'triggers', 'preinst', 'postinst',
                    'prerm', 'postrm', 'config', 'templates'})


def observe(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_TAR:
        raise ValueError('Bounded uncompressed control tar required')
    manifest = inventory(io.BytesIO(raw), max_entries=256, max_file=4 * 1024**2,
                         max_payload=8 * 1024**2, max_metadata=1024**2)
    entries = manifest['entries']
    if manifest['unsupported_metadata'] or 'control' not in entries:
        raise ValueError('Supported control inventory required')
    for name, row in entries.items():
        if ((name == '.' and row['kind'] != 'directory') or
                (name != '.' and (row['kind'] != 'file' or '/' in name))):
            raise ValueError('Flat regular control members required')
    expected = entries['control']
    if expected['bytes'] > MAX_CONTROL:
        raise ValueError('Control field byte budget')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = [m for m in archive if path_name(m.name, directory=m.isdir()) == 'control']
        if len(raw) - archive.offset < 1024 or any(raw[archive.offset:]):
            raise ValueError('Zero tar terminator/padding without trailing control data required')
        if len(members) != 1 or not members[0].isfile():
            raise ValueError('One regular control field member required')
        with archive.extractfile(members[0]) as source:
            data = source.read(MAX_CONTROL + 1)
    if (len(data) != expected['bytes'] or hashlib.sha256(data).hexdigest() != expected['sha256']
            or b'\0' in data):
        raise ValueError('Control field content integrity changed')
    message = Parser().parsestr(data.decode('utf8', errors='strict'))
    if message.defects or message.get_payload():
        raise ValueError('Single well-formed control paragraph required')
    fields = {}
    for key, value in message.raw_items():
        name = key.lower()
        if not re.fullmatch(r'[!-9;-~]+', key) or name in fields:
            raise ValueError('Unique control fields required')
        fields[name] = value
    if ('status' in fields or not all(key in fields for key in
                                     ('package', 'architecture', 'version'))):
        raise ValueError('Package identity without installed state required')
    return dict(schema_version='1.0', fields=fields, inventory=manifest,
                archive_signature_verified=False, maintainer_execution_authorized=False,
                candidate_filesystem_verified=False, publication_authorized=False)


def validate_new(before, after, tree, records, observations):
    """Check new-package control fields and copied info files against archives.

    Generated lists, conffiles, triggers, cache and log effects need separate
    validators. No generated state is blessed by its pathname here.
    """
    old, new = database_records(before), database_records(after)
    approved, copied, unsupported = set(), [], {}
    for record in records:
        name, arch, version = (record[k] for k in ('name', 'architecture', 'version'))
        key = (name, arch)
        if key in approved or key in old:
            raise ValueError('Distinct new-package control policy required')
        approved.add(key)
        observed = observations[name]['control']
        fields, entries = observed['fields'], observed['inventory']['entries']
        if (fields.get('package') != name or fields.get('architecture') != arch
                or fields.get('version') != version
                or new.get(key) != fields | {'status': 'install ok installed'}):
            raise ValueError('Installed package record differs from authenticated control')
        prefix = name + (':' + arch if fields.get('multi-arch') == 'same' else '')
        unsupported[name] = sorted(set(entries) - COPIED - {'.', 'control'})
        for member in sorted(set(entries) & COPIED):
            path = 'var/lib/dpkg/info/' + prefix + '.' + member
            source, actual = entries[member], tree['entries'].get(path)
            if (source['kind'] != 'file' or actual is None or actual['kind'] != 'file'
                    or any(actual[k] != source[k]
                           for k in ('uid', 'gid', 'mode', 'bytes', 'sha256'))
                    or actual['xattrs'] or actual['nlink'] != 1
                    or actual['hardlink_anchor'] != path):
                raise ValueError('Installed dpkg info differs from authenticated control member')
            copied.append(path)
    if any(old.get(key) != new.get(key) for key in (old.keys() | new.keys()) - approved):
        raise ValueError('Unapproved package record changed')
    return dict(schema_version='1.0', new_package_records_verified=len(approved),
                copied_control_paths_verified=sorted(copied),
                unsupported_control_members=unsupported, generated_state_validated=False,
                maintainer_effects_verified=False, changes_authorized=False,
                candidate_filesystem_verified=False, publication_authorized=False)
