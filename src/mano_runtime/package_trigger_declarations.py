"""Decode and bind trigger declarations as metadata, never execution authority.

https://manpages.debian.org/trixie/dpkg-dev/deb-triggers.5.en.html
Installed interests are read only through the fixed private-baseline reader.
"""
import base64
import hashlib
import re

from mano_runtime.package_payload import path_name
from mano_runtime.package_postconditions import database_records

MAX_BYTES = 1024**2
MAX_DIRECTIVES = 4096
MAX_SOURCE_BYTES = 4 * 1024**2
MAX_SOURCE_DIRECTIVES = 4096
DIRECTIVES = {'interest', 'interest-await', 'interest-noawait',
              'activate', 'activate-await', 'activate-noawait'}


def decode(data):
    if type(data) is not bytes or len(data) > MAX_BYTES:
        raise ValueError('Bounded actual trigger declaration bytes required')
    rows = []
    for raw in data.decode('utf8', errors='strict').split('\n'):
        line = raw.partition('#')[0].strip(' \t\r')
        if not line:
            continue
        words = re.split(r'[ \t]+', line)
        if (len(words) != 2 or words[0] not in DIRECTIVES or len(rows) >= MAX_DIRECTIVES
                or len(words[1].encode()) > 4096
                or any(not 0x21 <= ord(c) <= 0x7e for c in words[1])):
            raise ValueError('Known bounded trigger directive and opaque name required')
        trigger = words[1]
        if trigger.startswith('/') and trigger != '/':
            if path_name(trigger[1:], directory=True) != trigger[1:]:
                raise ValueError('Canonical file-trigger path required')
        rows.append(dict(directive=words[0], trigger=trigger,
                         kind='file' if trigger.startswith('/') else 'named'))
    return dict(schema_version='1.0', bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                declarations=rows, declarations_decoded=True, trigger_authority_verified=False,
                changes_authorized=False, publication_authorized=False)


def baseline_sources(before_status, baseline, references, read):
    """Bind only installed-package .triggers files, with no caller-selected path."""
    if not callable(read) or not isinstance(references, list) or len(references) > 256:
        raise ValueError('Bounded references and owned-baseline reader required')
    installed = database_records(before_status)
    sources, seen = [], set()
    total_bytes, total_directives = 0, 0
    for reference in references:
        key = reference['name'], reference['architecture']
        if key in seen:
            raise ValueError('Distinct trigger package references required')
        seen.add(key)
        fields = installed.get(key)
        if fields is None:
            sources.append(dict(package=reference, baseline_available=False,
                                reason='not-installed-in-baseline'))
            continue
        if ((fields['status'], fields['version']) != (
                'install ok installed', reference['version'])):
            raise ValueError('Exact installed baseline trigger identity required')
        prefix = key[0] + (':' + key[1] if fields.get('multi-arch') == 'same' else '')
        path = 'var/lib/dpkg/info/' + prefix + '.triggers'
        row = baseline['entries'].get(path)
        if row is None:
            sources.append(dict(package=reference, baseline_available=False,
                                reason='no-baseline-trigger-file', path=path))
            continue
        if (row['kind'] != 'file' or any(type(row[k]) is not int for k in
                ('uid', 'gid', 'mode', 'nlink', 'bytes'))
                or (row['uid'], row['gid'], row['mode'], row['nlink'])
                != (0, 0, 0o644, 1) or row['xattrs'] or row['hardlink_anchor'] != path
                or type(row['bytes']) is not int or not 0 <= row['bytes'] <= MAX_BYTES):
            raise ValueError('Plain Root-owned baseline trigger metadata required')
        if total_bytes + row['bytes'] > MAX_SOURCE_BYTES:
            raise ValueError('Aggregate baseline trigger byte budget')
        data = read(path, MAX_BYTES)
        if (type(data) is not bytes or len(data) != row['bytes']
                or hashlib.sha256(data).hexdigest() != row['sha256']):
            raise ValueError('Trigger declaration bytes differ from baseline tree')
        observation = decode(data)
        total_bytes += len(data)
        total_directives += len(observation['declarations'])
        if total_directives > MAX_SOURCE_DIRECTIVES:
            raise ValueError('Aggregate baseline trigger directive budget')
        sources.append(dict(package=reference, baseline_available=True, path=path,
                            data_base64=base64.b64encode(data).decode(),
                            observation=observation, baseline_tree_bound=True))
    return dict(schema_version='1.0', sources=sources, trigger_authority_verified=False,
                changes_authorized=False, publication_authorized=False)
