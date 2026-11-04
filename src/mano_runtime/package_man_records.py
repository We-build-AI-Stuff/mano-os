"""Bounded man-db 2.5.0 record framing; all strings remain inert binary data.

The ten-field format and multi-key references follow man-db 2.13.1's libdb
db_store.c/db_lookup.c protocol. This is an independent strict profile, not a
call into man-db. Descriptions, filters, compression and pointers never execute
or become paths. Resolving internal records does not bind manual-source files.
"""
import base64
import hashlib
import json
import re

from mano_runtime.package_gdbm_decode import decode

MAX_LINKS = 65536
MAX_SERIALIZED = 16 * 1024**2


def binary(raw):
    return base64.b64encode(raw).decode('ascii')


def cstring(raw):
    if not raw.endswith(b'\0') or b'\0' in raw[:-1]:
        raise ValueError('Exactly one terminal NUL required in man-db frame')
    return raw[:-1]


def integer(raw):
    if re.fullmatch(rb'-?(?:0|[1-9][0-9]{0,18})', raw) is None:
        raise ValueError('Canonical bounded decimal timestamp required')
    value = int(raw)
    if not -(2**63) <= value < 2**63 or str(value).encode() != raw:
        raise ValueError('Signed 64-bit timestamp required')
    return value


def parse(raw):
    database = decode(raw)
    entries = {base64.b64decode(row['key_base64'], validate=True):
               base64.b64decode(row['value_base64'], validate=True) for row in database['records']}
    if entries.pop(b'$version$\0', None) != b'2.5.0\0':
        raise ValueError('Exact man-db database version required')
    direct, references, keys, targets, count = {}, {}, {}, set(), 0
    for key, value in sorted(entries.items()):
        name_key, content = cstring(key), cstring(value)
        if not name_key or len(name_key.split(b'\t')) > 2:
            raise ValueError('One bounded page key or multi-key required')
        pieces = name_key.split(b'\t')
        if any(not part for part in pieces):
            raise ValueError('Nonempty man-db key fields required')
        if content.startswith(b'\t'):
            if len(pieces) != 1 or name_key != name_key.lower():
                raise ValueError('Lower-case base reference key required')
            fields = content[1:].split(b'\t')
            if len(fields) % 2 or not fields or any(not part for part in fields):
                raise ValueError('Complete nonempty name/extension reference pairs required')
            links, unique = [], set()
            for index in range(0, len(fields), 2):
                name, ext = fields[index:index + 2]
                target = name + b'\t' + ext + b'\0'
                count += 1
                if (name.lower() != name_key or target in unique or count > MAX_LINKS
                        or len(name) > 4096 or len(ext) > 128):
                    raise ValueError('Bounded unique name-bound man-db references required')
                unique.add(target)
                targets.add(target)
                links.append(dict(key_base64=binary(target), name_base64=binary(name),
                                  extension_base64=binary(ext)))
            references[binary(key)] = links
            continue
        fields = content.split(b'\t', 9)  # Description retains every subsequent tab.
        if len(fields) != 10 or any(not part for part in fields[:9]):
            raise ValueError('Ten explicit man-db record fields required')
        name, ext, section, seconds, nanos, kind, pointer, filters, comp, description = fields
        actual_name = pieces[0] if name == b'-' else name
        if (len(actual_name) > 4096 or not 1 <= len(ext) <= 128
                or not 1 <= len(section) <= 128 or kind not in (b'A', b'B', b'C', b'D', b'E')
                or actual_name.lower() != pieces[0].lower()
                or (len(pieces) == 1 and pieces[0] != pieces[0].lower())
                or (len(pieces) == 2 and (ext != pieces[1] or actual_name != pieces[0]))):
            raise ValueError('Exact man-db name, extension and type binding required')
        sec, ns = integer(seconds), integer(nanos)
        if not (0 <= ns < 10**9 or (sec, ns) == (-1, -1)):
            raise ValueError('Nanosecond range or explicit unknown timestamp required')
        direct[binary(key)] = dict(stored_name_base64=binary(name),
            name_base64=binary(actual_name), extension_base64=binary(ext),
            section_base64=binary(section), mtime_seconds=sec, mtime_nanoseconds=ns,
            mtime_known=(sec, ns) != (-1, -1), kind=kind.decode('ascii'),
            pointer_base64=binary(pointer), filter_base64=binary(filters),
            compression_base64=binary(comp), description_base64=binary(description))
        keys[key] = (actual_name, ext)
    for links in references.values():
        for link in links:
            key = base64.b64decode(link['key_base64'], validate=True)
            expected = (base64.b64decode(link['name_base64'], validate=True),
                        base64.b64decode(link['extension_base64'], validate=True))
            if keys.get(key) != expected:
                raise ValueError('Multi-key reference must resolve to the exact direct record')
    result = dict(profile='man-db-2.5.0-binary-record-frames-v1',
        input_sha256=hashlib.sha256(raw).hexdigest(), database_version='2.5.0',
        direct_records=direct, reference_records=references, resolved_references=count,
        orphan_multi_keys=[binary(key) for key in sorted(keys)
                           if b'\t' in key and key not in targets],
        record_frames_decoded=True, internal_references_resolved=True,
        man_index_semantics_verified=False, manual_source_paths_verified=False,
        source_timestamps_verified=False, filters_interpreted=False, pointers_interpreted=False,
        cache_sources_verified=False, changes_authorized=False, publication_authorized=False)
    if len(json.dumps(result, sort_keys=True, allow_nan=False).encode()) > MAX_SERIALIZED:
        raise ValueError('Man-db frame report serialization budget')
    return result
