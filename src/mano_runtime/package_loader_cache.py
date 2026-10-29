"""Decode a bounded glibc new-format cache as data, never library authority.

Supported profile: version 1.1, little endian, zero hwcaps/OS-version fields and
optional opaque generator metadata. Old/compat formats, hwcaps and other
extensions require explicit policies. No library is opened, followed or loaded.
"""
import hashlib
import struct
import unicodedata

from mano_runtime.package_payload import path_name

MAX_BYTES = 4 * 1024**2
MAX_ENTRIES = 32768
MAX_EXPANDED_STRINGS = 4 * 1024**2
MAGIC = b'glibc-ld.so.cache1.1'
EXTENSION_MAGIC = 0xEAA42174


def observe(raw):
    if type(raw) is not bytes or not 48 <= len(raw) <= MAX_BYTES or raw[:20] != MAGIC:
        raise ValueError('Bounded glibc new-format 1.1 cache required')
    count, string_bytes = struct.unpack_from('<II', raw, 20)
    extension_offset = struct.unpack_from('<I', raw, 32)[0]
    if raw[28] != 2 or any(raw[29:32]) or any(raw[36:48]):
        raise ValueError('Little-endian cache with zero reserved metadata required')
    strings_start = 48 + count * 24
    strings_end = strings_start + string_bytes
    if count > MAX_ENTRIES or strings_start > len(raw) or strings_end > len(raw):
        raise ValueError('Cache entry/string table bounds exceeded')
    memo, expanded, entries = {}, 0, []

    def string(offset):
        if not strings_start <= offset < strings_end:
            raise ValueError('Cache string offset outside string table')
        if offset not in memo:
            end = raw.find(b'\0', offset, min(strings_end, offset + 4097))
            if end < 0:
                raise ValueError('Bounded terminated cache string required')
            text = raw[offset:end].decode('utf8', errors='strict')
            if not text or any(unicodedata.category(c).startswith('C')
                               or unicodedata.category(c) in {'Zl', 'Zp'} for c in text):
                raise ValueError('Nonempty control-free cache string required')
            memo[offset] = text
        return memo[offset]

    for index in range(count):
        flags, key, value, osversion, hwcap = struct.unpack_from('<iIIIQ', raw, 48 + index*24)
        if osversion or hwcap:
            raise ValueError('OS-version/hwcap cache entries need a separate profile')
        soname, path = string(key), string(value)
        expanded += len(soname.encode()) + len(path.encode())
        if expanded > MAX_EXPANDED_STRINGS:
            raise ValueError('Expanded cache string budget')
        if '/' in soname or soname in {'.', '..'}:
            raise ValueError('Opaque cache SONAME must be a basename')
        if (not path.startswith('/') or path_name(path[1:]) != path[1:]):
            raise ValueError('Canonical absolute lexical cache path required')
        entries.append(dict(flags=flags, soname=soname, path=path))
    extensions = []
    if extension_offset == 0:
        if strings_end != len(raw):
            raise ValueError('Unmodeled bytes after cache string table')
    else:
        if (extension_offset != ((strings_end + 3) & ~3) or
                extension_offset + 8 > len(raw) or any(raw[strings_end:extension_offset])):
            raise ValueError('Aligned bounded extension directory required')
        magic, sections = struct.unpack_from('<II', raw, extension_offset)
        if magic != EXTENSION_MAGIC or sections > 1:
            raise ValueError('Supported bounded cache extension directory required')
        data_start = extension_offset + 8 + sections*16
        if data_start > len(raw):
            raise ValueError('Truncated extension descriptors')
        if sections:
            tag, flags, offset, size = struct.unpack_from('<IIII', raw, extension_offset + 8)
            if (tag != 0 or flags or offset != data_start or not 0 < size <= 8192
                    or offset + size != len(raw)):
                raise ValueError('One bounded opaque generator extension required')
            extensions.append(dict(tag=tag, bytes=size,
                                   sha256=hashlib.sha256(raw[offset:offset+size]).hexdigest()))
        elif data_start != len(raw):
            raise ValueError('Unmodeled extension payload')
    return dict(schema_version='1.0', profile='glibc-new-1.1-le-zero-hwcap',
                bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), entries=entries,
                decoded_entries=len(entries), extensions=extensions, cache_entries_decoded=True,
                entry_flags_interpreted=False, generator_identity_verified=False,
                all_cache_bytes_semantically_verified=False,
                library_objects_verified=False, cache_regeneration_verified=False,
                changes_authorized=False, publication_authorized=False)


def bind_pair(before, after, baseline, candidate):
    """Bind fixed cache bytes to tree observations; never bless library objects."""
    path = 'etc/ld.so.cache'
    for data, tree in ((before, baseline), (after, candidate)):
        row = tree['entries'].get(path)
        if (row is None or row['kind'] != 'file'
                or any(type(row[k]) is not int for k in ('uid', 'gid', 'mode', 'nlink', 'bytes'))
                or (row['uid'], row['gid'], row['mode'], row['nlink']) != (0, 0, 0o644, 1)
                or row['xattrs'] or row['hardlink_anchor'] != path
                or type(data) is not bytes or not 48 <= len(data) <= MAX_BYTES
                or row['bytes'] != len(data)
                or row['sha256'] != hashlib.sha256(data).hexdigest()):
            raise ValueError('Plain Root-owned cache bytes must match the fixed tree entry')
    return dict(schema_version='1.0', before=observe(before), after=observe(after),
                cache_bytes_bound_to_tree=True, cache_search_order_verified=False,
                library_objects_verified=False, cache_regeneration_verified=False,
                changes_authorized=False, publication_authorized=False)
