"""Bounded active-record decoding for GDBM's little-endian 64-bit file layout.

Independent Python implementation of the layout/hash facts in GNU GDBM 1.24
src/gdbmdefs.h, gdbmconst.h, hash.c and gdbmopen.c. The signed-char profile matches
the observed Debian amd64 package. No native database library is loaded.
Free-space chains, unused bytes and man-db meanings remain unverified; this is
not database validity, regeneration, source, mutation or publication authority.
"""
import base64
import hashlib
import json
import re
import struct

MAX_BYTES = 2 * 1024**2
MAX_RECORDS = 16384
MAX_KEY = 4096
MAX_VALUE = 65536
MAX_EXPANDED = 4 * 1024**2
MAX_PROBES = 1024**2
MAX_TOTAL_RECORDS = 65536
MAX_SERIALIZED = 16 * 1024**2
STANDARD = 0x13579ACF
NUMSYNC = 0x13579AD1


def key_hash(key):
    value = (0x238F13AF * len(key)) & 0x7FFFFFFF
    for index, byte in enumerate(key):
        signed = byte if byte < 128 else byte - 256
        value = (value + (signed << ((index * 5) % 24))) & 0x7FFFFFFF
    return (1103515243 * value + 12345) & 0x7FFFFFFF


def decode(raw):
    if type(raw) is not bytes or not 512 <= len(raw) <= MAX_BYTES:
        raise ValueError('Bounded GDBM file bytes required')
    magic, block, directory, directory_bytes, bits, bucket_bytes, slots, next_block = (
        struct.unpack_from('<iiqiiiiq', raw))
    if (magic not in {STANDARD, NUMSYNC} or block not in {512, 1024, 2048, 4096,
            8192, 16384, 32768, 65536} or len(raw) < 3 * block
            or not 3 <= bits <= 16 or directory_bytes != 8 * 2**bits
            or directory_bytes < block or not block <= directory
            or directory + directory_bytes >= len(raw) or bucket_bytes != block
            or slots != (block - 112) // 24 or not len(raw) <= next_block <= len(raw) + block
            or next_block % block):
        raise ValueError('Supported bounded little-endian 64-bit GDBM header required')
    avail_offset, synchronization = 40, None
    if magic == NUMSYNC:
        version, synchronization, *padding = struct.unpack_from('<iI6i', raw, 40)
        if version != 0 or any(padding):
            raise ValueError('Known zero-reserved GDBM extension required')
        avail_offset = 72
    avail_size, avail_count, avail_next = struct.unpack_from('<iiq', raw, avail_offset)
    if (avail_size != (block - avail_offset - 16) // 16 or not 0 <= avail_count <= avail_size
            or (avail_next != 0 and not block <= avail_next <= len(raw) - 16)):
        raise ValueError('Bounded GDBM free-space header required')
    pointers = struct.unpack_from('<' + 'q' * 2**bits, raw, directory)
    positions = {}
    for index, pointer in enumerate(pointers):
        if not block <= pointer <= len(raw) - bucket_bytes:
            raise ValueError('GDBM bucket outside file')
        positions.setdefault(pointer, []).append(index)
    if len(positions) > len(raw) // bucket_bytes:
        raise ValueError('GDBM physical bucket budget')
    intervals = ([(0, block), (directory, directory + directory_bytes)]
                 + [(pointer, pointer + bucket_bytes) for pointer in positions])
    intervals.sort()
    if any(left[1] > right[0] for left, right in zip(intervals, intervals[1:], strict=False)):
        raise ValueError('GDBM metadata regions overlap')
    records, seen, expanded, probes = [], set(), 0, 0
    for pointer, indexes in positions.items():
        free_count = struct.unpack_from('<i', raw, pointer)[0]
        bucket_bits, count = struct.unpack_from('<ii', raw, pointer + 104)
        if (not 0 <= free_count <= 6 or not 0 <= bucket_bits <= bits
                or not 0 <= count <= slots):
            raise ValueError('Bounded GDBM bucket metadata required')
        repeats = 2**(bits - bucket_bits)
        if (len(indexes) != repeats or indexes[0] % repeats
                or indexes[-1] != indexes[0] + repeats - 1):
            raise ValueError('GDBM directory aliases differ from bucket prefix')
        cells = [struct.unpack_from('<i4sqii', raw, pointer + 112 + 24 * index)
                 for index in range(slots)]
        if sum(cell[0] != -1 for cell in cells) != count:
            raise ValueError('GDBM active bucket count differs')
        for slot, (hashed, prefix, offset, key_size, value_size) in enumerate(cells):
            if hashed == -1:
                continue
            if (len(records) >= MAX_RECORDS or not 0 <= hashed < 2**31
                    or not 1 <= key_size <= MAX_KEY or not 0 <= value_size <= MAX_VALUE
                    or not block <= offset or offset + key_size + value_size > len(raw)):
                raise ValueError('Bounded GDBM active record required')
            expanded += key_size + value_size
            if expanded > MAX_EXPANDED:
                raise ValueError('GDBM expanded record budget')
            key = raw[offset:offset + key_size]
            value = raw[offset + key_size:offset + key_size + value_size]
            if (key in seen or key_hash(key) != hashed or prefix[:min(4, key_size)] != key[:4]
                    or pointers[hashed >> (31 - bits)] != pointer):
                raise ValueError('GDBM key/hash/prefix/directory binding differs')
            probe = hashed % slots
            while probe != slot:
                probes += 1
                if probes > MAX_PROBES or cells[probe][0] == -1:
                    raise ValueError('GDBM key is unreachable or probing exceeds budget')
                probe = (probe + 1) % slots
            seen.add(key)
            intervals.append((offset, offset + key_size + value_size))
            records.append((key, dict(key_base64=base64.b64encode(key).decode('ascii'),
                value_base64=base64.b64encode(value).decode('ascii'), bucket_offset=pointer,
                slot=slot, data_offset=offset, key_bytes=key_size, value_bytes=value_size)))
    intervals.sort()
    if any(left[1] > right[0] for left, right in zip(intervals, intervals[1:], strict=False)):
        raise ValueError('GDBM active records or structural regions overlap')
    return dict(schema_version='1.0', profile='gdbm-le64-signed-char-logical-v1',
        bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), magic=magic,
        block_size=block, directory_bits=bits, buckets=len(positions),
        synchronization_counter=synchronization,
        free_space_header=dict(size=avail_size, count=avail_count, next_block=avail_next),
        records=[row for _, row in sorted(records)], decoded_records=len(records),
        unmodeled_bytes=len(raw) - sum(end - start for start, end in intervals),
        logical_records_decoded=True, free_space_graph_verified=False,
        all_database_bytes_validated=False, man_index_semantics_verified=False,
        cache_sources_verified=False, cache_regeneration_verified=False,
        changes_authorized=False, publication_authorized=False)


def decode_artifacts(raw_files):
    """Serialize fixed retained-input reports with aggregate resource bounds."""
    if (type(raw_files) is not dict or len(raw_files) > 16
            or any(not isinstance(name, str) or re.fullmatch(
                r'staged-man-index-[0-7]-(baseline|candidate)\.db', name) is None
                or type(data) is not bytes for name, data in raw_files.items())
            or sum(map(len, raw_files.values())) > 8 * 1024**2):
        raise ValueError('Bounded retained man-index artifact set required')
    reports, count = {}, 0
    for name, data in sorted(raw_files.items()):
        report = decode(data)
        count += report['decoded_records']
        if count > MAX_TOTAL_RECORDS:
            raise ValueError('Aggregate GDBM record budget')
        reports[name] = report
    encoded = json.dumps(reports, sort_keys=True, allow_nan=False).encode()
    if len(encoded) > MAX_SERIALIZED:
        raise ValueError('Serialized GDBM report budget')
    summary = dict(schema_version='1.0', profile='retained-man-index-gdbm-logical-v1',
        artifact='staged-man-index-decoding.json', bytes=len(encoded),
        sha256=hashlib.sha256(encoded).hexdigest(), databases=len(reports), decoded_records=count,
        logical_records_decoded=True, free_space_graph_verified=False,
        all_database_bytes_validated=False, man_index_semantics_verified=False,
        cache_sources_verified=False, cache_regeneration_verified=False,
        changes_authorized=False, publication_authorized=False)
    return summary, encoded
