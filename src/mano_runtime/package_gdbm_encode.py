"""Deterministic bounded GDBM data encoding, without a native database library.

All allocation metadata, inactive cells, padding and trailing bytes are emitted
from scratch. Equality to a re-encoding binds the complete byte stream. This
does not validate man-db meanings, source authority or permission to publish.
"""
import base64
import hashlib
import struct

from mano_runtime.package_gdbm_decode import (
    MAX_BYTES,
    MAX_EXPANDED,
    MAX_KEY,
    MAX_RECORDS,
    MAX_VALUE,
    STANDARD,
    decode,
    key_hash,
)

BLOCK = 512
SLOTS = (BLOCK - 112) // 24
MAX_BITS = 16


def encode(pairs):
    if type(pairs) is not dict or len(pairs) > MAX_RECORDS:
        raise ValueError('Bounded exact key/value dictionary required')
    total = 0
    for key, value in pairs.items():
        if (type(key) is not bytes or not 1 <= len(key) <= MAX_KEY
                or type(value) is not bytes or len(value) > MAX_VALUE):
            raise ValueError('Bounded binary GDBM key/value required')
        total += len(key) + len(value)
        if total > MAX_EXPANDED:
            raise ValueError('Canonical GDBM expanded data budget')
    # Deterministic prefix tree: the high hash bits select leaf buckets; an
    # overfull leaf splits until it fits, or rejects a pathological collision.
    leaves = []

    def partition(rows, prefix, bits):
        if len(rows) <= SLOTS:
            leaves.append((prefix, bits, rows))
            return
        if bits == MAX_BITS:
            raise ValueError('Canonical GDBM hash-prefix collision budget')
        left, right = [], []
        for row in rows:
            (right if row[0] & (1 << (30 - bits)) else left).append(row)
        partition(left, prefix * 2, bits + 1)
        partition(right, prefix * 2 + 1, bits + 1)

    partition([(key_hash(key), key, value) for key, value in sorted(pairs.items())], 0, 0)
    bits = max(6, max(depth for _, depth, _ in leaves))
    directory_bytes = 8 * 2**bits
    buckets_start = BLOCK + directory_bytes
    data_start = buckets_start + BLOCK * len(leaves)
    size = ((data_start + total + BLOCK - 1) // BLOCK) * BLOCK
    if size > MAX_BYTES:
        raise ValueError('Canonical GDBM physical file budget')
    raw = bytearray(size)
    struct.pack_into('<iiqiiiiq', raw, 0, STANDARD, BLOCK, BLOCK, directory_bytes,
                     bits, BLOCK, SLOTS, size)
    struct.pack_into('<iiq', raw, 40, (BLOCK - 56) // 16, 0, 0)
    cursor = data_start
    for number, (prefix, depth, rows) in enumerate(leaves):
        offset = buckets_start + number * BLOCK
        start, count = prefix << (bits - depth), 1 << (bits - depth)
        for index in range(start, start + count):
            struct.pack_into('<q', raw, BLOCK + 8 * index, offset)
        struct.pack_into('<ii', raw, offset + 104, depth, len(rows))
        for slot in range(SLOTS):
            struct.pack_into('<i', raw, offset + 112 + slot * 24, -1)
        occupied = set()
        for hashed, key, value in rows:
            slot = hashed % SLOTS
            while slot in occupied:
                slot = (slot + 1) % SLOTS
            occupied.add(slot)
            struct.pack_into('<i4sqii', raw, offset + 112 + 24 * slot,
                             hashed, key[:4], cursor, len(key), len(value))
            raw[cursor:cursor + len(key) + len(value)] = key + value
            cursor += len(key) + len(value)
    return bytes(raw)


def require_canonical(raw):
    report = decode(raw)
    pairs = {base64.b64decode(row['key_base64'], validate=True):
             base64.b64decode(row['value_base64'], validate=True) for row in report['records']}
    expected = encode(pairs)
    if raw != expected:
        raise ValueError('Database differs from complete deterministic encoding')
    return dict(profile='gdbm-le64-zero-padding-canonical-v1', bytes=len(raw),
                sha256=hashlib.sha256(raw).hexdigest(), records=len(pairs),
                complete_canonical_encoding_verified=True, man_index_semantics_verified=False,
                cache_sources_verified=False, changes_authorized=False,
                publication_authorized=False)
