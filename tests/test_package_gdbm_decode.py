import base64
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_runtime import package_gdbm_decode as gdbm

BLOCK, BUCKET, DATA, SLOTS = 512, 1024, 1536, 16


def database(pairs=((b'name\0', b'value\0'),), *, extended=False):
    raw = bytearray(2048)
    magic = gdbm.NUMSYNC if extended else gdbm.STANDARD
    struct.pack_into('<iiqiiiiq', raw, 0, magic, BLOCK, BLOCK, BLOCK, 6, BLOCK, SLOTS, len(raw))
    start = 72 if extended else 40
    struct.pack_into('<iiq', raw, start, (BLOCK - start - 16) // 16, 0, 0)
    struct.pack_into('<' + 'q' * 64, raw, BLOCK, *([BUCKET] * 64))
    for slot in range(SLOTS):
        struct.pack_into('<i', raw, BUCKET + 112 + slot * 24, -1)
    cursor, occupied = DATA, set()
    for key, value in pairs:
        hashed = gdbm.key_hash(key)
        slot = hashed % SLOTS
        while slot in occupied:
            slot = (slot + 1) % SLOTS
        occupied.add(slot)
        struct.pack_into('<i4sqii', raw, BUCKET + 112 + 24 * slot,
                         hashed, key[:4], cursor, len(key), len(value))
        raw[cursor:cursor + len(key) + len(value)] = key + value
        cursor += len(key) + len(value)
    struct.pack_into('<ii', raw, BUCKET + 104, 0, len(occupied))
    return raw


class GdbmDecodeTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'linux', 'Native GNU DBM fixture runs in Linux CI only')
    def test_native_unprivileged_linux_writer_split_delete_and_reuse_crosscheck(self):
        # Native code creates only its own fixture; never run a database library
        # on the user's Mac or feed it an untrusted staged database.
        self.assertNotEqual(os.geteuid(), 0)
        import dbm.gnu
        pairs = {f'page-{index}\0'.encode(): b'value ' + str(index).encode() + b'\0'
                 for index in range(384)}
        pairs[b'\xff\0'] = b'binary\xff\0'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'index.db'
            with dbm.gnu.open(str(path), 'n', 0o600) as native:
                for key, value in pairs.items():
                    native[key] = value
                for key in list(pairs)[::5]:
                    del native[key]
                    del pairs[key]
                for index in range(32):
                    key = f'new-{index}\0'.encode()
                    pairs[key] = b'reused space\0'
                    native[key] = pairs[key]
            result = gdbm.decode(path.read_bytes())
        self.assertGreater(result['buckets'], 1)
        self.assertEqual({base64.b64decode(row['key_base64']):
                          base64.b64decode(row['value_base64'])
                          for row in result['records']}, pairs)

    def test_split_directory_prefix_and_hash_target_are_both_checked(self):
        raw = database()
        cell = BUCKET + 112 + 24 * (gdbm.key_hash(b'name\0') % SLOTS)
        raw.extend(b'\0' * BLOCK)
        struct.pack_into('<q', raw, 32, len(raw))
        raw[2048:2059] = raw[DATA:DATA + 11]
        raw[DATA:DATA + BLOCK] = database(())[BUCKET:BUCKET + BLOCK]
        struct.pack_into('<q', raw, cell + 8, 2048)
        struct.pack_into('<i', raw, BUCKET + 104, 1)
        struct.pack_into('<i', raw, DATA + 104, 1)
        pointers = [BUCKET] * 32 + [DATA] * 32
        if gdbm.key_hash(b'name\0') >> 30:
            pointers.reverse()
        struct.pack_into('<' + 'q' * 64, raw, BLOCK, *pointers)
        self.assertEqual(gdbm.decode(bytes(raw))['buckets'], 2)
        pointers.reverse()
        struct.pack_into('<' + 'q' * 64, raw, BLOCK, *pointers)
        with self.assertRaisesRegex(ValueError, 'directory binding'):
            gdbm.decode(bytes(raw))

    def test_standard_and_extension_preserve_exact_binary_records_without_authority(self):
        pairs = ((b'z\0', b'binary\xff\0'), (b'\xff\0', b'not executable'), (b'a\0', b''))
        for extended in (False, True):
            with self.subTest(extended=extended):
                result = gdbm.decode(bytes(database(pairs, extended=extended)))
                self.assertEqual([(base64.b64decode(row['key_base64']),
                                   base64.b64decode(row['value_base64']))
                                  for row in result['records']], sorted(pairs))
                self.assertEqual(result['decoded_records'], 3)
                self.assertTrue(result['logical_records_decoded'])
                for key in ('free_space_graph_verified', 'all_database_bytes_validated',
                            'man_index_semantics_verified', 'cache_sources_verified',
                            'cache_regeneration_verified', 'changes_authorized',
                            'publication_authorized'):
                    self.assertIs(result[key], False)

    def test_unsupported_header_truncation_and_extension_rejected(self):
        for offset, value in ((0, 0x13579ACD), (4, 513), (16, 256), (20, 17),
                              (24, 1024), (28, 17), (32, 0)):
            raw = database()
            struct.pack_into('<i', raw, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                gdbm.decode(bytes(raw))
        for raw in (b'', bytes(database())[:DATA + 2], bytearray(database())):
            with self.assertRaises(ValueError):
                gdbm.decode(raw)
        raw = database(extended=True)
        struct.pack_into('<i', raw, 48, 1)
        with self.assertRaises(ValueError):
            gdbm.decode(bytes(raw))

    def test_directory_alias_and_bucket_count_binding(self):
        for offset, fmt, value in ((BLOCK, '<q', 1), (BUCKET + 104, '<i', 1),
                                   (BUCKET + 108, '<i', 2), (BUCKET, '<i', 7)):
            raw = database()
            struct.pack_into(fmt, raw, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                gdbm.decode(bytes(raw))
        raw = database()
        struct.pack_into('<q', raw, BLOCK, BUCKET + 8)
        with self.assertRaisesRegex(ValueError, 'metadata regions overlap'):
            gdbm.decode(bytes(raw))

    def test_hash_prefix_and_reachability_are_checked(self):
        key = b'name\0'
        slot = gdbm.key_hash(key) % SLOTS
        for offset, fmt, value in ((BUCKET + 112 + slot * 24, '<i', 0),
                                   (BUCKET + 116 + slot * 24, '<4s', b'bad!')):
            raw = database()
            struct.pack_into(fmt, raw, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                gdbm.decode(bytes(raw))
        raw = database()
        source = BUCKET + 112 + slot * 24
        target = BUCKET + 112 + ((slot + 1) % SLOTS) * 24
        raw[target:target + 24] = raw[source:source + 24]
        struct.pack_into('<i', raw, source, -1)
        with self.assertRaisesRegex(ValueError, 'unreachable'):
            gdbm.decode(bytes(raw))

    def test_data_bounds_overlap_and_duplicate_keys_rejected(self):
        raw = database()
        slot = gdbm.key_hash(b'name\0') % SLOTS
        for offset, fmt, value in ((BUCKET + 120 + slot * 24, '<q', len(raw) - 1),
                                   (BUCKET + 128 + slot * 24, '<i', 4097),
                                   (BUCKET + 132 + slot * 24, '<i', 65537)):
            changed = bytearray(raw)
            struct.pack_into(fmt, changed, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                gdbm.decode(bytes(changed))
        with self.assertRaises(ValueError):
            gdbm.decode(bytes(database(((b'name\0', b'a'), (b'name\0', b'b')))))
        # A key's bytes can look valid inside bucket bookkeeping; it still overlaps.
        changed = database()
        changed[BUCKET + 32:BUCKET + 43] = b'name\0value\0'
        struct.pack_into('<q', changed, BUCKET + 120 + slot * 24, BUCKET + 32)
        with self.assertRaisesRegex(ValueError, 'overlap'):
            gdbm.decode(bytes(changed))
        changed = database(((b'ab\0', b'x\0'), (b'b\0', b'y\0')))
        second_slot = gdbm.key_hash(b'b\0') % SLOTS
        struct.pack_into('<q', changed, BUCKET + 120 + second_slot * 24, DATA + 1)
        with self.assertRaisesRegex(ValueError, 'overlap'):
            gdbm.decode(bytes(changed))

    def test_resource_budgets_and_unused_bytes_do_not_become_validated(self):
        raw = bytes(database())
        for limit in ('MAX_RECORDS', 'MAX_EXPANDED'):
            with patch.object(gdbm, limit, 0), self.assertRaises(ValueError):
                gdbm.decode(raw)
        collisions = {}
        for index in range(100):
            key = f'key{index}'.encode() + b'\0'
            slot = gdbm.key_hash(key) % SLOTS
            if slot in collisions:
                raw_collision = database(((collisions[slot], b'a'), (key, b'b')))
                with patch.object(gdbm, 'MAX_PROBES', 0), self.assertRaises(ValueError):
                    gdbm.decode(bytes(raw_collision))
                break
            collisions[slot] = key
        else:
            self.fail('Fixture needs one probing collision')
        changed = bytearray(raw)
        changed[-20:] = b'uninterpreted slack!'
        first, second = gdbm.decode(raw), gdbm.decode(bytes(changed))
        self.assertEqual(first['records'], second['records'])
        self.assertNotEqual(first['sha256'], second['sha256'])
        self.assertGreater(second['unmodeled_bytes'], 0)
        self.assertFalse(second['all_database_bytes_validated'])
        # GDBM may reserve the last block beyond EOF. Only unused trailing space
        # is removed here; complete active records remain independently bounded.
        shorter = gdbm.decode(raw[:-20])
        self.assertEqual(shorter['records'], first['records'])
        self.assertFalse(shorter['free_space_graph_verified'])
