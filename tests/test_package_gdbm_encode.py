import base64
import hashlib
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_runtime import package_gdbm_encode as writer
from mano_runtime.package_gdbm_decode import decode


def records(raw):
    return {base64.b64decode(row['key_base64']):base64.b64decode(row['value_base64'])
            for row in decode(raw)['records']}


def fixture():
    pairs = {f'page-{index}\0'.encode():b'description-'+str(index).encode()+b'\0'
             for index in range(384)}
    pairs.update({b'\xff\0':b'binary\xff\0', b'\0':b'', b'tabs\t\0':b'\t\0\xff'})
    return pairs


class CanonicalGdbmTests(unittest.TestCase):
    def test_exact_roundtrip_empty_binary_and_split_buckets(self):
        for pairs in ({}, {b'name\0':b'value\0'}, fixture()):
            raw = writer.encode(pairs)
            self.assertEqual(records(raw), pairs)
            report = writer.require_canonical(raw)
            self.assertTrue(report['complete_canonical_encoding_verified'])
            for flag in ('man_index_semantics_verified', 'cache_sources_verified',
                         'changes_authorized', 'publication_authorized'):
                self.assertIs(report[flag], False)
        self.assertGreater(decode(writer.encode(fixture()))['buckets'], 1)

    def test_input_insertion_order_cannot_change_any_output_byte(self):
        pairs = fixture()
        raw = writer.encode(pairs)
        self.assertEqual(raw, writer.encode(dict(reversed(list(pairs.items())))))
        self.assertEqual(raw, writer.encode(dict(sorted(pairs.items()))))
        self.assertEqual(hashlib.sha256(raw).digest(),
                         hashlib.sha256(writer.encode(pairs)).digest())

    def test_unused_header_bucket_cell_padding_and_trailing_changes_reject(self):
        raw = writer.encode({b'name\0':b'value\0'})
        decoded = decode(raw)
        bucket = decoded['records'][0]['bucket_offset']
        active_slot = decoded['records'][0]['slot']
        inactive_slot = (active_slot + 1) % writer.SLOTS
        offsets = [63, bucket + 7, bucket + 112 + 24*inactive_slot + 8, len(raw)-1]
        for offset in offsets:
            altered = bytearray(raw)
            altered[offset] ^= 1
            self.assertEqual(records(bytes(altered)), records(raw))
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, 'deterministic'):
                writer.require_canonical(bytes(altered))

    def test_every_directory_bucket_and_record_is_bound_to_its_encoding(self):
        raw = writer.encode(fixture())
        for offset in (0, 8, 24, 512, decode(raw)['records'][0]['data_offset']):
            changed = bytearray(raw)
            changed[offset] ^= 1
            # A changed actual record is a different valid database, so compare
            # records too. Metadata corruption must reject or change meaning.
            try:
                result = writer.require_canonical(bytes(changed))
            except ValueError:
                continue
            self.assertNotEqual(records(bytes(changed)), records(raw))
            self.assertNotEqual(result['sha256'], hashlib.sha256(raw).hexdigest())

    def test_binary_input_and_resource_budgets_are_explicit(self):
        for bad in ([], {b'':b'x'}, {'name':b'value'}, {b'name':bytearray(b'value')},
                    {b'x'*4097:b'x'}, {b'x':b'x'*65537}):
            with self.subTest(kind=type(bad)), self.assertRaises(ValueError):
                writer.encode(bad)
        for limit in ('MAX_BYTES', 'MAX_RECORDS', 'MAX_EXPANDED'):
            with patch.object(writer, limit, 0), self.assertRaises(ValueError):
                writer.encode({b'x':b'y'})
        with patch.object(writer, 'MAX_BITS', 1), patch.object(writer, 'key_hash', return_value=0):
            with self.assertRaisesRegex(ValueError, 'collision'):
                writer.encode({str(i).encode():b'x' for i in range(17)})

    def test_maximum_frame_sizes_remain_contiguous_and_exact(self):
        pairs = {b'k'*4096:b'v'*65536}
        raw = writer.encode(pairs)
        self.assertEqual(records(raw), pairs)
        self.assertEqual(writer.require_canonical(raw)['records'], 1)
        self.assertEqual(len(raw), struct.unpack_from('<q', raw, 32)[0])

    @unittest.skipUnless(sys.platform == 'linux', 'Native reader/writer runs only in Linux CI')
    def test_native_gnu_dbm_reads_and_updates_own_canonical_synthetic_fixture(self):
        self.assertNotEqual(os.geteuid(), 0)
        import dbm.gnu
        pairs = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            for number, small in enumerate(({}, {b'key\0':b'value\0'},
                                             {b'k'*4096:b'v'*65536})):
                small_path = Path(temporary) / f'small-{number}.db'
                small_path.write_bytes(writer.encode(small))
                with dbm.gnu.open(str(small_path), 'r') as native:
                    self.assertEqual({key:native[key] for key in native.keys()}, small)
            path = Path(temporary) / 'index.db'
            path.write_bytes(writer.encode(pairs))
            with dbm.gnu.open(str(path), 'r') as native:
                self.assertEqual({key:native[key] for key in native.keys()}, pairs)
            with dbm.gnu.open(str(path), 'w') as native:
                del native[b'page-0\0']
                native[b'new\0'] = b'new value\0'
                for index in range(64):
                    native[f'new-{index}'.encode()] = b'new'
            pairs.pop(b'page-0\0')
            pairs[b'new\0'] = b'new value\0'
            pairs.update({f'new-{i}'.encode():b'new' for i in range(64)})
            self.assertEqual(records(path.read_bytes()), pairs)
