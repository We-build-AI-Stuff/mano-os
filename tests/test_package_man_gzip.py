import binascii
import gzip
import hashlib
import os
import subprocess
import sys
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from mano_runtime import package_man_gzip as framed


def member(data, *, name=None, comment=None, extra=None, hcrc=False, level=6, strategy=0):
    flags = (8 if name is not None else 0) | (16 if comment is not None else 0)
    flags |= (4 if extra is not None else 0) | (2 if hcrc else 0)
    header = b'\x1f\x8b\x08'+bytes([flags])+b'\0'*4+b'\0\xff'
    if extra is not None:
        header += len(extra).to_bytes(2, 'little')+extra
    if name is not None:
        header += name+b'\0'
    if comment is not None:
        header += comment+b'\0'
    if hcrc:
        header += (binascii.crc32(header) & 0xffff).to_bytes(2, 'little')
    codec = zlib.compressobj(level, zlib.DEFLATED, -15, strategy=strategy)
    return (header+codec.compress(data)+codec.flush()+
            (binascii.crc32(data) & 0xffffffff).to_bytes(4, 'little')+
            len(data).to_bytes(4, 'little'))


class BoundedManualGzipTests(unittest.TestCase):
    def test_exact_binary_bytes_and_header_names_are_inert(self):
        data = b'.so /etc/shadow\n\0\xff'
        raw = member(data, name=b'../../outside.gz', comment=b'$(do-not-execute)',
                     extra=b'ZZ\x03\0abc', hcrc=True)
        expanded, report = framed.decode(raw)
        self.assertEqual(expanded, data)
        self.assertEqual(gzip.decompress(raw), data)
        self.assertEqual(report['expanded_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(report['members'][0]['optional_fields']['original_name']['bytes'], 16)
        for flag in ('header_names_used_as_paths', 'header_times_used_as_source_authority',
                     'roff_interpreted', 'source_declarations_verified',
                     'transitive_source_graph_verified', 'generated_state_validated',
                     'changes_authorized', 'publication_authorized'):
            self.assertIs(report[flag], False)

    def test_stored_fixed_dynamic_and_other_deflate_strategies(self):
        data = bytes(range(256))*100+b'x'*10000
        for level in (0, 1, 6, 9):
            for strategy in (zlib.Z_DEFAULT_STRATEGY, zlib.Z_FIXED,
                             zlib.Z_HUFFMAN_ONLY, zlib.Z_RLE):
                raw = member(data, level=level, strategy=strategy)
                with self.subTest(level=level, strategy=strategy):
                    self.assertEqual(framed.decode(raw)[0], data)

    def test_multiple_members_and_explicit_zero_padding_extension(self):
        raw = member(b'first')+b'\0\0'+member(b'next')+b'\0'*4
        expanded, report = framed.decode(raw)
        self.assertEqual(expanded, b'firstnext')
        self.assertEqual(gzip.decompress(raw), expanded)
        self.assertEqual(len(report['members']), 2)
        self.assertEqual(report['zero_padding_bytes'], 6)

    def test_every_truncation_of_one_member_rejects(self):
        raw = member(b'fixture', name=b'input', comment=b'note', extra=b'xy\0\0', hcrc=True)
        for size in range(len(raw)):
            with self.subTest(size=size), self.assertRaises(ValueError):
                framed.decode(raw[:size])

    def test_bad_header_reserved_flags_checksums_sizes_and_trailing_data_reject(self):
        raw = member(b'fixture', hcrc=True)
        for position in (0, 2, 3, 10, len(raw)-8, len(raw)-4):
            changed = bytearray(raw)
            changed[position] ^= 0xff
            with self.subTest(position=position), self.assertRaises(ValueError):
                framed.decode(bytes(changed))
        for changed in (raw+b'junk', raw+b'\0junk', b'\0'+raw, raw+member(b'later')[:-1]):
            with self.subTest(raw=changed[-10:]), self.assertRaises(ValueError):
                framed.decode(changed)
        changed = bytearray(member(b''))
        changed[10] = 7  # BFINAL=1, BTYPE=3 is reserved and invalid.
        with self.assertRaises(ValueError):
            framed.decode(bytes(changed))

    def test_limits_apply_before_unbounded_inflation_or_output_join(self):
        raw = member(b'A'*1024**2)
        with self.assertRaises(ValueError):
            framed.decode(raw, maximum=100)
        self.assertEqual(len(framed.decode(raw, maximum=1024**2)[0]), 1024**2)
        for bad in (True, -1, framed.MAX_EXPANDED_BYTES+1):
            with self.assertRaises(ValueError):
                framed.decode(raw, maximum=bad)
        for limit, sample in (('MAX_INPUT_BYTES', raw), ('MAX_MEMBERS', member(b'')),
                              ('MAX_PADDING_BYTES', member(b'')+b'\0')):
            with patch.object(framed, limit, 0), self.assertRaises(ValueError):
                framed.decode(sample)
        with self.assertRaises(ValueError):
            framed.decode(member(b'abc')+member(b'def'), maximum=5)

    def test_empty_member_can_exactly_fit_a_zero_expansion_budget(self):
        self.assertEqual(framed.decode(member(b''), maximum=0)[0], b'')
        with self.assertRaises(ValueError):
            framed.decode(member(b'x'), maximum=0)
        with self.assertRaises(ValueError):
            framed.decode(b'\0'*10)

    @unittest.skipUnless(sys.platform == 'linux', 'GNU gzip crosscheck runs only in Linux CI')
    def test_linux_gzip_independently_reads_only_self_created_streams(self):
        self.assertNotEqual(os.geteuid(), 0)
        self.assertTrue(Path('/usr/bin/gzip').is_file())
        for raw in (member(b'fixture', hcrc=True, name=b'../../never-written'),
                    member(b'first')+member(b'second')+b'\0'*8):
            expected, _ = framed.decode(raw)
            process = subprocess.run(['/usr/bin/gzip', '-cd'], input=raw,
                                     capture_output=True, timeout=5, check=False)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(process.stdout, expected)
        # Python's bounded compatibility extension accepts a padding gap, but
        # GNU gzip stops after the first member. Content authority requires both
        # decoders to agree normally, so this case must not pass that worker.
        raw = member(b'first')+b'\0\0'+member(b'second')
        self.assertEqual(framed.decode(raw)[0], b'firstsecond')
        process = subprocess.run(['/usr/bin/gzip', '-cd'], input=raw,
                                 capture_output=True, timeout=5, check=False)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, b'first')
        self.assertIn(b'trailing garbage', process.stderr)
