"""Synthetic bytes only; no staged-source inflation or native host execution."""
import base64
import hashlib
import io
import json
import struct
import unittest
from unittest.mock import patch

from test_package_man_gzip import member
from test_package_man_source_content import witness

from mano_runtime import package_man_gzip as codec
from mano_runtime import package_man_source_content as content


class ExpandedInputsTests(unittest.TestCase):
    def fixture(self):
        # Input order differs deliberately; names and source text remain data.
        bodies = {'man1/z.1.gz': b'\x00.so ../../not-opened\n',
                  'man1/a.1.gz': b'', 'ru/man1/\u044f.1.gz': b'fixture\n'*10000}
        raw = {name: member(body) for name, body in bodies.items()}
        manifest = {name: dict(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
                    for name, data in raw.items()}
        return bodies, raw, manifest

    def test_stream_records_exact_canonical_bytes_and_hashes(self):
        bodies, raw, manifest = self.fixture()
        stream = io.BytesIO()
        sink = content.ExpandedInputs(stream, 'a'*64, manifest)
        with patch.object(content, 'verify_gnu', side_effect=witness):
            result = content.process_files(dict(files={name: base64.b64encode(data).decode()
                for name, data in raw.items()}), codec, expanded_sink=sink)
        data = stream.getvalue()
        self.assertEqual(data[:19], b'MANO-MAN-EXPANDED\x00\x01')
        self.assertEqual(data[19:51], bytes.fromhex('a'*64))
        self.assertEqual(int.from_bytes(data[51:55], 'big'), len(raw))
        cursor = 55
        for name in sorted(bodies):
            name_length, expanded_length = struct.unpack('>IQ', data[cursor:cursor+12])
            cursor += 12
            self.assertEqual(data[cursor:cursor+name_length], name.encode())
            cursor += name_length
            self.assertEqual(data[cursor:cursor+32].hex(), manifest[name]['sha256'])
            cursor += 32
            self.assertEqual(data[cursor:cursor+32], hashlib.sha256(bodies[name]).digest())
            cursor += 32
            self.assertEqual(data[cursor:cursor+expanded_length], bodies[name])
            cursor += expanded_length
        self.assertEqual(cursor, len(data))
        self.assertEqual(result['profile'], 'man-source-gzip-content-v2')
        self.assertEqual(result['expanded_inputs']['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(result['expanded_inputs']['bytes'], len(data))
        self.assertFalse(result['publication_authorized'])
        summary = content.validate_report(result, dict(files=manifest))
        self.assertEqual(summary['expanded_inputs'], result['expanded_inputs'])
        self.assertNotIn('expanded_bytes_reacquired', summary)
        with self.assertRaises(ValueError):
            sink.finish()
        with self.assertRaises(ValueError):
            sink.append('man1/a.1.gz', manifest['man1/a.1.gz']['sha256'], b'')

    def test_invalid_manifest_names_digests_counts_and_budgets_refuse(self):
        for files in ({}, {'../x': dict(sha256='a'*64)}, {'/x': dict(sha256='a'*64)},
                      {'x//y': dict(sha256='a'*64)}, {'x\0': dict(sha256='a'*64)},
                      {'x': dict(sha256='A'*64)}, {'x': []}, {1: {}},
                      {str(i): {} for i in range(8193)}):
            with self.subTest(files=str(files)[:100]), self.assertRaises(ValueError):
                content.ExpandedInputs(io.BytesIO(), 'a'*64, files)
        for limit in ('MAX_PATH_BYTES', 'MAX_BUNDLE_BYTES'):
            with patch.object(content, limit, 0), self.assertRaises(ValueError):
                content.ExpandedInputs(io.BytesIO(), 'a'*64, {'x': dict(sha256='b'*64)})

    def test_order_digest_missing_record_and_preflight_limits(self):
        _, _, manifest = self.fixture()
        stream = io.BytesIO()
        sink = content.ExpandedInputs(stream, 'a'*64, manifest)
        original = stream.getvalue()
        for name, digest, body in (('man1/z.1.gz', manifest['man1/z.1.gz']['sha256'], b''),
                                   ('man1/a.1.gz', '0'*64, b''),
                                   ('man1/a.1.gz', manifest['man1/a.1.gz']['sha256'], bytearray()),
                                   ('man1/a.1.gz', manifest['man1/a.1.gz']['sha256'],
                                    b'x'*(8*1024**2+1))):
            with self.assertRaises(ValueError):
                sink.append(name, digest, body)
            self.assertEqual(stream.getvalue(), original)
        with self.assertRaises(ValueError):
            sink.finish()
        for limit in ('MAX_EXPANDED_TOTAL', 'MAX_BUNDLE_BYTES'):
            with patch.object(content, limit, 0), self.assertRaises(ValueError):
                sink.append('man1/a.1.gz', manifest['man1/a.1.gz']['sha256'], b'x')
            self.assertEqual(stream.getvalue(), original)

    def test_short_writes_complete_and_failed_writes_poison_sink(self):
        class Short(io.BytesIO):
            def write(self, data):
                return super().write(data[:3])

        class Broken(io.BytesIO):
            fail = False

            def write(self, data):
                return 0 if self.fail else super().write(data)

        for kind in (Short, Broken):
            with self.subTest(kind=kind):
                stream = kind()
                sink = content.ExpandedInputs(stream, 'a'*64, {'x': dict(sha256='b'*64)})
                if kind is Broken:
                    stream.fail = True
                    with self.assertRaises(OSError):
                        sink.append('x', 'b'*64, b'fixture')
                    stream.fail = False
                    with self.assertRaises(ValueError):
                        sink.append('x', 'b'*64, b'fixture')
                    with self.assertRaises(ValueError):
                        sink.finish()
                else:
                    sink.append('x', 'b'*64, b'fixture')
                    result = sink.finish()
                    self.assertEqual(result['sha256'],
                                     hashlib.sha256(stream.getvalue()).hexdigest())

    def test_decoder_disagreement_never_writes_a_record(self):
        raw = member(b'fixture')
        stream = io.BytesIO()
        sink = content.ExpandedInputs(stream, 'a'*64,
                                     {'x': dict(sha256=hashlib.sha256(raw).hexdigest())})
        header = stream.getvalue()
        with patch.object(content, 'verify_gnu', side_effect=ValueError('disagreed')), \
                self.assertRaises(ValueError):
            content.process_files(dict(files={'x': base64.b64encode(raw).decode()}),
                                  codec, expanded_sink=sink)
        self.assertEqual(stream.getvalue(), header)
        with self.assertRaises(ValueError):
            sink.finish()

    def test_legacy_process_still_discards_by_default(self):
        with patch.object(content, 'verify_gnu', side_effect=witness):
            report = content.process_files(
                dict(files={'x': base64.b64encode(member(b'x')).decode()}), codec)
        self.assertEqual(report['profile'], 'man-source-gzip-content-v1')
        self.assertNotIn('expanded_inputs', report)
        self.assertNotIn('expanded_inputs', json.dumps(report['files']))
