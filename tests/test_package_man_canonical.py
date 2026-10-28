import base64
import hashlib
import json
import unittest
from unittest.mock import patch

from test_package_man_sources import candidate, index, rehash

from mano_runtime import package_man_canonical as canonical
from mano_runtime.package_gdbm_encode import require_canonical


def bundle(raw, path='index.db'):
    return json.dumps({path:base64.b64encode(raw).decode()}).encode()


class DerivedManCacheTests(unittest.TestCase):
    def test_raw_and_canonical_input_identity_are_separate_and_all_bytes_bound(self):
        tree, _ = candidate()
        raw = bytearray(index())
        raw[63] = 65  # Unmodeled native allocator bytes must not survive canonicalization.
        original = bytes(raw)
        packet = bundle(original)
        summary, artifacts = canonical.derive(packet, tree)
        self.assertEqual(set(artifacts), canonical.FILES)
        self.assertEqual(summary['input_bundle_sha256'], hashlib.sha256(packet).hexdigest())
        encoded = json.loads(artifacts['staged-man-canonical-bytes.json'])['index.db']
        derived = base64.b64decode(encoded)
        self.assertNotEqual(original, derived)
        self.assertEqual(derived[63], 0)
        proof = require_canonical(derived)
        self.assertEqual(summary['databases']['index.db']['canonical'], proof)
        self.assertEqual(summary['primary_records_bound'], 1)
        self.assertTrue(summary['all_primary_records_bound'])
        for name, data in artifacts.items():
            self.assertEqual(summary['artifacts'][name],
                             dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
        for flag in ('transitive_source_graph_verified', 'descriptions_verified',
                     'compression_filters_verified', 'all_records_source_bound',
                     'cache_sources_verified', 'generated_state_validated',
                     'changes_authorized', 'publication_authorized'):
            self.assertIs(summary[flag], False)

    def test_record_frames_and_source_report_bind_the_actual_canonical_artifact(self):
        tree, _ = candidate()
        _, artifacts = canonical.derive(bundle(index()), tree)
        encoded = json.loads(artifacts['staged-man-canonical-bytes.json'])['index.db']
        digest = hashlib.sha256(base64.b64decode(encoded)).hexdigest()
        frames = json.loads(artifacts['staged-man-canonical-frames.json'])
        sources = json.loads(artifacts['staged-man-canonical-sources.json'])
        self.assertEqual(frames['index.db']['input_sha256'], digest)
        self.assertEqual(sources['indexes']['var/cache/man/index.db']['input_sha256'], digest)

    def test_unknown_source_does_not_get_blessed_by_valid_canonical_bytes(self):
        tree, path = candidate()
        tree['entries'].pop(path)
        rehash(tree)
        summary, _ = canonical.derive(bundle(index()), tree)
        self.assertTrue(summary['complete_canonical_encoding_verified'])
        self.assertFalse(summary['all_primary_records_bound'])
        self.assertEqual(summary['primary_records_bound'], 0)
        self.assertFalse(summary['generated_state_validated'])

    def test_duplicate_paths_bad_names_invalid_records_and_oversized_artifacts_reject(self):
        tree, _ = candidate()
        encoded = base64.b64encode(index()).decode()
        for bad in (b'[]', b'{}', b'{"../index.db":"AA=="}', b'{"index.db":"???"}',
                    ('{"index.db":"'+encoded+'","index.db":"'+encoded+'"}').encode()):
            with self.subTest(raw=bad[:40]), self.assertRaises(ValueError):
                canonical.derive(bad, tree)
        from mano_runtime.package_gdbm_encode import encode
        with self.assertRaises(ValueError):
            canonical.derive(bundle(encode({b'other':b'no man-db version'})), tree)
        for limit in ('MAX_DATABASES', 'MAX_BYTES', 'MAX_RECORDS', 'MAX_REPORT_BYTES',
                      'MAX_ARTIFACT_BYTES'):
            with patch.object(canonical, limit, 0), self.assertRaises(ValueError):
                canonical.derive(bundle(index()), tree)

    def test_database_order_cannot_change_outputs_or_report_hashes(self):
        tree, _ = candidate(locale='de')
        a = {'de/index.db':base64.b64encode(index()).decode(),
             'index.db':base64.b64encode(index()).decode()}
        b = dict(reversed(list(a.items())))
        left, left_artifacts = canonical.derive(json.dumps(a).encode(), tree)
        right, right_artifacts = canonical.derive(json.dumps(b).encode(), tree)
        self.assertNotEqual(left.pop('input_bundle_sha256'), right.pop('input_bundle_sha256'))
        self.assertEqual(left, right)
        self.assertEqual(left_artifacts, right_artifacts)
