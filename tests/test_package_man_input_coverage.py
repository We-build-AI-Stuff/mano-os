import copy
import hashlib
import json
import unittest

from test_package_man_sources import candidate, index, rehash

from mano_runtime.package_man_input_coverage import bind
from mano_runtime.package_man_source_bytes import prepare


def fixture():
    tree, path = candidate()
    extra = 'usr/share/man/man6/not-indexed.6.gz'
    tree['entries'][extra] = dict(tree['entries'][path], hardlink_anchor=extra,
                                 bytes=1, sha256=hashlib.sha256(b'x').hexdigest())
    rehash(tree)
    packet = prepare({'var/cache/man/index.db': index()}, tree, tree)
    # Fabricated native witness summaries: this test proves only metadata binding.
    source = dict(profile='man-source-opaque-bytes-v2',
        scope='observed-manual-root-regular-files',
        observed_manual_root_regular_files_captured=True, all_captured_content_hashes_match=True,
        manifest_sha256=hashlib.sha256(packet).hexdigest(), capture_sha256='a'*64,
        domain_drained=True, control_fixture_unchanged=True, source_files=2, source_bytes=1,
        indexed_source_files=1, additional_manual_files=1,
        changes_authorized=False, publication_authorized=False)
    content = dict(profile='man-source-gzip-content-v1',
        manifest_sha256=source['manifest_sha256'], input_capture_sha256='a'*64,
        capture_sha256='b'*64, domain_drained=True, control_fixture_unchanged=True,
        both_decoders_equal=True, source_files=2, expanded_bytes=10, gzip_members=2,
        changes_authorized=False, publication_authorized=False)
    return packet, tree, source, content


class ManualInputCoverageTests(unittest.TestCase):
    def test_all_observed_files_bind_without_semantic_or_runtime_authority(self):
        result = bind(*fixture())
        self.assertEqual((result['source_files'], result['indexed_source_files'],
                          result['additional_manual_files']), (2, 1, 1))
        self.assertTrue(result['observed_regular_file_inventory_covered'])
        self.assertTrue(result['gzip_decoding_covered_all_captured_files'])
        for key in ('actual_filesystem_reacquired', 'complete_readable_namespace_verified',
                    'roff_interpreted', 'source_declarations_verified', 'runtime_closure_verified',
                    'generated_state_validated', 'publication_authorized'):
            self.assertIs(result[key], False)

    def test_missing_unindexed_file_and_changed_observed_bytes_reject(self):
        packet, tree, source, content = fixture()
        request = json.loads(packet)
        del request['files']['man6/not-indexed.6.gz']
        changed = json.dumps(request, sort_keys=True).encode()
        with self.assertRaises(ValueError):
            bind(changed, tree, source, content)
        tree['entries']['usr/share/man/man6/not-indexed.6.gz']['sha256'] = 'c'*64
        rehash(tree)
        with self.assertRaises(ValueError):
            bind(packet, tree, source, content)

    def test_cross_capture_mismatch_incomplete_domain_and_false_counts_reject(self):
        packet, tree, source, content = fixture()
        for which, field, bad in ((0, 'source_files', True), (0, 'indexed_source_files', 2),
                (0, 'profile', 'man-source-opaque-bytes-v1'),
                (0, 'observed_manual_root_regular_files_captured', False),
                (1, 'input_capture_sha256', 'c'*64), (1, 'both_decoders_equal', False),
                (1, 'domain_drained', False), (1, 'control_fixture_unchanged', False),
                (1, 'capture_sha256', 'invalid'), (1, 'expanded_bytes', 64*1024**2+1),
                (1, 'gzip_members', 1), (0, 'publication_authorized', True)):
            reports = [copy.deepcopy(source), copy.deepcopy(content)]
            reports[which][field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                bind(packet, tree, *reports)

    def test_inventory_scope_cannot_downgrade_to_only_indexed_sources(self):
        packet, tree, source, content = fixture()
        request = json.loads(packet)
        for field, bad in (('profile', 'man-source-opaque-bytes-v1'),
                           ('scope', 'resolved-index-files')):
            changed = json.dumps(dict(request, **{field: bad})).encode()
            with self.subTest(field=field), self.assertRaises(ValueError):
                bind(changed, tree, source, content)
