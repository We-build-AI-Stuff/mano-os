"""Synthetic classified-source chains; no native or actual decompression proof."""
import copy
import unittest
from unittest.mock import patch

from test_package_man_reference_lookup import ORIGINAL, ROOT, trees
from test_package_man_sources import rehash

from mano_runtime import package_man_reference_lookup as lookup
from mano_runtime.package_man_leading_source import inspect


def source_inputs(namespace, texts):
    return {ROOT+'/'+path: dict(compressed_sha256=namespace._entries[ROOT+'/'+path]['sha256'],
                               request=inspect(text)) for path, text in texts.items()}


class ConditionalChainTests(unittest.TestCase):
    def test_original_directory_survives_recursive_hops(self):
        baseline, after = trees(files=('man2/first.1', 'man1/end.1', 'man2/end.1'),
                                directories=('man2',))
        namespace = lookup.Namespace(baseline, after)
        inputs = source_inputs(namespace, {'man1/original.1.gz': b'.so man2/first.1\n',
            'man2/first.1': b'.so end.1\n', 'man1/end.1': b'.TH RIGHT 1\n',
            'man2/end.1': b'.TH WRONG 1\n'})
        report = namespace.resolve_source(ROOT, ORIGINAL, inputs, ['gz'])
        self.assertEqual(report['resolution_state'], 'terminal')
        self.assertEqual(report['terminal']['path'], ROOT+'/man1/end.1')
        self.assertEqual(len(report['lookups']), 2)
        self.assertFalse(report['source_target_resolution_verified'])
        self.assertFalse(report['publication_authorized'])

    def test_nine_hops_can_terminate_but_tenth_relative_hop_hits_native_limit(self):
        for count, expected in ((9, 'terminal'), (10, 'unresolved')):
            names = tuple(f'p{i}.1' for i in range(count+1))
            baseline, after = trees(files=names)
            namespace = lookup.Namespace(baseline, after)
            texts = {name: f'.so p{i+1}.1\n'.encode() for i, name in enumerate(names[:-1])}
            texts[names[-1]] = b'.TH END 1\n'
            report = namespace.resolve_source(ROOT, ROOT+'/p0.1',
                source_inputs(namespace, texts), [])
            self.assertEqual(report['resolution_state'], expected)
            self.assertEqual(len(report['inspections']), 10)
            if count == 10:
                self.assertEqual(report['reason'], 'native-ten-inspection-limit')

    def test_cycle_is_bounded_without_inventing_a_terminal(self):
        baseline, after = trees(files=('a.1', 'b.1'))
        namespace = lookup.Namespace(baseline, after)
        report = namespace.resolve_source(ROOT, ROOT+'/a.1', source_inputs(namespace,
            {'a.1': b'.so b.1\n', 'b.1': b'.so a.1\n'}), [])
        self.assertEqual(report['resolution_state'], 'unresolved')
        self.assertEqual(len(report['inspections']), 10)
        self.assertTrue(report['repeated_source_paths'])
        self.assertNotIn('terminal', report)

    def hardlinks(self, *, symlink=False):
        baseline, after = trees(files=('man1/a.1', 'man1/b.1'),
            links=(('man1/link.1', 'b.1'),) if symlink else ())
        for tree in (baseline, after):
            first = tree['entries'][ROOT+'/man1/a.1']
            first.update(nlink=2, hardlink_anchor=ROOT+'/man1/a.1')
            tree['entries'][ROOT+'/man1/b.1'] = dict(first)
            rehash(tree)
        return lookup.Namespace(baseline, after)

    def test_initial_regular_hardlink_chooses_least_same_directory_basename(self):
        namespace = self.hardlinks()
        inputs = source_inputs(namespace, {'man1/a.1': b'.TH END 1\n',
                                           'man1/b.1': b'.TH END 1\n'})
        report = namespace.resolve_source(ROOT, ROOT+'/man1/b.1', inputs, [])
        self.assertEqual(report['terminal']['path'], ROOT+'/man1/a.1')
        self.assertEqual(report['initial_hardlink_selection']['selected'], ROOT+'/man1/a.1')

    def test_initial_single_link_symlink_does_not_recanonicalize_target_hardlinks(self):
        namespace = self.hardlinks(symlink=True)
        inputs = source_inputs(namespace, {'man1/a.1': b'.TH END 1\n',
                                           'man1/b.1': b'.TH END 1\n'})
        report = namespace.resolve_source(ROOT, ROOT+'/man1/link.1', inputs, [])
        self.assertEqual(report['initial_lstat']['kind'], 'symlink')
        self.assertEqual(report['terminal']['path'], ROOT+'/man1/b.1')
        self.assertIsNone(report['initial_hardlink_selection'])

    def test_supplied_content_does_not_override_directory_or_file_read_permissions(self):
        namespace = self.hardlinks()
        namespace._entries[ROOT+'/man1']['mode'] = 0o711
        inputs = source_inputs(namespace, {'man1/a.1': b'.TH END 1\n',
                                           'man1/b.1': b'.TH END 1\n'})
        report = namespace.resolve_source(ROOT, ROOT+'/man1/b.1', inputs, [])
        self.assertEqual(report['resolution_state'], 'unknown')
        self.assertEqual(report['reason'], 'initial-hardlink-directory-read-unverified')
        baseline, after = trees(modes={'man1/original.1.gz': 0o600})
        namespace = lookup.Namespace(baseline, after)
        inputs = source_inputs(namespace, {'man1/original.1.gz': b'.TH END 1\n'})
        report = namespace.resolve_source(ROOT, ORIGINAL, inputs, [])
        self.assertEqual(report['resolution_state'], 'unknown')
        self.assertEqual(report['reason'], 'source-read-permission-unverified')
        self.assertEqual(report['inspections'], [])

    def test_missing_classification_and_nonregular_selection_remain_unknown(self):
        baseline, after = trees(files=('target.1',), directories=('poison.1',))
        namespace = lookup.Namespace(baseline, after)
        for text, reason in ((b'.so target.1\n', 'source-classification-not-captured'),
                             (b'.so poison.1\n', 'selected-nonregular-source-not-captured')):
            report = namespace.resolve_source(ROOT, ORIGINAL,
                source_inputs(namespace, {'man1/original.1.gz': text}), [])
            self.assertEqual(report['resolution_state'], 'unknown')
            self.assertEqual(report['reason'], reason)

    def test_absolute_request_stops_without_opening_operand_and_empty_request_does_not(self):
        baseline, after = trees()
        namespace = lookup.Namespace(baseline, after)
        absolute = source_inputs(namespace, {'man1/original.1.gz': b'.so /unopened\n'})
        report = namespace.resolve_source(ROOT, ORIGINAL, absolute, [])
        self.assertEqual(report['resolution_state'], 'terminal')
        self.assertEqual(report['lookups'], [])
        empty = source_inputs(namespace, {'man1/original.1.gz': b'.so \n'})
        report = namespace.resolve_source(ROOT, ORIGINAL, empty, [])
        self.assertEqual(report['resolution_state'], 'unknown')

    def test_false_binding_and_authority_or_malformed_classification_refuse(self):
        baseline, after = trees()
        namespace = lookup.Namespace(baseline, after)
        inputs = source_inputs(namespace, {'man1/original.1.gz': b'.TH END 1\n'})
        for mutate in (lambda row: row.update(compressed_sha256='0'*64),
                       lambda row: row['request'].update(publication_authorized=True),
                       lambda row: row['request'].update(request_kind=[]),
                       lambda row: row['request'].update(input_bytes=True),
                       lambda row: row['request'].update(operand_base64='!')):
            changed = copy.deepcopy(inputs)
            mutate(changed[ORIGINAL])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                namespace.resolve_source(ROOT, ORIGINAL, changed, [])
        with patch.object(lookup, 'MAX_REPORT_BYTES', 0), self.assertRaises(ValueError):
            namespace.resolve_source(ROOT, ORIGINAL, inputs, [])
