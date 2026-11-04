"""Synthetic retained metadata/classifications only; no native parsing or inflation."""
import copy
import json
import unittest
from unittest.mock import patch

from test_package_man_sources import candidate, index, rehash

from mano_runtime import package_man_source_graph as graph
from mano_runtime.package_man_leading_source import inspect
from mano_runtime.package_man_sources import bind


def fixture(text=b'.TH TERMINAL 6\n'):
    tree, _ = candidate()
    bindings = bind({'var/cache/man/index.db': index()}, tree)
    leading = dict(profile='man-leading-source-requests-v1', all_captured_files_classified=True,
                   files={'man6/sl.6.gz': inspect(text)})
    return bindings, leading, tree


def derive(bindings, leading, tree):
    return graph.derive(graph.encoded(bindings), graph.encoded(leading), tree, tree, ['gz'])


class PrimarySourceGraphTests(unittest.TestCase):
    def test_complete_primary_context_coverage_has_no_generated_state_authority(self):
        bindings, leading, tree = fixture()
        report, raw = derive(bindings, leading, tree)
        self.assertEqual(json.loads(raw), report)
        self.assertEqual(report['primary_records'], 1)
        self.assertEqual(report['resolution_counts'], dict(terminal=1, unresolved=0, unknown=0))
        self.assertTrue(report['all_primary_conditional_chains_terminate'])
        for key in ('filesystem_source_paths_opened', 'staged_data_inflated',
                    'native_namespace_equivalence_verified', 'complete_source_graph_verified',
                    'virtual_alias_declarations_verified', 'descriptions_verified',
                    'generated_state_validated', 'publication_authorized'):
            self.assertFalse(report[key])

    def test_repeated_index_record_context_is_represented_once_without_losing_coverage(self):
        bindings, leading, tree = fixture()
        rows = bindings['indexes']['var/cache/man/index.db']['records']
        rows['second-record-opaque-key'] = copy.deepcopy(next(iter(rows.values())))
        bindings.update(primary_records=2, direct_records=2)
        report, _ = derive(bindings, leading, tree)
        self.assertEqual(report['distinct_primary_contexts'], 1)
        self.assertEqual(report['primary_records'], 2)
        self.assertEqual(len(report['indexes']['var/cache/man/index.db']), 2)

    def test_cycles_and_missing_classifications_remain_explicitly_incomplete(self):
        bindings, leading, tree = fixture(b'.so sl.6.gz\n')
        report, _ = derive(bindings, leading, tree)
        self.assertEqual(report['resolution_counts']['unresolved'], 1)
        self.assertFalse(report['all_primary_conditional_chains_terminate'])
        bindings, leading, tree = fixture(b'.so target.6.gz\n')
        source = tree['entries']['usr/share/man/man6/sl.6.gz']
        tree['entries']['usr/share/man/man6/target.6.gz'] = dict(source,
            hardlink_anchor='usr/share/man/man6/target.6.gz')
        rehash(tree)
        bindings['candidate_sha256'] = tree['manifest_sha256']
        report, _ = derive(bindings, leading, tree)
        self.assertEqual(report['resolution_counts']['unknown'], 1)
        self.assertFalse(report['all_primary_conditional_chains_terminate'])

    def test_changed_source_metadata_unbound_records_and_wrong_counts_refuse(self):
        for change in ('metadata', 'unbound', 'count', 'decimal', 'candidate'):
            bindings, leading, tree = fixture()
            row = next(iter(bindings['indexes']['var/cache/man/index.db']['records'].values()))
            if change == 'metadata':
                row['observed_metadata_sha256'] = '0'*64
            elif change == 'unbound':
                row['primary_metadata_bound'] = False
            elif change == 'count':
                bindings['primary_records'] = 2
            elif change == 'decimal':
                bindings['primary_records'] = 1.0
            else:
                bindings['candidate_sha256'] = '0'*64
            with self.subTest(change=change), self.assertRaises(ValueError):
                derive(bindings, leading, tree)

    def test_classification_scope_completeness_and_duplicate_json_fields_refuse(self):
        for relative in ('../outside', '/outside', 'man6/absent.6.gz'):
            bindings, leading, tree = fixture()
            leading['files'][relative] = leading['files'].pop('man6/sl.6.gz')
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                derive(bindings, leading, tree)
        bindings, leading, tree = fixture()
        leading['all_captured_files_classified'] = False
        with self.assertRaises(ValueError):
            derive(bindings, leading, tree)
        with self.assertRaises(ValueError):
            graph.derive(graph.encoded(bindings), b'{"files":{},"files":{}}', tree, tree, ['gz'])

    def test_context_record_input_and_report_resource_bounds_refuse(self):
        bindings, leading, tree = fixture()
        for setting, maximum in (('MAX_CONTEXTS', 0), ('MAX_RECORDS', 0),
                                 ('MAX_INPUT_BYTES', 1), ('MAX_REPORT_BYTES', 100)):
            with self.subTest(setting=setting), patch.object(graph, setting, maximum), \
                    self.assertRaises(ValueError):
                derive(bindings, leading, tree)


if __name__ == '__main__':
    unittest.main()
