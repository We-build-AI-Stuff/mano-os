import base64
import unittest
from unittest.mock import patch

from test_package_man_records import database, record
from test_package_man_sources import candidate, rehash

from mano_runtime import package_man_virtual_metadata as virtual


def inputs(**changes):
    target = record(sec=b'5', nano=b'9')
    fields = dict(name=b'/etc/shadow', kind=b'C', pointer=b'sl', description=b'',
                  sec=b'5', nano=b'9')
    fields.update(changes)
    return {b'sl\0':target, b'/etc/shadow\0':record(**fields)}


def link(report):
    return report['indexes']['var/cache/man/index.db']['virtual_links'][
        base64.b64encode(b'/etc/shadow\0').decode()]


class VirtualManMetadataTests(unittest.TestCase):
    def test_absolute_virtual_alias_is_inert_and_resolves_only_exact_primary_metadata(self):
        tree, _ = candidate()
        report = virtual.inspect({'var/cache/man/index.db':database(inputs())}, tree)
        self.assertEqual((report['virtual_records'], report['virtual_targets_metadata_bound']),
                         (1, 1))
        self.assertTrue(report['all_virtual_targets_metadata_bound'])
        self.assertTrue(link(report)['virtual_target_metadata_bound'])
        self.assertEqual(link(report)['target_key_base64'], base64.b64encode(b'sl\0').decode())
        self.assertNotIn('primary_path', link(report))
        for flag in ('alias_names_interpreted_as_paths', 'virtual_alias_declarations_verified',
                     'transitive_source_graph_verified', 'descriptions_verified',
                     'compression_filters_verified', 'cache_sources_verified',
                     'generated_state_validated', 'changes_authorized', 'publication_authorized'):
            self.assertIs(report[flag], False)

    def test_missing_case_wrong_extension_section_or_virtual_target_never_gets_substituted(self):
        tree, _ = candidate()
        for fields in (dict(pointer=b'other'), dict(pointer=b'SL'), dict(pointer=b'-'),
                       dict(ext=b'5'), dict(section=b'5'), dict(pointer=b'../../sl')):
            report = virtual.inspect({'var/cache/man/index.db':database(inputs(**fields))}, tree)
            with self.subTest(fields=fields):
                self.assertFalse(link(report)['virtual_target_metadata_bound'])
                self.assertFalse(report['all_virtual_targets_metadata_bound'])
        pairs = inputs(pointer=b'/etc/shadow')  # A virtual self-reference cannot target itself.
        report = virtual.inspect({'var/cache/man/index.db':database(pairs)}, tree)
        self.assertEqual(link(report)['reason'], 'missing-primary-record')

    def test_ambiguous_primary_records_are_not_chosen_by_iteration_order(self):
        tree, _ = candidate()
        pairs = inputs()
        pairs[b'sl\t6\0'] = record(sec=b'5', nano=b'9')
        report = virtual.inspect({'var/cache/man/index.db':database(pairs)}, tree)
        self.assertEqual(link(report)['reason'], 'ambiguous-primary-record')

    def test_changed_metadata_and_inline_description_stay_unresolved(self):
        tree, _ = candidate()
        for fields in (dict(filters=b't'), dict(comp=b'-'), dict(sec=b'6'), dict(nano=b'8'),
                       dict(description=b'not deduplicated'), dict(sec=b'-1', nano=b'-1')):
            report = virtual.inspect({'var/cache/man/index.db':database(inputs(**fields))}, tree)
            with self.subTest(fields=fields):
                self.assertFalse(link(report)['virtual_target_metadata_bound'])
                self.assertEqual(report['virtual_targets_metadata_bound'], 0)

    def test_matching_record_without_a_bound_source_stays_unresolved(self):
        tree, path = candidate()
        tree['entries'].pop(path)
        rehash(tree)
        report = virtual.inspect({'var/cache/man/index.db':database(inputs())}, tree)
        self.assertEqual(link(report)['reason'], 'target-primary-source-metadata-unbound')
        tree['entries']['.']['mode'] = 0
        with self.assertRaisesRegex(ValueError, 'integrity'):
            virtual.inspect({'var/cache/man/index.db':database(inputs())}, tree)

    def test_targets_do_not_cross_index_or_locale_boundaries(self):
        tree, _ = candidate()
        files = {'var/cache/man/index.db':database({b'sl\0':record(sec=b'5', nano=b'9')}),
                 'var/cache/man/de/index.db':database({b'/etc/shadow\0':inputs()[b'/etc/shadow\0']})}
        report = virtual.inspect(files, tree)
        self.assertEqual(report['virtual_targets_metadata_bound'], 0)
        row = next(iter(report['indexes']['var/cache/man/de/index.db']['virtual_links'].values()))
        self.assertEqual(row['reason'], 'missing-primary-record')

    def test_zero_virtual_records_and_report_budget_do_not_imply_source_authority(self):
        tree, _ = candidate()
        files = {'var/cache/man/index.db':database({b'sl\0':record(sec=b'5', nano=b'9')})}
        report = virtual.inspect(files, tree)
        self.assertEqual(report['virtual_records'], 0)
        self.assertTrue(report['all_virtual_targets_metadata_bound'])
        self.assertFalse(report['cache_sources_verified'])
        with patch.object(virtual, 'MAX_REPORT_BYTES', 0), self.assertRaises(ValueError):
            virtual.inspect(files, tree)
