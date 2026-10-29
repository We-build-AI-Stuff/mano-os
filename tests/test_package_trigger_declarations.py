import hashlib
import unittest
from unittest.mock import Mock, patch

from test_package_control import FIELDS, archive

from mano_runtime import package_trigger_declarations as triggers
from mano_runtime.package_control import observe


def status():
    return b'Package: fixture\nArchitecture: amd64\nVersion: 1\nStatus: install ok installed\n\n'


class TriggerDeclarationTests(unittest.TestCase):
    def setUp(self):
        self.path = 'var/lib/dpkg/info/fixture.triggers'
        self.raw = b'# comment\ninterest-noawait /usr/share/man\ninterest ldconfig\n'
        self.row = dict(kind='file', uid=0, gid=0, mode=0o644, nlink=1, xattrs={},
                        hardlink_anchor=self.path, bytes=len(self.raw),
                        sha256=hashlib.sha256(self.raw).hexdigest())
        self.tree = {'entries': {self.path: self.row}}
        self.refs = [dict(name='fixture', architecture='amd64', version='1')]

    def test_directives_comments_and_ascii_whitespace_decode_without_permission(self):
        raw = b' \tinterest-noawait /usr/share/man # comment\r\nactivate-noawait\tldconfig\n'
        result = triggers.decode(raw)
        self.assertEqual(result['declarations'], [
            dict(directive='interest-noawait', trigger='/usr/share/man', kind='file'),
            dict(directive='activate-noawait', trigger='ldconfig', kind='named')])
        self.assertFalse(result['trigger_authority_verified'])
        self.assertFalse(result['publication_authorized'])

    def test_unknown_directives_ambiguous_fields_paths_and_controls_fail_closed(self):
        for raw in (b'execute ldconfig\n', b'interest two names\n',
                    b'interest /usr/../etc\n', b'interest //usr/share/man\n',
                    b'interest bad\0name\n', 'interest caf\u00e9\n'.encode(),
                    'interest\u0085ldconfig\n'.encode()):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                triggers.decode(raw)

    def test_byte_and_directive_budgets(self):
        with patch.object(triggers, 'MAX_BYTES', 1), self.assertRaises(ValueError):
            triggers.decode(self.raw)
        with patch.object(triggers, 'MAX_DIRECTIVES', 1), self.assertRaises(ValueError):
            triggers.decode(self.raw)

    def test_baseline_metadata_bytes_and_identity_bound_to_snapshot_without_authority(self):
        read = Mock(return_value=self.raw)
        result = triggers.baseline_sources(status(), self.tree, self.refs, read)
        read.assert_called_once_with(self.path, triggers.MAX_BYTES)
        self.assertTrue(result['sources'][0]['baseline_tree_bound'])
        self.assertEqual(result['sources'][0]['observation']['sha256'], self.row['sha256'])
        self.assertFalse(result['trigger_authority_verified'])

    def test_missing_files_or_new_packages_are_explicitly_unavailable_without_reads(self):
        read = Mock()
        result = triggers.baseline_sources(status(), {'entries': {}}, self.refs, read)
        self.assertEqual(result['sources'][0]['reason'], 'no-baseline-trigger-file')
        result = triggers.baseline_sources(b'', self.tree, self.refs, read)
        self.assertEqual(result['sources'][0]['reason'], 'not-installed-in-baseline')
        read.assert_not_called()

    def test_version_alias_mode_ownership_and_content_mismatch_are_rejected(self):
        for key, value in (('kind', 'symlink'), ('uid', 1), ('gid', True), ('mode', 0o666),
                           ('nlink', 2), ('hardlink_anchor', 'elsewhere'),
                           ('xattrs', {'user.extra': {}}), ('sha256', '0'*64)):
            row = self.row | {key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                triggers.baseline_sources(status(), {'entries': {self.path: row}},
                                          self.refs, Mock(return_value=self.raw))
        with self.assertRaises(ValueError):
            triggers.baseline_sources(status(), self.tree, self.refs*2, Mock())
        with self.assertRaises(ValueError):
            triggers.baseline_sources(status(), self.tree,
                                      [self.refs[0] | {'version': '2'}], Mock())

    def test_signed_control_trigger_bytes_are_bound_and_no_file_remains_distinct(self):
        result = observe(archive({'control': FIELDS, 'triggers': b'activate-noawait ldconfig\n'}))
        self.assertEqual(result['trigger_declarations']['declarations'],
                         [dict(directive='activate-noawait', trigger='ldconfig', kind='named')])
        self.assertFalse(result['trigger_declarations']['trigger_authority_verified'])
        result = observe(archive({'control': FIELDS}))
        self.assertIsNone(result['trigger_data_base64'])
        self.assertEqual(result['trigger_declarations']['declarations'], [])

    def test_multiarch_baseline_info_path_comes_from_actual_database_field(self):
        before = status().replace(b'Version: 1\n', b'Version: 1\nMulti-Arch: same\n')
        path = 'var/lib/dpkg/info/fixture:amd64.triggers'
        row = self.row | {'hardlink_anchor': path}
        read = Mock(return_value=self.raw)
        result = triggers.baseline_sources(before, {'entries': {path: row}}, self.refs, read)
        self.assertEqual(result['sources'][0]['path'], path)


    def test_aggregate_baseline_byte_budget_rejects_before_reading_excess_file(self):
        other = dict(name='second', architecture='amd64', version='1')
        path = 'var/lib/dpkg/info/second.triggers'
        tree = {'entries': self.tree['entries'] | {path: self.row | {'hardlink_anchor': path}}}
        before = status()+status().replace(b'fixture', b'second')
        read = Mock(return_value=self.raw)
        with patch.object(triggers, 'MAX_SOURCE_BYTES', len(self.raw)), self.assertRaisesRegex(
                ValueError, 'Aggregate baseline trigger byte budget'):
            triggers.baseline_sources(before, tree, self.refs+[other], read)
        read.assert_called_once_with(self.path, triggers.MAX_BYTES)

    def test_aggregate_directive_budget_rejects_small_valid_files(self):
        read = Mock(return_value=self.raw)
        with patch.object(triggers, 'MAX_SOURCE_DIRECTIVES', 1), self.assertRaisesRegex(
                ValueError, 'Aggregate baseline trigger directive budget'):
            triggers.baseline_sources(status(), self.tree, self.refs, read)
