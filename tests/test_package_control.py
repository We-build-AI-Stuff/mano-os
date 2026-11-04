import copy
import io
import tarfile
import unittest
from unittest.mock import patch

from mano_runtime import package_control as control

FIELDS = b'Package: fixture\nArchitecture: amd64\nVersion: 1\nDescription: test\n continued\n'


def archive(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as tar:
        for name, value in files.items():
            member = tarfile.TarInfo(name)
            if isinstance(value, bytes):
                member.size = len(value)
                tar.addfile(member, io.BytesIO(value))
            else:
                member.type = tarfile.SYMTYPE
                member.linkname = value
                tar.addfile(member)
    return output.getvalue()


class PackageControlTests(unittest.TestCase):
    def setUp(self):
        self.observation = control.observe(archive({'./control': FIELDS,
                                                    './md5sums': b'hash file\n'}))
        row = self.observation['inventory']['entries']['md5sums']
        self.path = 'var/lib/dpkg/info/fixture.md5sums'
        self.tree = {'entries': {self.path: row | {'xattrs': {}, 'nlink': 1,
                                                  'hardlink_anchor': self.path}}}
        self.records = [dict(name='fixture', architecture='amd64', version='1')]
        self.observations = {'fixture': {'control': self.observation}}
        self.status = FIELDS + b'Status: install ok installed\n\n'

    def validate(self, *, before=b'', after=None):
        return control.validate_new(before, self.status if after is None else after,
                                    self.tree, self.records, self.observations)

    def test_complete_control_record_and_info_hash_match_without_effect_authority(self):
        result = self.validate()
        self.assertEqual(result['new_package_records_verified'], 1)
        self.assertEqual(result['copied_control_paths_verified'], [self.path])
        self.assertEqual(result['unsupported_control_members'], {'fixture': []})
        for key in ('generated_state_validated', 'maintainer_effects_verified',
                    'changes_authorized', 'candidate_filesystem_verified',
                    'publication_authorized'):
            self.assertIs(result[key], False)

    def test_new_record_must_match_every_archive_field_and_only_settled_status(self):
        for after in (self.status.replace(b'continued', b'changed'),
                      self.status.replace(b'Version: 1', b'Version: 2'),
                      self.status.replace(b'Status:', b'X-Extra: value\nStatus:'),
                      self.status.replace(b'install ok installed', b'install ok config-files'),
                      self.status.replace(b'Description: test\n continued\n', b'')):
            with self.subTest(after=after), self.assertRaises(ValueError):
                self.validate(after=after)

    def test_identity_and_duplicate_or_preexisting_packages_require_separate_policy(self):
        with self.assertRaises(ValueError):
            self.validate(before=self.status)
        self.records[0]['architecture'] = 'all'
        with self.assertRaises(ValueError):
            self.validate()
        self.records[0]['architecture'] = 'amd64'
        self.records *= 2
        with self.assertRaises(ValueError):
            self.validate()

    def test_info_bytes_permissions_ownership_xattrs_and_aliases_are_checked(self):
        original = self.tree['entries'][self.path]
        for key, value in (('sha256', '0'*64), ('bytes', 0), ('mode', 0o777), ('uid', 1),
                           ('gid', 1), ('kind', 'symlink'), ('nlink', 2),
                           ('hardlink_anchor', 'elsewhere'), ('xattrs', {'user.extra': {}})):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.tree['entries'][self.path] = original | {key: value}
                self.validate()
        self.tree['entries'] = {}
        with self.assertRaises(ValueError):
            self.validate()

    def test_multiarch_same_info_name_is_bound_to_archive_field(self):
        fields = FIELDS + b'Multi-Arch: same\n'
        self.observation = control.observe(archive({'control': fields, 'md5sums': b'hash file\n'}))
        self.observations['fixture']['control'] = self.observation
        self.status = fields + b'Status: install ok installed\n\n'
        new_path = 'var/lib/dpkg/info/fixture:amd64.md5sums'
        row = self.tree['entries'].pop(self.path)
        self.tree['entries'][new_path] = row | {'hardlink_anchor': new_path}
        self.assertEqual(self.validate()['copied_control_paths_verified'], [new_path])

    def test_unapproved_record_metadata_drift_is_rejected(self):
        base = FIELDS.replace(b'fixture', b'other') + b'Status: install ok installed\n\n'
        self.validate(before=base, after=base+self.status)
        with self.assertRaises(ValueError):
            self.validate(before=base, after=base.replace(b'continued', b'changed')+self.status)

    def test_unknown_control_files_are_retained_without_authority(self):
        value = control.observe(archive({'control': FIELDS, 'future-extension': b'opaque'}))
        self.observations['fixture']['control'] = value
        result = self.validate()
        self.assertEqual(result['unsupported_control_members'], {'fixture': ['future-extension']})
        self.assertFalse(result['changes_authorized'])

    def test_links_nested_paths_and_ambiguous_control_headers_are_rejected(self):
        for files in ({'control': '/outside'}, {'control': FIELDS, 'nested/file': b'x'},
                      {'control': FIELDS + b'package: duplicate\n'},
                      {'control': FIELDS + b'Status: install ok installed\n'},
                      {'control': FIELDS + b'Broken body\n'},
                      {'control': FIELDS + b'Unknown: bad\0value\n'},
                      {'control': b'Package: fixture\n'}):
            with self.subTest(files=files), self.assertRaises(ValueError):
                control.observe(archive(files))

    def test_control_input_and_member_budgets_fail_closed(self):
        raw = archive({'control': FIELDS})
        with patch.object(control, 'MAX_TAR', len(raw)-1), self.assertRaises(ValueError):
            control.observe(raw)
        with patch.object(control, 'MAX_CONTROL', 1), self.assertRaises(ValueError):
            control.observe(raw)
        for wrong in (b'', bytearray(raw), b'not tar'):
            with self.subTest(raw=type(wrong)), self.assertRaises((ValueError, tarfile.TarError)):
                control.observe(wrong)

    def test_observation_is_not_archive_or_execution_authority(self):
        value = copy.deepcopy(self.observation)
        for key in ('archive_signature_verified', 'maintainer_execution_authorized',
                    'candidate_filesystem_verified', 'publication_authorized'):
            self.assertIs(value[key], False)

    def test_nonzero_trailing_tar_bytes_cannot_hide_control_data(self):
        raw = archive({'control': FIELDS})
        with self.assertRaisesRegex(ValueError, 'trailing'):
            control.observe(raw + b'hidden data')
