import unittest

from mano_runtime import package_log_scope as scope

STAMP = b'2026-10-26 04:23:40 '


def status(name, version, *, arch='amd64', description='fixture'):
    return (f'Package: {name}\nArchitecture: {arch}\nVersion: {version}\n'
            f'Status: install ok installed\nDescription: {description}\n\n').encode()


class LogPackageScopeTests(unittest.TestCase):
    def setUp(self):
        self.before = status('existing', '1')
        self.after = self.before+status('newpkg', '2')
        self.records = [dict(name='newpkg', architecture='amd64', version='2')]

    def inspect(self, bodies):
        raw = b''.join(STAMP+body+b'\n' for body in bodies)
        return scope.inspect(b'old\n', b'old\n'+raw, self.before, self.after, self.records)

    def test_new_package_versions_and_unchanged_trigger_references_do_not_grant_authority(self):
        result = self.inspect([b'startup archives install', b'install newpkg:amd64 <none> 2',
                               b'configure newpkg:amd64 2 2', b'status installed newpkg:amd64 2',
                               b'status triggers-pending existing:amd64 1',
                               b'trigproc existing:amd64 1 <none>'])
        self.assertTrue(result['package_identity_versions_matched'])
        self.assertEqual(result['matched_package_events'], 5)
        self.assertEqual(result['referenced_trigger_packages'],
                         [dict(name='existing', architecture='amd64', version='1')])
        for key in ('trigger_authority_verified', 'sequence_policy_verified',
                    'time_window_verified', 'log_semantics_verified', 'log_change_accounted',
                    'changes_authorized', 'publication_authorized'):
            self.assertIs(result[key], False)

    def test_unknown_package_architecture_and_changed_version_are_rejected(self):
        for body in (b'install unknown:amd64 <none> 2', b'install newpkg:arm64 <none> 2',
                     b'install newpkg:amd64 <none> 3', b'status installed newpkg:amd64 3',
                     b'trigproc existing:amd64 2 <none>', b'configure newpkg:amd64 2 3'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.inspect([body])

    def test_non_trigger_baseline_actions_cannot_hide_behind_known_package_names(self):
        for body in (b'install existing:amd64 <none> 1', b'configure existing:amd64 1 1',
                     b'upgrade existing:amd64 1 2', b'remove existing:amd64 1 <none>',
                     b'status half-installed existing:amd64 1'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.inspect([body])

    def test_unqualified_names_need_unique_database_identity(self):
        self.inspect([b'install newpkg <none> 2'])
        self.before += status('existing', '1', arch='arm64')
        self.after = self.before+status('newpkg', '2')
        with self.assertRaises(ValueError):
            self.inspect([b'trigproc existing 1 <none>'])

    def test_new_package_can_reference_its_own_trigger_without_approving_it(self):
        result = self.inspect([b'trigproc newpkg:amd64 2 <none>'])
        self.assertEqual(result['referenced_trigger_packages'],
                         [dict(name='newpkg', architecture='amd64', version='2')])
        self.assertFalse(result['trigger_authority_verified'])

    def test_duplicate_or_existing_plan_records_and_unapproved_database_drift_fail(self):
        self.records *= 2
        with self.assertRaises(ValueError):
            self.inspect([])
        self.records = [dict(name='existing', architecture='amd64', version='1')]
        with self.assertRaises(ValueError):
            self.inspect([])
        self.records = [dict(name='newpkg', architecture='amd64', version='2')]
        self.after = self.after.replace(b'Description: fixture', b'Description: changed', 1)
        with self.assertRaises(ValueError):
            self.inspect([])

    def test_conffile_other_startups_and_rewritten_prefix_need_other_policies(self):
        for body in (b'conffile /etc/target keep', b'startup packages remove'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.inspect([body])
        with self.assertRaises(ValueError):
            scope.inspect(b'old\n', b'rewritten\n', self.before, self.after, self.records)
        empty = self.inspect([])
        self.assertEqual(empty['decoded_events'], 0)
        self.assertFalse(empty['log_semantics_verified'])
