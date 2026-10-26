import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from mano_runtime import package_change_accounting as policy


def manifest(entries):
    data = json.dumps(entries, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return dict(schema_version='1.0', entries=entries, excluded_subtrees=['.snapshots'],
                manifest_sha256=hashlib.sha256(data).hexdigest())


def directory():
    return dict(kind='directory', uid=0, gid=0, mode=0o755, nlink=1, xattrs={},
                mtime_ns=1, ctime_ns=1)


def file(path, *, empty=False):
    content = b'' if empty else b'content'
    return dict(kind='file', uid=0, gid=0, mode=0o640, nlink=1, xattrs={},
                mtime_ns=1, ctime_ns=1, bytes=len(content), hardlink_anchor=path,
                sha256=hashlib.sha256(content).hexdigest())


class ChangeAccountingTests(unittest.TestCase):
    """Classification fixtures; individual gates and native evidence test custody."""
    def setUp(self):
        self.before = {'.': directory(), 'usr': directory()}
        self.after = copy.deepcopy(self.before)
        self.after['usr']['mtime_ns'] = 2
        self.after['usr/file'] = file('usr/file')
        self.payloads = {'fixture': {'entries': {'usr/file': {'kind': 'file'}}}}
        self.control = dict(copied_control_paths_verified=[], unsupported_control_members={})
        self.lists = {'packages': {}}
        self.database = dict(verified_database_paths=[], unresolved_backup_paths=[])

    def account(self):
        return policy._account(manifest(self.before), manifest(self.after), self.payloads,
                               self.control, self.lists, self.database)

    def test_known_effect_and_unchanged_parent_times_account_without_authority(self):
        result = self.account()
        self.assertEqual(result['accounted_changes'], {
            'usr/file': 'authenticated-payload', 'usr': 'unchanged-parent-directory-timestamps'})
        self.assertTrue(result['change_set_fully_accounted'])
        for key in ('all_generated_state_validated', 'protected_runtime_policy_validated',
                    'candidate_filesystem_verified', 'changes_authorized',
                    'publication_authorized'):
            self.assertIs(result[key], False)

    def test_unlisted_effect_is_never_allowed_by_directory_or_filename_prefix(self):
        self.after['usr/backdoor'] = file('usr/backdoor')
        self.after['var/lib/dpkg/info/extra'] = file('var/lib/dpkg/info/extra')
        result = self.account()
        self.assertEqual(set(result['unresolved_changes']),
                         {'usr/backdoor', 'var/lib/dpkg/info/extra'})
        self.assertFalse(result['change_set_fully_accounted'])

    def test_parent_security_metadata_or_unrelated_timestamp_change_remains_unresolved(self):
        self.before['unrelated'] = directory()
        self.after['unrelated'] = directory() | {'mtime_ns': 2}
        self.after['usr']['mode'] = 0o777
        self.assertEqual(set(self.account()['unresolved_changes']), {'usr', 'unrelated'})

    def test_lock_timestamp_classification_requires_identical_empty_baseline_and_security(self):
        path = 'var/lib/dpkg/lock'
        self.before[path] = file(path, empty=True)
        self.after[path] = self.before[path] | {'mtime_ns': 2}
        self.assertEqual(self.account()['accounted_changes'][path],
                         'unchanged-empty-lock-timestamps')
        self.after[path]['bytes'] = 1
        self.assertIn(path, self.account()['unresolved_changes'])
        self.after[path] = self.before[path] | {'mtime_ns': 2, 'nlink': 2}
        self.assertIn(path, self.account()['unresolved_changes'])

    def test_dpkg_updates_times_require_empty_before_and_after_and_unchanged_metadata(self):
        path = policy.UPDATES
        self.before[path] = directory()
        self.after[path] = directory() | {'mtime_ns': 2}
        self.assertEqual(self.account()['accounted_changes'][path],
                         'drained-empty-dpkg-updates-timestamps')
        self.after[path+'/journal'] = file(path+'/journal')
        self.assertIn(path, self.account()['unresolved_changes'])

    def test_unresolved_backup_and_control_requirements_cannot_disappear_from_delta(self):
        self.database['unresolved_backup_paths'] = ['var/lib/dpkg/status-old']
        self.control['unsupported_control_members'] = {'fixture': ['future-extension']}
        result = self.account()
        self.assertFalse(result['change_set_fully_accounted'])
        self.assertEqual(result['unresolved_requirements'],
                         ['control:fixture/future-extension', 'var/lib/dpkg/status-old'])

    def test_strict_entry_recomputes_audit_and_rejects_paths_even_if_boolean_claims_complete(self):
        report = self.account()
        report['unresolved_changes'] = {'usr/backdoor': {}}
        report['change_set_fully_accounted'] = True
        with patch.object(policy, 'audit', return_value={'accounting': report}) as audit, \
                self.assertRaises(policy.UnaccountedChanges) as error:
            policy.require_accounted(-1, b'before', b'after', {}, {}, [], {})
        audit.assert_called_once()
        self.assertEqual(error.exception.paths, ('usr/backdoor',))
        report['unresolved_changes'] = {}
        with patch.object(policy, 'audit', return_value={'accounting': report}):
            result = policy.require_accounted(-1, b'', b'', {}, {}, [], {})
            self.assertIs(result['accounting'], report)

    def test_observations_must_exactly_match_distinct_authenticated_records_before_fd_use(self):
        for records, observations in (([{'name': 'fixture'}], {}),
                                      ([{'name': 'fixture'}]*2, {'fixture': {}})):
            with self.subTest(records=records), patch.object(policy, 'observe') as read, \
                    self.assertRaises(ValueError):
                policy.audit(-1, b'', b'', {}, {}, records, observations)
            read.assert_not_called()
