import copy
import hashlib
import unittest

from mano_runtime import package_database_files as db


def row(path, data, *, mtime=1):
    return dict(kind='file', uid=0, gid=0, mode=0o644, nlink=1, bytes=len(data),
                mtime_ns=mtime, ctime_ns=2, xattrs={}, hardlink_anchor=path,
                sha256=hashlib.sha256(data).hexdigest())


class DatabaseFileBindingTests(unittest.TestCase):
    def setUp(self):
        self.before, self.after = b'before database', b'after database'
        self.baseline = {'entries': {db.STATUS: row(db.STATUS, self.before)}}
        self.candidate = {'entries': {db.STATUS: row(db.STATUS, self.after),
                                      db.BACKUP: row(db.BACKUP, self.before)}}

    def bind(self, **kwargs):
        return db.bind(self.before, self.after, self.baseline, self.candidate, **kwargs)

    def test_exact_status_and_preimage_backup_have_no_transition_or_effect_authority(self):
        result = self.bind()
        self.assertTrue(result['status_bytes_bound_to_tree'])
        self.assertTrue(result['backup_matches_known_preimage'])
        self.assertEqual(result['verified_database_paths'], [db.STATUS, db.BACKUP])
        self.assertEqual(result['unresolved_backup_paths'], [])
        for key in ('package_transition_validated', 'all_generated_state_validated',
                    'changes_authorized', 'candidate_filesystem_verified',
                    'publication_authorized'):
            self.assertIs(result[key], False)

    def test_intermediate_or_missing_backup_is_not_approved_as_preimage(self):
        self.candidate['entries'][db.BACKUP] = row(db.BACKUP, b'intermediate')
        result = self.bind()
        self.assertEqual(result['verified_database_paths'], [db.STATUS])
        self.assertEqual(result['unresolved_backup_paths'], [db.BACKUP])
        self.assertFalse(result['backup_matches_known_preimage'])
        del self.candidate['entries'][db.BACKUP]
        result = self.bind()
        self.assertFalse(result['backup_matches_known_preimage'])
        self.assertEqual(result['unresolved_backup_paths'], [db.BACKUP])

    def test_plain_database_security_metadata_and_aliases_are_required(self):
        for path in (db.STATUS, db.BACKUP):
            for key, value in (('kind', 'symlink'), ('uid', 1), ('gid', 1), ('mode', 0o666),
                               ('mode', True), ('nlink', 2), ('hardlink_anchor', 'elsewhere'),
                               ('xattrs', {'security.capability': {}}), ('bytes', True)):
                candidate = copy.deepcopy(self.candidate)
                candidate['entries'][path][key] = value
                with self.subTest(path=path, key=key), self.assertRaises(ValueError):
                    db.bind(self.before, self.after, self.baseline, candidate)

    def test_source_and_candidate_database_bytes_are_bound_separately(self):
        for before, after in ((b'changed', self.after), (self.before, b'changed')):
            with self.subTest(before=before, after=after), self.assertRaises(ValueError):
                db.bind(before, after, self.baseline, self.candidate)
        self.baseline['entries'][db.STATUS]['sha256'] = '0'*64
        with self.assertRaises(ValueError):
            self.bind()

    def test_backup_mode_or_timestamp_drift_remains_unresolved(self):
        for key, value in (('mode', 0o600), ('mtime_ns', 10)):
            backup = self.candidate['entries'][db.BACKUP]
            original = backup[key]
            backup[key] = value
            result = self.bind()
            self.assertFalse(result['backup_matches_known_preimage'])
            self.assertEqual(result['unresolved_backup_paths'], [db.BACKUP])
            backup[key] = original

    def test_status_permissions_cannot_change_and_interruption_is_preserved(self):
        self.candidate['entries'][db.STATUS]['mode'] = 0o600
        with self.assertRaises(ValueError):
            self.bind()
        def stop():
            raise InterruptedError('Stop')
        with self.assertRaises(InterruptedError):
            self.bind(checkpoint=stop)
