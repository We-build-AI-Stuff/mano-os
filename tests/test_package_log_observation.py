import hashlib
import unittest
from unittest.mock import patch

from mano_runtime import package_log_observation as log


def tree(data):
    return {'entries': {log.PATH: dict(kind='file', uid=0, gid=0, mode=0o644, nlink=1,
                                     bytes=len(data), mtime_ns=1, ctime_ns=2, xattrs={},
                                     hardlink_anchor=log.PATH,
                                     sha256=hashlib.sha256(data).hexdigest())}}


class DpkgLogObservationTests(unittest.TestCase):
    def test_exact_prefix_and_hashes_do_not_approve_log_events(self):
        before, after = b'old log\n', b'old log\nnew untrusted event\n'
        result = log.observe(before, after, tree(before), tree(after))
        self.assertTrue(result['append_only_observed'])
        self.assertEqual(result['appended_bytes'], len(b'new untrusted event\n'))
        for key in ('log_events_parsed', 'log_semantics_verified', 'log_change_accounted',
                    'changes_authorized', 'publication_authorized'):
            self.assertIs(result[key], False)

    def test_rewrite_or_truncation_remains_observation_without_append_claim(self):
        for before, after in ((b'old\n', b'rewritten\n'), (b'old log\n', b'old')):
            with self.subTest(before=before, after=after):
                result = log.observe(before, after, tree(before), tree(after))
                self.assertFalse(result['append_only_observed'])
                self.assertIsNone(result['appended_bytes'])
                self.assertIsNone(result['appended_sha256'])
                self.assertFalse(result['log_change_accounted'])

    def test_empty_before_and_no_new_events_are_explicitly_supported(self):
        for before, after in ((b'', b'first\n'), (b'old\n', b'old\n'), (b'', b'')):
            with self.subTest(before=before, after=after):
                result = log.observe(before, after, tree(before), tree(after))
                self.assertEqual(result['appended_bytes'], len(after)-len(before))

    def test_metadata_aliases_and_actual_hash_bindings_fail_closed(self):
        data = b'old\n'
        for key, value in (('kind', 'symlink'), ('uid', 1), ('gid', 1), ('mode', 0o666),
                           ('nlink', 2), ('bytes', True), ('xattrs', {'user.extra': {}}),
                           ('hardlink_anchor', 'elsewhere'), ('sha256', '0'*64)):
            wrong = tree(data)
            wrong['entries'][log.PATH][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                log.observe(data, data, tree(data), wrong)

    def test_baseline_bytes_are_bound_independently(self):
        with self.assertRaises(ValueError):
            log.observe(b'changed', b'after', tree(b'original'), tree(b'after'))

    def test_quotas_and_non_bytes_refuse_before_content_claims(self):
        with patch.object(log, 'MAX_LOG', 1), self.assertRaises(ValueError):
            log.observe(b'too big', b'', tree(b'too big'), tree(b''))
        with self.assertRaises(ValueError):
            log.observe(bytearray(b'old'), b'', tree(b'old'), tree(b''))
