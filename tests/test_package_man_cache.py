import copy
import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_package_change_accounting import directory, file, manifest

from mano_runtime import package_man_cache as cache


class ManCacheBytesTests(unittest.TestCase):
    def setUp(self):
        self.path = 'var/cache/man/index.db'
        self.old, self.new = b'old opaque bytes', b'new opaque bytes'
        self.before = {self.path: self.row(self.old)}
        self.after = {self.path: self.row(self.new)}
        self.read_before = Mock(return_value=self.old)
        self.read_after = Mock(return_value=self.new)

    def row(self, data):
        return file(self.path) | dict(uid=6, gid=12, mode=0o644, bytes=len(data),
                                     sha256=hashlib.sha256(data).hexdigest())

    def collect(self):
        return cache.collect(manifest({'.': directory(), **self.before}),
                             manifest({'.': directory(), **self.after}),
                             self.read_before, self.read_after)

    def test_descriptor_reader_uses_actual_identity_and_rejects_alias_or_stale_metadata(self):
        # Portable ordinary-user files only; no Root/namespace/database parser.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / self.path
            path.parent.mkdir(parents=True)
            path.write_bytes(self.new)
            info = path.stat()
            row = dict(uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode),
                       nlink=info.st_nlink, bytes=info.st_size, mtime_ns=info.st_mtime_ns,
                       ctime_ns=info.st_ctime_ns)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertEqual(cache.read_index(fd, self.path, 4096, row), self.new)
                with self.assertRaises(ValueError):
                    cache.read_index(fd, self.path, 4096, row | {'bytes': row['bytes'] + 1})
                real_read = os.read

                def changed_read(descriptor, count):
                    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 10**9))
                    return real_read(descriptor, count)

                with patch.object(cache.os, 'read', side_effect=changed_read), \
                        self.assertRaisesRegex(ValueError, 'changed while reading'):
                    cache.read_index(fd, self.path, 4096, row)
                path.unlink()
                path.symlink_to(root / 'outside')
                with self.assertRaises(OSError):
                    cache.read_index(fd, self.path, 4096, row)
                path.unlink()
                path.write_bytes(self.new)
                path.parent.rename(root / 'real-man')
                path.parent.symlink_to(root / 'real-man', target_is_directory=True)
                with self.assertRaises(OSError):
                    cache.read_index(fd, self.path, 4096, row)
            finally:
                os.close(fd)

    def test_exact_before_after_bytes_bound_without_database_or_generation_claim(self):
        report, artifacts = self.collect()
        self.assertEqual(artifacts, {'staged-man-index-0-baseline.db': self.old,
                                    'staged-man-index-0-candidate.db': self.new})
        self.assertEqual(report['files'], 2)
        self.assertEqual(report['bytes'], len(self.old) + len(self.new))
        for key in ('database_records_decoded', 'cache_sources_verified',
                    'cache_regeneration_verified', 'generated_state_validated',
                    'changes_authorized', 'publication_authorized'):
            self.assertIs(report[key], False)

    def test_added_removed_and_timestamp_only_database_observations(self):
        self.before = {}
        report, _ = self.collect()
        self.assertIsNone(report['databases'][self.path]['baseline'])
        self.assertEqual(report['files'], 1)
        self.before, self.after = self.after, {}
        self.read_before.return_value = self.new
        report, _ = self.collect()
        self.assertIsNone(report['databases'][self.path]['candidate'])
        self.after = copy.deepcopy(self.before)
        self.after[self.path]['mtime_ns'] += 1
        report, _ = self.collect()
        self.assertEqual(report['files'], 2)

    def test_unchanged_or_out_of_scope_paths_never_read(self):
        self.before = copy.deepcopy(self.after)
        self.after.update({'var/cache/man/../../etc/index.db': self.row(self.new),
                           'var/cache/man/de/nested/index.db': self.row(self.new),
                           'var/cache/man/CACHEDIR.TAG': self.row(self.new)})
        report, artifacts = self.collect()
        self.assertEqual((report['files'], artifacts), (0, {}))
        self.read_before.assert_not_called()
        self.read_after.assert_not_called()

    def test_digest_size_and_byte_type_substitutions_reject(self):
        for data in (b'wrong', self.new + b'x', bytearray(self.new), 'text'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.read_after.return_value = data
                self.collect()

    def test_alias_security_metadata_and_size_budgets_reject_before_read(self):
        original = self.after[self.path]
        for key, value in (('kind', 'symlink'), ('uid', 0), ('gid', 0), ('nlink', 2),
                           ('nlink', True), ('mode', 0o666), ('xattrs', {'user.foo': {}}),
                           ('hardlink_anchor', 'other'), ('bytes', cache.MAX_DATABASE_BYTES + 1)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.after[self.path] = original | {key: value}
                self.collect()
        self.read_after.assert_not_called()

    def test_count_and_total_budgets_reject(self):
        self.before = {}
        self.after = {f'var/cache/man/l{i}/index.db': self.row(self.new) for i in range(9)}
        with self.assertRaisesRegex(ValueError, 'count budget'):
            self.collect()
        self.read_after.assert_not_called()
        self.after = {self.path: self.row(self.new)}
        with patch.object(cache, 'MAX_TOTAL_BYTES', len(self.new) - 1), \
                self.assertRaises(ValueError):
            self.collect()
        self.read_after.assert_not_called()
