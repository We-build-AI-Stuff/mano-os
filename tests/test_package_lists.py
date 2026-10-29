import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_runtime import package_lists as lists


def payload(paths=None):
    entries = paths if paths is not None else {'.': {'kind': 'directory'},
                                               'usr': {'kind': 'directory'},
                                               'usr/file': {'kind': 'file'}}
    raw = json.dumps(entries, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return dict(schema_version='1.0', entries=entries, unsupported_metadata={},
                manifest_sha256=hashlib.sha256(raw).hexdigest())


class GeneratedListTests(unittest.TestCase):
    def test_exact_paths_are_verified_without_order_or_effect_authority(self):
        result = lists.validate(b'/usr/file\n/.\n/usr\n', payload())
        self.assertEqual(result['payload_paths_verified'], 3)
        for key in ('all_generated_state_validated', 'changes_authorized',
                    'publication_authorized'):
            self.assertIs(result[key], False)

    def test_missing_extra_duplicate_traversal_alias_and_control_paths_rejected(self):
        for data in (b'/usr/file\n/.\n', b'/usr/file\n/.\n/usr\n/extra\n',
                     b'/usr/file\n/.\n/usr\n/usr\n', b'/usr/../usr/file\n/.\n/usr\n',
                     b'/usr/file\n/\n/usr\n', b'/usr/file\n/.\n/usr\n\n',
                     b'/usr/file\r\n/.\r\n/usr\r\n', b'/usr/file\0\n/.\n/usr\n',
                     b'/usr/file\n/.\n/usr', b''):
            with self.subTest(data=data), self.assertRaises(ValueError):
                lists.validate(data, payload())

    def test_inventory_integrity_metadata_and_ambiguous_names_fail_closed(self):
        for value in (payload() | {'manifest_sha256': '0'*64},
                      payload() | {'unsupported_metadata': {'usr/file': {'pax': 'unknown'}}},
                      payload({'usr/../escape': {'kind': 'file'}}),
                      payload({'usr/line\nbreak': {'kind': 'file'}})):
            with self.subTest(value=value), self.assertRaises(ValueError):
                lists.validate(b'/usr/file\n/.\n/usr\n', value)

    def test_list_budget_and_checkpoint_are_enforced(self):
        with patch.object(lists, 'MAX_LIST', 1), self.assertRaises(ValueError):
            lists.validate(b'/.\n', payload({'.': {'kind': 'directory'}}))
        def stop():
            raise InterruptedError('Stop')
        with self.assertRaises(InterruptedError):
            lists.validate(b'/.\n', payload(), checkpoint=stop)

    def test_root_ownership_required_before_list_descriptor_read(self):
        records = [dict(name='fixture', architecture='amd64', version='1')]
        observations = {'fixture': {'control': {'fields': dict(package='fixture',
                         architecture='amd64', version='1')}}}
        path = 'var/lib/dpkg/info/fixture.list'
        with patch.object(lists, 'read_owned') as read, self.assertRaises(ValueError):
            lists.observe(-1, {'entries': {path: dict(uid=1000, gid=1000)}}, records, observations)
        read.assert_not_called()

    def test_multiarch_list_path_and_report_bind_to_control_and_payload(self):
        records = [dict(name='fixture', architecture='amd64', version='1')]
        observations = {'fixture': {'payload': payload(), 'control': {'fields': dict(
            package='fixture', architecture='amd64', version='1', **{'multi-arch': 'same'})}}}
        path = 'var/lib/dpkg/info/fixture:amd64.list'
        expected = dict(uid=0, gid=0)
        with patch.object(lists, 'read_owned', return_value=b'/.\n/usr\n/usr/file\n') as read:
            result = lists.observe(-1, {'entries': {path: expected}}, records, observations)
        self.assertEqual(read.call_args.args, (-1, path, expected))
        self.assertEqual(result['packages']['fixture']['path'], path)
        self.assertEqual(result['packages']['fixture']['payload_paths_verified'], 3)
        self.assertFalse(result['candidate_filesystem_verified'])


class OwnedListDescriptorTests(unittest.TestCase):
    """Real user-owned temporary descriptors; not Root/native authority evidence."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.relative = 'var/lib/dpkg/info/fixture.list'
        self.path = self.root / self.relative
        self.path.parent.mkdir(parents=True)
        self.data = b'/.\n/usr\n/usr/file\n'
        self.path.write_bytes(self.data)
        self.path.chmod(0o644)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        info = self.path.stat()
        self.expected = dict(kind='file', uid=info.st_uid, gid=info.st_gid,
                             mode=stat.S_IMODE(info.st_mode), nlink=info.st_nlink,
                             bytes=info.st_size, mtime_ns=info.st_mtime_ns,
                             ctime_ns=info.st_ctime_ns, xattrs={},
                             hardlink_anchor=self.relative,
                             sha256=hashlib.sha256(self.data).hexdigest())

    def test_actual_stable_descriptor_bytes_match_tree(self):
        self.assertEqual(lists.read_owned(self.fd, self.relative, self.expected), self.data)

    def test_stale_metadata_hash_alias_and_budget_fail_closed(self):
        for key, value in (('mtime_ns', 0), ('ctime_ns', 0), ('sha256', '0'*64),
                           ('bytes', lists.MAX_LIST+1), ('mode', 0o777), ('nlink', 2),
                           ('hardlink_anchor', 'elsewhere'), ('uid', True),
                           ('xattrs', {'user.extra': {}})):
            with self.subTest(key=key), self.assertRaises(ValueError):
                lists.read_owned(self.fd, self.relative, self.expected | {key: value})

    def test_leaf_and_parent_symlinks_never_reach_read(self):
        self.path.unlink()
        target = self.root / 'outside'
        target.write_bytes(b'untouched')
        self.path.symlink_to(target)
        with patch.object(lists.os, 'read') as read, self.assertRaises(OSError):
            lists.read_owned(self.fd, self.relative, self.expected)
        read.assert_not_called()
        self.path.unlink()
        self.path.parent.rmdir()
        self.path.parent.symlink_to(self.root)
        with patch.object(lists.os, 'read') as read, self.assertRaises(OSError):
            lists.read_owned(self.fd, self.relative, self.expected)
        read.assert_not_called()
        self.assertEqual(target.read_bytes(), b'untouched')

    def test_mutation_during_read_is_rejected(self):
        original = os.read
        changed = False
        def racing(fd, count):
            nonlocal changed
            piece = original(fd, count)
            if not changed:
                changed = True
                self.path.write_bytes(self.data+b'extra')
            return piece
        with patch.object(lists.os, 'read', side_effect=racing), self.assertRaises(ValueError):
            lists.read_owned(self.fd, self.relative, self.expected)

    def test_fifo_replacement_is_nonblocking_and_never_read(self):
        self.path.unlink()
        os.mkfifo(self.path)
        with patch.object(lists.os, 'read') as read, self.assertRaises(ValueError):
            lists.read_owned(self.fd, self.relative, self.expected)
        read.assert_not_called()

    def test_interruption_closes_owned_descriptors(self):
        calls = 0
        def stop():
            nonlocal calls
            calls += 1
            if calls > 1:
                raise InterruptedError('Stop')
        opened = set()
        original_open, original_dup = os.open, os.dup
        def opening(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            opened.add(fd)
            return fd
        def duplicating(fd):
            duplicate = original_dup(fd)
            opened.add(duplicate)
            return duplicate
        with patch.object(lists.os, 'open', side_effect=opening), \
                patch.object(lists.os, 'dup', side_effect=duplicating), \
                self.assertRaises(InterruptedError):
            lists.read_owned(self.fd, self.relative, self.expected, checkpoint=stop)
        self.assertTrue(opened)
        for fd in opened:
            with self.subTest(fd=fd), self.assertRaises(OSError):
                os.fstat(fd)
        self.assertTrue(stat.S_ISDIR(os.fstat(self.fd).st_mode))
