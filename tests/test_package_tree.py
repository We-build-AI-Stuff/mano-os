import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_runtime import package_tree as tree


def manifest(entries):
    raw = json.dumps(entries, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return dict(schema_version='1.0', entries=entries,
                manifest_sha256=hashlib.sha256(raw).hexdigest(),
                excluded_subtrees=sorted(tree.EXCLUDED))


class TreeDeltaTests(unittest.TestCase):
    def test_add_remove_modify_and_unchanged_are_accounted_without_authority(self):
        before = manifest({'keep': {'mode': 1}, 'remove': {'mode': 2}, 'change': {'mode': 3}})
        after = manifest({'keep': {'mode': 1}, 'add': {'mode': 2}, 'change': {'mode': 4}})
        result = tree.delta(before, after)
        self.assertEqual((result['added'], result['removed'], result['modified']), (1, 1, 1))
        self.assertEqual(set(result['changes']), {'add', 'remove', 'change'})
        for key in ('changes_authorized', 'baseline_custody_verified',
                    'candidate_filesystem_verified', 'publication_authorized'):
            self.assertIs(result[key], False)

    def test_xattr_only_change_is_not_silently_ignored(self):
        before = manifest({'file': {'sha256': 'a'*64, 'xattrs': {}}})
        after = manifest({'file': {'sha256': 'a'*64, 'xattrs': {'security.capability': 'changed'}}})
        self.assertEqual(tree.delta(before, after)['modified'], 1)

    def test_altered_observation_or_changed_exclusions_is_rejected(self):
        before = manifest({'file': {'mode': 1}})
        for change in ('entries', 'excluded_subtrees'):
            wrong = copy.deepcopy(before)
            if change == 'entries':
                wrong['entries']['file']['mode'] = 2
            else:
                wrong['excluded_subtrees'] = ['usr']
            with self.subTest(change=change), self.assertRaises(ValueError):
                tree.delta(before, wrong)

    def test_mac_scan_refuses_before_descriptor_io(self):
        with patch.object(tree.sys, 'platform', 'darwin'), patch.object(tree.os, 'dup') as dup:
            with self.assertRaises(PermissionError):
                tree.scan(-1)
            dup.assert_not_called()


@unittest.skipUnless(sys.platform == 'linux', 'Linux descriptor/xattr observation only')
class LinuxTreeObservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)

    def test_hashes_links_fifo_and_explicit_snapshot_exclusion(self):
        path = self.root/'file'
        path.write_bytes(b'content')
        os.link(path, self.root/'hardlink')
        (self.root/'symlink').symlink_to('/must/not/be/followed')
        os.mkfifo(self.root/'fifo')
        (self.root/'.snapshots').mkdir()
        (self.root/'.snapshots/unobserved').write_bytes(b'excluded explicitly')
        result = tree.scan(self.fd)
        entries = result['entries']
        self.assertEqual(entries['file']['sha256'], hashlib.sha256(b'content').hexdigest())
        self.assertEqual(entries['hardlink']['hardlink_anchor'], 'file')
        self.assertEqual(entries['symlink']['target'], '/must/not/be/followed')
        self.assertEqual(entries['fifo']['kind'], 'fifo')
        self.assertFalse(any(k.startswith('.snapshots') for k in entries))
        self.assertEqual(result['excluded_subtrees'], ['.snapshots'])
        self.assertEqual(result['unobserved_hardlinks'], [])
        self.assertIs(result['full_root_verified'], False)
        self.assertIs(result['publication_authorized'], False)
        self.assertTrue(os.fstat(self.fd))

    def test_linux_user_xattr_hash_is_observed(self):
        path = self.root/'file'
        path.write_bytes(b'content')
        os.setxattr(path, 'user.mano-observer', b'attribute')
        result = tree.scan(self.fd)
        self.assertEqual(result['entries']['file']['xattrs']['user.mano-observer'],
                         {'bytes': 9, 'sha256': hashlib.sha256(b'attribute').hexdigest()})

    def test_unobserved_external_hardlink_is_explicit(self):
        (self.root/'.snapshots').mkdir()
        path = self.root/'file'
        path.write_bytes(b'x')
        os.link(path, self.root/'.snapshots/alias')
        self.assertEqual(tree.scan(self.fd)['unobserved_hardlinks'], ['file'])

    def test_entry_content_and_metadata_budgets_fail_closed(self):
        (self.root/'file').write_bytes(b'content')
        for limit, value in (('MAX_ENTRIES', 1), ('MAX_BYTES', 2), ('MAX_METADATA', 1)):
            with self.subTest(limit=limit), patch.object(tree, limit, value):
                with self.assertRaisesRegex(ValueError, 'budget'):
                    tree.scan(self.fd)

    def test_interruption_propagates_without_closing_caller_descriptor(self):
        def stop():
            raise PermissionError('revoked')

        with self.assertRaisesRegex(PermissionError, 'revoked'):
            tree.scan(self.fd, checkpoint=stop)
        self.assertTrue(os.fstat(self.fd))

    def test_change_during_content_read_is_rejected(self):
        path = self.root/'file'
        path.write_bytes(b'content')
        read = os.read
        changed = False

        def mutate(fd, size):
            nonlocal changed
            value = read(fd, size)
            if not changed:
                changed = True
                info = path.stat()
                os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns+10**9))
            return value

        with patch.object(tree.os, 'read', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'changed during'):
                tree.scan(self.fd)
