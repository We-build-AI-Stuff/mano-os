import copy
import os
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_package_payload import archive, file

from mano_runtime.package_candidate import compare_payload
from mano_runtime.package_payload import inventory


class CandidatePayloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'usr/bin').mkdir(parents=True)
        target = self.root / 'usr/bin/example'
        target.write_bytes(b'payload')
        target.chmod(0o755)
        os.link(target, self.root / 'usr/bin/copy')
        (self.root / 'usr/bin/link').symlink_to('/literal/unfollowed')
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        uid, gid = os.getuid(), os.getgid()
        attributes = {'uid': uid, 'gid': gid}
        self.manifest = inventory(archive([
            ('.', tarfile.DIRTYPE, '', attributes),
            file('usr/bin/example', b'payload', **attributes),
            ('usr/bin/copy', tarfile.LNKTYPE, 'usr/bin/example', attributes),
            ('usr/bin/link', tarfile.SYMTYPE, '/literal/unfollowed',
             attributes | {'mode': stat.S_IMODE((self.root / 'usr/bin/link').lstat().st_mode)}),
        ]))

    def compare(self):
        return compare_payload(self.fd, self.manifest)

    def test_bytes_literal_links_and_inode_provenance_match_without_authority(self):
        value = self.compare()
        self.assertTrue(value['payload_paths_match'])
        self.assertEqual(value['observed_paths'], 4)
        self.assertEqual(value['observed_file_bytes'], 7)
        for key in ('candidate_filesystem_verified', 'publication_authorized',
                    'archive_signature_verified', 'baseline_changes_checked',
                    'unlisted_mutations_checked', 'timestamps_compared',
                    'directory_metadata_compared'):
            self.assertIs(value[key], False)
        self.assertTrue(os.fstat(self.fd))  # Caller retains descriptor ownership.

    def test_same_size_payload_substitution_fails(self):
        (self.root / 'usr/bin/example').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'bytes'):
            self.compare()

    def test_copied_bytes_do_not_satisfy_hardlink_provenance(self):
        path = self.root / 'usr/bin/copy'
        path.unlink()
        path.write_bytes(b'payload')
        path.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'hardlink'):
            self.compare()

    def test_changed_ownership_or_mode_fails(self):
        (self.root / 'usr/bin/example').chmod(0o700)
        with self.assertRaisesRegex(ValueError, 'ownership or mode'):
            self.compare()

    def test_leaf_symlink_cannot_substitute_for_a_regular_file(self):
        path = self.root / 'usr/bin/example'
        path.unlink()
        path.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            self.compare()

    def test_symlink_parent_is_refused_without_following_outside_root(self):
        (self.root / 'usr').rename(self.root / 'original')
        (self.root / 'usr').symlink_to(self.root / 'original', target_is_directory=True)
        with self.assertRaises(OSError):
            self.compare()

    def test_changed_literal_symlink_fails(self):
        path = self.root / 'usr/bin/link'
        path.unlink()
        path.symlink_to('/different')
        with self.assertRaisesRegex(ValueError, 'literal symlink'):
            self.compare()

    def test_missing_path_fails(self):
        (self.root / 'usr/bin/link').unlink()
        with self.assertRaises(FileNotFoundError):
            self.compare()

    def test_fifo_substitution_is_rejected_before_a_blocking_open(self):
        path = self.root / 'usr/bin/example'
        path.unlink()
        os.mkfifo(path, 0o755)
        with self.assertRaisesRegex(ValueError, 'regular payload type'):
            self.compare()

    def test_in_place_mutation_during_read_is_rejected_even_if_bytes_match(self):
        original_read = os.read
        path = self.root / 'usr/bin/example'
        changed = False

        def read(fd, size):
            nonlocal changed
            result = original_read(fd, size)
            if not changed:
                changed = True
                info = path.stat()
                os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 10**9))
            return result

        with patch('mano_runtime.package_candidate.os.read', side_effect=read):
            with self.assertRaisesRegex(ValueError, 'identity differ'):
                self.compare()

    def test_regular_file_descriptor_cannot_be_used_as_candidate_root(self):
        with (self.root / 'usr/bin/example').open('rb') as source:
            with self.assertRaisesRegex(ValueError, 'directory descriptor'):
                compare_payload(source.fileno(), self.manifest)

    def test_manifest_tampering_and_unsupported_metadata_fail(self):
        original = copy.deepcopy(self.manifest)
        self.manifest['entries']['usr/bin/example']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'integrity'):
            self.compare()
        self.manifest = original
        self.manifest['unsupported_metadata'] = {'usr': {'unknown': 'true'}}
        with self.assertRaisesRegex(ValueError, 'supported'):
            self.compare()

    def test_extra_files_are_explicitly_outside_this_observation(self):
        (self.root / 'unlisted').write_bytes(b'not authorized by this comparison')
        result = self.compare()
        self.assertFalse(result['unlisted_mutations_checked'])
        self.assertFalse(result['candidate_filesystem_verified'])

    def test_interruption_propagates_and_leaves_owned_root_open(self):
        def revoke():
            raise PermissionError('Stop changed')

        with self.assertRaisesRegex(PermissionError, 'Stop changed'):
            compare_payload(self.fd, self.manifest, checkpoint=revoke)
        self.assertTrue(os.fstat(self.fd))

    def test_non_callable_checkpoint_cannot_disable_revocation(self):
        with self.assertRaisesRegex(ValueError, 'Callable'):
            compare_payload(self.fd, self.manifest, checkpoint=False)
