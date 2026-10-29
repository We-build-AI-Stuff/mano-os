import copy
import hashlib
import json
import unittest

from mano_runtime.package_candidate_policy import validate_payloads


def seal(entries, *, payload=False):
    raw = json.dumps(entries, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    common = dict(schema_version='1.0', entries=entries,
                  manifest_sha256=hashlib.sha256(raw).hexdigest())
    return common | ({'unsupported_metadata': {}} if payload else
                     {'excluded_subtrees': ['.snapshots']})


class CandidatePayloadPolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = dict(kind='directory', uid=0, gid=0, mode=0o755, mtime=1)
        self.file = dict(kind='file', uid=0, gid=0, mode=0o644, mtime=1,
                         bytes=1, sha256=hashlib.sha256(b'x').hexdigest())
        self.payload = {'.': self.directory.copy(), 'usr': self.directory.copy(),
                        'usr/file': self.file.copy()}
        root = dict(kind='directory', uid=0, gid=0, mode=0o755,
                    mtime_ns=0, ctime_ns=0, nlink=2, xattrs={})
        self.before = {'.': root.copy(), 'usr': root.copy()}
        self.after = copy.deepcopy(self.before)
        self.after['usr']['mtime_ns'] = 10
        self.after['usr/file'] = dict(kind='file', uid=0, gid=0, mode=0o644,
                                      mtime_ns=1_000_000_000, ctime_ns=2, nlink=1,
                                      xattrs={}, bytes=1, sha256=self.file['sha256'],
                                      hardlink_anchor='usr/file')

    def validate(self, *, payloads=None, checkpoint=None):
        return validate_payloads(seal(self.before), seal(self.after),
                                 payloads or {'one': seal(self.payload, payload=True)},
                                 checkpoint=checkpoint)

    def test_signed_paths_and_unlisted_changes_remain_separate_without_authority(self):
        self.after['unlisted'] = self.after['usr/file'].copy()
        result = self.validate()
        self.assertEqual(result['payload_paths'], 3)
        self.assertEqual(set(result['unresolved_changes']), {'usr', 'unlisted'})
        for key in ('generated_state_validated', 'protected_runtime_policy_validated',
                    'changes_authorized', 'candidate_filesystem_verified',
                    'publication_authorized', 'archive_signatures_verified'):
            self.assertIs(result[key], False)

    def test_shared_directories_preserve_baseline_security_metadata(self):
        self.before['usr']['mode'] = self.after['usr']['mode'] = 0o750
        attrs = {'system.posix_acl_access': {'bytes': 4, 'sha256': 'a'*64}}
        self.before['usr']['xattrs'] = attrs
        self.after['usr']['xattrs'] = copy.deepcopy(attrs)
        self.validate()
        for key, value in (('uid', 1), ('gid', 1), ('mode', 0o777), ('xattrs', {})):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.after)
                changed['usr'][key] = value
                with self.assertRaises(ValueError):
                    validate_payloads(seal(self.before), seal(changed),
                                      {'one': seal(self.payload, payload=True)})

    def test_new_directory_requires_signed_security_metadata_and_no_xattrs(self):
        del self.before['usr']
        self.validate()
        self.after['usr']['xattrs'] = {'security.capability': {'bytes': 1, 'sha256': 'a'*64}}
        with self.assertRaises(ValueError):
            self.validate()

    def test_non_directory_overlap_is_rejected_even_for_identical_bytes(self):
        with self.assertRaisesRegex(ValueError, 'Overlapping'):
            self.validate(payloads={'one': seal(self.payload, payload=True),
                                    'two': seal(copy.deepcopy(self.payload), payload=True)})

    def test_compatible_shared_directory_overlap_and_conflicting_modes(self):
        other = {'usr': self.directory.copy()}
        payloads = {'one': seal(self.payload, payload=True), 'two': seal(other, payload=True)}
        self.assertEqual(self.validate(payloads=payloads)['package_count'], 2)
        other['usr']['mode'] = 0o777
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            self.validate(payloads=payloads | {'two': seal(other, payload=True)})

    def test_cross_package_symlink_parent_rejected(self):
        self.payload['usr'] = dict(self.directory, kind='symlink', target='/elsewhere')
        with self.assertRaisesRegex(ValueError, 'non-directory'):
            self.validate()

    def test_payload_content_metadata_timestamps_and_missing_paths_rejected(self):
        for key, value in (('sha256', 'a'*64), ('bytes', 2), ('uid', 1), ('gid', 1),
                           ('mode', 0o4755), ('mtime_ns', 0), ('kind', 'fifo'),
                           ('xattrs', {'security.capability': {'bytes': 1, 'sha256': 'a'*64}})):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.after)
                changed['usr/file'][key] = value
                with self.assertRaises(ValueError):
                    validate_payloads(seal(self.before), seal(changed),
                                      {'one': seal(self.payload, payload=True)})
        del self.after['usr/file']
        with self.assertRaisesRegex(ValueError, 'missing'):
            self.validate()

    def test_hardlinks_require_exact_package_local_group_without_extra_aliases(self):
        self.payload['usr/link'] = dict(self.file, kind='hardlink', target='usr/file',
                                        content_path='usr/file')
        self.after['usr/link'] = self.after['usr/file'].copy()
        for row in (self.after['usr/file'], self.after['usr/link']):
            row['nlink'] = 2
        self.validate()
        self.after['usr/link']['hardlink_anchor'] = 'unlisted'
        with self.assertRaisesRegex(ValueError, 'aliases'):
            self.validate()
        self.after['usr/link']['hardlink_anchor'] = 'usr/file'
        self.after['usr/file']['nlink'] = 3
        with self.assertRaisesRegex(ValueError, 'aliases'):
            self.validate()

    def test_regular_files_cannot_gain_hardlinks_to_other_packages_or_unlisted_paths(self):
        self.after['usr/file']['nlink'] = 2
        with self.assertRaisesRegex(ValueError, 'aliases'):
            self.validate()

    def test_literal_symlink_checked_without_following_and_no_aliases(self):
        self.payload['usr/file'] = dict(self.file, kind='symlink', target='/outside')
        self.after['usr/file'] = dict(self.after['usr/file'], kind='symlink', target='/outside')
        self.validate()
        for key, value in (('target', '/different'), ('nlink', 2)):
            wrong = copy.deepcopy(self.after)
            wrong['usr/file'][key] = value
            with self.assertRaises(ValueError):
                validate_payloads(seal(self.before), seal(wrong),
                                  {'one': seal(self.payload, payload=True)})

    def test_tampered_unsupported_or_excluded_inventory_is_rejected(self):
        good = seal(self.payload, payload=True)
        for wrong in (good | {'manifest_sha256': '0'*64},
                      good | {'unsupported_metadata': {'usr/file': {'sparse': 'true'}}},
                      seal({'.snapshots': self.directory}, payload=True)):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                self.validate(payloads={'one': wrong})

    def test_cooperative_interrupt_is_propagated(self):
        def stop():
            raise InterruptedError('Stop')
        with self.assertRaises(InterruptedError):
            self.validate(checkpoint=stop)
