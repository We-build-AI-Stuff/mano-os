import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location('staged_package_probe',
                                             SCRIPTS / 'probe_staged_package.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class StagedProbeSafetyTests(unittest.TestCase):
    def apt_item(self):
        version = SimpleNamespace(architecture='amd64', version='5.02-1+b1', size=13000,
            record={'Package':'sl','Version':'5.02-1+b1','Architecture':'amd64','SHA256':'a'*64},
            origins=[SimpleNamespace(site='deb.debian.org',trusted=True)])
        return SimpleNamespace(name='sl:amd64',shortname='sl',candidate=version)

    def test_apt_display_architecture_does_not_become_archive_filename(self):
        name, _version, _digest, _origins, checks = probe.candidate_admission(self.apt_item())
        self.assertEqual(name, 'sl')
        self.assertTrue(all(checks.values()))

    def test_canonical_name_does_not_allow_mismatched_archive_record(self):
        item = self.apt_item()
        item.candidate.record['Architecture'] = 'arm64'
        self.assertFalse(probe.candidate_admission(item)[-1]['record_identity'])

    def candidate(self, **changes):
        values = dict(name='sl', architecture='amd64', version='5.02-1+b1',
                      digest='a' * 64, size=13000,
                      origins=[dict(site='deb.debian.org', trusted=True)])
        return probe.candidate_checks(**(values | changes))

    def test_expected_authenticated_debian_candidate_passes_all_fields(self):
        self.assertTrue(all(self.candidate().values()))

    def test_untrusted_official_site_is_not_enough(self):
        self.assertFalse(self.candidate(origins=[dict(site='deb.debian.org',
                                                   trusted=False)])['trusted_origin'])

    def test_trusted_third_party_site_is_not_enough(self):
        self.assertFalse(self.candidate(origins=[dict(site='other.example',
                                                   trusted=True)])['trusted_origin'])

    def test_malformed_name_missing_digest_and_wrong_arch_have_separate_failures(self):
        checks = self.candidate(name='sl:amd64', architecture='arm64', digest=None)
        self.assertEqual({key for key, ok in checks.items() if not ok},
                         {'name', 'architecture', 'sha256'})

    def test_invalid_size_types_and_values_remain_rejected(self):
        for size in (True, 1.5, 0, -1, 10 * 1024**2 + 1):
            with self.subTest(size=size):
                self.assertFalse(self.candidate(size=size)['size'])

    def test_mac_refuses_before_guest_commands_or_filesystem_setup(self):
        with patch.object(probe.sys, 'platform', 'darwin'), \
                patch.object(probe, 'guard') as guard, \
                patch.object(probe.recovery, 'layout') as layout:
            with self.assertRaises(PermissionError):
                probe.main()
        guard.assert_not_called()
        layout.assert_not_called()

    def test_candidate_symlink_cannot_redirect_observation_outside_clone(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            candidate = root / 'candidate'
            candidate.mkdir()
            outside = root / 'outside'
            outside.write_text('outside fixture')
            (candidate / 'payload').symlink_to(outside)
            with patch.object(probe.recovery, 'read') as read:
                with self.assertRaisesRegex(ValueError, 'alias'):
                    probe.candidate_read(candidate, 'payload', 1024)
                read.assert_not_called()

    def test_absolute_and_parent_paths_cannot_bypass_clone_observation_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            candidate = root / 'candidate'
            candidate.mkdir()
            for name in (str(root / 'outside'), '../outside'):
                with self.subTest(name=name), patch.object(probe.recovery, 'read') as read:
                    with self.assertRaisesRegex(ValueError, 'relative'):
                        probe.candidate_read(candidate, name, 1024)
                    read.assert_not_called()
