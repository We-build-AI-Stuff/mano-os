import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location('staged_package_probe',
                                             SCRIPTS / 'probe_staged_package.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class StagedProbeSafetyTests(unittest.TestCase):
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
