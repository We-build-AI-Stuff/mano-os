import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

from test_staged_package_probe import SCRIPTS

SPEC = importlib.util.spec_from_file_location('man_source_capture_probe',
                                             SCRIPTS / 'probe_package_man_source_bytes.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class ManualSourceCaptureProbeTests(unittest.TestCase):
    def test_source_role_reuses_dropped_identity_and_gets_only_fixed_program_and_manifest(self):
        args = probe.source_sandbox(Path('/private'), [], Path('/empty'), 'a'*64)
        self.assertEqual(args[-2:], ['/run/man-cache-guard', '--source-bytes'])
        self.assertIn('/private/man-source-cache', args)
        self.assertNotIn('/private/regenerated-man-cache', args)
        bindings = [tuple(args[i:i+3]) for i, arg in enumerate(args)
                    if arg in {'--ro-bind', '--bind'}]
        self.assertIn(('--ro-bind', '/private/man-source-reader.py',
                       '/run/man-source-reader.py'), bindings)
        self.assertIn(('--ro-bind', '/private/man-source-paths.json',
                       '/run/man-source-paths.json'), bindings)
        self.assertIn(('--ro-bind', '/private/candidate/usr/share/man', '/usr/share/man'), bindings)
        self.assertIn('--clear-groups', args)
        self.assertIn('--bounding-set=-all', args)
        self.assertIn('--inh-caps=-all', args)
        self.assertIn('--ambient-caps=-all', args)

    def test_source_role_has_its_own_bounded_process_domain(self):
        command = probe.source_unit()
        self.assertIn('--unit=mano-man-source-ci.service', command)
        for bound in ('MemoryMax=268435456', 'TasksMax=32', 'RuntimeMaxSec=70',
                      'KillMode=control-group', 'NoNewPrivileges=yes'):
            self.assertIn('--property='+bound, command)

    def test_controller_cannot_run_linux_root_operations_on_mac(self):
        with patch.object(probe.sys, 'platform', 'darwin'), \
                patch.object(probe.Path, 'read_bytes', side_effect=AssertionError('host read')):
            with self.assertRaises(PermissionError):
                probe.capture_sources(Path('/private'), b'', {}, {}, [], Path('/empty'), '', None)
