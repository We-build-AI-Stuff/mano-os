import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('probe_runtime_oom',
    Path(__file__).resolve().parents[1] / 'scripts/probe_runtime_oom.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class RuntimeOOMTests(unittest.TestCase):
    def test_kernel_event_counters_require_distinct_unsigned_oom_fields(self):
        self.assertEqual(probe.events('low 0\noom 2\noom_kill 1\n'),
                         dict(low=0, oom=2, oom_kill=1))
        for raw in ('oom 1\n', 'oom 0\noom_kill -1\n',
                    'oom 0\noom_kill 1\noom_kill 2\n', 'oom 0\noom_kill ١\n',
                    'oom 0\noom_kill 1 extra\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                probe.events(raw)

    def test_mac_refused_before_filesystem_services_or_callbacks(self):
        with (patch.object(probe.sys, 'platform', 'darwin'),
              patch.object(probe.Path, 'read_text') as read,
              patch.object(probe.subprocess, 'check_output') as command):
            with self.assertRaises(PermissionError):
                probe.run(None, None, None, None, None, None)
            read.assert_not_called()
            command.assert_not_called()

    def test_group_oom_preserves_unknown_without_inventing_exit_or_verification(self):
        outcome = dict(state='unknown', exit_code=None, verified=0)
        probe.validate_oom_outcome(outcome)
        for change in (dict(state='done'), dict(state='failed'), dict(exit_code=-9),
                       dict(verified=1), dict(verified=False)):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                probe.validate_oom_outcome(outcome | change)
