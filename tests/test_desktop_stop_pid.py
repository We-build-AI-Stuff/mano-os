import importlib.util
import unittest
from pathlib import Path

path = Path(__file__).resolve().parents[1] / 'scripts/probe_private_desktop.py'
spec = importlib.util.spec_from_file_location('desktop_stop_pid', path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class DesktopStopPidTests(unittest.TestCase):
    def test_resolves_private_pid_to_owned_vm_pid_instead_of_assuming_equality(self):
        statuses = {
            401: 'Uid:\t1004 1004 1004 1004\nNSpid:\t401 9\n',
            402: 'Uid:\t1005 1005 1005 1005\nNSpid:\t402 9\n',
            9: 'Uid:\t1004 1004 1004 1004\nNSpid:\t9\n',
        }
        self.assertEqual(probe.resolve_task_pid(statuses, 9, 1004), 401)

    def test_missing_changed_owner_or_ambiguous_mapping_is_not_stop_evidence(self):
        for statuses in ({}, {401: 'Uid: 1005 1005 1005 1005\nNSpid: 401 9\n'},
                         {401: 'Uid: 1004 1004 1004 1004\nNSpid: 402 9\n'},
                         {pid: f'Uid: 1004 1004 1004 1004\nNSpid: {pid} 9\n'
                          for pid in (401, 402)}):
            with self.subTest(statuses=statuses), self.assertRaises(ValueError):
                probe.resolve_task_pid(statuses, 9, 1004)
