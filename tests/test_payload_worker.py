import unittest
from unittest.mock import MagicMock, patch

from mano_runtime import package_payload_worker as worker


class PayloadWorkerAdmissionTests(unittest.TestCase):
    def test_mac_refuses_before_stdin_proc_or_resource_changes(self):
        with patch.object(worker.sys, 'platform', 'darwin'), \
                patch.object(worker.sys, 'stdin', MagicMock()) as stdin, \
                patch.object(worker.Path, 'read_text') as read, \
                patch.object(worker.resource, 'setrlimit') as limits:
            with self.assertRaises(PermissionError):
                worker.main()
            read.assert_not_called()
            limits.assert_not_called()
            stdin.buffer.read.assert_not_called()

    def test_linux_root_or_unmarked_context_refuses_before_proc(self):
        for uid, marker in ((0, '1'), (65534, '0')):
            with self.subTest(uid=uid, marker=marker), \
                    patch.object(worker.sys, 'platform', 'linux'), \
                    patch.object(worker.os, 'geteuid', return_value=uid), \
                    patch.dict(worker.os.environ, {'MANO_DISPOSABLE_CI': marker}), \
                    patch.object(worker.Path, 'read_text') as read:
                with self.assertRaises(PermissionError):
                    worker.guard()
                read.assert_not_called()

    def test_nonempty_capabilities_or_missing_nnp_refuses(self):
        for capabilities, nnp in ((1, 1), (0, 0)):
            status = '\n'.join(f'{key}: {capabilities:x}' for key in
                               ('CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb'))
            status += f'\nNoNewPrivs: {nnp}'
            with self.subTest(capabilities=capabilities, nnp=nnp), \
                    patch.object(worker.sys, 'platform', 'linux'), \
                    patch.object(worker.os, 'geteuid', return_value=65534), \
                    patch.dict(worker.os.environ, {'MANO_DISPOSABLE_CI': '1'}), \
                    patch.object(worker.Path, 'read_text', return_value=status):
                with self.assertRaisesRegex(PermissionError, 'Empty capability'):
                    worker.guard()
