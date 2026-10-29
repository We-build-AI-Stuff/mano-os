import io
import unittest
from unittest.mock import MagicMock, patch

from mano_runtime import package_payload_worker as worker


class PayloadWorkerAdmissionTests(unittest.TestCase):
    def test_decompressor_fixed_mode_and_parse_failure_kills_child(self):
        process = MagicMock()
        process.stdout = io.BytesIO(b'untrusted tar bytes')
        process.poll.return_value = None
        with patch.object(worker.os, 'lseek'), \
                patch.object(worker.subprocess, 'Popen', return_value=process) as popen:
            def fail(stream):
                raise ValueError('Malformed control input')
            with self.assertRaisesRegex(ValueError, 'Malformed'):
                worker.decompressed(12, '--ctrl-tarfile', fail)
            self.assertEqual(popen.call_args.args[0],
                             ['/usr/bin/dpkg-deb', '--ctrl-tarfile', '/proc/self/fd/12'])
            self.assertEqual(popen.call_args.kwargs['pass_fds'], (12,))
            process.kill.assert_called_once()
            process.wait.assert_called_once_with(timeout=5)
        with patch.object(worker.subprocess, 'Popen') as popen:
            with self.assertRaises(ValueError):
                worker.decompressed(12, '--execute-scripts', fail)
            popen.assert_not_called()

    def test_nonzero_decompressor_and_nonzero_trailing_bytes_are_rejected(self):
        for code, tail in ((1, b''), (0, b'bad'), (0, b'\0'*9)):
            process = MagicMock()
            process.stdout = io.BytesIO(tail)
            process.wait.return_value = code
            process.poll.return_value = code
            with self.subTest(code=code, tail=tail), patch.object(worker.os, 'lseek'), \
                    patch.object(worker.subprocess, 'Popen', return_value=process):
                if code or any(tail):
                    with self.assertRaises(ValueError):
                        worker.decompressed(12, '--ctrl-tarfile', lambda stream: 'observed')
                else:
                    self.assertEqual(worker.decompressed(12, '--ctrl-tarfile',
                                                         lambda stream: 'observed'), 'observed')

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
