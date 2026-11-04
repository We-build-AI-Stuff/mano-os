import errno
import stat
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from mano_runtime import package_ipc


class PackageIpcTests(unittest.TestCase):
    def setUp(self):
        self.first, self.second = MagicMock(), MagicMock()
        for name in ('connect', 'bind', 'listen', 'accept'):
            getattr(self.first, name).side_effect = PermissionError(errno.EPERM, 'denied')
        self.first.recv.return_value = b'private-reply'
        self.second.recv.return_value = b'package-private-pair'
        self.pair = patch.object(package_ipc.socket, 'socketpair', side_effect=[
            PermissionError(errno.EPERM, 'denied'), PermissionError(errno.EPERM, 'denied'),
            (self.first, self.second)]).start()
        self.named = patch.object(package_ipc.socket, 'socket',
            side_effect=PermissionError(errno.EPERM, 'denied')).start()
        self.descriptors = patch.object(package_ipc.os, 'listdir', return_value=[]).start()
        self.addCleanup(patch.stopall)

    def test_complete_denial_and_bidirectional_positive_control(self):
        result = package_ipc.verify()
        self.assertEqual(result, dict(host_named_ipc_denied=True,
            anonymous_stream_socketpair_works=True, inherited_socket_fds_absent=True))
        self.assertEqual(self.named.call_count, 9)
        self.assertEqual(self.pair.call_count, 3)
        self.assertEqual(self.first.connect.call_count, 2)
        self.first.sendall.assert_called_once_with(b'package-private-pair')
        self.second.sendall.assert_called_once_with(b'private-reply')

    def test_inherited_socket_is_rejected_before_new_socket_operations(self):
        self.descriptors.return_value = ['7']
        with patch.object(package_ipc.os, 'fstat',
                          return_value=SimpleNamespace(st_mode=stat.S_IFSOCK)):
            with self.assertRaisesRegex(PermissionError, 'Inherited'):
                package_ipc.verify()
        self.named.assert_not_called()

    def test_regular_pipe_and_closed_directory_descriptors_are_accepted(self):
        self.descriptors.return_value = ['0', '3', '4']
        with patch.object(package_ipc.os, 'fstat', side_effect=[
                SimpleNamespace(st_mode=stat.S_IFIFO), SimpleNamespace(st_mode=stat.S_IFREG),
                OSError(errno.EBADF, 'closed')]):
            self.assertTrue(package_ipc.verify()['inherited_socket_fds_absent'])

    def test_missing_named_socket_filter_is_rejected_and_socket_closed(self):
        connection = MagicMock()
        self.named.side_effect = None
        self.named.return_value = connection
        with self.assertRaisesRegex(PermissionError, 'creation'):
            package_ipc.verify()
        connection.close.assert_called_once()

    def test_unexpected_errno_does_not_count_as_kernel_denial(self):
        self.first.connect.side_effect = OSError(errno.ENOENT, 'masked path')
        with self.assertRaises(OSError) as raised:
            package_ipc.verify()
        self.assertEqual(raised.exception.errno, errno.ENOENT)

    def test_retargetable_pair_is_rejected_and_both_endpoints_closed(self):
        self.pair.side_effect = [(self.first, self.second)]
        with self.assertRaisesRegex(PermissionError, 'Retargetable'):
            package_ipc.verify()
        self.first.close.assert_called_once()
        self.second.close.assert_called_once()

    def test_anonymous_pair_must_transfer_exact_bytes(self):
        self.second.recv.return_value = b'x' * len(b'package-private-pair')
        with self.assertRaisesRegex(PermissionError, 'stream pair failed'):
            package_ipc.verify()

    def test_short_stream_reads_are_reassembled_but_eof_is_rejected(self):
        self.second.recv.side_effect = [b'package-', b'private-pair']
        self.assertTrue(package_ipc.verify()['anonymous_stream_socketpair_works'])
        self.second.recv.side_effect = [b'']
        with self.assertRaisesRegex(PermissionError, 'closed early'):
            package_ipc._transfer(self.first, self.second, b'expected')

    def test_negative_accept_reaches_syscall_before_timeout_wrapper_is_enabled(self):
        def denied_accept():
            self.first.settimeout.assert_not_called()
            self.second.settimeout.assert_not_called()
            raise PermissionError(errno.EPERM, 'native accept denial')
        self.first.accept.side_effect = denied_accept
        self.assertTrue(package_ipc.verify()['host_named_ipc_denied'])
        self.first.settimeout.assert_called_once_with(.2)
        self.second.settimeout.assert_called_once_with(.2)
