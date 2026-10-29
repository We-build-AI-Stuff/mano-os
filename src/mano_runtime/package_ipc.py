"""Pre-effect observations of the native package worker's socket restrictions."""

import errno
import os
import socket
import stat


def _transfer(sender, receiver, payload):
    sender.sendall(payload)
    received = bytearray()
    while len(received) < len(payload):
        chunk = receiver.recv(len(payload) - len(received))
        if not chunk:
            raise PermissionError('Anonymous package stream pair closed early')
        received.extend(chunk)
    if received != payload:
        raise PermissionError('Anonymous package stream pair failed')


def verify():
    # Inspect inherited descriptors before creating the positive control pair.
    # The launcher passes pipes and sealed regular archives, never host sockets.
    for name in os.listdir('/proc/self/fd'):
        try:
            info = os.fstat(int(name))
        except OSError as error:
            if error.errno == errno.EBADF:  # closed listdir directory descriptor
                continue
            raise
        if stat.S_ISSOCK(info.st_mode):
            raise PermissionError('Inherited package socket descriptor')
    for family in (socket.AF_UNIX, socket.AF_INET, socket.AF_INET6):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_SEQPACKET):
            try:
                connection = socket.socket(family, kind)
            except OSError as error:
                if error.errno != errno.EPERM:
                    raise
            else:
                connection.close()
                raise PermissionError('Named package socket creation was not denied')
    for kind in (socket.SOCK_DGRAM, socket.SOCK_SEQPACKET):
        try:
            pair = socket.socketpair(socket.AF_UNIX, kind)
        except OSError as error:
            if error.errno != errno.EPERM:
                raise
        else:
            for connection in pair:
                connection.close()
            raise PermissionError('Retargetable package socketpair was not denied')
    first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with first, second:
        # Keep blocking mode for negative probes: Python's timeout wrapper can
        # poll for readiness before accept(), hiding the syscall's EPERM.
        for operation in (
                lambda: first.connect('/run/mano-approval/human.sock'),
                lambda: first.connect('\0mano-package-boundary-no-peer'),
                lambda: first.bind('\0mano-package-boundary-no-listener'),
                lambda: first.listen(1), first.accept):
            try:
                operation()
            except OSError as error:
                if error.errno != errno.EPERM:
                    raise
            else:
                raise PermissionError('Named package IPC operation was not denied')
        first.settimeout(.2)
        second.settimeout(.2)
        _transfer(first, second, b'package-private-pair')
        _transfer(second, first, b'private-reply')
    return dict(host_named_ipc_denied=True, anonymous_stream_socketpair_works=True,
                inherited_socket_fds_absent=True)
