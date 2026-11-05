import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mano_desktop import protocol, session


def configuration():
    return dict(width=1024, height=720, cwd='.', timeout_seconds=90, input_limit_bytes=65536,
                memory_bytes=protocol.MEMORY_MAX, pids=protocol.PIDS_MAX, cpu_percent=50)


class DesktopProtocolTests(unittest.TestCase):
    def test_opening_cannot_select_host_sockets_commands_or_unbounded_resources(self):
        value = configuration()
        self.assertEqual(protocol.opening(value), value)
        for change in (dict(width=True), dict(height=721), dict(cwd='../human'),
                       dict(memory_bytes=protocol.MEMORY_MAX + 1), dict(pids=97),
                       dict(cpu_percent=51), dict(WAYLAND_DISPLAY='/run/human'),
                       dict(argv=['/bin/sh'])):
            with self.subTest(change=change), self.assertRaises(ValueError):
                protocol.opening(value | change)
        launch = protocol.launch_arguments(value)
        self.assertEqual(launch['argv'][:3], ['/usr/bin/python3', '-I', protocol.WORKER])
        self.assertEqual(json.loads(launch['argv'][3]), value)

    def test_control_coordinates_keys_and_paths_stay_inside_the_declared_session(self):
        for command, args in (
                ('pointer', dict(x=-1, y=0, button='left')),
                ('pointer', dict(x=1024, y=0, button=None)),
                ('key', dict(key='Return', modifiers=['ctrl', 'ctrl'])),
                ('key', dict(key='Return; exec sh', modifiers=[])),
                ('writer', dict(path='/home/human/document.odt')),
                ('writer', dict(path='https://example.org/document.odt')),
                ('writer', dict(path='docs/../document.odt')),
                ('writer', dict(path='docs/document.docm')),
                ('writer', dict(path='document.odt', flags=['--headless'])),
                ('screenshot', dict(path='/home/human/shot.png')),
                ('screenshot', dict(path='../shot.png')),
                ('screenshot', dict(path='a/../shot.png')),
                ('screenshot', dict(path='.git/shot.png')),
                ('type', dict(text='command\n')),
                ('ipc', dict(command='exec sh'))):
            with self.subTest(command=command, args=args), self.assertRaises(ValueError):
                protocol.control(command, args, width=1024, height=720)
        self.assertEqual(protocol.control('screenshot', dict(path='images/shot.png'),
                                          width=1024, height=720), dict(path='images/shot.png'))
        self.assertEqual(protocol.control('writer', dict(path='docs/report.odt'),
                                          width=1024, height=720), dict(path='docs/report.odt'))

    def test_framing_is_complete_bounded_unique_and_round_trips_data(self):
        raw = protocol.request('a'*32, 'type', dict(text='quoted "text" ☃'),
                               width=1024, height=720)
        value = protocol.decode(raw)
        self.assertEqual(value['args']['text'], 'quoted "text" ☃')
        self.assertEqual(raw.count(b'\n'), 1)
        for bad in (raw[:-1], b'{"id":1,"id":2}\n', b'{"value":NaN}\n',
                    b'x'*(protocol.MAX_FRAME+1)):
            with self.assertRaises(ValueError):
                protocol.decode(bad)

    def test_worker_requires_bubblewrap_private_devpts_mapping(self):
        status = 'NoNewPrivs: 1\nSeccomp: 2\nCapEff: 0\nCapBnd: 0\nCapAmb: 0\n'
        files = {'status': status, 'uid_map': '1004 0 1\n', 'gid_map': '1005 0 1\n'}

        def read(path):
            return files[path.name]

        with (patch.object(session.sys, 'platform', 'linux'),
              patch.object(session.os, 'geteuid', return_value=1004),
              patch.object(session.os, 'getegid', return_value=1005),
              patch.object(session.Path, 'read_text', autospec=True, side_effect=read),
              patch.object(session.Path, 'lstat', return_value=SimpleNamespace(
                  st_mode=session.stat.S_IFREG | 0o555, st_uid=65534))):
            session.require_task_context()
            for mapping in ('0 0 4294967295\n', '1004 0 2\n', '1004 1004 1\n',
                            '1004 0 1\n1005 1 1\n'):
                files['uid_map'] = mapping
                with self.subTest(mapping=mapping), self.assertRaisesRegex(
                        PermissionError, 'uid_map'):
                    session.require_task_context()

    def test_mac_worker_refuses_before_configuration_reads_or_process_creation(self):
        with (patch.object(session.sys, 'platform', 'darwin'),
              patch.object(session, 'wire') as wire,
              patch.object(session.tempfile, 'TemporaryDirectory') as temporary,
              patch.object(session.subprocess, 'Popen') as process):
            with self.assertRaises(PermissionError):
                session.Desktop(configuration())
            wire.assert_not_called()
            temporary.assert_not_called()
            process.assert_not_called()
