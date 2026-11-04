"""Portable capture plumbing only; native mandb runs exclusively in Debian CI."""
import base64
import io
import json
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mano_runtime import package_man_source_content as worker


class NativeCallerCaptureTests(unittest.TestCase):
    def observe(self, program, *, timeout=2, fixed_read=None):
        real_popen = subprocess.Popen
        calls = []

        def portable_child(command, **kwargs):
            calls.append((command, kwargs.copy()))
            # Explicitly replace the native command with ordinary Python only.
            return real_popen([sys.executable, '-c', program], **kwargs)

        def fixed_bytes(path, maximum):
            return {'/usr/bin/mandb': b'fixed synthetic command bytes',
                    '/etc/manpath.config': b'fixed synthetic configuration'}[path]

        with patch.object(worker, 'caller_identity', return_value=dict(uid=6, gid=12, groups=[])), \
                patch.object(worker, 'read_fixed', side_effect=fixed_read or fixed_bytes), \
                patch.object(worker.subprocess, 'Popen', side_effect=portable_child):
            result = worker.capture_native_caller(timeout=timeout)
        self.assertEqual(len(calls), 1)
        command, kwargs = calls[0]
        self.assertEqual(command, ['/usr/bin/mandb', '--test', '--debug', '/usr/share/man'])
        self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        self.assertTrue(kwargs['close_fds'])
        self.assertTrue(kwargs['start_new_session'])
        self.assertEqual(kwargs['cwd'], '/')
        self.assertEqual(kwargs['env'], dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C',
                                           TZ='UTC0', HOME='/nonexistent'))
        for name in ('stdout', 'stderr'):
            record = result[name]
            raw = base64.b64decode(record['base64'], validate=True)
            self.assertEqual(record['bytes'], len(raw))
            self.assertEqual(record['sha256'], worker.sha(raw))
        return result

    def test_capture_keeps_both_raw_streams_and_nonzero_outcome_without_authority(self):
        result = self.observe('import sys;print("observed");'
                              'print("diagnostic",file=sys.stderr);sys.exit(3)')
        self.assertTrue(result['capture_complete'])
        self.assertIsNone(result['capture_failure'])
        self.assertEqual(result['returncode'], 3)
        self.assertEqual(base64.b64decode(result['stdout']['base64']), b'observed\n')
        self.assertEqual(base64.b64decode(result['stderr']['base64']), b'diagnostic\n')
        for flag in ('native_man_db_caller_semantics_verified', 'full_source_semantics_verified',
                     'generated_state_validated', 'changes_authorized', 'publication_authorized'):
            self.assertIs(result[flag], False)

    def test_stream_budgets_keep_only_bounded_partial_bytes(self):
        for name, limit in (('stdout', 128*1024), ('stderr', 256*1024)):
            result = self.observe(f'import sys;sys.{name}.buffer.write(b"x"*{limit+1})')
            with self.subTest(stream=name):
                self.assertFalse(result['capture_complete'])
                self.assertEqual(result['capture_failure'], name+'-budget')
                self.assertEqual(result[name]['bytes'], limit)

    def test_deadline_handles_inherited_open_pipes_and_closed_streams(self):
        for program in ('import os,time\nif os.fork()==0:time.sleep(10)\n',
                        'import os,time;os.close(1);os.close(2);time.sleep(10)'):
            result = self.observe(program, timeout=.15)
            self.assertFalse(result['capture_complete'])
            self.assertEqual(result['capture_failure'], 'deadline')

    def test_changed_fixed_binary_cannot_keep_a_valid_custody_claim(self):
        values = iter((b'original', b'configuration', b'changed'))
        with self.assertRaisesRegex(ValueError, 'changed during capture'):
            self.observe('print("done")', fixed_read=lambda *args: next(values))

    def test_unsafe_identity_refuses_before_read_or_native_process(self):
        with patch.object(worker.sys, 'platform', 'darwin'), \
                patch.object(worker, 'read_fixed') as read, \
                patch.object(worker.subprocess, 'Popen') as spawn:
            with self.assertRaises(PermissionError):
                worker.capture_native_caller()
            read.assert_not_called()
            spawn.assert_not_called()

    def test_linux_root_or_wrong_group_never_reads_or_starts_the_caller(self):
        for uid, gid, groups in (((0, 0, 0), (12, 12, 12), []),
                                 ((6, 6, 6), (0, 0, 0), []),
                                 ((6, 6, 6), (12, 12, 12), [12])):
            with self.subTest(uid=uid, gid=gid, groups=groups), \
                    patch.object(worker.sys, 'platform', 'linux'), \
                    patch.object(worker.os, 'getresuid', return_value=uid, create=True), \
                    patch.object(worker.os, 'getresgid', return_value=gid, create=True), \
                    patch.object(worker.os, 'getgroups', return_value=groups), \
                    patch.object(worker, 'read_fixed') as read, \
                    patch.object(worker.subprocess, 'Popen') as spawn:
                with self.assertRaises(PermissionError):
                    worker.capture_native_caller()
                read.assert_not_called()
                spawn.assert_not_called()

    def test_bad_deadline_never_launches_a_process(self):
        with patch.object(worker, 'caller_identity', return_value={}), \
                patch.object(worker, 'read_fixed') as read, \
                patch.object(worker.subprocess, 'Popen') as spawn:
            for timeout in (True, 0, 21, None, '20', float('nan')):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    worker.capture_native_caller(timeout=timeout)
            read.assert_not_called()
            spawn.assert_not_called()

    def test_exact_request_dispatches_before_source_codec_imports(self):
        expected = dict(profile='fabricated-native-capture', publication_authorized=False)
        output = SimpleNamespace(buffer=io.BytesIO())
        with patch.object(worker.sys, 'platform', 'linux'), \
                patch.object(worker.sys, 'argv', ['fixed-worker']), \
                patch.object(worker.sys, 'stdout', output), \
                patch.object(worker.os, 'getresuid', return_value=(6, 6, 6), create=True), \
                patch.object(worker.os, 'getresgid', return_value=(12, 12, 12), create=True), \
                patch.object(worker.os, 'getgroups', return_value=[]), \
                patch.object(worker, 'read_fixed', return_value=worker.CALLER_REQUEST) as read, \
                patch.object(worker, 'capture_native_caller', return_value=expected) as capture:
            worker.main()
        self.assertEqual(json.loads(output.buffer.getvalue()), expected)
        capture.assert_called_once_with()
        read.assert_called_once_with('/run/man-source-paths.json', 4*1024**2, mode=0o444)
        self.assertEqual(worker.CALLER_REQUEST, b'{"profile":"man-native-reference-caller-v1"}\n')


if __name__ == '__main__':
    unittest.main()
