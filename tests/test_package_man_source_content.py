import base64
import copy
import hashlib
import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from test_package_man_gzip import member
from test_staged_package_probe import SCRIPTS

from mano_runtime import package_man_gzip as codec
from mano_runtime import package_man_source_content as content

SPEC = importlib.util.spec_from_file_location('source_content_probe',
                                             SCRIPTS/'probe_package_man_source_content.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def witness(raw, expected):
    return dict(command=['/usr/bin/gzip', '-cd'], returncode=0, input_bytes=len(raw),
                output_bytes=len(expected), output_sha256=hashlib.sha256(expected).hexdigest(),
                stderr_bytes=0, complete=True, bytes_equal=True)


class ManualContentTests(unittest.TestCase):
    def test_controller_capture_bounds_streams_and_retains_partial_failure(self):
        command = [sys.executable, '-I', '-B', '-c']
        self.assertEqual(probe.bounded_capture(command+['print("fixture")'], timeout=3),
                         b'fixture\n')
        for stream in ('stdout', 'stderr'):
            program = f'import os; os.write({1 if stream == "stdout" else 2}, b"x"*100000)'
            with self.subTest(stream=stream), self.assertRaises(
                    subprocess.CalledProcessError) as raised:
                probe.bounded_capture(command+[program], timeout=3,
                                      stdout_limit=4096, stderr_limit=4096)
            data = raised.exception.stdout if stream == 'stdout' else raised.exception.stderr
            self.assertEqual(data, b'x'*4096)
        with self.assertRaises(subprocess.CalledProcessError) as raised:
            probe.bounded_capture(command+['print("partial",flush=True);raise SystemExit(7)'],
                                  timeout=3)
        self.assertEqual(raised.exception.returncode, 7)
        self.assertEqual(raised.exception.stdout, b'partial\n')

    def test_controller_capture_deadline_survives_closed_or_inherited_pipes(self):
        command = [sys.executable, '-I', '-B', '-c']
        for program in ('import os,time;os.close(1);os.close(2);time.sleep(10)',
                        'import os,time;pid=os.fork();time.sleep(10) if pid == 0 else None'):
            with self.subTest(program=program), self.assertRaises(subprocess.TimeoutExpired):
                probe.bounded_capture(command+[program], timeout=.3)

    def test_synthetic_pipeline_binds_input_and_both_outputs_without_semantic_authority(self):
        raw = member(b'fixture')
        values = dict(files={'man1/example.1.gz': base64.b64encode(raw).decode()})
        with patch.object(content, 'verify_gnu', side_effect=witness) as compared:
            report = content.process_files(values, codec)
        compared.assert_called_once_with(raw, b'fixture')
        requested = dict(files={'man1/example.1.gz':
            dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())})
        summary = content.validate_report(report, requested)
        self.assertEqual(summary['expanded_bytes'], 7)
        self.assertTrue(summary['both_decoders_equal'])
        self.assertFalse(summary['roff_interpreted'])
        self.assertFalse(summary['publication_authorized'])
        for mutation in (lambda r:r.update(publication_authorized=True),
                         lambda r:r.update(expanded_bytes=True),
                         lambda r:r['files']['man1/example.1.gz']['independent_gzip'].update(
                             output_sha256='a'*64),
                         lambda r:r['files']['man1/example.1.gz']['independent_gzip'].update(
                             complete=False)):
            changed = copy.deepcopy(report)
            mutation(changed)
            with self.assertRaises(ValueError):
                content.validate_report(changed, requested)

    def test_aggregate_expansion_members_and_report_budgets_reject(self):
        values = dict(files={'page.gz': base64.b64encode(member(b'fixture')).decode()})
        for limit in ('MAX_EXPANDED_TOTAL', 'MAX_MEMBER_TOTAL', 'MAX_REPORT_BYTES'):
            with patch.object(content, limit, 0), \
                    patch.object(content, 'verify_gnu', side_effect=witness), \
                    self.assertRaises(ValueError):
                content.process_files(values, codec)

    def test_worker_refuses_mac_before_fixed_input_or_support_module_reads(self):
        with patch.object(content.sys, 'platform', 'darwin'), \
                patch.object(content.os, 'open', side_effect=AssertionError('host read')):
            with self.assertRaises(PermissionError):
                content.main()
            with self.assertRaises(PermissionError):
                content.verify_gnu(b'fixture', b'fixture')

    def test_controller_refuses_mac_before_root_operations(self):
        with patch.object(probe.sys, 'platform', 'darwin'):
            with self.assertRaises(PermissionError):
                probe.capture_content(Path('/private'), {}, [], Path('/empty'), '', None)
            with self.assertRaises(PermissionError):
                probe.freeze_expanded_inputs(Path('/private'), Path('/empty'))

    def test_content_unit_keeps_other_roles_budgets_and_gets_a_fixed_role(self):
        command = probe.content_sandbox(Path('/private'), [], Path('/empty'), 'a'*64)
        self.assertEqual(command[-2:], ['/run/man-cache-guard', '--source-content'])
        self.assertIn('/private/man-content-cache', command)
        self.assertNotIn('/private/man-source-cache', command)
        self.assertIn('/run/man-source-support', command)
        unit = probe.content_unit()
        self.assertIn('--unit=mano-man-content-ci.service', unit)
        self.assertIn('--property=RuntimeMaxSec=190', unit)
        self.assertIn('--property=MemoryMax=268435456', unit)
        self.assertIn('--property=TasksMax=32', unit)
        self.assertIn('--property=LimitFSIZE=75497472', unit)
        self.assertIn('--property=LimitFSIZE=2097152', probe.source_unit())
        self.assertIn('--property=RuntimeMaxSec=70', probe.source_unit())

    @unittest.skipUnless(sys.platform == 'linux', 'Actual GNU gzip only in Linux CI')
    def test_native_verifier_compares_bytes_and_rejects_mismatch_and_truncation(self):
        self.assertNotEqual(os.geteuid(), 0)
        raw = member(b'fixture', name=b'../../not-a-path', hcrc=True)
        result = content.verify_gnu(raw, b'fixture')
        self.assertEqual(result['output_bytes'], 7)
        for stream, expected in ((raw, b'wrong'), (raw[:-1], b'fixture'),
                                 (member(b'A'*100000), b'A'),
                                 (member(b'first')+b'\0\0'+member(b'second'),
                                  b'firstsecond')):
            with self.assertRaises(ValueError):
                content.verify_gnu(stream, expected)
