import base64
import copy
import hashlib
import importlib.util
import os
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
        self.assertIn('--property=RuntimeMaxSec=70', probe.source_unit())

    @unittest.skipUnless(sys.platform == 'linux', 'Actual GNU gzip only in Linux CI')
    def test_native_verifier_compares_bytes_and_rejects_mismatch_and_truncation(self):
        self.assertNotEqual(os.geteuid(), 0)
        raw = member(b'fixture', name=b'../../not-a-path', hcrc=True)
        result = content.verify_gnu(raw, b'fixture')
        self.assertEqual(result['output_bytes'], 7)
        for stream, expected in ((raw, b'wrong'), (raw[:-1], b'fixture'),
                                 (member(b'A'*100000), b'A')):
            with self.assertRaises(ValueError):
                content.verify_gnu(stream, expected)
