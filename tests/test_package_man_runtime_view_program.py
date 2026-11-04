"""Compile the optional future worker only; never execute its Linux operations."""
import ast
import contextlib
import copy
import io
import json
import sys
import unittest
from pathlib import Path

import test_package_man_regeneration as regeneration
import test_package_man_runtime_origin as origin_fixtures
import test_package_man_runtime_view as view_fixtures

from mano_runtime import package_man_runtime_view as view


class RuntimeViewProgramTests(unittest.TestCase):
    def test_origin_mode_embeds_only_serializer_and_binds_it_before_generation(self):
        root = Path(__file__).resolve().parents[1]/'src/mano_runtime'
        source = (root/'package_man_runtime_origin.py').read_text()
        data = regeneration.probe.program(regeneration.stage.PROGRAM,
            runtime_view_source=(root/'package_man_runtime_view.py').read_text(),
            runtime_origin_source=source)
        compile(data, 'source-identity-worker-compile-only', 'exec')
        text = data.decode()
        self.assertIn('def runtime_source_identity(info):', text)
        self.assertNotIn('def hold(', text)
        self.assertNotIn('def root_guard(', text)
        self.assertNotIn('/usr/bin/btrfs', text)
        self.assertIn('RUNTIME_ORIGIN_SOURCE_SHA256', text)
        self.assertLess(text.index("assert state['nnp']==1"),
                        text.index('runtime_view, runtime_source_identities=capture('))
        self.assertLess(text.index('runtime_view, runtime_source_identities=capture('),
                        text.index('result=run_observed('))
        with self.assertRaises(ValueError):
            regeneration.probe.program(regeneration.stage.PROGRAM, runtime_origin_source=source)

    def test_source_comparison_rejects_wrong_serializer_undrained_or_mismatched_view(self):
        identities = origin_fixtures.fixture()
        row = dict(runtime_view=view_fixtures.fixture(), domain_drained=True,
                   runtime_origin_source_sha256='c'*64)
        for target, sample in row['runtime_view']['paths'].items():
            for key in ('device', 'uid', 'mode', 'kind'):
                identities[target][key] = copy.deepcopy(sample[key])
        row['runtime_source_identities'] = copy.deepcopy(identities)
        result = regeneration.probe.compare_source_identities(row, identities, identities, 'c'*64)
        self.assertTrue(result['worker_source_identities_match'])
        for key, value in (('runtime_origin_source_sha256', 'd'*64), ('domain_drained', False)):
            altered = copy.deepcopy(row)
            altered[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                regeneration.probe.compare_source_identities(
                    altered, identities, identities, 'c'*64)
        for field, value in (('mode', 0o600), ('uid', False), ('device', [0.0, 1])):
            altered = copy.deepcopy(row)
            altered['runtime_view']['paths']['/etc/passwd'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                regeneration.probe.compare_source_identities(
                    altered, identities, identities, 'c'*64)

    def test_optional_isolated_worker_embeds_fixed_source_after_dropped_state_checks(self):
        source = (Path(__file__).resolve().parents[1]/
                  'src/mano_runtime/package_man_runtime_view.py').read_text()
        data = regeneration.probe.program(regeneration.stage.PROGRAM, runtime_view_source=source)
        compile(data, 'future-runtime-view-worker-fixture', 'exec')
        text = data.decode()
        self.assertIn('def capture(*, identity_function=None):', text)
        self.assertIn('os.O_PATH | os.O_CLOEXEC', text)
        self.assertLess(text.index("assert state['nnp']==1"),
                        text.index('runtime_view=capture()'))
        self.assertLess(text.index('runtime_view=capture()'), text.index('result=run_observed('))
        self.assertIn('runtime_view_proof=verify(runtime_view)', text)
        self.assertIn('MANO_MAN_RUNTIME_VIEW=', text)
        self.assertIn('runtime_view_source_sha256=RUNTIME_VIEW_SOURCE_SHA256', text)
        calls = [node for node in ast.walk(ast.parse(data)) if isinstance(node, ast.Call)]
        self.assertFalse(any(isinstance(node.func, ast.Name) and node.func.id == '__import__'
                             for node in calls))

    def test_refused_view_is_retained_before_any_generation_and_valid_view_can_proceed(self):
        source = (Path(__file__).resolve().parents[1]/
                  'src/mano_runtime/package_man_runtime_view.py').read_text()
        data = regeneration.probe.program(regeneration.stage.PROGRAM, runtime_view_source=source)
        text = data.decode()
        start = text.index('runtime_view=capture()')
        end = text.index("config=Path('/etc/manpath.config').read_bytes()", start)
        preflight = text[start:end]+'generation_started=True\n'
        for valid in (True, False):
            value = view_fixtures.fixture()
            if not valid:
                value['paths']['/usr/lib']['readonly'] = False
            environment = dict(capture=lambda value=value: value, verify=view.verify,
                               json=json, sys=sys, generation_started=False)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                if valid:
                    exec(compile(preflight, 'mocked-view-preflight', 'exec'), environment)
                else:
                    with self.assertRaises(ValueError):
                        exec(compile(preflight, 'mocked-view-preflight', 'exec'), environment)
            self.assertEqual(environment['generation_started'], valid)
            if valid:
                self.assertEqual(stderr.getvalue(), '')
            else:
                prefix, witness = stderr.getvalue().split('=', 1)
                self.assertEqual(prefix, 'MANO_MAN_RUNTIME_VIEW')
                self.assertEqual(json.loads(witness), value)

    def test_root_validator_requires_exact_helper_and_kernel_view_proof(self):
        host, row = regeneration.worker()
        row.update(runtime_view=view_fixtures.fixture(), runtime_view_source_sha256='c'*64)
        row['runtime_view_proof'] = view.verify(row['runtime_view'])
        regeneration.probe.validate(row, host, 'a'*64, runtime_view_source_sha256='c'*64)
        for field, value in (('runtime_view_source_sha256', 'd'*64),
                             ('runtime_view_proof', dict(row['runtime_view_proof'],
                                                        fixed_targets_readonly=10.0)),
                             ('runtime_view_proof', dict(row['runtime_view_proof'],
                                                        complete_runtime_closure_verified=True))):
            altered = dict(row)
            altered[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                regeneration.probe.validate(altered, host, 'a'*64,
                                            runtime_view_source_sha256='c'*64)

    def test_legacy_compiler_mode_preserves_worker_without_view_capture(self):
        data = regeneration.probe.program(regeneration.stage.PROGRAM)
        self.assertNotIn(b'runtime_view', data)
        self.assertNotIn(b'os.O_PATH', data)

    def test_missing_duplicate_or_unbounded_helper_source_fails_before_worker_creation(self):
        source = (Path(__file__).resolve().parents[1]/
                  'src/mano_runtime/package_man_runtime_view.py').read_text()
        for altered in ('', 'pass\n', source+'\ndef capture():\n    pass\n', 'x'*65537):
            with self.subTest(length=len(altered)), self.assertRaises(ValueError):
                regeneration.probe.program(regeneration.stage.PROGRAM,
                                           runtime_view_source=altered)


if __name__ == '__main__':
    unittest.main()
