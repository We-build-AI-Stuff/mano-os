"""Presentation must distinguish recorded observations, missing data and release gates."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('delivery_summary',
    Path(__file__).resolve().parents[1] / 'scripts/delivery_summary.py')
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


class DeliverySummaryTests(unittest.TestCase):
    def test_missing_reports_do_not_establish_any_journey_or_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            result = summary.render(Path(directory), 'a'*40)
        self.assertEqual(result.count('| Not established in collected reports |'), 6)
        self.assertIn('not an independent', result.replace('\n', ' '))
        self.assertIn('physical 8 GB performance', result)

    def test_duplicate_nonfinite_nonobject_and_oversized_reports_are_not_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/'architecture-audit.json'
            for raw in (b'{"decision":"go-for-phase1-development","decision":"bad"}',
                        b'{"value":NaN}', b'[]', b'x'*(summary.MAX_REPORT_BYTES+1)):
                path.write_bytes(raw)
                value, state = summary.load(root, path.name)
                self.assertIsNone(value)
                self.assertNotEqual(len(state), 64)
                self.assertNotIn('| Reported by fixture |', summary.render(root, 'a'*40))

    def test_truthy_numeric_flags_and_incomplete_recorded_workflow_do_not_count(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/'runtime-package.json'
            data = dict(services_inactive_on_install=True, policy_data_preserved_on_reinstall=True,
                        package_removed_services_stopped_data_preserved=1)
            path.write_text(json.dumps(data))
            self.assertNotIn('| Reported by fixture |', summary.render(root, 'a'*40))
            data['package_removed_services_stopped_data_preserved'] = True
            path.write_text(json.dumps(data))
            result = summary.render(root, 'a'*40)
            self.assertEqual(result.count('| Reported by fixture |'), 1)
            self.assertIn('Unsigned prototype package', result)

    def test_fixture_success_is_labeled_recorded_and_never_live_or_release_acceptance(self):
        terminal = dict.fromkeys((
            'recorded_developer_create_fail_fix_pass_exact_artifact',
            'recorded_developer_checkpoint_replay_no_model_disclosure',
            'recorded_developer_native_stop_restart_no_follow_on_effect'), True)
        witness = dict(status='verified', provider_disclosure=False, replay_no_effect=True,
                       native_pam_approvals=4)
        terminal['recorded_developer_workflow_witness'] = witness
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/'broker-service.json'
            path.write_text(json.dumps(dict(terminal_execution=terminal)))
            result = summary.render(root, 'a'*40)
            self.assertEqual(result.count('| Reported by fixture |'), 1)
            self.assertIn('no live-model claim', result)
            for key, value in (('native_pam_approvals', 4.0), ('provider_disclosure', True),
                               ('status', 'running'), ('replay_no_effect', 1)):
                changed = dict(witness, **{key: value})
                path.write_text(json.dumps(dict(terminal_execution=dict(terminal,
                    recorded_developer_workflow_witness=changed))))
                self.assertNotIn('| Reported by fixture |', summary.render(root, 'a'*40))

    def test_revision_is_not_untrusted_markdown_or_an_approximate_branch_name(self):
        for value in ('main', 'a'*39, 'a'*40+'\nInjected', '<script>'):
            with self.assertRaises(ValueError):
                summary.render(Path('/unused'), value)

    def test_overflow_and_deep_nesting_with_true_flags_do_not_establish_a_journey(self):
        prefix = (b'{"services_inactive_on_install":true,'
                  b'"policy_data_preserved_on_reinstall":true,'
                  b'"package_removed_services_stopped_data_preserved":true,"extra":')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/'runtime-package.json'
            for extra in (b'1e999', b'-1e999', b'['*10000+b'0'+b']'*10000):
                path.write_bytes(prefix+extra+b'}')
                self.assertIsNone(summary.load(root, path.name)[0])
                self.assertNotIn('| Reported by fixture |', summary.render(root, 'a'*40))
            path.write_bytes(prefix+b'0.5}')
            self.assertIsNotNone(summary.load(root, path.name)[0])
            self.assertEqual(summary.render(root, 'a'*40).count('| Reported by fixture |'), 1)

    def test_explicit_nesting_bound_does_not_depend_on_python_decoder_recursion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'runtime-package.json'
            for depth, accepted in ((summary.MAX_REPORT_DEPTH - 1, True),
                                    (summary.MAX_REPORT_DEPTH, False)):
                path.write_text('{"extra":' + '[' * depth + '0' + ']' * depth + '}')
                value, _ = summary.load(root, path.name)
                self.assertEqual(value is not None, accepted)
