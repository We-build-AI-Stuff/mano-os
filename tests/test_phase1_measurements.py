import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
SPEC = importlib.util.spec_from_file_location('phase1_measurements',
                                             SCRIPTS / 'phase1_measurements.py')
metrics = importlib.util.module_from_spec(SPEC)
with patch.object(sys, 'path', [str(SCRIPTS), *sys.path]):
    SPEC.loader.exec_module(metrics)


def fixture():
    task, workflow, artifact = 'a'*32, 'b'*32, 'c'*32
    observations = [dict(action_id=str(n)*32) for n in range(1, 5)]
    for index, code in ((1, 1), (3, 0)):
        observations[index]['output'] = dict(return_code=code, task_id=task,
                                             action_id=observations[index]['action_id'])
    manifest = dict(task_id=task, workflow_id=workflow, artifact_id=artifact,
        approval_ids=[str(n)*32 for n in range(5, 9)], native_pam_approvals=4,
        provider_disclosure=False, live_model_success=None, observations=observations,
        elapsed_seconds=12.5, artifact=dict(task_id=task, artifact_id=artifact,
            action_id='4'*32, sha256='d'*64),
        files={'workflow_answer.py': dict(sha256='d'*64)}, revision='e'*40)
    witness = dict(id=workflow, artifact_id=artifact, observations=copy.deepcopy(observations),
        status='verified', replay_no_effect=True, native_pam_approvals=4,
        provider_disclosure=False)
    terminal = dict(recorded_developer_workflow_witness=witness,
        recorded_developer_create_fail_fix_pass_exact_artifact=True,
        recorded_developer_checkpoint_replay_no_model_disclosure=True,
        recorded_developer_native_stop_restart_no_follow_on_effect=True)
    return dict(terminal_execution=terminal), manifest


class Phase1MeasurementsTests(unittest.TestCase):
    def test_missing_partial_invalid_and_stale_reports_are_unknown_not_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for raw in (None, '{"kernel_denials":[]}', '{"value":NaN}'):
                if raw is not None:
                    (root / 'broker-service.json').write_text(raw)
                report = metrics.collect(root, 'e'*40)
                for key in ('recorded_workflow', 'socket_journal_denials', 'runtime_memory',
                            'installed_runtime_oom', 'phase_wide_regression_count'):
                    self.assertIsNone(report[key])
                self.assertFalse(report['full_phase_accepted'])
            broker, manifest = fixture()
            (root / 'broker-service.json').write_text(json.dumps(broker))
            (root / 'developer-project').mkdir()
            (root / 'developer-project/manifest.json').write_text(json.dumps(manifest))
            self.assertIsNone(metrics.collect(root, 'f'*40)['recorded_workflow'])

    def test_denial_rate_requires_all_fourteen_distinct_expected_cases(self):
        cases = [dict(actor=actor, target=target, kernel_errno='EACCES')
                 for actor, target in sorted(metrics.DENIAL_CASES)]
        value = metrics.policy_denials(dict(kernel_denials=cases))
        self.assertEqual((value['attempted'], value['bypasses']), (14, 0))
        for changed in (cases[:-1], cases[:-1] + [cases[0]],
                        cases[:-1] + [cases[-1] | dict(kernel_errno='ENOENT')]):
            self.assertIsNone(metrics.policy_denials(dict(kernel_denials=changed)))

    def test_workflow_count_requires_bound_observations_and_four_unique_approvals(self):
        broker, manifest = fixture()
        value = metrics.workflow(broker, manifest)
        self.assertEqual((value['verified'], value['trials']), (1, 1))
        self.assertEqual(value['native_pam_interventions'], 4)
        self.assertIsNone(value['model_cost_usd'])
        for change in (dict(native_pam_approvals=4.0), dict(elapsed_seconds=float('nan')),
                       dict(approval_ids=['5'*32]*4), dict(artifact_id='f'*32)):
            self.assertIsNone(metrics.workflow(broker, manifest | change))
        changed = copy.deepcopy(broker)
        changed['terminal_execution']['recorded_developer_create_fail_fix_pass_exact_artifact'] = 1
        self.assertIsNone(metrics.workflow(changed, manifest))
        self.assertIsNone(metrics.workflow(dict(terminal_execution=[]), manifest))

    def test_missing_or_incomplete_oom_cannot_become_recovery_acceptance(self):
        self.assertIsNone(metrics.oom_measurement({}))
        self.assertIsNone(metrics.oom_measurement(dict(terminal_execution=dict(
            installed_runtime_oom=dict(trials=1, service_restart=False)))))
