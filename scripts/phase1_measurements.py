"""Publish scoped fixture measurements, never infer whole-phase acceptance."""

import argparse
import hashlib
import json
import math
import re
from pathlib import Path

from delivery_summary import load
from runtime_memory import MAX_SAMPLES, summarize

DENIAL_CASES = {
    (actor, target)
    for target, actors in {
        'request-socket': ('mano-agent', 'mano-core', 'mano-human'),
        'control-socket': ('mano-agent', 'mano-core', 'mano-worker', 'mano-human'),
        'provision-socket': ('mano-agent', 'mano-core', 'mano-worker', 'mano-human'),
        'private-journal': ('mano-agent', 'mano-core', 'mano-worker'),
    }.items() for actor in actors
}


def identifier(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{32}', value) is not None


def duration(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def workflow(broker, manifest):
    if not isinstance(broker, dict) or not isinstance(manifest, dict):
        return None
    terminal = broker.get('terminal_execution', {})
    if not isinstance(terminal, dict):
        return None
    witness = terminal.get('recorded_developer_workflow_witness', {})
    if not isinstance(witness, dict):
        return None
    ids = manifest.get('approval_ids')
    observations = manifest.get('observations')
    if (not all(identifier(manifest.get(k)) for k in ('task_id', 'workflow_id', 'artifact_id'))
            or not isinstance(ids, list) or len(ids) != 4 or not all(map(identifier, ids))
            or len(set(ids)) != 4 or type(manifest.get('native_pam_approvals')) is not int
            or manifest['native_pam_approvals'] != 4
            or manifest.get('provider_disclosure') is not False
            or manifest.get('live_model_success') is not None
            or not isinstance(observations, list) or len(observations) != 4
            or witness.get('id') != manifest['workflow_id']
            or witness.get('artifact_id') != manifest['artifact_id']
            or witness.get('observations') != observations
            or witness.get('status') != 'verified' or witness.get('replay_no_effect') is not True
            or type(witness.get('native_pam_approvals')) is not int
            or witness['native_pam_approvals'] != 4
            or witness.get('provider_disclosure') is not False
            or not duration(manifest.get('elapsed_seconds'))
            or not all(terminal.get(k) is True for k in (
                'recorded_developer_create_fail_fix_pass_exact_artifact',
                'recorded_developer_checkpoint_replay_no_model_disclosure',
                'recorded_developer_native_stop_restart_no_follow_on_effect'))):
        return None
    try:
        if len({item['action_id'] for item in observations}) != 4:
            return None
        for index, code in ((1, 1), (3, 0)):
            output = observations[index]['output']
            if (type(output['return_code']) is not int or output['return_code'] != code
                    or output['task_id'] != manifest['task_id']
                    or output['action_id'] != observations[index]['action_id']):
                return None
        artifact = manifest['artifact']
        if (artifact['task_id'] != manifest['task_id']
                or artifact['artifact_id'] != manifest['artifact_id']
                or artifact['action_id'] != observations[3]['action_id']
                or artifact['sha256'] != manifest['files']['workflow_answer.py']['sha256']):
            return None
    except (KeyError, TypeError):
        return None
    return dict(scope='one recorded create/fail/fix/pass workflow; not a phase-wide task rate',
        trials=1, verified=1, verified_fraction=1.0, task_id=manifest['task_id'],
        workflow_id=manifest['workflow_id'], artifact_id=manifest['artifact_id'],
        elapsed_seconds=manifest['elapsed_seconds'],
        native_pam_interventions=4, interventions_per_workflow=4.0,
        intervention_scope='four effect approvals; excludes setup and other fixtures',
        provider_disclosure=False, live_model_success=None,
        model_cost_usd=None, task_cost_usd=None, cost_reason='billing was not collected')


def policy_denials(broker):
    cases = broker.get('kernel_denials') if isinstance(broker, dict) else None
    if not isinstance(cases, list) or len(cases) != len(DENIAL_CASES):
        return None
    keys = []
    for case in cases:
        if (not isinstance(case, dict) or set(case) != {'actor', 'target', 'kernel_errno'}
                or not isinstance(case['actor'], str) or not isinstance(case['target'], str)
                or case['kernel_errno'] != 'EACCES'):
            return None  # An unexpected/missing result is not evidence of zero bypasses.
        keys.append((case['actor'], case['target']))
    if len(set(keys)) != len(keys) or set(keys) != DENIAL_CASES:
        return None
    return dict(scope='fixed socket/journal access cohort; not all policy attacks',
        attempted=len(cases), denied=len(cases), bypasses=0, bypass_fraction=0.0,
        cases=cases)


def oom_measurement(broker):
    terminal = broker.get('terminal_execution') if isinstance(broker, dict) else None
    value = terminal.get('installed_runtime_oom') if isinstance(terminal, dict) else None
    if not isinstance(value, dict):
        return None
    try:
        outcome = value['oom_outcome']
        before, after = value['memory_events_before'], value['memory_events_after']
        output = value['follow_up_output']
        approvals = value['native_pam_approval_ids']
        if (outcome['state'] != 'unknown' or outcome['exit_code'] is not None
                or type(outcome['verified']) is not int or outcome['verified'] != 0
                or outcome['id'] != value['oom_action_id']
                or outcome['task_id'] != value['task_id']
                or value['replay_no_execution'] is not True
                or value['no_terminal_output_fabricated'] is not True
                or value['service_restart'] is not False
                or value['services_before'] != value['services_after']
                or not value['services_before']
                or type(value['trials']) is not int or value['trials'] != 1
                or value['physical_hardware'] is not False
                or value['model_disclosure'] is not False
                or value['full_human_desktop_responsiveness'] is not None
                or not all(identifier(value[k]) for k in ('task_id', 'oom_action_id',
                                                          'follow_action_id'))
                or value['oom_action_id'] == value['follow_action_id']
                or output['task_id'] != value['task_id']
                or output['action_id'] != value['follow_action_id']
                or output['reason'] != 'completed' or output['effect_verified'] is not False
                or output['output_limit_reached'] is not False
                or type(output['return_code']) is not int or output['return_code'] != 0
                or type(output['streams']['stderr']['size']) is not int
                or output['streams']['stderr']['size'] != 0
                or not isinstance(approvals, list) or len(approvals) != 2
                or not all(map(identifier, approvals))
                or len(set(approvals)) != 2):
            return None
        for key in ('oom', 'oom_kill'):
            if type(before[key]) is not int or type(after[key]) is not int:
                return None
            if not 0 <= before[key] < after[key]:
                return None
        expected_services = {'mano-broker.service', 'mano-launcher.service',
                             'mano-approve.service', 'mano-stopd.service'}
        if set(value['services_before']) != expected_services:
            return None
        for service in value['services_before'].values():
            if (set(service) != {'pid', 'start_ticks', 'restarts'}
                    or any(type(service[k]) is not int or service[k] < 0 for k in service)
                    or service['pid'] == 0):
                return None
        raw = value['follow_up_stdout'].encode()
        if (not re.fullmatch(rb'[0-9a-f]{32}\n', raw)
                or type(output['streams']['stdout']['size']) is not int
                or len(raw) != output['streams']['stdout']['size']
                or hashlib.sha256(raw).hexdigest() != output['streams']['stdout']['sha256']):
            return None
        for key in ('first_kernel_oom_observed_seconds', 'post_oom_readiness_verified_seconds',
                    'approved_follow_up_complete_seconds'):
            if not duration(value[key]):
                return None
        if (value['approved_follow_up_complete_seconds']
                < value['post_oom_readiness_verified_seconds']):
            return None
        return value
    except (KeyError, TypeError, AttributeError, UnicodeError):
        return None


def collect(directory, revision):
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('Exact tested revision required')
    names = ('broker-service.json', 'developer-project/manifest.json',
             'developer-project/runtime-memory.json')
    reports = {name: load(directory, name) for name in names}
    broker, manifest, memory = (reports[name][0] for name in names)
    selected = workflow(broker, manifest)
    same_revision = isinstance(manifest, dict) and manifest.get('revision') == revision
    if not same_revision:
        selected = None
    ram = None
    if selected is not None and isinstance(memory, dict):
        try:
            summary = memory['summary']
            idle, samples = memory['idle_samples'], memory['workflow_samples']
            if (len(idle) == 10 and 2 <= len(samples) <= MAX_SAMPLES
                    and summary == summarize(idle, samples, summary['component_kernel_peak_bytes'])
                    and manifest.get('runtime_memory') == summary
                    == broker['terminal_execution'].get('recorded_developer_runtime_memory')):
                ram = summary
        except (KeyError, TypeError, ValueError):
            pass
    return dict(schema_version='1.0', revision=revision,
        scope='reported selected Phase 1 fixture cohorts in this CI run',
        sources={name: state for name, (_, state) in reports.items()},
        recorded_workflow=selected,
        socket_journal_denials=policy_denials(broker) if same_revision else None,
        runtime_memory=ram,
        installed_runtime_oom=oom_measurement(broker) if same_revision else None,
        phase_wide_task_success_fraction=None, phase_wide_policy_bypass_fraction=None,
        phase_wide_regression_count=None, full_phase_accepted=False,
        limitations=['selected cohorts, not a complete predefined phase-wide benchmark',
                     'fixture reports and hashes are not an independent security audit',
                     'missing/partial/invalid observations stay null',
                     'billing and quality-job regression data are not collected here',
                     'no physical input or physical 8 GB acceptance'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(collect(args.evidence, args.revision), indent=2) + '\n')


if __name__ == '__main__':
    main()
