#!/usr/bin/env python3
"""Render existing CI observations for readers; never certify a phase or merge."""
import argparse
import hashlib
import json
import math
import re
from pathlib import Path

MAX_REPORT_BYTES = 2 * 1024**2
MAX_REPORT_DEPTH = 64


def load(directory, name):
    path = directory / name
    try:
        with path.open('rb') as source:
            raw = source.read(MAX_REPORT_BYTES+1)
        if len(raw) > MAX_REPORT_BYTES:
            return None, 'oversized report'
        def pairs(values):
            result = {}
            for key, value in values:
                if key in result:
                    raise ValueError('Duplicate report key')
                result[key] = value
            return result
        def nonfinite(_):
            raise ValueError('Nonfinite report value')
        def finite_float(token):
            number = float(token)
            if not math.isfinite(number):
                raise ValueError('Nonfinite report number')
            return number
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite,
                           parse_float=finite_float)
        if type(value) is not dict:
            return None, 'invalid report object'
        pending = [(value, 1)]
        while pending:
            node, depth = pending.pop()
            if depth > MAX_REPORT_DEPTH:
                return None, 'report nesting limit exceeded'
            children = node.values() if isinstance(node, dict) else node
            pending.extend((child, depth + 1) for child in children
                           if isinstance(child, (dict, list)))
        return value, hashlib.sha256(raw).hexdigest()
    except FileNotFoundError:
        return None, 'not collected'
    except (OSError, ValueError, UnicodeError, RecursionError):
        return None, 'unreadable or invalid report'


def reported(value, names):
    return type(value) is dict and all(value.get(name) is True for name in names)


def website_reported(report):
    """Require the build, test, and browser observations in the stock VM report."""
    if not reported(report, ('changed_page_denied', 'descendants_drained')):
        return False
    website, status, screenshot = (report.get(key) for key in ('website', 'status', 'screenshot'))
    if any(type(value) is not dict for value in (website, status, screenshot)):
        return False
    browser = status.get('browser')
    actions = website.get('actions')
    if not reported(browser, ('local_pipe', 'renderer_filters_verified')):
        return False
    if type(actions) is not dict or set(actions) != {'build', 'test'}:
        return False
    action_ids = [report.get('action_id')]
    for step in ('build', 'test'):
        action = actions[step]
        if type(action) is not dict or type(action.get('output')) is not dict:
            return False
        output = action['output']
        if (type(output.get('return_code')) is not int or output['return_code'] != 0
                or output.get('reason') != 'completed'
                or output.get('action_id') != action.get('action_id')):
            return False
        action_ids.append(action.get('action_id'))
    return (all(type(value) is str and re.fullmatch('[a-f0-9]{32}', value) for value in action_ids)
            and len(set(action_ids)) == 3
            and all(type(value) is str and re.fullmatch('[a-f0-9]{64}', value)
                    for value in (website.get('html_sha256'), screenshot.get('sha256')))
            and report.get('locator_text') == '42')


def render(directory, revision):
    if not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Exact Git revision required')
    names = ('architecture-audit.json', 'broker-service.json', 'runtime-package.json',
             'stock-runtime-reboot.json', 'stock-private-browser.json')
    reports = {name: load(directory, name) for name in names}
    architecture, broker, package, reboot, website = [reports[name][0] for name in names]
    terminal = broker.get('terminal_execution') if broker else None
    workflow = (terminal.get('recorded_developer_workflow_witness')
                if type(terminal) is dict else None)
    recorded = (reported(terminal, (
        'recorded_developer_create_fail_fix_pass_exact_artifact',
        'recorded_developer_checkpoint_replay_no_model_disclosure',
        'recorded_developer_native_stop_restart_no_follow_on_effect'))
        and type(workflow) is dict and workflow.get('status') == 'verified'
        and workflow.get('provider_disclosure') is False
        and workflow.get('replay_no_effect') is True
        and type(workflow.get('native_pam_approvals')) is int
        and workflow['native_pam_approvals'] == 4)
    rows = [
        ('Phase 0 architecture', architecture is not None
         and architecture.get('decision') == 'go-for-phase1-development'
         and architecture.get('production_execution_authorized') is False,
         'Lab GO for Phase 1 development; production and physical acceptance separate'),
        ('Workspace create / failing test / fix / passing test', recorded,
         'Recorded plans, four native approvals and exact-file snapshot; no live-model claim'),
        ('Website build, test, and private Chromium verification', website_reported(website),
         'Stock Debian with native approvals and a sandboxed browser'),
        ('Protected policy boundary', reported(terminal, (
            'full_workspace_profile_protected_policy_kernel_denial',)),
         'OS-boundary negative fixture'),
        ('Independent Stop with frozen services', reported(terminal, (
            'native_stop_broker_and_launcher_frozen', 'native_stop_task_cgroup_drained',
            'native_stop_grant_latch_integrated')),
         'Native VM fixture; physical trigger remains unmeasured'),
        ('Runtime install / reinstall / removal', reported(package, (
            'services_inactive_on_install', 'policy_data_preserved_on_reinstall',
            'package_removed_services_stopped_data_preserved')),
         'Unsigned prototype package'),
        ('Clean Debian reboot and old-grant rejection', reported(reboot, (
            'runtime_started_on_boot_without_setup', 'old_grant_replay_denied',
            'previous_workspace_data_preserved')),
         'Installed mock workflow; no full OS-image acceptance'),
    ]
    lines = ['# mano-OS delivery observations', '', f'Tested revision: `{revision}`.', '',
        'This summarizes existing fixture reports from this run. Reported results are not',
        'an independent evidence audit, phase completion, live-AI success or release approval.', '',
        '| Journey | Report state | Scope |', '| --- | --- | --- |']
    for label, passed, scope in rows:
        state = 'Reported by fixture' if passed else 'Not established in collected reports'
        lines.append(f'| {label} | {state} | {scope} |')
    lines += ['', 'The full v2.1 release, integrated live-model MVP, authenticated coding',
        'delegates, physical 8 GB performance and signed OS installation remain separate',
        'acceptance gates. See `docs/DELIVERY.md` for the original requirements',
        'and next milestone.',
        '', '## Source reports', '', '| File | SHA-256 or collection state |', '| --- | --- |']
    for name in names:
        lines.append(f'| `{name}` | `{reports[name][1]}` |')
    lines += ['', 'Missing, partial or malformed evidence is shown as not established.',
        'This renderer changes no probe result, required check or merge decision.', '']
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = render(args.evidence, args.revision)
    if args.output:
        with args.output.open('a') as output:
            output.write(result)
    else:
        print(result)


if __name__ == '__main__':
    main()
