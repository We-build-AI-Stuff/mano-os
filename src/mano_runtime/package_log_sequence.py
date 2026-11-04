"""Check the supported new-install state sequences, never grant mutation authority.

This fixed profile requires one archives/install run, one unpack/configure cycle
per approved new package and settled trigger cycles. Dependency order, actual
trigger arguments, wall-clock provenance and script effects are separate gates.
"""
from mano_runtime.package_log_decode import decode_append
from mano_runtime.package_log_scope import inspect
from mano_runtime.package_postconditions import database_records


def require_sequence(before_log, after_log, before_status, after_status, records):
    scope = inspect(before_log, after_log, before_status, after_status, records)
    events = decode_append(before_log, after_log)['events']
    if not events or events[0]['event'] != 'startup':
        raise ValueError('One initial new-install startup required')
    old, new = database_records(before_status), database_records(after_status)
    identities = old.keys() | new.keys()
    by_name = {}
    for key in identities:
        by_name.setdefault(key[0], []).append(key)
    planned = {(r['name'], r['architecture']) for r in records}
    phase = {key: 'absent' for key in planned}
    pending, cycles, active = set(), {}, None
    previous = events[0]['local_timestamp']
    for event in events[1:]:
        stamp = event['local_timestamp']
        if stamp < previous:
            raise ValueError('Log timestamps moved backward')
        previous = stamp
        if event['event'] == 'startup':
            raise ValueError('Multiple startup runs require separate transaction policy')
        label = event['package']
        key = tuple(label.split(':')) if ':' in label else by_name[label][0]
        current = phase.get(key, 'installed')
        kind, state = event['event'], event.get('state')
        if kind == 'status' and state == 'triggers-pending':
            if current == 'absent':
                raise ValueError('New package interest before package installation')
            pending.add(key)
            continue
        if kind in {'install', 'configure', 'trigproc'}:
            if active is not None:
                raise ValueError('Overlapping package actions are outside the supported profile')
            if kind == 'install' and key in planned and current == 'absent':
                phase[key] = 'installing'
            elif kind == 'configure' and key in planned and current == 'unpacked':
                phase[key] = 'configuring'
            elif kind == 'trigproc' and current == 'installed' and key in pending:
                phase[key] = 'triggering'
                pending.remove(key)
                cycles[key] = cycles.get(key, 0) + 1
            else:
                raise ValueError('Package action conflicts with observed state sequence')
            active = key
            continue
        if kind != 'status' or active != key:
            raise ValueError('Package status lacks its preceding supported action')
        transition = {
            ('installing', 'half-installed'): 'half-installed',
            ('half-installed', 'unpacked'): 'unpacked',
            ('configuring', 'half-configured'): 'half-configured',
            ('half-configured', 'installed'): 'installed',
            ('triggering', 'half-configured'): 'trigger-half-configured',
            ('trigger-half-configured', 'installed'): 'installed',
        }.get((current, state))
        if transition is None:
            raise ValueError('Unsupported package status transition')
        phase[key] = transition
        if transition in {'unpacked', 'installed'}:
            active = None
    if active is not None or pending or any(phase.get(key) != 'installed' for key in planned):
        raise ValueError('Package event sequence did not settle')
    return dict(schema_version='1.0', profile='new-install-unpack-configure-settled-triggers-v1',
                events=scope['decoded_events'], new_packages=len(planned),
                trigger_cycles=sum(cycles.values()), supported_state_sequences_verified=True,
                timestamp_order_nondecreasing=True, timestamp_timezone_verified=False,
                time_window_verified=False, dependency_order_verified=False,
                actual_trigger_arguments_verified=False, trigger_authority_verified=False,
                log_change_accounted=False, changes_authorized=False, publication_authorized=False)
