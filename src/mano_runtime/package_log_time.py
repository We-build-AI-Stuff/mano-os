"""Bind UTC log timestamps to the trusted controller's execution observations.

Caller custody must prove the fixed worker TZ=UTC0 environment and these actual
controller samples. This validates containment and clock consistency, not an
external time authority, package consent, or maintainer-script effects.
"""
import datetime
import re

from mano_runtime.package_log_decode import decode_append

NANOSECOND = 10**9
MAX_RUNTIME_NS = 60 * NANOSECOND
MAX_CLOCK_DRIFT_NS = 2 * NANOSECOND
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
FIELDS = {'realtime_before_ns', 'realtime_after_ns', 'monotonic_before_ns',
          'monotonic_after_ns', 'boot_id_before', 'boot_id_after', 'worker_timezone'}


def bind_controller_window(before, after, samples):
    if not isinstance(samples, dict) or set(samples) != FIELDS:
        raise ValueError('Exact controller clock sample fields required')
    for name in ('realtime_before_ns', 'realtime_after_ns',
                 'monotonic_before_ns', 'monotonic_after_ns'):
        if type(samples[name]) is not int or not 0 < samples[name] < 2**63:
            raise ValueError('Positive bounded actual nanosecond clock samples required')
    boot = samples['boot_id_before']
    if (not isinstance(boot, str) or not UUID.fullmatch(boot)
            or boot != samples['boot_id_after'] or samples['worker_timezone'] != 'UTC0'):
        raise ValueError('Same boot and fixed worker UTC0 timezone required')
    elapsed = samples['monotonic_after_ns'] - samples['monotonic_before_ns']
    wall_elapsed = samples['realtime_after_ns'] - samples['realtime_before_ns']
    if (not 0 <= elapsed <= MAX_RUNTIME_NS or not 0 <= wall_elapsed <= MAX_RUNTIME_NS
            or abs(wall_elapsed - elapsed) > MAX_CLOCK_DRIFT_NS):
        raise ValueError('Bounded consistent controller clock interval required')
    report = decode_append(before, after)
    if not report['event_frames_decoded'] or not report['events']:
        raise ValueError('Preserved prefix and nonempty event frames required')
    first = samples['realtime_before_ns'] // NANOSECOND
    last = samples['realtime_after_ns'] // NANOSECOND
    previous = first
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC)
    for event in report['events']:
        stamp = datetime.datetime.strptime(event['local_timestamp'], '%Y-%m-%d %H:%M:%S')
        delta = stamp.replace(tzinfo=datetime.UTC) - epoch
        seconds = delta.days * 86400 + delta.seconds
        if not first <= seconds <= last or seconds < previous:
            raise ValueError('UTC event timestamp outside controller interval or decreasing')
        previous = seconds
    return dict(schema_version='1.0', events=report['decoded_events'],
                before_log_sha256=report['before_sha256'], after_log_sha256=report['after_sha256'],
                elapsed_monotonic_ns=elapsed, elapsed_realtime_ns=wall_elapsed,
                worker_timezone='UTC0', timestamp_timezone_verified=True,
                time_window_verified=True, controller_clock_consistency_verified=True,
                external_time_authority_verified=False, trigger_authority_verified=False,
                log_change_accounted=False, changes_authorized=False, publication_authorized=False)
