"""Parse bounded native executable-mapping diagnostics, never execute bytes.

The caller must bind the actual helper source/binary and confined launch. These
seven paired observations are measurements, not complete runtime authority.
"""
import hashlib
import json
import re

CASES = {'baseline_read', 'baseline_exec', 'temporary_read', 'temporary_exec',
         'temporary_write_exec', 'anonymous_write_exec', 'anonymous_to_exec'}


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate native mapping diagnostic field')
        value[key] = item
    return value


def inspect(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 4096:
        raise ValueError('Bounded retained mapping diagnostic bytes required')
    value = json.loads(raw, object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != {
            'profile', 'landlock_abi', 'kernel_release', 'uid', 'gid',
            'temporary_exec_before_allowed',
            'temporary_exec_after_denied', 'diagnostic_mapping_bytes_executed', 'before', 'after',
            'complete_runtime_closure_verified', 'publication_authorized'}
            or value['profile'] != 'man-cache-mapping-controls-v1'
            or type(value['landlock_abi']) is not int or not 5 <= value['landlock_abi'] <= 4096
            or type(value['kernel_release']) is not str
            or re.fullmatch('[A-Za-z0-9_.+\u002d]{1,128}', value['kernel_release']) is None
            or type(value['uid']) is not int or value['uid'] != 6
            or type(value['gid']) is not int or value['gid'] != 12
            or value['temporary_exec_before_allowed'] is not True
            or value['temporary_exec_after_denied'] is not True
            or any(value[key] is not False for key in (
                'diagnostic_mapping_bytes_executed', 'complete_runtime_closure_verified',
                'publication_authorized'))):
        raise ValueError('Exact native mapping control schema required')
    for stage in ('before', 'after'):
        if type(value[stage]) is not dict or set(value[stage]) != CASES:
            raise ValueError('Seven complete mapping controls per stage required')
        for name, result in value[stage].items():
            if (type(result) is not dict or set(result) != {'allowed', 'errno'}
                    or type(result['allowed']) is not bool or type(result['errno']) is not int
                    or (result['errno'] != 0 if result['allowed'] else
                        result['errno'] not in {1, 13})):
                raise ValueError('Mapping success or explicit permission denial required')
            if (name in {'baseline_read', 'baseline_exec', 'temporary_read'}
                    and not result['allowed']):
                raise ValueError('Read/baseline-code positive mapping controls must succeed')
    after = value['after']
    return dict(profile='man-executable-mapping-observation-v1',
        raw_sha256=hashlib.sha256(raw).hexdigest(), raw_bytes=len(raw),
        landlock_abi=value['landlock_abi'], kernel_release=value['kernel_release'],
        cases_per_stage=7, stages=2,
        temporary_launch_denied_but_rx_mapping_allowed=after['temporary_exec']['allowed'],
        temporary_private_write_exec_mapping_allowed=after['temporary_write_exec']['allowed'],
        anonymous_write_exec_mapping_allowed=after['anonymous_write_exec']['allowed'],
        anonymous_rw_to_rx_allowed=after['anonymous_to_exec']['allowed'],
        before=value['before'], after=after, diagnostic_mapping_bytes_executed=False,
        complete_runtime_closure_verified=False, loader_selection_verified=False,
        generated_state_validated=False, changes_authorized=False,
        publication_authorized=False)
