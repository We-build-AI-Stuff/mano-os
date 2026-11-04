"""Validate retained enforcement witnesses; never perform native memory operations.

This validates a bounded report, not its provenance. The caller must bind the
fixed native source/binary, enforcing profile and actual generation command.
No report here grants full runtime closure or publication authority.
"""
import json

MAPPINGS = frozenset(('baseline_read', 'baseline_exec', 'temporary_read',
    'temporary_exec', 'temporary_write_exec', 'anonymous_write_exec', 'anonymous_to_exec'))
POSITIVES = frozenset(('baseline_read', 'baseline_exec', 'temporary_read'))
SYSCALLS = frozenset(('baseline_write_exec', 'anonymous_exec', 'pkey_to_exec',
    'personality', 'memfd_create', 'shmget', 'shmat', 'userfaultfd', 'uselib'))
CONTEXT = 'mano-man-cache-execmem (enforce)'


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate executable-memory witness field')
        result[key] = value
    return result


def outcome(value, *, allowed, errors):
    if (type(value) is not dict or set(value) != {'allowed', 'errno'}
            or value['allowed'] is not allowed or type(value['errno']) is not int
            or value['errno'] not in errors):
        raise ValueError('Exact memory positive or explicit permission denial required')


def inspect(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 3072:
        raise ValueError('Bounded retained executable-memory witness required')
    value = json.loads(raw, object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != {'profile', 'apparmor_context',
            'diagnostic_mapping_bytes_executed', 'before', 'after', 'syscalls',
            'child_exec_inheritance_verified', 'complete_runtime_closure_verified',
            'publication_authorized'}
            or value['profile'] != 'man-execmem-enforcement-v1'
            or value['apparmor_context'] != CONTEXT
            or value['child_exec_inheritance_verified'] is not True
            or any(value[key] is not False for key in (
                'diagnostic_mapping_bytes_executed', 'complete_runtime_closure_verified',
                'publication_authorized'))):
        raise ValueError('Exact enforced manual-memory witness required')
    for stage in ('before', 'after'):
        mappings = value[stage]
        if type(mappings) is not dict or set(mappings) != MAPPINGS:
            raise ValueError('Seven complete memory observations per stage required')
        for name in MAPPINGS:
            allowed = name in POSITIVES or (stage == 'before' and name in {
                'anonymous_write_exec', 'anonymous_to_exec'})
            errors = {0} if allowed else ({1, 13} if stage == 'before'
                                         or name == 'temporary_exec' else {1})
            outcome(mappings[name], allowed=allowed, errors=errors)
    if type(value['syscalls']) is not dict or set(value['syscalls']) != SYSCALLS:
        raise ValueError('Complete alternate memory-route denials required')
    for result in value['syscalls'].values():
        outcome(result, allowed=False, errors={1})
    return value
