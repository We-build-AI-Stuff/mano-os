"""Require declaration support for log references; never approve script effects.

Inputs must retain authenticated archive custody. A supported activation is not
proof of which trigger dpkg passed to postinst, nor authority to execute it.
File interests match lexical package paths, never resolved symlink destinations.
"""
import base64
import hashlib
from bisect import bisect_left

from mano_runtime.package_candidate_policy import validate_payloads
from mano_runtime.package_control import validate_new
from mano_runtime.package_log_scope import inspect
from mano_runtime.package_trigger_declarations import MAX_BYTES, baseline_sources, decode

MAX_LINKS = 4096


def archive_declarations(control):
    entry = control['inventory']['entries'].get('triggers')
    encoded = control['trigger_data_base64']
    if entry is None:
        if encoded is not None:
            raise ValueError('Absent archive trigger member must have absent bytes')
        return decode(b'')['declarations']
    if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_BYTES + 2) // 3):
        raise ValueError('Bounded encoded archive trigger bytes required')
    data = base64.b64decode(encoded, validate=True)
    if (entry['kind'] != 'file' or type(entry['bytes']) is not int
            or len(data) != entry['bytes']
            or hashlib.sha256(data).hexdigest() != entry['sha256']):
        raise ValueError('Archive trigger bytes differ from authenticated inventory')
    return decode(data)['declarations']


def file_witness(trigger, paths):
    """Find one exact/descendant lexical path in a sorted authenticated inventory."""
    index = bisect_left(paths, trigger)
    if index < len(paths) and paths[index] == trigger:
        return paths[index]
    prefix = trigger.rstrip('/') + '/'
    index = bisect_left(paths, prefix)
    if index < len(paths) and paths[index].startswith(prefix):
        return paths[index]
    return None


def require_sources(before_log, after_log, before_status, after_status,
                    baseline, candidate, records, observations, read):
    """Recompute necessary gates and reject references without supported sources.

    No caller-supplied decoded declarations, scope reports or acceptance booleans
    are trusted. Explicit dpkg-trigger calls and dynamic activations need separate
    evidence and cannot satisfy this fixed new-install guard.
    """
    scope = inspect(before_log, after_log, before_status, after_status, records)
    names = {r['name'] for r in records}
    if len(names) != len(records) or names != set(observations):
        raise ValueError('Exact authenticated archive observation set required')
    payloads = {name: item['payload'] for name, item in observations.items()}
    validate_payloads(baseline, candidate, payloads)
    validate_new(before_status, after_status, candidate, records, observations)
    declarations, activations, paths = {}, {}, {}
    for record in records:
        name, arch = record['name'], record['architecture']
        rows = archive_declarations(observations[name]['control'])
        declarations[(name, arch)] = rows
        paths[name] = sorted('/' + p for p in payloads[name]['entries'] if p != '.')
        for row in rows:
            if row['directive'].startswith('activate'):
                activations.setdefault(row['trigger'], []).append(
                    dict(package=name, architecture=arch, directive=row['directive']))
    sources = baseline_sources(before_status, baseline,
                               scope['referenced_trigger_packages'], read)
    links = []
    for source in sources['sources']:
        ref = source['package']
        identity = ref['name'], ref['architecture']
        if identity in declarations:
            interests = declarations[identity]
            origin = 'authenticated-new-control'
        elif source['baseline_available']:
            interests = source['observation']['declarations']
            origin = 'bound-baseline-control'
        else:
            raise ValueError('Trigger reference has no available declaration source')
        matched = False
        for interest in interests:
            if not interest['directive'].startswith('interest'):
                continue
            trigger = interest['trigger']
            witness = None
            if trigger in activations:
                witness = dict(kind='declared-activation', **activations[trigger][0])
            elif interest['kind'] == 'file':
                for package, entries in paths.items():
                    path = file_witness(trigger, entries)
                    if path is not None:
                        witness = dict(kind='lexical-payload-path', package=package, path=path)
                        break
            if witness is not None:
                if len(links) >= MAX_LINKS:
                    raise ValueError('Trigger declaration linkage budget')
                links.append(dict(package=ref, declaration_origin=origin,
                                  interest=interest, activation=witness))
                matched = True
        if not matched:
            raise ValueError('Trigger reference lacks an approved-closure activation source')
    return dict(schema_version='1.0', referenced_packages=len(sources['sources']),
                declaration_activation_links=links, declaration_sources_matched=True,
                actual_trigger_arguments_verified=False, trigger_authority_verified=False,
                sequence_policy_verified=False, maintainer_effects_verified=False,
                changes_authorized=False, publication_authorized=False)
