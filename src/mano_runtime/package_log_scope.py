"""Match decoded log identities/versions without approving triggers or ordering."""
from mano_runtime.package_log_decode import decode_append
from mano_runtime.package_postconditions import database_records


def inspect(before_log, after_log, before_status, after_status, records):
    decoded = decode_append(before_log, after_log)
    if not decoded['event_frames_decoded']:
        raise ValueError('Preserved log prefix required for event scope inspection')
    old, new = database_records(before_status), database_records(after_status)
    if not isinstance(records, list) or not 1 <= len(records) <= 8:
        raise ValueError('Bounded authenticated new-package records required')
    planned = {}
    for record in records:
        key = record['name'], record['architecture']
        if (key in planned or key in old or key not in new or
                (new[key]['status'], new[key]['version']) != (
                    'install ok installed', record['version'])):
            raise ValueError('Exact distinct settled new-package records required')
        planned[key] = record['version']
    if any(old.get(key) != new.get(key) for key in (old.keys() | new.keys()) - planned.keys()):
        raise ValueError('Unapproved package record changed')
    identities = old.keys() | new.keys()
    triggers, matched = set(), 0
    for event in decoded['events']:
        kind = event['event']
        if kind == 'startup':
            if (event['kind'], event['command']) != ('archives', 'install'):
                raise ValueError('Log startup differs from fixed new-install operation')
            continue
        if kind == 'conffile':
            raise ValueError('Conffile decisions require an approved conffile policy')
        label = event['package']
        if ':' in label:
            key = tuple(label.split(':'))
            if key not in identities:
                raise ValueError('Log package identity is absent from actual databases')
        else:
            candidates = [key for key in identities if key[0] == label]
            if len(candidates) != 1:
                raise ValueError('Unqualified log package identity is ambiguous or absent')
            key = candidates[0]
        if key in planned:
            version = planned[key]
            if kind == 'install':
                valid = (event['installed_version'], event['available_version']) == (
                    '<none>', version)
            elif kind == 'configure':
                valid = (event['installed_version'] == version
                         and event['available_version'] in {version, '<none>'})
            elif kind == 'status':
                valid = event['version'] == version or (
                    event['state'] == 'not-installed' and event['version'] == '<none>')
            elif kind == 'trigproc':
                valid = (event['installed_version'], event['available_version']) == (
                    version, '<none>')
                triggers.add(key)
            else:
                valid = False
            if not valid:
                raise ValueError('Log action/version differs from approved new-package scope')
        else:
            prior = old.get(key)
            if prior is None or prior['status'] != 'install ok installed' or new.get(key) != prior:
                raise ValueError('Trigger reference must name an unchanged installed package')
            version = prior['version']
            if kind == 'trigproc':
                valid = (event['installed_version'], event['available_version']) == (
                    version, '<none>')
            elif kind == 'status':
                valid = (event['version'] == version and event['state'] in {
                    'triggers-pending', 'triggers-awaited', 'half-configured', 'installed'})
            else:
                valid = False
            if not valid:
                raise ValueError('Unapproved non-trigger package action or version')
            triggers.add(key)
        matched += 1
    return dict(schema_version='1.0', before_log_sha256=decoded['before_sha256'],
                after_log_sha256=decoded['after_sha256'], package_identity_versions_matched=True,
                matched_package_events=matched, decoded_events=decoded['decoded_events'],
                referenced_trigger_packages=[dict(name=name, architecture=arch,
                                                  version=new[(name, arch)]['version'])
                                             for name, arch in sorted(triggers)],
                trigger_authority_verified=False, sequence_policy_verified=False,
                time_window_verified=False, log_semantics_verified=False,
                log_change_accounted=False, changes_authorized=False, publication_authorized=False)
