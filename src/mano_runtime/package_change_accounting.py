"""Account drained candidate changes from recomputed validations, never consent.

No caller-selected allowlist. Remaining changes prevent the strict entry point
from returning. Even a fully accounted content delta is not publication authority
or a proof of protected-runtime safety, custody, approval or confinement.
"""
import hashlib

from mano_runtime.package_candidate_policy import validate_payloads
from mano_runtime.package_control import validate_new
from mano_runtime.package_database_files import bind
from mano_runtime.package_lists import observe
from mano_runtime.package_tree import delta

TIMES = {'mtime_ns', 'ctime_ns'}
LOCKS = {'var/lib/dpkg/lock', 'var/lib/dpkg/lock-frontend', 'var/lib/dpkg/triggers/Lock'}
UPDATES = 'var/lib/dpkg/updates'
EMPTY_SHA256 = hashlib.sha256(b'').hexdigest()


class UnaccountedChanges(ValueError):
    def __init__(self, paths):
        super().__init__('Candidate mutations remain unverified')
        self.paths = tuple(sorted(paths))


def without_times(row):
    return {k: v for k, v in row.items() if k not in TIMES}


def _account(baseline, candidate, payloads, control, lists, database):
    """Private classification using results recomputed by audit below."""
    changes = delta(baseline, candidate)['changes']
    verified = {}
    for payload in payloads.values():
        for path, row in payload['entries'].items():
            if path not in changes:
                continue
            before, after = changes[path]['before'], changes[path]['after']
            if row['kind'] != 'directory':
                verified[path] = 'authenticated-payload'
            elif before is None or without_times(before) == without_times(after):
                verified[path] = 'validated-payload-directory'
    for path in control['copied_control_paths_verified']:
        if path in changes:
            verified[path] = 'authenticated-control-info'
    for item in lists['packages'].values():
        if item['path'] in changes:
            verified[item['path']] = 'validated-generated-file-list'
    for path in database['verified_database_paths']:
        if path in changes:
            verified[path] = 'validated-database-file'
    for path in LOCKS & changes.keys():
        before, after = changes[path]['before'], changes[path]['after']
        if (before is not None and after is not None
                and without_times(before) == without_times(after)
                and before.get('kind') == 'file'
                and (before['uid'], before['gid'], before['nlink'], before['bytes']) == (0, 0, 1, 0)
                and before['mode'] in {0o600, 0o640, 0o644} and before['xattrs'] == {}
                and before['hardlink_anchor'] == path and before['sha256'] == EMPTY_SHA256):
            verified[path] = 'unchanged-empty-lock-timestamps'
    if UPDATES in changes:
        before, after = changes[UPDATES]['before'], changes[UPDATES]['after']
        if (before is not None and after is not None and before.get('kind') == 'directory'
                and without_times(before) == without_times(after)
                and (before['uid'], before['gid'], before['mode']) == (0, 0, 0o755)
                and before['xattrs'] == {} and all(not any(path.startswith(UPDATES + '/')
                    for path in tree['entries']) for tree in (baseline, candidate))):
            verified[UPDATES] = 'drained-empty-dpkg-updates-timestamps'
    parents = {path.rsplit('/', 1)[0] if '/' in path else '.' for path in verified}
    for path in parents & (changes.keys() - verified.keys()):
        before, after = changes[path]['before'], changes[path]['after']
        if (before is not None and after is not None and before.get('kind') == 'directory'
                and without_times(before) == without_times(after)):
            verified[path] = 'unchanged-parent-directory-timestamps'
    unresolved = {path: row for path, row in changes.items() if path not in verified}
    requirements = sorted(set(database['unresolved_backup_paths']) | {
        'control:' + package + '/' + member
        for package, members in control['unsupported_control_members'].items()
        for member in members})
    return dict(schema_version='1.0', before_sha256=baseline['manifest_sha256'],
                after_sha256=candidate['manifest_sha256'], accounted_changes=verified,
                unresolved_changes=unresolved, unresolved_requirements=requirements,
                changed_paths=len(changes),
                change_set_fully_accounted=not unresolved and not requirements,
                all_generated_state_validated=False, protected_runtime_policy_validated=False,
                candidate_filesystem_verified=False, changes_authorized=False,
                publication_authorized=False)


def audit(root_fd, before, after, baseline, candidate, records, observations, *, checkpoint=None):
    names = {record['name'] for record in records}
    if len(names) != len(records) or names != set(observations):
        raise ValueError('Exact authenticated package observation set required')
    payloads = {name: value['payload'] for name, value in observations.items()}
    payload = validate_payloads(baseline, candidate, payloads, checkpoint=checkpoint)
    control = validate_new(before, after, candidate, records, observations)
    database = bind(before, after, baseline, candidate, checkpoint=checkpoint)
    lists = observe(root_fd, candidate, records, observations, checkpoint=checkpoint)
    accounting = _account(baseline, candidate, payloads, control, lists, database)
    if checkpoint is not None:
        checkpoint()
    return dict(payload=payload, control=control, database=database, lists=lists,
                accounting=accounting)


def require_accounted(root_fd, before, after, baseline, candidate, records, observations,
                      *, checkpoint=None):
    """Recompute the fixed gates; never trust an externally supplied report."""
    result = audit(root_fd, before, after, baseline, candidate, records, observations,
                   checkpoint=checkpoint)
    unverified = (set(result['accounting']['unresolved_changes'])
                  | set(result['accounting']['unresolved_requirements']))
    if unverified:
        raise UnaccountedChanges(unverified)
    return result
