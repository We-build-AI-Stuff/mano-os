"""Bind validated database bytes to drained tree observations, not authority.

A backup which differs from the known preimage remains unresolved. In particular,
an intermediate dpkg backup is not silently treated as an approved final state.
"""
import hashlib

from mano_runtime.package_postconditions import MAX_STATUS

STATUS = 'var/lib/dpkg/status'
BACKUP = 'var/lib/dpkg/status-old'


def plain(entry, path):
    if (not isinstance(entry, dict) or entry.get('kind') != 'file'
            or any(type(entry.get(key)) is not int for key in
                   ('uid', 'gid', 'mode', 'nlink', 'bytes', 'mtime_ns', 'ctime_ns'))
            or (entry['uid'], entry['gid'], entry['nlink']) != (0, 0, 1)
            or entry['mode'] not in {0o600, 0o640, 0o644}
            or entry.get('xattrs') != {} or entry.get('hardlink_anchor') != path
            or not 0 < entry['bytes'] <= MAX_STATUS):
        raise ValueError('Private plain Root-owned database file required')


def bind(before, after, baseline, candidate, *, checkpoint=None):
    if checkpoint is not None and not callable(checkpoint):
        raise ValueError('Callable interruption checkpoint required')
    check = checkpoint if checkpoint is not None else (lambda: None)
    hashes = []
    for data, tree in ((before, baseline), (after, candidate)):
        check()
        if type(data) is not bytes or not 0 < len(data) <= MAX_STATUS:
            raise ValueError('Bounded actual database bytes required')
        row = tree['entries'].get(STATUS)
        plain(row, STATUS)
        digest = hashlib.sha256(data).hexdigest()
        if row['bytes'] != len(data) or row['sha256'] != digest:
            raise ValueError('Database bytes differ from tree observation')
        hashes.append(digest)
    original, current = baseline['entries'][STATUS], candidate['entries'][STATUS]
    if current['mode'] != original['mode']:
        raise ValueError('Database access mode changed outside metadata policy')
    backup = candidate['entries'].get(BACKUP)
    matches = False
    if backup is not None:
        plain(backup, BACKUP)
        matches = (backup['bytes'] == len(before) and backup['sha256'] == hashes[0]
                   and backup['mode'] == original['mode']
                   and backup['mtime_ns'] == original['mtime_ns'])
    check()
    return dict(schema_version='1.0', status_bytes_bound_to_tree=True,
                before_status_sha256=hashes[0], after_status_sha256=hashes[1],
                backup_matches_known_preimage=matches,
                verified_database_paths=[STATUS, BACKUP] if matches else [STATUS],
                unresolved_backup_paths=[] if matches else [BACKUP],
                all_generated_state_validated=False, package_transition_validated=False,
                changes_authorized=False, candidate_filesystem_verified=False,
                publication_authorized=False)
