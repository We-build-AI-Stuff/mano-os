"""Bind bounded private dpkg logs to tree observations; never approve log content.

Append-only shape does not establish that appended events are legitimate. Keep
the log mutation unresolved until a separate semantic validator accepts it.
"""
import hashlib

PATH = 'var/log/dpkg.log'
MAX_LOG = 16 * 1024**2


def observe(before, after, baseline, candidate):
    hashes = []
    for data, tree in ((before, baseline), (after, candidate)):
        if type(data) is not bytes or len(data) > MAX_LOG:
            raise ValueError('Bounded actual dpkg log bytes required')
        row = tree['entries'].get(PATH)
        if (not isinstance(row, dict) or row.get('kind') != 'file'
                or any(type(row.get(key)) is not int for key in
                       ('uid', 'gid', 'mode', 'nlink', 'bytes', 'mtime_ns', 'ctime_ns'))
                or (row['uid'], row['gid'], row['mode'], row['nlink']) != (0, 0, 0o644, 1)
                or row.get('xattrs') != {} or row.get('hardlink_anchor') != PATH):
            raise ValueError('Private plain Root-owned dpkg log required')
        digest = hashlib.sha256(data).hexdigest()
        if row['bytes'] != len(data) or row['sha256'] != digest:
            raise ValueError('Actual log bytes differ from tree observation')
        hashes.append(digest)
    append_only = after.startswith(before)
    suffix = after[len(before):] if append_only else None
    return dict(schema_version='1.0', log_path=PATH,
                before_sha256=hashes[0], after_sha256=hashes[1],
                before_bytes=len(before), after_bytes=len(after),
                append_only_observed=append_only,
                appended_bytes=len(suffix) if suffix is not None else None,
                appended_sha256=hashlib.sha256(suffix).hexdigest() if suffix is not None else None,
                log_events_parsed=False, log_semantics_verified=False,
                log_change_accounted=False, changes_authorized=False,
                publication_authorized=False)
