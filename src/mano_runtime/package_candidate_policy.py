"""Validate a combined payload against drained baseline/candidate observations.

This is one necessary candidate gate, not a publisher. Unlisted changes remain
unresolved even when they resemble dpkg bookkeeping or parent timestamps. Callers
must separately validate generated state, protected runtime paths and custody.
"""
import hashlib
import json
from decimal import Decimal, InvalidOperation

from mano_runtime.package_payload import MAX_ENTRIES, MAX_METADATA, path_name
from mano_runtime.package_tree import delta


def validate_payloads(before, after, payloads, *, checkpoint=None):
    """Reject collisions, payload drift, shared-directory drift and extra aliases.

    Accept one authenticated inventory per package; this function does not itself
    authenticate archives. No candidate path is opened or executed here.
    """
    if checkpoint is not None and not callable(checkpoint):
        raise ValueError('Callable interruption checkpoint required')
    check = checkpoint if checkpoint is not None else (lambda: None)
    if not isinstance(payloads, dict) or not 1 <= len(payloads) <= 8:
        raise ValueError('Bounded package payload closure required')
    changes = delta(before, after)
    merged, contents = {}, {}
    for package, payload in payloads.items():
        check()
        if not isinstance(package, str) or not package or len(package) > 256:
            raise ValueError('Bounded package identity required')
        entries = payload['entries']
        if (payload.get('schema_version') != '1.0' or not isinstance(entries, dict)
                or not 1 <= len(entries) <= MAX_ENTRIES
                or payload.get('unsupported_metadata') != {}):
            raise ValueError('Supported bounded payload inventory required')
        raw = json.dumps(entries, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode()
        if len(raw) > MAX_METADATA or hashlib.sha256(raw).hexdigest() != payload['manifest_sha256']:
            raise ValueError('Payload inventory integrity changed')
        for name, row in entries.items():
            check()
            kind = row['kind']
            if (path_name(name, directory=kind == 'directory') != name
                    or name.split('/')[0] == '.snapshots'
                    or kind not in {'file', 'hardlink', 'symlink', 'directory'}):
                raise ValueError('Canonical supported payload path required')
            if name in merged:
                if kind != 'directory' or merged[name]['kind'] != 'directory':
                    raise ValueError('Overlapping non-directory package payloads')
                # New shared directories must have one unambiguous owner/mode.
                if any(row[k] != merged[name][k] for k in ('uid', 'gid', 'mode')):
                    raise ValueError('Conflicting shared-directory metadata')
            else:
                merged[name] = row
                if len(merged) > MAX_ENTRIES:
                    raise ValueError('Combined payload entry budget')
            if kind in {'file', 'hardlink'}:
                source = name if kind == 'file' else row['content_path']
                if source not in entries or entries[source]['kind'] != 'file':
                    raise ValueError('Package-local regular hardlink source required')
                contents[name] = (package, source, entries[source])
    for name in merged:
        check()
        parts = name.split('/')
        for count in range(1, len(parts)):
            parent = '/'.join(parts[:count])
            if parent in merged and merged[parent]['kind'] != 'directory':
                raise ValueError('Combined payload descends through a non-directory')
    old, new = before['entries'], after['entries']
    groups = {}
    for name, expected in merged.items():
        check()
        actual = new.get(name)
        if actual is None:
            raise ValueError('Candidate payload path missing')
        kind = expected['kind']
        if kind == 'directory':
            if actual['kind'] != 'directory':
                raise ValueError('Candidate payload directory replaced')
            reference = old.get(name)
            if reference is not None and reference['kind'] != 'directory':
                raise ValueError('Baseline non-directory replaced by payload directory')
            metadata = reference if reference is not None else expected
            if any(actual[k] != metadata[k] for k in ('uid', 'gid', 'mode')):
                raise ValueError('Candidate directory ownership/mode changed')
            if actual['xattrs'] != (reference['xattrs'] if reference is not None else {}):
                raise ValueError('Candidate directory extended attributes changed')
            continue
        if any(actual[k] != expected[k] for k in ('uid', 'gid', 'mode')) or actual['xattrs']:
            raise ValueError('Candidate payload security metadata differs')
        try:
            timestamp = Decimal(str(expected['mtime'])) * 1_000_000_000
            if (not timestamp.is_finite() or not -(2**63) <= timestamp < 2**63
                    or timestamp != timestamp.to_integral_value()):
                raise ValueError('Precisely representable payload timestamp required')
            if actual['mtime_ns'] != int(timestamp):
                raise ValueError('Candidate payload timestamp differs')
        except InvalidOperation as error:
            raise ValueError('Valid payload timestamp required') from error
        if kind == 'symlink':
            if (actual['kind'] != 'symlink' or actual['target'] != expected['target']
                    or actual['nlink'] != 1):
                raise ValueError('Candidate literal symlink differs')
        else:
            package, source, content = contents[name]
            if (actual['kind'] != 'file' or any(actual[k] != content[k]
                                              for k in ('bytes', 'sha256'))):
                raise ValueError('Candidate payload content differs')
            groups.setdefault((package, source), []).append(name)
    for names in groups.values():
        anchor = min(names)
        for name in names:
            check()
            if new[name]['hardlink_anchor'] != anchor or new[name]['nlink'] != len(names):
                raise ValueError('Candidate payload has missing or unapproved hardlink aliases')
    check()
    return dict(schema_version='1.0', payload_closure_validated=True,
                payload_paths=len(merged), package_count=len(payloads),
                manifest_sha256={name: payload['manifest_sha256']
                                 for name, payload in payloads.items()},
                before_sha256=before['manifest_sha256'], after_sha256=after['manifest_sha256'],
                unresolved_changes={name: row for name, row in changes['changes'].items()
                                    if name not in merged or merged[name]['kind'] == 'directory'},
                archive_signatures_verified=False, generated_state_validated=False,
                protected_runtime_policy_validated=False, changes_authorized=False,
                candidate_filesystem_verified=False, publication_authorized=False)
