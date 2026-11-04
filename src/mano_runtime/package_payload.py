"""Observe a bounded uncompressed package tar stream; never extract or authorize.

The caller must supply verified immutable archive custody and run parsing in a
resource-limited worker. Library parsing of extension headers precedes observed
entry budgets; these limits do not replace a process memory/CPU boundary.
Unknown PAX attributes are retained as unsupported metadata, not silently blessed.
"""

import hashlib
import json
import math
import tarfile

MAX_ENTRIES = 100_000
MAX_PAYLOAD = 512 * 1024**2
MAX_FILE = 256 * 1024**2
MAX_METADATA = 32 * 1024**2
STANDARD_PAX = {'path', 'linkpath', 'size', 'uid', 'gid', 'uname', 'gname',
                'mtime', 'atime', 'ctime'}


def path_name(value, *, directory=False):
    if (not isinstance(value, str) or value.startswith('/') or '\0' in value
            or len(value.encode('utf8')) > 4096):
        raise ValueError('Bounded UTF8 archive path required')
    if value.startswith('./'):
        value = value[2:]
    if directory:
        value = value.rstrip('/')
        if value in {'', '.'}:
            return '.'
    parts = value.split('/')
    if (len(parts) > 128 or any(part in {'', '.', '..'} for part in parts)
            or any(len(part.encode('utf8')) > 255 for part in parts)):
        raise ValueError('Canonical relative archive path required')
    return value


def inventory(stream, *, max_entries=MAX_ENTRIES, max_payload=MAX_PAYLOAD,
              max_file=MAX_FILE, max_metadata=MAX_METADATA, checkpoint=None):
    """Return content/provenance observations, not a filesystem publication plan.

Symlink targets remain literal data and are never followed. Hard links must end
at a regular member of this same archive. A caller must still validate merged
package collisions, removals, candidate mutations, conffiles and authority scope.
"""
    for value, ceiling in ((max_entries, MAX_ENTRIES), (max_payload, MAX_PAYLOAD),
                           (max_file, MAX_FILE), (max_metadata, MAX_METADATA)):
        if type(value) is not int or not 0 < value <= ceiling:
            raise ValueError('Explicit bounded payload inventory budget required')
    if checkpoint is not None and not callable(checkpoint):
        raise ValueError('Callable interruption checkpoint required')
    check = checkpoint if checkpoint is not None else (lambda: None)
    entries, unsupported = {}, {}
    total, metadata = 0, 0
    try:
        with tarfile.open(fileobj=stream, mode='r|') as archive:
            for member in archive:
                check()
                if len(entries) >= max_entries:
                    raise ValueError('Package payload entry budget')
                if not member.name:
                    raise ValueError('Empty normalized archive member name')
                name = path_name(member.name, directory=member.isdir())
                if name in entries:
                    raise ValueError('Duplicate canonical package payload path')
                if (type(member.uid) is not int or not 0 <= member.uid < 2**32
                        or type(member.gid) is not int or not 0 <= member.gid < 2**32
                        or type(member.mode) is not int or member.mode & ~0o7777
                        or type(member.size) is not int or member.size < 0
                        or type(member.mtime) not in {int, float}
                        or not math.isfinite(member.mtime) or not -(2**63) < member.mtime < 2**63):
                    raise ValueError('Invalid numeric package payload metadata')
                record = dict(uid=member.uid, gid=member.gid, mode=member.mode, mtime=member.mtime)
                pax = dict(member.pax_headers)
                if any(not isinstance(k, str) or not isinstance(v, str) for k,v in pax.items()):
                    raise ValueError('Textual archive extension metadata required')
                extra = {k:v for k,v in pax.items() if k not in STANDARD_PAX}
                if member.issparse():
                    extra['unsupported_sparse_layout'] = 'true'
                if extra:
                    unsupported[name] = extra
                if pax:
                    record['pax_headers'] = pax
                initial_metadata = len(name.encode('utf8')) + len(json.dumps(
                    record, sort_keys=True).encode())
                if metadata + initial_metadata > max_metadata:
                    raise ValueError('Package payload metadata budget')
                if member.isfile():
                    if member.size > max_file or total + member.size > max_payload:
                        raise ValueError('Package payload byte budget')
                    digest, count = hashlib.sha256(), 0
                    source = archive.extractfile(member)
                    if source is None:
                        raise ValueError('Regular archive member data missing')
                    with source:
                        while piece := source.read(min(65536, member.size - count + 1)):
                            check()
                            count += len(piece)
                            if count > member.size:
                                raise ValueError('Archive member exceeded declared size')
                            digest.update(piece)
                    if count != member.size:
                        raise ValueError('Truncated archive member data')
                    total += count
                    record.update(kind='file', bytes=count, sha256=digest.hexdigest())
                elif member.isdir():
                    record['kind'] = 'directory'
                elif member.issym():
                    target = member.linkname
                    if not target or '\0' in target or len(target.encode('utf8')) > 4096:
                        raise ValueError('Bounded literal symlink target required')
                    record.update(kind='symlink', target=target)
                elif member.islnk():
                    target = path_name(member.linkname)
                    record.update(kind='hardlink', target=target)
                else:
                    raise ValueError('Special payload objects require a separate policy')
                if not member.isfile() and member.size:
                    raise ValueError('Unexpected data on a non-regular payload object')
                metadata += len(name.encode('utf8')) + len(json.dumps(
                    record, sort_keys=True).encode())
                if metadata > max_metadata:
                    raise ValueError('Package payload metadata budget')
                entries[name] = record
    except (tarfile.TarError, UnicodeError, OverflowError) as error:
        raise ValueError('Malformed or unsupported package payload stream') from error
    # Resolve forward links without recursion, filesystem lookups or quadratic
    # traversal of a long chain. Keep the original target for later provenance.
    resolved = {name:name for name,r in entries.items() if r['kind'] == 'file'}
    for name, record in entries.items():
        if record['kind'] != 'hardlink':
            continue
        chain, seen, current = [], set(), name
        while current not in resolved:
            check()
            if current in seen or current not in entries:
                raise ValueError('Cyclic or missing archive hardlink target')
            seen.add(current)
            item = entries[current]
            if item['kind'] != 'hardlink':
                raise ValueError('Archive hardlink must reference a regular payload')
            chain.append(current)
            current = item['target']
        for link in chain:
            resolved[link] = resolved[current]
        previous = len(json.dumps(record, sort_keys=True).encode())
        record['content_path'] = resolved[name]
        metadata += len(json.dumps(record, sort_keys=True).encode()) - previous
        if metadata > max_metadata:
            raise ValueError('Package payload metadata budget')
        target = entries[resolved[name]]
        if any(record[key] != target[key] for key in ('uid', 'gid', 'mode', 'mtime')):
            unsupported.setdefault(name, {})['hardlink_metadata_conflict'] = 'true'
    for name in entries:
        check()
        parts = name.split('/')
        for count in range(1, len(parts)):
            parent = '/'.join(parts[:count])
            if parent not in entries or entries[parent]['kind'] == 'directory':
                continue
            if entries[parent]['kind'] != 'symlink':
                raise ValueError('Payload path descends through a non-directory object')
            # Linux packages can contain directory symlinks. Preserve that
            # ambiguity for a baseline-aware candidate validator, never follow it.
            unsupported.setdefault(name, {})['symlink_parent'] = parent
    canonical = json.dumps(entries, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=True, allow_nan=False).encode()
    check()
    return dict(schema_version='1.0', entries=entries, payload_bytes=total,
                metadata_bytes=metadata, manifest_sha256=hashlib.sha256(canonical).hexdigest(),
                unsupported_metadata=unsupported, archive_signature_verified=False,
                candidate_filesystem_verified=False, publication_authorized=False)
