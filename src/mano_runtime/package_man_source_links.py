"""Resolve primary manual symlinks in retained metadata, never on the host.

This walks Linux path components in order: collapsing ``link/..`` before
following the link would give a different answer. Only the observed immutable
manual hierarchy is considered. The terminal content hash binds opaque source
bytes; roff includes, alias declarations and descriptions remain unverified.
"""
import hashlib
import json
import re

from mano_runtime.package_man_sources import bind

ROOT = ('usr', 'share', 'man')
MAX_LINKS = 40
MAX_COMPONENTS = 128
MAX_PATH_BYTES = 4096
MAX_REPORT_BYTES = 16 * 1024**2


def metadata_hash(row):
    return hashlib.sha256(json.dumps(row, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest()


def resolve(entries, primary):
    """Interpret only hash-bound tree data supplied by inspect(), never open paths."""
    if (type(primary) is not str or not primary.startswith('/'.join(ROOT) + '/')
            or len(primary.encode()) > MAX_PATH_BYTES):
        raise ValueError('Bounded primary path within the manual root required')
    pending = primary.split('/')[len(ROOT):]
    if any(part in {'', '.', '..'} for part in pending):
        raise ValueError('Canonical primary path required')
    directories, links, seen = {}, [], set()

    def directory(parts):
        path = '/'.join(parts)
        row = entries.get(path, {})
        if (row.get('kind') != 'directory' or type(row.get('uid')) is not int
                or row['uid'] != 0 or type(row.get('mode')) is not int
                or row['mode'] & 0o022):
            return False
        directories[path] = metadata_hash(row)
        return True

    def unresolved(reason):
        return dict(primary_symlink_chain_bound=False, reason=reason)

    for count in range(1, len(ROOT)+1):
        if not directory(ROOT[:count]):
            return unresolved('untrusted-or-aliased-manual-root-parent')
    current = list(ROOT)
    while pending:
        if (len(pending) + len(current) > MAX_COMPONENTS
                or len('/'.join(current + pending).encode()) > MAX_PATH_BYTES):
            return unresolved('source-link-path-budget')
        part, *pending = pending
        if part in {'', '.'}:
            continue
        if part == '..':
            if len(current) == len(ROOT):
                return unresolved('source-link-escapes-manual-root')
            current.pop()
            continue
        path = '/'.join(current + [part])
        row = entries.get(path)
        if row is None:
            return unresolved('source-link-target-absent')
        kind = row.get('kind')
        if kind == 'symlink':
            if type(row.get('uid')) is not int or row['uid'] != 0:
                return unresolved('unsupported-source-link-owner')
            state = (path, tuple(pending))
            if state in seen:
                return unresolved('source-link-cycle')
            seen.add(state)
            if len(links) >= MAX_LINKS:
                return unresolved('source-link-depth-budget')
            target = row.get('target')
            if (type(target) is not str or not target or '\0' in target
                    or len(target.encode()) > MAX_PATH_BYTES):
                return unresolved('unsupported-source-link-target')
            links.append(dict(path=path, target=target, metadata_sha256=metadata_hash(row)))
            parts = target.split('/')
            if target.startswith('/'):
                if tuple(parts[1:len(ROOT)+1]) != ROOT:
                    return unresolved('source-link-escapes-manual-root')
                current = list(ROOT)
                parts = parts[len(ROOT)+1:]
            pending = parts + pending
            continue
        if kind == 'directory':
            current.append(part)
            if not directory(current):
                return unresolved('untrusted-source-link-parent')
            continue
        if kind != 'file' or pending:
            return unresolved('source-link-target-not-regular-or-parent-not-directory')
        if (type(row.get('uid')) is not int or row['uid'] != 0
                or type(row.get('mode')) is not int or row['mode'] & 0o7022
                or type(row.get('bytes')) is not int or not 0 <= row['bytes'] <= 2**32
                or type(row.get('sha256')) is not str
                or re.fullmatch('[a-f0-9]{64}', row['sha256']) is None):
            return unresolved('unsupported-terminal-source-metadata')
        return dict(primary_symlink_chain_bound=True, terminal_path=path,
                    terminal_sha256=row['sha256'], terminal_bytes=row['bytes'],
                    terminal_metadata_sha256=metadata_hash(row),
                    directory_metadata_sha256=directories, symlinks=links)
    return unresolved('source-link-target-is-directory')


def inspect(index_files, candidate):
    primary = bind(index_files, candidate)  # Checks input budgets and complete tree digest.
    sources, indexes, count, bound = {}, {}, 0, 0
    for path, index in primary['indexes'].items():
        rows = {}
        for key, row in index['records'].items():
            if row['primary_metadata_bound'] is not True:
                rows[key] = dict(primary_symlink_chain_bound=False,
                                 reason='primary-source-metadata-unbound')
                continue
            count += 1
            source = row['primary_path']
            if source not in sources:
                sources[source] = resolve(candidate['entries'], source)
            result = sources[source]
            rows[key] = dict(primary_path=source,
                            primary_symlink_chain_bound=result['primary_symlink_chain_bound'])
            bound += int(result['primary_symlink_chain_bound'])
        indexes[path] = dict(input_sha256=index['input_sha256'], records=rows)
    report = dict(profile='man-db-primary-source-links-v1',
        candidate_sha256=candidate['manifest_sha256'], indexes=indexes, sources=sources,
        primary_records=primary['primary_records'], metadata_bound_primary_records=count,
        primary_symlink_chains_bound=bound,
        all_primary_symlink_chains_bound=(
            bool(count) and count == bound == primary['primary_records']),
        filesystem_paths_opened=False, terminal_bytes_interpreted=False,
        roff_includes_verified=False, virtual_alias_declarations_verified=False,
        transitive_source_graph_verified=False, descriptions_verified=False,
        compression_filters_verified=False, cache_sources_verified=False,
        generated_state_validated=False, changes_authorized=False, publication_authorized=False)
    if len(json.dumps(report, sort_keys=True, allow_nan=False).encode()) > MAX_REPORT_BYTES:
        raise ValueError('Manual source-link report budget')
    return report
