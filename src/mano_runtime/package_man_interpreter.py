"""Derive the main ELF interpreter selector from retained baseline metadata.

No filesystem access or interpreter execution occurs here. This deliberately
bounded alias profile rejects ambiguous/untrusted paths rather than emulating
every Linux pathname case. Actual kernel loading, source descriptors, dynamic
libraries and protected runtime updates require separate evidence.
"""
import hashlib
import json

from mano_runtime import package_man_elf_memory as memory

MAX_LINKS = 40
MAX_STEPS = 1024
MAX_PATH_BYTES = 4096
MAX_DEPTH = 128


def resolve(main_raw, baseline):
    """Resolve the retained mandb PT_INTERP within one hash-bound tree only."""
    main = memory.bind(main_raw, baseline, 'usr/bin/mandb')
    selector = main['declarations']['interpreter']
    if selector is None:
        raise ValueError('Dynamic main executable with explicit interpreter required')
    entries = baseline['entries']
    common = {'kind', 'uid', 'gid', 'mode', 'mtime_ns', 'ctime_ns', 'nlink', 'xattrs'}
    observations, aliases = [], []

    def checked(path, kind):
        row = entries.get(path)
        extra = ({'target'} if kind == 'symlink' else
                 {'bytes', 'sha256', 'hardlink_anchor'} if kind == 'file' else set())
        if (type(row) is not dict or set(row) != common | extra or row['kind'] != kind
                or any(type(row[k]) is not int for k in (
                    'uid', 'gid', 'mode', 'mtime_ns', 'ctime_ns', 'nlink'))
                or row['uid'] != 0 or not 0 <= row['gid'] < 2**32
                or not 0 <= row['mode'] <= 0o7777 or not 0 < row['nlink'] < 2**64
                or any(not -2**63 <= row[k] < 2**63 for k in ('mtime_ns', 'ctime_ns'))
                or row['xattrs'] != {}):
            raise ValueError('Exact Root-owned ordinary interpreter path metadata required')
        # Linux does not use symlink mode bits as access permissions. Trust its
        # owner and immutable parent instead; ordinary files/directories must
        # themselves exclude group/other writes.
        if kind != 'symlink' and row['mode'] & 0o022:
            raise ValueError('Nonwritable interpreter path component required')
        if kind == 'directory' and not row['mode'] & (
                0o010 if row['gid'] == 12 else 0o001):
            raise ValueError('Interpreter ancestor must be searchable by fixed man identity')
        digest = hashlib.sha256(json.dumps(row, sort_keys=True, separators=(',', ':'),
                                           allow_nan=False).encode()).hexdigest()
        observations.append(dict(path=path, kind=kind, metadata_sha256=digest))
        return row

    def components(target):
        if (type(target) is not str or not 0 < len(target) <= MAX_PATH_BYTES
                or any(not 33 <= ord(c) <= 126 for c in target)):
            raise ValueError('Bounded literal ASCII interpreter alias required')
        parts = target.split('/')[1:] if target.startswith('/') else target.split('/')
        if any(not part for part in parts):
            raise ValueError('Empty interpreter alias component is outside the profile')
        return parts

    checked('.', 'directory')
    pending, resolved, steps = components(selector), [], 0
    while pending:
        steps += 1
        if (steps > MAX_STEPS or len(resolved) > MAX_DEPTH
                or len('/'.join(pending)) > MAX_PATH_BYTES
                or len('/'.join(resolved)) > MAX_PATH_BYTES):
            raise ValueError('Interpreter alias traversal budget exceeded')
        part, pending = pending[0], pending[1:]
        if part == '.':
            continue
        if part == '..':
            if not resolved:
                raise ValueError('Interpreter alias root escape refused')
            resolved.pop()
            continue
        path = '/'.join([*resolved, part])
        if len(resolved) + 1 > MAX_DEPTH or len(path) > MAX_PATH_BYTES:
            raise ValueError('Interpreter resolved path budget exceeded')
        row = entries.get(path)
        if type(row) is not dict:
            raise ValueError('Interpreter component absent from observed baseline')
        kind = row.get('kind')
        if kind == 'symlink':
            row = checked(path, 'symlink')
            if len(aliases) >= MAX_LINKS:
                raise ValueError('Interpreter symlink limit exceeded')
            target = row['target']
            replacement = components(target)
            aliases.append(dict(path=path, target=target))
            if target.startswith('/'):
                resolved = []
            pending = replacement + pending
        elif pending:
            checked(path, 'directory')
            resolved.append(part)
        else:
            checked(path, 'file')
            resolved.append(part)
    terminal = '/'.join(resolved)
    if not terminal.startswith('usr/lib/'):
        raise ValueError('Canonical baseline usr/lib interpreter required')
    row = checked(terminal, 'file')
    access = 0o050 if row['gid'] == 12 else 0o005
    if row['mode'] & access != access:
        raise ValueError('Baseline interpreter readable/executable by fixed man identity required')
    if (type(row['bytes']) is not int or not 64 <= row['bytes'] <= memory.MAX_FILE_BYTES
            or type(row['sha256']) is not str or len(row['sha256']) != 64
            or any(c not in '0123456789abcdef' for c in row['sha256'])):
        raise ValueError('Bounded interpreter content metadata required')
    return dict(profile='man-baseline-interpreter-selector-v1',
        baseline_sha256=baseline['manifest_sha256'], main_binding=main,
        selector=selector, resolved_path=terminal, aliases=aliases,
        component_observations=observations, resolved_metadata=dict(row),
        baseline_selector_resolved=True, filesystem_paths_opened=False,
        interpreter_bytes_bound=False, readonly_source_descriptor_verified=False,
        actual_kernel_loading_verified=False, collector_authentication_verified=False,
        complete_runtime_closure_verified=False, publication_authorized=False)


def bind(main_raw, interpreter_raw, baseline):
    """Additionally bind retained loader bytes; this still proves no kernel load."""
    selection = resolve(main_raw, baseline)
    binding = memory.bind(interpreter_raw, baseline, selection['resolved_path'])
    declarations = binding['declarations']
    if declarations['elf_type'] != 3 or declarations['interpreter'] is not None:
        raise ValueError('Native ET_DYN interpreter without recursive PT_INTERP required')
    return dict(profile='man-baseline-interpreter-bytes-v1', selection=selection,
        interpreter_binding=binding, interpreter_bytes_bound=True,
        filesystem_paths_opened=False, readonly_source_descriptor_verified=False,
        actual_kernel_loading_verified=False, collector_authentication_verified=False,
        complete_runtime_closure_verified=False, publication_authorized=False)
