"""Conditional one-hop source lookup over retained metadata, never host paths.

This models ordinary Linux traversal/DAC for UID6/GID12 and a supplied compression
order. Unknown mounts, ACLs, scope and resource limits stop selection rather than
being mistaken for absence. It is not a native namespace or complete graph proof.
Initial hardlink canonicalization and recursive request handling are separate.
"""
import base64
import json
import re
from collections import deque

from mano_runtime.package_man_source_links import metadata_hash
from mano_runtime.package_tree import delta

ROOT = 'usr/share/man'
MAX_COMPONENTS = 128
MAX_LINKS = 40
MAX_REPORT_BYTES = 1024**2


class Namespace:
    def __init__(self, baseline, candidate):
        delta(baseline, baseline)
        delta(candidate, candidate)
        for tree in (baseline, candidate):
            for excluded in tree['excluded_subtrees']:
                for known in (ROOT, 'etc/alternatives'):
                    if (excluded == known or excluded.startswith(known+'/')
                            or known.startswith(excluded+'/')):
                        raise ValueError('Complete known lookup subtrees required')
        self.baseline_sha = baseline['manifest_sha256']
        self.candidate_sha = candidate['manifest_sha256']
        entries = {path: row for path, row in baseline['entries'].items()
            if path in {'.', 'usr', 'usr/share', 'etc', 'etc/alternatives'}
            or path.startswith('etc/alternatives/')}
        entries.update({path: row for path, row in candidate['entries'].items()
            if path == ROOT or path.startswith(ROOT+'/')})
        self._entries = json.loads(json.dumps(entries, sort_keys=True, allow_nan=False))

    @staticmethod
    def known(path):
        return (path in {'.', 'usr', 'usr/share', 'etc', 'etc/alternatives', ROOT}
                or path.startswith(ROOT+'/') or path.startswith('etc/alternatives/'))

    def stat(self, path):
        """Stat a namespace-root-relative name, not a host/cwd-relative name."""
        if type(path) is not str or not path or '\0' in path:
            raise ValueError('Nonempty NUL-free modeled pathname required')
        directories, links = {}, []

        def result(state, reason, *, terminal=None, row=None):
            value = dict(state=state, reason=reason, directories=directories, symlinks=links)
            if terminal is not None:
                value.update(terminal_path=terminal, kind=row['kind'],
                             terminal_metadata_sha256=metadata_hash(row))
            return value

        if len(path.encode())+(not path.startswith('/')) >= 4096:
            return result('unavailable', 'ENAMETOOLONG')
        pending = deque(part for part in path.split('/') if part)
        current = []
        require_directory = path.endswith('/')
        while pending:
            if len(current)+len(pending) > MAX_COMPONENTS:
                return result('unknown', 'component-budget')
            parent = '/'.join(current) or '.'
            row = self._entries.get(parent)
            if row is None:
                return result('unavailable', 'ENOENT')
            if row['kind'] != 'directory':
                return result('unavailable', 'ENOTDIR')
            if row['xattrs']:
                return result('unknown', 'directory-security-attributes-unmodeled')
            shift = 6 if row['uid'] == 6 else 3 if row['gid'] == 12 else 0
            if not (row['mode'] >> shift) & 1:
                return result('unavailable', 'EACCES')
            directories[parent] = metadata_hash(row)
            part = pending.popleft()
            if len(part.encode()) > 255:
                return result('unavailable', 'ENAMETOOLONG')
            if part == '.':
                continue
            if part == '..':
                if current:
                    current.pop()
                continue
            name = '/'.join(current+[part])
            if not self.known(name):
                return result('unknown', 'outside-observed-lookup-scope')
            entry = self._entries.get(name)
            if entry is None:
                return result('unavailable', 'ENOENT')
            if entry['kind'] == 'symlink':
                if row['mode'] & 0o1002 == 0o1002 and entry['uid'] not in {6, row['uid']}:
                    return result('unknown', 'protected-symlink-policy-unbound')
                if len(links) == MAX_LINKS:
                    return result('unavailable', 'ELOOP')
                target = entry['target']
                if not target or '\0' in target or len(target.encode()) >= 4096:
                    return result('unknown', 'unsupported-link-target')
                links.append(dict(path=name, target=target, metadata_sha256=metadata_hash(entry)))
                if not pending and target.endswith('/'):
                    require_directory = True
                if target.startswith('/'):
                    current = []
                pending.extendleft(reversed([item for item in target.split('/') if item]))
            else:
                current.append(part)
        terminal = '/'.join(current) or '.'
        entry = self._entries.get(terminal)
        if entry is None:
            return result('unavailable', 'ENOENT')
        if require_directory and entry['kind'] != 'directory':
            return result('unavailable', 'ENOTDIR')
        return result('exists', 'modeled-stat-success', terminal=terminal, row=entry)

    def select(self, mantree, original, operand, extensions):
        """First successful root candidate, then original-directory fallback."""
        for path in (mantree, original):
            if (type(path) is not str or not (path == ROOT or path.startswith(ROOT+'/'))
                    or any(part in {'', '.', '..'} for part in path.split('/'))):
                raise ValueError('Canonical manual tree and original page context required')
        if (type(operand) is not bytes or len(operand) > 4096 or b'\0' in operand
                or type(extensions) not in {list, tuple} or len(extensions) > 16
                or any(type(ext) is not str or re.fullmatch('[A-Za-z0-9]{1,8}', ext) is None
                       for ext in extensions) or len(set(extensions)) != len(extensions)):
            raise ValueError('Bounded inert operand and unique configured extensions required')
        report = dict(profile='man-conditional-reference-lookup-v1',
            baseline_sha256=self.baseline_sha, candidate_sha256=self.candidate_sha,
            mantree=mantree, original=original, operand_base64=base64.b64encode(operand).decode(),
            configured_extensions=list(extensions), attempts=[],
            runtime_manual_layer='candidate', runtime_other_layer='baseline',
            modeled_uid=6, modeled_gid=12, modeled_supplementary_groups=[],
            modeled_capability_sets_zero=True,
            conditional_linux_metadata_model=True, conditional_on_supplied_compression_order=True,
            filesystem_paths_opened=False, runtime_namespace_equivalence_verified=False,
            source_target_resolution_verified=False, transitive_source_graph_verified=False,
            generated_state_validated=False, changes_authorized=False, publication_authorized=False)

        def finish(state, reason):
            report.update(selection_state=state, reason=reason)
            if len(json.dumps(report, sort_keys=True).encode()) > MAX_REPORT_BYTES:
                raise ValueError('Reference lookup evidence budget')
            return report

        if operand.startswith(b'/'):
            return finish('ignored-absolute', 'ultimate-source-does-not-follow-absolute-request')
        try:
            text = operand.decode('utf-8', errors='strict')
        except UnicodeError:
            return finish('unknown', 'operand-outside-observation-encoding')
        for label, prefix in (('manual-tree', mantree),
                              ('original-directory', original.rsplit('/', 1)[0])):
            for extension in ('', *extensions):
                candidate = prefix+'/'+text+('.'+extension if extension else '')
                outcome = self.stat(candidate)
                report['attempts'].append(dict(context=label, extension=extension,
                                               path=candidate, outcome=outcome))
                if outcome['state'] == 'unknown':
                    return finish('unknown', outcome['reason'])
                if outcome['state'] == 'exists':
                    report['selected'] = dict(path=outcome['terminal_path'], kind=outcome['kind'],
                        metadata_sha256=outcome['terminal_metadata_sha256'])
                    return finish('selected', 'first-modeled-successful-candidate')
        return finish('unresolved', 'no-modeled-successful-candidate')
