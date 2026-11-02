"""Conditional source lookup over retained metadata, never host paths.

This models ordinary Linux traversal/DAC for UID6/GID12 and a supplied compression
order. Unknown mounts, ACLs, scope and resource limits stop selection rather than
being mistaken for absence. It is not a native namespace or complete graph proof.
Recursive handling assumes initial lstat metadata and all three link flags;
native caller behavior and namespace equivalence require separate evidence.
"""
import base64
import hashlib
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

    def stat(self, path, *, follow_final=True):
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
            if entry['kind'] == 'symlink' and (follow_final or pending or require_directory):
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

    def resolve_source(self, mantree, original, inputs, extensions):
        """Conditional initial-link handling and bounded leading-request chain.

        inputs contains externally bound compressed hashes and verified leading
        classifications. This method cannot establish their decompression or
        native provenance, and never promotes its result into execution authority.
        """
        if type(inputs) is not dict or not 1 <= len(inputs) <= 8192:
            raise ValueError('Bounded supplied source classification map required')
        # Validate context/order using the same API without resolving any operand.
        self.select(mantree, original, b'/context-validation-only', extensions)
        report = dict(profile='man-conditional-ultimate-source-v1',
            baseline_sha256=self.baseline_sha, candidate_sha256=self.candidate_sha,
            mantree=mantree, original=original, configured_extensions=list(extensions),
            inspections=[], lookups=[], repeated_source_paths=[], initial_hardlink_selection=None,
            conditional_on_bound_source_classifications=True, conditional_linux_metadata_model=True,
            conditional_on_initial_lstat_and_all_link_flags=True,
            filesystem_paths_opened=False, native_lookup_equivalence_verified=False,
            source_target_resolution_verified=False, complete_source_graph_verified=False,
            generated_state_validated=False, changes_authorized=False, publication_authorized=False)

        def finish(state, reason):
            report.update(resolution_state=state, reason=reason)
            if len(json.dumps(report, sort_keys=True).encode()) > MAX_REPORT_BYTES:
                raise ValueError('Ultimate-source evidence budget')
            return report

        initial = self.stat(original, follow_final=False)
        report['initial_lstat'] = initial
        if initial['state'] != 'exists':
            return finish('unknown' if initial['state'] == 'unknown' else 'unresolved',
                          initial['reason'])
        raw_path = initial['terminal_path']
        raw_row = self._entries[raw_path]
        followed = self.stat(original) if initial['kind'] == 'symlink' else initial
        report['initial_followed_stat'] = followed
        if followed['state'] != 'exists':
            return finish('unknown' if followed['state'] == 'unknown' else 'unresolved',
                          followed['reason'])
        current = followed['terminal_path']
        if raw_row['nlink'] > 1:
            if initial['kind'] != 'file':
                return finish('unknown', 'initial-nonregular-hardlink-identity-unmodeled')
            parent = current.rsplit('/', 1)[0]
            directory = self._entries[parent]
            shift = 6 if directory['uid'] == 6 else 3 if directory['gid'] == 12 else 0
            if directory['xattrs'] or not (directory['mode'] >> shift) & 4:
                return finish('unknown', 'initial-hardlink-directory-read-unverified')
            aliases = [path for path, row in self._entries.items()
                if row['kind'] == 'file'
                and row.get('hardlink_anchor') == raw_row['hardlink_anchor']
                and path.rsplit('/', 1)[0] == parent]
            if not aliases or len(aliases) > 4096:
                return finish('unknown', 'initial-hardlink-directory-evidence-budget')
            current = min(aliases, key=lambda path: path.rsplit('/', 1)[1].encode())
            report['initial_hardlink_selection'] = dict(selected=current,
                directory=parent, same_directory_aliases=sorted(aliases),
                hardlink_anchor=raw_row['hardlink_anchor'])
        seen = set()
        for iteration in range(10):
            row = self._entries.get(current, {})
            if row.get('kind') != 'file':
                return finish('unknown', 'no-bound-regular-source-content')
            shift = 6 if row['uid'] == 6 else 3 if row['gid'] == 12 else 0
            if row['xattrs'] or not (row['mode'] >> shift) & 4:
                return finish('unknown', 'source-read-permission-unverified')
            supplied = inputs.get(current)
            if supplied is None:
                return finish('unknown', 'source-classification-not-captured')
            if type(supplied) is not dict:
                raise ValueError('Supplied source evidence must be an object')
            encoded = json.dumps(supplied, sort_keys=True, allow_nan=False).encode()
            if len(encoded) > 32768:
                raise ValueError('Bounded supplied source classification required')
            supplied = json.loads(encoded)
            if (type(supplied) is not dict or set(supplied) != {'compressed_sha256', 'request'}
                    or supplied['compressed_sha256'] != row['sha256']):
                raise ValueError('Source classification must bind observed compressed bytes')
            request = supplied['request']
            if (type(request) is not dict
                    or request.get('profile') != 'man-db-2.13-leading-source-request-v1'
                    or type(request.get('input_bytes')) is not int
                    or not 0 <= request['input_bytes'] <= 8*1024**2
                    or type(request.get('input_sha256')) is not str
                    or re.fullmatch('[a-f0-9]{64}', request['input_sha256']) is None
                    or type(request.get('operand_base64')) is not str):
                raise ValueError('Versioned bound leading-source classification required')
            operand = base64.b64decode(request['operand_base64'], validate=True)
            if base64.b64encode(operand).decode() != request['operand_base64']:
                raise ValueError('Canonical inert source operand required')
            kind = request.get('request_kind')
            if (type(kind) is not str or kind not in {'no-leading-so-request', 'relative-reference',
                    'empty-relative-reference',
                    'absolute-reference-not-followed-by-ultimate-source'}
                    or len(operand) > 4096 or b'\0' in operand
                    or (kind in {'no-leading-so-request', 'empty-relative-reference'} and operand)
                    or (kind == 'relative-reference' and (not operand or operand.startswith(b'/')))
                    or (kind == 'absolute-reference-not-followed-by-ultimate-source'
                        and not operand.startswith(b'/'))):
                raise ValueError('Exact leading-request kind and operand required')
            for flag in ('filesystem_paths_opened', 'roff_interpreted',
                         'ultimate_source_target_resolved', 'transitive_source_graph_verified',
                         'virtual_alias_declarations_verified', 'descriptions_verified',
                         'compression_filters_verified', 'generated_state_validated',
                         'changes_authorized', 'publication_authorized'):
                if request.get(flag) is not False:
                    raise ValueError('Supplied classification cannot grant additional authority')
            if current in seen:
                report['repeated_source_paths'].append(current)
            seen.add(current)
            report['inspections'].append(dict(iteration=iteration, path=current,
                source_metadata_sha256=metadata_hash(row),
                classification_sha256=hashlib.sha256(encoded).hexdigest(),
                expanded_sha256=request['input_sha256'], request_kind=kind))
            if kind in {'no-leading-so-request',
                        'absolute-reference-not-followed-by-ultimate-source'}:
                report['terminal'] = dict(path=current, source_metadata_sha256=metadata_hash(row),
                    compressed_sha256=row['sha256'], expanded_sha256=request['input_sha256'])
                return finish('terminal', 'no-further-relative-leading-request')
            selected = self.select(mantree, original, operand, extensions)
            report['lookups'].append(selected)
            if selected['selection_state'] != 'selected':
                state = 'unknown' if selected['selection_state'] == 'unknown' else 'unresolved'
                return finish(state, selected['reason'])
            if selected['selected']['kind'] != 'file':
                return finish('unknown', 'selected-nonregular-source-not-captured')
            current = selected['selected']['path']
        return finish('unresolved', 'native-ten-inspection-limit')
