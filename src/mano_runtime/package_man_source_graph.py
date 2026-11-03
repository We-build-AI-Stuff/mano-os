"""Bound every primary index context to an inert conditional leading-source chain.

Only supplied metadata and already verified leading classifications are used.
This is not general roff interpretation or namespace/generated-state authority.
"""
import hashlib
import json

from mano_runtime.package_man_cache import index_path
from mano_runtime.package_man_reference_lookup import Namespace
from mano_runtime.package_man_source_bytes import unique
from mano_runtime.package_man_source_links import metadata_hash

MAX_INPUT_BYTES = 16*1024**2
MAX_REPORT_BYTES = 32*1024**2
MAX_CONTEXTS = 8192
MAX_RECORDS = 65536


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def derive(bindings_raw, leading_raw, baseline, candidate, extensions):
    for raw in (bindings_raw, leading_raw):
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT_BYTES:
            raise ValueError('Bounded retained source binding and classification bytes required')
    bindings = json.loads(bindings_raw, object_pairs_hook=unique)
    leading = json.loads(leading_raw, object_pairs_hook=unique)
    if (bindings.get('profile') != 'man-db-primary-source-metadata-v1'
            or bindings.get('candidate_sha256') != candidate['manifest_sha256']
            or bindings.get('all_primary_records_bound') is not True
            or leading.get('profile') != 'man-leading-source-requests-v1'
            or leading.get('all_captured_files_classified') is not True
            or type(bindings.get('indexes')) is not dict
            or not 1 <= len(bindings['indexes']) <= 64
            or type(leading.get('files')) is not dict
            or not 1 <= len(leading['files']) <= 8192):
        raise ValueError('Complete versioned primary bindings and classifications required')
    for key in ('primary_records', 'direct_records', 'virtual_or_cat_records'):
        if type(bindings[key]) is not int or not 0 <= bindings[key] <= MAX_RECORDS:
            raise ValueError('Exact bounded source record counts required')
    view = Namespace(baseline, candidate)
    inputs = {}
    for relative, request in leading['files'].items():
        if (type(relative) is not str or any(part in {'', '.', '..'}
                for part in relative.split('/'))):
            raise ValueError('Root-relative inert source classification name required')
        path = 'usr/share/man/'+relative
        row = candidate['entries'].get(path)
        if (row is None or row['kind'] != 'file'
                or request.get('profile') != 'man-db-2.13-leading-source-request-v1'):
            raise ValueError('Every classification must bind a retained regular manual source')
        inputs[path] = dict(compressed_sha256=row['sha256'], request=request)
    contexts, indexes = {}, {}
    counts = dict(terminal=0, unresolved=0, unknown=0)
    primary = virtual = records = 0
    charged = 4096
    for index, frame in sorted(bindings['indexes'].items()):
        if not index_path(index) or type(frame.get('records')) is not dict:
            raise ValueError('Bounded canonical manual-index contexts required')
        locale = index[len('var/cache/man/'):-len('/index.db')]
        root = ('usr/share/man' if index == 'var/cache/man/index.db'
                else 'usr/share/man/'+locale)
        indexes[index] = {}
        for key, row in sorted(frame['records'].items()):
            records += 1
            if records > MAX_RECORDS:
                raise ValueError('Primary context record budget')
            if row.get('primary_metadata_bound') is not True:
                if row.get('reason') != 'virtual-or-cat-record-needs-separate-source-graph':
                    raise ValueError('Unbound primary metadata cannot enter source graph')
                virtual += 1
                continue
            primary += 1
            path = row['primary_path']
            source = candidate['entries'].get(path)
            if (not path.startswith(root+'/') or source is None
                    or row.get('primary_lstat_timestamp_bound') is not True
                    or row.get('observed_metadata_sha256') != metadata_hash(source)):
                raise ValueError('Primary context differs from bound observed source metadata')
            context = hashlib.sha256(encoded([root, path])).hexdigest()
            indexes[index][key] = context
            charged += len(encoded([index, key, context]))
            if context not in contexts:
                if len(contexts) >= MAX_CONTEXTS:
                    raise ValueError('Distinct primary source context budget')
                report = view.resolve_source(root, path, inputs, extensions)
                charged += len(encoded(report))+len(context)+4
                if charged > MAX_REPORT_BYTES:
                    raise ValueError('Conditional source graph report budget')
                contexts[context] = report
                counts[report['resolution_state']] += 1
    if ((primary, virtual, records) != (bindings['primary_records'],
            bindings['virtual_or_cat_records'], bindings['direct_records']) or not primary):
        raise ValueError('Complete source record coverage and exact counts required')
    result = dict(profile='man-primary-conditional-source-graph-v1',
        baseline_sha256=baseline['manifest_sha256'], candidate_sha256=candidate['manifest_sha256'],
        source_bindings_sha256=hashlib.sha256(bindings_raw).hexdigest(),
        leading_classifications_sha256=hashlib.sha256(leading_raw).hexdigest(),
        configured_extensions=list(extensions), classified_regular_sources=len(inputs),
        primary_records=primary, virtual_or_cat_records_excluded=virtual,
        distinct_primary_contexts=len(contexts), resolution_counts=counts,
        indexes=indexes, contexts=contexts, complete_primary_context_coverage=True,
        all_primary_conditional_chains_terminate=counts['terminal'] == len(contexts),
        filesystem_source_paths_opened=False, staged_data_inflated=False,
        native_namespace_equivalence_verified=False, complete_source_graph_verified=False,
        virtual_alias_declarations_verified=False, descriptions_verified=False,
        compression_filters_verified=False, generated_state_validated=False,
        changes_authorized=False, publication_authorized=False)
    raw = encoded(result)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError('Final conditional source graph byte budget')
    return result, raw
