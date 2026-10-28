"""Resolve virtual cache links to primary records using exact inert metadata.

This is an internal index relationship, not a roff alias declaration or complete
source/include graph. Names and pointers remain base64 data, never filenames.
Primary metadata is independently recomputed from actual index bytes and the
hash-bound candidate observation. No caller-supplied green report is accepted.
"""
import hashlib
import json

from mano_runtime.package_man_records import parse
from mano_runtime.package_man_sources import bind

MAX_REPORT_BYTES = 16 * 1024**2
FIELDS = ('compression_base64', 'filter_base64', 'mtime_seconds', 'mtime_nanoseconds')


def inspect(index_files, candidate):
    primary = bind(index_files, candidate)  # Also enforces aggregate input/count/path bounds.
    indexes, total, resolved = {}, 0, 0
    for path, raw in sorted(index_files.items()):
        frames = parse(raw)['direct_records']
        targets = {}
        for key, row in frames.items():
            if row['kind'] in {'A', 'B'}:
                signature = tuple(row[field] for field in
                                  ('name_base64', 'extension_base64', 'section_base64'))
                targets.setdefault(signature, []).append(key)
        links = {}
        for key, row in frames.items():
            if row['kind'] != 'C':
                continue
            total += 1
            link = dict(virtual_target_metadata_bound=False)
            links[key] = link
            if row['pointer_base64'] == 'LQ==':  # Literal '-' is man-db's unset sentinel.
                link['reason'] = 'missing-virtual-pointer'
                continue
            signature = tuple(row[field] for field in
                              ('pointer_base64', 'extension_base64', 'section_base64'))
            matches = targets.get(signature, [])
            if len(matches) != 1:
                link['reason'] = ('missing-primary-record' if not matches
                                  else 'ambiguous-primary-record')
                continue
            target_key = matches[0]
            target = frames[target_key]
            link['target_key_base64'] = target_key
            if row['description_base64'] != '':
                link['reason'] = 'virtual-inline-description-needs-separate-policy'
                continue
            differences = [field for field in FIELDS if row[field] != target[field]]
            if differences or row['mtime_known'] is not True or target['mtime_known'] is not True:
                link.update(reason='virtual-target-metadata-differs', differing_fields=differences)
                continue
            source = primary['indexes'][path]['records'][target_key]
            if source['primary_metadata_bound'] is not True:
                link['reason'] = 'target-primary-source-metadata-unbound'
                continue
            link.update(virtual_target_metadata_bound=True,
                        target_primary_metadata_sha256=source['observed_metadata_sha256'])
            resolved += 1
        indexes[path] = dict(input_sha256=hashlib.sha256(raw).hexdigest(), virtual_links=links)
    result = dict(profile='man-db-virtual-target-metadata-v1',
        candidate_sha256=candidate['manifest_sha256'], indexes=indexes,
        virtual_records=total, virtual_targets_metadata_bound=resolved,
        all_virtual_targets_metadata_bound=total == resolved,
        metadata_fields_compared=list(FIELDS),
        alias_names_interpreted_as_paths=False, virtual_alias_declarations_verified=False,
        transitive_source_graph_verified=False, descriptions_verified=False,
        compression_filters_verified=False, cache_sources_verified=False,
        generated_state_validated=False, changes_authorized=False, publication_authorized=False)
    if len(json.dumps(result, sort_keys=True, allow_nan=False).encode()) > MAX_REPORT_BYTES:
        raise ValueError('Virtual manual metadata report budget')
    return result
