"""Derive complete deterministic cache bytes and source diagnostics as data.

The raw regenerated bundle remains a separate retained witness. This pipeline
never writes into a candidate or executes a database/native reader. Canonical
byte equality is distinct from source semantics and publication permission.
"""
import base64
import hashlib
import json

from mano_runtime.package_gdbm_decode import decode
from mano_runtime.package_gdbm_encode import encode, require_canonical
from mano_runtime.package_man_cache import MAX_DATABASE_BYTES, index_path
from mano_runtime.package_man_records import parse
from mano_runtime.package_man_source_links import inspect as inspect_source_links
from mano_runtime.package_man_sources import bind
from mano_runtime.package_man_virtual_metadata import inspect as inspect_virtual_targets

MAX_DATABASES = 64
MAX_BYTES = 8 * 1024**2
MAX_RECORDS = 65536
MAX_REPORT_BYTES = 16 * 1024**2
MAX_ARTIFACT_BYTES = 32 * 1024**2
FILES = {'staged-man-canonical-bytes.json', 'staged-man-canonical-frames.json',
         'staged-man-canonical-sources.json'}
SOURCE_FILES = {'staged-man-source-links.json', 'staged-man-virtual-targets.json'}


def serialize(value):
    raw = json.dumps(value, sort_keys=True, allow_nan=False).encode()
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError('Canonical manual-cache report byte budget')
    return raw


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate regenerated database key')
        result[key] = value
    return result


def derive(raw_bundle, candidate, *, baseline=None):
    if type(raw_bundle) is not bytes or len(raw_bundle) > MAX_REPORT_BYTES:
        raise ValueError('Bounded retained regeneration bundle required')
    raw_files = json.loads(raw_bundle, object_pairs_hook=unique_object)
    if type(raw_files) is not dict or not 1 <= len(raw_files) <= MAX_DATABASES:
        raise ValueError('Bounded nonempty regenerated database map required')
    canonical_files, binary_files, frame_reports, databases = {}, {}, {}, {}
    total_input = total_output = records = 0
    for path, encoded in sorted(raw_files.items()):
        if (not isinstance(path, str) or not index_path('var/cache/man/' + path)
                or type(encoded) is not str or len(encoded) > 4 * ((MAX_DATABASE_BYTES + 2) // 3)):
            raise ValueError('Fixed bounded regenerated index bytes required')
        raw = base64.b64decode(encoded, validate=True)
        total_input += len(raw)
        if total_input > MAX_BYTES:
            raise ValueError('Canonical derivation input byte budget')
        logical = decode(raw)
        records += logical['decoded_records']
        if records > MAX_RECORDS:
            raise ValueError('Canonical derivation record budget')
        pairs = {base64.b64decode(row['key_base64'], validate=True):
                 base64.b64decode(row['value_base64'], validate=True) for row in logical['records']}
        canonical = encode(pairs)
        proof = require_canonical(canonical)
        total_output += len(canonical)
        if total_output > MAX_BYTES:
            raise ValueError('Canonical derivation output byte budget')
        frame_reports[path] = parse(canonical)
        canonical_files[path] = base64.b64encode(canonical).decode('ascii')
        binary_files['var/cache/man/' + path] = canonical
        databases[path] = dict(input_bytes=len(raw), input_sha256=hashlib.sha256(raw).hexdigest(),
                               canonical=proof)
        # Bound aggregate object growth before adding another database.
        serialize(frame_reports)
        serialize(canonical_files)
    sources = bind(binary_files, candidate)
    artifacts = {'staged-man-canonical-bytes.json': serialize(canonical_files),
                 'staged-man-canonical-frames.json': serialize(frame_reports),
                 'staged-man-canonical-sources.json': serialize(sources)}
    source_metadata = None
    if baseline is not None:
        linked = inspect_source_links(binary_files, candidate, baseline=baseline)
        virtual = inspect_virtual_targets(binary_files, candidate)
        virtual_chains = 0
        for path, index in virtual['indexes'].items():
            for row in index['virtual_links'].values():
                if row['virtual_target_metadata_bound'] is True:
                    target = linked['indexes'][path]['records'][row['target_key_base64']]
                    virtual_chains += int(target['primary_symlink_chain_bound'])
        artifacts.update({'staged-man-source-links.json': serialize(linked),
                          'staged-man-virtual-targets.json': serialize(virtual)})
        source_metadata = dict(baseline_sha256=baseline['manifest_sha256'],
            primary_chains_bound=linked['primary_symlink_chains_bound'],
            all_primary_chains_bound=linked['all_primary_symlink_chains_bound'],
            virtual_records=virtual['virtual_records'],
            virtual_targets_metadata_bound=virtual['virtual_targets_metadata_bound'],
            virtual_target_chains_bound=virtual_chains,
            all_virtual_target_chains_bound=virtual_chains == virtual['virtual_records'],
            source_declarations_verified=False, transitive_source_graph_verified=False,
            descriptions_verified=False, compression_filters_verified=False,
            generated_state_validated=False, changes_authorized=False,
            publication_authorized=False)
    if sum(map(len, artifacts.values())) > MAX_ARTIFACT_BYTES:
        raise ValueError('Canonical derivation aggregate artifact budget')
    summary = dict(schema_version='1.0', profile='derived-man-cache-canonical-v1',
        input_bundle_sha256=hashlib.sha256(raw_bundle).hexdigest(),
        candidate_sha256=candidate['manifest_sha256'], databases=databases,
        input_bytes=total_input, canonical_bytes=total_output, decoded_records=records,
        primary_records=sources['primary_records'],
        primary_records_bound=sources['primary_records_bound'],
        all_primary_records_bound=sources['all_primary_records_bound'],
        virtual_or_cat_records=sources['virtual_or_cat_records'],
        artifacts={name:dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                   for name, raw in artifacts.items()},
        complete_canonical_encoding_verified=True, record_frames_decoded=True,
        internal_references_resolved=True, transitive_source_graph_verified=False,
        descriptions_verified=False, compression_filters_verified=False,
        all_records_source_bound=False, cache_sources_verified=False,
        generated_state_validated=False, changes_authorized=False, publication_authorized=False)
    if source_metadata is not None:
        summary['source_metadata'] = source_metadata
    serialize(summary)
    return summary, artifacts
