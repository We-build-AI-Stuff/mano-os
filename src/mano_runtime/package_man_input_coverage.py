"""Bind observed manual regular-file coverage; never interpret source content."""
import hashlib
import json
import re

from mano_runtime.package_man_source_bytes import PROFILE, SCOPE, STAT_FIELDS, manifest
from mano_runtime.package_man_source_links import metadata_hash
from mano_runtime.package_tree import delta


def bind(packet, candidate, source, content):
    requested = manifest(packet)
    delta(candidate, candidate)  # Validate the entire retained tree and its digest.
    observed = {path.removeprefix('usr/share/man/'): row
                for path, row in candidate['entries'].items()
                if path.startswith('usr/share/man/') and row['kind'] == 'file'}
    if (requested['candidate_sha256'] != candidate['manifest_sha256']
            or set(requested['files']) != set(observed)):
        raise ValueError('Every observed regular manual input must be captured')
    for path, row in observed.items():
        expected = dict(**{key: row[key] for key in STAT_FIELDS}, sha256=row['sha256'],
                        observed_metadata_sha256=metadata_hash(row))
        if requested['files'][path] != expected:
            raise ValueError('Exact observed input metadata and content bindings required')
    total = sum(row['bytes'] for row in observed.values())
    indexed = len(requested['indexed_files'])
    packet_sha = hashlib.sha256(packet).hexdigest()
    if any(type(report.get('capture_sha256')) is not str or
           re.fullmatch('[a-f0-9]{64}', report['capture_sha256']) is None
           for report in (source, content)):
        raise ValueError('Exact source and content capture hashes required')
    if (source.get('profile') != PROFILE or source.get('scope') != SCOPE
            or content.get('profile') not in
                {'man-source-gzip-content-v1', 'man-source-gzip-content-v2'}
            or source.get('observed_manual_root_regular_files_captured') is not True
            or source.get('all_captured_content_hashes_match') is not True
            or source.get('manifest_sha256') != packet_sha
            or content.get('manifest_sha256') != packet_sha
            or content.get('input_capture_sha256') != source.get('capture_sha256')
            or content.get('both_decoders_equal') is not True
            or source.get('domain_drained') is not True or content.get('domain_drained') is not True
            or source.get('control_fixture_unchanged') is not True
            or content.get('control_fixture_unchanged') is not True):
        raise ValueError('Bound drained opaque capture and matching content domain required')
    for report, counts in ((source, dict(source_files=len(observed), source_bytes=total,
            indexed_source_files=indexed, additional_manual_files=len(observed)-indexed)),
            (content, dict(source_files=len(observed)))):
        if any(type(report.get(key)) is not int or report[key] != count
               for key, count in counts.items()):
            raise ValueError('Exact complete inventory and decoded input counts required')
    if (type(content.get('expanded_bytes')) is not int
            or not 0 <= content['expanded_bytes'] <= 64*1024**2
            or type(content.get('gzip_members')) is not int
            or not len(observed) <= content['gzip_members'] <= 16384):
        raise ValueError('Bounded complete content expansion evidence required')
    for report in (source, content):
        if (report.get('changes_authorized') is not False
                or report.get('publication_authorized') is not False):
            raise ValueError('Input coverage grants no mutation or publication authority')
    extra = sorted(set(observed)-set(requested['indexed_files']))
    extra_sha = hashlib.sha256(json.dumps(extra, sort_keys=True).encode()).hexdigest()
    return dict(profile='man-observed-regular-input-coverage-v1', scope=SCOPE,
        candidate_sha256=candidate['manifest_sha256'], manifest_sha256=packet_sha,
        source_capture_sha256=source['capture_sha256'],
        content_capture_sha256=content['capture_sha256'],
        source_files=len(observed), source_bytes=total, indexed_source_files=indexed,
        additional_manual_files=len(extra),
        additional_paths_sha256=extra_sha,
        observed_regular_file_inventory_covered=True, gzip_decoding_covered_all_captured_files=True,
        expanded_bytes=content['expanded_bytes'], gzip_members=content['gzip_members'],
        actual_filesystem_reacquired=False, complete_readable_namespace_verified=False,
        roff_interpreted=False, source_declarations_verified=False,
        transitive_source_graph_verified=False, descriptions_verified=False,
        compression_filters_verified=False, runtime_closure_verified=False,
        generated_state_validated=False, changes_authorized=False, publication_authorized=False)
