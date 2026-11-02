"""Classify initial requests in frozen plaintext; never inflate or open operands.

This is a pure data transformation. Native provenance and domain custody are
established by the caller and must be independently checked before acceptance.
Initial request classification grants no target, graph or publication authority.
"""
import hashlib
import json

from mano_runtime.package_man_leading_source import inspect
from mano_runtime.package_man_source_bytes import manifest, unique
from mano_runtime.package_man_source_content import (
    EXPANDED_MAGIC,
    MAX_BUNDLE_BYTES,
    MAX_EXPANDED_TOTAL,
    MAX_REPORT_BYTES,
    validate_report,
)

PROFILE = 'man-leading-source-requests-v1'
ARTIFACT = 'staged-man-leading-requests.json'
KINDS = ('no-leading-so-request', 'relative-reference', 'empty-relative-reference',
         'absolute-reference-not-followed-by-ultimate-source')


def derive(packet, binary, capture):
    """Bind every classified file to manifest, plaintext and both decoder hashes."""
    requested = manifest(packet)
    if (type(binary) is not bytes or not 55 <= len(binary) <= MAX_BUNDLE_BYTES
            or type(capture) is not bytes or not 0 < len(capture) <= MAX_REPORT_BYTES+4097):
        raise ValueError('Bounded retained manual inputs required')
    header, separator, body = capture.partition(b'\n')
    if not separator or len(header) > 4096 or len(body) > MAX_REPORT_BYTES:
        raise ValueError('Bounded content capture framing required')
    guard = json.loads(header, object_pairs_hook=unique)
    worker = json.loads(body, object_pairs_hook=unique)
    if (type(guard) is not dict or guard.get('role') != 'source-content'
            or type(worker) is not dict or worker.get('profile') != 'man-source-gzip-content-v2'
            or worker.get('manifest_sha256') != hashlib.sha256(packet).hexdigest()):
        raise ValueError('Versioned content capture and manifest binding required')
    native = validate_report(worker, requested)
    retained = native['expanded_inputs']
    binary_sha = hashlib.sha256(binary).hexdigest()
    if retained['bytes'] != len(binary) or retained['sha256'] != binary_sha:
        raise ValueError('Exact frozen expanded-input artifact required')
    cursor = 0

    def take(count):
        nonlocal cursor
        if count < 0 or cursor+count > len(binary):
            raise ValueError('Truncated expanded-input record')
        result = binary[cursor:cursor+count]
        cursor += count
        return result

    if (take(len(EXPANDED_MAGIC)) != EXPANDED_MAGIC
            or take(32).hex() != hashlib.sha256(packet).hexdigest()
            or int.from_bytes(take(4), 'big') != len(requested['files'])):
        raise ValueError('Exact expanded-input version, manifest and record count required')
    files, kinds, total = {}, dict.fromkeys(KINDS, 0), 0
    report_bytes = 2
    for path, row in sorted(requested['files'].items()):
        name_length = int.from_bytes(take(4), 'big')
        size = int.from_bytes(take(8), 'big')
        if (name_length != len(path.encode()) or size > 8*1024**2
                or total+size > MAX_EXPANDED_TOTAL or take(name_length) != path.encode()):
            raise ValueError('Ordered bounded expanded-input names and lengths required')
        input_sha, output_sha = take(32).hex(), take(32).hex()
        evidence = worker['files'][path]
        if (input_sha != row['sha256'] or input_sha != evidence['input_sha256']
                or output_sha != evidence['framing']['expanded_sha256']
                or size != evidence['framing']['expanded_bytes']
                or size != evidence['independent_gzip']['output_bytes']
                or output_sha != evidence['independent_gzip']['output_sha256']):
            raise ValueError('Exact native decoder and compressed-input record binding required')
        raw = take(size)
        if hashlib.sha256(raw).hexdigest() != output_sha:
            raise ValueError('Expanded source bytes differ from both decoder witnesses')
        result = inspect(raw)
        report_bytes += len(json.dumps(path).encode()) + len(
            json.dumps(result, sort_keys=True, allow_nan=False).encode()) + 4
        if report_bytes > MAX_REPORT_BYTES:
            raise ValueError('Leading-request evidence byte budget')
        files[path] = result
        kinds[result['request_kind']] += 1
        total += size
    if cursor != len(binary) or total != retained['expanded_bytes']:
        raise ValueError('Complete expanded-input bundle without trailing bytes required')
    report = dict(profile=PROFILE, manifest_sha256=hashlib.sha256(packet).hexdigest(),
        expanded_artifact_sha256=binary_sha, expanded_artifact_bytes=len(binary),
        content_capture_sha256=hashlib.sha256(capture).hexdigest(), source_files=len(files),
        expanded_bytes=total, request_kind_counts=kinds, all_captured_files_classified=True,
        staged_gzip_inflated=False, filesystem_source_paths_opened=False,
        ultimate_source_targets_resolved=False, transitive_source_graph_verified=False,
        virtual_alias_declarations_verified=False, descriptions_verified=False,
        compression_filters_verified=False, runtime_closure_verified=False,
        generated_state_validated=False, changes_authorized=False, publication_authorized=False)
    encoded = json.dumps(dict(report, files=files), sort_keys=True, allow_nan=False).encode()+b'\n'
    if len(encoded) > MAX_REPORT_BYTES:
        raise ValueError('Final leading-request evidence byte budget')
    return dict(report, artifact=ARTIFACT, sha256=hashlib.sha256(encoded).hexdigest(),
                bytes=len(encoded)), encoded
