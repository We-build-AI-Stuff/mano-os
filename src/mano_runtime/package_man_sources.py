"""Bind direct man-db records to observed primary source metadata, as data only.

man-db 2.13.1 check_mandirs.c records lstat time before following manual links.
Consequently this check uses the primary link's own timestamp. It never follows
symlinks, opens manual files, interprets roff, or treats an alias name as a path.
The complete include/link/description graph and generated-state policy remain
unverified, even when every primary A/B record matches.
"""
import base64
import hashlib
import json

from mano_runtime.package_man_cache import MAX_DATABASE_BYTES, index_path
from mano_runtime.package_man_records import parse
from mano_runtime.package_tree import delta

MAX_DATABASES = 64
MAX_TOTAL_BYTES = 8 * 1024**2
MAX_RECORDS = 65536
MAX_REPORT_BYTES = 16 * 1024**2


def component(encoded):
    raw = base64.b64decode(encoded, validate=True)
    text = raw.decode('utf8')
    if (not text or text in {'.', '..'} or len(raw) > 255
            or any(character in text for character in '/\\\0\t\n\r')):
        raise ValueError('One bounded manual filename component required')
    return text


def bind(index_files, candidate):
    if (type(index_files) is not dict or not 1 <= len(index_files) <= MAX_DATABASES
            or any(not index_path(path) or type(raw) is not bytes
                   or len(raw) > MAX_DATABASE_BYTES for path, raw in index_files.items())
            or sum(map(len, index_files.values())) > MAX_TOTAL_BYTES):
        raise ValueError('Bounded manual-index bytes required')
    delta(candidate, candidate)  # Check the retained observation's complete content hash.
    entries = candidate['entries']
    reports, count, primary, bound = {}, 0, 0, 0
    for index, raw in sorted(index_files.items()):
        locale = index[len('var/cache/man/'):-len('/index.db')]
        # The root index has no locale, rather than a directory named index.db.
        root = 'usr/share/man' if index == 'var/cache/man/index.db' else 'usr/share/man/'+locale
        frames = parse(raw)
        rows = {}
        for key, record in frames['direct_records'].items():
            count += 1
            if count > MAX_RECORDS:
                raise ValueError('Manual primary-source record budget')
            if record['kind'] not in {'A', 'B'}:
                rows[key] = dict(primary_metadata_bound=False,
                    reason='virtual-or-cat-record-needs-separate-source-graph')
                continue
            primary += 1
            row = dict(primary_metadata_bound=False)
            rows[key] = row
            try:
                name, ext, section, comp = [component(record[field]) for field in
                    ('name_base64', 'extension_base64', 'section_base64', 'compression_base64')]
                filename = name + '.' + ext + ('' if comp == '-' else '.' + comp)
                if len(filename.encode('utf8')) > 255:
                    raise ValueError('Manual filename byte budget')
            except (ValueError, UnicodeError):
                row['reason'] = 'unsupported-primary-filename-component'
                continue
            path = root + '/man' + section + '/' + filename
            row['primary_path'] = path
            parts = path.split('/')
            if any(entries.get('/'.join(parts[:i]), {}).get('kind') != 'directory'
                   for i in range(1, len(parts))):
                row['reason'] = 'missing-or-aliased-source-parent'
                continue
            source = entries.get(path)
            if source is None:
                row['reason'] = 'primary-source-absent'
                continue
            if (source['kind'] not in {'file', 'symlink'} or type(source['uid']) is not int
                    or source['uid'] != 0 or type(source['mode']) is not int
                    or (source['kind'] == 'file' and source['mode'] & 0o7022)
                    or type(source['mtime_ns']) is not int):
                row['reason'] = 'unsupported-primary-source-metadata'
                continue
            metadata = json.dumps(source, sort_keys=True, separators=(',', ':'),
                                  allow_nan=False).encode()
            row['observed_metadata_sha256'] = hashlib.sha256(metadata).hexdigest()
            if record['mtime_known'] is not True:
                row['reason'] = 'unknown-record-timestamp'
                continue
            expected = record['mtime_seconds'] * 10**9 + record['mtime_nanoseconds']
            if source['mtime_ns'] != expected:
                row['reason'] = 'primary-lstat-timestamp-mismatch'
                continue
            row.update(primary_metadata_bound=True, source_kind=source['kind'],
                       primary_lstat_timestamp_bound=True)
            bound += 1
        reports[index] = dict(input_sha256=hashlib.sha256(raw).hexdigest(), records=rows)
    result = dict(profile='man-db-primary-source-metadata-v1',
        candidate_sha256=candidate['manifest_sha256'], indexes=reports,
        direct_records=count, primary_records=primary, primary_records_bound=bound,
        all_primary_records_bound=bool(primary) and primary == bound,
        virtual_or_cat_records=count-primary,
        transitive_source_graph_verified=False, descriptions_verified=False,
        compression_filters_verified=False, all_records_source_bound=False,
        cache_sources_verified=False, generated_state_validated=False,
        changes_authorized=False, publication_authorized=False)
    if len(json.dumps(result, sort_keys=True, allow_nan=False).encode()) > MAX_REPORT_BYTES:
        raise ValueError('Manual primary-source report byte budget')
    return result
