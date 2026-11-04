import copy
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from test_package_man_sources import candidate, index, rehash

from mano_runtime import package_man_source_bytes as sources


def packet():
    tree, _ = candidate()
    return sources.prepare({'var/cache/man/index.db': index()}, tree, tree)


class OpaqueManualSourceTests(unittest.TestCase):
    def test_worker_output_ceiling_includes_its_trailing_newline(self):
        root = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        with patch.object(sources.os, 'fstat', return_value=root), \
                patch.object(sources, 'read_relative', return_value=b''):
            body = sources.acquire(123, packet())
            with patch.object(sources, 'MAX_OUTPUT_BYTES', len(body)), \
                    self.assertRaises(ValueError):
                sources.acquire(123, packet())
            with patch.object(sources, 'MAX_OUTPUT_BYTES', len(body)+1):
                self.assertEqual(sources.acquire(123, packet()), body)

    def test_v2_captures_unindexed_regular_files_with_explicit_scope(self):
        tree, path = candidate()
        extra = 'usr/share/man/man6/unindexed.6.gz'
        tree['entries'][extra] = dict(tree['entries'][path], hardlink_anchor=extra,
                                     bytes=1, sha256=hashlib.sha256(b'x').hexdigest())
        rehash(tree)
        request = sources.prepare({'var/cache/man/index.db': index()}, tree, tree)
        value = sources.manifest(request)
        self.assertEqual(value['profile'], 'man-source-opaque-bytes-v2')
        self.assertEqual(value['scope'], 'observed-manual-root-regular-files')
        self.assertEqual(value['indexed_files'], ['man6/sl.6.gz'])
        self.assertEqual(set(value['files']), {'man6/sl.6.gz', 'man6/unindexed.6.gz'})
        body = dict(profile=sources.PROFILE, manifest_sha256=hashlib.sha256(request).hexdigest(),
                    files={'man6/sl.6.gz': '', 'man6/unindexed.6.gz': 'eA=='},
                    source_files=2, source_bytes=1, all_file_stat_fields_verified=True,
                    source_content_interpreted=False, changes_authorized=False,
                    publication_authorized=False)
        report = sources.validate_capture(request, json.dumps(body).encode())
        self.assertEqual((report['indexed_source_files'],
                          report['additional_manual_files']), (1, 1))
        self.assertFalse(report['source_content_interpreted'])
        del body['files']['man6/unindexed.6.gz']
        with self.assertRaises(ValueError):
            sources.validate_capture(request, json.dumps(body).encode())

    def test_v2_scope_subset_and_unindexed_metadata_cannot_be_downgraded(self):
        good = json.loads(packet())
        for field, bad in (('profile', 'man-source-opaque-bytes-v1'),
                           ('scope', 'resolved-index-files'), ('indexed_files', []),
                           ('indexed_files', ['man6/absent.6.gz']),
                           ('indexed_files', ['man6/sl.6.gz', 'man6/sl.6.gz'])):
            with self.subTest(field=field), self.assertRaises(ValueError):
                sources.manifest(json.dumps(dict(good, **{field: bad})).encode())
        tree, path = candidate()
        extra = 'usr/share/man/man6/unindexed.6.gz'
        tree['entries'][extra] = dict(tree['entries'][path], hardlink_anchor=extra, mode=0o666)
        rehash(tree)
        with self.assertRaises(ValueError):
            sources.prepare({'var/cache/man/index.db': index()}, tree, tree)

    def test_capture_requires_complete_exact_bytes_and_cannot_claim_interpretation(self):
        request = packet()
        value = dict(profile=sources.PROFILE, manifest_sha256=hashlib.sha256(request).hexdigest(),
                     files={'man6/sl.6.gz': ''}, source_files=1, source_bytes=0,
                     all_file_stat_fields_verified=True, source_content_interpreted=False,
                     changes_authorized=False, publication_authorized=False)
        report = sources.validate_capture(request, json.dumps(value).encode())
        self.assertEqual(report['source_files'], 1)
        self.assertTrue(report['all_captured_content_hashes_match'])
        for field, bad in (('files', {}), ('files', {'/etc/shadow': ''}),
                           ('source_files', True), ('source_bytes', True),
                           ('manifest_sha256', 'a'*64), ('all_file_stat_fields_verified', False),
                           ('source_content_interpreted', True), ('changes_authorized', True),
                           ('publication_authorized', True)):
            changed = dict(value, **{field: bad})
            with self.subTest(field=field), self.assertRaises(ValueError):
                sources.validate_capture(request, json.dumps(changed).encode())
        with patch.object(sources, 'MAX_OUTPUT_BYTES', 0), self.assertRaises(ValueError):
            sources.validate_capture(request, json.dumps(value).encode())

    def test_capture_rejects_changed_content_and_noncanonical_base64_padding(self):
        request = json.loads(packet())
        request['files']['man6/sl.6.gz'].update(bytes=1, sha256=hashlib.sha256(b'f').hexdigest())
        encoded = json.dumps(request).encode()
        value = dict(profile=sources.PROFILE, manifest_sha256=hashlib.sha256(encoded).hexdigest(),
                     files={'man6/sl.6.gz': 'Zg=='}, source_files=1, source_bytes=1,
                     all_file_stat_fields_verified=True, source_content_interpreted=False,
                     changes_authorized=False, publication_authorized=False)
        sources.validate_capture(encoded, json.dumps(value).encode())
        for data in ('Zw==', 'Zh==', '???'):
            value['files']['man6/sl.6.gz'] = data
            with self.subTest(data=data), self.assertRaises(ValueError):
                sources.validate_capture(encoded, json.dumps(value).encode())

    def test_manifest_is_rebuilt_from_actual_record_and_observed_source_metadata(self):
        value = sources.manifest(packet())
        self.assertEqual(list(value['files']), ['man6/sl.6.gz'])
        self.assertEqual(value['files']['man6/sl.6.gz']['sha256'],
                         hashlib.sha256(b'').hexdigest())
        tree, path = candidate()
        tree['entries'][path]['sha256'] = 'b'*64
        with self.assertRaises(ValueError):
            sources.prepare({'var/cache/man/index.db': index()}, tree, tree)
        rehash(tree)
        altered = sources.prepare({'var/cache/man/index.db': index()}, tree, tree)
        self.assertNotEqual(packet(), altered)

    def test_unbound_source_has_no_implicit_read_fallback(self):
        tree, path = candidate()
        tree['entries'].pop(path)
        rehash(tree)
        with self.assertRaises(ValueError):
            sources.prepare({'var/cache/man/index.db': index()}, tree, tree)

    def test_manifest_rejects_duplicate_fields_and_malformed_hashes_and_types(self):
        good = json.loads(packet())
        key = 'man6/sl.6.gz'
        for field, value in (('uid', 6), ('uid', True), ('mode', 0o666), ('mode', 0o4755),
                             ('nlink', 0), ('bytes', True), ('bytes', -1),
                             ('mtime_ns', 2**63), ('gid', -1), ('sha256', 'x'),
                             ('observed_metadata_sha256', 'x')):
            changed = copy.deepcopy(good)
            changed['files'][key][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                sources.manifest(json.dumps(changed).encode())
        duplicate = packet().decode().replace('"profile":', '"profile":"wrong","profile":')
        for bad in (b'[]', b'{}', duplicate.encode(), packet()+b'{}'):
            with self.subTest(bad=bad[:30]), self.assertRaises(ValueError):
                sources.manifest(bad)

    def test_path_components_cannot_escape_or_be_normalized_before_traversal(self):
        for path in ('/etc/shadow', '../secret', 'man1/../secret', 'man1//page',
                     'man1/./page', 'man1/x\0', 'man1/x\n', 'man1/x\\y', 'x'*256):
            with self.subTest(path=path), self.assertRaises(ValueError):
                sources.relative_path(path)
        self.assertEqual(sources.relative_path('de.UTF-8/man6/sl.6.gz'),
                         ['de.UTF-8', 'man6', 'sl.6.gz'])

    def test_file_count_manifest_serialization_and_aggregate_byte_budgets(self):
        raw = packet()
        for limit in ('MAX_FILES', 'MAX_MANIFEST_BYTES'):
            with patch.object(sources, limit, 0), self.assertRaises(ValueError):
                sources.manifest(raw)
        value = json.loads(raw)
        value['files']['man6/sl.6.gz']['bytes'] = 1
        with patch.object(sources, 'MAX_TOTAL_BYTES', 0), self.assertRaises(ValueError):
            sources.manifest(json.dumps(value).encode())
        with patch.object(sources, 'MAX_FILE_BYTES', 0), self.assertRaises(ValueError):
            sources.manifest(json.dumps(value).encode())

    def test_descriptor_reader_retains_exact_binary_bytes_without_interpretation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'fixture'
            raw = b'\x1f\x8bnot-a-gzip-stream\0\xff.so /etc/shadow\n'
            path.write_bytes(raw)
            fd = os.open(path, os.O_RDONLY)
            try:
                expected = dict(sources.observed(os.fstat(fd)),
                                sha256=hashlib.sha256(raw).hexdigest())
                self.assertEqual(sources.read_file(fd, expected), raw)
            finally:
                os.close(fd)

    def test_changed_metadata_hash_and_growth_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'fixture'
            path.write_bytes(b'original')
            fd = os.open(path, os.O_RDONLY)
            try:
                expected = dict(sources.observed(os.fstat(fd)),
                                sha256=hashlib.sha256(b'original').hexdigest())
                changed = dict(expected, mtime_ns=expected['mtime_ns']+1)
                with self.assertRaises(ValueError):
                    sources.read_file(fd, changed)
                with self.assertRaises(ValueError):
                    sources.read_file(fd, dict(expected, sha256='a'*64))
                os.lseek(fd, 0, os.SEEK_SET)
                original_read = os.read
                grew = False

                def grow(open_fd, size):
                    nonlocal grew
                    raw = original_read(open_fd, size)
                    if not grew:
                        with path.open('ab') as stream:
                            stream.write(b'x')
                        grew = True
                    return raw

                with patch.object(sources.os, 'read', side_effect=grow), \
                        self.assertRaises(ValueError):
                    sources.read_file(fd, expected)
            finally:
                os.close(fd)

    def test_leaf_parent_symlinks_and_fifo_cannot_redirect_or_block_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'target').write_bytes(b'fixture')
            (root/'link').symlink_to('target')
            (root/'parent').symlink_to('.')
            os.mkfifo(root/'fifo')
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            expected = dict(sources.observed((root/'target').stat()), sha256='a'*64)
            try:
                for path in ('link', 'parent/target', 'fifo'):
                    with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                        sources.read_relative(fd, path, expected)
                os.fstat(fd)  # The caller-owned root descriptor remains open.
            finally:
                os.close(fd)

    def test_fixed_worker_refuses_host_execution_before_reading_any_paths(self):
        with patch.object(sources.sys, 'platform', 'darwin'), \
                patch.object(sources.os, 'open', side_effect=AssertionError('host path read')):
            with self.assertRaises(PermissionError):
                sources.main()
