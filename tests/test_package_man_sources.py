import base64
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from test_package_man_records import database, record

from mano_runtime import package_man_sources as sources


def candidate(*, locale='', link=False, mtime=5000000009):
    root = 'usr/share/man' + ('/'+locale if locale else '')
    path = root+'/man6/sl.6.gz'
    entries = {'.':dict(kind='directory', uid=0, gid=0, mode=0o755, mtime_ns=0,
                       ctime_ns=0, nlink=2, xattrs={})}
    parts = path.split('/')
    for i in range(1, len(parts)):
        entries['/'.join(parts[:i])] = dict(entries['.'])
    row = dict(kind='file', uid=0, gid=0, mode=0o644, mtime_ns=mtime, ctime_ns=1,
               nlink=1, xattrs={}, hardlink_anchor=path, bytes=0,
               sha256=hashlib.sha256(b'').hexdigest())
    if link:
        row = dict(kind='symlink', uid=0, gid=0, mode=0o777, mtime_ns=mtime, ctime_ns=1,
                   nlink=1, xattrs={}, target='../../../../outside-not-read')
    entries[path] = row
    result = dict(schema_version='1.0', entries=entries, excluded_subtrees=['.snapshots'])
    rehash(result)
    return result, path


def rehash(tree):
    tree['manifest_sha256'] = hashlib.sha256(json.dumps(tree['entries'], sort_keys=True,
        separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def index(kind=b'A', **fields):
    return database({b'sl\0':record(kind=kind, sec=b'5', nano=b'9', **fields)})


class PrimaryManSourcesTests(unittest.TestCase):
    def test_direct_record_binds_exact_path_and_primary_lstat_time(self):
        tree, path = candidate()
        result = sources.bind({'var/cache/man/index.db':index()}, tree)
        self.assertEqual(result['primary_records_bound'], 1)
        self.assertTrue(result['all_primary_records_bound'])
        row = next(iter(result['indexes']['var/cache/man/index.db']['records'].values()))
        self.assertEqual(row['primary_path'], path)
        self.assertTrue(row['primary_lstat_timestamp_bound'])
        for flag in ('transitive_source_graph_verified', 'descriptions_verified',
                     'compression_filters_verified', 'all_records_source_bound',
                     'cache_sources_verified', 'generated_state_validated',
                     'changes_authorized', 'publication_authorized'):
            self.assertIs(result[flag], False)

    def test_locale_maps_only_inside_fixed_manual_hierarchy(self):
        tree, path = candidate(locale='de.UTF-8')
        result = sources.bind({'var/cache/man/de.UTF-8/index.db':index()}, tree)
        self.assertTrue(result['all_primary_records_bound'])
        row = next(iter(result['indexes']['var/cache/man/de.UTF-8/index.db']['records'].values()))
        self.assertEqual(row['primary_path'], path)
        for wrong in ('var/cache/man/../index.db', 'var/cache/man/de/x/index.db', '/tmp/index.db'):
            with self.assertRaises(ValueError):
                sources.bind({wrong:index()}, tree)

    def test_link_uses_its_own_lstat_time_without_reading_its_target(self):
        tree, _ = candidate(link=True)
        result = sources.bind({'var/cache/man/index.db':index(kind=b'B')}, tree)
        self.assertTrue(result['all_primary_records_bound'])
        self.assertFalse(result['transitive_source_graph_verified'])
        self.assertFalse(result['all_records_source_bound'])

    def test_virtual_alias_names_and_pointers_never_become_source_paths(self):
        tree, _ = candidate()
        data = database({b'/etc/shadow\0':record(name=b'/etc/shadow', kind=b'C',
            pointer=b'../../etc/shadow')})
        result = sources.bind({'var/cache/man/index.db':data}, tree)
        self.assertEqual(result['virtual_or_cat_records'], 1)
        self.assertEqual(result['primary_records'], 0)
        self.assertFalse(result['all_primary_records_bound'])
        row = next(iter(result['indexes']['var/cache/man/index.db']['records'].values()))
        self.assertNotIn('primary_path', row)

    def test_modified_source_time_missing_file_or_aliased_parent_stays_unbound(self):
        original, path = candidate()
        for mutation in ('time', 'missing', 'parent', 'owner', 'mode', 'unknown-time'):
            tree = copy.deepcopy(original)
            raw = index()
            if mutation == 'time':
                tree['entries'][path]['mtime_ns'] += 1
            elif mutation == 'missing':
                tree['entries'].pop(path)
            elif mutation == 'parent':
                tree['entries']['usr/share/man/man6'] = dict(kind='symlink', target='/outside')
            elif mutation == 'owner':
                tree['entries'][path]['uid'] = True
            elif mutation == 'mode':
                tree['entries'][path]['mode'] = 0o666
            else:
                raw = database({b'sl\0':record(sec=b'-1', nano=b'-1')})
            rehash(tree)
            result = sources.bind({'var/cache/man/index.db':raw}, tree)
            with self.subTest(mutation=mutation):
                self.assertFalse(result['all_primary_records_bound'])
                self.assertEqual(result['primary_records_bound'], 0)

    def test_absolute_or_traversal_names_never_escape_the_manual_root(self):
        tree, _ = candidate()
        for name in (b'/etc/shadow', b'../sl', b'..', b'bad\nname', b'bad\\name', b'\xff'):
            data = database({name+b'\0':record()})
            result = sources.bind({'var/cache/man/index.db':data}, tree)
            row = next(iter(result['indexes']['var/cache/man/index.db']['records'].values()))
            self.assertFalse(row['primary_metadata_bound'])
            self.assertNotIn('primary_path', row)

    def test_changed_observation_and_aggregate_budgets_reject(self):
        tree, path = candidate()
        for limit in ('MAX_DATABASES', 'MAX_TOTAL_BYTES', 'MAX_RECORDS', 'MAX_REPORT_BYTES'):
            with patch.object(sources, limit, 0), self.assertRaises(ValueError):
                sources.bind({'var/cache/man/index.db':index()}, tree)
        tree['entries'][path]['mtime_ns'] += 1
        with self.assertRaisesRegex(ValueError, 'integrity'):
            sources.bind({'var/cache/man/index.db':index()}, tree)

    def test_full_primary_metadata_digest_tracks_changes_without_claiming_content_read(self):
        tree, path = candidate()
        first = sources.bind({'var/cache/man/index.db':index()}, tree)
        tree['entries'][path]['sha256'] = 'a'*64
        rehash(tree)
        second = sources.bind({'var/cache/man/index.db':index()}, tree)
        key = base64.b64encode(b'sl\0').decode()
        a = first['indexes']['var/cache/man/index.db']['records'][key]
        b = second['indexes']['var/cache/man/index.db']['records'][key]
        self.assertTrue(a['primary_metadata_bound'] and b['primary_metadata_bound'])
        self.assertNotEqual(a['observed_metadata_sha256'], b['observed_metadata_sha256'])
        self.assertFalse(second['cache_sources_verified'])
