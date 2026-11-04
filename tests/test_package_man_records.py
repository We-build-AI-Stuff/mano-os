import base64
import unittest
from unittest.mock import patch

from mano_runtime import package_man_records as frames
from mano_runtime.package_gdbm_encode import encode


def record(**changes):
    fields = dict(name=b'-', ext=b'6', section=b'6', sec=b'1565158510', nano=b'0', kind=b'A',
                  pointer=b'-', filters=b'-', comp=b'gz', description=b'description')
    fields.update(changes)
    return b'\t'.join(fields.values()) + b'\0'


def database(pairs):
    return encode({b'$version$\0':b'2.5.0\0', **pairs})


class ManRecordFrameTests(unittest.TestCase):
    def test_single_record_case_name_and_opaque_fields_roundtrip_without_interpretation(self):
        raw = database({b'ls\0':record(name=b'LS', pointer=b'../../etc/shadow',
            filters=b'|do-not-execute', description=b'one\ttwo\xff\nthree')})
        report = frames.parse(raw)
        row = report['direct_records'][base64.b64encode(b'ls\0').decode()]
        self.assertEqual(base64.b64decode(row['name_base64']), b'LS')
        self.assertEqual(base64.b64decode(row['pointer_base64']), b'../../etc/shadow')
        self.assertEqual(base64.b64decode(row['description_base64']), b'one\ttwo\xff\nthree')
        for key in ('man_index_semantics_verified', 'manual_source_paths_verified',
                    'source_timestamps_verified', 'filters_interpreted', 'pointers_interpreted',
                    'cache_sources_verified', 'changes_authorized', 'publication_authorized'):
            self.assertIs(report[key], False)

    def test_internal_multi_keys_are_case_sensitive_and_all_references_resolve(self):
        pairs = {b'as\0':b'\tAS\t1\tas\t1\0',
                 b'AS\t1\0':record(name=b'AS', ext=b'1', section=b'1'),
                 b'as\t1\0':record(ext=b'1', section=b'1')}
        report = frames.parse(database(pairs))
        self.assertEqual(report['resolved_references'], 2)
        self.assertEqual(len(report['direct_records']), 2)
        self.assertEqual(report['orphan_multi_keys'], [])
        self.assertTrue(report['internal_references_resolved'])
        for changed in ({b'AS\t1\0':None}, {b'AS\t1\0':record(name=b'as', ext=b'1')},
                        {b'AS\t1\0':record(name=b'AS', ext=b'2')},
                        {b'as\0':b'\tas\t1\tas\t1\0'},
                        {b'as\0':b'\tother\t1\0'}, {b'as\0':b'\tas\0'}):
            bad = dict(pairs)
            for key, value in changed.items():
                if value is None:
                    bad.pop(key)
                else:
                    bad[key] = value
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                frames.parse(database(bad))

    def test_record_without_reference_is_exposed_as_an_orphan_not_source_authority(self):
        raw = database({b'as\t1\0':record(ext=b'1')})
        report = frames.parse(raw)
        self.assertEqual(report['orphan_multi_keys'], [base64.b64encode(b'as\t1\0').decode()])
        self.assertFalse(report['cache_sources_verified'])

    def test_version_cstring_and_field_truncation_or_hidden_suffixes_reject(self):
        for pairs in ({b'$version$\0':b'2.4.0\0'}, {b'ls':record()},
                      {b'ls\0':record()[:-1]}, {b'ls\0':record()+b'hidden\0'},
                      {b'ls\0hidden\0':record()}, {b'ls\0':b'few\tfields\0'},
                      {b'\0':record()}, {b'ls\0':record(ext=b'')},
                      {b'a\tb\tc\0':record()}, {b'\t1\0':record()}):
            with self.subTest(pairs=pairs), self.assertRaises(ValueError):
                frames.parse(database(pairs))
        with self.assertRaises(ValueError):
            frames.parse(encode({b'ls\0':record()}))

    def test_timestamp_ranges_decimal_syntax_and_explicit_unknown(self):
        for sec, nano in ((b'-1', b'-1'), (b'-9223372036854775808', b'0'),
                          (b'9223372036854775807', b'999999999')):
            report = frames.parse(database({b'ls\0':record(sec=sec, nano=nano)}))
            row = next(iter(report['direct_records'].values()))
            self.assertEqual((row['mtime_seconds'], row['mtime_nanoseconds']),
                             (int(sec), int(nano)))
            self.assertEqual(row['mtime_known'], (sec, nano) != (b'-1', b'-1'))
        for fields in (dict(sec=b'+1'), dict(sec=b'01'), dict(sec=b'-0'), dict(sec=b'1junk'),
                       dict(sec=b'9223372036854775808'), dict(nano=b'1000000000'),
                       dict(nano=b'-1'), dict(sec=b'-1', nano=b'-2'), dict(nano=b'0.0')):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                frames.parse(database({b'ls\0':record(**fields)}))

    def test_alias_types_binary_names_empty_descriptions_and_name_mismatch(self):
        for kind in (b'A', b'B', b'C', b'D', b'E'):
            frames.parse(database({b'\xff-name\0':record(kind=kind, description=b'')}))
        for fields in (dict(kind=b'F'), dict(kind=b'AA'), dict(name=b'other')):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                frames.parse(database({b'ls\0':record(**fields)}))
        with self.assertRaises(ValueError):
            frames.parse(database({b'LS\0':record()}))

    def test_reference_and_serialization_budgets_reject(self):
        raw = database({b'as\0':b'\tas\t1\0', b'as\t1\0':record(ext=b'1')})
        for limit in ('MAX_LINKS', 'MAX_SERIALIZED'):
            with patch.object(frames, limit, 0), self.assertRaises(ValueError):
                frames.parse(raw)
