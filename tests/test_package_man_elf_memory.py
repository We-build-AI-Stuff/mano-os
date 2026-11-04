"""Hand-built byte fixtures only; no host ELF loading or native execution."""
import hashlib
import struct
import unittest
from unittest.mock import patch

from mano_runtime import package_man_elf_memory as memory


def fixture(*, interpreter=b'/lib64/ld-linux-x86-64.so.2\0', kind=3):
    raw = bytearray(4096)
    count = 4 if interpreter is not None else 3
    struct.pack_into('<16sHHIQQQIHHHHHH', raw, 0, b'\x7fELF\x02\x01\x01'+b'\0'*9,
                     kind, 62, 1, 0x200, 64, 0, 0, 64, 56, count, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 0, 0, 2048, 2048, 4096)
    struct.pack_into('<IIQQQQQQ', raw, 120, 1, 6, 2048, 6144, 0, 2048, 4096, 4096)
    struct.pack_into('<IIQQQQQQ', raw, 176, 0x6474e551, 6, 0, 0, 0, 0, 0, 16)
    if interpreter is not None:
        raw[400:400+len(interpreter)] = interpreter
        struct.pack_into('<IIQQQQQQ', raw, 232, 3, 4, 400, 400, 0,
                         len(interpreter), len(interpreter), 1)
    return bytes(raw)


class ElfMemoryDeclarationTests(unittest.TestCase):
    def test_native_pie_executable_and_shared_object_declarations_without_runtime_claim(self):
        for kind in (2, 3):
            for interpreter in (None, b'/lib64/ld-linux-x86-64.so.2\0'):
                raw = fixture(kind=kind, interpreter=interpreter)
                result = memory.inspect(raw)
                self.assertEqual(result['raw_sha256'], hashlib.sha256(raw).hexdigest())
                self.assertEqual(result['raw_bytes'], len(raw))
                self.assertEqual(result['elf_type'], kind)
                self.assertTrue(result['nonexecutable_stack_declared'])
                self.assertFalse(result['writable_executable_load_declared'])
                for key in ('complete_elf_validity_verified', 'interpreter_resolution_verified',
                            'across_exec_personality_verified', 'complete_runtime_closure_verified',
                            'publication_authorized'):
                    self.assertIs(result[key], False)

    def test_executable_missing_duplicate_or_ambiguous_stack_is_refused(self):
        for flags in (0, 1, 4, 5, 7, 0x10000006):
            raw = bytearray(fixture())
            struct.pack_into('<I', raw, 180, flags)
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                memory.inspect(bytes(raw))
        for tag in (0, 1):
            raw = bytearray(fixture())
            struct.pack_into('<I', raw, 176, tag)
            with self.assertRaises(ValueError):
                memory.inspect(bytes(raw))
        raw = bytearray(fixture())
        raw[232:288] = raw[176:232]
        with self.assertRaises(ValueError):
            memory.inspect(bytes(raw))

    def test_writable_executable_segments_unknown_flags_or_no_loads_are_refused(self):
        for flags in (3, 7, 0x10000005):
            raw = bytearray(fixture())
            struct.pack_into('<I', raw, 68, flags)
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                memory.inspect(bytes(raw))
        raw = bytearray(fixture())
        struct.pack_into('<I', raw, 64, 0)
        struct.pack_into('<I', raw, 120, 0)
        with self.assertRaises(ValueError):
            memory.inspect(bytes(raw))

    def test_compatibility_abi_unknown_format_extended_header_and_quota_refuse(self):
        for offset, fmt, value in ((4, 'B', 1), (5, 'B', 2), (6, 'B', 2), (7, 'B', 9),
                (8, 'B', 1), (18, '<H', 3), (16, '<H', 1), (20, '<I', 2),
                (48, '<I', 1), (52, '<H', 0), (54, '<H', 48), (56, '<H', 0),
                (56, '<H', 65535), (32, '<Q', 0), (32, '<Q', 4090)):
            raw = bytearray(fixture())
            struct.pack_into(fmt, raw, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                memory.inspect(bytes(raw))
        for raw in (b'', b'\0'*63, bytearray(fixture()), fixture().decode('latin1')):
            with self.assertRaises(ValueError):
                memory.inspect(raw)
        with patch.object(memory, 'MAX_FILE_BYTES', 64), self.assertRaises(ValueError):
            memory.inspect(fixture())

    def test_out_of_file_overflow_misaligned_and_oversized_memory_ranges_refuse(self):
        for offset, value in ((64+8, 4097), (64+32, 4097), (64+40, 1),
                              (64+16, 2**64-1), (64+48, 3), (64+16, 1)):
            raw = bytearray(fixture())
            struct.pack_into('<Q', raw, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                memory.inspect(bytes(raw))
        with self.assertRaises(ValueError):
            memory.inspect(fixture()[:63])

    def test_interpreter_is_retained_not_resolved_and_malformed_selectors_refuse(self):
        for path in (b'relative\0', b'/../lib/ld.so\0', b'/lib/./ld.so\0', b'/lib//ld.so\0',
                     b'/lib/ld.so', b'/lib/ld.so\0x\0', b'/lib/ld.so\n\0', b'/lib/\xff\0'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                memory.inspect(fixture(interpreter=path))
        raw = bytearray(fixture())
        struct.pack_into('<Q', raw, 232+8, 4090)
        with self.assertRaises(ValueError):
            memory.inspect(bytes(raw))
        raw = bytearray(fixture())
        raw[176:232] = raw[232:288]
        with self.assertRaises(ValueError):
            memory.inspect(bytes(raw))


def baseline(raw):
    from test_package_man_sources import candidate, rehash
    value, old = candidate()
    value['entries']['usr/bin'] = dict(value['entries']['usr'])
    path = 'usr/bin/mandb'
    value['entries'][path] = dict(value['entries'][old], mode=0o755, bytes=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(), hardlink_anchor=path)
    rehash(value)
    return value, path


class ElfMemoryBindingTests(unittest.TestCase):
    def test_exact_baseline_bytes_and_parents_bind_without_selection_or_authority_claim(self):
        raw = fixture()
        tree, path = baseline(raw)
        value = memory.bind(raw, tree, path)
        self.assertEqual(value['declarations'], memory.inspect(raw))
        self.assertEqual(value['file_content_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(set(value['parent_metadata_sha256']), {'.', 'usr', 'usr/bin'})
        self.assertTrue(value['observed_content_matches'])
        for key in ('filesystem_paths_opened', 'collector_authentication_verified',
                    'readonly_source_descriptor_verified', 'actual_worker_selection_verified',
                    'complete_runtime_closure_verified', 'publication_authorized'):
            self.assertIs(value[key], False)

    def test_bad_bytes_mutable_or_changed_metadata_and_numeric_aliases_refuse(self):
        import copy

        from test_package_man_sources import rehash
        raw = fixture()
        original, path = baseline(raw)
        for key, changed in (('bytes', len(raw)-1), ('bytes', float(len(raw))),
                ('sha256', '0'*64), ('uid', False), ('uid', 6), ('mode', 0o777),
                ('gid', 12.0), ('nlink', True), ('nlink', 2), ('hardlink_anchor', '../other'),
                ('xattrs', {'unknown': 'unmodeled'}), ('kind', 'symlink')):
            tree = copy.deepcopy(original)
            tree['entries'][path][key] = changed
            rehash(tree)
            with self.subTest(key=key), self.assertRaises(ValueError):
                memory.bind(raw, tree, path)
        tree = copy.deepcopy(original)
        tree['entries'][path]['sha256'] = '0'*64
        with self.assertRaises(ValueError):
            memory.bind(raw, tree, path)
        with self.assertRaises(ValueError):
            memory.bind(raw[:-1]+b'x', original, path)

    def test_symlink_unsearchable_or_untrusted_parent_never_gets_followed(self):
        import copy

        from test_package_man_sources import rehash
        raw = fixture()
        original, path = baseline(raw)
        for parent in ('.', 'usr', 'usr/bin'):
            for key, changed in (('kind', 'symlink'), ('uid', 6), ('mode', 0o777),
                                 ('mode', 0o700), ('nlink', True)):
                tree = copy.deepcopy(original)
                tree['entries'][parent][key] = changed
                rehash(tree)
                with self.subTest(parent=parent, key=key), self.assertRaises(ValueError):
                    memory.bind(raw, tree, path)
        for path in ('/usr/bin/mandb', './usr/bin/mandb', 'usr/bin/../bin/mandb',
                     'tmp/mandb', 'usr/share/man/mandb', 'usr/bin/mandb/', None):
            with self.subTest(path=path), self.assertRaises(ValueError):
                memory.bind(raw, original, path)

    def test_known_internal_hardlinks_bind_but_external_or_inconsistent_aliases_refuse(self):
        import copy

        from test_package_man_sources import rehash
        raw = fixture()
        tree, path = baseline(raw)
        alias = 'usr/bin/mandb-alias'
        tree['entries'][path]['nlink'] = 2
        tree['entries'][alias] = dict(tree['entries'][path])
        rehash(tree)
        value = memory.bind(raw, tree, path)
        self.assertEqual(value['aliases'], [path, alias])
        for key, changed in (('sha256', '0'*64), ('mode', 0o644), ('uid', 6),
                             ('hardlink_anchor', alias)):
            bad = copy.deepcopy(tree)
            bad['entries'][alias][key] = changed
            rehash(bad)
            with self.subTest(key=key), self.assertRaises(ValueError):
                memory.bind(raw, bad, path)
