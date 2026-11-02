"""Hand-built ELF data fixtures only; no native executable/library loading."""
import base64
import hashlib
import struct
import unittest
from unittest.mock import patch

from mano_runtime import package_man_compression_table as tables


def fixture(extensions=(b'gz', b'xz')):
    raw = bytearray(4096)
    ident = b'\x7fELF\x02\x01\x01'+b'\0'*9
    struct.pack_into('<16sHHIQQQIHHHHHH', raw, 0, ident, 3, 62, 1, 0, 64, 2048,
                     0, 64, 56, 2, 64, 7, 6)
    struct.pack_into('<IIQQQQQQ', raw, 64, 1, 4, 0, 0x1000, 0, 1024, 1024, 4096)
    struct.pack_into('<IIQQQQQQ', raw, 120, 1, 6, 1024, 0x3000, 0, 512, 512, 4096)
    raw[256:267] = b'\0comp_list\0'
    size = (len(extensions)+1)*24
    struct.pack_into('<IBBHQQ', raw, 344, 1, 17, 0, 4, 0x3000, size)
    strings = bytearray()
    for index, extension in enumerate(extensions):
        program_address = 0x1200+len(strings)
        strings.extend(b'fixture-decoder -dc\0')
        extension_address = 0x1200+len(strings)
        strings.extend(extension+b'\0')
        address = 0x3000+index*24
        struct.pack_into('<QQQ', raw, 1024+index*24, program_address, extension_address, 0)
        struct.pack_into('<QQq', raw, 768+index*48, address, 8, program_address)
        struct.pack_into('<QQq', raw, 792+index*48, address+8, 8, extension_address)
    raw[512:512+len(strings)] = strings
    sections = (
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (0, 3, 2, 0x1100, 256, 11, 0, 0, 1, 0),
        (0, 11, 2, 0x1140, 320, 48, 1, 1, 8, 24),
        (0, 1, 2, 0x1200, 512, len(strings), 0, 0, 1, 0),
        (0, 1, 3, 0x3000, 1024, size, 0, 0, 8, 0),
        (0, 4, 2, 0x1300, 768, len(extensions)*48, 2, 0, 8, 24),
        (0, 3, 0, 0, 1600, 1, 0, 0, 1, 0),
    )
    for index, section in enumerate(sections):
        struct.pack_into('<IIQQQQIIQQ', raw, 2048+index*64, *section)
    return bytes(raw)


class CompressionTableTests(unittest.TestCase):
    def test_configured_order_and_inert_program_bytes_are_bound_to_library(self):
        raw = fixture()
        result = tables.decode(raw)
        self.assertEqual(result['configured_extensions'], ['gz', 'xz'])
        self.assertEqual(result['library_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertTrue(result['static_initializers_verified'])
        self.assertEqual(base64.b64decode(result['rows'][0]['program_base64']),
                         b'fixture-decoder -dc')
        for key in ('library_loaded_or_executed', 'runtime_loader_symbol_resolution_verified',
                    'program_search_paths_verified', 'program_execution_authorized',
                    'source_reference_resolution_verified', 'publication_authorized'):
            self.assertIs(result[key], False)

    def test_no_compiled_extensions_remains_a_valid_empty_configuration(self):
        result = tables.decode(fixture(()))
        self.assertEqual(result['configured_extensions'], [])
        self.assertEqual(result['rows'], [])

    def test_malformed_elf_ranges_symbols_and_relocations_refuse(self):
        def packed(fmt, offset, value):
            def mutate(raw):
                struct.pack_into(fmt, raw, offset, value)
            return mutate

        mutations = (
            packed('<B', 4, 1), packed('<H', 18, 183), packed('<Q', 32, 4090),
            packed('<Q', 40, 4090), packed('<H', 60, 257),
            packed('<B', 348, 18), packed('<B', 349, 1), packed('<H', 350, 0),
            packed('<Q', 360, 71), packed('<Q', 360, 1000),
            packed('<Q', 1024+16, 1), packed('<Q', 768+8, 9),
            packed('<Q', 768+16, 0), packed('<Q', 792, 0x3000),
            packed('<Q', 1024, 0x3000), packed('<Q', 768+16, 0x3000),
            packed('<I', 2048+5*64+4, 19),
            packed('<Q', 2048+2*64+32, 47),
            lambda raw: raw.__setitem__(slice(257, 266), b'not_table'),
            lambda raw: raw.__setitem__(slice(1024, 1048), b'\0'*24),
            lambda raw: raw.__setitem__(slice(1072, 1096), b'x'*24),
        )
        for mutate in mutations:
            changed = bytearray(fixture())
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                tables.decode(bytes(changed))

    def test_extra_relocation_to_null_stem_is_not_ignored(self):
        raw = bytearray(fixture())
        struct.pack_into('<Q', raw, 2048+5*64+32, 120)
        struct.pack_into('<QQq', raw, 864, 0x3010, 8, 0)
        with self.assertRaises(ValueError):
            tables.decode(bytes(raw))

    def test_duplicate_or_unbounded_extensions_and_resource_budgets_refuse(self):
        for extensions in ((b'gz', b'gz'), (b'x'*9,), (b'../x',)):
            with self.subTest(extensions=extensions), self.assertRaises(ValueError):
                tables.decode(fixture(extensions))
        for name in ('MAX_LIBRARY_BYTES', 'MAX_SECTIONS', 'MAX_SYMBOLS', 'MAX_RELOCATIONS'):
            with patch.object(tables, name, 0), self.assertRaises(ValueError):
                tables.decode(fixture())
        for raw in (b'', bytearray(fixture()), 'ELF', fixture()[:64], fixture()[:2200]):
            with self.subTest(raw_type=type(raw)), self.assertRaises(ValueError):
                tables.decode(raw)
