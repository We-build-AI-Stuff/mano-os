import hashlib
import struct
import unittest
from unittest.mock import patch

from mano_runtime import package_loader_cache as cache


def fixture(*, generator=b'fixture generator'):
    strings = b'/usr/lib/libfixture.so.1\0'
    raw = bytearray(cache.MAGIC+struct.pack('<II',1,len(strings))+b'\x02\0\0\0'+b'\0'*16)
    # SONAME legitimately shares a suffix of the full pathname string.
    raw.extend(struct.pack('<iIIIQ',771,72+len(b'/usr/lib/'),72,0,0))
    raw.extend(strings)
    if generator is not None:
        raw.extend(b'\0'*((-len(raw))%4))
        offset=len(raw)
        struct.pack_into('<I',raw,32,offset)
        raw.extend(struct.pack('<IIIIII',cache.EXTENSION_MAGIC,1,0,0,offset+24,len(generator)))
        raw.extend(generator)
    return bytes(raw)


def changed(raw, offset, fmt, *values):
    data=bytearray(raw)
    struct.pack_into(fmt,data,offset,*values)
    return bytes(data)


class LoaderCacheTests(unittest.TestCase):
    def test_structural_decode_and_shared_suffix_strings_do_not_verify_libraries(self):
        result=cache.observe(fixture())
        self.assertEqual(result['entries'],[
            dict(flags=771,soname='libfixture.so.1',path='/usr/lib/libfixture.so.1')])
        self.assertEqual(len(result['extensions']),1)
        self.assertTrue(result['cache_entries_decoded'])
        for key in ('entry_flags_interpreted','generator_identity_verified',
                    'library_objects_verified','cache_regeneration_verified',
                    'changes_authorized','publication_authorized'):
            self.assertFalse(result[key])
        self.assertEqual(cache.observe(fixture(generator=None))['extensions'],[])

    def test_header_format_reserved_endian_and_count_bounds(self):
        raw=fixture()
        for data in (b'not a cache',raw[:47],b'other'+raw[5:],
                     changed(raw,28,'B',3),changed(raw,29,'B',1),changed(raw,36,'I',1),
                     changed(raw,20,'I',2**32-1),changed(raw,24,'I',2**32-1)):
            with self.subTest(data=data[:48]),self.assertRaises(ValueError):
                cache.observe(data)

    def test_string_offsets_must_refer_to_string_table_not_header_entry_or_extension(self):
        raw=fixture()
        extension=struct.unpack_from('<I',raw,32)[0]
        for offset in (0,48,extension,len(raw),2**32-1):
            with self.subTest(offset=offset),self.assertRaises(ValueError):
                cache.observe(changed(raw,52,'I',offset))

    def test_unterminated_non_utf8_or_control_strings_and_noncanonical_paths(self):
        raw=fixture(generator=None)
        for data in (raw[:-1]+b'x',
                     raw.replace(b'libfixture',b'libfi\xffture'),
                     raw.replace(b'libfixture',b'libfi\nture'),
                     raw.replace(b'/usr/lib/',b'/usr/../'),
                     raw.replace(b'/usr/lib/',b'./usr/lib')):
            with self.subTest(data=data),self.assertRaises(ValueError):
                cache.observe(data)

    def test_c_string_terminator_changes_observed_name_without_blessing_unreferenced_bytes(self):
        raw=fixture(generator=None).replace(b'libfixture',b'libfi\0ture')
        result=cache.observe(raw)
        self.assertEqual(result['entries'][0]['soname'],'libfi')
        self.assertEqual(result['entries'][0]['path'],'/usr/lib/libfi')
        self.assertFalse(result['all_cache_bytes_semantically_verified'])
        self.assertFalse(result['changes_authorized'])

    def test_hwcaps_osversion_and_unmodeled_trailing_bytes_require_another_policy(self):
        raw=fixture()
        for data in (changed(raw,60,'I',1),changed(raw,64,'Q',1),
                     fixture(generator=None)+b'trailing'):
            with self.subTest(data=data[:72]),self.assertRaises(ValueError):
                cache.observe(data)

    def test_extension_magic_alignment_flags_overlap_unknown_tags_and_truncation(self):
        raw=fixture()
        offset=struct.unpack_from('<I',raw,32)[0]
        for data in (changed(raw,32,'I',offset+1),changed(raw,offset,'I',0),
                     changed(raw,offset+4,'I',2),changed(raw,offset+8,'I',1),
                     changed(raw,offset+12,'I',1),changed(raw,offset+16,'I',48),
                     changed(raw,offset+20,'I',2**32-1),raw[:-1]):
            with self.subTest(data=data[:48]),self.assertRaises(ValueError):
                cache.observe(data)

    def test_byte_entry_and_expanded_string_quotas(self):
        for name,value in (('MAX_BYTES',48),('MAX_ENTRIES',0),('MAX_EXPANDED_STRINGS',1)):
            with self.subTest(name=name), patch.object(cache,name,value), \
                    self.assertRaises(ValueError):
                cache.observe(fixture())


    def test_fixed_cache_binding_rejects_alias_metadata_and_bytes_without_library_approval(self):
        raw=fixture()
        path='etc/ld.so.cache'
        row=dict(kind='file',uid=0,gid=0,mode=0o644,nlink=1,bytes=len(raw),
                 sha256=hashlib.sha256(raw).hexdigest(),xattrs={},hardlink_anchor=path)
        tree={'entries':{path:row}}
        result=cache.bind_pair(raw,raw,tree,tree)
        self.assertTrue(result['cache_bytes_bound_to_tree'])
        self.assertFalse(result['library_objects_verified'])
        self.assertFalse(result['changes_authorized'])
        for field,value in (('kind','symlink'),('uid',False),('gid',1),('mode',0o666),
                            ('nlink',2),('bytes',0),('sha256','0'*64),
                            ('xattrs',{'user.extra':{}}),('hardlink_anchor','elsewhere')):
            with self.subTest(field=field),self.assertRaises(ValueError):
                cache.bind_pair(raw,raw,tree,{'entries':{path:row|{field:value}}})

        with patch.object(cache,'MAX_BYTES',48), patch.object(cache.hashlib,'sha256') as digest:
            with self.assertRaises(ValueError):
                cache.bind_pair(raw,raw,tree,tree)
            digest.assert_not_called()
