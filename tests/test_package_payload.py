import hashlib
import io
import tarfile
import unittest

from mano_runtime import package_payload as payload


def archive(items, *, format=tarfile.GNU_FORMAT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=format) as target:
        for name, kind, data, attributes in items:
            member = tarfile.TarInfo(name)
            member.uid, member.gid, member.mode, member.mtime = 0, 0, 0o755, 123
            member.type = kind
            if kind == tarfile.REGTYPE:
                member.size = len(data)
            else:
                member.linkname = data
            for key, value in attributes.items():
                setattr(member, key, value)
            target.addfile(member, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    output.seek(0)
    return output


def file(name='usr/bin/example', data=b'\x00\xffpayload', **attributes):
    return name, tarfile.REGTYPE, data, attributes


class PackagePayloadTests(unittest.TestCase):
    def test_inventory_records_bytes_metadata_links_and_never_authorizes(self):
        value = payload.inventory(archive([
            ('./', tarfile.DIRTYPE, '', {}), file('./usr/bin/example'),
            ('usr/bin/link', tarfile.SYMTYPE, '/usr/bin/example', {}),
            ('usr/bin/copy', tarfile.LNKTYPE, './usr/bin/example', {}),
        ]))
        entry = value['entries']['usr/bin/example']
        self.assertEqual(entry['sha256'], hashlib.sha256(b'\x00\xffpayload').hexdigest())
        self.assertEqual((entry['bytes'], entry['mode'], entry['uid'], entry['mtime']),
                         (9, 0o755, 0, 123))
        self.assertEqual(value['entries']['usr/bin/link']['target'], '/usr/bin/example')
        self.assertEqual(value['entries']['usr/bin/copy']['content_path'], 'usr/bin/example')
        for key in ('archive_signature_verified','candidate_filesystem_verified',
                    'publication_authorized'):
            self.assertIs(value[key], False)

    def test_forward_hardlink_chain_resolves_without_filesystem_lookup(self):
        value = payload.inventory(archive([
            ('first', tarfile.LNKTYPE, 'second', {}),
            ('second', tarfile.LNKTYPE, 'last', {}), file('last', b'content')]))
        self.assertEqual(value['entries']['first']['content_path'], 'last')
        self.assertEqual(value['entries']['second']['content_path'], 'last')
        self.assertEqual(value['payload_bytes'], 7)

    def test_cycles_missing_and_nonregular_hardlink_targets_are_rejected(self):
        cases = [[('a',tarfile.LNKTYPE,'b',{}), ('b',tarfile.LNKTYPE,'a',{})],
                 [('a',tarfile.LNKTYPE,'missing',{})],
                 [('a',tarfile.LNKTYPE,'dir',{}), ('dir',tarfile.DIRTYPE,'',{})],
                 [('a',tarfile.LNKTYPE,'sym',{}), ('sym',tarfile.SYMTYPE,'file',{})]]
        for items in cases:
            with self.subTest(items=items), self.assertRaises(ValueError):
                payload.inventory(archive(items))

    def test_hardlink_metadata_conflict_is_retained_as_unsupported(self):
        value = payload.inventory(archive([
            file('target'), ('link',tarfile.LNKTYPE,'target',{'mode': 0o600})]))
        self.assertEqual(value['unsupported_metadata']['link'],
                         {'hardlink_metadata_conflict':'true'})

    def test_absolute_traversing_and_ambiguous_paths_are_rejected(self):
        for name in ('/etc/shadow','../escape','usr/../escape','a//b','a/./b','././a'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                payload.inventory(archive([file(name)]))

    def test_duplicate_paths_after_dot_prefix_normalization_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            payload.inventory(archive([file('./same'), file('same')]))

    def test_absolute_directory_root_is_not_normalized_into_relative_root(self):
        for name in ('/', '/etc/'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                payload.inventory(archive([(name, tarfile.DIRTYPE, '', {})]))

    def test_spaces_and_utf8_names_are_preserved_as_literal_data(self):
        value = payload.inventory(archive([file('usr/share/naïve name.txt')]))
        self.assertIn('usr/share/naïve name.txt', value['entries'])

    def test_entry_payload_single_file_and_metadata_quotas_are_independent(self):
        cases = [dict(max_entries=1), dict(max_payload=2), dict(max_file=2),
                 dict(max_metadata=10)]
        for limits in cases:
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                payload.inventory(archive([file('one'),file('two')]), **limits)

    def test_boolean_negative_and_above_ceiling_budgets_are_rejected(self):
        for value in (True,0,-1,payload.MAX_FILE+1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                payload.inventory(archive([]), max_file=value)

    def test_special_device_and_fifo_entries_are_not_blessed_as_regular(self):
        for kind in (tarfile.CHRTYPE,tarfile.BLKTYPE,tarfile.FIFOTYPE):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'Special'):
                payload.inventory(archive([('special',kind,'',{})]))

    def test_unknown_pax_security_metadata_is_preserved_not_authorized(self):
        value = payload.inventory(archive([file('file',pax_headers={
            'SCHILY.xattr.security.capability':'opaque', 'mtime':'123'})],
            format=tarfile.PAX_FORMAT))
        self.assertEqual(value['unsupported_metadata']['file'],
                         {'SCHILY.xattr.security.capability':'opaque'})
        self.assertFalse(value['publication_authorized'])

    def test_archive_order_does_not_change_canonical_manifest_hash(self):
        one = payload.inventory(archive([file('a'),file('b')]))
        two = payload.inventory(archive([file('b'),file('a')]))
        self.assertEqual(one['manifest_sha256'], two['manifest_sha256'])

    def test_revocation_checkpoint_aborts_instead_of_returning_a_manifest(self):
        def revoked():
            raise PermissionError('revoked')
        with self.assertRaisesRegex(PermissionError, 'revoked'):
            payload.inventory(archive([file()]), checkpoint=revoked)

    def test_invalid_false_callback_cannot_silently_disable_interruption_checks(self):
        for callback in (False, 0, [], 'not callable'):
            with self.subTest(callback=callback), self.assertRaisesRegex(ValueError, 'Callable'):
                payload.inventory(archive([file()]), checkpoint=callback)

    def test_truncated_member_is_not_accepted_as_a_shorter_payload(self):
        raw = archive([file(data=b'long content')]).getvalue()
        with self.assertRaises(ValueError):
            payload.inventory(io.BytesIO(raw[:514]))

    def test_member_below_regular_file_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'non-directory'):
            payload.inventory(archive([file('parent'), file('parent/child')]))

    def test_symlink_parent_is_reported_without_following_or_authorizing(self):
        value = payload.inventory(archive([
            ('bin', tarfile.SYMTYPE, 'usr/bin', {}), file('bin/example')]))
        self.assertEqual(value['unsupported_metadata']['bin/example']['symlink_parent'], 'bin')
        self.assertFalse(value['candidate_filesystem_verified'])
        self.assertFalse(value['publication_authorized'])
