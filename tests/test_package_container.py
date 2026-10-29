import hashlib
import unittest

from mano_runtime import package_container as container


def ar(members):
    result = b'!<arch>\n'
    for name, content in members:
        header = (name.ljust(16) + '0'.ljust(12) + '0'.ljust(6) +
                  '0'.ljust(6) + '100644'.ljust(8) + str(len(content)).ljust(10) + '`\n')
        result += header.encode('ascii') + content + (b'\n' if len(content) % 2 else b'')
    return result


class PackageContainerTests(unittest.TestCase):
    def bind(self, raw, **changes):
        args = dict(expected_sha256=hashlib.sha256(raw).hexdigest(), expected_bytes=len(raw))
        return container.bind(raw, **(args | changes))

    def normal(self, data='data.tar.xz', control='control.tar.xz'):
        # Framing tests deliberately do not claim these synthetic bytes are tar.
        return ar([('debian-binary', b'2.0\n'), (control, b'control'), (data, b'payload')])

    def test_exact_archive_binds_offsets_and_hashes_without_tar_or_signature_claim(self):
        raw = self.normal()
        result = self.bind(raw)
        self.assertTrue(result['expected_identity_matched'])
        for member in result['members']:
            data = raw[member['offset']:member['offset']+member['bytes']]
            self.assertEqual(hashlib.sha256(data).hexdigest(), member['sha256'])
        self.assertEqual(raw[result['data']['offset']:][:7], b'payload')
        for key in ('archive_signature_verified', 'payload_inventory_verified',
                    'candidate_filesystem_verified', 'publication_authorized'):
            self.assertIs(result[key], False)

    def test_all_documented_control_and_payload_compression_names_are_preserved(self):
        for data in container.DATA:
            for control in container.CONTROL:
                with self.subTest(data=data, control=control):
                    result = self.bind(self.normal(data, control))
                    self.assertEqual(result['data']['name'], data)
                    self.assertEqual(result['control']['name'], control)

    def test_whole_archive_identity_is_checked_before_container_parsing(self):
        with self.assertRaisesRegex(ValueError, 'expected identity'):
            self.bind(b'not an archive', expected_sha256='0' * 64)

    def test_mutable_bytes_size_mismatch_and_invalid_expected_identity_fail(self):
        raw = self.normal()
        cases = [dict(expected_bytes=True), dict(expected_bytes=len(raw)+1),
                 dict(expected_sha256='A'*64)]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.bind(raw, **changes)
        with self.assertRaises(ValueError):
            self.bind(bytearray(raw))

    def test_member_order_duplicates_missing_members_and_unknown_required_fail(self):
        cases = [[('control.tar', b'x'), ('debian-binary', b'2.0\n'), ('data.tar', b'x')],
                 [('debian-binary', b'2.0\n'), ('data.tar', b'x')],
                 [('debian-binary', b'2.0\n'), ('control.tar', b'x'), ('control.tar', b'y')],
                 [('debian-binary', b'2.0\n'), ('unknown', b'x'),
                  ('control.tar', b'x'), ('data.tar', b'y')]]
        for members in cases:
            with self.subTest(members=members), self.assertRaises(ValueError):
                self.bind(ar(members))

    def test_underscore_extensions_and_trailing_members_are_recorded(self):
        raw = ar([('debian-binary/', b'2.1\nfuture\n'), ('_future', b'x'),
                  ('control.tar/', b'y'), ('data.tar/', b'z'), ('future', b'any')])
        self.assertEqual(self.bind(raw)['additional_members'], ['_future', 'future'])

    def test_trailing_known_names_are_opaque_after_the_required_payload(self):
        raw = ar([('debian-binary', b'2.0\n'), ('control.tar', b'x'),
                  ('data.tar', b'y'), ('control.tar.xz', b'opaque'),
                  ('data.tar.gz', b'also opaque')])
        result = self.bind(raw)
        self.assertEqual(result['control']['name'], 'control.tar')
        self.assertEqual(result['data']['name'], 'data.tar')
        self.assertEqual(result['additional_members'], ['control.tar.xz', 'data.tar.gz'])

    def test_incompatible_version_invalid_padding_and_truncation_fail(self):
        wrong_version = ar([('debian-binary', b'3.0\n'), ('control.tar', b'x'),
                            ('data.tar', b'y')])
        raw = self.normal()
        cases = [wrong_version, raw[:-1], raw[:-4], raw+b'x',
                 raw[:7]+b'x'+raw[8:], raw[:-1]+b'x']
        for value in cases:
            with self.subTest(value=value[-20:]), self.assertRaises(ValueError):
                self.bind(value)

    def test_long_path_and_symbol_table_ar_extensions_fail(self):
        for name in ('../data.tar', '#1/8', '/', '//'):
            raw = ar([('debian-binary', b'2.0\n'), (name, b'x'), ('data.tar', b'y')])
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.bind(raw)

    def test_invalid_numeric_header_is_rejected_after_identity_check(self):
        raw = self.normal()
        for offset in (24, 36, 42, 48, 56):
            changed = raw[:offset]+b'x'+raw[offset+1:]
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, 'numeric'):
                self.bind(changed)

    def test_count_budget_and_revocation_are_enforced(self):
        raw = ar([('debian-binary', b'2.0\n'), ('control.tar', b'x'), ('data.tar', b'y')]
                 + [(f'extra{i}', b'x') for i in range(container.MAX_MEMBERS)])
        with self.assertRaisesRegex(ValueError, 'count budget'):
            self.bind(raw)

        def revoke():
            raise PermissionError('revoked')

        with self.assertRaisesRegex(PermissionError, 'revoked'):
            self.bind(self.normal(), checkpoint=revoke)
        with self.assertRaisesRegex(ValueError, 'Callable'):
            self.bind(self.normal(), checkpoint=False)
