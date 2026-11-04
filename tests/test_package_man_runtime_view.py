"""Synthetic mountinfo/FD witnesses; never inspect this Mac's mounts or Linux state."""
import base64
import contextlib
import copy
import hashlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mano_runtime import package_man_runtime_view as view
from mano_runtime.package_man_runtime_origin import identity


def mount_field(raw):
    return dict(base64=base64.b64encode(raw).decode(), bytes=len(raw),
                sha256=hashlib.sha256(raw).hexdigest())


def fixture(extra=b''):
    # VFS ro bind over a rw superblock is still read-only. Private writable
    # cache/tmp and /run ancestors do not make the injected ro code mounts rw.
    raw = (b'1 0 0:1 / / ro - ext4 /dev/vda rw\n'
           b'2 1 0:2 /guard /run/man-cache-guard ro - tmpfs none rw\n'
           b'3 1 0:2 /script /run/man-regeneration.py ro - tmpfs none rw\n'
           b'4 1 0:3 / /run rw - tmpfs none rw\n'
           b'5 1 0:4 / /var/cache/man rw - tmpfs none rw\n'
           b'6 1 0:5 / /tmp rw - tmpfs none rw\n'+extra)
    paths = {}
    for target in view.TARGETS:
        identity = 2 if target.endswith('man-cache-guard') else (
                   3 if target.endswith('man-regeneration.py') else 1)
        paths[target] = dict(mount_id=identity, device=[0, 2 if identity > 1 else 1],
            resolved_path=target, readonly=True, uid=0,
            mode=0o755 if target in view.TREES else 0o644,
            kind='directory' if target in view.TREES else 'file')
    return dict(mountinfo=mount_field(raw), paths=paths)


class RuntimeViewTests(unittest.TestCase):
    def test_fixed_readonly_targets_with_private_writable_scratch_have_narrow_claim(self):
        proof = view.verify(fixture())
        self.assertEqual(proof['fixed_targets_readonly'], 10)
        self.assertTrue(proof['named_code_configuration_mounts_readonly'])
        self.assertFalse(proof['complete_runtime_closure_verified'])
        self.assertFalse(proof['loader_selection_verified'])
        self.assertFalse(proof['publication_authorized'])

    def test_btrfs_subvolume_device_is_not_falsely_equated_to_superblock_device(self):
        value = fixture()
        raw = base64.b64decode(value['mountinfo']['base64']).replace(b' - ext4 ', b' - btrfs ')
        value['mountinfo'] = mount_field(raw)
        for observed in value['paths'].values():
            if observed['mount_id'] == 1:
                observed['device'] = [0, 99]
        proof = view.verify(value)
        self.assertTrue(proof['named_code_configuration_mounts_readonly'])
        self.assertFalse(proof['filesystem_object_origin_verified'])
        value['paths']['/usr/lib']['device'] = [0, 100]
        with self.assertRaises(ValueError):
            view.verify(value)

    def test_writable_code_submount_or_exact_tree_shadow_refuses(self):
        for target in (b'/usr/lib/gconv', b'/usr/lib', b'/usr/bin/new-tools'):
            value = fixture(b'7 1 0:6 / '+target+b' rw - tmpfs none rw\n')
            with self.subTest(target=target), self.assertRaises(ValueError):
                view.verify(value)

    def test_fd_device_mount_readonly_and_object_metadata_must_agree(self):
        for field, wrong in (('mount_id', 1.0), ('mount_id', 100), ('device', [0, 99]),
                             ('readonly', False), ('readonly', 1), ('uid', 6),
                             ('mode', 0o777), ('mode', -512), ('mode', 0o10000), ('kind', 'file')):
            value = fixture()
            value['paths']['/usr/lib'][field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError):
                view.verify(value)
        value = fixture()
        value['paths']['/usr/lib']['mount_id'] = 4
        value['paths']['/usr/lib']['device'] = [0, 3]
        with self.assertRaises(ValueError):
            view.verify(value)

    def test_writable_config_overlay_cannot_hide_behind_stale_root_mount_identity(self):
        value = fixture(b'7 1 0:6 / /etc rw - tmpfs none rw\n')
        # The claimed FD is still on the root ro mount, contradicting /etc's
        # more specific overlay even before checking the actual readonly flag.
        with self.assertRaises(ValueError):
            view.verify(value)

    def test_complete_path_set_and_exact_stream_hash_size_are_required(self):
        value = fixture()
        for key in ('sha256', 'bytes'):
            changed = copy.deepcopy(value)
            changed['mountinfo'][key] = '0'*64 if key == 'sha256' else 0
            with self.subTest(key=key), self.assertRaises(ValueError):
                view.verify(changed)
        value['paths'].pop('/etc/ld.so.cache')
        with self.assertRaises(ValueError):
            view.verify(value)

    def test_mount_stream_bounds_and_shapes_precede_base64_decoding(self):
        for change in ('extra', 'oversized', 'decimal', 'nonstring', 'wrongpath'):
            value = fixture()
            if change == 'extra':
                value['mountinfo']['extra'] = 'untrusted'
            elif change == 'oversized':
                value['mountinfo']['base64'] = 'A'*349529
            elif change == 'decimal':
                value['mountinfo']['bytes'] = float(value['mountinfo']['bytes'])
            elif change == 'nonstring':
                value['mountinfo']['base64'] = 1
            else:
                value['paths']['/usr/lib']['resolved_path'] = None
            with self.subTest(change=change), self.assertRaises(ValueError):
                view.verify(value)

    def test_mount_escaping_duplicates_partial_rows_and_limits_are_strict(self):
        raw = b'1 0 0:1 / /escaped\\040space ro - btrfs none rw\n'
        self.assertEqual(view.parse(raw)[1]['target'], '/escaped space')
        for bad in (raw+raw, raw[:-1], raw.replace(b'\\040', b'\\777'),
                    raw.replace(b' ro ', b' ro,rw '), b'not a mount record\n'):
            with self.subTest(raw=bad), self.assertRaises(ValueError):
                view.parse(bad)
        with patch.object(view, 'MAX_MOUNTS', 0), self.assertRaises(ValueError):
            view.parse(raw)
        with patch.object(view, 'MAX_MOUNT_BYTES', 1), self.assertRaises(ValueError):
            view.parse(raw)

    def mocked_capture(self, *, fail_fdinfo=False, change_mounts=False, include_identities=False):
        value = fixture()
        raw = base64.b64decode(value['mountinfo']['base64'])
        opened = {}
        mount_reads = 0

        def open_path(target, flags):
            self.assertEqual(flags, view.os.O_PATH | view.os.O_CLOEXEC)
            fd = len(opened)+10
            opened[fd] = target
            return fd

        def info(fd):
            row = value['paths'][opened[fd]]
            kind = 0o040000 if row['kind'] == 'directory' else 0o100000
            return SimpleNamespace(st_dev=view.os.makedev(*row['device']), st_uid=row['uid'],
                st_mode=kind | row['mode'], st_ino=fd+100, st_gid=0,
                st_size=4096, st_nlink=1, st_mtime_ns=7, st_ctime_ns=8)

        def fdinfo(path, *args, **kwargs):
            if fail_fdinfo:
                raise OSError('synthetic fdinfo failure')
            row = value['paths'][opened[int(str(path).rsplit('/', 1)[1])]]
            return 'mnt_id:\t'+str(row['mount_id'])+'\n'

        def mounts(*args, **kwargs):
            nonlocal mount_reads
            mount_reads += 1
            data = (raw.replace(b'/ / ro ', b'/ / rw ')
                    if change_mounts and mount_reads == 2 else raw)
            return io.BytesIO(data)

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(view.sys, 'platform', 'linux'))
            stack.enter_context(patch.object(view.os, 'getresuid', return_value=(6, 6, 6),
                                             create=True))
            stack.enter_context(patch.object(view.os, 'getresgid', return_value=(12, 12, 12),
                                             create=True))
            stack.enter_context(patch.object(view.os, 'getgroups', return_value=[]))
            stack.enter_context(patch.object(view.os, 'O_PATH', 0x200000, create=True))
            stack.enter_context(patch.object(view.os, 'open', side_effect=open_path))
            stack.enter_context(patch.object(view.os, 'fstat', side_effect=info))
            stack.enter_context(patch.object(view.os, 'readlink', side_effect=lambda path:
                opened[int(path.rsplit('/', 1)[1])]))
            stack.enter_context(patch.object(view.os, 'statvfs', return_value=SimpleNamespace(
                f_flag=view.os.ST_RDONLY)))
            stack.enter_context(patch.object(view.Path, 'open', side_effect=mounts))
            stack.enter_context(patch.object(view.Path, 'read_text', autospec=True,
                                             side_effect=fdinfo))
            close = stack.enter_context(patch.object(view.os, 'close'))
            try:
                result = view.capture(identity_function=identity if include_identities else None)
            finally:
                self.assertEqual([call.args[0] for call in close.call_args_list], list(opened))
        return result, value

    def test_mocked_capture_binds_each_fd_and_closes_all_handles(self):
        actual, expected = self.mocked_capture()
        self.assertEqual(actual, expected)
        self.assertEqual(view.verify(actual)['fixed_targets_readonly'], 10)

    def test_optional_source_identities_come_from_the_same_open_fds(self):
        (actual, identities), expected = self.mocked_capture(include_identities=True)
        self.assertEqual(actual, expected)
        self.assertEqual(set(identities), set(view.TARGETS))
        for target, row in identities.items():
            self.assertGreater(row['inode'], 100)
            for key in ('device', 'uid', 'mode', 'kind'):
                self.assertEqual(row[key], actual['paths'][target][key])

    def test_mocked_capture_closes_the_fd_when_fdinfo_read_fails(self):
        with self.assertRaisesRegex(OSError, 'synthetic fdinfo failure'):
            self.mocked_capture(fail_fdinfo=True)

    def test_mocked_capture_rejects_topology_changes_after_closing_handles(self):
        with self.assertRaisesRegex(ValueError, 'topology changed'):
            self.mocked_capture(change_mounts=True)

    def test_mac_and_wrong_linux_identity_refuse_before_any_proc_or_fd_read(self):
        with patch.object(view.sys, 'platform', 'darwin'), \
                patch.object(view.Path, 'open') as read, patch.object(view.os, 'open') as open_fd:
            with self.assertRaises(PermissionError):
                view.capture()
            read.assert_not_called()
            open_fd.assert_not_called()
        with patch.object(view.sys, 'platform', 'linux'), \
                patch.object(view.os, 'getresuid', return_value=(0, 0, 0), create=True), \
                patch.object(view.Path, 'open') as read, patch.object(view.os, 'open') as open_fd:
            with self.assertRaises(PermissionError):
                view.capture()
            read.assert_not_called()
            open_fd.assert_not_called()


if __name__ == '__main__':
    unittest.main()
