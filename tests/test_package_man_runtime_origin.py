"""Portable identity fixtures and mocked FDs; no Root/Linux capture on Mac."""
import contextlib
import copy
import stat
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mano_runtime import package_man_runtime_origin as origin


def fixture():
    return {target: dict(device=[0, 99], inode=index+100, uid=0, gid=0,
        mode=0o755 if target in {'/usr/bin', '/usr/lib'} else 0o644,
        kind='directory' if target in {'/usr/bin', '/usr/lib'} else 'file',
        bytes=4096, nlink=1, mtime_ns=7, ctime_ns=8)
        for index, target in enumerate(sorted(origin.TARGETS))}


class RuntimeOriginTests(unittest.TestCase):
    def test_matching_held_and_child_identities_do_not_promote_full_runtime_authority(self):
        value = fixture()
        proof = origin.compare(value, copy.deepcopy(value), copy.deepcopy(value))
        self.assertTrue(proof['worker_source_identities_match'])
        self.assertEqual((proof['baseline_objects'], proof['injected_objects']), (8, 2))
        for key in ('collector_authentication_verified', 'complete_runtime_closure_verified',
                    'loader_selection_verified', 'generated_state_validated',
                    'changes_authorized', 'publication_authorized'):
            self.assertIs(proof[key], False)

    def test_replaced_inode_or_same_inode_in_another_btrfs_subvolume_refuses(self):
        value = fixture()
        for target in sorted(origin.TARGETS):
            for key, changed in (('inode', 2000), ('device', [0, 100])):
                child = copy.deepcopy(value)
                child[target][key] = changed
                with self.subTest(target=target, field=key), self.assertRaises(ValueError):
                    origin.compare(value, value, child)

    def test_root_mutation_and_worker_metadata_substitution_refuse(self):
        value = fixture()
        for key, changed in (('mtime_ns', 9), ('ctime_ns', 10), ('bytes', 9),
                             ('nlink', 2), ('gid', 12), ('mode', 0o600)):
            altered = copy.deepcopy(value)
            altered['/run/man-cache-guard'][key] = changed
            for before, after, worker in ((value, altered, value), (value, value, altered)):
                with self.subTest(field=key), self.assertRaises(ValueError):
                    origin.compare(before, after, worker)

    def test_numeric_aliases_permissions_missing_and_extra_fields_refuse(self):
        value = fixture()
        for key, changed in (('inode', 100.0), ('uid', False), ('device', [0.0, 99]),
                             ('mode', 0o666), ('kind', 'symlink'), ('nlink', 0),
                             ('inode', 2**64), ('bytes', 2**63), ('gid', 2**32),
                             ('device', [0, 2**32]), ('mtime_ns', 2**63)):
            altered = copy.deepcopy(value)
            altered['/etc/passwd'][key] = changed
            with self.subTest(field=key), self.assertRaises(ValueError):
                origin.compare(altered, altered, altered)
        for mutation in ('missing-target', 'extra-field'):
            altered = copy.deepcopy(value)
            if mutation == 'missing-target':
                altered.pop('/etc/passwd')
            else:
                altered['/etc/passwd']['trust_me'] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                origin.checked(altered)

    def test_guard_refuses_before_any_filesystem_access(self):
        for platform, uid in (('darwin', 0), ('linux', 501)):
            with patch.object(origin.sys, 'platform', platform), \
                    patch.object(origin.os, 'geteuid', return_value=uid), \
                    patch.object(origin.os, 'open') as opened:
                with self.assertRaises(PermissionError), origin.hold():
                    self.fail('Guard allowed source capture')
                opened.assert_not_called()

    def test_snapshot_property_uses_fixed_existing_btrfs_readonly_contract(self):
        for value in (b'ro=true\n', b'ro=false\n', b''):
            with patch.object(origin.subprocess, 'check_output', return_value=value) as run:
                if value == b'ro=true\n':
                    origin._readonly_snapshot()
                else:
                    with self.assertRaises(PermissionError):
                        origin._readonly_snapshot()
                run.assert_called_once_with(['/usr/bin/btrfs', 'property', 'get',
                    str(origin.BASE / 'baseline'), 'ro'], timeout=5)

    def mocked_holder(self, *, fail_open=None, readonly=True):
        values = fixture()
        descriptors, parents, closed = {}, {}, []
        current = None

        def parent(root, relative):
            nonlocal current
            current = ('/'+relative if root == 11 else next(
                target for target, name in origin.INJECTED.items() if name == relative))
            descriptor = 900+len(parents)
            parents[descriptor] = (root, relative)
            return descriptor

        def opened(path, flags, *, dir_fd=None):
            if path == origin.BASE:
                return 10
            if path == 'baseline':
                self.assertEqual(dir_fd, 10)
                return 11
            if current == fail_open:
                raise OSError('Synthetic source-open failure')
            self.assertEqual(flags, origin.os.O_PATH | origin.os.O_NOFOLLOW | origin.os.O_CLOEXEC)
            self.assertEqual(parents[dir_fd][1].rsplit('/', 1)[-1], path)
            descriptor = 100+len(descriptors)
            descriptors[descriptor] = current
            return descriptor

        def observed(fd):
            if fd == 10:
                return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o700)
            row = values[descriptors[fd]]
            return SimpleNamespace(st_dev=origin.os.makedev(*row['device']),
                st_ino=row['inode'], st_uid=row['uid'], st_gid=row['gid'],
                st_mode=(stat.S_IFDIR if row['kind'] == 'directory' else stat.S_IFREG)
                        | row['mode'], st_size=row['bytes'], st_nlink=row['nlink'],
                st_mtime_ns=row['mtime_ns'], st_ctime_ns=row['ctime_ns'])

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(origin, 'root_guard'))
            stack.enter_context(patch.object(origin.os, 'O_PATH', 1 << 21, create=True))
            stack.enter_context(patch.object(origin.os, 'open', side_effect=opened))
            stack.enter_context(patch.object(origin.os, 'fstat', side_effect=observed))
            stack.enter_context(patch.object(origin.subprocess, 'check_output',
                return_value=b'ro=true\n' if readonly else b'ro=false\n'))
            stack.enter_context(patch.object(origin.os, 'close', side_effect=closed.append))
            stack.enter_context(patch('mano_runtime.package_candidate.parent_fd',
                                      side_effect=parent))
            if fail_open is not None or not readonly:
                with self.assertRaises((OSError, PermissionError)), origin.hold():
                    self.fail('Rejected capture entered worker scope')
            else:
                with origin.hold() as holder:
                    before = holder.observe()
                    self.assertEqual(before, values)
                    self.assertTrue(set(descriptors).isdisjoint(closed))
                    proof = origin.compare(before, holder.observe(), values)
                    self.assertTrue(proof['held_source_identities_stable'])
            self.assertCountEqual(closed, [10, 11, *parents, *descriptors])
            self.assertEqual(len(closed), len(set(closed)))

    def test_sources_remain_held_across_scope_and_close_on_success(self):
        self.mocked_holder()

    def test_partial_open_failure_and_writable_baseline_close_all_owned_fds(self):
        self.mocked_holder(fail_open='/etc/locale.alias')
        self.mocked_holder(readonly=False)


if __name__ == '__main__':
    unittest.main()
