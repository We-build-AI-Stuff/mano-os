"""Synthetic source comparisons and mocked FD custody; no native host operation."""
import copy
import json
import os
import stat
import unittest
from types import SimpleNamespace
from unittest.mock import call, patch

from test_package_man_elf_memory import baseline, fixture

from mano_runtime import package_man_executable_origin as source


def packet():
    raw = fixture()
    tree, path = baseline(raw)
    row = tree['entries'][path]
    identity = dict(device=[0, 56], inode=99,
        **{key: row[key] for key in ('uid', 'gid', 'mode', 'kind', 'bytes', 'nlink',
                                    'mtime_ns', 'ctime_ns')})
    native = dict(profile='man-fixed-mandb-execfd-v1', path='/usr/bin/mandb',
        execution_method='execveat-empty-path', descriptor_cloexec=True,
        readonly_mount=True, identity=copy.deepcopy(identity))
    return raw, tree, identity, native


class ExecutableSourceTests(unittest.TestCase):
    def test_bytes_descriptor_and_baseline_bind_without_full_authority_claim(self):
        raw, tree, identity, native = packet()
        value = source.compare(raw, tree, identity, copy.deepcopy(identity), native)
        self.assertEqual(value['raw_bytes'], len(raw))
        self.assertTrue(value['held_source_identity_stable'])
        self.assertTrue(value['native_source_identity_matches'])
        self.assertLess(len(json.dumps(value).encode()), source.MAX_PACKET_BYTES)
        for key in ('collector_authentication_verified', 'complete_runtime_closure_verified',
                    'loader_selection_verified', 'generated_state_validated',
                    'changes_authorized', 'publication_authorized'):
            self.assertIs(value[key], False)

    def test_same_name_same_bytes_different_object_or_changed_root_hold_refuse(self):
        for key, changed in (('inode', 100), ('device', [0, 55]), ('mtime_ns', 1),
                             ('ctime_ns', 2), ('gid', 12), ('mode', 0o555)):
            for side in ('native', 'after'):
                raw, tree, identity, native = packet()
                after = copy.deepcopy(identity)
                target = native['identity'] if side == 'native' else after
                target[key] = changed
                with self.subTest(key=key, side=side), self.assertRaises(ValueError):
                    source.compare(raw, tree, identity, after, native)

    def test_held_metadata_must_also_match_baseline_not_only_native_stat(self):
        for key, changed in (('mtime_ns', 1), ('ctime_ns', 2), ('mode', 0o555), ('gid', 12)):
            raw, tree, identity, native = packet()
            identity[key] = changed
            native['identity'] = copy.deepcopy(identity)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'metadata differs'):
                source.compare(raw, tree, identity, copy.deepcopy(identity), native)

    def test_mutable_aliased_unreadable_or_numeric_identity_fields_refuse(self):
        for key, changed in (('uid', False), ('uid', 6), ('gid', True), ('mode', 0o777),
                ('mode', 0o700), ('bytes', 1), ('nlink', False), ('inode', 0),
                ('device', [False, 56]), ('kind', 'symlink'), ('ctime_ns', 1.0),
                ('mtime_ns', 2**63)):
            _, _, identity, _ = packet()
            identity[key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError):
                source.checked_identity(identity)
        raw, tree, identity, native = packet()
        with self.assertRaises(ValueError):
            source.compare(raw[:-1]+b'x', tree, identity, identity, native)
        with patch.object(source, 'MAX_BYTES', 64), self.assertRaises(ValueError):
            source.compare(raw, tree, identity, identity, native)

    def test_pathname_launch_extra_fields_or_nonreadonly_source_cannot_substitute(self):
        for key, changed in (('execution_method', 'execve'), ('path', '/tmp/mandb'),
                            ('readonly_mount', 1), ('readonly_mount', False),
                            ('descriptor_cloexec', False), ('extra', True)):
            _, _, _, native = packet()
            native[key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError):
                source.checked_native(native)

    def test_guard_refusal_precedes_all_filesystem_operations(self):
        with patch.object(source.origin, 'root_guard', side_effect=PermissionError('CI only')):
            with patch.object(source.os, 'open') as opened, patch.object(source.os, 'fstat') as st:
                with self.assertRaises(PermissionError), source.hold({}):
                    self.fail('Guard refusal must not yield')
                opened.assert_not_called()
                st.assert_not_called()

    def test_mocked_root_holder_keeps_same_read_fd_until_context_drains(self):
        raw, tree, identity, _ = packet()
        info = SimpleNamespace(st_dev=os.makedev(*identity['device']), st_ino=identity['inode'],
            st_uid=0, st_gid=identity['gid'], st_mode=stat.S_IFREG | identity['mode'],
            st_size=len(raw), st_nlink=identity['nlink'], st_mtime_ns=identity['mtime_ns'],
            st_ctime_ns=identity['ctime_ns'])
        base = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o700)
        def fstat(fd):
            self.assertIn(fd, {3, 6})
            return base if fd == 3 else info
        with patch.object(source.origin, 'root_guard'), \
                patch.object(source.origin, '_readonly_snapshot'), \
                patch('mano_runtime.package_candidate.parent_fd', return_value=5), \
                patch.object(source.os, 'open', side_effect=[3, 4, 6]) as opened, \
                patch.object(source.os, 'fstat', side_effect=fstat), \
                patch.object(source.os, 'read', side_effect=[raw, b'']), \
                patch.object(source.os, 'close') as closed:
            with source.hold(tree) as held:
                self.assertEqual(held.raw, raw)
                self.assertEqual(held.observe(), identity)
                self.assertEqual(held.fd, 6)
                closed.assert_not_called()
            self.assertEqual(closed.call_args_list, [call(6), call(5), call(4), call(3)])
            self.assertTrue(opened.call_args_list[-1].args[1] & os.O_NOFOLLOW)
            self.assertTrue(opened.call_args_list[-1].args[1] & os.O_CLOEXEC)


class ExecutableSourceControllerTests(unittest.TestCase):
    def test_explicit_v5_selection_keeps_prior_v4_schema_strict(self):
        import test_package_man_regeneration as regeneration
        from test_package_man_execmem import fixture as memory_fixture
        raw, tree, identity, native = packet()
        flags = ('groups_empty nnp all_capability_sets_zero control_read_before_allowed '
            'control_write_before_allowed control_read_denied control_write_denied '
            'tmp_exec_before_allowed tmp_exec_denied cache_write_allowed namespace_change_denied '
            'identity_change_denied child_exec_inheritance_verified seccomp_enforced').split()
        guard = dict.fromkeys(flags, True)
        guard.update(profile='man-cache-landlock-seccomp-v5', role='mandb', uid=6, gid=12,
                     landlock_abi=6, execmem=memory_fixture(), executable_source=native)
        host, row = regeneration.worker()
        row.update(mode='restricted', input_guard=guard)
        row['result']['stdout'] = regeneration.stream(json.dumps(guard).encode()+b'\n')
        regeneration.probe.validate(row, host, 'a'*64, require_input_guard=True,
                                   require_execmem=True, require_executable_source=True)
        self.assertLess(len(json.dumps(guard).encode()), 4096)
        with self.assertRaises(ValueError):
            regeneration.probe.require_guard(row, execmem=True)
        with self.assertRaises(ValueError):
            regeneration.probe.validate(row, host, 'a'*64, require_executable_source=True)
        for changed in (1, 'true', None):
            with self.assertRaises(ValueError):
                regeneration.probe.validate_native_guard(guard, role='mandb', execmem=True,
                                                         executable_source=changed)
        for name, value in (('profile', 'man-cache-landlock-seccomp-v4'),
                            ('readonly_mount', False), ('descriptor_cloexec', 1)):
            altered = copy.deepcopy(guard)
            if name == 'profile':
                altered[name] = value
            else:
                altered['executable_source'][name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                regeneration.probe.validate_native_guard(altered, role='mandb', execmem=True,
                                                         executable_source=True)

    def test_new_worker_changes_only_fixed_restricted_generation_selection(self):
        from pathlib import Path

        import test_package_man_regeneration as regeneration
        root = Path(__file__).resolve().parents[1]
        options = dict(runtime_view_source=(root/'src/mano_runtime/package_man_runtime_view.py')
            .read_text(), runtime_origin_source=(root/'src/mano_runtime/'
            'package_man_runtime_origin.py').read_text(), mapping_controls=True,
            execmem_profile_source=(root/'packaging/apparmor/mano-man-cache-execmem').read_bytes())
        old = regeneration.probe.program(regeneration.stage.PROGRAM, **options)
        new = regeneration.probe.program(regeneration.stage.PROGRAM, **options,
                                         executable_source=True)
        self.assertEqual(old.replace(b"'--mandb-enforced'", b"'--mandb-enforced-source'"), new)
        compile(new, 'synthetic-source-bound-worker', 'exec')
        for value in (1, None, 'true'):
            with self.assertRaises(ValueError):
                regeneration.probe.program(regeneration.stage.PROGRAM, **options,
                                           executable_source=value)
        with self.assertRaises(ValueError):
            regeneration.probe.program(regeneration.stage.PROGRAM, executable_source=True)
