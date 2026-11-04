"""Mocked source custody and retained-byte checks; no native host operations."""
import contextlib
import copy
import json
import os
import stat
import unittest
from types import SimpleNamespace
from unittest.mock import call, patch

from test_package_man_interpreter import LOADER, inputs

from mano_runtime import package_man_interpreter_origin as source


def packet():
    main, raw, tree = inputs()
    row = tree['entries'][LOADER]
    identity = dict(device=[0, 55], inode=99, **{key: row[key] for key in (
        'uid', 'gid', 'mode', 'kind', 'bytes', 'nlink', 'mtime_ns', 'ctime_ns')})
    return main, raw, tree, identity


class InterpreterSourceTests(unittest.TestCase):
    def test_held_bytes_bind_without_kernel_load_or_publication_claim(self):
        main, raw, tree, identity = packet()
        result = source.compare(main, raw, tree, identity, copy.deepcopy(identity))
        self.assertEqual(result['raw_bytes'], len(raw))
        self.assertTrue(result['held_source_identity_stable'])
        self.assertTrue(result['interpreter_bytes_bound'])
        self.assertLess(len(json.dumps(result).encode()), source.MAX_PACKET_BYTES)
        for key in ('actual_kernel_loading_verified', 'readonly_kernel_source_verified',
                    'collector_authentication_verified', 'complete_runtime_closure_verified',
                    'loader_selection_verified', 'generated_state_validated',
                    'changes_authorized', 'publication_authorized'):
            self.assertIs(result[key], False)

    def test_changed_object_content_or_baseline_metadata_refuse(self):
        main, raw, tree, identity = packet()
        for key, value in (('inode', 100), ('device', [0, 56]), ('mtime_ns', 1),
                           ('ctime_ns', 2), ('gid', 12), ('mode', 0o555)):
            after = dict(identity, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                source.compare(main, raw, tree, identity, after)
        for key, value in (('mtime_ns', 1), ('ctime_ns', 2), ('mode', 0o555)):
            changed = dict(identity, **{key: value})
            with self.assertRaisesRegex(ValueError, 'metadata differs'):
                source.compare(main, raw, tree, changed, changed)
        with self.assertRaises(ValueError):
            source.compare(main, raw[:-1]+b'x', tree, identity, identity)
        with self.assertRaises(ValueError):
            source.compare(main[:-1]+b'x', raw, tree, identity, identity)
        with patch.object(source, 'MAX_BYTES', 64), self.assertRaises(ValueError):
            source.compare(main, raw, tree, identity, identity)
        with patch.object(source, 'MAX_PACKET_BYTES', 64), self.assertRaises(ValueError):
            source.compare(main, raw, tree, identity, identity)

    def test_guard_refusal_precedes_even_first_open_or_stat(self):
        with patch.object(source.origin, 'root_guard', side_effect=PermissionError('CI only')), \
                patch.object(source.os, 'open') as opened, \
                patch.object(source.os, 'fstat') as observed:
            with self.assertRaises(PermissionError), source.hold({}, b''):
                self.fail('Must never yield')
            opened.assert_not_called()
            observed.assert_not_called()

    def mocked_holder(self, raw, identity):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        info = SimpleNamespace(st_dev=os.makedev(*identity['device']), st_ino=identity['inode'],
            st_uid=0, st_gid=identity['gid'], st_mode=stat.S_IFREG | identity['mode'],
            st_size=len(raw), st_nlink=identity['nlink'], st_mtime_ns=identity['mtime_ns'],
            st_ctime_ns=identity['ctime_ns'])
        base = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o700)
        stack.enter_context(patch.object(source.origin, 'root_guard'))
        stack.enter_context(patch.object(source.origin, '_readonly_snapshot'))
        parent = stack.enter_context(patch('mano_runtime.package_candidate.parent_fd',
                                          return_value=5))
        opened = stack.enter_context(patch.object(source.os, 'open', side_effect=[3, 4, 6]))
        stack.enter_context(patch.object(source.os, 'fstat',
                                        side_effect=lambda fd: base if fd == 3 else info))
        read = stack.enter_context(patch.object(source.os, 'read', side_effect=[raw, b'']))
        closed = stack.enter_context(patch.object(source.os, 'close'))
        return parent, opened, read, closed

    def test_canonical_nofollow_descriptor_retained_until_generation_context_exits(self):
        main, raw, tree, identity = packet()
        parent, opened, _, closed = self.mocked_holder(raw, identity)
        with source.hold(tree, main) as held:
            self.assertEqual(held.fd, 6)
            self.assertEqual(held.raw, raw)
            self.assertEqual(held.observe(), identity)
            closed.assert_not_called()
        parent.assert_called_once_with(4, LOADER)
        self.assertEqual(opened.call_args_list[-1].args[0], LOADER.rsplit('/', 1)[1])
        flags = opened.call_args_list[-1].args[1]
        self.assertTrue(flags & os.O_NOFOLLOW and flags & os.O_CLOEXEC)
        self.assertEqual(closed.call_args_list, [call(6), call(5), call(4), call(3)])

    def test_truncated_read_refuses_and_closes_all_descriptors(self):
        main, raw, tree, identity = packet()
        _, _, read, closed = self.mocked_holder(raw, identity)
        read.side_effect = [raw[:-1], b'']
        with self.assertRaisesRegex(ValueError, 'changed during retained read'), \
                source.hold(tree, main):
            self.fail('Must not yield partial bytes')
        self.assertEqual(closed.call_args_list, [call(6), call(5), call(4), call(3)])

    def test_drain_validation_failure_still_closes_all_descriptors(self):
        main, raw, tree, identity = packet()
        _, _, _, closed = self.mocked_holder(raw, identity)
        with self.assertRaisesRegex(ValueError, 'generation did not drain'), \
                source.hold(tree, main):
            raise ValueError('generation did not drain')
        self.assertEqual(closed.call_args_list, [call(6), call(5), call(4), call(3)])
