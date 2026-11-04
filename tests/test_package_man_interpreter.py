"""Portable alias/byte fixtures; no host loader or filesystem path is used."""
import copy
import hashlib
import unittest
from unittest.mock import patch

from test_package_man_elf_memory import baseline, fixture
from test_package_man_sources import rehash

from mano_runtime import package_man_interpreter as interpreter

LOADER = 'usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'


def inputs():
    main, loader = fixture(), fixture(interpreter=None)
    tree, path = baseline(main)
    directory = dict(tree['entries']['usr'])
    for name in ('usr/lib', 'usr/lib64', 'usr/lib/x86_64-linux-gnu'):
        tree['entries'][name] = dict(directory)
    def alias(target):
        return dict(directory, kind='symlink', mode=0o777, target=target)
    tree['entries']['lib64'] = alias('usr/lib64')
    tree['entries']['usr/lib64/ld-linux-x86-64.so.2'] = alias(
        '../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2')
    tree['entries'][LOADER] = dict(tree['entries'][path], bytes=len(loader),
        sha256=hashlib.sha256(loader).hexdigest(), hardlink_anchor=LOADER)
    rehash(tree)
    return main, loader, tree


class InterpreterSelectorTests(unittest.TestCase):
    def test_debian_relative_aliases_bind_without_kernel_or_descriptor_claims(self):
        main, loader, tree = inputs()
        result = interpreter.bind(main, loader, tree)
        selected = result['selection']
        self.assertEqual(selected['resolved_path'], LOADER)
        self.assertEqual([a['path'] for a in selected['aliases']], [
            'lib64', 'usr/lib64/ld-linux-x86-64.so.2'])
        self.assertEqual(result['interpreter_binding']['file_content_sha256'],
                         hashlib.sha256(loader).hexdigest())
        for record in (result, selected):
            for key in ('filesystem_paths_opened', 'readonly_source_descriptor_verified',
                        'actual_kernel_loading_verified', 'collector_authentication_verified',
                        'complete_runtime_closure_verified', 'publication_authorized'):
                self.assertIs(record[key], False)
        self.assertIs(selected['interpreter_bytes_bound'], False)
        self.assertIs(result['interpreter_bytes_bound'], True)

    def test_absolute_alias_restarts_at_tree_root_without_touching_host(self):
        main, loader, tree = inputs()
        tree['entries']['usr/lib64/ld-linux-x86-64.so.2']['target'] = '/'+LOADER
        rehash(tree)
        with patch('os.open', side_effect=AssertionError('Host access forbidden')):
            self.assertEqual(interpreter.bind(main, loader, tree)['selection'][
                'resolved_path'], LOADER)

    def test_untrusted_alias_parent_and_terminal_metadata_fail_closed(self):
        main, _, original = inputs()
        for name in ('.', 'usr/lib64', 'lib64', LOADER):
            for key, value in (('uid', 6), ('gid', True), ('mtime_ns', 1.0),
                               ('nlink', 0), ('xattrs', {'security.unknown': 'value'})):
                tree = copy.deepcopy(original)
                tree['entries'][name][key] = value
                rehash(tree)
                with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                    interpreter.resolve(main, tree)
        for name in ('usr/lib64', LOADER):
            for mode in (0o777, 0o700):
                tree = copy.deepcopy(original)
                tree['entries'][name]['mode'] = mode
                rehash(tree)
                with self.assertRaises(ValueError):
                    interpreter.resolve(main, tree)

    def test_missing_targets_loops_and_escape_refuse_instead_of_host_fallback(self):
        main, _, original = inputs()
        for target in ('/outside/loader', '../../../usr/lib/loader',
                       '/lib64/ld-linux-x86-64.so.2', 'ld-linux-x86-64.so.2',
                       '', '//usr/lib/loader', '../lib//loader', '../lib/loader/',
                       '../lib/loader\n', '../lib/\N{SNOWMAN}', False, 'a'*4097):
            tree = copy.deepcopy(original)
            tree['entries']['usr/lib64/ld-linux-x86-64.so.2']['target'] = target
            rehash(tree)
            with self.subTest(target=target), self.assertRaises(ValueError):
                interpreter.resolve(main, tree)

    def test_file_as_parent_dotdot_does_not_skip_component_checks(self):
        main, _, tree = inputs()
        tree['entries']['usr/lib64/ld-linux-x86-64.so.2']['target'] = (
            '../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2/../ld-linux-x86-64.so.2')
        rehash(tree)
        with self.assertRaises(ValueError):
            interpreter.resolve(main, tree)

    def test_metadata_path_and_step_budgets_refuse(self):
        main, _, tree = inputs()
        for key, value in (('MAX_LINKS', 1), ('MAX_STEPS', 2),
                           ('MAX_DEPTH', 2), ('MAX_PATH_BYTES', 30)):
            with patch.object(interpreter, key, value), self.assertRaises(ValueError):
                interpreter.resolve(main, tree)
        bad = copy.deepcopy(tree)
        bad['entries'][LOADER]['sha256'] = 'g'*64
        rehash(bad)
        with self.assertRaises(ValueError):
            interpreter.resolve(main, bad)
        bad = copy.deepcopy(tree)
        bad['entries'][LOADER]['uid'] = 6
        with self.assertRaises(ValueError):
            interpreter.resolve(main, bad)

    def test_wrong_loader_bytes_alias_metadata_or_recursive_interpreter_refuse(self):
        main, loader, original = inputs()
        with self.assertRaises(ValueError):
            interpreter.bind(main, loader[:-1]+b'x', original)
        for raw in (fixture(), fixture(interpreter=None, kind=2)):
            tree = copy.deepcopy(original)
            tree['entries'][LOADER]['sha256'] = hashlib.sha256(raw).hexdigest()
            rehash(tree)
            with self.assertRaises(ValueError):
                interpreter.bind(main, raw, tree)
        tree = copy.deepcopy(original)
        tree['entries'][LOADER]['nlink'] = 2
        rehash(tree)
        with self.assertRaises(ValueError):
            interpreter.bind(main, loader, tree)

    def test_main_binding_and_no_interpreter_refuse(self):
        main, _, tree = inputs()
        with self.assertRaises(ValueError):
            interpreter.resolve(main[:-1]+b'x', tree)
        main = fixture(interpreter=None)
        tree, _ = baseline(main)
        with self.assertRaises(ValueError):
            interpreter.resolve(main, tree)


if __name__ == '__main__':
    unittest.main()
