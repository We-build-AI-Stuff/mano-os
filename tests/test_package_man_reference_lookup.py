"""Synthetic metadata only; no host path operations or native Linux claims."""
import copy
import hashlib
import unittest
from unittest.mock import patch

from test_package_man_sources import candidate, rehash

from mano_runtime import package_man_reference_lookup as lookup

ROOT = 'usr/share/man'
ORIGINAL = ROOT+'/man1/original.1.gz'


def trees(files=(), directories=(), links=(), modes=None, metadata=None):
    tree, primary = candidate()
    template = dict(tree['entries'][primary])
    directory = dict(tree['entries']['.'])
    for name in ('man1', *directories):
        path = ROOT+'/'+name
        parts = path.split('/')
        for index in range(1, len(parts)+1):
            tree['entries'].setdefault('/'.join(parts[:index]), dict(directory))
    for name in ('man1/original.1.gz', *files):
        path = ROOT+'/'+name
        tree['entries'][path] = dict(template, hardlink_anchor=path,
                                    sha256=hashlib.sha256(name.encode()).hexdigest())
    for name, target in links:
        tree['entries'][ROOT+'/'+name] = dict(kind='symlink', uid=0, gid=0, mode=0o777,
            nlink=1, mtime_ns=0, ctime_ns=0, xattrs={}, target=target)
    for name, mode in (modes or {}).items():
        tree['entries'][ROOT+'/'+name]['mode'] = mode
    for name, fields in (metadata or {}).items():
        tree['entries'][ROOT+('/'+name if name else '')].update(copy.deepcopy(fields))
    rehash(tree)
    return tree, copy.deepcopy(tree)


def namespace(**kwargs):
    return lookup.Namespace(*trees(**kwargs))


class ConditionalReferenceTests(unittest.TestCase):
    def test_plain_then_configured_compressions_then_original_directory(self):
        view = namespace(files=('target.1', 'target.1.gz', 'target.1.xz',
                                'man1/local.1.gz'))
        result = view.select(ROOT, ORIGINAL, b'target.1', ['xz', 'gz'])
        self.assertEqual(result['selected']['path'], ROOT+'/target.1')
        self.assertEqual(len(result['attempts']), 1)
        view = namespace(files=('target.1.gz', 'target.1.xz'))
        result = view.select(ROOT, ORIGINAL, b'target.1', ['xz', 'gz'])
        self.assertEqual(result['selected']['path'], ROOT+'/target.1.xz')
        view = namespace(files=('man1/local.1.gz',))
        result = view.select(ROOT, ORIGINAL, b'local.1', ['gz'])
        self.assertEqual(result['selected']['path'], ROOT+'/man1/local.1.gz')
        self.assertEqual(result['attempts'][-1]['context'], 'original-directory')

    def test_first_successful_nonregular_entry_is_never_skipped(self):
        view = namespace(files=('target.1.xz',), directories=('target.1.gz',))
        result = view.select(ROOT, ORIGINAL, b'target.1', ['gz', 'xz'])
        self.assertEqual(result['selected']['kind'], 'directory')
        self.assertEqual(result['selected']['path'], ROOT+'/target.1.gz')
        self.assertEqual(len(result['attempts']), 2)

    def test_link_is_followed_before_dotdot_without_lexical_collapse(self):
        view = namespace(files=('goal.1', 'man2/goal.1'), directories=('man2/deep',),
                         links=(('bridge', 'man2/deep'),))
        result = view.select(ROOT, ORIGINAL, b'bridge/../goal.1', ['gz'])
        self.assertEqual(result['selected']['path'], ROOT+'/man2/goal.1')
        self.assertEqual(result['attempts'][0]['outcome']['symlinks'][0]['path'], ROOT+'/bridge')
        view = namespace(files=('file', 'goal.1'), links=(('bridge', 'file'),))
        result = view.select(ROOT, ORIGINAL, b'bridge/../goal.1', [])
        self.assertEqual(result['selection_state'], 'unresolved')
        self.assertEqual(result['attempts'][0]['outcome']['reason'], 'ENOTDIR')

    def test_dangling_or_cyclic_plain_link_can_fall_back_to_existing_compressed_name(self):
        for target in ('missing', 'target.1'):
            view = namespace(files=('target.1.gz',), links=(('target.1', target),))
            result = view.select(ROOT, ORIGINAL, b'target.1', ['gz'])
            self.assertEqual(result['selected']['path'], ROOT+'/target.1.gz')
            self.assertIn(result['attempts'][0]['outcome']['reason'], {'ENOENT', 'ELOOP'})

    def test_unknown_scope_stops_without_guessing_absence_and_fallback(self):
        view = namespace(files=('target.1.gz',), links=(('target.1', '/outside/unknown'),))
        result = view.select(ROOT, ORIGINAL, b'target.1', ['gz'])
        self.assertEqual(result['selection_state'], 'unknown')
        self.assertEqual(len(result['attempts']), 1)
        self.assertNotIn('selected', result)

    def test_file_read_permission_does_not_change_existence_selection(self):
        view = namespace(files=('target.1', 'target.1.gz'), modes={'target.1': 0o600})
        result = view.select(ROOT, ORIGINAL, b'target.1', ['gz'])
        self.assertEqual(result['selected']['path'], ROOT+'/target.1')
        self.assertFalse(result['source_target_resolution_verified'])

    def test_unsearchable_parent_can_fail_root_lookup_before_directory_fallback(self):
        view = namespace(files=('blocked/x.1.gz', 'man1/blocked/x.1'),
            directories=('blocked', 'man1/blocked'), modes={'blocked': 0o700})
        result = view.select(ROOT, ORIGINAL, b'blocked/x.1', ['gz'])
        self.assertEqual(result['attempts'][0]['outcome']['reason'], 'EACCES')
        self.assertEqual(result['selected']['path'], ROOT+'/man1/blocked/x.1')

    def test_primary_group_and_owner_class_take_precedence_over_other_permissions(self):
        for owner, group in ((0, 12), (6, 0)):
            mode = 0o701 if owner == 0 else 0o611
            view = namespace(files=('dir/target.1',), directories=('dir',),
                metadata={'dir': dict(uid=owner, gid=group, mode=mode)})
            self.assertEqual(view.stat(ROOT+'/dir/target.1')['reason'], 'EACCES')

    def test_unbound_protected_symlink_policy_is_unknown_instead_of_absent(self):
        view = namespace(files=('target.1',), links=(('link.1', 'target.1'),),
            metadata={'': dict(mode=0o1777), 'link.1': dict(uid=1000)})
        result = view.select(ROOT, ORIGINAL, b'link.1', ['gz'])
        self.assertEqual(result['selection_state'], 'unknown')
        self.assertEqual(result['reason'], 'protected-symlink-policy-unbound')
        self.assertEqual(len(result['attempts']), 1)

    def test_trailing_slash_and_dot_require_directory_but_not_final_file_read(self):
        view = namespace(files=('file',), directories=('dir',), modes={'dir': 0o000})
        self.assertEqual(view.stat(ROOT+'/file/')['reason'], 'ENOTDIR')
        self.assertEqual(view.stat(ROOT+'/file/.')['reason'], 'ENOTDIR')
        self.assertEqual(view.stat(ROOT+'/dir/')['state'], 'exists')
        self.assertEqual(view.stat(ROOT+'/dir/.')['reason'], 'EACCES')

    def test_locale_context_and_relative_leave_then_reentry_preserve_order(self):
        view = namespace(files=('de/man1/name.1.gz', 'name.1'),
                         directories=('de/man1',))
        result = view.select(ROOT+'/de', ROOT+'/de/man1/source.1.gz', b'man1/name.1', ['gz'])
        self.assertEqual(result['selected']['path'], ROOT+'/de/man1/name.1.gz')
        result = view.select(ROOT, ORIGINAL, b'../man/name.1', [])
        self.assertEqual(result['selected']['path'], ROOT+'/name.1')

    def test_nested_lookup_preserves_original_page_directory_context(self):
        view = namespace(files=('man2/first.1', 'man1/final.1', 'man2/final.1'),
                         directories=('man2',))
        first = view.select(ROOT, ORIGINAL, b'man2/first.1', [])
        self.assertEqual(first['selected']['path'], ROOT+'/man2/first.1')
        second = view.select(ROOT, ORIGINAL, b'final.1', [])
        self.assertEqual(second['selected']['path'], ROOT+'/man1/final.1')

    def test_supplied_tree_mutation_cannot_change_frozen_lookup_snapshot(self):
        baseline, after = trees(files=('target.1',))
        view = lookup.Namespace(baseline, after)
        original_sha = after['manifest_sha256']
        del after['entries'][ROOT+'/target.1']
        after['entries'][ROOT]['mode'] = 0
        rehash(after)
        result = view.select(ROOT, ORIGINAL, b'target.1', [])
        self.assertEqual(result['selection_state'], 'selected')
        self.assertEqual(result['candidate_sha256'], original_sha)

    def test_absolute_symlink_to_baseline_alternatives_selector_is_followed_as_metadata(self):
        baseline, after = trees(files=('target.1',),
            links=(('link.1', '/etc/alternatives/manual-selector'),))
        for path in ('etc', 'etc/alternatives'):
            baseline['entries'][path] = dict(baseline['entries']['.'])
            after['entries'][path] = dict(after['entries']['.'])
        selector = dict(kind='symlink', uid=0, gid=0, mode=0o777, nlink=1,
                        mtime_ns=0, ctime_ns=0, xattrs={}, target='/'+ROOT+'/target.1')
        baseline['entries']['etc/alternatives/manual-selector'] = selector
        after['entries']['etc/alternatives/manual-selector'] = dict(selector, target='/unknown')
        rehash(baseline)
        rehash(after)
        result = lookup.Namespace(baseline, after).select(ROOT, ORIGINAL, b'link.1', [])
        self.assertEqual(result['selected']['path'], ROOT+'/target.1')
        self.assertFalse(result['runtime_namespace_equivalence_verified'])

    def test_absolute_empty_inert_quote_and_invalid_encoding_are_distinct(self):
        view = namespace(files=('"literal"', '$(inert)'))
        with patch.object(view, 'stat', side_effect=AssertionError('no lookup for absolute')):
            result = view.select(ROOT, ORIGINAL, b'/outside', ['gz'])
        self.assertEqual(result['selection_state'], 'ignored-absolute')
        self.assertEqual(result['attempts'], [])
        self.assertEqual(view.select(ROOT, ORIGINAL, b'', [])['selected']['kind'], 'directory')
        for operand in (b'"literal"', b'$(inert)'):
            result = view.select(ROOT, ORIGINAL, operand, [])
            self.assertEqual(result['selected']['path'], ROOT+'/'+operand.decode())
        self.assertEqual(view.select(ROOT, ORIGINAL, b'bad\xff', [])['selection_state'], 'unknown')

    def test_unsupported_attributes_and_resource_limits_never_create_authority(self):
        view = namespace(files=('target.1',), metadata={'': {'xattrs': {
            'user.unmodeled': dict(bytes=0, sha256=hashlib.sha256(b'').hexdigest())}}})
        self.assertEqual(view.select(ROOT, ORIGINAL, b'target.1', [])['selection_state'], 'unknown')
        view = namespace(files=('target.1',))
        with patch.object(lookup, 'MAX_COMPONENTS', 0):
            self.assertEqual(view.select(ROOT, ORIGINAL, b'target.1', [])['selection_state'],
                             'unknown')
        with patch.object(lookup, 'MAX_REPORT_BYTES', 0), self.assertRaises(ValueError):
            view.select(ROOT, ORIGINAL, b'target.1', [])
        for operand, extensions in ((b'x\0', []), (b'x', ['gz', 'gz']),
                                    (b'x', ['../bad']), (b'x'*4097, [])):
            with self.assertRaises(ValueError):
                view.select(ROOT, ORIGINAL, operand, extensions)
        report = view.select(ROOT, ORIGINAL, b'target.1', [])
        for key in ('filesystem_paths_opened', 'runtime_namespace_equivalence_verified',
                    'source_target_resolution_verified', 'transitive_source_graph_verified',
                    'generated_state_validated', 'changes_authorized', 'publication_authorized'):
            self.assertIs(report[key], False)
