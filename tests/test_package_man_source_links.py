import copy
import hashlib
import unittest
from unittest.mock import patch

from test_package_man_sources import candidate, index, rehash

from mano_runtime import package_man_source_links as links


def fixture():
    tree, source = candidate(link=True)
    target = 'usr/share/man/man6/target.6.gz'
    row = dict(kind='file', uid=0, gid=0, mode=0o644, bytes=4,
               sha256=hashlib.sha256(b'data').hexdigest(), mtime_ns=1,
               ctime_ns=1, nlink=1, xattrs={}, hardlink_anchor=target)
    tree['entries'][target] = row
    tree['entries'][source]['target'] = 'target.6.gz'
    return tree, source, target


class ManualSourceLinkTests(unittest.TestCase):
    def test_bound_link_and_terminal_hash_are_data_only(self):
        tree, source, target = fixture()
        rehash(tree)
        report = links.inspect({'var/cache/man/index.db': index(kind=b'B')}, tree)
        row = report['sources'][source]
        self.assertTrue(row['primary_symlink_chain_bound'])
        self.assertEqual(row['terminal_path'], target)
        self.assertEqual(row['terminal_sha256'], hashlib.sha256(b'data').hexdigest())
        self.assertEqual(row['symlinks'][0]['target'], 'target.6.gz')
        self.assertEqual(report['primary_symlink_chains_bound'], 1)
        for flag in ('filesystem_paths_opened', 'terminal_bytes_interpreted',
                     'roff_includes_verified', 'virtual_alias_declarations_verified',
                     'transitive_source_graph_verified', 'descriptions_verified',
                     'cache_sources_verified', 'generated_state_validated',
                     'changes_authorized', 'publication_authorized'):
            self.assertIs(report[flag], False)

    def test_regular_source_also_binds_opaque_terminal_hash(self):
        tree, source = candidate()
        report = links.inspect({'var/cache/man/index.db': index()}, tree)
        self.assertTrue(report['all_primary_symlink_chains_bound'])
        self.assertEqual(report['sources'][source]['symlinks'], [])

    def test_relative_parent_and_absolute_inside_root_are_resolved(self):
        tree, source, target = fixture()
        for destination in ('../man6/target.6.gz', '/usr/share/man/man6/target.6.gz',
                            './target.6.gz', '../man6//target.6.gz'):
            tree['entries'][source]['target'] = destination
            with self.subTest(destination=destination):
                self.assertEqual(links.resolve(tree['entries'], source)['terminal_path'], target)

    def test_source_cannot_escape_even_if_observation_contains_external_target(self):
        tree, source, target = fixture()
        tree['entries']['etc/shadow'] = copy.deepcopy(tree['entries'][target])
        for destination in ('/etc/shadow', '../../../../etc/shadow',
                            '/usr/share/man/../../../etc/shadow', '../../man/man6/target.6.gz'):
            tree['entries'][source]['target'] = destination
            with self.subTest(destination=destination):
                row = links.resolve(tree['entries'], source)
                self.assertFalse(row['primary_symlink_chain_bound'])
                self.assertEqual(row['reason'], 'source-link-escapes-manual-root')

    def test_link_dotdot_is_followed_before_parent_is_evaluated(self):
        tree, source, target = fixture()
        # jump/.. reaches the locale directory, not man6. Lexical collapse
        # would incorrectly choose the existing man6/target.6.gz.
        directory = copy.deepcopy(tree['entries']['usr/share/man/man6'])
        tree['entries']['usr/share/man/de'] = directory
        tree['entries']['usr/share/man/de/man6'] = copy.deepcopy(directory)
        jump = copy.deepcopy(tree['entries'][source])
        jump['target'] = '../de/man6'
        tree['entries']['usr/share/man/man6/jump'] = jump
        tree['entries'][source]['target'] = 'jump/../target.6.gz'
        row = links.resolve(tree['entries'], source)
        self.assertFalse(row['primary_symlink_chain_bound'])
        self.assertEqual(row['reason'], 'source-link-target-absent')
        actual = 'usr/share/man/de/target.6.gz'
        tree['entries'][actual] = copy.deepcopy(tree['entries'][target])
        self.assertEqual(links.resolve(tree['entries'], source)['terminal_path'], actual)

    def test_regular_file_cannot_be_traversed_as_a_directory_even_with_dotdot(self):
        tree, source, _ = fixture()
        for target in ('target.6.gz/../target.6.gz', 'target.6.gz/.', 'target.6.gz/'):
            tree['entries'][source]['target'] = target
            with self.subTest(target=target):
                self.assertFalse(
                    links.resolve(tree['entries'], source)['primary_symlink_chain_bound'])

    def test_cycle_depth_and_expansion_budgets_fail_closed(self):
        tree, source, _ = fixture()
        tree['entries'][source]['target'] = 'sl.6.gz'
        self.assertEqual(links.resolve(tree['entries'], source)['reason'], 'source-link-cycle')
        tree['entries'][source]['target'] = './sl.6.gz/extra'
        with patch.object(links, 'MAX_LINKS', 3):
            self.assertEqual(links.resolve(tree['entries'], source)['reason'],
                             'source-link-depth-budget')
        tree['entries'][source]['target'] = 'x/'*129+'target'
        self.assertEqual(links.resolve(tree['entries'], source)['reason'],
                         'source-link-path-budget')

    def test_repeated_symlink_with_shortening_pending_path_is_not_a_cycle(self):
        tree, source, target = fixture()
        repeat = copy.deepcopy(tree['entries'][source])
        repeat['target'] = '.'
        tree['entries']['usr/share/man/man6/repeat'] = repeat
        tree['entries'][source]['target'] = 'repeat/repeat/target.6.gz'
        self.assertEqual(links.resolve(tree['entries'], source)['terminal_path'], target)

    def test_missing_unsafe_owner_aliased_parent_and_special_terminal_are_unbound(self):
        original, source, target = fixture()
        mutations = (
            lambda e: e.pop(target),
            lambda e: e[target].update(uid=6),
            lambda e: e[target].update(mode=0o666),
            lambda e: e[target].update(kind='fifo'),
            lambda e: e[source].update(uid=6),
            lambda e: e['usr/share'].update(kind='symlink', target='/outside'),
            lambda e: e['usr/share/man/man6'].update(mode=0o777),
        )
        for mutate in mutations:
            tree = copy.deepcopy(original)
            mutate(tree['entries'])
            with self.subTest(mutate=mutate):
                self.assertFalse(
                    links.resolve(tree['entries'], source)['primary_symlink_chain_bound'])

    def test_tree_and_record_binding_cannot_be_supplied_as_green_claims(self):
        tree, source, _ = fixture()
        rehash(tree)
        tree['entries'][source]['target'] = '/outside'
        with self.assertRaises(ValueError):
            links.inspect({'var/cache/man/index.db': index(kind=b'B')}, tree)
        rehash(tree)
        report = links.inspect({'var/cache/man/index.db': index(kind=b'B')}, tree)
        self.assertFalse(report['all_primary_symlink_chains_bound'])
        with patch.object(links, 'MAX_REPORT_BYTES', 0), self.assertRaises(ValueError):
            links.inspect({'var/cache/man/index.db': index(kind=b'B')}, tree)
