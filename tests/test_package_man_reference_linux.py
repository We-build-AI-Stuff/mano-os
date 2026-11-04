"""Linux CI kernel comparisons on self-created files, never staged manual data.

The caller owns every fixture; ownership is mapped to modeled UID6/GID12.
These checks do not establish the real source-content domain's credentials,
mounts, man-db caller flags, initial hardlinks, or native library semantics.
"""
import errno
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from test_package_man_reference_lookup import ORIGINAL, ROOT, trees
from test_package_man_sources import rehash

from mano_runtime.package_man_reference_lookup import Namespace


@unittest.skipUnless(sys.platform == 'linux' and os.environ.get('GITHUB_ACTIONS') == 'true'
                     and os.getuid() != 0, 'Disposable unprivileged Linux CI only')
class KernelReferenceLookupTests(unittest.TestCase):
    def test_fixed_kernel_traversals_match_conditional_stat_and_selection(self):
        baseline, candidate = trees(
            files=('target.1.gz', 'target.1.xz', 'plain.1', 'plain.1.gz',
                   'dangling.1.gz', 'cycle.1.gz', 'poison.1.xz', 'man1/local.1.gz',
                   'goal.1', 'man2/goal.1', 'blocked/hidden.1', 'unreadable.1',
                   'literal "$(inert)".1'),
            directories=('man2/deep', 'poison.1.gz', 'blocked', 'no-search'),
            links=(('bridge', 'man2/deep'), ('file-link', 'plain.1'),
                   ('dangling.1', 'absent'), ('cycle.1', 'cycle.1'),
                   ('absolute-link', '/usr/share/man/man2/deep'),
                   ('link-a', 'link-b'), ('link-b', 'goal.1')),
            modes={'blocked': 0o600, 'no-search': 0o600, 'unreadable.1': 0})
        for tree in (baseline, candidate):
            for row in tree['entries'].values():
                row.update(uid=6, gid=12)
            rehash(tree)
        namespace = Namespace(baseline, candidate)
        with tempfile.TemporaryDirectory(prefix='mano-kernel-reference-') as temporary:
            root = Path(temporary)
            # Construct while searchable, apply denied search modes last. Cleanup
            # restores only our fixed fixture directories before removing them.
            directories = []
            for path, row in sorted(candidate['entries'].items()):
                target = root if path == '.' else root / path
                if row['kind'] == 'directory':
                    target.mkdir(exist_ok=True)
                    directories.append((target, row['mode']))
                elif row['kind'] == 'file':
                    target.write_bytes(b'fixed synthetic kernel fixture\n')
                    target.chmod(row['mode'])
                elif row['kind'] == 'symlink':
                    value = row['target']
                    os.symlink(str(root)+value if value.startswith('/') else value, target)
                else:
                    self.fail('Unexpected synthetic fixture kind')
            for path, mode in reversed(directories):
                path.chmod(mode)
            try:
                paths = ('plain.1', 'unreadable.1', 'missing', 'plain.1/', 'plain.1/.',
                         'file-link/../goal.1', 'bridge/../goal.1',
                         'absolute-link/../goal.1', 'link-a', 'cycle.1', 'dangling.1',
                         'no-search/', 'no-search/.', 'blocked/hidden.1', 'man2/deep/..',
                         'literal "$(inert)".1', 'a'*256)
                for path in paths:
                    for follow in (True, False):
                        with self.subTest(path=path, follow_final=follow):
                            result = namespace.stat(ROOT+'/'+path, follow_final=follow)
                            native_path = str(root / ROOT)+'/'+path
                            try:
                                actual = os.stat(native_path, follow_symlinks=follow)
                            except OSError as error:
                                self.assertEqual(result['state'], 'unavailable')
                                self.assertEqual(result['reason'], errno.errorcode[error.errno])
                            else:
                                self.assertEqual(result['state'], 'exists')
                                expected = os.stat(root / result['terminal_path'],
                                                   follow_symlinks=follow)
                                self.assertEqual((actual.st_dev, actual.st_ino),
                                                 (expected.st_dev, expected.st_ino))
                                kind = ('directory' if stat.S_ISDIR(actual.st_mode) else
                                        'symlink' if stat.S_ISLNK(actual.st_mode) else 'file')
                                self.assertEqual(result['kind'], kind)
                for operand in ('target.1', 'plain.1', 'dangling.1', 'cycle.1', 'poison.1',
                                'local.1', 'bridge/../goal.1', 'unreadable.1', 'absent'):
                    with self.subTest(operand=operand):
                        modeled = namespace.select(ROOT, ORIGINAL, operand.encode(), ['gz', 'xz'])
                        actual = None
                        for prefix in (ROOT, ORIGINAL.rsplit('/', 1)[0]):
                            for suffix in ('', '.gz', '.xz'):
                                path = root / prefix / (operand+suffix)
                                if not suffix and not os.access(path, os.F_OK):
                                    continue
                                try:
                                    actual = os.stat(path)
                                except OSError:
                                    continue
                                break
                            if actual is not None:
                                break
                        if actual is None:
                            self.assertEqual(modeled['selection_state'], 'unresolved')
                        else:
                            self.assertEqual(modeled['selection_state'], 'selected')
                            expected = os.stat(root / modeled['selected']['path'])
                            self.assertEqual((actual.st_dev, actual.st_ino),
                                             (expected.st_dev, expected.st_ino))
            finally:
                for path, _mode in directories:
                    path.chmod(0o700)
