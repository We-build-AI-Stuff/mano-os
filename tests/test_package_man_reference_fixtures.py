"""Mocked fixed-path custody tests; no Linux/Root probes or live file opens."""
import copy
import errno
import hashlib
import importlib.util
import io
import json
import stat
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from test_package_man_reference_lookup import trees
from test_staged_package_probe import SCRIPTS

from mano_runtime import package_man_source_content as worker
from mano_runtime.package_man_reference_lookup import ROOT, Namespace

SPEC = importlib.util.spec_from_file_location('reference_fixture_probe',
    SCRIPTS/'probe_package_man_reference_fixtures.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class ReferenceFixtureCustodyTests(unittest.TestCase):
    def fixtures(self):
        observed = {}
        for index, name in enumerate(sorted(set(worker.REFERENCE_DIRECTORIES)
                | set(worker.REFERENCE_FILES) | set(worker.REFERENCE_LINKS))):
            row = dict(device=37, inode=100+index, uid=0, gid=0, mode=0o644,
                       nlink=1, mtime_ns=0, ctime_ns=0, xattrs={}, size=0)
            if name in worker.REFERENCE_DIRECTORIES:
                row.update(kind='directory', nlink=2)
                row['uid'], row['gid'], row['mode'] = worker.REFERENCE_DIRECTORIES[name]
            elif name in worker.REFERENCE_LINKS:
                row.update(kind='symlink', mode=0o777, target=worker.REFERENCE_LINKS[name])
            else:
                data = b'fixed-reference-fixture:'+name.encode()+b'\n'
                row.update(kind='file', bytes=len(data), size=len(data),
                           sha256=hashlib.sha256(data).hexdigest())
                if name == 'unreadable.1':
                    row['mode'] = 0
            observed[name] = row
        baseline, _ = trees()
        baseline['entries']['var'] = dict(baseline['entries']['.'])
        baseline['entries']['var/cache'] = dict(baseline['entries']['.'])
        model = probe.model_tree(observed, baseline)
        namespace = Namespace(model, model)

        def fake_stat(path, *, follow_symlinks=True):
            self.assertTrue(path.startswith(worker.REFERENCE_ROOT+'/'))
            normalized = ROOT+path[len(worker.REFERENCE_ROOT):]
            result = namespace.stat(normalized, follow_final=follow_symlinks)
            if result['state'] != 'exists':
                self.assertEqual(result['state'], 'unavailable')
                raise OSError(getattr(errno, result['reason']), 'fixed synthetic result')
            name = result['terminal_path'][len(ROOT):].removeprefix('/')
            row = observed[name]
            kind = {'file': stat.S_IFREG, 'directory': stat.S_IFDIR, 'symlink': stat.S_IFLNK}
            return SimpleNamespace(st_dev=row['device'], st_ino=row['inode'],
                st_uid=row['uid'], st_gid=row['gid'], st_mode=row['mode'] | kind[row['kind']])

        def fake_access(path, mode):
            self.assertEqual(mode, 0)
            try:
                fake_stat(path)
            except OSError:
                return False
            return True

        with patch.object(worker.os, 'stat', fake_stat), \
                patch.object(worker.os, 'access', fake_access), \
                patch.object(worker.os, 'getuid', return_value=6), \
                patch.object(worker.os, 'getgid', return_value=12), \
                patch.object(worker.os, 'getgroups', return_value=[]):
            native = worker.reference_fixture_results()
        return native, observed, model

    def test_fixed_mocked_witnesses_bind_all_cases_without_native_claim(self):
        native, observed, model = self.fixtures()
        self.assertEqual(model['entries'][ROOT+'/absolute-link']['target'],
                         '/usr/share/man/man2/deep')
        errors = {(row['path'], row['follow_final']): row['outcome'].get('errno')
                  for row in native['queries']}
        self.assertEqual(errors[('cycle.1', True)], 40)
        self.assertEqual(errors[('a'*256, False)], 36)
        report = probe.compare(native, observed, model)
        self.assertEqual(report['stat_lstat_queries'], 40)
        self.assertEqual(report['selection_queries'], 9)
        self.assertTrue(report['declared_kernel_fixture_matches_metadata_model'])
        self.assertFalse(report['actual_source_namespace_equivalence_verified'])
        self.assertFalse(report['native_man_db_caller_semantics_verified'])

    def test_crossed_inode_permissions_errors_order_and_false_authority_refuse(self):
        native, observed, model = self.fixtures()
        missing = next(i for i, row in enumerate(native['queries'])
                       if row['outcome']['state'] == 'unavailable')
        for mutate in (
            lambda row: row['queries'][0]['outcome'].update(inode=0),
            lambda row: row['queries'][0]['outcome'].update(mode=0),
            lambda row: row['queries'][missing]['outcome'].update(errno=errno.EIO),
            lambda row: row['queries'].pop(),
            lambda row: row['queries'].reverse(),
            lambda row: row['selections'][0]['attempts'].pop(0),
            lambda row: row['selections'][0]['attempts'][0].update(access_f_ok=True),
            lambda row: row.update(configured_extensions=['xz', 'gz']),
            lambda row: row.update(groups=[0]),
            lambda row: row.update(source_inputs_opened=True),
            lambda row: row.update(publication_authorized=True),
        ):
            changed = copy.deepcopy(native)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                probe.compare(changed, observed, model)

    def test_exact_request_dispatch_never_reads_source_capture(self):
        output = io.BytesIO()
        with patch.object(worker.sys, 'platform', 'linux'), \
                patch.object(worker.sys, 'argv', ['fixed-worker']), \
                patch.object(worker.os, 'getresuid', return_value=(6, 6, 6), create=True), \
                patch.object(worker.os, 'getresgid', return_value=(12, 12, 12), create=True), \
                patch.object(worker.os, 'getgroups', return_value=[]), \
                patch.object(worker, 'read_fixed', return_value=worker.REFERENCE_REQUEST) as read, \
                patch.object(worker, 'reference_fixture_results', return_value={'fixed': True}), \
                patch.object(worker.sys, 'stdout', SimpleNamespace(buffer=output)):
            worker.main()
        read.assert_called_once_with('/run/man-source-paths.json', 4*1024**2, mode=0o444)
        self.assertEqual(json.loads(output.getvalue()), {'fixed': True})

    def test_fixture_mode_retains_report_budget(self):
        exactly_full_without_newline = {'x': 'a'*(262144-9)}
        self.assertEqual(len(json.dumps(exactly_full_without_newline).encode()), 262144)
        with patch.object(worker.sys, 'platform', 'linux'), \
                patch.object(worker.sys, 'argv', ['fixed-worker']), \
                patch.object(worker.os, 'getresuid', return_value=(6, 6, 6), create=True), \
                patch.object(worker.os, 'getresgid', return_value=(12, 12, 12), create=True), \
                patch.object(worker.os, 'getgroups', return_value=[]), \
                patch.object(worker, 'read_fixed', return_value=worker.REFERENCE_REQUEST), \
                patch.object(worker, 'reference_fixture_results',
                             return_value=exactly_full_without_newline):
            with self.assertRaises(ValueError):
                worker.main()

    def test_fixture_command_changes_only_readonly_request_and_shorter_deadline(self):
        from probe_package_man_source_content import content_sandbox, content_unit

        BASE = probe.BASE
        original = content_unit()+content_sandbox(BASE, [], BASE/'empty', '0'*64)
        expected = list(original)
        expected[expected.index(str(BASE/'man-source-paths.json'))] = str(
            BASE/'man-reference-fixture-request.json')
        expected[expected.index('--property=RuntimeMaxSec=190')] = '--property=RuntimeMaxSec=30'
        self.assertEqual(probe.fixture_command(BASE, [], BASE/'empty', '0'*64), expected)

    def test_controller_refuses_mac_and_nonroot_before_any_fixture_access(self):
        BASE = probe.BASE
        with patch('sys.platform', 'darwin'), self.assertRaises(PermissionError):
            probe.capture_reference_fixtures(BASE, {}, [], BASE/'empty', '0'*64, None)
        with patch('sys.platform', 'linux'), patch('os.geteuid', return_value=1000), \
                self.assertRaises(PermissionError):
            probe.capture_reference_fixtures(BASE, {}, [], BASE/'empty', '0'*64, None)

    def test_retained_linux_observations_reject_relative_absolute_link_and_host_errno_drift(self):
        record = json.loads((SCRIPTS.parent/'tests/fixtures/'
            'man-reference-linux-x86-64-errors.json').read_text())
        self.assertFalse(record['native35_accepted'])
        _, _, tree = self.fixtures()
        namespace = Namespace(tree, tree)
        linux_errors = {'ENOENT': 2, 'ENOTDIR': 20, 'EACCES': 13, 'ELOOP': 40,
                        'ENAMETOOLONG': 36}

        def compare(actual, modeled, plain=False):
            if modeled['state'] == 'unavailable':
                expected = dict(state='unavailable')
                if not plain:
                    expected['errno'] = linux_errors[modeled['reason']]
            else:
                self.assertEqual(modeled['state'], 'exists')
                row = namespace._entries[modeled['terminal_path']]
                expected = dict(state='exists', **{key: row[key] for key in
                                ('kind', 'uid', 'gid', 'mode')})
            self.assertEqual(actual, expected)

        for row in record['queries']:
            compare(row['outcome'], namespace.stat(ROOT+'/'+row['path'],
                    follow_final=row['follow_final']))
        for row in record['selections']:
            result = namespace.select(ROOT, ROOT+'/man1/original.1',
                row['operand'].encode(), ['gz', 'xz'])
            self.assertEqual(len(row['attempts']), len(result['attempts']))
            for actual, expected in zip(row['attempts'], result['attempts'], strict=True):
                self.assertEqual(actual['path'], worker.REFERENCE_ROOT+expected['path'][len(ROOT):])
                self.assertEqual(actual['extension'], expected['extension'])
                compare(actual['outcome'], expected['outcome'], plain=not expected['extension'])


if __name__ == '__main__':
    unittest.main()
