import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mano_runtime import package_tree_worker as worker


class TreeCollectorAdmissionTests(unittest.TestCase):
    def status(self, **changes):
        values = dict(CapEff=worker.REQUIRED_CAPS, CapPrm=worker.REQUIRED_CAPS,
                      CapBnd=worker.REQUIRED_CAPS, CapInh=0, CapAmb=0, NoNewPrivs=1)
        values.update(changes)
        return '\n'.join(key+': '+(str(value) if key == 'NoNewPrivs' else format(value, 'x'))
                         for key, value in values.items())

    def test_mac_refuses_before_root_io_processes_or_resource_changes(self):
        with patch.object(worker.sys, 'platform', 'darwin'), \
                patch.object(worker.Path, 'read_text') as read, \
                patch.object(worker.subprocess, 'check_output') as process, \
                patch.object(worker.resource, 'setrlimit') as limits:
            with self.assertRaises(PermissionError):
                worker.main()
            read.assert_not_called()
            process.assert_not_called()
            limits.assert_not_called()

    def test_unprivileged_or_unmarked_context_refuses_before_marker_io(self):
        for uid, marker in ((1000, '1'), (0, '0')):
            with self.subTest(uid=uid, marker=marker), \
                    patch.object(worker.sys, 'platform', 'linux'), \
                    patch.object(worker.os, 'geteuid', return_value=uid), \
                    patch.dict(worker.os.environ, {'MANO_DISPOSABLE_CI': marker}), \
                    patch.object(worker.Path, 'read_text') as read:
                with self.assertRaises(PermissionError):
                    worker.guard()
                read.assert_not_called()

    def test_fixed_kernel_capability_shape_and_nnp_are_required(self):
        cases = [{}, {'CapEff': 0}, {'CapBnd': worker.REQUIRED_CAPS | 1},
                 {'CapInh': worker.REQUIRED_CAPS}, {'CapAmb': worker.REQUIRED_CAPS},
                 {'NoNewPrivs': 0}]
        for changes in cases:
            with self.subTest(changes=changes), \
                    patch.object(worker.sys, 'platform', 'linux'), \
                    patch.object(worker.os, 'geteuid', return_value=0), \
                    patch.dict(worker.os.environ, {'MANO_DISPOSABLE_CI': '1'}), \
                    patch.object(worker.Path, 'read_text',
                        side_effect=['mano-phase0-ci', self.status(**changes)]), \
                    patch.object(worker.subprocess, 'check_output', return_value='kvm\n'):
                if changes:
                    with self.assertRaises(PermissionError):
                        worker.guard()
                else:
                    self.assertEqual(worker.guard()['CapBnd'], worker.REQUIRED_CAPS)

    def test_unknown_snapshot_role_refuses_before_resource_or_directory_operations(self):
        with patch.object(worker, 'guard'), patch.object(worker.sys, 'argv',
                ['worker', '../arbitrary-root']), \
                patch.object(worker.resource, 'setrlimit') as limits, \
                patch.object(worker.os, 'open') as opened:
            with self.assertRaisesRegex(ValueError, 'Fixed snapshot role'):
                worker.main()
            limits.assert_not_called()
            opened.assert_not_called()

    def test_wrong_cgroup_or_kernel_resource_limits_refuse_before_directory_io(self):
        group = '0::/mano.slice/mano-package.slice/mano-tree-baseline-ci.service'
        for fields in (['0::/other'], [group, '1', '8'], [group, '536870912', '9']):
            with self.subTest(fields=fields), patch.object(worker, 'guard'), \
                    patch.object(worker.sys, 'argv', ['worker', 'baseline']), \
                    patch.object(worker.resource, 'setrlimit'), \
                    patch.object(worker.Path, 'read_text', side_effect=fields), \
                    patch.object(worker.os, 'open') as opened:
                with self.assertRaises(PermissionError):
                    worker.main()
                opened.assert_not_called()

    def test_nonprivate_or_nonroot_owned_base_is_refused_and_descriptor_closed(self):
        group = '0::/mano.slice/mano-package.slice/mano-tree-baseline-ci.service'
        for uid, mode in ((1000, 0o40700), (0, 0o40755)):
            with self.subTest(uid=uid, mode=mode), patch.object(worker, 'guard'), \
                    patch.object(worker.sys, 'argv', ['worker', 'baseline']), \
                    patch.object(worker.resource, 'setrlimit'), \
                    patch.object(worker.Path, 'read_text', side_effect=[group, '536870912', '8']), \
                    patch.object(worker.os, 'open', return_value=10) as opened, \
                    patch.object(worker.os, 'fstat', return_value=SimpleNamespace(
                        st_uid=uid, st_mode=mode)), patch.object(worker.os, 'close') as close, \
                    patch.object(worker, 'scan') as scan:
                with self.assertRaises(PermissionError):
                    worker.main()
                opened.assert_called_once()
                scan.assert_not_called()
                close.assert_called_once_with(10)
