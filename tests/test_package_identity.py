"""Portable schema/capture tests; Linux identity/capability operations are mocked."""
import contextlib
import copy
import io
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from mano_runtime import package_identity as identity


def fixture():
    namespaces = {name: name+':[123]' for name in identity.KINDS}
    before = dict(uid=[6]*3, gid=[12]*3, groups=[12],
        caps=dict(CapEff=0, CapPrm=0, CapAmb=0, CapBnd=219, CapInh=219),
        securebits=11, nnp=1, seccomp=2, label='mano-package-worker (enforce)',
        namespaces=namespaces)
    value = dict(profile=identity.PROFILE, before=before, after=copy.deepcopy(before),
        denials=dict(root_restore_errno=1, extra_capability_errno=1, securebits_reset_errno=1))
    return value, dict(uid=6, gid=12, groups=[12], namespaces=namespaces)


class PackageIdentityTests(unittest.TestCase):
    def test_complete_drop_and_denials_are_required_with_no_saved_root(self):
        value, expected = fixture()
        self.assertEqual(identity.validate(value, **expected), value)
        for section in ('before', 'after'):
            altered = copy.deepcopy(value)
            altered[section]['uid'][2] = 0
            with self.subTest(section=section), self.assertRaises(ValueError):
                identity.validate(altered, **expected)

    def test_permitted_ambient_outside_capability_and_numeric_relabeling_refuse(self):
        value, expected = fixture()
        for key, wrong in (('CapEff', 1), ('CapPrm', 219), ('CapAmb', 219),
                           ('CapBnd', 219.0), ('CapInh', 1 << 21)):
            altered = copy.deepcopy(value)
            altered['before']['caps'][key] = wrong
            with self.subTest(field=key), self.assertRaises(ValueError):
                identity.validate(altered, **expected)
        for key, wrong in (('securebits', 43), ('nnp', True), ('seccomp', 0),
                           ('label', 'unconfined'), ('groups', [0, 12])):
            altered = copy.deepcopy(value)
            altered['before'][key] = wrong
            with self.subTest(field=key), self.assertRaises(ValueError):
                identity.validate(altered, **expected)

    def test_exact_denial_codes_and_parent_namespace_match_are_mandatory(self):
        value, expected = fixture()
        for code in (0, True, 1.0):
            altered = copy.deepcopy(value)
            altered['denials']['root_restore_errno'] = code
            with self.subTest(code=code), self.assertRaises(ValueError):
                identity.validate(altered, **expected)
        altered = copy.deepcopy(value)
        altered['after']['namespaces']['mnt'] = 'mnt:[other]'
        with self.assertRaises(ValueError):
            identity.validate(altered, **expected)
        with self.assertRaises(ValueError):
            identity.validate(value, **(expected | dict(uid=0)))

    def test_mac_guards_precede_nss_proc_native_library_and_process(self):
        with patch.object(identity.sys, 'platform', 'darwin'), \
                patch.object(identity.pwd, 'getpwnam') as account, \
                patch.object(identity.ctypes, 'CDLL') as native, \
                patch.object(identity.subprocess, 'Popen') as spawn:
            for operation in (identity.state, identity.denials, identity.verify_own_drop,
                              identity.capture, identity.preflight):
                with self.subTest(operation=operation.__name__), self.assertRaises(PermissionError):
                    operation()
            account.assert_not_called()
            native.assert_not_called()
            spawn.assert_not_called()

    def test_root_child_refuses_before_any_kernel_denial_probe(self):
        with patch.object(identity.sys, 'platform', 'linux'), \
                patch.object(identity, 'account', return_value=(6, 12, [12])), \
                patch.object(identity.os, 'getresuid', return_value=(0, 0, 0), create=True), \
                patch.object(identity, 'state') as state, \
                patch.object(identity, 'denials') as denials:
            with self.assertRaises(PermissionError):
                identity.verify_own_drop()
            state.assert_not_called()
            denials.assert_not_called()

    def test_mocked_child_rechecks_identical_state_after_all_denials(self):
        value, _ = fixture()
        with patch.object(identity, 'child_guard', return_value=(6, 12, [12])), \
                patch.object(identity, 'state', side_effect=[value['before'], value['after']]), \
                patch.object(identity, 'denials', return_value=value['denials']):
            self.assertEqual(identity.verify_own_drop(), value)

    def test_parent_independently_checks_child_and_retains_its_own_state(self):
        value, _ = fixture()
        parent = copy.deepcopy(value['before'])
        parent.update(uid=[0]*3, gid=[0]*3, groups=[0])
        parent['caps'] = dict.fromkeys(identity.CAPS, 219)
        with patch.object(identity, 'parent_guard'), \
                patch.object(identity, 'account', return_value=(6, 12, [12])), \
                patch.object(identity, 'state', side_effect=[parent, copy.deepcopy(parent)]), \
                patch.object(identity, 'capture',
                    return_value=json.dumps(value).encode()) as capture:
            self.assertEqual(identity.preflight(), value)
            capture.assert_called_once_with()
        changed = copy.deepcopy(parent)
        changed['caps']['CapEff'] = 0
        with patch.object(identity, 'parent_guard'), \
                patch.object(identity, 'account', return_value=(6, 12, [12])), \
                patch.object(identity, 'state', side_effect=[parent, changed]), \
                patch.object(identity, 'capture', return_value=json.dumps(value).encode()):
            with self.assertRaises(PermissionError):
                identity.preflight()

    def portable_capture(self, program, *, timeout=2):
        original = subprocess.Popen
        calls = []

        def portable(command, **kwargs):
            calls.append((command, kwargs.copy()))
            return original([sys.executable, '-c', program], **kwargs)

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(identity, 'parent_guard'))
            stack.enter_context(patch.object(identity.subprocess, 'Popen', side_effect=portable))
            stack.enter_context(patch.object(identity.sys, 'stderr', io.StringIO()))
            try:
                return identity.capture(timeout=timeout)
            finally:
                self.assertEqual(len(calls), 1)
                command, kwargs = calls[0]
                self.assertEqual(command, list(identity.COMMAND))
                self.assertTrue(kwargs['close_fds'])
                self.assertTrue(kwargs['start_new_session'])
                self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
                self.assertEqual(kwargs['env'], identity.ENV)

    def test_fixed_capture_accepts_only_complete_zero_exit_without_stderr(self):
        self.assertEqual(self.portable_capture('print("fixed")'), b'fixed\n')
        for program in ('import sys;sys.exit(1)', 'import sys;print("bad",file=sys.stderr)'):
            with self.subTest(program=program), self.assertRaises(ValueError):
                self.portable_capture(program)

    def test_capture_bounds_output_and_handles_inherited_or_closed_pipes(self):
        with self.assertRaisesRegex(ValueError, 'output budget'):
            self.portable_capture('print("x"*8193)')
        for program in ('import os,time\nif os.fork()==0:time.sleep(10)\n',
                        'import os,time;os.close(1);os.close(2);time.sleep(10)'):
            with self.subTest(program=program), self.assertRaises(TimeoutError):
                self.portable_capture(program, timeout=.15)

    def test_invalid_deadline_never_reaches_process_creation(self):
        with patch.object(identity, 'parent_guard'), \
                patch.object(identity.subprocess, 'Popen') as spawn:
            for timeout in (True, 0, 6, None, float('nan')):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    identity.capture(timeout=timeout)
            spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main()
