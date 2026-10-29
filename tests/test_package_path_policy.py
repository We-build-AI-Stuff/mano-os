import hashlib
import stat
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mano_runtime import administration as admin
from mano_runtime import package_path_policy as policy


class PackagePolicyBindingTests(unittest.TestCase):
    def setUp(self):
        self.body = (Path(__file__).resolve().parents[1] /
                     'packaging/apparmor/mano-package-worker').read_bytes()
        self.info = dict(st_mode=stat.S_IFREG | 0o444, st_uid=0, st_nlink=1,
                         st_size=len(self.body))

    def test_packaged_policy_matches_fixed_trusted_source_digest(self):
        self.assertEqual(hashlib.sha256(self.body).hexdigest(), policy.POLICY_SHA256)
        self.assertEqual(policy.validate_source(self.body, SimpleNamespace(**self.info)), self.body)

    def test_source_custody_and_complete_content_are_required(self):
        for changed in (dict(st_uid=1002), dict(st_nlink=2), dict(st_size=1),
                        dict(st_mode=stat.S_IFREG | 0o664), dict(st_mode=stat.S_IFLNK | 0o444)):
            with self.subTest(changed=changed):
                with self.assertRaises(PermissionError):
                    policy.validate_source(self.body, SimpleNamespace(**(self.info | changed)))
        with self.assertRaises(PermissionError):
            policy.validate_source(self.body.replace(b'deny', b'xxxx', 1),
                                   SimpleNamespace(**self.info))

    def test_only_actual_exact_enforce_label_is_accepted(self):
        for label in ('unconfined', 'mano-package-worker (complain)',
                      'other (enforce)', 'mano-package-worker (enforce)//&other'):
            with self.subTest(label=label), \
                    patch.object(policy.Path, 'read_text', return_value=label):
                with self.assertRaises(PermissionError):
                    policy.verify_label()
        with patch.object(policy.Path, 'read_text',
                          return_value='mano-package-worker (enforce)\n'):
            policy.verify_label()

    def test_disabled_kernel_policy_cannot_reach_privileged_loader(self):
        with patch.object(admin, 'root'), \
                patch.object(admin.Path, 'read_text', return_value='N'), \
                patch.object(admin.subprocess, 'run') as run:
            with self.assertRaises(PermissionError):
                admin.load_package_path_policy()
            run.assert_not_called()

    def test_loader_uses_verified_stdin_and_no_model_selected_path(self):
        with patch.object(admin, 'root'), \
                patch.object(admin.Path, 'read_text', return_value='Y'), \
                patch.object(policy, 'read_source', return_value=self.body), \
                patch.object(admin.subprocess, 'run') as run:
            admin.load_package_path_policy()
        args, kwargs = run.call_args
        self.assertEqual(args[0], ['/usr/sbin/apparmor_parser', '--replace', '--skip-cache'])
        self.assertEqual(kwargs['input'], self.body)
        self.assertTrue(kwargs['check'])

    def test_untrusted_source_never_reaches_privileged_loader(self):
        with patch.object(admin, 'root'), \
                patch.object(admin.Path, 'read_text', return_value='Y'), \
                patch.object(policy, 'read_source', side_effect=PermissionError('untrusted')), \
                patch.object(admin.subprocess, 'run') as run:
            with self.assertRaises(PermissionError):
                admin.load_package_path_policy()
            run.assert_not_called()
