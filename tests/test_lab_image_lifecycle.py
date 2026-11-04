import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('lab_image_lifecycle',
    Path(__file__).resolve().parents[1] / 'scripts/lab_image_lifecycle.py')
images = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(images)


class LabImageLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.uid = os.geteuid()
        self.job = dict(run='123', attempt='1', job='security-lab', uid=self.uid)
        # Ordinary tiny fixture files, not actual VM images; no VM/native execution.
        for name in (*images.IMAGES, images.PRISTINE):
            (self.directory / name).write_bytes(b'fixture')
        (self.directory / images.PRISTINE).chmod(0o444)
        self.recorded = images.snapshot(self.directory, self.uid, self.job)

    def tearDown(self):
        self.temp.cleanup()

    def test_plan_selects_only_job_images_and_retains_base_and_unrelated_files(self):
        (self.directory / 'user-notes').write_text('retain')
        names = images.validate(self.directory, self.uid, self.job, self.recorded)
        self.assertEqual(set(names), set(images.IMAGES))
        self.assertNotIn(images.PRISTINE, names)
        self.assertNotIn('user-notes', names)
        self.assertTrue(all((self.directory / name).exists() for name in names))

    def test_wrong_job_or_replaced_image_is_rejected_before_any_release(self):
        with self.assertRaises(ValueError):
            images.validate(self.directory, self.uid, self.job | dict(run='other'), self.recorded)
        name = images.IMAGES[0]
        (self.directory / name).rename(self.directory / 'original')
        (self.directory / name).write_bytes(b'replacement')
        with self.assertRaises(ValueError):
            images.validate(self.directory, self.uid, self.job, self.recorded)
        self.assertTrue((self.directory / 'original').exists())

    def test_symlinks_and_hardlinks_are_rejected(self):
        name = images.IMAGES[0]
        (self.directory / name).rename(self.directory / 'original')
        (self.directory / name).symlink_to('original')
        with self.assertRaises(ValueError):
            images.validate(self.directory, self.uid, self.job, self.recorded)
        (self.directory / name).unlink()
        os.link(self.directory / 'original', self.directory / name)
        with self.assertRaises(ValueError):
            images.snapshot(self.directory, self.uid, self.job)

    def test_base_must_remain_readonly_and_caller_cannot_add_release_paths(self):
        altered = self.recorded | dict(images=self.recorded['images'] | {'../user-data': {}})
        with self.assertRaises(ValueError):
            images.validate(self.directory, self.uid, self.job, altered)
        (self.directory / images.PRISTINE).chmod(0o644)
        with self.assertRaises(ValueError):
            images.validate(self.directory, self.uid, self.job, self.recorded)

    def test_eligibility_excludes_personal_hosts_root_and_other_workspaces(self):
        env = dict(MANO_DISPOSABLE_CI='1', GITHUB_ACTIONS='true', GITHUB_RUN_ID='123',
                   GITHUB_JOB='security-lab', GITHUB_WORKSPACE=str(self.directory))
        self.assertTrue(images.eligible(env, 'linux', 1001, self.directory))
        self.assertFalse(images.eligible(env, 'darwin', 1001, self.directory))
        self.assertFalse(images.eligible(env, 'linux', 0, self.directory))
        self.assertFalse(images.eligible(env | dict(GITHUB_ACTIONS='false'),
                                         'linux', 1001, self.directory))
        with (patch.object(images.sys, 'argv', ['helper', 'release']),
              patch.object(images.sys, 'platform', 'darwin'),
              patch.object(images.Path, 'unlink') as unlink):
            self.assertEqual(images.main(), 0)
            unlink.assert_not_called()

    def test_complete_lifecycle_releases_only_tiny_owned_fixture_files(self):
        # Portable filesystem test in a new temporary fake checkout. No real
        # VM files, Linux probes, user paths or privileged operations are used.
        root = self.directory / 'fake-checkout'
        vm = root / 'work/vm'
        vm.mkdir(parents=True)
        (root / 'evidence').mkdir()
        for name in (*images.IMAGES, images.PRISTINE, 'user-notes'):
            (vm / name).write_bytes(b'fixture')
        (vm / images.PRISTINE).chmod(0o444)
        env = dict(GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1', GITHUB_JOB='security-lab')
        with (patch.object(images, 'ROOT', root),
              patch.object(images, 'eligible', return_value=True),
              patch.dict(images.os.environ, env), patch('builtins.print')):
            with patch.object(images.sys, 'argv', ['helper', 'record']):
                self.assertEqual(images.main(), 0)
            with patch.object(images.sys, 'argv', ['helper', 'release']):
                self.assertEqual(images.main(), 0)
        self.assertTrue(all(not (vm / name).exists() for name in images.IMAGES))
        self.assertEqual((vm / images.PRISTINE).read_bytes(), b'fixture')
        self.assertEqual((vm / 'user-notes').read_bytes(), b'fixture')
        import json

        receipt = json.loads((root / 'evidence/released-vm-images.json').read_text())
        self.assertEqual(receipt['status'], 'released')
        self.assertEqual(receipt['released'], list(images.IMAGES))
