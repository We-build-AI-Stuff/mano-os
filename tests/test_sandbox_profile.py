import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mano_broker.sandbox import command, guard


class SandboxProfileGuards(unittest.TestCase):
    def test_user_owned_guard_never_accepted(self):
        with TemporaryDirectory() as temporary:
            native = Path(temporary) / "guard"
            native.write_text("untrusted fixture")
            native.chmod(0o555)
            with patch("mano_broker.sandbox.GUARD", native):
                with self.assertRaises(PermissionError):
                    guard()

    def test_private_shared_memory_requires_explicit_desktop_pty(self):
        for options in (dict(desktop=True), dict(desktop='true', task_pty=True),
                        dict(desktop=True, task_pty=True, read_only=True)):
            with self.subTest(options=options), self.assertRaisesRegex(
                    ValueError, 'desktop PTY profile'):
                command(3, 4, ['true'], **options)

    def test_root_or_nonlinux_never_compiles_or_checks_package(self):
        for platform, uid in (("darwin", 1004), ("linux", 0)):
            with (
                patch("mano_broker.sandbox.sys.platform", platform),
                patch("mano_broker.sandbox.os.geteuid", return_value=uid),
                patch("mano_broker.sandbox.require_patched") as package,
            ):
                with self.assertRaises(PermissionError):
                    command(3, 4, ["true"])
                package.assert_not_called()
