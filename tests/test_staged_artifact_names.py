import importlib.util
import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/staged_artifact_names.py'
SPEC = importlib.util.spec_from_file_location('staged_names', SCRIPT)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class StagedNamesTests(unittest.TestCase):
    def test_names_are_sorted_nul_framed_without_a_glob(self):
        packet = module.names({'artifact_sha256': {'staged-z.bin': 'a'*64,
                                                   'staged-a.json': 'b'*64}})
        self.assertEqual(packet, b'staged-a.json\0staged-z.bin\0')
        self.assertNotIn(b'*', packet)

    def test_empty_malformed_and_over_budget_maps_fail(self):
        for report in ([], {}, {'artifact_sha256': {}}, {'artifact_sha256': []},
                       {'artifact_sha256': {f'staged-{n}': 'a'*64 for n in range(65)}}):
            with self.subTest(report=type(report)), self.assertRaises(ValueError):
                module.names(report)

    def test_paths_options_control_bytes_and_malformed_hashes_fail(self):
        for name in ('../escape', '/tmp/staged-x', '--checkpoint-action=exec=bad',
                     'staged-a/b', 'staged-*', 'staged-a\0b', 'staged-a\nb'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                module.names({'artifact_sha256': {name: 'a'*64}})
        with self.assertRaises(ValueError):
            module.names({'artifact_sha256': {'staged-safe': 'A'*64}})

    @unittest.skipUnless(sys.platform == 'linux', 'GNU tar CI transfer regression')
    def test_gnu_tar_creates_archive_from_exact_nul_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'staged-a.json').write_bytes(b'report')
            (root/'staged-b.bin').write_bytes(b'archive')
            packet = module.names({'artifact_sha256': {'staged-b.bin': 'a'*64,
                                                       'staged-a.json': 'b'*64}})
            result = subprocess.run(['tar', '-cf', '-', '-C', str(root), '--null',
                                     '--verbatim-files-from', '--files-from=-'],
                                    input=packet, capture_output=True, check=True, timeout=5)
            with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
                self.assertEqual(archive.getnames(), ['staged-a.json', 'staged-b.bin'])
                self.assertEqual(archive.extractfile('staged-a.json').read(), b'report')
                self.assertEqual(archive.extractfile('staged-b.bin').read(), b'archive')
