import subprocess
import tempfile
import unittest
from pathlib import Path


class BrokerFramingCustodyTests(unittest.TestCase):
    def test_framing_failure_copies_guest_witnesses_before_exit(self):
        source = (Path(__file__).resolve().parents[1] / 'scripts/run_vm_lab.sh').read_text()
        start = source.index('  # Progress belongs on stderr.')
        end = source.index('\n  ssh "${ssh_opts[@]}" lab@127.0.0.1', start)
        fragment = source[start:end]
        prolog = '''set -euo pipefail
repo_root=$1
fixture_evidence=$2
ssh_opts=(fixture-option)
ssh() { command tar -cf - -C "$fixture_evidence" .; }
'''
        for report, status in (('progress\n{}', 3), ('[]', 3), ('', 3), ('{}', 0)):
            with self.subTest(report=report), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repo, guest = root / 'repo', root / 'guest'
                (repo / 'evidence').mkdir(parents=True)
                guest.mkdir()
                (repo / 'evidence/broker-service.json').write_text(report)
                (guest / 'package-apply.json').write_bytes(b'preserved witness')
                result = subprocess.run(['bash', '-c', prolog + fragment, 'bash', str(repo),
                                         str(guest)], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, status, result.stderr.decode())
                witness = repo / 'evidence/package-apply.json'
                if status:
                    self.assertEqual(witness.read_bytes(), b'preserved witness')
                else:
                    self.assertFalse(witness.exists())
