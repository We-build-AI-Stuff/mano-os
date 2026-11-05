import ast
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('probe_redteam_corpus',
                                             ROOT / 'scripts/probe_redteam_corpus.py')
corpus = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(corpus)


class RedteamCorpusTests(unittest.TestCase):
    def test_declared_cases_and_payload_are_fixed_bounded_data_without_execution(self):
        declared = json.loads((ROOT / 'tests/redteam/corpus.json').read_text())
        self.assertEqual(declared, dict(schema_version='1.0', cases=corpus.CASE_SOURCES))
        files = {name: (ROOT / relative).read_text() for name, relative in corpus.FILES.items()}
        argv = corpus.payload(files, 'redteam-' + 'a'*16, '/run/synthetic-ci-canary')
        self.assertTrue(all(len(arg.encode()) <= 4096 for arg in argv))
        self.assertLess(len(json.dumps(argv).encode()), 65536)
        body = json.loads(''.join(argv[3:]))
        self.assertEqual(body['files'], files)
        ast.parse(corpus.DRIVER)
        for name, source in files.items():
            if name.endswith('.py'):
                ast.parse(source)
        for change in (files | {'../escape': 'x'}, files | {'attacks.py': 'x'*4097}):
            with self.assertRaises(ValueError):
                corpus.payload(change, 'redteam-' + 'a'*16, '/run/synthetic-ci-canary')
        with self.assertRaises(ValueError):
            corpus.payload(files, '../outside', '/run/synthetic-ci-canary')

    def test_mac_harness_rejected_before_filesystem_native_calls_or_secret_creation(self):
        with (patch.object(corpus.sys, 'platform', 'darwin'),
              patch.object(corpus.Path, 'read_text') as read,
              patch.object(corpus.subprocess, 'check_output') as command,
              patch.object(corpus.tempfile, 'TemporaryDirectory') as temporary):
            with self.assertRaises(PermissionError):
                corpus.run(None, None, None, None, None, None, None)
            read.assert_not_called()
            command.assert_not_called()
            temporary.assert_not_called()

    def test_untrusted_corpus_observations_reject_duplicate_keys_and_nonfinite_values(self):
        for raw in ('{"case":"one","case":"two"}', '{"value":NaN}'):
            with self.assertRaises(ValueError):
                corpus.decode(raw)

    def test_worker_guard_refuses_mac_before_any_attack(self):
        spec = importlib.util.spec_from_file_location('redteam_attacks',
                                                     ROOT / 'tests/redteam/attacks.py')
        attacks = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(attacks)
        with (patch.object(attacks.sys, 'platform', 'darwin'),
              patch.object(attacks.Path, 'write_text') as write,
              patch.object(attacks.socket, 'socket') as channel):
            with self.assertRaises(PermissionError):
                attacks.exercise('repository-instructions')
            write.assert_not_called()
            channel.assert_not_called()
