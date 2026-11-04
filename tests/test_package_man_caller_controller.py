"""Pure command/report fixtures; never create Root paths or execute mandb."""
import base64
import copy
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from test_staged_package_probe import SCRIPTS

SPEC = importlib.util.spec_from_file_location('native_caller_probe',
    SCRIPTS/'probe_package_man_native_caller.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def stream(raw):
    return dict(base64=base64.b64encode(raw).decode(), bytes=len(raw),
                sha256=hashlib.sha256(raw).hexdigest())


class NativeCallerControllerTests(unittest.TestCase):
    def corpus(self):
        data = (Path(__file__).parent/'fixtures/man-native-reference-corpus-v1.json').read_bytes()
        return data, probe.corpus(data)

    def fixture(self):
        _, spec = self.corpus()
        guard = dict.fromkeys(('groups_empty', 'nnp', 'all_capability_sets_zero',
            'control_read_before_allowed', 'control_write_before_allowed',
            'control_read_denied', 'control_write_denied', 'tmp_exec_before_allowed',
            'tmp_exec_denied', 'cache_write_allowed', 'namespace_change_denied',
            'identity_change_denied', 'child_exec_inheritance_verified', 'seccomp_enforced'), True)
        guard.update(profile='man-cache-landlock-seccomp-v3', role='source-content',
                     landlock_abi=5, uid=6, gid=12)
        diagnostics = b''.join(b'test_manfile: considering /usr/share/man/'+name.encode()+b'\n'
                               for name in spec['cases'].values())
        value = dict(profile='man-native-reference-caller-capture-v1', uid=6, gid=12, groups=[],
            command=list(probe.worker.CALLER_COMMAND),
            environment=dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C',
                             TZ='UTC0', HOME='/nonexistent'),
            mandb_executable_sha256='a'*64, manpath_configuration_sha256='b'*64,
            fixed_command_and_configuration_unchanged=True, returncode=0,
            capture_complete=True, capture_failure=None, stdout=stream(b''),
            stderr=stream(diagnostics), native_man_db_caller_semantics_verified=False,
            full_source_semantics_verified=False, generated_state_validated=False,
            changes_authorized=False, publication_authorized=False)
        baseline = dict(entries={'usr/bin/mandb': dict(kind='file', uid=0, gid=0, mode=0o755,
                                                      nlink=1, sha256='a'*64)})
        return spec, guard, value, baseline

    def test_literal_corpus_is_bounded_and_cannot_be_replaced(self):
        data, spec = self.corpus()
        self.assertEqual(len(spec['files']), 37)
        self.assertEqual(len(spec['cases']), 13)
        self.assertEqual(spec['hardlinks'], {'man1/b-hard.1': 'man1/a-hard.1'})
        for altered in (data+b' ', b'{}', b'x'*32769):
            with self.assertRaises(ValueError):
                probe.corpus(altered)

    def test_command_changes_only_three_existing_mount_sources_and_shorter_deadline(self):
        config = 'b'*64
        expected = probe.content_unit()+probe.content_sandbox(probe.BASE, (), Path('/empty'),
                                                             config)
        for old, new in ((probe.BASE/'candidate/usr/share/man', probe.ROOT),
                         (probe.BASE/'man-content-cache', probe.CACHE),
                         (probe.BASE/'man-source-paths.json',
                          probe.BASE/'man-native-caller-request.json')):
            expected[expected.index(str(old))] = str(new)
        expected[expected.index('--property=RuntimeMaxSec=190')] = '--property=RuntimeMaxSec=30'
        self.assertEqual(probe.caller_command(probe.BASE, (), Path('/empty'), config), expected)
        self.assertIn('--property=MemoryMax=268435456', expected)
        self.assertIn('--property=TasksMax=32', expected)
        with self.assertRaises(ValueError):
            probe.caller_command(Path('/tmp/other'), (), Path('/empty'), config)

    def test_fabricated_raw_caller_observation_does_not_prove_source_semantics(self):
        spec, guard, value, baseline = self.fixture()
        raw = json.dumps(guard).encode()+b'\n'+json.dumps(value).encode()
        actual_guard, actual = probe.validate_capture(raw, spec, baseline, 'b'*64)
        self.assertEqual(actual_guard, guard)
        self.assertEqual(actual, value)
        self.assertFalse(actual['native_man_db_caller_semantics_verified'])
        self.assertFalse(actual['publication_authorized'])

    def test_wrong_identity_command_capture_hash_or_missing_case_is_rejected(self):
        spec, guard, value, baseline = self.fixture()
        for key, wrong in (('uid', 6.0), ('returncode', 1), ('capture_complete', False),
                           ('publication_authorized', True),
                           ('command', ['/bin/sh']), ('manpath_configuration_sha256', 'c'*64)):
            altered = copy.deepcopy(value)
            altered[key] = wrong
            raw = json.dumps(guard).encode()+b'\n'+json.dumps(altered).encode()
            with self.subTest(field=key), self.assertRaises(ValueError):
                probe.validate_capture(raw, spec, baseline, 'b'*64)
        for altered_stream in (stream(b'no primary cases\n'),
                               value['stderr'] | dict(sha256='0'*64)):
            altered = value | dict(stderr=altered_stream)
            raw = json.dumps(guard).encode()+b'\n'+json.dumps(altered).encode()
            with self.assertRaises(ValueError):
                probe.validate_capture(raw, spec, baseline, 'b'*64)

    def test_mac_or_wrong_controller_base_refuses_before_any_corpus_or_process(self):
        with patch.object(probe.sys, 'platform', 'darwin'), \
                patch.object(probe, 'corpus') as decode, \
                patch.object(probe, 'bounded_capture') as spawn:
            with self.assertRaises(PermissionError):
                probe.capture_reference_caller(probe.BASE, {}, (), Path('/empty'), 'b'*64, None)
            decode.assert_not_called()
            spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main()
