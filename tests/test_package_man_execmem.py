"""Synthetic witness validation only; no native memory or Linux execution."""
import copy
import json
import unittest

from mano_runtime.package_man_execmem import CONTEXT, MAPPINGS, POSITIVES, SYSCALLS, inspect


def fixture():
    return dict(profile='man-execmem-enforcement-v1', apparmor_context=CONTEXT,
        diagnostic_mapping_bytes_executed=False,
        before={name: dict(allowed=name not in {'temporary_exec', 'temporary_write_exec'},
                           errno=13 if name in {'temporary_exec', 'temporary_write_exec'} else 0)
                for name in MAPPINGS},
        after={name: dict(allowed=name in POSITIVES,
                          errno=0 if name in POSITIVES else 13 if name == 'temporary_exec' else 1)
               for name in MAPPINGS},
        syscalls={name: dict(allowed=False, errno=1) for name in SYSCALLS},
        child_exec_inheritance_verified=True, complete_runtime_closure_verified=False,
        publication_authorized=False)


class ExecmemWitnessTests(unittest.TestCase):
    def test_complete_witness_retains_results_without_authority_claim(self):
        value = fixture()
        self.assertEqual(inspect(json.dumps(value).encode()), value)
        self.assertFalse(value['complete_runtime_closure_verified'])
        self.assertFalse(value['publication_authorized'])

    def test_every_negative_requires_permission_denial_not_resource_or_kernel_error(self):
        for section in ('before', 'after', 'syscalls'):
            for name, result in fixture()[section].items():
                if result['allowed']:
                    continue
                for error in (0, 12, 22, 38, False, 1.0):
                    bad = fixture()
                    bad[section][name]['errno'] = error
                    with self.subTest(section=section, name=name, error=error):
                        with self.assertRaises(ValueError):
                            inspect(json.dumps(bad).encode())

    def test_each_positive_is_required_and_aliases_are_refused(self):
        for section in ('before', 'after'):
            for name, result in fixture()[section].items():
                if not result['allowed']:
                    continue
                for alteration in (dict(allowed=False, errno=13), dict(allowed=1, errno=0),
                                   dict(allowed=True, errno=False), dict(allowed=True, errno=1)):
                    bad = fixture()
                    bad[section][name] = alteration
                    with self.subTest(section=section, name=name, value=alteration):
                        with self.assertRaises(ValueError):
                            inspect(json.dumps(bad).encode())

    def test_no_control_or_section_can_be_omitted_or_added(self):
        original = fixture()
        for section in ('before', 'after', 'syscalls'):
            for key in original[section]:
                bad = copy.deepcopy(original)
                del bad[section][key]
                with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                    inspect(json.dumps(bad).encode())
            bad = copy.deepcopy(original)
            bad[section]['unknown'] = dict(allowed=False, errno=1)
            with self.assertRaises(ValueError):
                inspect(json.dumps(bad).encode())
        for key in original:
            bad = copy.deepcopy(original)
            del bad[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                inspect(json.dumps(bad).encode())

    def test_context_claim_inheritance_authority_and_duplicate_fields_refuse(self):
        for key, changed in (('apparmor_context', CONTEXT.replace('enforce', 'complain')),
                ('apparmor_context', 'unconfined'), ('child_exec_inheritance_verified', 1),
                ('publication_authorized', True), ('complete_runtime_closure_verified', True),
                ('diagnostic_mapping_bytes_executed', True), ('profile', 'other')):
            bad = fixture()
            bad[key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError):
                inspect(json.dumps(bad).encode())
        raw = json.dumps(fixture()).encode()
        for invalid in (b'', b' '*3073, raw.decode(), b'[]',
                        raw.replace(b'"before": {', b'"before": {}, "before": {', 1)):
            with self.assertRaises(ValueError):
                inspect(invalid)

    def test_file_profile_denial_does_not_substitute_for_syscall_filter(self):
        for section, name in [('after', 'temporary_write_exec'), ('after', 'anonymous_to_exec'),
                              *[('syscalls', name) for name in SYSCALLS]]:
            bad = fixture()
            bad[section][name]['errno'] = 13
            with self.subTest(section=section, name=name), self.assertRaises(ValueError):
                inspect(json.dumps(bad).encode())


class ExecmemControllerTests(unittest.TestCase):
    def setUp(self):
        import test_package_man_regeneration as regeneration
        self.probe = regeneration.probe
        self.stage = regeneration.stage

    def test_guard_version_requires_explicit_mode_and_complete_memory_witness(self):
        from test_package_man_regeneration import stream, worker
        controls = ('groups_empty nnp all_capability_sets_zero control_read_before_allowed '
            'control_write_before_allowed control_read_denied control_write_denied '
            'tmp_exec_before_allowed tmp_exec_denied cache_write_allowed namespace_change_denied '
            'identity_change_denied child_exec_inheritance_verified seccomp_enforced').split()
        guard = dict.fromkeys(controls, True)
        guard.update(profile='man-cache-landlock-seccomp-v4', role='mandb', landlock_abi=6,
                     uid=6, gid=12, execmem=fixture())
        _, row = worker()
        row.update(mode='restricted', input_guard=guard)
        row['result']['stdout'] = stream(json.dumps(guard).encode()+b'\n')
        self.assertLessEqual(len(json.dumps(guard).encode()), 4096)
        self.probe.require_guard(row, execmem=True)
        with self.assertRaises(ValueError):
            self.probe.require_guard(row)
        for role in ('source-bytes', 'source-content'):
            with self.assertRaises(ValueError):
                self.probe.validate_native_guard(guard, role=role, execmem=True)
        for mode in (1, None, 'true'):
            with self.assertRaises(ValueError):
                self.probe.validate_native_guard(guard, role='mandb', execmem=mode)
        for key in controls:
            bad = copy.deepcopy(guard)
            bad[key] = False
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.probe.validate_native_guard(bad, role='mandb', execmem=True)
        bad = copy.deepcopy(row)
        bad['result']['stdout'] = stream(b'{}\n')
        with self.assertRaises(ValueError):
            self.probe.require_guard(bad, execmem=True)
        bad = copy.deepcopy(guard)
        bad['execmem']['syscalls']['personality']['errno'] = 22
        with self.assertRaises(ValueError):
            self.probe.validate_native_guard(bad, role='mandb', execmem=True)

    def test_profile_exec_boundary_follows_complete_drop_and_control_remains_baseline(self):
        from pathlib import Path
        args = self.probe.sandbox(Path('/private'), [], Path('/empty'), 'a'*64, execmem=True)
        boundary = args.index('/usr/bin/aa-exec')
        self.assertEqual(args[boundary:boundary+4],
                         ['/usr/bin/aa-exec', '-p', 'mano-man-cache-execmem', '--'])
        self.assertGreater(boundary, args.index('--ambient-caps=-all'))
        self.assertGreater(boundary, args.index('--no-new-privs'))
        self.assertEqual(args[boundary+4:boundary+8],
                         ['/usr/bin/python3', '-I', '-B', '/run/man-regeneration.py'])
        control = self.probe.sandbox(Path('/private'), [], Path('/empty'), 'a'*64,
                                     mode='control', execmem=True)
        self.assertNotIn('/usr/bin/aa-exec', control)
        for value in (1, None, 'true'):
            with self.assertRaises(ValueError):
                self.probe.sandbox(Path('/private'), [], Path('/empty'), 'a'*64, execmem=value)

    def test_profile_binding_precedes_manual_inputs_and_changes_actual_generation(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        profile = (root/'packaging/apparmor/mano-man-cache-execmem').read_bytes()
        options = dict(runtime_view_source=(root/'src/mano_runtime/package_man_runtime_view.py')
                        .read_text(), runtime_origin_source=(root/'src/mano_runtime/'
                        'package_man_runtime_origin.py').read_text(), mapping_controls=True)
        data = self.probe.program(self.stage.PROGRAM, **options, execmem_profile_source=profile)
        compile(data, 'synthetic-enforced-worker', 'exec')
        self.assertLess(data.index(b'Exact enforcing manual-memory profile required'),
                        data.index(b"config=Path('/etc/manpath.config')"))
        self.assertIn(b"['/run/man-cache-guard','--mandb-enforced']", data)
        self.assertIn(b"['/run/man-cache-guard','--mapping-controls']", data)
        legacy = self.probe.program(self.stage.PROGRAM, **options)
        self.assertNotIn(b'--mandb-enforced', legacy)
        self.assertNotIn(b'execmem_context=', legacy)
        for value in (b'', b'x'*16385, profile.decode(), True):
            with self.assertRaises(ValueError):
                self.probe.program(self.stage.PROGRAM, **options, execmem_profile_source=value)
        with self.assertRaises(ValueError):
            self.probe.program(self.stage.PROGRAM, execmem_profile_source=profile)

    def test_worker_profile_preflight_runs_before_mode_assignment_and_refuses_bad_labels(self):
        import ast
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import Mock
        root = Path(__file__).resolve().parents[1]
        profile = (root/'packaging/apparmor/mano-man-cache-execmem').read_bytes()
        options = dict(runtime_view_source=(root/'src/mano_runtime/package_man_runtime_view.py')
                        .read_text(), runtime_origin_source=(root/'src/mano_runtime/'
                        'package_man_runtime_origin.py').read_text(), mapping_controls=True,
                        execmem_profile_source=profile)
        program = self.probe.program(self.stage.PROGRAM, **options)
        nodes = ast.parse(program).body
        start = next(i for i, node in enumerate(nodes) if isinstance(node, ast.Assign)
                     and isinstance(node.targets[0], ast.Name)
                     and node.targets[0].id == 'execmem_context')
        end = next(i for i, node in enumerate(nodes) if isinstance(node, ast.Assign)
                   and isinstance(node.targets[0], ast.Name)
                   and node.targets[0].id == 'execmem_profile_sha256')
        preflight = compile(ast.Module(body=nodes[start:end+1], type_ignores=[]),
                            'isolated-synthetic-profile-preflight', 'exec')
        for label in (b'unconfined\n', b'mano-man-cache-execmem (complain)\n',
                      b'mano-man-cache-execmem (enforce)', b'',
                      b'mano-man-cache-execmem (enforce)\nextra'):
            path = Mock()
            path.return_value.read_bytes.return_value = label
            env = dict(sys=SimpleNamespace(argv=['worker', 'a'*64, 'restricted']), Path=path)
            with self.subTest(label=label), self.assertRaises(ValueError):
                exec(preflight, env)
        path = Mock()
        path.return_value.read_bytes.return_value = (CONTEXT+'\n').encode()
        env = dict(sys=SimpleNamespace(argv=['worker', 'a'*64, 'restricted']), Path=path)
        exec(preflight, env)
        self.assertEqual(env['execmem_context'], (CONTEXT+'\n').encode())
        import hashlib
        self.assertEqual(env['execmem_profile_sha256'], hashlib.sha256(profile).hexdigest())
        path.reset_mock()
        env = dict(sys=SimpleNamespace(argv=['worker', 'a'*64, 'control']), Path=path)
        exec(preflight, env)
        path.assert_not_called()
        self.assertIsNone(env['execmem_context'])

    def test_retained_native44_failure_refuses_despite_enforcing_label_and_clean_identity(self):
        import hashlib
        from pathlib import Path
        raw = (Path(__file__).parent/'fixtures/'
               'man-execmem-d35b5d1-prefilter-failure.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         'c1a0dff57b64fd392673b9735cbea7ab5fbafc8e4b5f020e78ba848f2b4f3943')
        row = json.loads(raw)
        self.assertEqual(row['execmem_context'], 'mano-man-cache-execmem (enforce)')
        self.assertEqual(row['result']['returncode'], 125)
        self.assertIs(row['result']['capture_complete'], True)
        self.assertIsNone(row['input_guard'])
        proof = self.probe.inspect_mapping_result(row['mapping_controls_result'])
        for key in ('temporary_launch_denied_but_rx_mapping_allowed',
                    'temporary_private_write_exec_mapping_allowed',
                    'anonymous_write_exec_mapping_allowed', 'anonymous_rw_to_rx_allowed'):
            self.assertIs(proof[key], True)
        row['domain_drained'] = True
        host = {key: key+':[0]' for key in row['state']['namespaces']}
        with self.assertRaisesRegex(ValueError, 'Fresh mandb must finish'):
            self.probe.validate(row, host, row['config_sha256'],
                                require_input_guard=True, require_execmem=True)
        self.assertEqual(row['result']['stdout']['bytes'], 0)
        import base64
        expected = b'manual memory pre-filter positive/profile controls: Operation not permitted\n'
        self.assertEqual(row['result']['stderr']['bytes'], len(expected))
        self.assertEqual(base64.b64decode(row['result']['stderr']['base64'], validate=True),
                         expected)
