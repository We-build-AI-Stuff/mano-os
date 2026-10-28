import base64
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from test_package_gdbm_decode import database
from test_staged_package_probe import probe as stage

from mano_runtime import package_man_regeneration as regen

SPEC = importlib.util.spec_from_file_location('man_regeneration_probe',
    Path(__file__).resolve().parents[1] / 'scripts/probe_package_man_regeneration.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def stream(raw):
    return dict(base64=base64.b64encode(raw).decode(), bytes=len(raw),
                sha256=hashlib.sha256(raw).hexdigest())


def worker():
    host = {key: key+':[1]' for key in ('mnt', 'pid', 'net', 'ipc', 'uts', 'cgroup')}
    state = dict(uid=[6]*3, gid=[12]*3, groups=[], nnp=1,
        caps=dict.fromkeys(('CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb'), 0),
        namespaces={key: key+':[2]' for key in host})
    row = dict(state=state, domain_drained=True, initial_cache_empty=True,
        config_sha256='a'*64, result=dict(returncode=0, capture_complete=True,
                                        stdout=stream(b''), stderr=stream(b'')))
    return host, row


def tree(raw):
    return dict(manifest_sha256='b'*64, entries={'index.db': dict(kind='file', uid=6, gid=12,
        mode=0o644, nlink=1, xattrs={}, hardlink_anchor='index.db', bytes=len(raw),
        sha256=hashlib.sha256(raw).hexdigest())})


class ManRegenerationTests(unittest.TestCase):
    def test_config_mapping_rejects_nested_duplicate_missing_or_ambiguous_root(self):
        raw = b'# baseline\nMANDB_MAP /usr/share/man /var/cache/man\n'
        self.assertEqual(probe.config_profile(raw), hashlib.sha256(raw).hexdigest())
        for bad in (b'', b'x\0', raw+raw, raw.replace(b'/var/cache/man', b'/tmp'),
                    raw+b'MANDB_MAP /usr/share/man/de /other\n', b'x'*65537,
                    b'MANDB_MAP /usr/share/man\n'):
            with self.subTest(raw=bad[:80]), self.assertRaises(ValueError):
                probe.config_profile(bad)

    def test_worker_source_compiles_without_executing_linux_operations(self):
        data = probe.program(stage.PROGRAM)
        compile(data, 'fixed-man-regeneration-fixture', 'exec')
        self.assertIn(b'verify_no_inherited_fds()', data)
        self.assertIn(b"['/usr/bin/mandb','--create','--quiet','/usr/share/man']", data)

    def test_sandbox_uses_immutable_tools_readonly_manuals_and_separate_output(self):
        args = probe.sandbox(Path('/private'), [], Path('/empty'), 'a'*64)
        binds = [(args[n], args[n+1], args[n+2]) for n in range(len(args)-2)
                 if args[n] in {'--bind', '--ro-bind'}]
        self.assertIn(('--ro-bind', '/private/baseline', '/'), binds)
        self.assertIn(('--ro-bind', '/private/candidate/usr/share/man', '/usr/share/man'), binds)
        self.assertEqual([row for row in binds if row[0] == '--bind'],
                         [('--bind', '/private/regenerated-man-cache', '/var/cache/man')])
        self.assertIn('--cap-drop', args)
        self.assertEqual(args[args.index('--cap-drop')+1], 'ALL')
        self.assertIn('--clear-groups', args)
        self.assertIn('--bounding-set=-all', args)
        self.assertIn('--inh-caps=-all', args)
        self.assertIn('--ambient-caps=-all', args)
        self.assertIn('--no-new-privs', args)
        with self.assertRaises(ValueError):
            probe.sandbox(Path('/private'), [], Path('/empty'), '../config')

    def test_loopback_setup_capability_never_reaches_the_man_process(self):
        unit = probe.unit_command()
        ceiling = next(arg.split('=', 2)[2].split() for arg in unit
                       if arg.startswith('--property=CapabilityBoundingSet='))
        self.assertEqual(set(ceiling), {'CAP_SYS_ADMIN', 'CAP_SYS_CHROOT', 'CAP_SETUID',
            'CAP_SETGID', 'CAP_SETPCAP', 'CAP_DAC_READ_SEARCH', 'CAP_NET_ADMIN'})
        args = probe.sandbox(Path('/private'), [], Path('/empty'), 'a'*64)
        added = [args[i+1] for i, arg in enumerate(args) if arg == '--cap-add']
        self.assertEqual(set(added), {'CAP_SETUID', 'CAP_SETGID', 'CAP_SETPCAP'})
        self.assertNotIn('CAP_NET_ADMIN', added)
        host, row = worker()
        row['state']['caps']['CapBnd'] = 1 << 12  # CAP_NET_ADMIN must be gone.
        with self.assertRaises(ValueError):
            probe.validate(row, host, 'a'*64)

    def test_launch_failure_retains_bounded_binary_diagnostics_without_success(self):
        raw = b'bwrap: loopback: Failed RTM_NEWADDR: No child processes\n'
        error = subprocess.CalledProcessError(1, ['fixed'], output=b'', stderr=raw)
        report = probe.launch_failure(error)
        self.assertEqual(base64.b64decode(report['streams']['stderr']['base64']), raw)
        self.assertTrue(report['launch_failed'])
        self.assertFalse(report['fresh_generation_observed'])
        self.assertFalse(report['publication_authorized'])
        error.stdout = b'x'*65537
        report = probe.launch_failure(error)
        self.assertFalse(report['streams']['stdout']['complete'])
        self.assertEqual(report['streams']['stdout']['bytes'], 65536)

    def test_worker_diagnostics_and_private_capability_free_identity(self):
        host, row = worker()
        probe.validate(row, host, 'a'*64)
        row['state']['groups'] = [12]
        probe.validate(row, host, 'a'*64)
        mutations = [lambda r: r['state']['caps'].update(CapBnd=1),
                     lambda r: r['state'].update(groups=[0]),
                     lambda r: r['state'].update(uid=[True]*3),
                     lambda r: r['state'].update(nnp=True),
                     lambda r: r['state']['namespaces'].update(mnt=host['mnt']),
                     lambda r: r.update(domain_drained=False),
                     lambda r: r.update(initial_cache_empty=False),
                     lambda r: r.update(config_sha256='b'*64),
                     lambda r: r['result'].update(returncode=True),
                     lambda r: r['result'].update(capture_complete=False),
                     lambda r: r['result']['stdout'].update(sha256='0'*64),
                     lambda r: r['result']['stderr'].update(bytes=True)]
        for change in mutations:
            bad = copy.deepcopy(row)
            change(bad)
            with self.subTest(change=change), self.assertRaises(ValueError):
                probe.validate(bad, host, 'a'*64)

    @unittest.skipIf(sys.platform == 'linux', 'Mac refusal is a non-Linux-only check')
    def test_no_controller_linux_operations_can_run_on_mac(self):
        with self.assertRaises(PermissionError):
            probe.regenerate(Path('/private'), '', {}, [], Path('/empty'), b'', None)

    def test_config_and_candidate_manual_subtree_bind_exact_bytes_and_metadata(self):
        config = b'MANDB_MAP /usr/share/man /var/cache/man\n'
        baseline = dict(manifest_sha256='a'*64, entries={'etc/manpath.config':
            dict(kind='file', uid=0, mode=0o644, bytes=len(config),
                 sha256=hashlib.sha256(config).hexdigest())})
        candidate = dict(manifest_sha256='b'*64, entries={
            'usr/share/man': dict(kind='directory'),
            'usr/share/man/man6/sl.6.gz': dict(kind='file', sha256='c'*64)})
        result = regen.inputs(baseline, candidate, config)
        self.assertEqual(result['candidate_manual_tree_entries'], 2)
        changed = copy.deepcopy(candidate)
        changed['entries']['usr/share/man/man6/sl.6.gz']['sha256'] = 'd'*64
        self.assertNotEqual(result['candidate_manual_tree_sha256'],
                            regen.inputs(baseline, changed, config)['candidate_manual_tree_sha256'])
        with self.assertRaises(ValueError):
            regen.inputs(baseline, candidate, config+b'# other')
        baseline['entries']['etc/manpath.config']['mode'] = 0o666
        with self.assertRaises(ValueError):
            regen.inputs(baseline, candidate, config)

    def test_raw_bundle_matches_observation_and_has_aggregate_bounds(self):
        raw = bytes(database())
        summary, bundle = regen.collect(tree(raw), lambda path, maximum: raw)
        self.assertEqual(summary['bytes'], len(raw))
        self.assertEqual(base64.b64decode(json.loads(bundle)['index.db']), raw)
        for field, value in (('uid', 0), ('nlink', 2), ('bytes', True), ('xattrs', {'x': 1}),
                             ('mode', 0o666), ('hardlink_anchor', 'alias')):
            altered = tree(raw)
            altered['entries']['index.db'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                regen.collect(altered, lambda path, maximum: raw)
        with self.assertRaises(ValueError):
            regen.collect(tree(raw), lambda path, maximum: b'changed')
        for limit in ('MAX_TOTAL_BYTES', 'MAX_DATABASES', 'MAX_SERIALIZED'):
            with patch.object(regen, limit, 0), self.assertRaises(ValueError):
                regen.collect(tree(raw), lambda path, maximum: raw)

    def test_logical_comparison_exposes_stale_records_without_authorizing_them(self):
        raw = bytes(database(((b'$version$\0', b'2.5.0\0'), (b'new\0', b'value\0'))))
        _, bundle = regen.collect(tree(raw), lambda path, maximum: raw)
        result = regen.compare(bundle, {'var/cache/man/index.db': raw})
        self.assertTrue(result['all_compared_indexes_equal'])
        for flag in ('all_database_bytes_validated', 'cache_sources_verified',
                     'generated_state_validated', 'changes_authorized', 'publication_authorized'):
            self.assertIs(result[flag], False)
        stale = bytes(database(((b'$version$\0', b'2.5.0\0'), (b'old\0', b'value\0'))))
        result = regen.compare(bundle, {'var/cache/man/index.db': stale,
                                       'var/cache/man/de/index.db': raw})
        self.assertFalse(result['all_compared_indexes_equal'])
        row = result['databases']['var/cache/man/index.db']
        self.assertEqual(row['candidate_only_keys'], [base64.b64encode(b'old\0').decode()])
        self.assertEqual(row['regenerated_only_keys'], [base64.b64encode(b'new\0').decode()])
        self.assertFalse(result['databases']['var/cache/man/de/index.db']['regenerated_index_present'])
        changed = bytes(database(((b'$version$\0', b'2.5.0\0'), (b'new\0', b'changed\0'))))
        row = regen.compare(bundle, {'var/cache/man/index.db': changed})['databases'][
            'var/cache/man/index.db']
        self.assertEqual(row['differing_value_keys'], [base64.b64encode(b'new\0').decode()])

    def test_comparison_rejects_paths_bad_base64_and_resource_substitutions(self):
        raw = bytes(database())
        _, bundle = regen.collect(tree(raw), lambda path, maximum: raw)
        for bad in (b'[]', b'{}', b'{"../index.db":"AA=="}', b'{"index.db":"???"}'):
            with self.subTest(raw=bad), self.assertRaises(ValueError):
                regen.compare(bad, {})
        with self.assertRaises(ValueError):
            regen.compare(bundle, {'/tmp/index.db': raw})
        for limit in ('MAX_TOTAL_BYTES', 'MAX_TOTAL_RECORDS', 'MAX_SERIALIZED'):
            with patch.object(regen, limit, 0), self.assertRaises(ValueError):
                regen.compare(bundle, {'var/cache/man/index.db': raw})
