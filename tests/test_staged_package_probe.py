import contextlib
import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from test_package_container import ar

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location('staged_package_probe',
                                             SCRIPTS / 'probe_staged_package.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class StagedProbeSafetyTests(unittest.TestCase):
    def test_tree_adapter_requires_fixed_role_privileges_and_kernel_limits(self):
        import json

        caps = dict(CapEff=probe.TREE_CAPS, CapPrm=probe.TREE_CAPS,
                    CapBnd=probe.TREE_CAPS, CapInh=0, CapAmb=0)
        valid = dict(uid=0, observed_role='baseline', no_new_privileges=True,
                     trusted_controller_collector=True, address_space_limit_bytes=384 * 1024**2,
                     cpu_limit_seconds=60, capabilities=caps, memory_max_bytes=512 * 1024**2,
                     pids_max=8, cgroup_path='/mano.slice/mano-package.slice/'
                     'mano-tree-baseline-ci.service', full_root_verified=False,
                     immutable_root_verified=False, production_guard_used=False,
                     adversarial_confinement_verified=False, candidate_filesystem_verified=False,
                     publication_authorized=False)
        for changes in ({}, {'uid': 1000}, {'observed_role': 'candidate'}, {'memory_max_bytes': 0},
                        {'pids_max': 0}, {'publication_authorized': True},
                        {'capabilities': caps | {'CapInh': False}}):
            with self.subTest(changes=changes), patch.object(probe, 'run',
                    return_value=json.dumps(valid | changes)) as run:
                if changes:
                    with self.assertRaises(ValueError):
                        probe.tree_observation('baseline')
                else:
                    self.assertEqual(probe.tree_observation('baseline'), valid)
                    command = run.call_args.args[0]
                    self.assertIn('--property=MemoryMax=536870912', command)
                    self.assertIn('--property=RuntimeMaxSec=90', command)
        with patch.object(probe, 'run') as run:
            with self.assertRaises(ValueError):
                probe.tree_observation('../outside')
            run.assert_not_called()

    def clone_metadata(self):
        return [dict(uuid='live', parent_uuid='-', subvolume_id=1),
                dict(uuid='baseline', parent_uuid='live', subvolume_id=2),
                dict(uuid='candidate', parent_uuid='baseline', subvolume_id=3)]

    def test_clone_pair_checks_ancestry_and_kernel_readonly_properties(self):
        metadata = self.clone_metadata()
        outputs = [b'', b'ro=true\n', b'', b'ro=false\n']
        with patch.object(probe.recovery, 'subvolume', side_effect=metadata), \
                patch.object(probe, 'run', side_effect=outputs) as run:
            self.assertEqual(probe.clone_pair(), (*metadata, b'ro=true\n'))
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(commands[0], ['/usr/bin/btrfs', 'subvolume', 'snapshot', '-r', '/',
                                           str(probe.BASE / 'baseline')])
            self.assertEqual(commands[2], ['/usr/bin/btrfs', 'subvolume', 'snapshot',
                                           str(probe.BASE / 'baseline'),
                                           str(probe.BASE / 'candidate')])

    def test_clone_pair_rejects_wrong_ancestry_reused_ids_or_wrong_properties(self):
        for phase, field, value in ((1, 'parent_uuid', 'wrong'), (1, 'uuid', 'live'),
                                    (1, 'subvolume_id', 1), (2, 'parent_uuid', 'live'),
                                    (2, 'uuid', 'baseline'), (2, 'subvolume_id', 1),
                                    (1, 'property', b'ro=false\n'),
                                    (2, 'property', b'ro=true\n')):
            metadata = self.clone_metadata()
            outputs = [b'', b'ro=true\n', b'', b'ro=false\n']
            if field == 'property':
                outputs[1 if phase == 1 else 3] = value
            else:
                metadata[phase][field] = value
            with self.subTest(phase=phase, field=field, value=value), \
                    patch.object(probe.recovery, 'subvolume', side_effect=metadata), \
                    patch.object(probe, 'run', side_effect=outputs):
                with self.assertRaises(ValueError):
                    probe.clone_pair()

    def test_private_credential_mask_is_empty_readonly_and_refuses_reuse(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(probe, 'BASE', Path(temporary)):
            path = probe.credential_mask()
            self.assertEqual(path, Path(temporary) / 'empty-credential')
            self.assertEqual(path.read_bytes(), b'')
            self.assertEqual(path.stat().st_mode & 0o777, 0o400)
            with self.assertRaises(FileExistsError):
                probe.credential_mask()

    def test_credential_mask_refuses_an_existing_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(probe, 'BASE', Path(temporary)):
            target = Path(temporary) / 'preserved'
            target.write_bytes(b'preserved')
            (Path(temporary) / 'empty-credential').symlink_to(target)
            with self.assertRaises(FileExistsError):
                probe.credential_mask()
            self.assertEqual(target.read_bytes(), b'preserved')

    def test_payload_adapter_requires_complete_unprivileged_worker_evidence(self):
        import json

        record = dict(filename='sl.deb', sha256='a' * 64, bytes=3,
                      container={'archive_sha256': 'a' * 64})
        valid = dict(uid=65534, capabilities={key: 0 for key in
                     ('CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb')},
                     no_new_privileges=True, sealed_archive_observed=True,
                     container=record['container'], address_space_limit_bytes=384 * 1024**2,
                     cpu_limit_seconds=12, production_guard_used=False,
                     production_pam_used=False, archive_signature_verified=False,
                     publication_authorized=False)
        cases = [{}, {'uid': 0}, {'uid': True}, {'capabilities': {}},
                 {'no_new_privileges': False}, {'sealed_archive_observed': False},
                 {'container': {}}, {'cpu_limit_seconds': 0}, {'publication_authorized': True}]
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / 'archives').mkdir()
            (base / 'archives/sl.deb').write_bytes(b'raw')
            for changes in cases:
                with self.subTest(changes=changes), patch.object(probe, 'BASE', base), \
                        patch.object(probe, 'run', return_value=json.dumps(valid | changes)) as run:
                    if changes:
                        with self.assertRaises(ValueError):
                            probe.payload_observation(record)
                    else:
                        self.assertEqual(probe.payload_observation(record), valid)
                        command = run.call_args.args[0]
                        for option in ('--property=User=nobody',
                                       '--property=CapabilityBoundingSet=',
                                       '--property=NoNewPrivileges=yes',
                                       '--property=MemoryMax=536870912',
                                       '--property=RuntimeMaxSec=25'):
                            self.assertIn(option, command)
                        self.assertEqual(run.call_args.kwargs['input'], b'raw')

    def test_acquisition_binds_container_before_archive_is_written(self):
        raw = ar([('debian-binary', b'2.0\n'), ('control.tar', b'x'), ('data.tar', b'y')])
        for data in (raw, b'not a Debian package'):
            with self.subTest(valid=data == raw), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                (base / 'archives').mkdir()
                item = self.apt_item()
                item.is_installed, item.marked_delete = False, False
                item.mark_install = MagicMock()
                item.candidate.size = len(data)
                item.candidate.uri = 'https://deb.debian.org/debian/pool/s/sl/sl.deb'
                item.candidate.record['SHA256'] = hashlib.sha256(data).hexdigest()
                cache = MagicMock()
                cache.__getitem__.return_value = item
                cache.get_changes.return_value = [item]
                opener = MagicMock()
                opener.open.return_value.__enter__.return_value.read.return_value = data
                with patch.object(probe, 'BASE', base), \
                        patch.object(probe.urllib.request, 'build_opener', return_value=opener):
                    if data == raw:
                        records = probe.acquire_from(cache)
                        self.assertTrue(records[0]['container']['expected_identity_matched'])
                        self.assertEqual((base / 'archives/sl.deb').read_bytes(), raw)
                    else:
                        with self.assertRaisesRegex(ValueError, 'ar container'):
                            probe.acquire_from(cache)
                        self.assertFalse((base / 'archives/sl.deb').exists())

    @contextlib.contextmanager
    def private_cache(self):
        cache = MagicMock(broken_count=0, dpkg_journal_dirty=False)
        apt = MagicMock()
        apt.Cache.return_value = cache
        apt_pkg = MagicMock()
        modules = {'apt': apt, 'apt.progress': apt.progress,
                   'apt.progress.base': apt.progress.base, 'apt_pkg': apt_pkg}
        manifest = {'catalog_id': 'a' * 64}
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(probe, 'BASE', Path(temporary)), \
                patch.object(probe, 'load', return_value=(Path('/verified'), manifest)) as load, \
                patch.object(probe, 'fingerprint') as fingerprint, \
                patch.object(probe, 'prepare_apt_root') as prepare, \
                patch.dict(sys.modules, modules):
            yield cache, apt, apt_pkg, load, fingerprint, prepare

    def test_private_cache_uses_verified_sources_and_rechecks_custody(self):
        with self.private_cache() as (cache, apt, apt_pkg, load, fingerprint, prepare):
            with probe.candidate_cache() as selected:
                self.assertIs(selected, cache)
                root = prepare.call_args.args[0]
                self.assertTrue(root.is_dir())
                self.assertEqual(prepare.call_args.kwargs, {'catalog': Path('/verified')})
                self.assertEqual(apt.Cache.call_args.kwargs['rootdir'], str(root))
                self.assertTrue(apt.Cache.call_args.kwargs['memonly'])
            self.assertFalse(root.exists())
            self.assertEqual(fingerprint.call_count, 2)
            self.assertEqual(load.call_args.args, ('a' * 64,))
            cache.close.assert_called_once()
            apt_pkg.config.set.assert_any_call('Dir::Etc', str(root / 'etc/apt'))

    def test_private_cache_rejects_unsettled_state_and_closes(self):
        with self.private_cache() as (cache, _apt, _apt_pkg, _load, _fingerprint, _prepare):
            cache.broken_count = 1
            with self.assertRaisesRegex(ValueError, 'Settled'), probe.candidate_cache():
                self.fail('Unsettled cache yielded')
            cache.close.assert_called_once()

    def test_changed_catalog_custody_is_rejected_after_work(self):
        with self.private_cache() as (cache, _apt, _apt_pkg, _load, fingerprint, _prepare):
            fingerprint.side_effect = [None, ValueError('changed signed input')]
            with self.assertRaisesRegex(ValueError, 'changed signed input'):
                with probe.candidate_cache():
                    pass
            cache.close.assert_called_once()

    def test_invalid_catalog_stops_before_apt_initialization(self):
        with patch.object(probe, 'load', side_effect=ValueError('invalid catalog')), \
                patch.object(probe, 'prepare_apt_root') as prepare:
            with self.assertRaisesRegex(ValueError, 'invalid catalog'), probe.candidate_cache():
                self.fail('Invalid catalog yielded')
            prepare.assert_not_called()

    def apt_item(self):
        version = SimpleNamespace(architecture='amd64', version='5.02-1+b1', size=13000,
            record={'Package':'sl','Version':'5.02-1+b1','Architecture':'amd64','SHA256':'a'*64},
            origins=[SimpleNamespace(site='deb.debian.org',trusted=True)])
        return SimpleNamespace(name='sl:amd64',shortname='sl',candidate=version)

    def test_apt_display_architecture_does_not_become_archive_filename(self):
        name, _version, _digest, _origins, checks = probe.candidate_admission(self.apt_item())
        self.assertEqual(name, 'sl')
        self.assertTrue(all(checks.values()))

    def test_canonical_name_does_not_allow_mismatched_archive_record(self):
        item = self.apt_item()
        item.candidate.record['Architecture'] = 'arm64'
        self.assertFalse(probe.candidate_admission(item)[-1]['record_identity'])

    def candidate(self, **changes):
        values = dict(name='sl', architecture='amd64', version='5.02-1+b1',
                      digest='a' * 64, size=13000,
                      origins=[dict(site='deb.debian.org', trusted=True)])
        return probe.candidate_checks(**(values | changes))

    def test_expected_authenticated_debian_candidate_passes_all_fields(self):
        self.assertTrue(all(self.candidate().values()))

    def test_untrusted_official_site_is_not_enough(self):
        self.assertFalse(self.candidate(origins=[dict(site='deb.debian.org',
                                                   trusted=False)])['trusted_origin'])

    def test_trusted_third_party_site_is_not_enough(self):
        self.assertFalse(self.candidate(origins=[dict(site='other.example',
                                                   trusted=True)])['trusted_origin'])

    def test_malformed_name_missing_digest_and_wrong_arch_have_separate_failures(self):
        checks = self.candidate(name='sl:amd64', architecture='arm64', digest=None)
        self.assertEqual({key for key, ok in checks.items() if not ok},
                         {'name', 'architecture', 'sha256'})

    def test_invalid_size_types_and_values_remain_rejected(self):
        for size in (True, 1.5, 0, -1, 10 * 1024**2 + 1):
            with self.subTest(size=size):
                self.assertFalse(self.candidate(size=size)['size'])

    def test_mac_refuses_before_guest_commands_or_filesystem_setup(self):
        with patch.object(probe.sys, 'platform', 'darwin'), \
                patch.object(probe, 'guard') as guard, \
                patch.object(probe.recovery, 'layout') as layout:
            with self.assertRaises(PermissionError):
                probe.main()
        guard.assert_not_called()
        layout.assert_not_called()

    def test_candidate_symlink_cannot_redirect_observation_outside_clone(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            candidate = root / 'candidate'
            candidate.mkdir()
            outside = root / 'outside'
            outside.write_text('outside fixture')
            (candidate / 'payload').symlink_to(outside)
            with patch.object(probe.recovery, 'read') as read:
                with self.assertRaisesRegex(ValueError, 'alias'):
                    probe.candidate_read(candidate, 'payload', 1024)
                read.assert_not_called()

    def test_absolute_and_parent_paths_cannot_bypass_clone_observation_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            candidate = root / 'candidate'
            candidate.mkdir()
            for name in (str(root / 'outside'), '../outside'):
                with self.subTest(name=name), patch.object(probe.recovery, 'read') as read:
                    with self.assertRaisesRegex(ValueError, 'relative'):
                        probe.candidate_read(candidate, name, 1024)
                    read.assert_not_called()
