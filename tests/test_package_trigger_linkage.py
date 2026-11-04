import copy
import hashlib
import unittest
from unittest.mock import Mock, patch

from test_package_candidate_policy import seal
from test_package_control import FIELDS, archive

from mano_runtime import package_trigger_linkage as linkage
from mano_runtime.package_control import observe
from mano_runtime.package_payload import inventory


class TriggerLinkageTests(unittest.TestCase):
    def setUp(self):
        import io
        self.raw = b'interest-noawait /usr/share/man\ninterest-noawait ldconfig\n'
        self.path = 'var/lib/dpkg/info/existing.triggers'
        self.control = observe(archive({'control': FIELDS,
                                       'triggers': b'activate-noawait ldconfig\n'}))
        self.payload = inventory(io.BytesIO(archive({'usr/share/man/man1/fixture.1': b'x'})))
        self.before_status = (b'Package: existing\nArchitecture: amd64\nVersion: 1\n'
                              b'Status: install ok installed\n\n')
        self.after_status = self.before_status+FIELDS+b'Status: install ok installed\n\n'
        self.records = [dict(name='fixture', architecture='amd64', version='1')]
        self.before = {'.': dict(kind='directory', uid=0, gid=0, mode=0o755,
            nlink=2, xattrs={}, mtime_ns=0, ctime_ns=0),
            self.path: dict(kind='file', uid=0, gid=0, mode=0o644,
            nlink=1, xattrs={}, hardlink_anchor=self.path, bytes=len(self.raw),
            sha256=hashlib.sha256(self.raw).hexdigest(), mtime_ns=0, ctime_ns=0)}
        self.observations = {'fixture': dict(control=self.control, payload=self.payload)}
        self.log = (b'2026-10-26 04:23:40 trigproc existing:amd64 1 <none>\n')
        self.read = Mock(side_effect=lambda path, maximum: self.raw)

    def run_policy(self):
        candidate = copy.deepcopy(self.before)
        for path, row in self.payload['entries'].items():
            candidate[path] = row | dict(nlink=1, xattrs={}, hardlink_anchor=path,
                                        mtime_ns=int(row['mtime']*10**9), ctime_ns=0)
            del candidate[path]['mtime']
        for name, row in self.control['inventory']['entries'].items():
            if name == 'control':
                continue
            path = 'var/lib/dpkg/info/fixture.'+name
            candidate[path] = row | dict(nlink=1, xattrs={}, hardlink_anchor=path,
                                        mtime_ns=int(row['mtime']*10**9), ctime_ns=0)
            del candidate[path]['mtime']
        return linkage.require_sources(b'', self.log, self.before_status, self.after_status,
            seal(self.before), seal(candidate), self.records, self.observations, self.read)

    def test_named_and_lexical_file_sources_match_without_execution_authority(self):
        result = self.run_policy()
        self.assertEqual(result['referenced_packages'], 1)
        self.assertEqual(len(result['declaration_activation_links']), 2)
        self.assertEqual({r['activation']['kind'] for r in result['declaration_activation_links']},
                         {'declared-activation', 'lexical-payload-path'})
        for key in ('actual_trigger_arguments_verified', 'trigger_authority_verified',
                    'sequence_policy_verified', 'maintainer_effects_verified',
                    'changes_authorized', 'publication_authorized'):
            self.assertIs(result[key], False)

    def test_interest_alone_or_activation_without_matching_interest_is_rejected(self):
        for raw in (b'interest unknown\n', b'activate ldconfig\n',
                    b'interest /usr/share/man-other\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.raw = raw
                self.before[self.path].update(bytes=len(raw),
                                             sha256=hashlib.sha256(raw).hexdigest())
                self.run_policy()

    def test_declarations_recomputed_from_bytes_not_supplied_decoded_observation(self):
        self.control['trigger_declarations']['declarations'] = [
            dict(directive='activate', trigger='invented', kind='named')]
        self.raw = b'interest invented\n'
        self.before[self.path].update(bytes=len(self.raw),
                                     sha256=hashlib.sha256(self.raw).hexdigest())
        with self.assertRaisesRegex(ValueError, 'activation source'):
            self.run_policy()

    def test_baseline_hash_and_archive_hash_tampering_rejected(self):
        self.before[self.path]['sha256'] = '0'*64
        with self.assertRaises(ValueError):
            self.run_policy()
        self.before[self.path]['sha256'] = hashlib.sha256(self.raw).hexdigest()
        self.control['inventory']['entries']['triggers']['sha256'] = '0'*64
        with self.assertRaises(ValueError):
            self.run_policy()

    def test_missing_baseline_is_not_inferred_from_log_reference(self):
        del self.before[self.path]
        with self.assertRaisesRegex(ValueError, 'no available declaration'):
            self.run_policy()
        self.read.assert_not_called()

    def test_new_package_self_trigger_uses_its_authenticated_control(self):
        self.control = observe(archive({'control': FIELDS,
            'triggers': b'interest ldconfig\nactivate-noawait ldconfig\n'}))
        self.observations['fixture']['control'] = self.control
        self.log = b'2026-10-26 04:23:40 trigproc fixture:amd64 1 <none>\n'
        result = self.run_policy()
        self.assertEqual(result['declaration_activation_links'][0]['declaration_origin'],
                         'authenticated-new-control')
        self.read.assert_not_called()

    def test_lexical_boundary_root_and_symlink_names_never_resolve(self):
        names = ['/elsewhere/man', '/usr/share/man-other', '/usr/share/man/man1/x']
        self.assertEqual(linkage.file_witness('/usr/share/man', names),
                         '/usr/share/man/man1/x')
        self.assertIsNone(linkage.file_witness('/elsewhere/real-target', names))
        self.assertIsNotNone(linkage.file_witness('/', names))
        self.assertEqual(linkage.file_witness('/elsewhere/man', names), '/elsewhere/man')

    def test_bounded_links_and_exact_observation_set(self):
        with patch.object(linkage, 'MAX_LINKS', 1), self.assertRaisesRegex(ValueError, 'budget'):
            self.run_policy()
        self.observations['extra'] = self.observations['fixture']
        with self.assertRaisesRegex(ValueError, 'Exact authenticated'):
            self.run_policy()
