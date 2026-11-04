import unittest
from unittest.mock import patch

import test_package_trigger_linkage as fixtures
from test_package_process_outcomes import call

from mano_runtime import package_trigger_arguments as arguments


class TriggerArgumentTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.TriggerLinkageTests()
        self.fixture.setUp()
        self.path = b'/var/lib/dpkg/info/existing.postinst'

    def inputs(self):
        with patch.object(fixtures.linkage, 'require_sources',
                          wraps=fixtures.linkage.require_sources) as observed:
            self.fixture.run_policy()
        return observed.call_args.args

    def run_policy(self, raw=None):
        if raw is None:
            raw = call(10, self.path, [b'triggered', b'ldconfig /usr/share/man'])
        return arguments.require_arguments(raw, *self.inputs())

    def test_actual_arguments_link_to_recomputed_named_and_file_sources(self):
        result = self.run_policy()
        row = result['callbacks'][0]
        self.assertEqual(row['package'], dict(name='existing', architecture='amd64', version='1'))
        self.assertEqual(row['triggers'], ['/usr/share/man', 'ldconfig'])
        self.assertEqual(row['pid'], 10)
        self.assertTrue(result['observed_callback_arguments_linked'])
        for key in ('caller_ancestry_verified', 'all_execs_observed',
                    'script_contents_at_exec_verified', 'trigger_authority_verified',
                    'maintainer_effects_verified', 'changes_authorized', 'publication_authorized'):
            self.assertIs(result[key], False)

    def test_trigger_name_order_is_not_authority_but_duplicates_and_unknowns_reject(self):
        self.run_policy(call(10, self.path, [b'triggered', b'/usr/share/man ldconfig']))
        for names in (b'ldconfig', b'ldconfig /usr/share/man unknown',
                      b'ldconfig ldconfig /usr/share/man', b' ldconfig /usr/share/man',
                      b'ldconfig  /usr/share/man', b'ldconfig\t/usr/share/man'):
            with self.subTest(names=names), self.assertRaises(ValueError):
                self.run_policy(call(10, self.path, [b'triggered', names]))

    def test_missing_duplicate_failed_or_unexpected_callback_rejected(self):
        valid = call(10, self.path, [b'triggered', b'ldconfig /usr/share/man'])
        for raw in (call(1, b'/usr/bin/true', []), valid + valid,
                    valid.replace(b'= 0', b'= -1 ENOENT (No such file or directory)'),
                    valid + call(11, b'/var/lib/dpkg/info/unknown.postinst', [b'configure']),
                    valid + call(11, b'/var/lib/dpkg/tmp.ci/preinst', [b'install'])):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.run_policy(raw)

    def test_wrong_mode_or_split_arguments_rejected(self):
        for argv in ([b'configure', b'ldconfig /usr/share/man'],
                     [b'triggered', b'ldconfig', b'/usr/share/man'], [b'triggered']):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                self.run_policy(call(10, self.path, argv))

    def test_changed_source_bytes_are_rejected_before_argument_matching(self):
        inputs = self.inputs()
        self.fixture.raw = b'interest invented\n'
        with self.assertRaises(ValueError):
            arguments.require_arguments(
                call(10, self.path, [b'triggered', b'ldconfig /usr/share/man']), *inputs)

    def test_multiarch_same_requires_qualified_script_path(self):
        self.fixture.before_status += b'Multi-Arch: same\n'
        # Keep the field inside the existing record rather than a new paragraph.
        self.fixture.before_status = self.fixture.before_status.replace(
            b'\n\nMulti-Arch: same\n', b'\nMulti-Arch: same\n\n')
        self.fixture.after_status = (self.fixture.before_status + fixtures.FIELDS
                                    + b'Status: install ok installed\n\n')
        self.fixture.path = 'var/lib/dpkg/info/existing:amd64.triggers'
        row = self.fixture.before.pop('var/lib/dpkg/info/existing.triggers')
        row['hardlink_anchor'] = self.fixture.path
        self.fixture.before[self.fixture.path] = row
        with self.assertRaises(ValueError):
            self.run_policy()
        self.path = b'/var/lib/dpkg/info/existing:amd64.postinst'
        self.run_policy()
