import unittest
from pathlib import Path

from test_package_log_scope import status

from mano_runtime.package_log_sequence import require_sequence

STAMP = b'2026-10-26 04:23:40 '


class PackageLogSequenceTests(unittest.TestCase):
    def setUp(self):
        self.before = status('existing', '1')
        self.after = self.before+status('newpkg', '2')
        self.records = [dict(name='newpkg', architecture='amd64', version='2')]
        self.bodies = [b'startup archives install', b'install newpkg:amd64 <none> 2',
            b'status half-installed newpkg:amd64 2', b'status unpacked newpkg:amd64 2',
            b'configure newpkg:amd64 2 2', b'status half-configured newpkg:amd64 2',
            b'status installed newpkg:amd64 2']

    def inspect(self, bodies=None):
        raw = b''.join(STAMP+b+b'\n' for b in (self.bodies if bodies is None else bodies))
        return require_sequence(b'', raw, self.before, self.after, self.records)

    def test_complete_install_and_trigger_cycles_do_not_grant_authority(self):
        self.bodies.insert(2, b'status triggers-pending existing:amd64 1')
        self.bodies.extend([b'trigproc existing:amd64 1 <none>',
            b'status half-configured existing:amd64 1', b'status installed existing:amd64 1'])
        result = self.inspect()
        self.assertEqual(result['trigger_cycles'], 1)
        self.assertTrue(result['supported_state_sequences_verified'])
        for key in ('dependency_order_verified', 'time_window_verified',
                    'actual_trigger_arguments_verified', 'trigger_authority_verified',
                    'log_change_accounted', 'changes_authorized', 'publication_authorized'):
            self.assertFalse(result[key])

    def test_empty_missing_or_repeated_startup_and_missing_final_events_rejected(self):
        for bodies in ([], self.bodies[1:], [self.bodies[0]]+self.bodies,
                       self.bodies[:-1], self.bodies[:1]):
            with self.subTest(bodies=bodies), self.assertRaises(ValueError):
                self.inspect(bodies)

    def test_repeated_or_reordered_install_and_configure_are_rejected(self):
        for bodies in (self.bodies+[self.bodies[1]], self.bodies+[self.bodies[4]],
                       self.bodies[:2]+self.bodies[3:4]+self.bodies[2:3]+self.bodies[4:],
                       self.bodies[:2]+self.bodies[4:]):
            with self.subTest(bodies=bodies), self.assertRaises(ValueError):
                self.inspect(bodies)

    def test_trigger_processing_without_pending_or_with_unsettled_pending_rejected(self):
        for extra in ([b'trigproc existing:amd64 1 <none>'],
                      [b'status triggers-pending existing:amd64 1']):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self.inspect(self.bodies+extra)

    def test_same_package_can_repeat_a_complete_new_pending_trigger_cycle(self):
        cycle = [b'status triggers-pending existing:amd64 1',
                 b'trigproc existing:amd64 1 <none>',
                 b'status half-configured existing:amd64 1',
                 b'status installed existing:amd64 1']
        self.assertEqual(self.inspect(self.bodies+cycle+cycle)['trigger_cycles'], 2)

    def test_backwards_wall_clock_text_and_overlapping_actions_rejected(self):
        raw = b''.join(STAMP+b+b'\n' for b in self.bodies)
        raw = raw.replace(STAMP+b'configure', b'2026-10-26 04:23:39 configure')
        with self.assertRaises(ValueError):
            require_sequence(b'', raw, self.before, self.after, self.records)
        self.after += status('otherpkg', '2')
        self.records.append(dict(name='otherpkg', architecture='amd64', version='2'))
        bodies = self.bodies[:2]+[b'install otherpkg:amd64 <none> 2']+self.bodies[2:]
        with self.assertRaises(ValueError):
            self.inspect(bodies)

    def test_actual_native_suffix_fixture_matches_supported_profile(self):
        before = status('libc-bin', '2.41-12+deb13u4')+status('man-db', '2.13.1-1')
        after = before+status('libncurses6', '6.5+20250216-2')+status('sl', '5.02-1+b1')
        records = [dict(name='libncurses6', architecture='amd64', version='6.5+20250216-2'),
                   dict(name='sl', architecture='amd64', version='5.02-1+b1')]
        raw = (Path(__file__).parent/'fixtures/dpkg-log-31eb9ba-append.txt').read_bytes()
        result = require_sequence(b'', raw, before, after, records)
        self.assertEqual((result['events'], result['new_packages'], result['trigger_cycles']),
                         (21, 2, 2))
