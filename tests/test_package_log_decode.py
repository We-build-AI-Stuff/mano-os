import unittest
from pathlib import Path
from unittest.mock import patch

from mano_runtime import package_log_decode as log

STAMP = b'2026-10-26 04:23:40 '


class DpkgLogDecodeTests(unittest.TestCase):
    def test_recorded_native_install_and_trigger_frames_remain_untrusted(self):
        raw = (Path(__file__).parent/'fixtures/dpkg-log-31eb9ba-append.txt').read_bytes()
        result = log.decode_append(b'old\n', b'old\n'+raw)
        self.assertEqual(result['decoded_events'], 21)
        self.assertEqual(result['events'][0]['event'], 'startup')
        triggers = [row['package'] for row in result['events'] if row['event'] == 'trigproc']
        self.assertEqual(triggers, ['libc-bin:amd64', 'man-db:amd64'])
        for key in ('timestamp_timezone_verified', 'package_scope_verified',
                    'trigger_authority_verified', 'time_window_verified', 'log_semantics_verified',
                    'log_change_accounted', 'changes_authorized', 'publication_authorized'):
            self.assertIs(result[key], False)

    def test_documented_event_families_and_literal_conffile_spaces(self):
        cases = (b'startup packages triggers-only', b'status not-installed pkg:all <none>',
                 b'upgrade pkg:amd64 1:2+3-4 2:3~rc1', b'configure pkg:amd64 2 2',
                 b'disappear pkg:amd64 2 <none>', b'remove pkg:amd64 2 <none>',
                 b'purge pkg:amd64 2 <none>', b'conffile /etc/path with spaces keep')
        for body in cases:
            with self.subTest(body=body):
                self.assertEqual(len(log.frames(STAMP+body+b'\n')), 1)
        self.assertEqual(log.frames(STAMP+cases[-1]+b'\n')[0]['path'], '/etc/path with spaces')

    def test_unknown_actions_states_scope_syntax_and_extra_fields_are_rejected(self):
        cases = (b'execute pkg 1 2', b'status malicious pkg 1', b'install ../pkg 1 2',
                 b'install pkg:amd64 1 2 extra', b'startup archives purge',
                 b'conffile relative keep', b'conffile /etc/target execute',
                 b'install  pkg:amd64 1 2', b'status installed pkg:AMD64 1')
        for body in cases:
            with self.subTest(body=body), self.assertRaises(ValueError):
                log.frames(STAMP+body+b'\n')

    def test_incomplete_invalid_timestamp_utf8_and_control_characters_are_rejected(self):
        cases = (STAMP+b'install pkg 1 2', b'2026-02-30 04:23:40 install pkg 1 2\n',
                 STAMP+b'install pkg 1 2\r\n', STAMP+b'install pkg 1 2\0\n',
                 STAMP+b'conffile /etc/\xff keep\n', b'\n')
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                log.frames(raw)
        for character in ('\u0085', '\u2028', '\u202e'):
            with self.subTest(character=character), self.assertRaises(ValueError):
                log.frames(STAMP+('conffile /etc/'+character+' keep\n').encode())

    def test_quotas_are_checked_before_line_array_allocation(self):
        raw = STAMP+b'install pkg 1 2\n'
        for name in ('MAX_LOG', 'MAX_LINE'):
            with self.subTest(name=name), patch.object(log, name, 1), self.assertRaises(ValueError):
                log.frames(raw)
        with patch.object(log, 'MAX_EVENTS', 1), self.assertRaises(ValueError):
            log.frames(raw*2)

    def test_rewrite_has_no_decoded_append_and_empty_append_is_not_an_install(self):
        rewritten = log.decode_append(b'old\n', b'changed\n')
        self.assertFalse(rewritten['event_frames_decoded'])
        self.assertIsNone(rewritten['events'])
        self.assertIsNone(rewritten['decoded_events'])
        empty = log.decode_append(b'old\n', b'old\n')
        self.assertEqual(empty['events'], [])
        self.assertFalse(empty['log_semantics_verified'])
