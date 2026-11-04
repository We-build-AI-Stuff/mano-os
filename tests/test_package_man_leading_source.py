import base64
import hashlib
import unittest
from unittest.mock import patch

from mano_runtime import package_man_leading_source as leading


class LeadingManualSourceTests(unittest.TestCase):
    def test_exact_initial_comments_are_skipped_and_reported_as_bound_bytes(self):
        prefix = leading.COMMENT+b' comment\n'+leading.COMMENT+b' another\n'
        raw = prefix+b' \t.so man7/target.7\r\nremaining data\n'
        report = leading.inspect(raw)
        self.assertEqual(report['initial_comment_lines'], 2)
        self.assertEqual(report['selected_line_offset'], len(prefix))
        self.assertEqual(report['comment_prefix_sha256'], hashlib.sha256(prefix).hexdigest())
        self.assertEqual(base64.b64decode(report['operand_base64']), b'man7/target.7')
        self.assertEqual(report['request_kind'], 'relative-reference')
        self.assertFalse(report['filesystem_paths_opened'])
        self.assertFalse(report['ultimate_source_target_resolved'])

    def test_blank_line_indented_comment_and_later_requests_do_not_change_first_line(self):
        for raw in (b'\n.so later.1\n', b' '+leading.COMMENT+b' comment\n.so later.1\n',
                    b'.TH TITLE 1\n.so later.1\n', b'.if 1 .so later.1\n'):
            with self.subTest(raw=raw):
                report = leading.inspect(raw)
                self.assertEqual(report['request_kind'], 'no-leading-so-request')
                self.assertEqual(report['initial_comment_lines'], 0)
                self.assertFalse(report['transitive_source_graph_verified'])

    def test_so_prefix_accepts_no_whitespace_but_never_normalizes_or_executes_operand(self):
        for raw, operand in ((b'.soman1/page.1\n', b'man1/page.1'),
                (b'.so link/../page.1\n', b'link/../page.1'),
                (b'.so "quoted-name"\n', b'"quoted-name"'),
                (b'.so $(do-not-execute) trailing\n', b'$(do-not-execute)'),
                (b'.so filename\xff\n', b'filename\xff')):
            with self.subTest(raw=raw):
                report = leading.inspect(raw)
                self.assertEqual(report['request_kind'], 'relative-reference')
                self.assertEqual(base64.b64decode(report['operand_base64']), operand)
                self.assertFalse(report['filesystem_paths_opened'])
                self.assertFalse(report['publication_authorized'])

    def test_absolute_and_empty_requests_are_distinct_from_absent_requests(self):
        self.assertEqual(leading.inspect(b'.so /etc/shadow\n')['request_kind'],
                         'absolute-reference-not-followed-by-ultimate-source')
        self.assertEqual(leading.inspect(b'.so \t\n')['request_kind'], 'empty-relative-reference')
        for raw in (b'', leading.COMMENT+b' comment', b'.SO upper.1\n'):
            with self.subTest(raw=raw):
                self.assertEqual(leading.inspect(raw)['request_kind'], 'no-leading-so-request')

    def test_nul_unknown_input_types_and_all_report_budgets_reject(self):
        for raw in (b'.so target\0ignored', bytearray(b'fixture'), 'fixture'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                leading.inspect(raw)
        for limit, raw in (('MAX_INPUT_BYTES', b'x'), ('MAX_LINE_BYTES', b'x'),
                           ('MAX_COMMENT_LINES', leading.COMMENT+b' comment\n'),
                           ('MAX_OPERAND_BYTES', b'.so x')):
            with patch.object(leading, limit, 0), self.assertRaises(ValueError):
                leading.inspect(raw)
