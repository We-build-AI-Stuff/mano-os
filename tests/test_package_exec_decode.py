import base64
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_runtime import package_exec_decode as decoder


def quote(value):
    return b'"'+b''.join(f'\\x{b:02x}'.encode() for b in value)+b'"'


def frame(path=b'/usr/bin/tool', args=None, result=b'0'):
    args=[path] if args is None else args
    return (b'execve('+quote(path)+b', ['+b', '.join(map(quote,args))
            +b'], 0x123 /* 2 vars */) = '+result)


class ExecTraceDecoderTests(unittest.TestCase):
    def test_success_and_failed_attempts_preserve_bytes_without_process_success_or_authority(self):
        raw=(b'10  '+frame(args=[b'tool',b'\xff\n'])+b'\n11  '
             +frame(result=b'-1 ENOENT (No such file or directory)')+b'\n')
        result=decoder.decode(raw)
        self.assertEqual((result['decoded_execve_calls'],result['successful_execve_returns'],
                          result['failed_execve_returns']),(2,1,1))
        self.assertEqual(base64.b64decode(result['events'][0]['argv_base64'][1]),b'\xff\n')
        self.assertEqual(result['events'][1]['errno'],'ENOENT')
        for k in ('process_exit_status_verified','caller_ancestry_verified','all_execs_observed',
                  'actual_trigger_arguments_verified','script_contents_at_exec_verified',
                  'trigger_authority_verified','changes_authorized','publication_authorized'):
            self.assertFalse(result[k])

    def test_interleaved_unfinished_and_resumed_calls_preserve_entry_and_completion_lines(self):
        body=frame()
        head,tail=body.split(b') = ',1)
        raw=(b'10  '+head+decoder.UNFINISHED+b'\n11  '+frame()+b'\n10  '
             +decoder.RESUMED+b') = '+tail+b'\n')
        result=decoder.decode(raw)
        self.assertEqual([e['pid'] for e in result['events']],[10,11])
        self.assertEqual((result['events'][0]['entry_line'],result['events'][0]['completion_line']),
                         (1,3))

    def test_unmatched_duplicate_wrong_syscall_or_missing_resume_fail(self):
        body=frame().split(b') = ',1)[0]
        pending=b'10  '+body+decoder.UNFINISHED+b'\n'
        for raw in (pending,b'10  '+decoder.RESUMED+b') = 0\n',pending+pending,
                    pending+b'10  '+frame()+b'\n',pending+b'10  <... execveat resumed>) = 0\n'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                decoder.decode(raw)

    def test_resumed_result_column_padding_preserves_exact_arguments_and_line_linkage(self):
        for ending in (b'0', b'-1 ENOENT (No such file or directory)'):
            body = frame(result=ending)
            head, tail = body.split(b') = ', 1)
            for spaces in (1, 13, 40, 64):
                raw = (b'10  '+head+decoder.UNFINISHED+b'\n11  +++ exited with 0 +++\n'
                       b'10  '+decoder.RESUMED+b')'+b' '*spaces+b'= '+tail+b'\n')
                value = decoder.decode(raw, observe_exits=True)
                event = value['events'][0]
                self.assertEqual((event['entry_line'], event['completion_line']), (1, 3))
                self.assertEqual(base64.b64decode(event['path_base64']), b'/usr/bin/tool')
                self.assertEqual(event['return_value'], 0 if ending == b'0' else -1)
                self.assertFalse(value['process_exit_status_verified'])
                self.assertFalse(value['changes_authorized'])
        for gap in (b'', b'\t', b' \t ', b' '*65, b'\r', b'\v'):
            raw = b'10  '+frame().replace(b') = ', b')'+gap+b'= ')+b'\n'
            with self.subTest(gap=repr(gap)), self.assertRaises(ValueError):
                decoder.decode(raw)

    def test_unknown_truncated_unreadable_and_nonhex_frames_fail(self):
        raw=b'10  '+frame()+b'\n'
        for data in (raw.replace(b'execve(',b'execveat('),raw[:-1],
                     raw.replace(quote(b'/usr/bin/tool'),b'0x123'),
                     raw.replace(quote(b'/usr/bin/tool'),b'"tool"'),
                     raw.replace(b'], 0x',b'...], 0x'),raw+b'garbage\n',
                     raw.replace(b' = 0',b' = ?'),raw.replace(b' /* 2 vars */',b'')):
            with self.subTest(data=data),self.assertRaises(ValueError):
                decoder.decode(data)

    def test_null_environment_empty_strings_and_empty_vector_are_data(self):
        raw=b'10  '+frame(path=b'',args=[]).replace(b'0x123 /* 2 vars */',b'NULL')+b'\n'
        value=decoder.decode(raw)['events'][0]
        self.assertEqual((value['path_base64'],value['argv_base64'],value['environment_count']),
                         ('',[],0))
        with self.assertRaises(ValueError):
            decoder.decode(b'10  '+frame(args=[b'bad\0name'])+b'\n')

    def test_pid_line_string_argument_and_expanded_byte_quotas(self):
        raw=b'10  '+frame()+b'\n'
        for prefix in (b'0 ',b'-1 ',b'2147483648 ',b'[pid 10] '):
            with self.subTest(prefix=prefix),self.assertRaises(ValueError):
                decoder.decode(prefix+frame()+b'\n')
        for name,value in (('MAX_BYTES',len(raw)),('MAX_LINES',0),('MAX_LINE',1),
                           ('MAX_STRING',1),('MAX_ARGS',0),('MAX_EXPANDED',1)):
            with self.subTest(name=name),patch.object(decoder,name,value), \
                    self.assertRaises(ValueError):
                decoder.decode(raw)

    def test_pending_call_quota_is_enforced_before_reassembly(self):
        head,tail=frame().split(b') = ',1)
        raw=b'10  '+head+decoder.UNFINISHED+b'\n10  '+decoder.RESUMED+b') = '+tail+b'\n'
        with patch.object(decoder,'MAX_PENDING',0),self.assertRaises(ValueError):
            decoder.decode(raw)

    def test_actual_native_fixture_decodes_without_promoting_script_or_execution_claims(self):
        raw=(Path(__file__).parent/'fixtures/exec-trace-2011fdd.txt').read_bytes()
        result=decoder.decode(raw)
        self.assertEqual((result['physical_lines'],result['decoded_execve_calls'],
                          result['successful_execve_returns'],result['failed_execve_returns']),
                         (29,29,19,10))
        callbacks=[e for e in result['events']
                   if base64.b64decode(e['path_base64']).endswith(b'.postinst')]
        self.assertEqual([[base64.b64decode(v) for v in e['argv_base64'][1:]] for e in callbacks],
                         [[b'triggered',b'ldconfig'],[b'triggered',b'/usr/share/man']])

    def test_native_aligned_resume_fixture_retains_all_calls_and_process_events(self):
        raw = (Path(__file__).parent/'fixtures/exec-trace-f49cc1d-aligned-resume.txt').read_bytes()
        value = decoder.decode(raw, observe_exits=True)
        self.assertEqual((value['physical_lines'], value['decoded_execve_calls'],
                          value['successful_execve_returns'], value['failed_execve_returns']),
                         (62, 30, 20, 10))
        self.assertEqual(len(value['exit_events']), 31)
        resumed = [e for e in value['events'] if e['entry_line'] != e['completion_line']]
        self.assertEqual(len(resumed), 1)
        event = resumed[0]
        self.assertEqual((event['pid'], event['entry_line'], event['completion_line']),
                         (7892, 12, 14))
        self.assertEqual(base64.b64decode(event['path_base64']), b'/usr/bin/tar')
        self.assertFalse(value['caller_ancestry_verified'])
        self.assertFalse(value['script_contents_at_exec_verified'])
        self.assertFalse(value['publication_authorized'])
