import unittest
from pathlib import Path

from test_package_exec_decode import frame
from test_staged_package_probe import probe

from mano_runtime.package_exec_decode import decode


def call(pid,path,args):
    return str(pid).encode()+b'  '+frame(path=path,args=[path,*args])+b'\n'


def fixture():
    return (call(10,b'/var/lib/dpkg/info/libc-bin.postinst',[b'triggered',b'ldconfig'])
            +call(11,b'/var/lib/dpkg/info/man-db.postinst',[b'triggered',b'/usr/share/man'])
            +call(12,b'/usr/bin/mandb',[b'-pq'])+b'12  +++ exited with 0 +++\n'
            +b'10  +++ exited with 0 +++\n11  +++ exited with 0 +++\n')


class ProcessOutcomeTests(unittest.TestCase):
    def test_explicit_exit_dialect_preserves_normal_signal_and_core_records(self):
        raw=(call(10,b'/usr/bin/tool',[])+b'10  +++ exited with 7 +++\n'
             +b'11  +++ killed by SIGTERM +++\n12  +++ killed by SIGSEGV (core dumped) +++\n')
        value=decode(raw,observe_exits=True)
        self.assertEqual(value['profile'],'strace-hex-execve-exit-v1')
        self.assertEqual([e['exit_code'] for e in value['exit_events']],[7,None,None])
        self.assertEqual([e['signal'] for e in value['exit_events']],[None,'SIGTERM','SIGSEGV'])
        self.assertTrue(value['exit_events'][-1]['core_dumped'])
        self.assertFalse(value['process_exit_status_verified'])
        with self.assertRaises(ValueError):
            decode(raw)

    def test_pid_reuse_creates_distinct_observed_generations(self):
        raw=(call(10,b'/usr/bin/first',[])+b'10  +++ exited with 0 +++\n'
             +call(10,b'/usr/bin/second',[])+b'10  +++ exited with 9 +++\n')
        value=decode(raw,observe_exits=True)
        self.assertEqual([e['process_generation'] for e in value['events']],[0,1])
        self.assertEqual([e['process_generation'] for e in value['exit_events']],[0,1])

    def test_malformed_out_of_range_or_pending_terminal_record_rejected(self):
        for raw in (b'10 +++ exited with 256 +++\n',b'10 +++ exited with -1 +++\n',
                    b'10 +++ exited with 00 +++\n',b'10 +++ killed by garbage +++\n',
                    b'10 +++ detached +++\n',
                    b'10 execve( <unfinished ...>\n10 +++ exited with 0 +++\n'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                decode(raw,observe_exits=True)
        with self.assertRaises(ValueError):
            decode(fixture(),observe_exits='yes')

    def test_fixed_process_zero_exits_do_not_grant_coverage_or_authority(self):
        value=probe.process_outcomes(fixture())
        self.assertEqual(set(value['observations']),{'libc-trigger','man-trigger','mandb'})
        self.assertTrue(value['observed_target_zero_exits'])
        self.assertEqual(value['observations']['mandb']['exit_line'],4)
        for key in ('all_process_outcomes_verified','credentials_at_exec_verified',
                    'caller_ancestry_verified','all_execs_observed','script_contents_at_exec_verified',
                    'trigger_authority_verified','changes_authorized','publication_authorized'):
            self.assertFalse(value[key])

    def test_missing_nonzero_signalled_or_duplicate_target_rejects(self):
        raw=fixture()
        for altered in (raw.replace(b'12  +++ exited with 0 +++\n',b''),
                        raw.replace(b'12  +++ exited with 0 +++',b'12  +++ exited with 1 +++'),
                        raw.replace(b'12  +++ exited with 0 +++',b'12  +++ killed by SIGTERM +++'),
                        call(12,b'/usr/bin/mandb',[b'-pq'])+raw):
            with self.subTest(altered=altered),self.assertRaises(ValueError):
                probe.process_outcomes(altered)

    def test_unexpected_replacement_arguments_or_wrong_generation_rejects(self):
        raw=fixture()
        wrong_generation=(b'12  +++ exited with 0 +++\n'
                          +raw.replace(b'12  +++ exited with 0 +++\n',b''))
        replacement=raw.replace(b'12  +++ exited',
                                call(12,b'/usr/bin/other',[])+b'12  +++ exited')
        wrong_arguments=raw.replace(call(12,b'/usr/bin/mandb',[b'-pq']),
                                    call(12,b'/usr/bin/mandb',[b'--wrong']))
        for altered in (replacement,wrong_generation,wrong_arguments,
                        raw.replace(b'12  +++ exited',b'13  +++ exited')):
            with self.subTest(altered=altered),self.assertRaises(ValueError):
                probe.process_outcomes(altered)

    def test_archived_native_exec_only_trace_cannot_prove_terminal_status(self):
        raw=(Path(__file__).parent/'fixtures/exec-trace-2011fdd.txt').read_bytes()
        with self.assertRaises(ValueError):
            probe.process_outcomes(raw)
