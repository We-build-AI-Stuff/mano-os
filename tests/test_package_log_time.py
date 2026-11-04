import datetime
import unittest

from mano_runtime import package_log_time as timing


class PackageLogTimeTests(unittest.TestCase):
    def setUp(self):
        self.start = int(datetime.datetime(2026, 10, 26, 4, 23, 40,
                        tzinfo=datetime.UTC).timestamp())*10**9
        self.samples = dict(realtime_before_ns=self.start+100,
            realtime_after_ns=self.start+10**9+200,
            monotonic_before_ns=10**12, monotonic_after_ns=10**12+10**9,
            boot_id_before='11111111-2222-3333-4444-555555555555',
            boot_id_after='11111111-2222-3333-4444-555555555555',worker_timezone='UTC0')
        self.log = (b'2026-10-26 04:23:40 startup archives install\n'
                    b'2026-10-26 04:23:41 install newpkg:amd64 <none> 1\n')

    def bind(self):
        return timing.bind_controller_window(b'prior\n',b'prior\n'+self.log,self.samples)

    def test_second_resolution_intervals_include_start_and_end_buckets_without_authority(self):
        result = self.bind()
        self.assertEqual(result['events'],2)
        self.assertTrue(result['timestamp_timezone_verified'])
        self.assertTrue(result['time_window_verified'])
        self.assertEqual(result['elapsed_monotonic_ns'],10**9)
        for name in ('external_time_authority_verified','trigger_authority_verified',
                     'log_change_accounted','changes_authorized','publication_authorized'):
            self.assertFalse(result[name])

    def test_events_before_after_or_decreasing_within_interval_are_rejected(self):
        for raw in (self.log.replace(b'04:23:40',b'04:23:39'),
                    self.log.replace(b'04:23:41',b'04:23:42'),
                    b'\n'.join(reversed(self.log.rstrip(b'\n').split(b'\n')))+b'\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                timing.bind_controller_window(b'',raw,self.samples)

    def test_clock_reversal_duration_and_wall_clock_jump_are_rejected(self):
        for field,value in (('monotonic_after_ns',1),('realtime_after_ns',1),
                ('monotonic_after_ns',10**12+61*10**9),
                ('realtime_after_ns',self.start+10*10**9)):
            with self.subTest(field=field,value=value), self.assertRaises(ValueError):
                timing.bind_controller_window(b'',self.log,self.samples|{field:value})

    def test_missing_extra_boolean_negative_and_overflow_samples_are_rejected(self):
        for field in ('realtime_before_ns','realtime_after_ns',
                      'monotonic_before_ns','monotonic_after_ns'):
            for value in (True,-1,0,2**63,'1'):
                with self.subTest(field=field,value=value), self.assertRaises(ValueError):
                    timing.bind_controller_window(b'',self.log,self.samples|{field:value})
        for samples in ({},self.samples|{'claimed_verified':True}):
            with self.assertRaises(ValueError):
                timing.bind_controller_window(b'',self.log,samples)

    def test_boot_or_timezone_substitution_cannot_validate_local_timestamp_text(self):
        for field,value in (('worker_timezone','UTC'),('worker_timezone','Asia/Kolkata'),
                ('boot_id_after','aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'),
                ('boot_id_before','not-a-boot-id')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                timing.bind_controller_window(b'',self.log,self.samples|{field:value})

    def test_empty_or_rewritten_log_is_not_execution_evidence(self):
        for before,after in ((b'',b''),(b'prior',self.log)):
            with self.assertRaises(ValueError):
                timing.bind_controller_window(before,after,self.samples)
