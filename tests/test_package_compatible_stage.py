import base64
import copy
import unittest
from pathlib import Path

from test_staged_package_probe import probe

from mano_runtime.package_exec_decode import decode


def b64(raw):
    return base64.b64encode(raw).decode()


def fixture():
    decoded=decode((Path(__file__).parent/'fixtures/exec-trace-2011fdd.txt').read_bytes())
    drop=next(e for e in decoded['events'] if e['return_value']==0 and
              b'--reuid' in [base64.b64decode(a) for a in e['argv_base64']])
    event=dict(pid=drop['pid'],entry_line=100,completion_line=100,
               path_base64=b64(b'/usr/bin/mandb'),argv_base64=[b64(b'/usr/bin/mandb'),b64(b'-pq')],
               return_value=0,errno=None,environment_count=4)
    decoded['events'].append(event)
    worker=dict(securebits=11,capability_profile='uid-drop-compatible-v1',
                no_new_privileges=True,capabilities=dict.fromkeys(
                    ('CapEff','CapPrm','CapInh','CapBnd','CapAmb'),0xdb))
    return worker,decoded


class CompatibleStageTests(unittest.TestCase):
    def test_previously_native_missing_mandb_is_not_promoted_to_compatibility(self):
        worker,decoded=fixture()
        decoded['events'].pop()
        with self.assertRaises(ValueError):
            probe.compatible_stage(worker,decoded)

    def test_synthetic_mandb_image_event_keeps_outcome_and_authority_unverified(self):
        worker,decoded=fixture()
        value=probe.compatible_stage(worker,decoded)
        self.assertTrue(value['mandb_image_replacement_observed'])
        for k in ('process_exit_status_verified','credentials_at_mandb_exec_verified',
                  'caller_ancestry_verified','all_execs_observed','script_contents_at_exec_verified',
                  'trigger_authority_verified','changes_authorized','publication_authorized'):
            self.assertFalse(value[k])

    def test_wrong_arguments_pid_order_failure_duplicates_or_profile_rejected(self):
        worker,decoded=fixture()
        for key,value in (('pid',99999),('entry_line',1),('return_value',-1),
                          ('argv_base64',[b64(b'/usr/bin/mandb'),b64(b'--wrong')])):
            altered=copy.deepcopy(decoded)
            altered['events'][-1][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                probe.compatible_stage(worker,altered)
        altered=copy.deepcopy(decoded)
        altered['events'].append(altered['events'][-1])
        with self.assertRaises(ValueError):
            probe.compatible_stage(worker,altered)
        for key,value in (('securebits',43),('capability_profile','other'),
                          ('no_new_privileges',False)):
            altered=copy.deepcopy(worker)
            altered[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                probe.compatible_stage(altered,decoded)
        worker['capabilities']['CapEff']=0x2000db
        with self.assertRaises(ValueError):
            probe.compatible_stage(worker,decoded)
