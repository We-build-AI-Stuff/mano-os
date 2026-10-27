import base64
import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0,str(SCRIPTS))
SPEC=importlib.util.spec_from_file_location('uid_probe',SCRIPTS/'probe_package_uid_drop.py')
uid=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(uid)
from test_staged_package_probe import probe as stage  # noqa: E402


def stream(raw):
    return dict(base64=base64.b64encode(raw).decode(),bytes=len(raw),
                sha256=hashlib.sha256(raw).hexdigest())


def fixture(bits):
    host={k:k+':[1]' for k in ('mnt','pid','net','ipc','uts','cgroup')}
    ns={k:k+':[2]' for k in host}
    parent=dict(uid=[0]*3,gid=[0]*3,groups=[0],caps=dict.fromkeys(
        ('CapEff','CapPrm','CapInh','CapBnd','CapAmb'),0xdb),securebits=bits,nnp=1,namespaces=ns)
    child=copy.deepcopy(parent)
    child.update(uid=[6]*3,gid=[12]*3,groups=[12],securebits=11)
    child['caps'].update(CapEff=0,CapPrm=0,CapAmb=0)
    report=dict(before=child,after=child,extra_capability_errno=1,
                root_restore_errno=1,securebits_reset_errno=1)
    raw=json.dumps(report).encode()
    result=dict(returncode=0,capture_complete=True,stdout=stream(raw),stderr=stream(b''))
    if bits==43:
        result.update(returncode=1,stdout=stream(b''),stderr=stream(
            b'setpriv: keep process capabilities failed: Operation not permitted\n'))
    row=dict(profile=bits,parent=parent,man_uid=6,man_gid=12,expected_groups=[12],
             extra_capability_errno=1,result=result,domain_drained=True)
    return host,row,report


class UidDropComparisonTests(unittest.TestCase):
    def test_dropped_child_source_is_readable_but_never_writable_or_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            data=uid.write_program(base,stage.PROGRAM)
            target=base/'uid-drop.py'
            self.assertEqual(target.read_bytes(),data)
            self.assertEqual(target.stat().st_mode & 0o777,0o444)
            with self.assertRaises(FileExistsError):
                uid.write_program(base,stage.PROGRAM)
            self.assertEqual(target.read_bytes(),data)

    def test_fixed_ci_worker_pairs_use_verified_profiles_only(self):
        for leaf,bits in (('probe.py',11),('uid-drop.py',43),('uid-drop.py',11)):
            args=stage.sandbox_argv(Path('/candidate'),[],Path('/empty'),
                                    program=leaf,securebits=bits)
            self.assertIn(str(stage.BASE/leaf),args)
            option=next(v for v in args if v.startswith('--securebits='))
            self.assertEqual('keep_caps_locked' in option,bits==43)
            self.assertIn('--bounding-set='+stage.CAPS,args)
        for leaf,bits in (('probe.py',43),('other.py',43),('uid-drop.py',0)):
            with self.assertRaises(ValueError):
                stage.sandbox_argv(Path('/candidate'),[],Path('/empty'),
                                   program=leaf,securebits=bits)
        compile(uid.program(stage.PROGRAM),'uid-drop-ci-fixture','exec')
        # No embedded Linux worker or Root operation runs on this host.

    def test_locked_control_and_successful_drop_reports_are_distinct(self):
        host,row,_=fixture(43)
        self.assertIsNone(uid.validate(row,43,host))
        host,row,report=fixture(11)
        self.assertEqual(uid.validate(row,11,host),report)

    def test_false_control_success_incomplete_or_substituted_streams_rejected(self):
        host,row,_=fixture(43)
        for change in ({'returncode':0},{'capture_complete':False},
                       {'stderr':stream(b'different failure')},
                       {'stdout':stream(b'unexpected child output')}):
            altered=copy.deepcopy(row)
            altered['result'].update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):
                uid.validate(altered,43,host)
        row['result']['stderr']['sha256']='0'*64
        with self.assertRaises(ValueError):
            uid.validate(row,43,host)

    def test_root_capability_namespace_or_escalation_substitutions_rejected(self):
        host,row,report=fixture(11)
        for key,val in (('uid',[0]*3),('gid',[0]*3),('groups',[0,12]),
                        ('securebits',43),('nnp',0),('namespaces',host)):
            altered=copy.deepcopy(report)
            altered['before'][key]=val
            altered['after']=copy.deepcopy(altered['before'])
            self.reject_child(host,row,altered)
        for key,val in (('CapEff',0xdb),('CapPrm',0xdb),('CapAmb',0xdb),
                        ('CapBnd',0x2000db),('CapInh',0x2000db),('CapEff',False)):
            altered=copy.deepcopy(report)
            altered['before']['caps'][key]=val
            altered['after']=copy.deepcopy(altered['before'])
            self.reject_child(host,row,altered)
        for key in ('root_restore_errno','extra_capability_errno','securebits_reset_errno'):
            altered=copy.deepcopy(report)
            altered[key]=0
            self.reject_child(host,row,altered)
        row['domain_drained']=False
        with self.assertRaises(ValueError):
            uid.validate(row,11,host)

    def reject_child(self,host,row,report):
        altered=copy.deepcopy(row)
        altered['result']['stdout']=stream(json.dumps(report).encode())
        with self.assertRaises(ValueError):
            uid.validate(altered,11,host)
