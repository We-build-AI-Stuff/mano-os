"""Fixed disposable-CI UID-drop comparison; never changes production policy."""
import ast
import base64
import hashlib
import json
import time
from pathlib import Path

HEADER = '''import base64,ctypes,errno,hashlib,json,os,pwd,resource,selectors,subprocess,sys,time
from pathlib import Path
'''
BODY = r'''
def state():
    status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines())
    return dict(uid=list(os.getresuid()),gid=list(os.getresgid()),groups=sorted(os.getgroups()),
        caps={k:int(status[k].strip(),16) for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')},
        securebits=ctypes.CDLL(None,use_errno=True).prctl(27,0,0,0,0),
        nnp=int(status['NoNewPrivs']),
        namespaces={k:os.readlink('/proc/self/ns/'+k) for k in
                    ('mnt','pid','net','ipc','uts','cgroup')})

lib=ctypes.CDLL(None,use_errno=True)
class Head(ctypes.Structure):
    _fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class Data(ctypes.Structure):
    _fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),
              ('inheritable',ctypes.c_uint32)]
def deny_extra_capability():
    head=Head(0x20080522,0)
    data=(Data*2)()
    data[0].effective=data[0].permitted=1<<21  # CAP_SYS_ADMIN, outside 0xdb.
    ctypes.set_errno(0)
    result=lib.capset(ctypes.byref(head),ctypes.byref(data))
    assert result==-1 and ctypes.get_errno()==errno.EPERM
    return errno.EPERM

man=pwd.getpwnam('man')
assert man.pw_uid>0 and man.pw_gid>0
environment={'PATH':'/usr/sbin:/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
if sys.argv[1:]==['retention-postexec']:
    print(json.dumps(state()))
elif len(sys.argv)==5 and sys.argv[1]=='retention':
    expected,wide,value=map(int,sys.argv[2:])
    assert expected in {43,11} and wide in {0,1} and value in {0,1}
    assert os.uname().machine=='x86_64'
    before=state()
    assert before['uid']==before['gid']==[0]*3 and before['securebits']==expected
    assert before['nnp']==1 and set(before['caps'].values())=={0xdb}
    option=8+(wide<<32)  # PR_SET_KEEPCAPS, including the kernel's int selector alias.
    lib.syscall.restype=ctypes.c_long
    ctypes.set_errno(0)
    result=lib.syscall(ctypes.c_long(157),ctypes.c_ulong(option),ctypes.c_ulong(value),
        ctypes.c_ulong(0),ctypes.c_ulong(0),ctypes.c_ulong(0))
    error=ctypes.get_errno()
    after=state()
    post=run_observed(['/usr/bin/python3','-P','/run/probe.py','retention-postexec'],
        environment,2)
    assert post['capture_complete'] and post['returncode']==0
    assert not base64.b64decode(post['stderr']['base64'])
    postexec=json.loads(base64.b64decode(post['stdout']['base64']))
    print(json.dumps(dict(profile=expected,option_word=option,requested_keepcaps=value,
        returncode=result,errno=error,before=before,after_set=after,after_exec=postexec)))
elif sys.argv[1:]==['child']:
    before=state()
    assert before['uid']==[man.pw_uid]*3 and before['gid']==[man.pw_gid]*3
    assert before['groups']==sorted(set(os.getgrouplist('man',man.pw_gid)))
    assert 0 not in before['groups'] and before['nnp']==1 and before['securebits']==11
    assert before['caps']['CapBnd']==0xdb
    assert before['caps']['CapEff']==before['caps']['CapPrm']==before['caps']['CapAmb']==0
    assert before['caps']['CapInh'] & ~0xdb==0
    denied=deny_extra_capability()
    try:
        os.setresuid(0,0,0)
    except OSError as error:
        assert error.errno==errno.EPERM
        root_denied=error.errno
    else:
        raise AssertionError('Dropped process regained root IDs')
    ctypes.set_errno(0)
    assert lib.prctl(28,0,0,0,0)==-1 and ctypes.get_errno()==errno.EPERM
    after=state()
    assert before==after
    print(json.dumps(dict(before=before,after=after,extra_capability_errno=denied,
        root_restore_errno=root_denied,securebits_reset_errno=errno.EPERM)))
else:
    assert len(sys.argv)==2 and sys.argv[1] in {'43','11'}
    expected=int(sys.argv[1]);before=state()
    assert before['uid']==before['gid']==[0,0,0]
    assert before['nnp']==1 and before['securebits']==expected
    assert set(before['caps'].values())=={0xdb} and os.getpid()==2
    denied=deny_extra_capability()
    assert before==state()
    controls=[]
    for wide,value in ((0,0),(0,1),(1,0),(1,1)):
        controls.append(run_observed(['/usr/bin/python3','-P','/run/probe.py','retention',
            str(expected),str(wide),str(value)],environment,4))
        assert before==state()
    result=run_observed(['/usr/bin/setpriv','--reuid','man','--regid','man','--init-groups',
        '--','/usr/bin/python3','-P','/run/probe.py','child'],
        environment,5)
    print(json.dumps(dict(profile=expected,parent=before,man_uid=man.pw_uid,man_gid=man.pw_gid,
        expected_groups=sorted(set(os.getgrouplist('man',man.pw_gid))),
        extra_capability_errno=denied,result=result,
        retention_controls_profile='uid-drop-keepcaps-controls-v1',retention_controls=controls)))
'''


def program(source):
    tree=ast.parse(source)
    capture=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='run_observed')
    text=HEADER+ast.get_source_segment(source,capture)+'\n'+BODY
    compile(text,'uid-drop-ci-worker','exec')
    return text.encode()


def state_shape(value):
    keys={'CapEff','CapPrm','CapInh','CapBnd','CapAmb'}
    if (set(value['caps'])!=keys or any(type(v) is not int or v<0
            for v in value['caps'].values())
            or any(type(value[k]) is not int for k in ('securebits','nnp'))
            or any(type(v) is not int or v<0 for k in ('uid','gid','groups') for v in value[k])
            or len(value['uid'])!=3 or len(value['gid'])!=3
            or value['groups']!=sorted(set(value['groups']))):
        raise ValueError('Exact integer kernel state fields required')


def validate_retention_controls(row, profile):
    if (row.get('retention_controls_profile')!='uid-drop-keepcaps-controls-v1'
            or type(row.get('retention_controls')) is not list
            or len(row['retention_controls'])!=4):
        raise ValueError('Complete fixed capability-retention controls required')
    for result,(wide,requested) in zip(row['retention_controls'],
            ((0,0),(0,1),(1,0),(1,1)),strict=True):
        if (type(result['returncode']) is not int or result['returncode']!=0
                or result['capture_complete'] is not True):
            raise ValueError('Complete normal retention control process required')
        streams={}
        for label in ('stdout','stderr'):
            field=result[label]
            if type(field['base64']) is not str or len(field['base64'])>87384:
                raise ValueError('Bounded retention control diagnostics required')
            raw=base64.b64decode(field['base64'],validate=True)
            if (len(raw)>65536 or type(field['bytes']) is not int or field['bytes']!=len(raw)
                    or field['sha256']!=hashlib.sha256(raw).hexdigest()):
                raise ValueError('Exact retention control diagnostic bytes/hash required')
            streams[label]=raw
        if streams['stderr']:
            raise ValueError('Retention controls must not hide stderr')
        control=json.loads(streams['stdout'])
        if set(control)!={'profile','option_word','requested_keepcaps','returncode','errno',
                          'before','after_set','after_exec'}:
            raise ValueError('Exact retention control fields required')
        values=dict(profile=profile,option_word=8+(wide<<32),requested_keepcaps=requested,
                    returncode=-1 if profile==43 else 0,errno=1 if profile==43 else 0)
        if any(type(control[key]) is not int or control[key]!=value
               for key,value in values.items()):
            raise ValueError('Fixed x86-64 native/wide selector and retention result required')
        for key in ('before','after_set','after_exec'):
            state_shape(control[key])
        expected=json.loads(json.dumps(row['parent']))
        expected['securebits']=profile | (16 if profile==11 and requested==1 else 0)
        if (control['before']!=row['parent'] or control['after_set']!=expected
                or control['after_exec']!=row['parent']):
            raise ValueError('Retained flag must be isolated and reset by exec without cap gain')


def validate(row, profile, host, *, require_retention=False):
    state_shape(row['parent'])
    if row['domain_drained'] is not True:
        raise ValueError('Comparison domain must drain')
    if (type(row['profile']) is not int or row['profile']!=profile
            or type(row['extra_capability_errno']) is not int or row['extra_capability_errno']!=1):
        raise ValueError('Exact CI profile and denied capability addition required')
    parent=row['parent']
    if (parent['uid']!=[0]*3 or parent['gid']!=[0]*3 or parent['securebits']!=profile
            or parent['nnp']!=1 or set(parent['caps'].values())!={0xdb}
            or set(parent['namespaces'])!=set(host)
            or any(parent['namespaces'][k]==host[k] for k in host)):
        raise ValueError('Fixed parent UID/capability/private namespace state required')
    if require_retention or 'retention_controls_profile' in row or 'retention_controls' in row:
        validate_retention_controls(row,profile)
    result=row['result']
    if result['capture_complete'] is not True:
        raise ValueError('Complete bounded comparison output required')
    streams={}
    for label in ('stdout','stderr'):
        field=result[label]
        if type(field['base64']) is not str or len(field['base64'])>87384:
            raise ValueError('Bounded comparison stream required')
        raw=base64.b64decode(field['base64'],validate=True)
        if (len(raw)>65536 or type(field['bytes']) is not int or field['bytes']!=len(raw)
                or field['sha256']!=hashlib.sha256(raw).hexdigest()):
            raise ValueError('Comparison stream bytes/hash mismatch')
        streams[label]=raw
    if type(result['returncode']) is not int:
        raise ValueError('Explicit child return code required')
    if profile==43:
        if (result['returncode']!=1 or streams['stdout'] or
                streams['stderr']!=(b'setpriv: keep process capabilities failed: '
                                    b'Operation not permitted\n')):
            raise ValueError('Locked negative control did not reproduce observed conflict')
        return None
    if profile!=11 or result['returncode']!=0 or streams['stderr']:
        raise ValueError('Alternative must complete the real setpriv UID drop')
    child=json.loads(streams['stdout'])
    state=child['before']
    state_shape(state)
    state_shape(child['after'])
    if (state!=child['after'] or type(row['man_uid']) is not int or row['man_uid']<=0
            or type(row['man_gid']) is not int or row['man_gid']<=0
            or state['uid']!=[row['man_uid']]*3 or state['gid']!=[row['man_gid']]*3
            or state['groups']!=row['expected_groups'] or 0 in state['groups']
            or state['nnp']!=1 or state['securebits']!=11
            or state['caps']['CapBnd']!=0xdb or state['caps']['CapInh'] & ~0xdb
            or any(state['caps'][k]!=0 for k in ('CapEff','CapPrm','CapAmb'))
            or state['namespaces']!=parent['namespaces']
            or any(type(child[k]) is not int or child[k]!=1 for k in
                   ('extra_capability_errno','root_restore_errno','securebits_reset_errno'))):
        raise ValueError('Dropped identity and failed escalation evidence required')
    return child


def write_program(base, capture_source):
    data=program(capture_source)
    path=base/'uid-drop.py'
    with path.open('xb') as stream:
        stream.write(data)
    # The fixed child runs as man and must read this source through its RO bind.
    # BASE stays Root-private; no writable permission is granted to the child.
    path.chmod(0o444)
    return data


def compare(base, capture_source, host, sandbox, run):
    data=write_program(base,capture_source)
    rows={}
    for label,bits in (('locked',43),('compatible',11)):
        unit='mano-staged-uid-drop-'+label+'.service'
        argv=['/usr/bin/systemd-run','--quiet','--pipe','--wait','--collect',
              '--unit='+unit,'--slice=mano-package.slice','--property=MemoryMax=134217728',
              '--property=TasksMax=16','--property=RuntimeMaxSec=10',
              '--property=KillMode=control-group','--property=Restart=no',
              '--property=LimitCORE=0','--property=LimitNOFILE=128']
        row=json.loads(run(argv+sandbox(bits)+[str(bits)],timeout=15))
        group=Path('/sys/fs/cgroup/mano.slice/mano-package.slice')/unit
        deadline=time.monotonic()+5
        while group.exists():
            try:
                events=dict(line.split() for line in
                            (group/'cgroup.events').read_text().splitlines())
            except FileNotFoundError:
                break
            if events.get('populated')=='0':
                break
            if time.monotonic()>=deadline:
                raise ValueError('UID comparison domain did not drain')
            time.sleep(.02)
        row['domain_drained']=True
        rows[label]=row
        # Retain the raw report before rejecting a compatibility or negative check.
        target=Path('/opt/mano-lab/evidence')/('staged-uid-drop-'+label+'.json')
        with target.open('x') as stream:
            json.dump(row,stream,sort_keys=True)
        validate(row,bits,host,require_retention=True)
    return data,dict(schema_version='1.0',program_sha256=hashlib.sha256(data).hexdigest(),
        host_namespaces=host,profiles=rows,production_policy_changed=False,
        package_callback_success_verified=False,trigger_authority_verified=False,
        publication_authorized=False)
