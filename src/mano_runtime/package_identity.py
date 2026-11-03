"""Fixed complete-UID delegation preflight; no public command or path API.

Only the Linux native package boundary may launch this child. Kernel probes run
only as the fully dropped identity; the parent preserves its transaction state.
"""
import base64
import ctypes
import errno
import json
import os
import pwd
import re
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

from mano_protocol.actions import unique_object

CAPS = {'CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb'}
KINDS = ('mnt', 'net', 'ipc', 'pid', 'cgroup')
PROFILE = 'package-complete-uid-drop-v1'
COMMAND = ('/usr/bin/setpriv', '--reuid', 'man', '--regid', 'man', '--init-groups', '--',
           '/usr/bin/python3', '-P', '-m', 'mano_runtime.package_identity', '--verify-delegated')
ENV = {'PATH': '/usr/sbin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC0',
       'HOME': '/nonexistent', 'PYTHONPATH': '/usr/lib/mano-os', 'PYTHONDONTWRITEBYTECODE': '1'}


def account():
    man = pwd.getpwnam('man')
    groups = sorted(set(os.getgrouplist('man', man.pw_gid)))
    if (type(man.pw_uid) is not int or man.pw_uid <= 0
            or type(man.pw_gid) is not int or man.pw_gid <= 0
            or not groups or man.pw_gid not in groups or 0 in groups
            or any(type(item) is not int or item < 0 for item in groups)):
        raise PermissionError('Fixed non-Root delegated account required')
    return man.pw_uid, man.pw_gid, groups


def parent_guard():
    if sys.platform != 'linux' or os.geteuid() != 0 or os.getpid() != 2:
        raise PermissionError('Fixed private Linux Root package boundary required')


def child_guard():
    if sys.platform != 'linux':
        raise PermissionError('Linux delegated-identity verification required')
    uid, gid, groups = account()
    if (os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid)
            or sorted(os.getgroups()) != groups):
        raise PermissionError('Complete delegated identity required before kernel probes')
    return uid, gid, groups


def state():
    if sys.platform != 'linux':
        raise PermissionError('Linux identity state only')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
    lib = ctypes.CDLL(None, use_errno=True)
    lib.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                         ctypes.c_ulong, ctypes.c_ulong]
    return dict(uid=list(os.getresuid()), gid=list(os.getresgid()), groups=sorted(os.getgroups()),
        caps={key: int(status[key].strip(), 16) for key in CAPS},
        securebits=lib.prctl(27, 0, 0, 0, 0), nnp=int(status['NoNewPrivs']),
        seccomp=int(status['Seccomp']),
        label=Path('/proc/self/attr/current').read_text().strip(),
        namespaces={kind: os.readlink('/proc/self/ns/'+kind) for kind in KINDS})


def validate_state(value, *, uid, gid, groups, namespaces):
    if type(value) is not dict or set(value) != {
            'uid', 'gid', 'groups', 'caps', 'securebits', 'nnp', 'seccomp', 'label', 'namespaces'}:
        raise ValueError('Exact delegated kernel-state fields required')
    for key, expected in (('uid', [uid]*3), ('gid', [gid]*3), ('groups', groups)):
        if (type(value[key]) is not list or value[key] != expected
                or any(type(item) is not int for item in value[key])):
            raise ValueError('Exact complete delegated credentials required')
    caps = value['caps']
    if (type(caps) is not dict or set(caps) != CAPS
            or any(type(item) is not int or item < 0 for item in caps.values())
            or any(caps[key] != 0 for key in ('CapEff', 'CapPrm', 'CapAmb'))
            or caps['CapBnd'] != 0xdb or caps['CapInh'] & ~0xdb):
        raise ValueError('Dropped effective/permitted/ambient sets and exact ceiling required')
    for key, expected in (('securebits', 11), ('nnp', 1), ('seccomp', 2)):
        if type(value[key]) is not int or value[key] != expected:
            raise ValueError('Exact inherited native restrictions required')
    if (value['label'] != 'mano-package-worker (enforce)'
            or type(value['namespaces']) is not dict or set(value['namespaces']) != set(KINDS)
            or value['namespaces'] != namespaces
            or any(type(item) is not str or re.fullmatch(kind+r':\[[1-9][0-9]*\]', item) is None
                   for kind, item in value['namespaces'].items())):
        raise ValueError('Same private namespaces and enforced package label required')


def validate(value, *, uid, gid, groups, namespaces):
    if (type(uid) is not int or uid <= 0 or type(gid) is not int or gid <= 0
            or type(groups) is not list or not groups or 0 in groups
            or any(type(item) is not int or item < 0 for item in groups)
            or groups != sorted(set(groups))):
        raise ValueError('Trusted non-Root account identity required')
    if type(value) is not dict or set(value) != {'profile', 'before', 'after', 'denials'}:
        raise ValueError('Exact complete delegation witness required')
    if value['profile'] != PROFILE:
        raise ValueError('Fixed complete delegation profile required')
    for key in ('before', 'after'):
        validate_state(value[key], uid=uid, gid=gid, groups=groups, namespaces=namespaces)
    if value['before'] != value['after']:
        raise ValueError('Delegated identity changed during denial probes')
    if (type(value['denials']) is not dict or set(value['denials']) != {
            'root_restore_errno', 'extra_capability_errno', 'securebits_reset_errno'}
            or any(type(item) is not int or item != 1 for item in value['denials'].values())):
        raise ValueError('Explicit failed Root/capability/securebits restoration required')
    return value


def denials():
    child_guard()  # Never run Linux capability/identity probes in Root or on Mac.
    lib = ctypes.CDLL(None, use_errno=True)

    class Head(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32),
                   ('inheritable', ctypes.c_uint32)]

    header, data = Head(0x20080522, 0), (Data*2)()
    data[0].effective = data[0].permitted = 1 << 21
    ctypes.set_errno(0)
    if lib.capset(ctypes.byref(header), ctypes.byref(data)) != -1 or (
            ctypes.get_errno() != errno.EPERM):
        raise PermissionError('Delegated child acquired an outside capability')
    try:
        os.setresuid(0, 0, 0)
    except OSError as error:
        if error.errno != errno.EPERM:
            raise
    else:
        raise PermissionError('Delegated child restored Root IDs')
    lib.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                         ctypes.c_ulong, ctypes.c_ulong]
    ctypes.set_errno(0)
    if lib.prctl(28, 0, 0, 0, 0) != -1 or ctypes.get_errno() != errno.EPERM:
        raise PermissionError('Delegated child reset securebits')
    return dict(root_restore_errno=1, extra_capability_errno=1, securebits_reset_errno=1)


def verify_own_drop():
    uid, gid, groups = child_guard()
    before = state()
    validate_state(before, uid=uid, gid=gid, groups=groups, namespaces=before['namespaces'])
    outcome = denials()
    result = dict(profile=PROFILE, before=before, after=state(), denials=outcome)
    return validate(result, uid=uid, gid=gid, groups=groups, namespaces=before['namespaces'])


def capture(*, timeout=5):
    parent_guard()
    if type(timeout) not in {int, float} or not 0 < timeout <= 5:
        raise ValueError('Bounded package delegation deadline required')
    process = subprocess.Popen(list(COMMAND), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, close_fds=True, start_new_session=True, cwd='/', env=ENV)
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    deadline = time.monotonic()+timeout
    failed = True
    try:
        with selectors.DefaultSelector() as selector:
            for name, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map() or process.poll() is None:
                if time.monotonic() >= deadline:
                    raise TimeoutError('Package identity delegation deadline')
                for key, _ in selector.select(.02):
                    remaining = 8192-sum(map(len, output.values()))
                    try:
                        data = os.read(key.fd, min(4096, remaining+1))
                    except (BlockingIOError, InterruptedError):
                        continue
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    output[key.data].extend(data[:remaining])
                    if len(data) > remaining:
                        raise ValueError('Package identity delegation output budget')
        if process.returncode != 0 or output['stderr']:
            raise ValueError('Complete normal package identity delegation required')
        failed = False
        return bytes(output['stdout'])
    except (ValueError, TimeoutError):
        # Operator-private diagnostics only; the Root controller never turns
        # this prefix or its data into Broker/public authority messages.
        diagnostic = {name: base64.b64encode(raw).decode() for name, raw in output.items()}
        print('MANO_PACKAGE_PRIVATE_IDENTITY=' + json.dumps(diagnostic),
              file=sys.stderr, flush=True)
        raise
    finally:
        if failed or process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.stdout.close()
        process.stderr.close()
        process.wait(timeout=2)


def preflight():
    parent_guard()
    uid, gid, groups = account()
    before = state()
    if (before['uid'] != [0]*3 or before['securebits'] != 11 or before['nnp'] != 1
            or before['seccomp'] != 2 or set(before['caps'].values()) != {0xdb}
            or before['label'] != 'mano-package-worker (enforce)'):
        raise PermissionError('Exact bounded native parent required for delegation')
    result = json.loads(capture(), object_pairs_hook=unique_object)
    validate(result, uid=uid, gid=gid, groups=groups, namespaces=before['namespaces'])
    if state() != before:
        raise PermissionError('Native parent state changed during delegation')
    return result


def main():
    if sys.argv[1:] != ['--verify-delegated']:
        raise ValueError('Fixed delegated-identity verification mode required')
    print(json.dumps(verify_own_drop(), sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    main()
