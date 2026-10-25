"""Test the real profile's path names on private substitute directories in CI.

The real interpreter and libraries are mounted read-only. Every write target is
a synthetic inode, including the python3 alias and a stand-in future interpreter.
This is not the package worker's complete capability/seccomp context.
"""

import hashlib
import json
import os
import subprocess
from pathlib import Path

from probe_package_plans import guard

BASE = Path('/run/mano-lab-policy-names')
PROGRAM = r'''
import errno,json,os,stat
from pathlib import Path
assert Path('/proc/self/attr/current').read_text().strip()=='mano-package-worker (enforce)'
assert not os.statvfs('/usr/bin').f_flag & os.ST_RDONLY
assert not os.statvfs('/usr/lib').f_flag & os.ST_RDONLY
denials={}
def denied(name,operation):
 try:operation()
 except OSError as e:
  assert e.errno in {errno.EACCES,errno.EPERM},(name,e.errno)
  denials[name]=e.errno
 else:raise AssertionError('Real profile name rule failed: '+name)
p=Path('/usr/bin/ordinary.fixture')
p.write_text('ordinary');p.rename('/usr/bin/ordinary.renamed')
p=Path('/usr/bin/ordinary.renamed');p.chmod(0o600)
os.link(p,'/usr/bin/ordinary.link')
assert Path('/usr/bin/ordinary.link').read_text()=='ordinary'
assert stat.S_IMODE(p.stat().st_mode)==0o600
denied('interpreter_alias_unlink',lambda:Path('/usr/bin/python3').unlink())
Path('/usr/bin/ordinary.replacement').symlink_to('python3.999')
denied('interpreter_alias_replace',lambda:os.replace('/usr/bin/ordinary.replacement',
                                                   '/usr/bin/python3'))
denied('future_interpreter_write',lambda:Path('/usr/bin/python3.999').write_text('changed'))
denied('future_interpreter_mode',lambda:Path('/usr/bin/python3.999').chmod(0o777))
denied('hardlink_write_alias',lambda:os.link('/usr/bin/python3.999','/usr/bin/ordinary.alias'))
denied('absent_zip_entry',lambda:Path('/usr/lib/python313.zip').write_text('changed'))
denied('clear_execution_profile',lambda:Path('/proc/self/attr/current').write_text(
                                            'changeprofile unconfined'))
print(json.dumps(dict(denials=denials,ordinary_sibling_operations=True,
                     enforced_label='mano-package-worker (enforce)')))
'''


def run():
    guard()
    from mano_runtime.package_path_policy import POLICY_SHA256

    BASE.mkdir(mode=0o700)
    binary = BASE / 'bin'
    library = BASE / 'lib'
    binary.mkdir(mode=0o700)
    library.mkdir(mode=0o700)
    payload = b'Synthetic future interpreter; never executed\n'
    (binary / 'python3.999').write_bytes(payload)
    (binary / 'python3').symlink_to('python3.13')
    original_mode = (binary / 'python3.999').stat().st_mode & 0o7777
    argv = ['/usr/bin/bwrap', '--die-with-parent', '--new-session', '--unshare-pid',
            '--unshare-net', '--unshare-ipc', '--unshare-uts', '--unshare-cgroup',
            '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/run', '--tmpfs', '/tmp', '--tmpfs', '/root', '--tmpfs', '/home',
            '--bind', str(binary), '/usr/bin', '--bind', str(library), '/usr/lib']
    for path in ('/usr/bin/python3.13', '/usr/bin/aa-exec', '/usr/lib/python3.13',
                 '/usr/lib/python3', '/usr/lib/x86_64-linux-gnu'):
        argv += ['--ro-bind', path, path]
    argv += ['--clearenv', '--setenv', 'PATH', '/usr/bin:/bin',
             '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
             '--chdir', '/', '/usr/bin/aa-exec', '-p', 'mano-package-worker', '--',
             '/usr/bin/python3.13', '-c', PROGRAM]
    child = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=15)
    assert child.returncode == 0, (child.stdout[-4096:], child.stderr[-4096:])
    proof = json.loads(child.stdout)
    assert (binary / 'python3.999').read_bytes() == payload
    assert (binary / 'python3.999').stat().st_mode & 0o7777 == original_mode
    assert os.readlink(binary / 'python3') == 'python3.13'
    assert not (library / 'python313.zip').exists()
    return dict(scope='real package profile name rules on private CI substitute inodes',
                policy_sha256=POLICY_SHA256, proof=proof,
                synthetic_payload_sha256=hashlib.sha256(payload).hexdigest(),
                synthetic_payload_mode=original_mode,
                host_interpreter_write_attempted=False,
                production_worker_full_context_verified=False,
                complete_trusted_runtime_closure_verified=False)
