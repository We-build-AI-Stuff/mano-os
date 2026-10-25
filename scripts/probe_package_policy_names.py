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
HELPERS = (
    '/usr/bin/btrfs', '/usr/bin/bwrap', '/usr/bin/dpkg-deb', '/usr/bin/dpkg-query',
    '/usr/bin/findmnt', '/usr/bin/gpgv', '/usr/bin/mount', '/usr/bin/passwd',
    '/usr/bin/snapper', '/usr/bin/systemctl', '/usr/bin/systemd-sysusers',
    '/usr/bin/systemd-tmpfiles', '/usr/bin/umount', '/usr/sbin/runuser',
    '/usr/sbin/usermod', '/usr/sbin/apparmor_parser', '/usr/lib/apt/apt-helper',
)
ELF_LEAVES = (
    'ld-linux-x86-64.so.999',
    'libacl.so.999',
    'libapt-pkg.so.999',
    'libapt-private.so.999',
    'libattr.so.999',
    'libaudit.so.999',
    'libblkid.so.999',
    'libboost_thread.so.999',
    'libbsd.so.999',
    'libbtrfs.so.999',
    'libbz2.so.999',
    'libc.so.999',
    'libcap-ng.so.999',
    'libcap.so.999',
    'libcrypt.so.999',
    'libcrypto.so.999',
    'libdb-5.3.so.999',
    'libdbus-1.so.999',
    'libexpat.so.999',
    'libffi.so.999',
    'libgcc_s.so.999',
    'libgcrypt.so.999',
    'libgpg-error.so.999',
    'libjson-c.so.999',
    'liblz4.so.999',
    'liblzma.so.999',
    'liblzo2.so.999',
    'libm.so.999',
    'libmd.so.999',
    'libmount.so.999',
    'libncursesw.so.999',
    'libpam.so.999',
    'libpam_misc.so.999',
    'libpanelw.so.999',
    'libpcre2-8.so.999',
    'libreadline.so.999',
    'libselinux.so.999',
    'libsemanage.so.999',
    'libsepol.so.999',
    'libsmartcols.so.999',
    'libsnapper.so.999',
    'libsqlite3.so.999',
    'libssl.so.999',
    'libstdc++.so.999',
    'libsystemd.so.999',
    'libtinfo.so.999',
    'libudev.so.999',
    'libuuid.so.999',
    'libxml2.so.999',
    'libxxhash.so.999',
    'libz.so.999',
    'libzstd.so.999',
    'libsystemd-shared-999.so.999',
)
PROGRAM = r'''
import errno,json,os,stat,sys
from pathlib import Path
assert Path('/proc/self/attr/current').read_text().strip()=='mano-package-worker (enforce)'
assert not os.statvfs('/usr/bin').f_flag & os.ST_RDONLY
assert not os.statvfs('/usr/lib').f_flag & os.ST_RDONLY
assert not os.statvfs('/etc').f_flag & os.ST_RDONLY
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
denied('archive_keyring_write',lambda:Path(
 '/usr/share/keyrings/debian-archive-keyring.pgp').write_text('changed'))
assert not Path('/etc/ld.so.preload').exists()
ordinary_config=Path('/etc/ordinary.fixture')
ordinary_config.write_text('ordinary')
denied('absent_preload_write',lambda:Path('/etc/ld.so.preload').write_text('changed'))
denied('absent_preload_symlink',lambda:os.symlink('/etc/ordinary.fixture','/etc/ld.so.preload'))
denied('absent_preload_replace',lambda:os.replace(ordinary_config,'/etc/ld.so.preload'))
assert ordinary_config.read_text()=='ordinary'
helper_denials={}
for name in json.loads(sys.argv[1]):
 try:Path(name).write_text('changed')
 except OSError as e:
  assert e.errno in {errno.EACCES,errno.EPERM},(name,e.errno)
  helper_denials[name]=e.errno
 else:raise AssertionError('Privileged helper name was writable: '+name)
elf_denials={}
for name in json.loads(sys.argv[2]):
 try:Path(name).write_text('changed')
 except OSError as e:
  assert e.errno in {errno.EACCES,errno.EPERM},(name,e.errno)
  elf_denials[name]=e.errno
 else:raise AssertionError('Trusted ELF name was writable: '+name)
denied('elf_alias_unlink',lambda:Path('/usr/lib/libc.so.999').unlink())
denied('elf_mode_change',lambda:Path('/usr/lib/libc.so.999').chmod(0o777))
denied('elf_hardlink_alias',lambda:os.link('/usr/lib/libc.so.999',
                                        '/usr/lib/ordinary.elf-alias'))
Path('/usr/lib/ordinary.elf-replacement').write_text('ordinary')
denied('elf_alias_replace',lambda:os.replace('/usr/lib/ordinary.elf-replacement',
                                          '/usr/lib/libc.so.999'))
print(json.dumps(dict(denials=denials,ordinary_sibling_operations=True,
                     helper_denials=helper_denials,
                     elf_denials=elf_denials,
                     enforced_label='mano-package-worker (enforce)')))
'''


def run():
    guard()
    from mano_runtime.package_path_policy import POLICY_SHA256

    BASE.mkdir(mode=0o700)
    binary = BASE / 'bin'
    system_binary = BASE / 'sbin'
    library = BASE / 'lib'
    keyrings = BASE / 'keyrings'
    configuration = BASE / 'etc'
    binary.mkdir(mode=0o700)
    system_binary.mkdir(mode=0o700)
    library.mkdir(mode=0o700)
    keyrings.mkdir(mode=0o700)
    configuration.mkdir(mode=0o700)
    (library / 'apt').mkdir(mode=0o700)
    elf_directory = library / 'mano-elf-fixture'
    elf_directory.mkdir(mode=0o700)
    elf_payload = b'Synthetic trusted ELF name; never executed\n'
    elf_standins = [elf_directory / leaf for leaf in ELF_LEAVES]
    # Include the directory root form as well as a nested search-directory name.
    elf_standins.append(library / 'libc.so.999')
    for path in elf_standins:
        path.write_bytes(elf_payload)
    elf_paths = ['/usr/lib/' + str(path.relative_to(library)) for path in elf_standins]
    elf_paths.append('/usr/lib/mano-elf-fixture/libc.so.absent')
    helper_payload = b'Synthetic privileged helper; never executed\n'
    standins = {}
    for name in HELPERS:
        relative = name.removeprefix('/usr/')
        standins[name] = BASE / relative
        standins[name].write_bytes(helper_payload)
    keyring_payload = b'CI-only synthetic archive trust input\n'
    (keyrings / 'debian-archive-keyring.pgp').write_bytes(keyring_payload)
    payload = b'Synthetic future interpreter; never executed\n'
    (binary / 'python3.999').write_bytes(payload)
    (binary / 'python3').symlink_to('python3.13')
    original_mode = (binary / 'python3.999').stat().st_mode & 0o7777
    argv = ['/usr/bin/bwrap', '--die-with-parent', '--new-session', '--unshare-pid',
            '--unshare-net', '--unshare-ipc', '--unshare-uts', '--unshare-cgroup',
            '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/run', '--tmpfs', '/tmp', '--tmpfs', '/root', '--tmpfs', '/home',
            '--bind', str(binary), '/usr/bin', '--bind', str(system_binary), '/usr/sbin',
            '--bind', str(library), '/usr/lib',
            '--bind', str(keyrings), '/usr/share/keyrings',
            '--bind', str(configuration), '/etc']
    for path in ('/usr/bin/python3.13', '/usr/bin/aa-exec', '/usr/lib/python3.13',
                 '/usr/lib/python3', '/usr/lib/x86_64-linux-gnu'):
        argv += ['--ro-bind', path, path]
    argv += ['--clearenv', '--setenv', 'PATH', '/usr/bin:/bin',
             '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
             '--chdir', '/', '/usr/bin/aa-exec', '-p', 'mano-package-worker', '--',
             '/usr/bin/python3.13', '-c', PROGRAM, json.dumps(HELPERS), json.dumps(elf_paths)]
    child = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=15)
    assert child.returncode == 0, (child.stdout[-4096:], child.stderr[-4096:])
    proof = json.loads(child.stdout)
    assert (binary / 'python3.999').read_bytes() == payload
    assert (binary / 'python3.999').stat().st_mode & 0o7777 == original_mode
    assert os.readlink(binary / 'python3') == 'python3.13'
    assert not (library / 'python313.zip').exists()
    assert all(path.read_bytes() == helper_payload for path in standins.values())
    assert (keyrings / 'debian-archive-keyring.pgp').read_bytes() == keyring_payload
    assert not (configuration / 'ld.so.preload').exists()
    assert all(path.read_bytes() == elf_payload for path in elf_standins)
    assert not (elf_directory / 'libc.so.absent').exists()
    return dict(scope='real package profile name rules on private CI substitute inodes',
                policy_sha256=POLICY_SHA256, proof=proof,
                synthetic_payload_sha256=hashlib.sha256(payload).hexdigest(),
                synthetic_payload_mode=original_mode,
                synthetic_helpers_sha256=hashlib.sha256(helper_payload).hexdigest(),
                synthetic_keyring_sha256=hashlib.sha256(keyring_payload).hexdigest(),
                synthetic_elf_names_sha256=hashlib.sha256(elf_payload).hexdigest(),
                host_interpreter_write_attempted=False,
                production_worker_full_context_verified=False,
                complete_trusted_runtime_closure_verified=False)
