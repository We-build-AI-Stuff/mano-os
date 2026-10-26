"""Disposable CI feasibility only: real package/cache work in an unpublished clone.

This is not the production worker, a PAM authority path, a publication mechanism,
or an adversarial confinement proof. It never installs into the live package DB.
"""

import contextlib
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

from probe_package_plans import guard

from mano_broker.package_catalog import load
from mano_broker.package_solver import fingerprint, prepare_apt_root
from mano_runtime import recovery
from mano_runtime.package_apply import NoRedirect, archive_url
from mano_runtime.package_candidate import compare_payload
from mano_runtime.package_candidate_policy import validate_payloads
from mano_runtime.package_container import bind as bind_container
from mano_runtime.package_postconditions import MAX_STATUS, database
from mano_runtime.package_tree import delta as tree_delta
from mano_runtime.package_tree_worker import REQUIRED_CAPS as TREE_CAPS

BASE = Path('/.snapshots/.mano-staged-package-ci')
CANARY = Path('/usr/share/.mano-staged-ci-control')
FIXTURE_LIBRARY = Path('/usr/local/lib/libmano-stage-fixture.so.1.0')
ENV = {'PATH': '/usr/sbin:/usr/bin:/bin', 'LANG': 'C.UTF-8'}
CAPS = '-all,+chown,+dac_override,+fowner,+fsetid,+setuid,+setgid'
PROGRAM = r'''
import ctypes,hashlib,json,os,shutil,subprocess,sys
from pathlib import Path
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines())
caps={k:int(status[k].strip(),16) for k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')}
assert all(v==0xdb for v in caps.values()),caps
secure=ctypes.CDLL(None,use_errno=True).prctl(27,0,0,0,0)
assert secure==43 and status['NoNewPrivs'].strip()=='1',(secure,status['NoNewPrivs'])
assert os.getpid()==2
namespaces={k:os.readlink('/proc/self/ns/'+k) for k in ('mnt','pid','net','ipc','uts','cgroup')}
body=json.loads(sys.stdin.buffer.read(32769));assert set(body)=={'archives'}
assert 1<=len(body['archives'])<=8
assert all('/' not in p and p.endswith('.deb') for p in body['archives'])
env={'PATH':'/usr/sbin:/usr/bin:/bin','LANG':'C.UTF-8','DEBIAN_FRONTEND':'noninteractive'}
result=subprocess.run(['/usr/bin/dpkg','--force-confold','--install',
 *['/run/archives/'+p for p in body['archives']]],env=env,capture_output=True,timeout=30)
assert result.returncode==0,(result.returncode,result.stderr[-2048:])
Path('/usr/share/.mano-staged-ci-control').write_bytes(b'candidate-only\n')
shutil.copyfile('/run/stage-fixture.so','/usr/local/lib/libmano-stage-fixture.so.1.0')
cache=subprocess.run(['/usr/sbin/ldconfig'],env=env,capture_output=True,timeout=10)
assert cache.returncode==0,(cache.returncode,cache.stderr[-2048:])
print(json.dumps(dict(capabilities=caps,securebits=secure,no_new_privileges=True,
 namespaces=namespaces,pid=os.getpid(),
 dpkg_returncode=result.returncode,ldconfig_returncode=cache.returncode,
 dpkg_output_sha256=hashlib.sha256(result.stdout+result.stderr).hexdigest(),
 production_guard_used=False,production_pam_used=False)))
'''


def run(argv, *, input=None, timeout=45):
    value = subprocess.run(argv, input=input, env=ENV, cwd='/', capture_output=True,
                           timeout=timeout, check=False)
    if len(value.stdout) > 32 * 1024**2 or len(value.stderr) > 65536:
        raise ValueError('Staged experiment output budget')
    if value.returncode:
        # This fixed CI workload has no user plan, credentials or model output.
        print(json.dumps(dict(event='staging-ci-command-failed', program=Path(argv[0]).name,
                              return_code=value.returncode,
                              stderr_tail=value.stderr[-4096:].decode(errors='replace'),
                              stdout_tail=value.stdout[-1024:].decode(errors='replace'))),
              file=sys.stderr, flush=True)
        value.check_returncode()
    return value.stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def live_inputs():
    paths = {
        Path('/var/lib/dpkg/status'), Path('/etc/ld.so.cache'),
        Path('/etc/ld.so.conf'), Path('/var/lib/apt/extended_states'), CANARY}
    inventory = json.loads(recovery.read(
        Path('/opt/mano-lab/evidence/package-elf-inventory.json'), 16 * 1024**2))
    if not 1 <= len(inventory['files']) <= 512:
        raise ValueError('Bounded live ELF observation list required')
    for name in inventory['files']:
        if not name.startswith(('/usr/', '/lib/', '/lib64/')):
            raise ValueError('Expected system ELF observation path')
        paths.add(Path(name))
    return {str(path): sha(recovery.read(path.resolve(strict=True), 64 * 1024**2))
            for path in sorted(paths)}


def candidate_checks(name, architecture, version, digest, size, origins):
    """Keep source admission explicit; public metadata is diagnostic, not consent."""
    return dict(
        name=isinstance(name, str) and bool(re.fullmatch('[a-z0-9][a-z0-9+.-]{1,63}', name)),
        architecture=architecture in {'amd64', 'all'},
        version=isinstance(version, str) and bool(re.fullmatch(
            r'[A-Za-z0-9.+:~_-]{1,256}', version)),
        sha256=isinstance(digest, str) and bool(re.fullmatch('[a-f0-9]{64}', digest)),
        size=type(size) is int and 0 < size <= 10 * 1024**2,
        trusted_origin=any(row['trusted'] is True and row['site'] in {
            'deb.debian.org', 'security.debian.org'} for row in origins))


def candidate_admission(item):
    version = item.candidate
    name, digest = item.shortname, version.record.get('SHA256')
    origins = [dict(site=origin.site, trusted=origin.trusted) for origin in version.origins]
    checks = candidate_checks(name, version.architecture, version.version,
                              digest, version.size, origins)
    checks['record_identity'] = (version.record.get('Package') == name and
                                 version.record.get('Version') == version.version and
                                 version.record.get('Architecture') == version.architecture)
    return name, version, digest, origins, checks


@contextlib.contextmanager
def candidate_cache():
    """Use the verified catalog's canonical sources, never cloud mirror config."""
    catalog, manifest = load()
    fingerprint(manifest, catalog=catalog)
    import apt_pkg

    with tempfile.TemporaryDirectory(prefix='apt-', dir=BASE) as temporary:
        root = Path(temporary)
        prepare_apt_root(root, catalog=catalog)
        apt_pkg.config.set('Dir', str(root))
        apt_pkg.config.set('Dir::Etc', str(root / 'etc/apt'))
        apt_pkg.init_config()
        import apt
        import apt.progress.base

        for key, value in {
            'APT::Architecture': 'amd64', 'APT::Architectures::': 'amd64',
            'APT::Install-Recommends': 'false', 'APT::Install-Suggests': 'false',
        }.items():
            apt_pkg.config.set(key, value)
        cache = apt.Cache(progress=apt.progress.base.OpProgress(), rootdir=str(root), memonly=True)
        try:
            if cache.broken_count or cache.dpkg_journal_dirty:
                raise ValueError('Settled catalog package state required')
            yield cache
            # Recheck signed input custody and live state after acquisition.
            fingerprint(manifest, catalog=catalog)
            load(manifest['catalog_id'])
        finally:
            cache.close()


def acquire():
    with candidate_cache() as cache:
        return acquire_from(cache)


def acquire_from(cache):
    if cache['sl'].is_installed:
        raise ValueError('Experiment needs an uninstalled fixed sl package')
    cache['sl'].mark_install(auto_fix=True, auto_inst=True, from_user=True)
    changes = sorted(cache.get_changes(), key=lambda item: item.name)
    if not 1 <= len(changes) <= 8 or any(item.is_installed or item.marked_delete
                                       for item in changes):
        raise ValueError('Only a small new-package dependency closure is allowed')
    records = []
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    for item in changes:
        name, version, digest, origins, checks = candidate_admission(item)
        if not all(checks.values()):
            # Fixed CI package metadata only; no URI credentials, keys or plans.
            print(json.dumps(dict(event='staging-ci-candidate-denied',
                                  name=name, apt_name=item.name, architecture=version.architecture,
                                  version=version.version, bytes=version.size,
                                  sha256=(digest[:128] if isinstance(digest, str) else None),
                                  record_identity={key: version.record.get(key) for key in
                                                   ('Package', 'Version', 'Architecture')},
                                  origins=origins,
                                  failed_fields=[key for key, ok in checks.items() if not ok])),
                  file=sys.stderr, flush=True)
            raise ValueError('Bounded authenticated Debian candidate required')
        url = archive_url(version.uri)
        with opener.open(url, timeout=20) as response:
            data = response.read(version.size + 1)
        if len(data) != version.size or sha(data) != digest:
            raise ValueError('Signed-index archive identity mismatch')
        container = bind_container(data, expected_sha256=digest, expected_bytes=version.size)
        path = BASE / 'archives' / (name + '.deb')
        with path.open('xb') as stream:
            stream.write(data)
        path.chmod(0o400)
        records.append(dict(name=name, architecture=version.architecture,
                            version=version.version, sha256=digest, bytes=len(data),
                            filename=path.name, url=url, container=container))
    return records


def candidate_read(candidate, relative, maximum):
    if Path(relative).is_absolute() or '..' in Path(relative).parts:
        raise ValueError('Fixed relative candidate path required')
    path = candidate / relative
    if path.resolve(strict=True) != path:
        raise ValueError('Candidate alias escapes fixed observation path')
    return recovery.read(path, maximum)


def credential_mask():
    """Create a fresh private empty inode; never depend on a removable fixture."""
    path = BASE / 'empty-credential'
    with path.open('xb'):
        pass
    path.chmod(0o400)
    return path


def clone_pair():
    """Preserve an immutable baseline before making the writable candidate."""
    baseline, candidate = BASE / 'baseline', BASE / 'candidate'
    live = recovery.subvolume(Path('/'))
    run(['/usr/bin/btrfs', 'subvolume', 'snapshot', '-r', '/', str(baseline)])
    source = recovery.subvolume(baseline)
    readonly = run(['/usr/bin/btrfs', 'property', 'get', str(baseline), 'ro'])
    if (source['uuid'] == live['uuid'] or source['parent_uuid'] != live['uuid']
            or source['subvolume_id'] == live['subvolume_id'] or readonly.strip() != b'ro=true'):
        raise ValueError('Distinct read-only baseline required')
    run(['/usr/bin/btrfs', 'subvolume', 'snapshot', str(baseline), str(candidate)])
    stage = recovery.subvolume(candidate)
    writable = run(['/usr/bin/btrfs', 'property', 'get', str(candidate), 'ro'])
    if (stage['parent_uuid'] != source['uuid']
            or stage['uuid'] in {source['uuid'], live['uuid']}
            or stage['subvolume_id'] in {source['subvolume_id'], live['subvolume_id']}
            or writable.strip() != b'ro=false'):
        raise ValueError('Distinct writable COW clone required')
    return live, source, stage, readonly


def payload_observation(record):
    """Unprivileged bounded parser; sealed archive input, no extraction."""
    program = ('import sys;sys.path.insert(0,"/opt/mano-lab/src");'
               'from mano_runtime.package_payload_worker import main;main()')
    command = ['/usr/bin/systemd-run', '--quiet', '--pipe', '--wait', '--collect',
               '--unit=mano-payload-observer-ci.service', '--slice=mano-package.slice',
               '--property=User=nobody', '--property=NoNewPrivileges=yes',
               '--property=CapabilityBoundingSet=', '--property=MemoryMax=536870912',
               '--property=TasksMax=16', '--property=RuntimeMaxSec=25',
               '--property=KillMode=control-group', '--property=Restart=no',
               '--property=LimitCORE=0', '--property=LimitNOFILE=64',
               '--property=ProtectSystem=strict', '--property=ProtectHome=yes',
               '--property=PrivateTmp=yes', '--property=PrivateDevices=yes',
               '--property=PrivateNetwork=yes', '--setenv=MANO_DISPOSABLE_CI=1',
               '/usr/bin/python3', '-I', '-B', '-c', program,
               record['sha256'], str(record['bytes'])]
    raw = (BASE / 'archives' / record['filename']).read_bytes()
    value = json.loads(run(command, input=raw, timeout=35))
    if (type(value['uid']) is not int or value['uid'] <= 0
            or set(value['capabilities']) != {'CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb'}
            or any(type(cap) is not int or cap != 0 for cap in value['capabilities'].values())
            or value['no_new_privileges'] is not True
            or value['sealed_archive_observed'] is not True
            or value['container'] != record['container']
            or value['address_space_limit_bytes'] != 384 * 1024**2
            or value['cpu_limit_seconds'] != 12):
        raise ValueError('Bounded unprivileged archive observation required')
    for key in ('production_guard_used', 'production_pam_used',
                'archive_signature_verified', 'publication_authorized'):
        if value[key] is not False:
            raise ValueError('CI observer cannot grant authority')
    return value


def tree_observation(role, *, admission_only=False):
    if role not in {'baseline', 'candidate'}:
        raise ValueError('Fixed snapshot role required')
    program = ('import sys;sys.path.insert(0,"/opt/mano-lab/src");'
               'from mano_runtime.package_tree_worker import main;main()')
    command = ['/usr/bin/systemd-run', '--quiet', '--pipe', '--wait', '--collect',
               '--unit=mano-tree-' + role + '-ci.service', '--slice=mano-package.slice',
               '--property=User=root', '--property=NoNewPrivileges=yes',
               '--property=CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_ADMIN',
               '--property=AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_SYS_ADMIN',
               '--property=MemoryMax=536870912', '--property=TasksMax=8',
               '--property=RuntimeMaxSec=90', '--property=KillMode=control-group',
               '--property=Restart=no', '--property=LimitCORE=0', '--property=LimitNOFILE=256',
               '--property=ProtectSystem=strict', '--property=ProtectHome=yes',
               '--property=PrivateTmp=yes', '--property=PrivateDevices=yes',
               '--property=PrivateNetwork=yes', '--setenv=MANO_DISPOSABLE_CI=1',
               '/usr/bin/python3', '-I', '-B', '-c', program, role]
    if admission_only:
        command.append('--admission-only')
    value = json.loads(run(command, timeout=100))
    expected_group = '/mano.slice/mano-package.slice/mano-tree-' + role + '-ci.service'
    if (type(value['uid']) is not int or value['uid'] != 0 or value['observed_role'] != role
            or value['no_new_privileges'] is not True
            or value['trusted_controller_collector'] is not True
            or value['admission_only'] is not admission_only
            or value['address_space_limit_bytes'] != 384 * 1024**2
            or value['cpu_limit_seconds'] != 60
            or value['cgroup_path'] != expected_group
            or value['memory_max_bytes'] != 512 * 1024**2 or value['pids_max'] != 8
            or any(type(cap) is not int for cap in value['capabilities'].values())
            or value['capabilities'] != dict.fromkeys(
                ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb'), TREE_CAPS)):
        raise ValueError('Fixed trusted collector context required')
    for key in ('full_root_verified', 'immutable_root_verified',
                'production_guard_used', 'adversarial_confinement_verified',
                'candidate_filesystem_verified', 'publication_authorized'):
        if value[key] is not False:
            raise ValueError('Tree collector cannot grant authority')
    return value


def main():
    if sys.platform != 'linux':
        raise PermissionError('Disposable Debian CI only')
    guard()
    recovery.root_guard()
    layout = recovery.layout()
    if layout['free_bytes'] < 2 * 1024**3:
        raise ValueError('Staged experiment needs the existing 2GiB reserve')
    if FIXTURE_LIBRARY.exists() or FIXTURE_LIBRARY.is_symlink():
        raise ValueError('Synthetic fixture library must be absent from live root')
    BASE.mkdir(mode=0o700)  # Refuse reuse; retain all experiment state in this VM.
    (BASE / 'archives').mkdir(mode=0o700)
    empty = credential_mask()
    with CANARY.open('xb') as stream:
        stream.write(b'live-host-only\n')
    CANARY.chmod(0o600)
    before = live_inputs()
    before_status = recovery.read(Path('/var/lib/dpkg/status'), MAX_STATUS)
    records = acquire()
    observations = {record['name']: payload_observation(record) for record in records}
    (BASE / 'probe.py').write_text(PROGRAM)
    (BASE / 'probe.py').chmod(0o400)
    (BASE / 'fixture.c').write_text('int mano_stage_fixture(void) { return 42; }\n')
    run(['/usr/bin/cc', '-shared', '-fPIC', '-Wl,-soname,libmano-stage-fixture.so.1',
         '-o', str(BASE / 'fixture.so'), str(BASE / 'fixture.c')])
    candidate = BASE / 'candidate'
    host_namespaces = {kind: os.readlink('/proc/self/ns/' + kind)
                       for kind in ('mnt', 'pid', 'net', 'ipc', 'uts', 'cgroup')}
    with recovery.locked():
        if live_inputs() != before:
            raise ValueError('Live baseline changed before staged snapshot')
        live_source, source, stage, baseline_property = clone_pair()
        baseline = BASE / 'baseline'
        baseline_status = candidate_read(baseline, 'var/lib/dpkg/status', MAX_STATUS)
        if baseline_status != before_status:
            raise ValueError('Read-only baseline package state changed')
        baseline_tree = tree_observation('baseline')
        argv = ['/usr/bin/bwrap', '--die-with-parent', '--new-session', '--unshare-pid',
                '--unshare-net', '--unshare-ipc', '--unshare-uts', '--unshare-cgroup',
                '--bind', str(candidate), '/', '--proc', '/proc', '--dev', '/dev',
                '--ro-bind', '/proc/sys', '/proc/sys',
                '--ro-bind', '/proc/sysrq-trigger', '/proc/sysrq-trigger',
                '--tmpfs', '/run', '--tmpfs', '/tmp', '--tmpfs', '/home', '--tmpfs', '/root',
                '--tmpfs', '/opt', '--tmpfs', '/mnt', '--tmpfs', '/media', '--tmpfs', '/srv',
                '--tmpfs', '/var/lib/mano-broker', '--tmpfs', '/var/lib/mano-provider',
                '--tmpfs', '/.snapshots', '--ro-bind', str(BASE / 'archives'), '/run/archives',
                '--ro-bind', str(BASE / 'probe.py'), '/run/probe.py',
                '--ro-bind', str(BASE / 'fixture.so'), '/run/stage-fixture.so',
                '--ro-bind', str(empty), '/etc/shadow',
                '--ro-bind', str(empty), '/etc/gshadow',
                '--clearenv', '--setenv', 'PATH', ENV['PATH'], '--setenv', 'LANG', ENV['LANG'],
                '--setenv', 'PYTHONDONTWRITEBYTECODE', '1', '--chdir', '/',
                '/usr/bin/setpriv', '--no-new-privs', '--bounding-set=' + CAPS,
                '--inh-caps=' + CAPS, '--ambient-caps=' + CAPS,
                '--securebits=+noroot,+noroot_locked,+no_setuid_fixup_locked,+keep_caps_locked',
                '/usr/bin/python3', '-P', '/run/probe.py']
        unit = ['/usr/bin/systemd-run', '--quiet', '--pipe', '--wait', '--collect',
                '--unit=mano-staged-package-ci.service', '--slice=mano-package.slice',
                '--property=MemoryMax=536870912', '--property=TasksMax=64',
                '--property=RuntimeMaxSec=45', '--property=KillMode=control-group',
                '--property=Restart=no', '--property=LimitCORE=0', '--property=LimitNOFILE=128']
        proof = json.loads(run(unit + argv, input=json.dumps(
            dict(archives=[r['filename'] for r in records])).encode(), timeout=60))
        if (set(proof['namespaces']) != set(host_namespaces) or
                any(proof['namespaces'][kind] == value for kind, value in host_namespaces.items())):
            raise ValueError('Staged worker namespaces are not private')
        group = Path('/sys/fs/cgroup/mano.slice/mano-package.slice/mano-staged-package-ci.service')
        deadline = time.monotonic() + 5
        while True:
            try:
                events = dict(line.split() for line in
                              (group / 'cgroup.events').read_text().splitlines())
            except FileNotFoundError:
                break  # The collected unit's cgroup has already been removed.
            if events.get('populated') == '0':
                break
            if time.monotonic() >= deadline:
                raise ValueError('Staged child domain did not drain')
            time.sleep(.05)
        if live_inputs() != before:
            raise ValueError('Live package or loader inputs changed in staged experiment')
        if FIXTURE_LIBRARY.exists() or FIXTURE_LIBRARY.is_symlink():
            raise ValueError('Synthetic fixture library appeared in live root')
        if (run(['/usr/bin/btrfs', 'property', 'get', str(baseline), 'ro']) != baseline_property
                or candidate_read(baseline, 'var/lib/dpkg/status', MAX_STATUS) != baseline_status):
            raise ValueError('Baseline custody changed during staged experiment')
        candidate_tree = tree_observation('candidate')
        baseline_after = tree_observation('baseline')
        if (baseline_after['manifest_sha256'] != baseline_tree['manifest_sha256']
                or baseline_after['entries'] != baseline_tree['entries']):
            raise ValueError('Baseline tree changed during staged experiment')
        changes = tree_delta(baseline_tree, candidate_tree)
        payload_policy = validate_payloads(baseline_tree, candidate_tree,
                                          {name: value['payload']
                                           for name, value in observations.items()})
        after = candidate_read(candidate, 'var/lib/dpkg/status', MAX_STATUS)
        old, new = database(before_status), database(after)
        approved = {(r['name'], r['architecture']) for r in records}
        if any(new.get(key) != old.get(key) for key in (old.keys() | new.keys()) - approved):
            raise ValueError('Candidate database changed outside fixed dependency closure')
        for record in records:
            if new.get((record['name'], record['architecture'])) != (
                    'install ok installed', record['version']):
                raise ValueError('Candidate package did not settle')
            if sha((BASE / 'archives' / record['filename']).read_bytes()) != record['sha256']:
                raise ValueError('Read-only archive custody changed')
        candidate_fd = os.open(candidate, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for record in records:
                record['payload_comparison'] = compare_payload(
                    candidate_fd, observations[record['name']]['payload'])
        finally:
            os.close(candidate_fd)
        if candidate_read(candidate, str(CANARY).lstrip('/'), 4096) != b'candidate-only\n':
            raise ValueError('Candidate mutation missing')
        tar_data = run(['/usr/bin/dpkg-deb', '--fsys-tarfile', str(BASE / 'archives/sl.deb')])
        with tarfile.open(fileobj=io.BytesIO(tar_data)) as archive:
            member = archive.getmember('./usr/games/sl')
            if not member.isfile() or not 0 < member.size < 1024**2:
                raise ValueError('Expected fixed signed sl payload')
            payload = archive.extractfile(member).read()
        if candidate_read(candidate, 'usr/games/sl', 1024**2) != payload:
            raise ValueError('Candidate executable differs from signed payload')
        cache = candidate_read(candidate, 'etc/ld.so.cache', 4 * 1024**2)
        if candidate_read(candidate, str(FIXTURE_LIBRARY).lstrip('/'), 1024**2) != (
                BASE / 'fixture.so').read_bytes():
            raise ValueError('Candidate synthetic library differs from compiled fixture')
        listing = run(['/usr/sbin/ldconfig', '-p', '-C', str(candidate / 'etc/ld.so.cache')])
        if sha(cache) == before['/etc/ld.so.cache'] or b'libmano-stage-fixture.so.1' not in listing:
            raise ValueError('Private loader cache did not add the synthetic library')
    revision = json.loads(Path('/opt/mano-lab/source-info.json').read_text())['revision']
    artifacts = {
        'staged-before-status': before_status, 'staged-after-status': after,
        'staged-installed-sl': payload, 'staged-loader-cache-after': cache,
        'staged-loader-cache-before': recovery.read(Path('/etc/ld.so.cache'), 4 * 1024**2),
        'staged-loader-cache-listing': listing,
        'staged-fixture.c': (BASE / 'fixture.c').read_bytes(),
        'staged-fixture.so': (BASE / 'fixture.so').read_bytes(),
        'staged-baseline-property': baseline_property,
        'staged-baseline-status': baseline_status,
        'staged-tree-baseline.json': json.dumps(baseline_tree, sort_keys=True).encode(),
        'staged-tree-baseline-after.json': json.dumps(baseline_after, sort_keys=True).encode(),
        'staged-tree-candidate.json': json.dumps(candidate_tree, sort_keys=True).encode(),
        'staged-tree-changes.json': json.dumps(changes, sort_keys=True).encode(),
    }
    for record in records:
        record['artifact'] = 'staged-archive-' + record['filename']
        artifacts[record['artifact']] = (BASE / 'archives' / record['filename']).read_bytes()
        record['payload_observation_artifact'] = 'staged-payload-' + record['name'] + '.json'
        artifacts[record['payload_observation_artifact']] = json.dumps(
            observations[record['name']], sort_keys=True, allow_nan=False).encode()
    for name, data in artifacts.items():
        with (Path('/opt/mano-lab/evidence') / name).open('xb') as stream:
            stream.write(data)
    return dict(schema_version='1.0', source_revision=revision,
                scope='CI-only btrfs package/cache staging feasibility; no publication',
                source=source, candidate=stage, archives=records, worker=proof,
                live_source=live_source, source_read_only=True,
                tree_observation_reported=True, tree_changes_authorized=False,
                payload_closure_validation=payload_policy,
                archive_container_identity_bound=True,
                candidate_inventoried_payload_paths_match=True,
                host_namespaces=host_namespaces,
                live_input_sha256=before, live_inputs_unchanged=True,
                candidate_database_transition_verified=True,
                candidate_signed_sl_payload_sha256=sha(payload),
                candidate_canary_changed_live_canary_unchanged=True,
                candidate_loader_cache_sha256=sha(cache),
                candidate_loader_cache_fixture_entry_verified=True,
                fixture_library_absent_from_live_root=True,
                staged_child_domain_empty=True,
                artifact_sha256={name: sha(data) for name, data in artifacts.items()},
                production_guard_used=False, production_pam_used=False,
                adversarial_confinement_verified=False, publication_implemented=False,
                publication_authorized=False, candidate_retained=True,
                peak_space_bytes=None, complete_trusted_runtime_closure_verified=False)


if __name__ == '__main__':
    if sys.argv[1:] == ['--check-tree-admission']:
        if sys.platform != 'linux':
            raise PermissionError('Disposable Debian CI only')
        guard()
        recovery.root_guard()
        print(json.dumps(tree_observation('baseline', admission_only=True), sort_keys=True))
    elif sys.argv[1:]:
        raise ValueError('Fixed staging or admission probe only')
    else:
        print(json.dumps(main(), sort_keys=True))
