"""Fixed source-byte capture in the disposable unprivileged cache sandbox."""
import base64
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

from probe_package_man_regeneration import sandbox, unit_command, validate_native_guard

from mano_runtime.package_man_source_bytes import prepare, validate_capture

FILES = {'staged-man-source-reader.py', 'staged-man-source-manifest.json',
         'staged-man-source-capture.txt'}


def source_sandbox(base, masks, empty, config_digest):
    command = sandbox(base, masks, empty, config_digest)
    if command[-6:] != ['/usr/bin/python3', '-I', '-B', '/run/man-regeneration.py',
                       config_digest, 'restricted']:
        raise ValueError('Fixed inherited sandbox setup required')
    command[-6:] = ['/run/man-cache-guard', '--source-bytes']
    position = command.index(str(base / 'regenerated-man-cache'))
    command[position] = str(base / 'man-source-cache')
    position = command.index('--clearenv')
    command[position:position] = [
        '--ro-bind', str(base / 'man-source-reader.py'), '/run/man-source-reader.py',
        '--ro-bind', str(base / 'man-source-paths.json'), '/run/man-source-paths.json']
    return command


def source_unit():
    command = unit_command()
    position = command.index('--unit=mano-man-regeneration-ci.service')
    command[position] = '--unit=mano-man-source-ci.service'
    return command


def fixture_identity(path):
    info = path.lstat()
    return (path.read_bytes(), info.st_dev, info.st_ino, info.st_mode,
            info.st_uid, info.st_gid, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def capture_sources(base, canonical_bundle, baseline, candidate, masks, empty, config_digest, run):
    if sys.platform != 'linux':
        raise PermissionError('Disposable Debian source acquisition only')
    from probe_package_plans import guard

    from mano_runtime import recovery

    guard()
    recovery.root_guard()
    if base != Path('/.snapshots/.mano-staged-package-ci'):
        raise ValueError('Fixed private source acquisition directory required')
    encoded = json.loads(canonical_bundle)
    inputs = {'var/cache/man/'+path: base64.b64decode(data, validate=True)
              for path, data in encoded.items()}
    packet = prepare(inputs, baseline, candidate)
    program = Path('/opt/mano-lab/src/mano_runtime/package_man_source_bytes.py').read_bytes()
    artifacts = {'staged-man-source-reader.py': program,
                 'staged-man-source-manifest.json': packet}
    for name, data in (('man-source-reader.py', program), ('man-source-paths.json', packet)):
        with (base / name).open('xb') as stream:
            stream.write(data)
        (base / name).chmod(0o444)
    evidence = Path('/opt/mano-lab/evidence')
    for name, data in artifacts.items():
        with (evidence / name).open('xb') as stream:
            stream.write(data)
    cache = base / 'man-source-cache'
    cache.mkdir(mode=0o700)
    run(['/usr/bin/mount', '-t', 'tmpfs', '-o',
         'size=16777216,nosuid,nodev,noexec,mode=0755,uid=6,gid=12',
         'mano-man-source-ci', str(cache)])
    run(['/usr/bin/mount', '--make-private', str(cache)])
    control = base / 'man-cache-control-file'
    original = fixture_identity(control)
    try:
        raw = run(source_unit() + source_sandbox(base, masks, empty, config_digest), timeout=80)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        # Preserve bounded partial bytes before propagating a failed launch.
        stdout = error.stdout or b''
        stderr = error.stderr or b''
        if type(stdout) is bytes and type(stderr) is bytes:
            with (evidence / 'staged-man-source-failed-stdout.txt').open('xb') as stream:
                stream.write(stdout[:32*1024**2])
            with (evidence / 'staged-man-source-failed-stderr.txt').open('xb') as stream:
                stream.write(stderr[:65536])
        raise
    artifacts['staged-man-source-capture.txt'] = raw
    with (evidence / 'staged-man-source-capture.txt').open('xb') as stream:
        stream.write(raw)
    group = Path('/sys/fs/cgroup/mano.slice/mano-package.slice/mano-man-source-ci.service')
    deadline = time.monotonic() + 5
    while True:
        try:
            events = dict(line.split() for line in
                          (group / 'cgroup.events').read_text().splitlines())
        except FileNotFoundError:
            break
        if events.get('populated') == '0':
            break
        if time.monotonic() >= deadline:
            raise ValueError('Manual source domain did not drain')
        time.sleep(.02)
    first, separator, body = raw.partition(b'\n')
    if not separator or len(first) > 4096:
        raise ValueError('Bounded native source-role guard header required')
    native = json.loads(first)
    validate_native_guard(native, role='source-bytes')
    report = validate_capture(packet, body)
    if fixture_identity(control) != original:
        raise ValueError('Source acquisition changed the public control fixture')
    report.update(guard=native, domain_drained=True, control_fixture_unchanged=True,
                  observed_manual_root_regular_files_captured=True,
                  capture_sha256=hashlib.sha256(raw).hexdigest(), capture_bytes=len(raw),
                  program_sha256=hashlib.sha256(program).hexdigest(),
                  source_declarations_verified=False, transitive_source_graph_verified=False,
                  descriptions_verified=False, compression_filters_verified=False)
    return report, artifacts
