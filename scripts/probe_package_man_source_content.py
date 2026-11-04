"""Fixed disposable CI content worker; native inflaters never run in Root."""
import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

from probe_package_man_regeneration import validate_native_guard
from probe_package_man_source_bytes import fixture_identity, source_sandbox, source_unit

from mano_runtime.package_man_source_content import MAX_BUNDLE_BYTES, validate_report

FILES = {'staged-man-content-reader.py', 'staged-man-content-gzip.py',
         'staged-man-content-capture.txt', 'staged-man-expanded-inputs.bin'}


def freeze_expanded_inputs(cache, evidence):
    """Collect only a fixed drained-domain leaf; no native data parser runs here."""
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise PermissionError('Disposable Debian Root custody collector required')
    if (cache != Path('/.snapshots/.mano-staged-package-ci/man-content-cache')
            or evidence != Path('/opt/mano-lab/evidence')):
        raise ValueError('Fixed expanded-input custody locations required')
    source_fd = os.open(cache / 'expanded-inputs.bin',
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    destination = evidence / 'staged-man-expanded-inputs.bin'
    with os.fdopen(source_fd, 'rb', buffering=0) as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 6 or before.st_gid != 12
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 0 <= before.st_size <= MAX_BUNDLE_BYTES):
            raise ValueError('Private single-link bounded worker output required')
        target_fd = os.open(destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(target_fd, 'wb') as target:
            try:
                copied = 0
                while True:
                    data = source.read(min(65536, MAX_BUNDLE_BYTES-copied+1))
                    if not data:
                        break
                    copied += len(data)
                    if copied > MAX_BUNDLE_BYTES:
                        raise ValueError('Worker expanded-input output exceeded custody budget')
                    if target.write(data) != len(data):
                        raise OSError('Complete frozen expanded-input copy required')
                after = os.fstat(source.fileno())
                def identity(info):
                    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                if copied != before.st_size or identity(before) != identity(after):
                    raise ValueError('Worker expanded-input output changed during custody')
            finally:
                try:
                    target.flush()
                finally:
                    os.fchmod(target.fileno(), 0o444)
    # Only Root-owned frozen data is handed to later pure validators.
    return destination.read_bytes()


def bounded_capture(command, *, timeout, stdout_limit=16*1024**2+4097,
                    stderr_limit=65536):
    """Bound retained bytes while reading, including a child holding pipes open."""
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True, cwd='/',
        env={'PATH': '/usr/sbin:/usr/bin:/bin', 'LANG': 'C.UTF-8'})
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    limits = {'stdout': stdout_limit, 'stderr': stderr_limit}
    deadline = time.monotonic() + timeout
    failed = True
    try:
        with selectors.DefaultSelector() as selector:
            for label, stream in (('stdout', child.stdout), ('stderr', child.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map() or child.poll() is None:
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(command, timeout,
                        output=bytes(output['stdout']), stderr=bytes(output['stderr']))
                for key, _ in selector.select(.05):
                    label = key.data
                    remaining = limits[label] - len(output[label])
                    try:
                        data = os.read(key.fd, min(65536, remaining+1))
                    except (BlockingIOError, InterruptedError):
                        continue
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    output[label].extend(data[:remaining])
                    if len(data) > remaining:
                        raise subprocess.CalledProcessError(-1, command,
                            output=bytes(output['stdout']), stderr=bytes(output['stderr']))
        if child.returncode:
            raise subprocess.CalledProcessError(child.returncode, command,
                output=bytes(output['stdout']), stderr=bytes(output['stderr']))
        failed = False
        return bytes(output['stdout'])
    finally:
        if failed or child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.stdout.close()
        child.stderr.close()
        child.wait(timeout=2)


def content_sandbox(base, masks, empty, config_digest):
    command = source_sandbox(base, masks, empty, config_digest)
    if command[-2:] != ['/run/man-cache-guard', '--source-bytes']:
        raise ValueError('Fixed source sandbox inherited role required')
    command[-1] = '--source-content'
    command[command.index(str(base / 'man-source-cache'))] = str(base / 'man-content-cache')
    position = command.index('--clearenv')
    command[position:position] = [
        '--ro-bind', str(base / 'man-source-content.py'), '/run/man-source-content.py',
        '--ro-bind', str(base / 'man-source-support'), '/run/man-source-support',
        '--ro-bind', '/opt/mano-lab/evidence/staged-man-source-capture.txt',
        '/run/man-source-capture.txt']
    return command


def content_unit():
    command = source_unit()
    command[command.index('--unit=mano-man-source-ci.service')] = (
        '--unit=mano-man-content-ci.service')
    command[command.index('--property=RuntimeMaxSec=70')] = '--property=RuntimeMaxSec=190'
    command[command.index('--property=LimitFSIZE=2097152')] = (
        '--property=LimitFSIZE=75497472')
    return command


def capture_content(base, baseline, masks, empty, config_digest, run):
    if sys.platform != 'linux':
        raise PermissionError('Disposable Debian content verification only')
    from probe_package_plans import guard

    from mano_runtime import recovery

    guard()
    recovery.root_guard()
    if base != Path('/.snapshots/.mano-staged-package-ci'):
        raise ValueError('Fixed private content directory required')
    evidence = Path('/opt/mano-lab/evidence')
    sources = Path('/opt/mano-lab/src/mano_runtime')
    program = (sources / 'package_man_source_content.py').read_bytes()
    codec = (sources / 'package_man_gzip.py').read_bytes()
    support = base / 'man-source-support'
    support.mkdir(mode=0o700)
    for name, data in (('source_bytes.py', (base / 'man-source-reader.py').read_bytes()),
                       ('gzip_frame.py', codec)):
        with (support / name).open('xb') as stream:
            stream.write(data)
        (support / name).chmod(0o444)
    support.chmod(0o555)
    with (base / 'man-source-content.py').open('xb') as stream:
        stream.write(program)
    (base / 'man-source-content.py').chmod(0o444)
    artifacts = {'staged-man-content-reader.py': program, 'staged-man-content-gzip.py': codec}
    for name, data in artifacts.items():
        with (evidence / name).open('xb') as stream:
            stream.write(data)
    cache = base / 'man-content-cache'
    cache.mkdir(mode=0o700)
    run(['/usr/bin/mount', '-t', 'tmpfs', '-o',
         'size=134217728,nosuid,nodev,noexec,mode=0755,uid=6,gid=12',
         'mano-man-content-ci', str(cache)])
    run(['/usr/bin/mount', '--make-private', str(cache)])
    control = base / 'man-cache-control-file'
    before = fixture_identity(control)
    try:
        raw = bounded_capture(content_unit() +
                              content_sandbox(base, masks, empty, config_digest), timeout=200)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        for label in ('stdout', 'stderr'):
            value = getattr(error, label) or b''
            if type(value) is bytes:
                with (evidence / ('staged-man-content-failed-'+label+'.txt')).open('xb') as stream:
                    stream.write(value[:32*1024**2 if label == 'stdout' else 65536])
        # The launcher process group is separate from the service domain. Stop
        # the fixed service too; its KillMode covers native descendants.
        run(['/usr/bin/systemctl', 'stop', 'mano-man-content-ci.service'], timeout=10)
        try:
            freeze_expanded_inputs(cache, evidence)
        except FileNotFoundError:
            pass  # The worker may have refused before creating its fixed output.
        raise
    artifacts['staged-man-content-capture.txt'] = raw
    with (evidence / 'staged-man-content-capture.txt').open('xb') as stream:
        stream.write(raw)
    group = Path('/sys/fs/cgroup/mano.slice/mano-package.slice/mano-man-content-ci.service')
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
            raise ValueError('Content verification process domain did not drain')
        time.sleep(.02)
    expanded = freeze_expanded_inputs(cache, evidence)
    artifacts['staged-man-expanded-inputs.bin'] = expanded
    first, separator, body = raw.partition(b'\n')
    if not separator or len(first) > 4096 or len(body) > 16*1024**2:
        raise ValueError('Bounded native content capture required')
    native = json.loads(first)
    validate_native_guard(native, role='source-content')
    value = json.loads(body)
    report = validate_report(value, json.loads((base / 'man-source-paths.json').read_bytes()))
    retained = report['expanded_inputs']
    if (retained['bytes'] != len(expanded)
            or retained['sha256'] != hashlib.sha256(expanded).hexdigest()):
        raise ValueError('Frozen expanded-input artifact must match worker digest and length')
    source_capture = (evidence / 'staged-man-source-capture.txt').read_bytes()
    packet = (base / 'man-source-paths.json').read_bytes()
    def sha(data):
        return hashlib.sha256(data).hexdigest()

    binary = baseline['entries']['usr/bin/gzip']
    module = value['zlib_module']
    prefix = '/usr/bin/' if module['kind'] == 'builtin' else '/usr/lib/'
    if (value['input_capture_sha256'] != sha(source_capture)
            or value['manifest_sha256'] != sha(packet)
            or value['gzip_executable_sha256'] != binary['sha256']
            or module['kind'] not in {'builtin', 'extension'}
            or type(module['path']) is not str or not module['path'].startswith(prefix)
            or module['sha256'] != baseline['entries'][module['path'][1:]]['sha256']
            or fixture_identity(control) != before):
        raise ValueError('Exact native input/runtime hashes and unchanged control required')
    report.update(guard=native, domain_drained=True, control_fixture_unchanged=True,
        input_capture_sha256=value['input_capture_sha256'],
        manifest_sha256=value['manifest_sha256'],
        gzip_executable_sha256=value['gzip_executable_sha256'], zlib_module=module,
        capture_sha256=sha(raw), capture_bytes=len(raw),
        worker_sha256=sha(body), worker_bytes=len(body),
        program_sha256=sha(program), codec_sha256=sha(codec),
        expanded_inputs_custody=dict(domain_drained=True, source_uid=6, source_gid=12,
            source_mode=0o600, source_nlink=1, source_fd_identity_unchanged=True,
            frozen_uid=0, frozen_mode=0o444, frozen_before_validation=True,
            artifact_sha256=sha(expanded), artifact_bytes=len(expanded),
            cache_tmpfs_bytes=134217728, file_size_limit_bytes=MAX_BUNDLE_BYTES))
    return report, artifacts
