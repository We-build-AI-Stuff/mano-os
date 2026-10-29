"""Fixed disposable CI content worker; native inflaters never run in Root."""
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

from probe_package_man_regeneration import validate_native_guard
from probe_package_man_source_bytes import fixture_identity, source_sandbox, source_unit

from mano_runtime.package_man_source_content import validate_report

FILES = {'staged-man-content-reader.py', 'staged-man-content-gzip.py',
         'staged-man-content-capture.txt'}


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
         'size=16777216,nosuid,nodev,noexec,mode=0755,uid=6,gid=12',
         'mano-man-content-ci', str(cache)])
    run(['/usr/bin/mount', '--make-private', str(cache)])
    control = base / 'man-cache-control-file'
    before = fixture_identity(control)
    try:
        raw = run(content_unit() + content_sandbox(base, masks, empty, config_digest), timeout=200)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        for label in ('stdout', 'stderr'):
            value = getattr(error, label) or b''
            if type(value) is bytes:
                with (evidence / ('staged-man-content-failed-'+label+'.txt')).open('xb') as stream:
                    stream.write(value[:32*1024**2 if label == 'stdout' else 65536])
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
    first, separator, body = raw.partition(b'\n')
    if not separator or len(first) > 4096 or len(body) > 16*1024**2:
        raise ValueError('Bounded native content capture required')
    native = json.loads(first)
    validate_native_guard(native, role='source-content')
    value = json.loads(body)
    report = validate_report(value, json.loads((base / 'man-source-paths.json').read_bytes()))
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
        program_sha256=sha(program), codec_sha256=sha(codec))
    return report, artifacts
