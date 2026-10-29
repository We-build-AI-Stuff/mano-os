"""Fixed unprivileged content worker; no real-source decoding on Root or Mac.

The standalone worker loads two fixed immutable support modules. Real captured
sources are decoded only after the native guard has installed confinement.
Expanded bytes are compared against GNU gzip and then discarded; reports bind
hashes and framing, not roff/include/description semantics or publication.
"""
import base64
import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import time

MAX_EXPANDED_TOTAL = 64 * 1024**2
MAX_MEMBER_TOTAL = 16384
MAX_REPORT_BYTES = 16 * 1024**2
MAX_CAPTURE_BYTES = 24 * 1024**2 + 4097


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify_gnu(raw, expected, *, timeout=10):
    """Compare bounded stdout directly, never trust a checksum alone or use paths."""
    if sys.platform != 'linux' or os.geteuid() == 0:
        raise PermissionError('Unprivileged Linux gzip verification required')
    if (type(raw) is not bytes or len(raw) > 1024**2 or type(expected) is not bytes
            or len(expected) > 8*1024**2 or type(timeout) not in {int, float}
            or not 0 < timeout <= 10):
        raise ValueError('Bounded gzip verification input and deadline required')
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC0', 'HOME': '/nonexistent'}
    process = subprocess.Popen(['/usr/bin/gzip', '-cd'], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, close_fds=True,
        start_new_session=True)
    selector = selectors.DefaultSelector()
    written = received = 0
    errors = bytearray()
    deadline = time.monotonic() + timeout
    try:
        for stream, event, label in ((process.stdin, selectors.EVENT_WRITE, 'input'),
                                    (process.stdout, selectors.EVENT_READ, 'output'),
                                    (process.stderr, selectors.EVENT_READ, 'error')):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, event, label)
        while selector.get_map() or process.poll() is None:
            if time.monotonic() >= deadline:
                raise ValueError('Gzip verifier deadline')
            for key, _ in selector.select(.05):
                stream = key.fileobj
                if key.data == 'input':
                    if written == len(raw):
                        selector.unregister(stream)
                        stream.close()
                        continue
                    try:
                        written += os.write(stream.fileno(), raw[written:written+65536])
                    except (BlockingIOError, InterruptedError):
                        continue
                    except BrokenPipeError:
                        selector.unregister(stream)
                        stream.close()
                else:
                    try:
                        chunk = os.read(stream.fileno(), 65536)
                    except (BlockingIOError, InterruptedError):
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    if key.data == 'output':
                        end = received + len(chunk)
                        if end > len(expected) or chunk != expected[received:end]:
                            raise ValueError('Independent gzip output mismatch or byte budget')
                        received = end
                    else:
                        if len(errors) + len(chunk) > 65536:
                            raise ValueError('Gzip diagnostic budget')
                        errors.extend(chunk)
        if (process.returncode != 0 or written != len(raw) or received != len(expected)
                or errors):
            raise ValueError('Complete normal matching gzip verification required')
        return dict(command=['/usr/bin/gzip', '-cd'], returncode=0,
                    input_bytes=written, output_bytes=received, output_sha256=sha(expected),
                    stderr_bytes=0, complete=True, bytes_equal=True)
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
        selector.close()
        process.wait(timeout=2)


def read_fixed(path, maximum, *, mode=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) & 0o7022
                or (mode is not None and stat.S_IMODE(before.st_mode) != mode)
                or not 0 < before.st_size <= maximum):
            raise ValueError('Fixed immutable Root-owned input required')
        raw = stream.read(maximum+1)
        after = os.fstat(stream.fileno())
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if len(raw) != before.st_size or identity(before) != identity(after):
            raise ValueError('Fixed input changed during acquisition')
    return raw


def process_files(value, codec):
    files, total, members = {}, 0, 0
    serialized_bytes = 2
    for path, encoded in sorted(value['files'].items()):
        raw = base64.b64decode(encoded, validate=True)
        try:
            expanded, frame = codec.decode(raw, maximum=min(8*1024**2, MAX_EXPANDED_TOTAL-total))
            count = len(frame['members'])
            if members + count > MAX_MEMBER_TOTAL:
                raise ValueError('Aggregate gzip member budget')
            verified = verify_gnu(raw, expanded)
        except (ValueError, OSError, subprocess.TimeoutExpired) as error:
            raise ValueError(f'Manual source {path!r}: {error}') from error
        total += len(expanded)
        members += count
        row = dict(input_sha256=sha(raw), framing=frame, independent_gzip=verified)
        serialized_bytes += (len(json.dumps(path).encode()) +
                             len(json.dumps(row, sort_keys=True, allow_nan=False).encode()) + 4)
        if serialized_bytes > MAX_REPORT_BYTES:
            raise ValueError('Source content report budget')
        files[path] = row
    return dict(profile='man-source-gzip-content-v1', files=files, source_files=len(files),
        expanded_bytes=total, gzip_members=members, both_decoders_equal=True,
        roff_interpreted=False, source_declarations_verified=False,
        transitive_source_graph_verified=False, descriptions_verified=False,
        compression_filters_verified=False, runtime_closure_verified=False,
        generated_state_validated=False, changes_authorized=False, publication_authorized=False)


def validate_report(value, manifest_value):
    """Check native evidence without running an inflater in the controller."""
    expected = manifest_value['files']
    if (type(value) is not dict or value.get('profile') != 'man-source-gzip-content-v1'
            or type(value.get('files')) is not dict or set(value['files']) != set(expected)
            or type(value.get('source_files')) is not int or value['source_files'] != len(expected)
            or value.get('both_decoders_equal') is not True):
        raise ValueError('Complete native dual-decoder source report required')
    total = members = 0
    for path, row in value['files'].items():
        frame, second = row['framing'], row['independent_gzip']
        if (row['input_sha256'] != expected[path]['sha256']
                or frame['profile'] != 'bounded-gzip-members-v1'
                or frame['gzip_header_and_trailer_checks_passed'] is not True
                or frame['raw_deflate_implementation'] != 'zlib'
                or frame['input_sha256'] != row['input_sha256']
                or type(frame['input_bytes']) is not int
                or frame['input_bytes'] != expected[path]['bytes']
                or type(frame['expanded_bytes']) is not int
                or not 0 <= frame['expanded_bytes'] <= 8*1024**2
                or type(frame['members']) is not list or not 1 <= len(frame['members']) <= 128
                or type(frame['expanded_sha256']) is not str
                or len(frame['expanded_sha256']) != 64
                or any(c not in '0123456789abcdef' for c in frame['expanded_sha256'])
                or second['command'] != ['/usr/bin/gzip', '-cd']
                or type(second['returncode']) is not int or second['returncode'] != 0
                or type(second['input_bytes']) is not int
                or second['input_bytes'] != frame['input_bytes']
                or type(second['output_bytes']) is not int
                or second['output_bytes'] != frame['expanded_bytes']
                or second['output_sha256'] != frame['expanded_sha256']
                or type(second['stderr_bytes']) is not int or second['stderr_bytes'] != 0
                or second['complete'] is not True or second['bytes_equal'] is not True):
            raise ValueError('Exact normal matching independent gzip evidence required')
        for flag in ('header_names_used_as_paths', 'header_times_used_as_source_authority',
                     'extra_subfields_interpreted', 'roff_interpreted',
                     'source_declarations_verified', 'transitive_source_graph_verified',
                     'generated_state_validated', 'changes_authorized', 'publication_authorized'):
            if frame[flag] is not False:
                raise ValueError('Gzip framing cannot grant source semantics or authority')
        total += frame['expanded_bytes']
        members += len(frame['members'])
        if total > MAX_EXPANDED_TOTAL or members > MAX_MEMBER_TOTAL:
            raise ValueError('Aggregate native content evidence budget')
    if (type(value.get('expanded_bytes')) is not int or value['expanded_bytes'] != total
            or type(value.get('gzip_members')) is not int or value['gzip_members'] != members):
        raise ValueError('Exact aggregate native expansion counts required')
    for name in ('roff_interpreted', 'source_declarations_verified',
                 'transitive_source_graph_verified', 'descriptions_verified',
                 'compression_filters_verified', 'runtime_closure_verified',
                 'generated_state_validated', 'changes_authorized', 'publication_authorized'):
        if value.get(name) is not False:
            raise ValueError('Native decompression cannot grant source semantics or authority')
    return dict(profile=value['profile'], source_files=len(expected), expanded_bytes=total,
                gzip_members=members, both_decoders_equal=True, roff_interpreted=False,
                source_declarations_verified=False, transitive_source_graph_verified=False,
                descriptions_verified=False, compression_filters_verified=False,
                runtime_closure_verified=False, generated_state_validated=False,
                changes_authorized=False, publication_authorized=False)


def main():
    if (sys.platform != 'linux' or os.getresuid() != (6, 6, 6)
            or os.getresgid() != (12, 12, 12) or os.getgroups() != [] or len(sys.argv) != 1):
        raise PermissionError('Fixed unprivileged Linux source content worker required')
    sys.path.insert(0, '/run/man-source-support')
    import gzip_frame as codec
    from source_bytes import validate_capture

    packet = read_fixed('/run/man-source-paths.json', 4*1024**2, mode=0o444)
    captured = read_fixed('/run/man-source-capture.txt', MAX_CAPTURE_BYTES)
    first, separator, body = captured.partition(b'\n')
    if not separator or len(first) > 4096 or json.loads(first).get('role') != 'source-bytes':
        raise ValueError('Prior fixed source-byte capture required')
    validate_capture(packet, body)
    result = process_files(json.loads(body), codec)
    gzip_binary = read_fixed('/usr/bin/gzip', 16*1024**2)
    module_path = getattr(codec.zlib, '__file__', None)
    if module_path is None:
        if 'zlib' not in sys.builtin_module_names:
            raise ValueError('Known built-in zlib implementation required')
        kind = 'builtin'
        module_path = os.path.realpath(sys.executable)
        prefix = '/usr/bin/'
    else:
        kind, prefix = 'extension', '/usr/lib/'
    if not module_path.startswith(prefix) or '/..' in module_path:
        raise ValueError('Fixed baseline zlib implementation path required')
    module = read_fixed(module_path, 16*1024**2)
    result.update(input_capture_sha256=sha(captured), manifest_sha256=sha(packet),
                  gzip_executable_sha256=sha(gzip_binary),
                  zlib_module=dict(kind=kind, path=module_path, sha256=sha(module)))
    encoded = json.dumps(result, sort_keys=True, allow_nan=False).encode()
    if len(encoded)+1 > MAX_REPORT_BYTES:
        raise ValueError('Source content final report budget')
    sys.stdout.buffer.write(encoded+b'\n')


if __name__ == '__main__':
    main()
