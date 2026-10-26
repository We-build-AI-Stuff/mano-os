"""Decode bounded strace -f -qq -xx execve frames; never execute trace content.

This profile supports complete and unfinished/resumed execve calls. Other calls,
truncated/unreadable arguments and unknown framing fail closed. Byte strings stay
base64 data. Syscall success is not process success, ancestry or script authority.
"""
import base64
import hashlib
import re

MAX_BYTES = 16 * 1024**2
MAX_LINES = 10000
MAX_LINE = 256 * 1024
MAX_STRING = 16384
MAX_ARGS = 256
MAX_EXPANDED = 4 * 1024**2
MAX_PENDING = 256
UNFINISHED = b' <unfinished ...>'
RESUMED = b'<... execve resumed>'


def _string(body, position):
    if body[position:position+1] != b'"':
        raise ValueError('Fully observed hex-quoted exec string required')
    end = body.find(b'"', position+1)
    encoded = body[position+1:end] if end >= 0 else b''
    if (end < 0 or len(encoded) > 4*MAX_STRING
            or not re.fullmatch(rb'(?:\\x[0-9a-f]{2})*', encoded)):
        raise ValueError('Bounded complete hex string required')
    value = bytes.fromhex(encoded.replace(b'\\x', b'').decode('ascii'))
    if b'\0' in value:
        raise ValueError('Exec strings exclude their C terminator')
    return value, end+1


def _call(body):
    if not body.startswith(b'execve('):
        raise ValueError('Unsupported syscall or exec frame')
    path, position = _string(body, len(b'execve('))
    if body[position:position+3] != b', [':
        raise ValueError('Observed exec argument vector required')
    position += 3
    args = []
    if body[position:position+1] != b']':
        while True:
            value, position = _string(body, position)
            if len(args) >= MAX_ARGS:
                raise ValueError('Exec argument count budget')
            args.append(value)
            if body[position:position+1] == b']':
                break
            if body[position:position+2] != b', ':
                raise ValueError('Complete separated exec arguments required')
            position += 2
    position += 1
    if body[position:position+2] != b', ':
        raise ValueError('Explicit environment summary required')
    ending = re.fullmatch(
        rb'(?:NULL|0x[0-9a-f]{1,16} /\* ([0-9]{1,6}) vars \*/)\) = '
        rb'(0|-1 ([A-Z][A-Z0-9_]{0,31}) \([\x20-\x7e]{1,256}\))', body[position+2:])
    if ending is None or (ending[1] is not None and int(ending[1]) > 4096):
        raise ValueError('Known bounded environment and exec return frame required')
    success = ending[2] == b'0'
    return dict(path_base64=base64.b64encode(path).decode(),
                argv_base64=[base64.b64encode(a).decode() for a in args],
                environment_count=int(ending[1]) if ending[1] is not None else 0,
                return_value=0 if success else -1,
                errno=None if success else ending[3].decode('ascii')), len(path)+sum(map(len, args))


def decode(raw):
    if (type(raw) is not bytes or not 0 < len(raw) < MAX_BYTES
            or not raw.endswith(b'\n') or raw.count(b'\n') > MAX_LINES):
        raise ValueError('Bounded nonempty complete raw exec trace required')
    pending, events, expanded = {}, [], 0
    for number, line in enumerate(raw.split(b'\n')[:-1], 1):
        if not 0 < len(line) <= MAX_LINE:
            raise ValueError('Exec trace line budget')
        match = re.fullmatch(rb'([1-9][0-9]{0,9}) +(.+)', line)
        if match is None or int(match[1]) >= 2**31:
            raise ValueError('Exact positive PID prefix required')
        pid, body = int(match[1]), match[2]
        if body.endswith(UNFINISHED):
            if pid in pending or len(pending) >= MAX_PENDING or not body.startswith(b'execve('):
                raise ValueError('Bounded distinct pending exec call required')
            pending[pid] = (number, body[:-len(UNFINISHED)])
            continue
        if body.startswith(RESUMED):
            if pid not in pending:
                raise ValueError('Resumed exec lacks matching entry')
            entry, prefix = pending.pop(pid)
            body = prefix + body[len(RESUMED):]
            if len(body) > MAX_LINE:
                raise ValueError('Reassembled exec line budget')
        else:
            if pid in pending:
                raise ValueError('New exec before prior call resumed')
            entry = number
        event, size = _call(body)
        expanded += size
        if expanded > MAX_EXPANDED:
            raise ValueError('Expanded exec argument budget')
        events.append(dict(pid=pid, entry_line=entry, completion_line=number, **event))
    if pending:
        raise ValueError('Incomplete pending exec at trace end')
    events.sort(key=lambda e: e['entry_line'])
    return dict(schema_version='1.0', profile='strace-hex-execve-v1', bytes=len(raw),
                sha256=hashlib.sha256(raw).hexdigest(), physical_lines=raw.count(b'\n'),
                events=events, decoded_execve_calls=len(events),
                successful_execve_returns=sum(e['return_value'] == 0 for e in events),
                failed_execve_returns=sum(e['return_value'] == -1 for e in events),
                execve_arguments_decoded=True, process_exit_status_verified=False,
                caller_ancestry_verified=False, all_execs_observed=False,
                actual_trigger_arguments_verified=False, script_contents_at_exec_verified=False,
                trigger_authority_verified=False, changes_authorized=False,
                publication_authorized=False)
