"""Closed desktop requests and framed control data; no authority or effects."""

import json
import re
from pathlib import PurePosixPath

WORKER = '/usr/lib/mano-desktop/session.py'
MAX_FRAME = 8192
MEMORY_MAX = 512 * 1024**2
PIDS_MAX = 96
CPU_MAX = 50
KEYS = {'Return', 'Escape', 'Tab', 'BackSpace', 'Delete', 'Left', 'Right', 'Up', 'Down',
        'Home', 'End', 'PageUp', 'PageDown', 's'}
MODIFIERS = {'ctrl', 'alt', 'shift', 'logo'}


def integer(value, low, high):
    """Reject booleans and values outside the declared integer interval."""
    if type(value) is not int or not low <= value <= high:
        raise ValueError('Desktop integer outside its fixed bounds')
    return value


def text(value, maximum, *, empty=False):
    """Validate printable UTF-8 data before it reaches the compositor or filesystem."""
    if (not isinstance(value, str) or (not value and not empty)
            or len(value.encode()) > maximum
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError('Expected bounded printable desktop text')
    return value


def opening(value):
    """Validate the exact native approval shape, with no executable or display selector."""
    if not isinstance(value, dict) or set(value) != {
            'width', 'height', 'cwd', 'timeout_seconds', 'input_limit_bytes',
            'memory_bytes', 'pids', 'cpu_percent'}:
        raise ValueError('Unexpected desktop opening fields')
    integer(value['width'], 320, 1280)
    integer(value['height'], 240, 720)
    integer(value['timeout_seconds'], 1, 120)
    integer(value['input_limit_bytes'], 1, 65536)
    integer(value['memory_bytes'], 64 * 1024**2, MEMORY_MAX)
    integer(value['pids'], 16, PIDS_MAX)
    integer(value['cpu_percent'], 1, CPU_MAX)
    if value['cwd'] != '.':
        raise ValueError('Desktop starts only in the allocated workspace')
    return dict(value)


def launch_arguments(value):
    """Translate the approved configuration into fixed worker arguments."""
    value = opening(value)
    return dict(argv=['/usr/bin/python3', '-I', WORKER, json.dumps(value, sort_keys=True)],
        cwd='.', timeout_seconds=value['timeout_seconds'], rows=24, columns=80,
        input_limit_bytes=value['input_limit_bytes'])


def control(command, args, *, width, height):
    """Validate one operation against the private canvas and closed argument sets."""
    if not isinstance(args, dict):
        raise ValueError('Expected desktop control object')
    fields = {
        'status': set(), 'close': set(), 'terminal': {'title'}, 'type': {'text'},
        'writer': {'path'}, 'key': {'key', 'modifiers'}, 'pointer': {'x', 'y', 'button'},
        'writer_export_pdf': {'path'},
        'focus': {'window_id'}, 'screenshot': {'path'},
    }
    if not isinstance(command, str) or command not in fields or set(args) != fields[command]:
        raise ValueError('Unexpected desktop control fields')
    if command == 'terminal':
        text(args['title'], 80)
    elif command == 'type':
        text(args['text'], 2048)
    elif command == 'key':
        if not isinstance(args['key'], str) or args['key'] not in KEYS:
            raise ValueError('Unknown desktop key')
        modifiers = args['modifiers']
        if (not isinstance(modifiers, list) or len(modifiers) > 4
                or not all(isinstance(item, str) and item in MODIFIERS for item in modifiers)
                or len(set(modifiers)) != len(modifiers)):
            raise ValueError('Unknown or duplicate desktop modifier')
    elif command == 'pointer':
        integer(args['x'], 0, width - 1)
        integer(args['y'], 0, height - 1)
        if args['button'] not in (None, 'left', 'right', 'middle'):
            raise ValueError('Unknown desktop pointer button')
    elif command == 'focus':
        integer(args['window_id'], 1, (1 << 63) - 1)
    elif command in {'writer', 'writer_export_pdf', 'screenshot'}:
        suffix = {'writer': '.odt', 'writer_export_pdf': '.pdf', 'screenshot': '.png'}[command]
        path = text(args['path'], 256)
        parsed = PurePosixPath(path)
        if (parsed.is_absolute() or '..' in parsed.parts or str(parsed) != path
                or parsed.suffix != suffix or any(part.startswith('.') for part in parsed.parts)):
            raise ValueError('Expected a workspace-relative ' + suffix + ' path')
    return dict(args)


def decode(raw):
    """Accept one complete bounded JSON frame with unique keys and finite values."""
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_FRAME or not raw.endswith(b'\n'):
        raise ValueError('Expected a bounded complete desktop frame')

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate desktop frame key')
            result[key] = value
        return result

    def invalid(_):
        raise ValueError('Nonfinite desktop frame value')

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    if not isinstance(value, dict):
        raise ValueError('Expected desktop frame object')
    return value


def request(identifier, command, args, *, width, height):
    """Create one UTF-8 control line that fits the canonical PTY input limit."""
    if not isinstance(identifier, str) or not re.fullmatch('[0-9a-f]{32}', identifier):
        raise ValueError('Expected desktop request identity')
    args = control(command, args, width=width, height=height)
    raw = (json.dumps(dict(schema_version='1.0', id=identifier, command=command, args=args),
                      sort_keys=True, separators=(',', ':'), allow_nan=False,
                      ensure_ascii=False) + '\n').encode()
    if len(raw) > 4000:
        raise ValueError('Desktop frame exceeds its bound')
    return raw
