"""Bounded human result client and literal text rendering; no command execution."""

import base64
import codecs
import hashlib
import re

from mano_protocol.actions import identifier, relative_path

from .approve import rpc
from .intake import parse

PREVIEW_BYTES = 4096


def packet(prompt_id):
    return b'\x01\x0a' + identifier(prompt_id).encode('ascii')


def parse_result(value, prompt_id):
    if not isinstance(value, dict) or set(value) != {'prompt', 'result'}:
        raise ValueError('Unexpected result response')
    prompt = parse(value['prompt'], prompt_id)
    item = value['result']
    if item is None:
        return dict(prompt=prompt, result=None)
    if (prompt['task_id'] is None or not isinstance(item, dict) or set(item) != {
            'action_id', 'artifact_id', 'path', 'size', 'sha256', 'data',
            'preview_sha256', 'truncated'}):
        raise ValueError('Invalid verified result')
    for key in ('action_id', 'artifact_id'):
        identifier(item[key])
    relative_path(item['path'])
    for key in ('sha256', 'preview_sha256'):
        if not isinstance(item[key], str) or not re.fullmatch('[0-9a-f]{64}', item[key]):
            raise ValueError('Invalid artifact digest')
    if (type(item['size']) is not int or not 0 <= item['size'] <= 8388608
            or not isinstance(item['data'], str) or len(item['data']) > 5464
            or type(item['truncated']) is not bool):
        raise ValueError('Invalid bounded preview')
    data = base64.b64decode(item['data'], validate=True)
    if (len(data) != min(item['size'], PREVIEW_BYTES)
            or item['truncated'] != (item['size'] > PREVIEW_BYTES)
            or hashlib.sha256(data).hexdigest() != item['preview_sha256']
            or (not item['truncated'] and item['preview_sha256'] != item['sha256'])):
        raise ValueError('Preview integrity mismatch')
    return dict(prompt=prompt, result=dict(item))


def read_result(prompt_id):
    response = rpc(packet(prompt_id))
    if not isinstance(response, dict) or response.get('ok') is not True:
        raise ValueError('Result unavailable')
    return parse_result({key: response.get(key) for key in ('prompt', 'result')}, prompt_id)


def display(value):
    item = value['result']
    if item is None:
        return 'No verified snapshot is available for this request yet.', ''
    path = repr(item['path'])
    if len(path) > 180:
        path = path[:180] + '… (path shortened)'
    summary = (f"File: {path}\nAction: {item['action_id']}\n"
               f"Artifact: {item['artifact_id']}\nSize: {item['size']} bytes\n"
               f"SHA-256: {item['sha256']}\n"
               'Verified snapshot; the workspace may have changed since capture.')
    if item['truncated']:
        summary += '\nShowing the first 4096 bytes.'
    data = base64.b64decode(item['data'], validate=True)
    try:
        # Omit an incomplete final character at the prefix boundary, while
        # still rejecting invalid UTF-8 anywhere in the captured prefix.
        content = codecs.getincrementaldecoder('utf8')().decode(data, final=not item['truncated'])
        if '\x00' in content:
            raise UnicodeError('Binary data')
    except UnicodeError:
        content = 'Binary snapshot; a text preview is unavailable.'
    return summary, content
