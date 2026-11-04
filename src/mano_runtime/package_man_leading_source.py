"""Inspect man-db's leading source reference as bytes, without opening paths.

This describes only the initial request examined by man-db 2.13's ultimate-
source lookup. It is not a roff interpreter or a complete include graph. The
function is currently unused by native acquisition and publication.
"""
import base64
import hashlib

MAX_INPUT_BYTES = 8 * 1024**2
MAX_COMMENT_LINES = 65536
MAX_LINE_BYTES = 16384
MAX_OPERAND_BYTES = 4096
WHITESPACE = b' \t\n\r\v\f'
COMMENT = bytes((46, 92, 34))


def inspect(raw):
    if type(raw) is not bytes or len(raw) > MAX_INPUT_BYTES:
        raise ValueError('Bounded expanded manual bytes required')
    if b'\0' in raw:
        raise ValueError('Embedded NUL has no supported leading-source interpretation')
    start = comments = 0
    while True:
        end = raw.find(b'\n', start)
        end = len(raw) if end < 0 else end+1
        line = raw[start:end]
        if len(line) > MAX_LINE_BYTES:
            raise ValueError('Leading manual line budget')
        if not line.startswith(COMMENT):
            break
        comments += 1
        if comments > MAX_COMMENT_LINES:
            raise ValueError('Initial comment line budget')
        start = end
    selected = line.lstrip(WHITESPACE)
    operand, kind, ignored = b'', 'no-leading-so-request', b''
    if selected.startswith(b'.so'):
        argument = selected[3:].lstrip(WHITESPACE)
        boundary = next((i for i, char in enumerate(argument) if char in WHITESPACE),
                        len(argument))
        operand, ignored = argument[:boundary], argument[boundary:]
        if len(operand) > MAX_OPERAND_BYTES:
            raise ValueError('Leading include operand budget')
        if not operand:
            kind = 'empty-relative-reference'
        elif operand.startswith(b'/'):
            kind = 'absolute-reference-not-followed-by-ultimate-source'
        else:
            kind = 'relative-reference'
    def sha(data):
        return hashlib.sha256(data).hexdigest()

    return dict(profile='man-db-2.13-leading-source-request-v1',
        input_bytes=len(raw), input_sha256=sha(raw), initial_comment_lines=comments,
        comment_prefix_bytes=start, comment_prefix_sha256=sha(raw[:start]),
        selected_line_offset=start, selected_line_bytes=len(line),
        selected_line_sha256=sha(line), selected_line_base64=base64.b64encode(line).decode(),
        request_kind=kind, operand_bytes=len(operand),
        operand_base64=base64.b64encode(operand).decode(),
        trailing_argument_bytes=len(ignored), trailing_argument_sha256=sha(ignored),
        filesystem_paths_opened=False, roff_interpreted=False,
        ultimate_source_target_resolved=False, transitive_source_graph_verified=False,
        virtual_alias_declarations_verified=False, descriptions_verified=False,
        compression_filters_verified=False, generated_state_validated=False,
        changes_authorized=False, publication_authorized=False)
