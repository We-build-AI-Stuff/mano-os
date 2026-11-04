"""Inspect ELF memory declarations as bytes, never load or execute an object.

The accepted header profile is ordinary ELF64/little-endian/x86-64 ET_EXEC or
ET_DYN, with one explicit nonexecutable GNU stack and no writable executable
PT_LOAD segment. This is deliberately not complete ELF validation. A caller
must separately bind bytes, source identities, allowed paths, script interpreters,
actual loader behavior, CPU NX and every executable reachable after exec.
"""
import hashlib
import struct

MAX_FILE_BYTES = 64 * 1024**2
MAX_PROGRAM_HEADERS = 256


def inspect(raw):
    if type(raw) is not bytes or not 64 <= len(raw) <= MAX_FILE_BYTES:
        raise ValueError('Bounded retained ELF bytes required')

    def region(offset, count):
        if offset < 0 or count < 0 or offset + count > len(raw):
            raise ValueError('ELF memory-header region exceeds retained bytes')
        return raw[offset:offset+count]

    header = struct.unpack('<16sHHIQQQIHHHHHH', region(0, 64))
    ident, kind, machine, version = header[:4]
    if (ident[:7] != b'\x7fELF\x02\x01\x01' or ident[7] not in {0, 3}
            or ident[8:] != b'\0'*8 or kind not in {2, 3} or (machine, version) != (62, 1)
            or header[7] != 0 or header[8] != 64 or header[9] != 56
            or not 1 <= header[10] <= MAX_PROGRAM_HEADERS or header[5] < 64):
        raise ValueError('Ordinary bounded native x86-64 ELF program-header profile required')
    region(header[5], header[10]*56)
    loads, stacks, interpreters = [], [], []
    for index in range(header[10]):
        part = struct.unpack('<IIQQQQQQ', region(header[5]+index*56, 56))
        tag, flags, offset, address, _, file_bytes, memory_bytes, alignment = part
        if tag == 1:
            if (flags & ~7 or (flags & 3) == 3 or file_bytes > memory_bytes
                    or address + memory_bytes > 2**64
                    or (alignment > 1 and (alignment & (alignment-1)
                        or address % alignment != offset % alignment))):
                raise ValueError('Bounded non-WX loadable memory declaration required')
            region(offset, file_bytes)
            loads.append(dict(flags=flags, offset=offset, address=address,
                file_bytes=file_bytes, memory_bytes=memory_bytes, alignment=alignment))
        elif tag == 0x6474e551:
            if flags != 6:
                raise ValueError('Explicit read/write nonexecutable GNU stack required')
            stacks.append(index)
        elif tag == 3:
            if not 2 <= file_bytes <= 4096:
                raise ValueError('Bounded exact ELF interpreter bytes required')
            data = region(offset, file_bytes)
            if data[-1:] != b'\0' or b'\0' in data[:-1]:
                raise ValueError('One terminated ELF interpreter path required')
            try:
                path = data[:-1].decode('ascii')
            except UnicodeError as error:
                raise ValueError('Fixed ASCII interpreter path required') from error
            if (not path.startswith('/') or any(ord(c) < 33 or ord(c) > 126 for c in path)
                    or any(part in {'', '.', '..'} for part in path.split('/')[1:])):
                raise ValueError('Absolute uninterpreted ELF interpreter path required')
            interpreters.append(path)
    if not loads or len(stacks) != 1 or len(interpreters) > 1:
        raise ValueError('Loadable object with unique explicit stack/interpreter required')
    return dict(profile='man-native-elf-memory-declarations-v1',
        raw_sha256=hashlib.sha256(raw).hexdigest(), raw_bytes=len(raw),
        elf_class=64, machine=62, elf_type=kind, program_header_count=header[10],
        loads=loads, gnu_stack_index=stacks[0], gnu_stack_flags=6,
        interpreter=interpreters[0] if interpreters else None,
        nonexecutable_stack_declared=True, writable_executable_load_declared=False,
        complete_elf_validity_verified=False, interpreter_resolution_verified=False,
        across_exec_personality_verified=False, complete_runtime_closure_verified=False,
        publication_authorized=False)


def bind(raw, baseline, path):
    """Bind one ELF declaration to observed baseline metadata, without opening it.

    This does not authenticate the tree or prove that the worker selected this
    object. The controller must separately bind its read-only source descriptor
    and actual execution/mapping path. Alias names are not followed here.
    """
    import json

    from mano_runtime.package_payload import path_name
    from mano_runtime.package_tree import delta

    if (type(path) is not str or path_name(path) != path
            or not path.startswith(('usr/bin/', 'usr/lib/'))):
        raise ValueError('Canonical baseline code path required')
    delta(baseline, baseline)
    if type(raw) is not bytes or not 64 <= len(raw) <= MAX_FILE_BYTES:
        raise ValueError('Bounded retained baseline ELF bytes required')
    entries = baseline['entries']
    common = {'kind', 'uid', 'gid', 'mode', 'mtime_ns', 'ctime_ns', 'nlink', 'xattrs'}

    def checked(row, kind):
        if (type(row) is not dict or row.get('kind') != kind
                or set(row) != common | ({'bytes', 'sha256', 'hardlink_anchor'}
                                         if kind == 'file' else set())
                or any(type(row[key]) is not int for key in (
                    'uid', 'gid', 'mode', 'mtime_ns', 'ctime_ns', 'nlink'))
                or row['uid'] != 0 or not 0 <= row['gid'] < 2**32
                or not 0 <= row['mode'] <= 0o7777 or row['mode'] & 0o022
                or not 0 < row['nlink'] < 2**64
                or any(not -2**63 <= row[key] < 2**63 for key in ('mtime_ns', 'ctime_ns'))
                or row['xattrs'] != {}):
            raise ValueError('Exact Root-owned nonwritable ordinary baseline metadata required')
        return row

    def metadata(row):
        return hashlib.sha256(json.dumps(row, sort_keys=True, separators=(',', ':'),
            allow_nan=False).encode()).hexdigest()

    parents = ['.'] + ['/'.join(path.split('/')[:index])
                       for index in range(1, len(path.split('/')))]
    parent_hashes = {}
    for parent in parents:
        row = checked(entries.get(parent), 'directory')
        if not row['mode'] & (0o010 if row['gid'] == 12 else 0o001):
            raise ValueError('Baseline parents must be searchable by fixed man identity')
        parent_hashes[parent] = metadata(row)
    row = checked(entries.get(path), 'file')
    if (type(row['bytes']) is not int or row['bytes'] != len(raw)
            or row['sha256'] != hashlib.sha256(raw).hexdigest()
            or type(row['hardlink_anchor']) is not str
            or path_name(row['hardlink_anchor']) != row['hardlink_anchor']):
        raise ValueError('Exact baseline file content and link metadata required')
    aliases = {name: other for name, other in entries.items()
               if type(other) is dict and other.get('kind') == 'file'
               and other.get('hardlink_anchor') == row['hardlink_anchor']}
    if len(aliases) != row['nlink'] or min(aliases) != row['hardlink_anchor']:
        raise ValueError('Complete in-baseline hardlink group required')
    for name, alias in aliases.items():
        if path_name(name) != name or checked(alias, 'file') != row:
            raise ValueError('Identical ordinary hardlink metadata required')
    declarations = inspect(raw)
    return dict(profile='man-baseline-elf-memory-binding-v1', path=path,
        baseline_sha256=baseline['manifest_sha256'], file_metadata_sha256=metadata(row),
        parent_metadata_sha256=parent_hashes, aliases=sorted(aliases),
        file_content_sha256=hashlib.sha256(raw).hexdigest(), file_bytes=len(raw),
        declarations=declarations, observed_content_matches=True,
        filesystem_paths_opened=False, collector_authentication_verified=False,
        readonly_source_descriptor_verified=False, actual_worker_selection_verified=False,
        complete_runtime_closure_verified=False, publication_authorized=False)
