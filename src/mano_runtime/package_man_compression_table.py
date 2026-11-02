"""Inspect static libman's compression table as bytes, never load an ELF file.

The deliberately narrow ELF64/x86-64 profile requires a defined comp_list data
symbol and ordinary relative pointer relocations. Unsupported layouts fail
closed. A caller must bind the library to immutable runtime provenance separately.
This decoder proves no loader symbol resolution or decompressor search authority.
"""
import base64
import hashlib
import re
import struct

MAX_LIBRARY_BYTES = 1024**2
MAX_SECTIONS = 256
MAX_SYMBOLS = 16384
MAX_RELOCATIONS = 16384
PROFILE = 'man-db-elf64-compression-table-v1'


def decode(raw):
    if type(raw) is not bytes or not 64 <= len(raw) <= MAX_LIBRARY_BYTES:
        raise ValueError('Bounded immutable libman ELF bytes required')

    def region(offset, count):
        if offset < 0 or count < 0 or offset+count > len(raw):
            raise ValueError('ELF data range outside retained library')
        return raw[offset:offset+count]

    def unpack(fmt, offset):
        return struct.unpack(fmt, region(offset, struct.calcsize(fmt)))

    header = unpack('<16sHHIQQQIHHHHHH', 0)
    ident, kind, machine, version = header[:4]
    if (ident[:7] != b'\x7fELF\x02\x01\x01' or ident[7] not in {0, 3}
            or ident[8:] != b'\0'*8 or (kind, machine, version) != (3, 62, 1)
            or header[7] != 0 or header[8] != 64 or header[9] != 56
            or not 1 <= header[10] <= 128 or header[11] != 64
            or not 1 <= header[12] <= MAX_SECTIONS or not 0 < header[13] < header[12]):
        raise ValueError('Known ordinary ELF64 x86-64 shared-library layout required')
    region(header[5], header[10]*56)
    region(header[6], header[12]*64)
    loads = []
    for index in range(header[10]):
        part = unpack('<IIQQQQQQ', header[5]+index*56)
        if part[0] == 1:
            if part[5] > part[6] or part[3]+part[6] >= 2**64:
                raise ValueError('Bounded loadable ELF memory range required')
            region(part[2], part[5])
            loads.append(part)
    if not loads:
        raise ValueError('File-backed loadable ELF segments required')

    def virtual(address, count, *, writable=None):
        found = [part for part in loads if part[3] <= address
                 and address+count <= part[3]+part[5]]
        if len(found) != 1 or count <= 0:
            raise ValueError('Unique file-backed ELF pointer mapping required')
        part = found[0]
        if not part[1] & 4 or (writable is not None and bool(part[1] & 2) != writable):
            raise ValueError('Expected ELF data/string segment permissions required')
        return region(part[2]+address-part[3], count)

    sections = []
    for index in range(header[12]):
        section = unpack('<IIQQQQIIQQ', header[6]+index*64)
        if section[1] != 8:
            region(section[4], section[5])
        if section[1] in {9, 19} and section[5]:
            raise ValueError('Packed or implicit-addend ELF relocations unsupported')
        sections.append(section)
    if sections[header[13]][1] != 3:
        raise ValueError('Ordinary ELF section-name string table required')
    symbols, relocations, symbol_count = [], {}, 0
    for section in sections:
        if section[1] == 11:
            symbol_count += section[5]//24
            if (section[9] != 24 or section[5] % 24
                    or symbol_count > MAX_SYMBOLS or not 0 < section[6] < len(sections)):
                raise ValueError('Bounded ordinary dynamic symbol table required')
            strings = sections[section[6]]
            if strings[1] != 3:
                raise ValueError('Dynamic symbol names require a string table')
            table = region(strings[4], strings[5])
            if (virtual(section[3], section[5], writable=False) !=
                    region(section[4], section[5])
                    or virtual(strings[3], strings[5], writable=False) != table):
                raise ValueError('Runtime and file symbol tables must agree')
            for offset in range(section[4], section[4]+section[5], 24):
                symbol = unpack('<IBBHQQ', offset)
                start = symbol[0]
                end = table.find(b'\0', start, start+4097)
                if not 0 <= start < len(table) or end < start:
                    raise ValueError('Bounded terminated ELF symbol name required')
                if table[start:end] == b'comp_list':
                    symbols.append(symbol)
        if section[1] == 4:
            if section[9] != 24 or section[5] % 24:
                raise ValueError('Ordinary explicit-addend ELF relocations required')
            if len(relocations)+section[5]//24 > MAX_RELOCATIONS:
                raise ValueError('ELF relocation count budget')
            for offset in range(section[4], section[4]+section[5], 24):
                address, info, addend = unpack('<QQq', offset)
                if address in relocations:
                    raise ValueError('Duplicate ELF relocation target')
                relocations[address] = (info, addend)
    if len(symbols) != 1:
        raise ValueError('One exported compression table definition required')
    symbol = symbols[0]
    _, info, visibility, section_index, address, size = symbol
    if (info != 17 or visibility != 0 or not 0 < section_index < len(sections)
            or not 24 <= size <= 17*24 or size % 24):
        raise ValueError('Bounded defined global compression data object required')
    section = sections[section_index]
    if (section[1] != 1 or section[2] & 7 != 3 or address < section[3]
            or address+size > section[3]+section[5]
            or virtual(address, size, writable=True) !=
            region(section[4]+address-section[3], size)):
        raise ValueError('Compression table must occupy mapped writable data')

    def c_string(pointer, maximum):
        value = bytearray()
        for index in range(maximum+1):
            char = virtual(pointer+index, 1, writable=False)
            if char == b'\0':
                if not value:
                    raise ValueError('Nonempty compression strings required')
                return bytes(value)
            value.extend(char)
        raise ValueError('Compression string byte budget')

    rows, allowed_relocations, extensions = [], set(), set()
    terminated = False
    for index in range(size//24):
        base = address+24*index
        program, extension, stem = struct.unpack('<QQQ', virtual(base, 24, writable=True))
        if (program, extension, stem) == (0, 0, 0):
            if index != size//24-1:
                raise ValueError('Only the final compression record may terminate the table')
            terminated = True
            break
        if stem != 0 or not program or not extension or index == size//24-1:
            raise ValueError('Initialized compression strings and final null sentinel required')
        for offset, pointer in ((base, program), (base+8, extension)):
            if relocations.get(offset) != (8, pointer):
                raise ValueError('Direct ordinary relative pointer relocation required')
            allowed_relocations.add(offset)
        program_bytes = c_string(program, 511)
        extension_bytes = c_string(extension, 8)
        if not re.fullmatch(rb'[A-Za-z0-9]{1,8}', extension_bytes):
            raise ValueError('Bounded compression extension required')
        if extension_bytes in extensions:
            raise ValueError('Unique compression extensions required')
        extensions.add(extension_bytes)
        rows.append(dict(extension=extension_bytes.decode('ascii'),
            program_base64=base64.b64encode(program_bytes).decode(),
            program_bytes=len(program_bytes),
            program_sha256=hashlib.sha256(program_bytes).hexdigest(),
            program_relocation_offset=base, extension_relocation_offset=base+8,
            initial_stem_is_null=True))
    affected = {offset for offset in relocations if address-7 <= offset < address+size}
    if not terminated or affected != allowed_relocations:
        raise ValueError('Compression table may have no other relocation writes')
    return dict(profile=PROFILE, library_bytes=len(raw),
        library_sha256=hashlib.sha256(raw).hexdigest(),
        symbol='comp_list', symbol_virtual_address=address, symbol_bytes=size, rows=rows,
        configured_extensions=[row['extension'] for row in rows], static_initializers_verified=True,
        library_loaded_or_executed=False, runtime_loader_symbol_resolution_verified=False,
        program_search_paths_verified=False, program_execution_authorized=False,
        source_reference_resolution_verified=False, full_source_semantics_verified=False,
        generated_state_validated=False, changes_authorized=False, publication_authorized=False)
