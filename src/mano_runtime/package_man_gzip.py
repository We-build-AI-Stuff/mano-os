"""Bounded gzip framing for a future unprivileged manual-content worker.

RFC 1952 headers and trailers are checked explicitly; raw DEFLATE uses zlib
with a nonzero output ceiling. Never call this on staged data from a Root
controller or the Mac. Portable tests use only self-created synthetic streams.
Header names/comments are inert bytes, never filesystem paths or timestamps
for source-authority decisions. This does not interpret roff or grant authority.
"""
import binascii
import hashlib
import zlib

MAX_INPUT_BYTES = 1024**2
MAX_EXPANDED_BYTES = 8 * 1024**2
MAX_MEMBERS = 128
MAX_PADDING_BYTES = 65536


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode(raw, *, maximum=MAX_EXPANDED_BYTES):
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT_BYTES
            or type(maximum) is not int or not 0 <= maximum <= MAX_EXPANDED_BYTES):
        raise ValueError('Bounded gzip input and nonnegative expanded limit required')
    cursor, total, padding = 0, 0, 0
    members, chunks, padding_regions = [], [], []

    def available(count):
        if count < 0 or cursor + count > len(raw):
            raise ValueError('Truncated gzip frame')

    while cursor < len(raw):
        if members and raw[cursor] == 0:
            start = cursor
            while cursor < len(raw) and raw[cursor] == 0:
                cursor += 1
            padding += cursor - start
            if padding > MAX_PADDING_BYTES:
                raise ValueError('Gzip zero-padding budget')
            padding_regions.append(dict(offset=start, bytes=cursor-start))
            if cursor == len(raw):
                break
        if len(members) >= MAX_MEMBERS:
            raise ValueError('Gzip member-count budget')
        start = cursor
        available(10)
        if raw[cursor:cursor+3] != b'\x1f\x8b\x08' or raw[cursor+3] & 0xe0:
            raise ValueError('Explicit gzip DEFLATE header with zero reserved flags required')
        flags = raw[cursor+3]
        mtime = int.from_bytes(raw[cursor+4:cursor+8], 'little')
        xfl, operating_system = raw[cursor+8:cursor+10]
        cursor += 10
        fields = {}
        if flags & 4:
            available(2)
            length = int.from_bytes(raw[cursor:cursor+2], 'little')
            cursor += 2
            available(length)
            fields['extra'] = dict(bytes=length, sha256=sha(raw[cursor:cursor+length]))
            cursor += length
        for bit, name in ((8, 'original_name'), (16, 'comment')):
            if flags & bit:
                end = raw.find(b'\0', cursor)
                if end < 0:
                    raise ValueError('Terminated bounded gzip header field required')
                fields[name] = dict(bytes=end-cursor, sha256=sha(raw[cursor:end]))
                cursor = end + 1
        header_crc = None
        if flags & 2:
            available(2)
            header_crc = int.from_bytes(raw[cursor:cursor+2], 'little')
            if (binascii.crc32(raw[start:cursor]) & 0xffff) != header_crc:
                raise ValueError('Gzip header checksum mismatch')
            cursor += 2
        payload = cursor
        compressed = raw[payload:]
        inflater = zlib.decompressobj(-zlib.MAX_WBITS)
        try:
            # +1 distinguishes exact-limit success from a compressed bomb.
            # Never use flush(): its length is an initial allocation, not a cap.
            expanded = inflater.decompress(compressed, maximum-total+1)
        except zlib.error as error:
            raise ValueError('Invalid raw DEFLATE stream') from error
        if len(expanded) > maximum-total:
            raise ValueError('Expanded gzip byte budget')
        if not inflater.eof or inflater.unconsumed_tail:
            raise ValueError('Incomplete or output-limited DEFLATE stream')
        cursor = payload + len(compressed) - len(inflater.unused_data)
        if cursor <= payload:
            raise ValueError('Nonempty terminated DEFLATE frame required')
        trailer = cursor
        available(8)
        crc = int.from_bytes(raw[cursor:cursor+4], 'little')
        size = int.from_bytes(raw[cursor+4:cursor+8], 'little')
        if (binascii.crc32(expanded) & 0xffffffff) != crc or len(expanded) != size:
            raise ValueError('Gzip payload checksum or size mismatch')
        cursor += 8
        members.append(dict(offset=start, payload_offset=payload, trailer_offset=trailer,
            end_offset=cursor, header_bytes=payload-start, header_sha256=sha(raw[start:payload]),
            flags=flags, header_mtime=mtime, extra_flags=xfl, operating_system=operating_system,
            optional_fields=fields, header_crc16=header_crc,
            deflate_bytes=trailer-payload, deflate_sha256=sha(raw[payload:trailer]),
            expanded_bytes=len(expanded),
            expanded_sha256=sha(expanded), crc32=crc))
        chunks.append(expanded)
        total += len(expanded)
    if not members:
        raise ValueError('At least one complete gzip member required')
    expanded = b''.join(chunks)
    return expanded, dict(profile='bounded-gzip-members-v1', input_bytes=len(raw),
        input_sha256=sha(raw), expanded_bytes=total, expanded_sha256=sha(expanded),
        members=members, zero_padding_regions=padding_regions, zero_padding_bytes=padding,
        zero_padding_compatibility_extension=True, gzip_header_and_trailer_checks_passed=True,
        raw_deflate_implementation='zlib', zlib_runtime_version=zlib.ZLIB_RUNTIME_VERSION,
        header_names_used_as_paths=False, header_times_used_as_source_authority=False,
        extra_subfields_interpreted=False, roff_interpreted=False,
        source_declarations_verified=False, transitive_source_graph_verified=False,
        generated_state_validated=False, changes_authorized=False, publication_authorized=False)
