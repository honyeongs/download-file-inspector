import io
import stat
import struct
import zipfile

from .policy import Limits
from .rules import Findings, inspect_name, portable_name
from .zip_preflight import ZipEnvelopeError, preflight


def _local_span(data: bytes, info: zipfile.ZipInfo, central: int) -> tuple[int, int]:
    offset = info.header_offset
    if offset < 0 or offset + 30 > central or data[offset:offset + 4] != b"PK\x03\x04":
        raise ValueError("Missing or out-of-range local ZIP header.")
    flags, method = struct.unpack_from("<2H", data, offset + 6)
    name_size, extra_size = struct.unpack_from("<2H", data, offset + 26)
    body = offset + 30 + name_size + extra_size
    end = body + info.compress_size
    if body > central or end > central:
        raise ValueError("ZIP member exceeds the data region.")
    raw_name = data[offset + 30:offset + 30 + name_size]
    name = raw_name.decode("utf-8" if flags & 0x800 else "cp437")
    if name != info.orig_filename or flags != info.flag_bits or method != info.compress_type:
        raise ValueError("Local and central ZIP headers disagree.")
    if not flags & 8:
        crc, compressed, expanded = struct.unpack_from("<3I", data, offset + 14)
        if crc != info.CRC or (compressed != 0xFFFFFFFF and compressed != info.compress_size) or (expanded != 0xFFFFFFFF and expanded != info.file_size):
            raise ValueError("Local and central ZIP size or CRC declarations disagree.")
    return offset, end


def inspect_zip(data: bytes, findings: Findings, limits: Limits) -> dict:
    result = dict(is_zip=True, status="metadata_checked", members=[], entries=0,
                  total_uncompressed_bytes=0, content_check="not_performed", crc_check="not_performed")
    try:
        central, declared_count = preflight(data, limits)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > limits.entries:
                raise ZipEnvelopeError("limit_exceeded", "Too many ZIP entries.")
            if len(entries) != declared_count:
                raise ValueError("ZIP parser and envelope entry count disagree.")
            spans, names, portable = [], set(), set()
            expanded, compressed = 0, 0
            for info in entries:
                name = info.orig_filename
                inspect_name(name, findings, archive=True)
                canonical = portable_name(name)
                if name in names:
                    findings.add("ZIP_DUPLICATE", "medium", "Duplicate member name.", name)
                elif canonical in portable:
                    findings.add("ZIP_NAME_COLLISION", "medium", "Names collide on common filesystems.", name)
                names.add(name)
                portable.add(canonical)
                if info.flag_bits & 1:
                    findings.add("ZIP_ENCRYPTED", "medium", "Encrypted member content was not inspected.", name)
                mode = stat.S_IFMT(info.external_attr >> 16)
                if mode not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    findings.add("ZIP_SPECIAL_FILE", "high", "Symbolic link or special filesystem entry.", name)
                if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA}:
                    findings.add("ZIP_COMPRESSION_UNSUPPORTED", "medium", "Compression method is not supported.", name)
                ratio = info.file_size / max(info.compress_size, 1)
                if info.file_size > limits.member_bytes or (info.file_size >= 1024 * 1024 and ratio > limits.ratio):
                    findings.add("ZIP_EXPANSION", "high", "Declared member size or compression ratio exceeds policy.", name)
                expanded += info.file_size
                compressed += info.compress_size
                spans.append(_local_span(data, info, central))
                result["members"].append(dict(name=name, size_bytes=info.file_size,
                                              compressed_bytes=info.compress_size, encrypted=bool(info.flag_bits & 1),
                                              compression_method=info.compress_type))
            result.update(entries=len(entries), total_uncompressed_bytes=expanded,
                          compression_ratio=round(expanded / max(compressed, 1), 2))
            if expanded > limits.expanded_bytes or (expanded >= 1024 * 1024 and expanded / max(compressed, 1) > limits.ratio):
                findings.add("ZIP_TOTAL_EXPANSION", "high", "Declared aggregate ZIP expansion exceeds policy.")
            spans.sort()
            furthest = 0
            for begin, end in spans:
                if begin < furthest:
                    findings.add("ZIP_OVERLAP", "high", "ZIP members overlap in the data region.")
                    break
                furthest = max(furthest, end)
            if spans and spans[0][0] > 0:
                findings.add("ZIP_PREFIX", "medium", "ZIP contains an uninspected prefix or executable wrapper.")
    except ZipEnvelopeError as exc:
        result["status"] = exc.status
        findings.add("ZIP_INCOMPLETE", "high", str(exc))
    except (ValueError, OSError, zipfile.BadZipFile, NotImplementedError, struct.error, UnicodeError):
        result["status"] = "invalid"
        findings.add("ZIP_INVALID", "high", "Malformed or inconsistent ZIP metadata; inspection is incomplete.")
    return result
