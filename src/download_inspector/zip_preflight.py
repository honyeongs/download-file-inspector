"""Bound central-directory allocation before handing ZIP semantics to zipfile."""
import struct

from .policy import Limits


class ZipEnvelopeError(ValueError):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status


def preflight(data: bytes, limits: Limits) -> tuple[int, int]:
    start = max(0, len(data) - 65557)
    position = len(data)
    eocd = -1
    while position > start:
        position = data.rfind(b"PK\x05\x06", start, position)
        if position < 0:
            break
        if position + 22 <= len(data):
            comment_size = struct.unpack_from("<H", data, position + 20)[0]
            if position + 22 + comment_size == len(data):
                eocd = position
                break
    if eocd < 0:
        raise ZipEnvelopeError("invalid", "Missing or inconsistent ZIP end record.")
    _, disk, central_disk, count_disk, count, size, offset, _ = struct.unpack_from("<4s4H2IH", data, eocd)
    if disk or central_disk or count_disk != count:
        raise ZipEnvelopeError("unsupported", "Multi-disk ZIP is not supported.")
    if count == 65535 or size == 0xFFFFFFFF or offset == 0xFFFFFFFF:
        raise ZipEnvelopeError("unsupported", "ZIP64 central directories are not supported by this bounded inspector.")
    if count > limits.entries or size > limits.central_bytes:
        raise ZipEnvelopeError("limit_exceeded", "ZIP metadata exceeds inspection limits.")
    central = eocd - size
    if central < 0 or central - offset < 0:
        raise ZipEnvelopeError("invalid", "Invalid ZIP central-directory location.")
    cursor, actual = central, 0
    while cursor < eocd:
        if cursor + 46 > eocd or data[cursor:cursor + 4] != b"PK\x01\x02":
            raise ZipEnvelopeError("invalid", "Invalid central-directory envelope.")
        lengths = struct.unpack_from("<3H", data, cursor + 28)
        cursor += 46 + sum(lengths)
        actual += 1
        if actual > limits.entries:
            raise ZipEnvelopeError("limit_exceeded", "Too many ZIP entries.")
        if cursor > eocd:
            raise ZipEnvelopeError("invalid", "Truncated central-directory entry.")
    if actual != count:
        raise ZipEnvelopeError("invalid", "ZIP entry count is inconsistent.")
    return central, count
