import hashlib
import os
import re
import stat
from pathlib import Path

from .policy import DEFAULT_LIMITS, Limits


class InspectionError(ValueError):
    pass


def expected_digest(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    value = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise InspectionError("Expected SHA-256 must contain exactly 64 hexadecimal characters.")
    return value


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_snapshot(path: Path, limits: Limits = DEFAULT_LIMITS) -> bytes:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise InspectionError("Only regular files are accepted; symlinks and devices are rejected.")
    if before.st_size > limits.file_bytes:
        raise InspectionError("File exceeds the 64 MiB inspection limit.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise InspectionError("Only regular files are accepted.")
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise InspectionError("File changed while opening it; retry with a stable copy.")
        data = handle.read(limits.file_bytes + 1)
        after = os.fstat(handle.fileno())
    if len(data) > limits.file_bytes:
        raise InspectionError("File exceeds the inspection limit.")
    if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise InspectionError("File changed during inspection; retry with a stable copy.")
    return data
