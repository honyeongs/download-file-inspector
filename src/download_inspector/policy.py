from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    file_bytes: int = 64 * 1024 * 1024
    central_bytes: int = 1024 * 1024
    entries: int = 3000
    member_bytes: int = 128 * 1024 * 1024
    expanded_bytes: int = 512 * 1024 * 1024
    ratio: int = 100
    findings: int = 500


DEFAULT_LIMITS = Limits()
