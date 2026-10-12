from pathlib import PurePosixPath

from .archive import inspect_zip
from .hashing import InspectionError, expected_digest, sha256
from .policy import DEFAULT_LIMITS, Limits
from .rules import Findings, ZIP_TYPES, inspect_name
from .signatures import inspect_type


def inspect_bytes(data: bytes, name: str, expected: str | None = None, limits: Limits = DEFAULT_LIMITS) -> dict:
    if not isinstance(data, bytes):
        raise InspectionError("Inspection requires an immutable byte snapshot.")
    if len(data) > limits.file_bytes:
        raise InspectionError("File exceeds the inspection limit.")
    if not name or len(name) > 1024:
        raise InspectionError("Filename must contain 1 to 1024 characters.")
    expected = expected_digest(expected)
    digest = sha256(data)
    integrity = "not_provided" if expected is None else "match" if expected == digest else "mismatch"
    findings = Findings(limits.findings)
    inspect_name(name, findings)
    kind = inspect_type(data, name, findings)
    ext = PurePosixPath(name.replace("\\", "/")).suffix.lower()
    # Signature detection only; the bounded envelope must precede ZIP parsing.
    is_zip = data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")) or b"PK\x05\x06" in data[-65557:]
    archive = dict(is_zip=False, status="not_applicable", members=[], entries=0,
                   content_check="not_performed", crc_check="not_performed")
    if is_zip or ext in ZIP_TYPES:
        archive = inspect_zip(data, findings, limits)
        if kind == "unknown":
            kind = "zip" if is_zip else "unknown"
    if integrity == "mismatch":
        findings.add("HASH_MISMATCH", "high", "Bytes differ from the supplied reference; cause and maliciousness are unknown.")
    return dict(schema_version="1.0", file=dict(name=name, size_bytes=len(data), sha256=digest,
                detected_type=kind, extension=ext), integrity=dict(status=integrity, expected_sha256=expected,
                algorithm="sha256", reference_trust="caller_supplied"),
                assessment=dict(risk=findings.highest if findings.count else "no_indicators",
                                indicator_count=findings.count, antivirus="not_performed", safe_to_open=None),
                archive=archive, findings=findings.items, finding_count=findings.count,
                findings_truncated=findings.count > len(findings.items))


def exit_status(report: dict) -> int:
    if report["archive"]["status"] not in {"metadata_checked", "not_applicable"}:
        return 3
    return int(report["integrity"]["status"] == "mismatch" or report["assessment"]["risk"] == "high")
