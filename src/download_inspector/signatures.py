from pathlib import PurePosixPath

from .rules import Findings


def detect_type(data: bytes) -> str:
    signatures = [(b"MZ", "windows-executable"), (b"\x7fELF", "elf-executable"),
                  (b"%PDF-", "pdf"), (b"\x89PNG\r\n\x1a\n", "png"),
                  (b"\xff\xd8\xff", "jpeg"), (b"\xd0\xcf\x11\xe0", "ole-container")]
    for magic, label in signatures:
        if data.startswith(magic):
            return label
    return "unknown"


def inspect_type(data: bytes, name: str, findings: Findings) -> str:
    kind = detect_type(data)
    ext = PurePosixPath(name).suffix.lower()
    if kind in {"windows-executable", "elf-executable"}:
        findings.add("EXECUTABLE_SIGNATURE", "high", "Executable file signature; origin must be verified.")
    expected = {".pdf": "pdf", ".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".exe": "windows-executable"}
    if ext in expected and kind != expected[ext]:
        findings.add("TYPE_MISMATCH", "medium", "Extension does not match the shallow file signature.")
    return kind
