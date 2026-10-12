import re
import unicodedata
from pathlib import PurePosixPath

EXECUTABLES = {".exe", ".dll", ".com", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".sh",
               ".vbs", ".js", ".hta", ".lnk", ".sys", ".jar", ".apk", ".app", ".desktop"}
ARCHIVES = {".zip", ".7z", ".rar", ".tar", ".gz", ".xz", ".bz2", ".zipx"}
ZIP_TYPES = {".zip", ".zipx", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".epub", ".odt"}
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


class Findings:
    def __init__(self, limit: int):
        self.items: list[dict] = []
        self.count = 0
        self.highest = "info"
        self.limit = limit

    def add(self, code: str, severity: str, message: str, member: str | None = None):
        self.count += 1
        if RANK[severity] > RANK[self.highest]:
            self.highest = severity
        if len(self.items) < self.limit:
            self.items.append(dict(code=code, severity=severity, message=message, member=member))


def portable_name(name: str) -> str:
    return "/".join(part.rstrip(" .") for part in unicodedata.normalize("NFKC", name)
                    .replace("\\", "/").casefold().split("/"))


def inspect_name(name: str, findings: Findings, *, archive: bool = False):
    normalized = name.replace("\\", "/")
    parts = normalized.split("/")
    suffix = PurePosixPath(normalized).suffix.lower()
    if archive and (normalized.startswith("/") or re.match(r"^[a-zA-Z]:", normalized)
                    or ".." in parts):
        findings.add("ZIP_PATH_ESCAPE", "high", "Absolute or parent-relative archive path.", name)
    if archive and any(":" in part for part in parts):
        findings.add("ZIP_WINDOWS_STREAM", "high", "Windows drive or alternate data stream path.", name)
    if archive and any(re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", p)
                       or p.endswith((" ", ".")) for p in parts if p):
        findings.add("ZIP_AMBIGUOUS_PATH", "medium", "Reserved or ambiguous portable filename.", name)
    if any(unicodedata.category(c) in {"Cc", "Cf"} for c in name):
        findings.add("NAME_CONTROL", "medium", "Filename contains control or direction-changing characters.", name)
    if suffix in EXECUTABLES:
        findings.add("EXECUTABLE_NAME", "medium", "Executable or script extension; not proof of malware.", name)
        if re.search(r"(?i)\.(pdf|jpg|png|txt|docx|xlsx)\.[^.]+$", normalized):
            findings.add("DISGUISED_EXECUTABLE", "high", "Document-looking double extension on executable.", name)
    if suffix in {".docm", ".xlsm", ".pptm"}:
        findings.add("MACRO_DOCUMENT", "medium", "Macro-enabled document extension.", name)
    if archive and suffix in ARCHIVES:
        findings.add("NESTED_ARCHIVE", "medium", "Nested archive was not recursively inspected.", name)
