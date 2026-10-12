"""Inspect real project files without walking private folders or executing content."""
import hashlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from download_inspector.hashing import read_snapshot
from download_inspector.inspection import inspect_bytes

ROOT = Path(__file__).resolve().parents[1]


class ProjectFileTests(unittest.TestCase):
    def test_actual_readme_copy_and_mutation(self):
        original = read_snapshot(ROOT / "README.md")
        reference = hashlib.sha256(original).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            copy = Path(folder) / "project-document.md"
            copy.write_bytes(original)
            matched = inspect_bytes(read_snapshot(copy), copy.name, reference)
            self.assertEqual(matched["integrity"]["status"], "match")
            copy.write_bytes(original + b"\nCONTROLLED_LOCAL_TEST_MUTATION\n")
            changed = inspect_bytes(read_snapshot(copy), copy.name, reference)
            self.assertEqual(changed["integrity"]["status"], "mismatch")
            self.assertIsNone(changed["assessment"]["safe_to_open"])
        self.assertEqual(hashlib.sha256(read_snapshot(ROOT / "README.md")).hexdigest(), reference)

    def test_zip_of_actual_project_sources(self):
        source_paths = ("run.py", "src/download_inspector/inspection.py", "src/download_inspector/hashing.py")
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name in source_paths:
                info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, read_snapshot(ROOT / name))
        original = stream.getvalue()
        with tempfile.TemporaryDirectory() as folder:
            package = Path(folder) / "project-sources.zip"
            package.write_bytes(original)
            report = inspect_bytes(read_snapshot(package), package.name, hashlib.sha256(original).hexdigest())
        self.assertEqual(report["integrity"]["status"], "match")
        self.assertEqual(report["archive"]["status"], "metadata_checked")
        self.assertEqual(report["archive"]["entries"], len(source_paths))
        self.assertIsNone(report["assessment"]["safe_to_open"])
        self.assertEqual(report["archive"]["crc_check"], "not_performed")
