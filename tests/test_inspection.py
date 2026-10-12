import hashlib
import tempfile
import unittest
from pathlib import Path

from download_inspector.hashing import InspectionError, read_snapshot
from download_inspector.inspection import exit_status, inspect_bytes
from download_inspector.policy import Limits
from .fixtures import make_zip


class InspectionTests(unittest.TestCase):
    def test_hash_match_is_not_safety(self):
        data = make_zip()
        result = inspect_bytes(data, "release.zip", hashlib.sha256(data).hexdigest().upper())
        self.assertEqual(result["integrity"]["status"], "match")
        self.assertIsNone(result["assessment"]["safe_to_open"])
        self.assertEqual(result["assessment"]["antivirus"], "not_performed")
        self.assertEqual(result["archive"]["crc_check"], "not_performed")

    def test_missing_hash(self):
        self.assertEqual(inspect_bytes(b"sample", "sample.txt")["integrity"]["status"], "not_provided")

    def test_mismatch(self):
        result = inspect_bytes(b"sample", "sample.txt", "0" * 64)
        self.assertEqual(result["integrity"]["status"], "mismatch")
        self.assertEqual(exit_status(result), 1)

    def test_invalid_digest(self):
        for value in ["a" * 63, "g" * 64, "0" * 65, "가" * 64]:
            with self.subTest(value=value), self.assertRaises(InspectionError):
                inspect_bytes(b"x", "test.txt", value)

    def test_limit(self):
        with self.assertRaises(InspectionError):
            inspect_bytes(b"abcd", "test", limits=Limits(file_bytes=3))

    def test_immutable(self):
        with self.assertRaises(InspectionError):
            inspect_bytes(bytearray(b"x"), "test")

    def test_executable_signature_and_disguise(self):
        result = inspect_bytes(b"MZsynthetic", "invoice.pdf.exe")
        codes = {f["code"] for f in result["findings"]}
        self.assertTrue({"EXECUTABLE_SIGNATURE", "DISGUISED_EXECUTABLE"} <= codes)

    def test_type_mismatch(self):
        self.assertEqual(inspect_bytes(b"not a pdf", "sample.pdf")["findings"][0]["code"], "TYPE_MISMATCH")

    def test_bidi_filename(self):
        self.assertIn("NAME_CONTROL", {f["code"] for f in inspect_bytes(b"x", "file\u202etxt")["findings"]})

    def test_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "file.txt"
            path.write_bytes(b"abc")
            self.assertEqual(read_snapshot(path), b"abc")
            with self.assertRaises(InspectionError):
                read_snapshot(path, Limits(file_bytes=1))
            with self.assertRaises(InspectionError):
                read_snapshot(Path(folder))

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "source"
            path.write_bytes(b"x")
            link = Path(folder) / "link"
            try:
                link.symlink_to(path)
            except OSError:
                self.skipTest("Symlink permission unavailable")
            with self.assertRaises(InspectionError):
                read_snapshot(link)

    def test_unknown_and_empty(self):
        for data in [b"", b"random bytes"]:
            result = inspect_bytes(data, "file.bin")
            self.assertEqual(result["file"]["detected_type"], "unknown")
            self.assertEqual(result["archive"]["status"], "not_applicable")

    def test_name_limits(self):
        for name in ["", "x" * 1025]:
            with self.assertRaises(InspectionError):
                inspect_bytes(b"x", name)
