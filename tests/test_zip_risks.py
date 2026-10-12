import io
import stat
import struct
import unittest
import warnings
import zipfile

from download_inspector.inspection import exit_status, inspect_bytes
from download_inspector.policy import Limits
from .fixtures import make_zip, patch_u16, patch_u32


class ZipRiskTests(unittest.TestCase):
    def scan(self, data, name="sample.zip", limits=Limits()):
        return inspect_bytes(data, name, limits=limits)

    def codes(self, report):
        return {finding["code"] for finding in report["findings"]}

    def test_benign_metadata(self):
        report = self.scan(make_zip())
        self.assertEqual(report["archive"]["status"], "metadata_checked")
        self.assertEqual(report["archive"]["entries"], 1)
        self.assertEqual(exit_status(report), 0)

    def test_paths(self):
        for name in ["../escape.txt", "a/../../escape", "..\\escape", "/root.txt", "C:\\test", "\\\\server\\file"]:
            with self.subTest(name=name):
                self.assertIn("ZIP_PATH_ESCAPE", self.codes(self.scan(make_zip([(name, b"x")]))))

    def test_portable_paths(self):
        for name, code in [("readme.txt:payload", "ZIP_WINDOWS_STREAM"), ("CON.txt", "ZIP_AMBIGUOUS_PATH"),
                           ("a. /b", "ZIP_AMBIGUOUS_PATH")]:
            self.assertIn(code, self.codes(self.scan(make_zip([(name, b"x")]))))

    def test_nested_and_macros(self):
        report = self.scan(make_zip([("inner.zip", b"not actually zip"), ("sheet.xlsm", b"synthetic")]))
        self.assertTrue({"NESTED_ARCHIVE", "MACRO_DOCUMENT"} <= self.codes(report))

    def test_duplicate(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            data = make_zip([("same", b"1"), ("same", b"2")])
        self.assertIn("ZIP_DUPLICATE", self.codes(self.scan(data)))

    def test_colliding(self):
        self.assertIn("ZIP_NAME_COLLISION", self.codes(self.scan(make_zip([("A.txt", b"1"), ("a.txt", b"2")]))))

    def test_symlink(self):
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.assertIn("ZIP_SPECIAL_FILE", self.codes(self.scan(make_zip([(info, b"../outside")]))))

    def test_encryption(self):
        data = make_zip()
        central = data.index(b"PK\x01\x02")
        data = patch_u16(patch_u16(data, 6, 1), central + 8, 1)
        self.assertIn("ZIP_ENCRYPTED", self.codes(self.scan(data)))

    def test_compression_method(self):
        data = make_zip()
        central = data.index(b"PK\x01\x02")
        data = patch_u16(patch_u16(data, 8, 99), central + 10, 99)
        self.assertIn("ZIP_COMPRESSION_UNSUPPORTED", self.codes(self.scan(data)))

    def test_ratio(self):
        data = make_zip([("large.txt", b"0" * (2 * 1024 * 1024))], zipfile.ZIP_DEFLATED)
        self.assertIn("ZIP_EXPANSION", self.codes(self.scan(data)))

    def test_declared_size(self):
        data = make_zip()
        central = data.index(b"PK\x01\x02")
        data = patch_u32(data, central + 24, 1024 * 1024 * 1024)
        data = patch_u32(data, 22, 1024 * 1024 * 1024)
        self.assertIn("ZIP_TOTAL_EXPANSION", self.codes(self.scan(data)))

    def test_header_disagreement(self):
        data = make_zip()
        report = self.scan(patch_u16(data, 8, 99))
        self.assertEqual(report["archive"]["status"], "invalid")
        self.assertEqual(exit_status(report), 3)

    def test_crc_declaration_disagreement(self):
        self.assertEqual(self.scan(patch_u32(make_zip(), 14, 0))["archive"]["status"], "invalid")

    def test_member_outside_data(self):
        data = make_zip()
        central = data.index(b"PK\x01\x02")
        self.assertEqual(self.scan(patch_u32(data, central + 20, 0xFFFFFFF))["archive"]["status"], "invalid")

    def test_invalid_and_truncated(self):
        for data in [b"not a zip", make_zip()[:-10], b"PK\x03\x04broken"]:
            with self.subTest(size=len(data)):
                self.assertEqual(self.scan(data)["archive"]["status"], "invalid")

    def test_entry_count_tampering(self):
        data = make_zip()
        eocd = data.rfind(b"PK\x05\x06")
        data = patch_u16(patch_u16(data, eocd + 8, 0), eocd + 10, 0)
        self.assertEqual(self.scan(data)["archive"]["status"], "invalid")

    def test_entry_limit(self):
        data = make_zip([("a", b"x"), ("b", b"y")])
        self.assertEqual(self.scan(data, limits=Limits(entries=1))["archive"]["status"], "limit_exceeded")

    def test_central_byte_limit(self):
        self.assertEqual(self.scan(make_zip(), limits=Limits(central_bytes=1))["archive"]["status"], "limit_exceeded")

    def test_multidisk_and_zip64(self):
        data = make_zip()
        eocd = data.rfind(b"PK\x05\x06")
        self.assertEqual(self.scan(patch_u16(data, eocd + 4, 1))["archive"]["status"], "unsupported")
        self.assertEqual(self.scan(patch_u32(data, eocd + 12, 0xFFFFFFFF))["archive"]["status"], "unsupported")

    def test_crc_not_claimed(self):
        data = bytearray(make_zip())
        data[30 + len("readme.txt")] ^= 1
        report = self.scan(bytes(data))
        self.assertEqual(report["archive"]["status"], "metadata_checked")
        self.assertEqual(report["archive"]["crc_check"], "not_performed")

    def test_no_decompression_or_extraction(self):
        from unittest.mock import patch
        data = make_zip()
        with patch.object(zipfile.ZipFile, "open", side_effect=AssertionError("No payload reads")), \
             patch.object(zipfile.ZipFile, "extractall", side_effect=AssertionError("No extraction")):
            self.assertEqual(self.scan(data)["archive"]["status"], "metadata_checked")

    def test_zip_disguised_as_text_and_sfx(self):
        self.assertTrue(self.scan(make_zip(), "file.txt")["archive"]["is_zip"])
        report = self.scan(b"MZsynthetic wrapper" + make_zip(), "setup.exe")
        self.assertEqual(report["archive"]["status"], "metadata_checked")
        self.assertIn("ZIP_PREFIX", self.codes(report))

    def test_bounded_findings(self):
        report = self.scan(make_zip([("../a.exe", b"x"), ("../b.exe", b"x")]), limits=Limits(findings=1))
        self.assertEqual(len(report["findings"]), 1)
        self.assertTrue(report["findings_truncated"])
        self.assertEqual(report["assessment"]["risk"], "high")

    def test_empty_zip(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w"):
            pass
        self.assertEqual(self.scan(stream.getvalue())["archive"]["entries"], 0)

    def test_malformed_utf8(self):
        data = make_zip([("a.txt", b"x")])
        central = data.index(b"PK\x01\x02")
        data = bytearray(patch_u16(data, central + 8, 0x800))
        data[central + 46] = 0xFF
        self.assertEqual(self.scan(bytes(data))["archive"]["status"], "invalid")

    def test_overlapping_members(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            data = make_zip([("same", b"x"), ("same", b"x")])
        first = data.index(b"PK\x01\x02")
        second = data.index(b"PK\x01\x02", first + 4)
        data = patch_u32(data, second + 42, 0)
        self.assertIn("ZIP_OVERLAP", self.codes(self.scan(data)))

    def test_data_descriptor_archive(self):
        class Unseekable(io.BytesIO):
            def seekable(self):
                return False

            def seek(self, *args):
                raise OSError("Synthetic unseekable stream")

        stream = Unseekable()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("sample.txt", b"synthetic")
        self.assertEqual(self.scan(stream.getvalue())["archive"]["status"], "metadata_checked")

    def test_zip_comment(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("sample.txt", b"synthetic")
            archive.comment = b"synthetic comment"
        self.assertEqual(self.scan(stream.getvalue())["archive"]["status"], "metadata_checked")

    def test_mutated_metadata_does_not_crash(self):
        import random
        rng = random.Random(73)
        original = make_zip([("sample.txt", b"synthetic")])
        for _ in range(500):
            data = bytearray(original)
            for _ in range(rng.randrange(1, 5)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            report = self.scan(bytes(data))
            self.assertIsNone(report["assessment"]["safe_to_open"])
