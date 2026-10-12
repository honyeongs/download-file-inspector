import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from download_inspector.cli import main
from .fixtures import make_zip


class CliTests(unittest.TestCase):
    def test_report_and_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "file.zip"
            path.write_bytes(make_zip())
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["inspect", str(path)]), 0)
            report = json.loads(stdout.getvalue())
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["hash", str(path)]), 0)
            self.assertEqual(stdout.getvalue().strip(), report["file"]["sha256"])

    def test_output_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.txt"
            path.write_bytes(b"original")
            output = Path(directory) / "report.json"
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["inspect", str(path), "--output", str(path)]), 2)
                self.assertEqual(main(["inspect", str(path), "--output", str(output)]), 0)
                self.assertEqual(main(["inspect", str(path), "--output", str(output)]), 2)
            self.assertEqual(path.read_bytes(), b"original")
            self.assertEqual(json.loads(output.read_text())["file"]["name"], "input.txt")

    def test_invalid_input(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["inspect", "no-such-file.zip"]), 2)

    def test_report_contains_no_absolute_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample"
            path.write_bytes(b"x")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                main(["inspect", str(path)])
            self.assertNotIn(directory, stdout.getvalue())
