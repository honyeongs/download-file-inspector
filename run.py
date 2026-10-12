"""Run directly from a checkout without installing packages."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from download_inspector.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
