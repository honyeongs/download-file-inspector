import argparse
import json
import sys
from pathlib import Path

from .hashing import InspectionError, read_snapshot, sha256
from .inspection import exit_status, inspect_bytes


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Local file inspection; not an antivirus.")
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="Compare SHA-256 and inspect ZIP risk indicators")
    inspect.add_argument("file", type=Path)
    inspect.add_argument("--sha256")
    inspect.add_argument("--output", type=Path, help="Create a new JSON report; never overwrite")
    hash_command = commands.add_parser("hash", help="Calculate a hash, without verifying authenticity")
    hash_command.add_argument("file", type=Path)
    serve = commands.add_parser("serve", help="Start a loopback-only web interface")
    serve.add_argument("--port", type=int, default=8893)
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            from .server import serve_local
            serve_local(args.port)
            return 0
        data = read_snapshot(args.file)
        if args.command == "hash":
            print(sha256(data))
            return 0
        report = inspect_bytes(data, args.file.name, args.sha256)
        output = json.dumps(report, ensure_ascii=True, indent=2) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(output)
        else:
            print(output, end="")
        return exit_status(report)
    except (InspectionError, OSError, ValueError) as exc:
        # Avoid leaking absolute paths or other local context in reports and logs.
        message = str(exc) if isinstance(exc, InspectionError) else type(exc).__name__
        print("Inspection failed: " + message, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
