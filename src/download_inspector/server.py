"""Loopback-only, memory-only UI. Never expose this development server publicly."""
import json
import socket
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import unquote

from .hashing import InspectionError
from .inspection import inspect_bytes
from .policy import DEFAULT_LIMITS

WEB_ROOT = Path(__file__).parent / "web"
ASSETS = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/render.js": ("render.js", "text/javascript; charset=utf-8"),
          "/transport.js": ("transport.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}
for _icon in ("shield-check", "folder-open", "download", "rotate-ccw"):
    ASSETS[f"/assets/{_icon}.svg"] = (f"assets/{_icon}.svg", "image/svg+xml")


class LocalServer(HTTPServer):
    allow_reuse_address = True

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        return connection, address

    def handle_error(self, request, client_address):
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = "LocalInspector"
    sys_version = ""

    def log_message(self, format, *args):
        pass

    @property
    def origin(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def _respond(self, status, data, kind="application/json; charset=utf-8"):
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()
        # Half-close first and discard a bounded tail so rejection is not hidden by a TCP reset.
        if self.command == "POST" and not getattr(self, "body_consumed", False):
            try:
                self.connection.shutdown(socket.SHUT_WR)
                self.connection.settimeout(0.05)
                self.rfile.read1(65536)
            except (TimeoutError, OSError):
                pass

    def _json(self, status, value):
        self._respond(status, json.dumps(value, ensure_ascii=True).encode("utf-8"))

    def _host_valid(self):
        return self.headers.get_all("Host", []) == [self.origin.removeprefix("http://")]

    def do_GET(self):
        if not self._host_valid():
            return self._json(403, {"error": "Host rejected."})
        if self.path == "/api/health":
            return self._json(200, {"status": "ready", "max_file_bytes": DEFAULT_LIMITS.file_bytes})
        if self.path not in ASSETS:
            return self._json(404, {"error": "Not found."})
        filename, mime = ASSETS[self.path]
        self._respond(200, (WEB_ROOT / filename).read_bytes(), mime)

    def do_POST(self):
        if not self._host_valid() or self.headers.get_all("Origin", []) != [self.origin]:
            return self._json(403, {"error": "Only same-origin loopback requests are accepted."})
        if self.path != "/api/inspect":
            return self._json(404, {"error": "Not found."})
        if self.headers.get("Transfer-Encoding"):
            return self._json(400, {"error": "Transfer encoding is not supported."})
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or len(lengths[0]) > 10 or not lengths[0].isascii() or not lengths[0].isdecimal():
            return self._json(411, {"error": "One valid Content-Length is required."})
        length = int(lengths[0])
        if length > DEFAULT_LIMITS.file_bytes:
            return self._json(413, {"error": "File exceeds 64 MiB."})
        if self.headers.get("Content-Type") != "application/octet-stream":
            return self._json(415, {"error": "Expected application/octet-stream."})
        try:
            name = unquote(self.headers.get("X-File-Name", ""), errors="strict")
            if "/" in name or "\\" in name:
                raise InspectionError("Send a filename, not a filesystem path.")
            # read1 plus a total deadline bounds slow bodies, not only idle time.
            chunks, remaining, deadline = [], length, time.monotonic() + 20
            while remaining:
                budget = deadline - time.monotonic()
                if budget <= 0:
                    raise TimeoutError
                self.connection.settimeout(min(10, budget))
                chunk = self.rfile.read1(min(1024 * 1024, remaining))
                if not chunk:
                    return self._json(400, {"error": "Truncated request body."})
                chunks.append(chunk)
                remaining -= len(chunk)
            self.body_consumed = True
            report = inspect_bytes(b"".join(chunks), name, self.headers.get("X-Expected-SHA256"))
            self._json(200, report)
        except InspectionError as exc:
            self._json(400, {"error": str(exc)})
        except (UnicodeError, ValueError):
            self._json(400, {"error": "Invalid request metadata."})
        except (TimeoutError, socket.timeout):
            self._json(408, {"error": "Request body timeout."})


def create_server(port=8893):
    if not 0 <= port <= 65535:
        raise InspectionError("Port must be between 0 and 65535.")
    return LocalServer(("127.0.0.1", port), Handler)


def serve_local(port=8893):
    with create_server(port) as server:
        print(f"Local inspector: http://127.0.0.1:{server.server_port}/", flush=True)
        server.serve_forever(poll_interval=0.25)
