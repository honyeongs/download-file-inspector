import http.client
import json
import threading
import unittest
from urllib.parse import quote

from download_inspector.server import create_server
from .fixtures import make_zip


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = create_server(0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_port
        cls.origin = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def request(self, method="GET", path="/", body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def post(self, body=b"data", **headers):
        defaults = {"Origin": self.origin, "Content-Type": "application/octet-stream", "X-File-Name": "sample.txt"}
        defaults.update(headers)
        return self.request("POST", "/api/inspect", body, defaults)

    def test_assets_and_headers(self):
        for path in ["/", "/app.js", "/render.js", "/style.css", "/assets/shield-check.svg"]:
            status, headers, data = self.request(path=path)
            self.assertEqual(status, 200)
            self.assertTrue(data)
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
            self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_health(self):
        status, _, body = self.request(path="/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["max_file_bytes"], 64 * 1024 * 1024)

    def test_zip_flow(self):
        status, _, body = self.post(make_zip(), **{"X-File-Name": quote("한글.zip")})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["file"]["name"], "한글.zip")

    def test_cross_origin_rejected(self):
        self.assertEqual(self.post(Origin="https://attacker.invalid")[0], 403)
        self.assertEqual(self.request("POST", "/api/inspect", b"x", {"Content-Type": "application/octet-stream"})[0], 403)

    def test_dns_rebinding_host_rejected(self):
        self.assertEqual(self.request(headers={"Host": f"attacker.invalid:{self.port}"})[0], 403)
        self.assertEqual(self.post(Host=f"localhost:{self.port}")[0], 403)

    def test_path_traversal_and_unknown_routes(self):
        for path in ["/../pyproject.toml", "/%2e%2e/run.py", "/api/inspect?path=C:/secret", "/assets/../server.py"]:
            self.assertEqual(self.request(path=path)[0], 404)

    def test_type_limit_and_filename_validation(self):
        self.assertEqual(self.post(**{"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.post(**{"Content-Length": str(64 * 1024 * 1024 + 1)})[0], 413)
        self.assertEqual(self.post(**{"X-File-Name": "..%2Fsecret"})[0], 400)
        self.assertEqual(self.post(**{"X-Expected-SHA256": "invalid"})[0], 400)

    def test_missing_invalid_or_ambiguous_length(self):
        for length in ["-1", "not-a-number", "9" * 5000]:
            self.assertEqual(self.post(**{"Content-Length": length})[0], 411)
        self.assertEqual(self.post(**{"Transfer-Encoding": "chunked"})[0], 400)

    def test_malicious_filename_is_json_not_html(self):
        name = '<img src=x onerror="alert(1)">.txt'
        status, headers, body = self.post(**{"X-File-Name": quote(name)})
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("application/json"))
        self.assertEqual(json.loads(body)["file"]["name"], name)

    def test_empty_file(self):
        self.assertEqual(self.post(b"")[0], 200)

    def test_port_validation(self):
        with self.assertRaises(ValueError):
            create_server(65536)
