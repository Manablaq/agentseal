from __future__ import annotations

import io
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

from fixtures.bradbury.service import fixture_service as _fixture_service

_fixture_service.MANIFEST_PATH = Path(__file__).with_name("agentseal-manifest-v1.json")


class handler(BaseHTTPRequestHandler):
    server_version = "AgentSealFixture/1.0"

    def _dispatch(self):
        length = int(self.headers.get("content-length") or "0")
        body = self.rfile.read(length) if length > 0 else b""
        environ = {
            "REQUEST_METHOD": self.command,
            "PATH_INFO": urlparse(self.path).path,
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
        }
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = headers

        payload = b"".join(_fixture_service.application(environ, start_response))
        code = int(str(captured["status"]).split(" ", 1)[0])
        self.send_response(code)
        for key, value in captured["headers"]:
            self.send_header(str(key), str(value))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def log_message(self, format, *args):
        return
