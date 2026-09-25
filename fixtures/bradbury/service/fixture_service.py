from __future__ import annotations

import io
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

MANIFEST_PATH = Path(__file__).resolve().parents[1] / "agentseal-manifest-v1.json"
INTENTIONAL_MISMATCH = "AGENTSEAL_INTENTIONAL_MISMATCH_V1"
REQUEST_BINDING_FIELDS = (
    "protocol",
    "evaluation_id",
    "agent_wallet",
    "profile_digest",
    "capability_id",
    "policy_id",
    "policy_version",
    "manifest_id",
)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _reference_map() -> dict[str, str]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return {
        str(case["case_id"]): str(case["reference"])
        for case in manifest["cases"]
    }


def _mode(path: str) -> str | None:
    clean = urlparse(path).path.rstrip("/")
    if clean in {"/stable", "/drift", "/fail"}:
        return clean.rsplit("/", 1)[-1]
    return None


def _build_response(mode: str, request: dict[str, Any]) -> dict[str, Any]:
    for field in REQUEST_BINDING_FIELDS:
        if field not in request:
            raise ValueError(f"missing binding field: {field}")

    if request["protocol"] != "agentseal-evaluation-v1":
        raise ValueError("protocol mismatch")

    evaluation_id = request["evaluation_id"]
    if not isinstance(evaluation_id, str):
        raise ValueError("evaluation_id must be a string")

    challenge = evaluation_id.startswith("agentseal-challenge-v1:")
    issuance = evaluation_id.startswith("agentseal-v1:")
    if not (challenge or issuance):
        raise ValueError("unsupported evaluation domain")

    cases = request.get("cases")
    if not isinstance(cases, list) or len(cases) != 2:
        raise ValueError("exactly two selected cases are required")

    refs = _reference_map()
    results = []
    for selected in cases:
        if not isinstance(selected, dict):
            raise ValueError("selected case must be an object")
        case_id = selected.get("case_id")
        if not isinstance(case_id, str) or case_id not in refs:
            raise ValueError("unknown case_id")

        if mode == "stable":
            output = refs[case_id]
        elif mode == "drift":
            output = INTENTIONAL_MISMATCH if challenge else refs[case_id]
        elif mode == "fail":
            output = INTENTIONAL_MISMATCH
        else:
            raise ValueError("unsupported mode")

        results.append({"case_id": case_id, "output": output})

    payload = {field: request[field] for field in REQUEST_BINDING_FIELDS}
    payload["results"] = results
    return payload


def _respond(start_response, status: str, payload: object):
    body = _canonical_bytes(payload)
    start_response(
        status,
        [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
        ],
    )
    return [body]


def application(environ, start_response):
    method = str(environ.get("REQUEST_METHOD", "GET")).upper()
    path = str(environ.get("PATH_INFO", "/"))

    if method == "GET" and path.rstrip("/") == "/healthz":
        return _respond(
            start_response,
            "200 OK",
            {"service": "agentseal-bradbury-fixture-v1", "status": "ok"},
        )

    if method != "POST":
        return _respond(start_response, "405 Method Not Allowed", {"error": "POST required"})

    mode = _mode(path)
    if mode is None:
        return _respond(start_response, "404 Not Found", {"error": "unknown fixture mode"})

    try:
        length = int(environ.get("CONTENT_LENGTH") or "0")
        if length <= 0 or length > 65_536:
            raise ValueError("invalid content length")
        raw = environ["wsgi.input"].read(length)
        request = json.loads(raw.decode("utf-8"))
        if not isinstance(request, dict):
            raise ValueError("request must be an object")
        payload = _build_response(mode, request)
    except Exception as exc:
        return _respond(start_response, "400 Bad Request", {"error": str(exc)})

    return _respond(start_response, "200 OK", payload)


class _Handler(BaseHTTPRequestHandler):
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

        payload = b"".join(application(environ, start_response))
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


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8787), _Handler)
    print("AgentSeal fixture service listening on http://127.0.0.1:8787")
    server.serve_forever()
