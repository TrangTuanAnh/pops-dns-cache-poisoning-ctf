"""Flag service entry point - 3 flag B scope.

Trach nhiem:
  - Validate evidence cho 3 flag deterministic (1B, 2B, 3B).
  - Cho phep player submit flag/token de verify (POST /api/v1/submit/<id>).

Flag A (1A, 2A, 3A) da bo khoi scope - khong co passive query loop nua.
Flag B la deterministic timing/probe experiment, validator co the
verify chinh xac evidence pattern.

Service cung image dung cho ca 3 stage; phan biet qua env STAGE.

Env vars:
  STAGE              - stage1 / stage2 / stage3
  FLAG_1B/2B/3B      - flag value cho moi stage

Endpoint:
  GET  /health
  GET  /api/v1/state                     - service info
  POST /api/v1/stage1/window-evidence    - flag 1B
  POST /api/v1/stage2/noncompliant-evidence - flag 2B
  POST /api/v1/stage3/normalization-evidence - flag 3B
  POST /api/v1/submit/{flag_id}          - submit flag string de verify
"""
from __future__ import annotations

import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import stage1
import stage2
import stage3


log = logging.getLogger("flag-service")


VALIDATORS = {
    "/api/v1/stage1/window-evidence": stage1.validate_window_evidence,
    "/api/v1/stage2/noncompliant-evidence": stage2.validate_noncompliant_evidence,
    "/api/v1/stage3/normalization-evidence": stage3.validate_normalization_evidence,
}


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _flag_for_id(flag_id: str) -> str:
    return os.environ.get(f"FLAG_{flag_id}", "")


def _validate_submission(flag_id: str, submitted: str) -> dict:
    expected = _flag_for_id(flag_id)
    if not expected:
        return {"status_code": 404, "error": f"FLAG_{flag_id} not configured"}
    ok = submitted.strip() == expected.strip()
    return {
        "status_code": 200 if ok else 401,
        "verdict": "valid" if ok else "invalid",
        "flag_id": flag_id,
    }


class FlagHandler(BaseHTTPRequestHandler):
    server_version = "pops-ctf-flag-service/0.3"

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            _json_response(
                self, 200,
                {
                    "ok": True,
                    "service": "flag-service",
                    "stage": os.environ.get("STAGE", ""),
                    "scope": "3 flag B (1B, 2B, 3B)",
                    "configured_flags": sorted(
                        k for k in os.environ if k.startswith("FLAG_")
                    ),
                },
            )
            return
        if path == "/api/v1/state":
            _json_response(
                self, 200,
                {
                    "service": "flag-service",
                    "stage": os.environ.get("STAGE", ""),
                    "scope": "3 flag B",
                    "endpoints": sorted(VALIDATORS.keys()),
                },
            )
            return
        _json_response(self, 404, {"error": "not_found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            _json_response(self, 400, {"error": "invalid_json"})
            return

        if path.startswith("/api/v1/submit/"):
            flag_id = path[len("/api/v1/submit/"):].strip().upper()
            submitted = str(payload.get("flag", ""))
            result = _validate_submission(flag_id, submitted)
            _json_response(self, result.pop("status_code", 200), result)
            return

        validator = VALIDATORS.get(path)
        if validator is None:
            _json_response(self, 404, {"error": "not_found"})
            return

        result = validator(payload)
        flag_id = result.pop("award_flag_id", None)
        status_code = result.pop("status_code", 200)
        if flag_id is not None:
            result["flag"] = _flag_for_id(flag_id)
            result["flag_id"] = flag_id
        _json_response(self, status_code, result)

    def log_message(self, fmt, *args):
        log.info("api " + fmt, *args)


def main() -> int:
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.INFO,
        stream=sys.stdout,
    )
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), FlagHandler)
    log.info("flag-service listening on %d (scope=3-flag-B)", port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
