import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import stage1
import stage2
import stage3


VALIDATORS = {
    "/api/v1/stage1/reproduction": stage1.validate_reproduction,
    "/api/v1/stage1/window-evidence": stage1.validate_window_evidence,
    "/api/v1/stage2/fragmentation-evidence": stage2.validate_fragmentation_evidence,
    "/api/v1/stage2/noncompliant-evidence": stage2.validate_noncompliant_evidence,
    "/api/v1/stage3/bailiwick-evidence": stage3.validate_bailiwick_evidence,
    "/api/v1/stage3/normalization-evidence": stage3.validate_normalization_evidence,
}


def json_response(handler, status, payload):
    body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def masked_flags():
    return sorted(key for key in os.environ if key.startswith("FLAG_"))


class FlagHandler(BaseHTTPRequestHandler):
    server_version = "pops-ctf-flag-service/0.1"

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "service": "flag-service",
                    "stage": os.environ.get("STAGE", "all"),
                    "configured_flags": masked_flags(),
                    "mode": "scaffold",
                },
            )
            return
        json_response(self, 404, {"error": "not_found"})

    def do_POST(self):
        path = urlparse(self.path).path
        validator = VALIDATORS.get(path)
        if validator is None:
            json_response(self, 404, {"error": "not_found"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        result = validator(payload)
        json_response(self, result.pop("status_code", 200), result)

    def log_message(self, fmt, *args):
        print("flag-service " + fmt % args)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), FlagHandler)
    print(f"flag-service listening on {port}")
    server.serve_forever()

