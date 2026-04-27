import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


def json_response(handler, status, payload):
    body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class SpoofHelperHandler(BaseHTTPRequestHandler):
    server_version = "pops-ctf-spoof-helper/0.1"

    def do_GET(self):
        if urlparse(self.path).path == "/health":
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "service": "spoof-helper",
                    "dry_run": os.environ.get("SPOOF_HELPER_DRY_RUN", "true"),
                },
            )
            return
        json_response(self, 404, {"error": "not_found"})

    def do_POST(self):
        if urlparse(self.path).path != "/api/v1/lab/spoof-udp":
            json_response(self, 404, {"error": "not_found"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        dry_run = os.environ.get("SPOOF_HELPER_DRY_RUN", "true").lower() == "true"

        if dry_run:
            json_response(
                self,
                202,
                {
                    "status": "dry_run_recorded",
                    "note": "raw packet send is intentionally not implemented yet",
                    "request": payload,
                },
            )
            return

        json_response(
            self,
            501,
            {
                "error": "not_implemented",
                "note": "wire up raw UDP sending only after threat-model review",
            },
        )

    def log_message(self, fmt, *args):
        print("spoof-helper " + fmt % args)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), SpoofHelperHandler)
    print(f"spoof-helper listening on {port}")
    server.serve_forever()

