import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


STATE_PATH = Path(os.environ.get("REGISTRAR_STATE_PATH", "/data/registrations.json"))


def read_state():
    if not STATE_PATH.exists():
        return {"registrations": []}
    with STATE_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_state(state):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with STATE_PATH.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)


def json_response(handler, status, payload):
    body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class RegistrarHandler(BaseHTTPRequestHandler):
    server_version = "pops-ctf-registrar/0.1"

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            json_response(self, 200, {"ok": True, "service": "registrar"})
            return
        if path == "/api/v1/registrations":
            json_response(self, 200, read_state())
            return
        json_response(self, 404, {"error": "not_found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/v1/register":
            json_response(self, 404, {"error": "not_found"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        domain = str(payload.get("domain", "")).strip().lower().rstrip(".")
        ns_ip = str(payload.get("ns_ip", "")).strip()

        if not domain.endswith(".example") or not ns_ip:
            json_response(
                self,
                400,
                {"error": "domain must end with .example and ns_ip is required"},
            )
            return

        state = read_state()
        state["registrations"].append({"domain": domain, "ns_ip": ns_ip})
        write_state(state)
        json_response(
            self,
            202,
            {
                "status": "recorded",
                "note": "zone reload is not implemented in scaffold mode",
                "domain": domain,
                "ns_ip": ns_ip,
            },
        )

    def log_message(self, fmt, *args):
        print("registrar " + fmt % args)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), RegistrarHandler)
    print(f"registrar-service listening on {port}")
    server.serve_forever()

