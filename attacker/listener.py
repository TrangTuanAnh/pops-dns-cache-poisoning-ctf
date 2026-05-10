"""HTTP listener nhan flag tu flag-service khi cache bi poison.

flag-service POST `{"flag_id": "...", "flag": "flag{...}"}` toi /flag.
Listener in flag ra stdout va luu vao /tmp/received_flags.log de attack
script doc lai sau.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = "/tmp/received_flags.log"
log = logging.getLogger("attacker-listener")


class FlagHandler(BaseHTTPRequestHandler):
    server_version = "attacker-listener/0.1"

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            payload = json.loads(body) if body else {}
        except Exception:
            payload = {"_raw": body}
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        line = json.dumps({"ts": ts, "path": self.path, "payload": payload})
        print(f"[FLAG-RECEIVED] {line}", flush=True)
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"received"}')

    def do_GET(self) -> None:
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true,"role":"attacker-listener"}')
            return
        if self.path == "/flags":
            try:
                with open(LOG_PATH) as f:
                    data = f.read()
            except FileNotFoundError:
                data = ""
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(data.encode("utf-8"))
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, fmt, *args) -> None:
        log.info("listener " + fmt, *args)


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), FlagHandler)
    log.info("attacker listener on 0.0.0.0:%d (log -> %s)", port, LOG_PATH)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
