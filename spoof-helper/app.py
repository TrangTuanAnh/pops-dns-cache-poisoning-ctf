"""Spoof helper - lab convenience UDP send voi spoofed source IP.

Endpoint duy nhat: POST /api/v1/lab/spoof-udp
Payload:
    {
      "src_ip": "10.0.0.10",
      "src_port": 53,
      "dst_ip": "10.0.0.3",
      "dst_port": 53,
      "payload_hex": "<hex string>"
    }

Service:
  - Validate ca src_ip va dst_ip phai trong subnet challenge cho phep.
  - Validate payload_hex parse duoc thanh bytes, kich thuoc <= 4096.
  - Xay UDP packet voi src spoofed bang raw IP socket
    (SOCK_RAW + IP_HDRINCL).

Khi SPOOF_HELPER_DRY_RUN=true, khong gui that ma chi log + tra ve summary.
Capability yeu cau: NET_RAW (set trong docker-compose).
"""
from __future__ import annotations

import binascii
import ipaddress
import json
import logging
import os
import socket
import struct
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


log = logging.getLogger("spoof-helper")

ALLOWED_SUBNETS = os.environ.get(
    "SPOOF_HELPER_ALLOWED_SUBNETS",
    "10.0.0.0/24,10.0.2.0/24,10.0.3.0/24",
).split(",")
MAX_PAYLOAD = int(os.environ.get("SPOOF_HELPER_MAX_PAYLOAD", "4096"))


def _ip_in_allowed(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for subnet in ALLOWED_SUBNETS:
        try:
            if addr in ipaddress.ip_network(subnet.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _build_ip_udp_packet(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload: bytes
) -> bytes:
    ip_ver_ihl = (4 << 4) | 5
    ip_tos = 0
    ip_total = 20 + 8 + len(payload)
    ip_id = struct.unpack("!H", os.urandom(2))[0]
    ip_flags_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_UDP
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    ip_check = 0
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ver_ihl, ip_tos, ip_total, ip_id, ip_flags_off,
        ip_ttl, ip_proto, ip_check, src, dst,
    )
    ip_check = _checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ver_ihl, ip_tos, ip_total, ip_id, ip_flags_off,
        ip_ttl, ip_proto, ip_check, src, dst,
    )

    udp_len = 8 + len(payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, ip_proto, udp_len)
    udp_check = _checksum(pseudo + udp_header + payload)
    if udp_check == 0:
        udp_check = 0xFFFF
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, udp_check)
    return ip_header + udp_header + payload


def _send_raw(packet: bytes, dst_ip: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.sendto(packet, (dst_ip, 0))
    finally:
        sock.close()


def _json(handler: BaseHTTPRequestHandler, status: int, body: dict) -> None:
    payload = json.dumps(body, indent=2, sort_keys=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


class SpoofHelperHandler(BaseHTTPRequestHandler):
    server_version = "pops-ctf-spoof-helper/0.2"

    def do_GET(self) -> None:
        if urlparse(self.path).path == "/health":
            _json(
                self, 200,
                {
                    "ok": True,
                    "service": "spoof-helper",
                    "dry_run": os.environ.get("SPOOF_HELPER_DRY_RUN", "true"),
                    "allowed_subnets": ALLOWED_SUBNETS,
                },
            )
            return
        _json(self, 404, {"error": "not_found"})

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/v1/lab/spoof-udp":
            _json(self, 404, {"error": "not_found"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            _json(self, 400, {"error": "invalid_json"})
            return

        src_ip = str(body.get("src_ip", "")).strip()
        dst_ip = str(body.get("dst_ip", "")).strip()
        try:
            src_port = int(body.get("src_port", 0))
            dst_port = int(body.get("dst_port", 0))
        except (TypeError, ValueError):
            _json(self, 400, {"error": "src_port/dst_port phai la integer"})
            return
        payload_hex = str(body.get("payload_hex", "")).strip()

        if not _ip_in_allowed(src_ip):
            _json(self, 400, {"error": f"src_ip {src_ip} ngoai allowed subnet"})
            return
        if not _ip_in_allowed(dst_ip):
            _json(self, 400, {"error": f"dst_ip {dst_ip} ngoai allowed subnet"})
            return
        if not (0 < src_port < 65536) or not (0 < dst_port < 65536):
            _json(self, 400, {"error": "port phai trong [1, 65535]"})
            return
        try:
            payload = binascii.unhexlify(payload_hex)
        except (binascii.Error, ValueError):
            _json(self, 400, {"error": "payload_hex khong hop le"})
            return
        if len(payload) > MAX_PAYLOAD:
            _json(self, 413, {"error": f"payload qua dai (>{MAX_PAYLOAD} byte)"})
            return

        packet = _build_ip_udp_packet(src_ip, src_port, dst_ip, dst_port, payload)
        dry_run = os.environ.get("SPOOF_HELPER_DRY_RUN", "true").lower() == "true"

        if dry_run:
            _json(
                self, 202,
                {
                    "status": "dry_run_recorded",
                    "packet_len": len(packet),
                    "src": f"{src_ip}:{src_port}",
                    "dst": f"{dst_ip}:{dst_port}",
                    "payload_len": len(payload),
                    "note": "Set SPOOF_HELPER_DRY_RUN=false de gui that.",
                },
            )
            return

        try:
            _send_raw(packet, dst_ip)
        except OSError as exc:
            log.warning("raw send error: %s", exc)
            _json(self, 500, {"error": "send_failed", "detail": str(exc)})
            return
        _json(
            self, 202,
            {
                "status": "sent",
                "packet_len": len(packet),
                "src": f"{src_ip}:{src_port}",
                "dst": f"{dst_ip}:{dst_port}",
            },
        )

    def log_message(self, fmt, *args):
        log.info("api " + fmt, *args)


def main() -> int:
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.INFO,
        stream=sys.stdout,
    )
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), SpoofHelperHandler)
    log.info(
        "spoof-helper listening on %d (dry_run=%s)",
        port, os.environ.get("SPOOF_HELPER_DRY_RUN", "true"),
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
