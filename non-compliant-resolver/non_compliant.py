"""Non-compliant resolver cho flag 2B.

Resolver nhan query, forward len POPS upstream qua UDP. Khi response co
TC=1 (POPS mitigation triggered), resolver KHONG retry qua TCP - thay vao
do tra ve SERVFAIL hoac timeout (cau hinh qua NON_COMPLIANT_BEHAVIOR).

Day la dai dien cho 2.67% resolver ma APNIC do duoc khong RFC compliant
(paper POPS Section 4.2).

Behavior modes:
  servfail  - tra rcode=SERVFAIL khi nhan TC=1 (default)
  timeout   - khong response (client se timeout)
  drop      - drop response cua POPS, khong retry, client timeout
"""
from __future__ import annotations

import logging
import os
import socket
import sys
import threading

import dnslib


log = logging.getLogger("non-compliant")


UPSTREAM_HOST = os.environ.get("UPSTREAM_HOST", "10.0.2.2")
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "53"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "53"))
BEHAVIOR = os.environ.get("NON_COMPLIANT_BEHAVIOR", "servfail").strip().lower()


def _forward_udp(query: bytes) -> bytes | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    try:
        sock.sendto(query, (UPSTREAM_HOST, UPSTREAM_PORT))
        data, _ = sock.recvfrom(65535)
        return data
    except socket.timeout:
        return None
    finally:
        sock.close()


def _build_servfail(query_bytes: bytes) -> bytes:
    parsed = dnslib.DNSRecord.parse(query_bytes)
    parsed.header.qr = 1
    parsed.header.ra = 1
    parsed.header.rcode = dnslib.RCODE.SERVFAIL
    return parsed.pack()


def _handle_query(server_sock: socket.socket, data: bytes, addr) -> None:
    response = _forward_udp(data)
    if response is None:
        if BEHAVIOR == "servfail":
            server_sock.sendto(_build_servfail(data), addr)
        # else: drop / timeout -> khong gui gi
        return
    try:
        parsed = dnslib.DNSRecord.parse(response)
    except Exception:
        server_sock.sendto(response, addr)
        return

    if parsed.header.tc:
        # POPS triggered. Resolver "khong RFC compliant" -> khong retry TCP.
        log.info("received TC=1; non-compliant behavior=%s", BEHAVIOR)
        if BEHAVIOR == "servfail":
            server_sock.sendto(_build_servfail(data), addr)
        elif BEHAVIOR == "timeout":
            return  # khong gui gi -> client timeout
        elif BEHAVIOR == "drop":
            return
        else:
            server_sock.sendto(_build_servfail(data), addr)
        return

    # Response binh thuong, forward back.
    server_sock.sendto(response, addr)


def main() -> int:
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.INFO,
        stream=sys.stdout,
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", LISTEN_PORT))
    log.info(
        "non-compliant resolver listening on udp/%d (behavior=%s, upstream=%s:%d)",
        LISTEN_PORT, BEHAVIOR, UPSTREAM_HOST, UPSTREAM_PORT,
    )
    while True:
        data, addr = sock.recvfrom(65535)
        t = threading.Thread(
            target=_handle_query, args=(sock, data, addr), daemon=True
        )
        t.start()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
