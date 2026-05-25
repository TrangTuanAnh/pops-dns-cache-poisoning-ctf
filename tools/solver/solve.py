"""Reference solver for Bailiwick Breakout 2: Trust Boundary.

The challenge has no real plaintext flag in the pcap. This solver reconstructs
the incident evidence and optionally submits it to the checker.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
from pathlib import Path
from typing import Any

import requests
from scapy.all import DNS, DNSQR, DNSRR, IP, rdpcap


log = logging.getLogger("solve")


_CACHE_LINE_RE = re.compile(
    r"^(?P<name>\S+)\s+(?P<type>\S+)\s+(?P<ttl>\d+)\s+(?P<data>.+?)\s*$"
)
_GENERATED_RE = re.compile(r"^Generated:\s*(?P<ts>\S+)\s*$")


def _iter_rr(rr: Any) -> list[DNSRR]:
    out: list[DNSRR] = []
    while isinstance(rr, DNSRR):
        out.append(rr)
        rr = rr.payload
    return out


def _name(raw: Any) -> str:
    if hasattr(raw, "rrname"):
        raw = raw.rrname
    elif hasattr(raw, "qname"):
        raw = raw.qname
    if isinstance(raw, bytes):
        return raw.decode("ascii", errors="replace").rstrip(".").lower()
    return str(raw).rstrip(".").lower()


def _rdata(rr: DNSRR) -> str:
    data = rr.rdata
    if isinstance(data, list):
        parts = []
        for item in data:
            if isinstance(item, bytes):
                parts.append(item.decode("utf-8", errors="replace"))
            else:
                parts.append(str(item))
        return "".join(parts).rstrip(".").lower()
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace").rstrip(".").lower()
    return str(data).rstrip(".").lower()


def _normalize_ip(value: str) -> str:
    return value.strip().strip('"').rstrip(".")


def _in_bailiwick(owner: str, qname: str) -> bool:
    owner = owner.rstrip(".").lower()
    qname = qname.rstrip(".").lower()
    return qname == owner or qname.endswith("." + owner)


def parse_cache(path: Path) -> tuple[str | None, set[tuple[str, str, str]]]:
    generated: str | None = None
    rows: set[tuple[str, str, str]] = set()
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            m_gen = _GENERATED_RE.match(line)
            if m_gen:
                generated = m_gen.group("ts")
                continue
            if (
                not line
                or line.startswith("=")
                or line.startswith("-")
                or line.startswith("Snapshot:")
                or line.startswith("Entries:")
                or ("Domain" in line and "Type" in line)
            ):
                continue
            m = _CACHE_LINE_RE.match(line)
            if not m:
                continue
            rows.add(
                (
                    m.group("name").rstrip(".").lower(),
                    m.group("type").upper(),
                    m.group("data").strip().strip('"').rstrip(".").lower(),
                )
            )
    return generated, rows


def _cache_delta(
    before: set[tuple[str, str, str]],
    after: set[tuple[str, str, str]],
) -> set[tuple[str, str, str]]:
    return after - before


def _find_poison_response(
    pcap_path: Path,
    added_ns: set[tuple[str, str]],
) -> dict[str, Any] | None:
    packets = rdpcap(str(pcap_path))
    log.info("Loaded %d packets from %s", len(packets), pcap_path)
    log.info("New NS entries to correlate: %s", sorted(added_ns))

    candidates: list[dict[str, Any]] = []
    oob_total = 0
    for idx, pkt in enumerate(packets, start=1):
        if not pkt.haslayer(DNS):
            continue
        dns = pkt[DNS]
        if dns.qr != 1 or dns.nscount == 0 or dns.qd is None:
            continue
        qname = _name(dns.qd)

        matching_ns: list[tuple[str, str]] = []
        oob_records: list[dict[str, str]] = []
        for rr in _iter_rr(dns.ns):
            if rr.type != 2:  # NS
                continue
            owner = _name(rr)
            target = _rdata(rr)
            is_oob = not _in_bailiwick(owner, qname)
            if is_oob:
                oob_total += 1
                oob_records.append({"owner": owner, "target": target})
            if is_oob and (owner, target) in added_ns:
                matching_ns.append((owner, target))

        if not matching_ns:
            continue

        additional = []
        for rr in _iter_rr(dns.ar):
            additional.append(
                {
                    "name": _name(rr),
                    "type": rr.sprintf("%type%"),
                    "data": _rdata(rr),
                }
            )

        candidates.append(
            {
                "packet_number": idx,
                "timestamp": float(pkt.time),
                "src_ip": pkt[IP].src if pkt.haslayer(IP) else "",
                "dst_ip": pkt[IP].dst if pkt.haslayer(IP) else "",
                "dns_txid": f"0x{int(dns.id):04x}",
                "trigger_qname": qname,
                "matched_ns": matching_ns,
                "oob_records": oob_records,
                "additional": additional,
            }
        )

    log.info("OOB Authority NS records observed: %d", oob_total)
    log.info("Cache-correlated candidates: %d", len(candidates))
    if not candidates:
        return None
    if len(candidates) > 1:
        log.warning("Multiple candidates found; choosing earliest packet")
    return sorted(candidates, key=lambda c: c["packet_number"])[0]


def _first_client_query(pcap_path: Path, victim_domain: str, after_packet: int) -> str | None:
    packets = rdpcap(str(pcap_path))
    for idx, pkt in enumerate(packets, start=1):
        if idx <= after_packet or not pkt.haslayer(DNS) or not pkt.haslayer(IP):
            continue
        dns = pkt[DNS]
        if dns.qr != 0 or dns.qd is None:
            continue
        if pkt[IP].dst != "10.13.37.53":
            continue
        if _name(dns.qd) == victim_domain:
            from datetime import datetime, timezone

            return datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
    return None


def build_evidence(
    pcap_path: Path,
    cache_before: Path,
    cache_after_1: Path,
    cache_after_2: Path,
) -> dict[str, Any]:
    _, before_rows = parse_cache(cache_before)
    first_cache_seen, after1_rows = parse_cache(cache_after_1)
    _, after2_rows = parse_cache(cache_after_2)

    added_after1 = _cache_delta(before_rows, after1_rows)
    added_ns = {(name, data) for name, rtype, data in added_after1 if rtype == "NS"}
    added_a_after1 = {
        (name, data) for name, rtype, data in added_after1 if rtype in {"A", "AAAA"}
    }
    added_a_after2 = {
        (name, data) for name, rtype, data in _cache_delta(after1_rows, after2_rows) if rtype == "A"
    }

    poison = _find_poison_response(pcap_path, added_ns)
    if poison is None:
        raise RuntimeError("No cache-correlated OOB Authority NS response found")

    victim_domain, malicious_ns = poison["matched_ns"][0]
    malicious_ns_ip = None
    for row_name, row_ip in added_a_after1:
        if row_name == malicious_ns:
            malicious_ns_ip = row_ip
            break
    if malicious_ns_ip is None:
        for rr in poison["additional"]:
            if rr["name"] == malicious_ns and rr["type"] == "A":
                malicious_ns_ip = _normalize_ip(rr["data"])
                break
    if malicious_ns_ip is None:
        for row_name, row_ip in added_a_after2:
            if row_name == victim_domain:
                malicious_ns_ip = row_ip
                break
    if malicious_ns_ip is None:
        raise RuntimeError("Could not determine malicious NS IP from cache or Additional section")

    first_victim_query = _first_client_query(
        pcap_path,
        victim_domain,
        int(poison["packet_number"]),
    )
    if first_victim_query is None:
        raise RuntimeError("Could not find first client query for poisoned victim domain")

    return {
        "victim_domain": victim_domain,
        "malicious_ns": malicious_ns,
        "malicious_ns_ip": malicious_ns_ip,
        "trigger_qname": poison["trigger_qname"],
        "poison_packet_number": poison["packet_number"],
        "poison_dns_txid": poison["dns_txid"],
        "first_cache_seen": first_cache_seen,
        "first_victim_query": first_victim_query,
    }


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", default=str(repo_root / "challenge" / "capture.pcapng"))
    parser.add_argument("--cache-before", default=str(repo_root / "challenge" / "cache_before.txt"))
    parser.add_argument("--cache-after-1", default=str(repo_root / "challenge" / "cache_after_1.txt"))
    parser.add_argument("--cache-after-2", default=str(repo_root / "challenge" / "cache_after_2.txt"))
    parser.add_argument("--submit", default=None, help="Checker base URL, e.g. http://127.0.0.1:5000")
    parser.add_argument("--out", default=None, help="Optional path to write evidence JSON")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    evidence = build_evidence(
        Path(args.pcap).resolve(),
        Path(args.cache_before).resolve(),
        Path(args.cache_after_1).resolve(),
        Path(args.cache_after_2).resolve(),
    )

    print(json.dumps(evidence, indent=2, sort_keys=True))
    if args.out:
        Path(args.out).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        log.info("Wrote evidence to %s", args.out)

    if args.submit:
        response = requests.post(f"{args.submit.rstrip('/')}/submit", json=evidence, timeout=5.0)
        log.info("Status %d: %s", response.status_code, response.text)
        if response.status_code != 200:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
