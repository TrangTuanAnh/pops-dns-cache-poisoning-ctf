"""Hard-only generator for Bailiwick Breakout 2: Trust Boundary.

The generated challenge is intentionally noisy. There are no easy/medium/hard
profiles and no plaintext real flag in the packet capture. Players must submit
incident evidence instead of extracting a TXT record.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP
from scapy.utils import PcapNgWriter


log = logging.getLogger("gen_challenge")


# ---------------------------------------------------------------------------
# Scenario constants
# ---------------------------------------------------------------------------
RESOLVER_IP = "10.13.37.53"
CLIENT_IPS = [
    "10.13.37.21",
    "10.13.37.22",
    "10.13.37.23",
    "10.13.37.30",
    "10.13.37.45",
    "10.13.37.88",
    "10.13.37.101",
    "10.13.37.144",
]

ATTACKER_ZONE = "attacker.net"
ATTACKER_AUTH_IP = "203.0.113.66"
TRIGGER_QNAME = "promo.attacker.net"
TRIGGER_ANSWER_IP = "198.51.100.24"

VICTIM_DOMAIN = "bank.victim.com"
EVIL_NS_DOMAIN = "ns.evilcorp.example"
EVIL_NS_IP = "6.6.6.6"

BASE_TS = 1779357600.0  # 2026-05-21 10:00:00 UTC
POISON_TS = BASE_TS + 192.0  # 10:03:12
AFTER1_TS = BASE_TS + 194.0  # 10:03:14
VICTIM_QUERY_TS = BASE_TS + 438.0  # 10:07:18
AFTER2_TS = BASE_TS + 440.0  # 10:07:20

# Fixed hard-only noise volume. This is deliberately not exposed as a
# difficulty profile.
BENIGN_FLOWS = 2400
ATTACKER_RECON_FLOWS = 90
LEGIT_REFERRAL_FLOWS = 70
OOB_DECOY_FLOWS = 160
LOOKALIKE_DECOY_FLOWS = 55
ADDITIONAL_GLUE_DECOY_FLOWS = 30
TXT_DECOY_BUDGET = 50

LEGIT_AUTHS = {
    "google.com": ("216.239.32.10", "142.250.80.100"),
    "cloudflare.com": ("1.1.1.1", "104.16.132.229"),
    "amazonaws.com": ("205.251.192.40", "52.95.110.1"),
    "github.com": ("140.82.121.6", "140.82.121.3"),
    "wikipedia.org": ("208.80.154.232", "208.80.154.224"),
    "stackoverflow.com": ("151.101.1.69", "151.101.65.69"),
    "microsoft.com": ("184.86.251.85", "20.103.85.33"),
    "apple.com": ("17.253.144.10", "17.142.160.59"),
    "youtube.com": ("216.239.32.10", "142.250.80.110"),
    "reddit.com": ("151.101.1.140", "151.101.65.140"),
    "discord.com": ("162.159.135.232", "162.159.137.232"),
    "linkedin.com": ("108.174.10.10", "13.107.42.14"),
    "facebook.com": ("69.171.250.35", "157.240.22.35"),
    "instagram.com": ("157.240.241.174", "31.13.71.174"),
    "netflix.com": ("54.236.255.79", "52.85.132.45"),
    "spotify.com": ("35.186.224.47", "104.154.127.47"),
    "dropbox.com": ("162.125.81.18", "162.125.7.18"),
    "slack.com": ("3.221.81.55", "52.74.149.74"),
    "atlassian.com": ("104.192.142.21", "13.226.225.41"),
    "zoom.us": ("3.235.71.34", "170.114.52.32"),
    "wordpress.org": ("198.143.164.252", "198.143.164.253"),
    "mozilla.org": ("63.245.208.195", "44.234.214.115"),
    "nytimes.com": ("151.101.1.164", "151.101.65.164"),
    "bbc.co.uk": ("151.101.0.81", "151.101.64.81"),
    "cnn.com": ("151.101.193.67", "151.101.65.67"),
    "paypal.com": ("64.4.250.32", "64.4.250.33"),
    "shopify.com": ("23.227.38.65", "23.227.38.66"),
    "salesforce.com": ("104.109.10.171", "13.110.54.31"),
    "digitalocean.com": ("104.16.181.15", "104.16.182.15"),
    "fastly.net": ("151.101.1.57", "151.101.65.57"),
    "akamai.net": ("23.48.203.88", "23.48.203.93"),
}

RED_HERRING_ZONES = [
    ("trk.adnet-x.io", "203.0.113.101"),
    ("ads.tracker-9.org", "203.0.113.102"),
    ("cdn.malvert.co", "203.0.113.103"),
    ("metrics.shady-stats.net", "203.0.113.104"),
    ("links.clickfarm.biz", "203.0.113.105"),
    ("pixel.dataminer.io", "203.0.113.106"),
    ("collector.scamware.net", "203.0.113.107"),
    ("redir.darksideads.com", "203.0.113.108"),
    ("sync.affiliate-mesh.test", "203.0.113.109"),
    ("log.adexchange-lab.example", "203.0.113.110"),
]

RED_HERRING_VICTIMS = [
    "shop.demobank.example",
    "sso.democorp.example",
    "auth.example-corp.test",
    "id.fakebank-online.example",
    "login.cred-store.test",
    "vault.fakevault.example",
    "portal.democorp.test",
    "api.payments-example.test",
    "console.demo-cloud.example",
    "internal.democorp.test",
    "secure.demobank-online.example",
    "files.demobank-portal.example",
    "bank-victim.com",
    "bank.victim.co",
    "login.bank-victim.com",
    "bank.xn--vctim-pta.com",
    "bank.victim.com.attacker.net",
    "fakevictim.com",
    "notvictim.com",
    "victim.com.attacker.net",
]

RED_HERRING_NS = [
    "ns1.fakeattacker.net",
    "ns2.fakeattacker.net",
    "dns.parkedinfra.com",
    "ns-evil.lookalike.org",
    "ghost.malvert.example",
    "shadow.darkops.test",
    "phantom.threatactor.example",
    "decoy.honeynet.test",
    "lure.canarynet.example",
    "trap.deception.test",
]

SUBDOMAIN_PREFIXES = [
    "www",
    "api",
    "static",
    "cdn",
    "mail",
    "auth",
    "login",
    "portal",
    "dashboard",
    "metrics",
    "logs",
    "search",
    "assets",
    "img",
    "docs",
    "support",
    "blog",
    "shop",
    "pay",
    "id",
    "sso",
    "edge",
    "origin",
    "cache",
    "files",
    "data",
    "events",
    "queue",
    "git",
    "ci",
    "build",
    "registry",
]

DECOY_FLAGS = [
    "CTF{honeypot_canary_001}",
    "CTF{dns_txt_is_not_always_flag}",
    "CTF{wrong_authority_section}",
    "CTF{aws_metadata_lure_x9q}",
    "CTF{splunk_audit_marker}",
    "CTF{dkim_relay_test_2024}",
    "CTF{spf_bounce_indicator}",
    "CTF{purpleteam_breadcrumb}",
    "CTF{soc_handover_token}",
    "CTF{red_team_decoy_42}",
    "CTF{network_probe_signature}",
    "CTF{kerberos_spn_marker}",
    "CTF{ldap_audit_token_2024}",
    "CTF{vpn_marker_test_alpha}",
    "CTF{ssh_canary_88b}",
    "CTF{siem_correlation_hash}",
    "CTF{idp_session_lure}",
    "CTF{mfa_seed_decoy}",
    "CTF{ad_replication_canary}",
    "CTF{nps_radius_marker}",
    "CTF{ocsp_responder_test}",
    "CTF{crl_distribution_token}",
    "CTF{ca_audit_baseline}",
    "CTF{forensic_baseline_001}",
    "CTF{ir_playbook_marker}",
    "CTF{threathunt_baseline}",
    "CTF{ndr_canary_03}",
    "CTF{edr_baseline_marker}",
    "CTF{xdr_correlation_id}",
    "CTF{soar_lookup_token}",
    "CTF{ueba_audit_seed}",
    "CTF{ti_feed_decoy}",
    "CTF{ja3_fingerprint_lure}",
    "CTF{tls_sni_marker}",
    "CTF{quic_canary_2024}",
    "CTF{doh_audit_token}",
    "CTF{dot_baseline_marker}",
    "CTF{ipv6_ra_canary}",
    "CTF{dhcp_snoop_token}",
    "CTF{stp_topology_marker}",
    "CTF{bgp_peering_audit}",
    "CTF{netflow_v9_decoy}",
    "CTF{ipfix_marker_001}",
    "CTF{wmi_audit_lure}",
    "CTF{powershell_canary_seed}",
    "CTF{sysmon_event_marker}",
    "CTF{etw_provider_audit}",
    "CTF{event_log_canary_42}",
    "CTF{auditd_baseline_decoy}",
    "CTF{ebpf_probe_marker}",
]


@dataclass(frozen=True)
class PktSpec:
    timestamp: float
    pkt: Any
    note: str = ""


@dataclass(frozen=True)
class CacheEvent:
    timestamp: float
    name: str
    rtype: str
    ttl: int
    data: str


@dataclass
class FlowResult:
    packets: list[PktSpec]
    cache_events: list[CacheEvent]
    resolver_log: list[str]
    debug_log: list[str]
    upstream_txid: int
    upstream_response_time: float


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hex_label(rng: random.Random, n: int = 8) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _random_ip(rng: random.Random) -> str:
    return ".".join(str(rng.randint(1, 254)) for _ in range(4))


def _chain(rrs: list[DNSRR] | None):
    if not rrs:
        return None
    rr = rrs[0]
    for nxt in rrs[1:]:
        rr = rr / nxt
    return rr


def _mk_query(
    src_ip: str,
    dst_ip: str,
    sport: int,
    qname: str,
    qtype: str,
    txid: int,
    ts: float,
    rd: int = 1,
) -> PktSpec:
    pkt = (
        Ether()
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=53)
        / DNS(id=txid, qr=0, rd=rd, qd=DNSQR(qname=qname, qtype=qtype))
    )
    pkt.time = ts
    return PktSpec(ts, pkt, f"query {qname}")


def _mk_response(
    src_ip: str,
    dst_ip: str,
    dport: int,
    qname: str,
    qtype: str,
    txid: int,
    ts: float,
    answers: list[DNSRR] | None = None,
    authority: list[DNSRR] | None = None,
    additional: list[DNSRR] | None = None,
    rcode: int = 0,
    aa: int = 1,
    ra: int = 0,
) -> PktSpec:
    dns_kwargs: dict[str, Any] = {
        "id": txid,
        "qr": 1,
        "aa": aa,
        "rd": 1,
        "ra": ra,
        "rcode": rcode,
        "qd": DNSQR(qname=qname, qtype=qtype),
    }
    if answers:
        dns_kwargs["an"] = _chain(answers)
    if authority:
        dns_kwargs["ns"] = _chain(authority)
    if additional:
        dns_kwargs["ar"] = _chain(additional)

    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=53, dport=dport) / DNS(**dns_kwargs)
    pkt.time = ts
    return PktSpec(ts, pkt, f"response {qname}")


def _rdata_to_cache(rr: DNSRR) -> str:
    data = rr.rdata
    if isinstance(data, list):
        parts = []
        for item in data:
            if isinstance(item, bytes):
                parts.append(item.decode("utf-8", errors="replace"))
            else:
                parts.append(str(item))
        return '"' + "".join(parts) + '"'
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace").rstrip(".")
    return str(data).rstrip(".")


def _flow(
    rng: random.Random,
    ts: float,
    client_ip: str,
    qname: str,
    qtype: str,
    auth_ip: str,
    answers: list[DNSRR],
    authority: list[DNSRR] | None = None,
    additional: list[DNSRR] | None = None,
    cache_answers: bool = True,
    cache_extra: list[CacheEvent] | None = None,
    debug_extra: list[str] | None = None,
) -> FlowResult:
    client_txid = rng.randint(1, 65535)
    upstream_txid = rng.randint(1, 65535)
    client_sport = rng.randint(20000, 62000)
    resolver_sport = rng.randint(20000, 62000)
    upstream_response_time = ts + rng.uniform(0.020, 0.140)
    client_response_time = upstream_response_time + rng.uniform(0.004, 0.020)

    packets = [
        _mk_query(client_ip, RESOLVER_IP, client_sport, qname, qtype, client_txid, ts),
        _mk_query(
            RESOLVER_IP,
            auth_ip,
            resolver_sport,
            qname,
            qtype,
            upstream_txid,
            ts + rng.uniform(0.002, 0.008),
        ),
        _mk_response(
            auth_ip,
            RESOLVER_IP,
            resolver_sport,
            qname,
            qtype,
            upstream_txid,
            upstream_response_time,
            answers=answers,
            authority=authority,
            additional=additional,
            aa=1,
            ra=0,
        ),
        _mk_response(
            RESOLVER_IP,
            client_ip,
            client_sport,
            qname,
            qtype,
            client_txid,
            client_response_time,
            answers=answers,
            aa=0,
            ra=1,
        ),
    ]

    cache_events: list[CacheEvent] = []
    if cache_answers:
        for rr in answers:
            rr_name = _rdata_name(rr.rrname)
            cache_events.append(
                CacheEvent(
                    timestamp=upstream_response_time,
                    name=rr_name,
                    rtype=rr.sprintf("%type%"),
                    ttl=int(rr.ttl),
                    data=_rdata_to_cache(rr),
                )
            )
    if cache_extra:
        cache_events.extend(cache_extra)

    elapsed_ms = int((client_response_time - ts) * 1000)
    resolver_log = [
        (
            f"{_iso(ts)} INFO query client={client_ip} qname={qname} "
            f"qtype={qtype} action=RECURSE upstream={auth_ip} "
            f"rcode=NOERROR elapsed_ms={elapsed_ms}"
        )
    ]

    debug_log = [
        (
            f"{_iso(upstream_response_time)} DEBUG upstream_response "
            f"src={auth_ip} dst={RESOLVER_IP} txid=0x{upstream_txid:04x} "
            f"qname={qname} answer={len(answers)} "
            f"authority={len(authority or [])} additional={len(additional or [])}"
        )
    ]
    if debug_extra:
        debug_log.extend(debug_extra)

    return FlowResult(
        packets=packets,
        cache_events=cache_events,
        resolver_log=resolver_log,
        debug_log=debug_log,
        upstream_txid=upstream_txid,
        upstream_response_time=upstream_response_time,
    )


def _rdata_name(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("ascii", errors="replace").rstrip(".").lower()
    return str(value).rstrip(".").lower()


def _maybe_txt_decoy(rng: random.Random, pool: list[str], owner: str) -> DNSRR | None:
    if not pool:
        return None
    if rng.random() > 0.45:
        return None
    return DNSRR(rrname=owner, type="TXT", ttl=600, rdata=pool.pop())


def _benign_flow(
    rng: random.Random,
    ts: float,
    decoy_pool: list[str],
) -> FlowResult:
    zone = rng.choice(list(LEGIT_AUTHS))
    auth_ip = rng.choice(LEGIT_AUTHS[zone])
    qname = f"{rng.choice(SUBDOMAIN_PREFIXES)}-{_hex_label(rng, 4)}.{zone}"
    client_ip = rng.choice(CLIENT_IPS)

    pick = rng.random()
    if pick < 0.75:
        qtype = "A"
        answer = DNSRR(rrname=qname, type="A", ttl=300, rdata=_random_ip(rng))
    elif pick < 0.90:
        qtype = "AAAA"
        v6 = "2606:4700:" + ":".join(_hex_label(rng, 4) for _ in range(2)) + "::1"
        answer = DNSRR(rrname=qname, type="AAAA", ttl=300, rdata=v6)
    else:
        qtype = "TXT"
        if decoy_pool and rng.random() < 0.65:
            txt = decoy_pool.pop()
        else:
            txt = f"v=spf1 include:_spf.{zone} ~all"
        answer = DNSRR(rrname=qname, type="TXT", ttl=300, rdata=txt)

    return _flow(rng, ts, client_ip, qname, qtype, auth_ip, [answer])


def _legit_referral_flow(
    rng: random.Random,
    ts: float,
    decoy_pool: list[str],
) -> FlowResult:
    zone = rng.choice(list(LEGIT_AUTHS))
    auth_ip = rng.choice(LEGIT_AUTHS[zone])
    qname = f"{rng.choice(SUBDOMAIN_PREFIXES)}.{zone}"
    client_ip = rng.choice(CLIENT_IPS)

    answer = DNSRR(rrname=qname, type="A", ttl=300, rdata=_random_ip(rng))
    ns_targets = [f"ns{i}.{zone}" for i in range(1, rng.randint(2, 4))]
    authority = [DNSRR(rrname=zone, type="NS", ttl=86400, rdata=ns) for ns in ns_targets]
    additional: list[DNSRR] = [
        DNSRR(rrname=ns, type="A", ttl=86400, rdata=_random_ip(rng)) for ns in ns_targets
    ]
    maybe = _maybe_txt_decoy(rng, decoy_pool, f"_audit.{zone}")
    if maybe:
        additional.append(maybe)

    return _flow(
        rng,
        ts,
        client_ip,
        qname,
        "A",
        auth_ip,
        [answer],
        authority=authority,
        additional=additional,
    )


def _attacker_recon_flow(
    rng: random.Random,
    ts: float,
    decoy_pool: list[str],
) -> FlowResult:
    qname = f"{_hex_label(rng, 10)}.{ATTACKER_ZONE}"
    answer = DNSRR(rrname=qname, type="A", ttl=120, rdata=f"203.0.113.{rng.randint(2, 254)}")
    additional: list[DNSRR] = []
    maybe = _maybe_txt_decoy(rng, decoy_pool, f"_canary.{ATTACKER_ZONE}")
    if maybe:
        additional.append(maybe)
    return _flow(
        rng,
        ts,
        rng.choice(CLIENT_IPS),
        qname,
        "A",
        ATTACKER_AUTH_IP,
        [answer],
        additional=additional or None,
    )


def _oob_decoy_flow(
    rng: random.Random,
    ts: float,
    decoy_pool: list[str],
) -> FlowResult:
    zone, auth_ip = rng.choice(RED_HERRING_ZONES)
    qname = f"{_hex_label(rng, 8)}.{zone}"
    fake_victim = rng.choice(RED_HERRING_VICTIMS)
    fake_ns = rng.choice(RED_HERRING_NS)
    fake_ns_ip = f"198.51.100.{rng.randint(2, 254)}"

    answer = DNSRR(rrname=qname, type="A", ttl=120, rdata=f"203.0.113.{rng.randint(2, 254)}")
    authority = [DNSRR(rrname=fake_victim, type="NS", ttl=rng.choice([0, 30, 86400]), rdata=fake_ns)]
    additional = [DNSRR(rrname=fake_ns, type="A", ttl=86400, rdata=fake_ns_ip)]
    if decoy_pool:
        additional.append(DNSRR(rrname=fake_ns, type="TXT", ttl=86400, rdata=decoy_pool.pop()))

    debug_extra = [
        (
            f"{_iso(ts + 0.160)} DEBUG bailiwick_observation owner={fake_victim} "
            f"type=NS data={fake_ns} qname={qname} cache_status=not_present"
        )
    ]
    return _flow(
        rng,
        ts,
        rng.choice(CLIENT_IPS),
        qname,
        "A",
        auth_ip,
        [answer],
        authority=authority,
        additional=additional,
        debug_extra=debug_extra,
    )


def _lookalike_decoy_flow(
    rng: random.Random,
    ts: float,
    decoy_pool: list[str],
) -> FlowResult:
    qname = f"{_hex_label(rng, 6)}.{ATTACKER_ZONE}"
    owner = rng.choice(
        [
            "bank.victim.com.attacker.net",
            "login.bank.victim.com.attacker.net",
            "victim.com.attacker.net",
            "notvictim.com",
            "fakevictim.com",
            "bank-victim.com",
        ]
    )
    fake_ns = f"ns-{_hex_label(rng, 4)}.{ATTACKER_ZONE}"
    answer = DNSRR(rrname=qname, type="A", ttl=120, rdata=f"203.0.113.{rng.randint(2, 254)}")
    authority = [DNSRR(rrname=owner, type="NS", ttl=86400, rdata=fake_ns)]
    additional = [DNSRR(rrname=fake_ns, type="A", ttl=86400, rdata=f"203.0.113.{rng.randint(2, 254)}")]
    maybe = _maybe_txt_decoy(rng, decoy_pool, fake_ns)
    if maybe:
        additional.append(maybe)

    return _flow(
        rng,
        ts,
        rng.choice(CLIENT_IPS),
        qname,
        "A",
        ATTACKER_AUTH_IP,
        [answer],
        authority=authority,
        additional=additional,
    )


def _additional_glue_decoy_flow(
    rng: random.Random,
    ts: float,
    decoy_pool: list[str],
) -> FlowResult:
    zone, auth_ip = rng.choice(RED_HERRING_ZONES)
    qname = f"{_hex_label(rng, 8)}.{zone}"
    owner = rng.choice(["victim.com", "login.victim.com", "bank-victim.com"])
    ns_name = "ns1.victim.com" if owner != "bank-victim.com" else "ns1.bank-victim.com"
    answer = DNSRR(rrname=qname, type="A", ttl=120, rdata=f"203.0.113.{rng.randint(2, 254)}")
    authority = [DNSRR(rrname=owner, type="NS", ttl=86400, rdata=ns_name)]
    additional = [DNSRR(rrname=ns_name, type="A", ttl=86400, rdata=EVIL_NS_IP)]
    if decoy_pool:
        additional.append(DNSRR(rrname=ns_name, type="TXT", ttl=86400, rdata=decoy_pool.pop()))
    return _flow(
        rng,
        ts,
        rng.choice(CLIENT_IPS),
        qname,
        "A",
        auth_ip,
        [answer],
        authority=authority,
        additional=additional,
    )


def _poison_flow(rng: random.Random) -> FlowResult:
    answer = DNSRR(rrname=TRIGGER_QNAME, type="A", ttl=120, rdata=TRIGGER_ANSWER_IP)
    authority = [
        DNSRR(rrname=VICTIM_DOMAIN, type="NS", ttl=86400, rdata=EVIL_NS_DOMAIN),
    ]
    additional = [
        DNSRR(rrname=EVIL_NS_DOMAIN, type="A", ttl=86400, rdata=EVIL_NS_IP),
        DNSRR(rrname=EVIL_NS_DOMAIN, type="TXT", ttl=86400, rdata="CTF{dns_txt_is_not_always_flag}"),
    ]
    poison_cache = [
        CacheEvent(POISON_TS + 0.090, TRIGGER_QNAME, "A", 120, TRIGGER_ANSWER_IP),
        CacheEvent(POISON_TS + 0.090, VICTIM_DOMAIN, "NS", 86400, EVIL_NS_DOMAIN),
        CacheEvent(POISON_TS + 0.090, EVIL_NS_DOMAIN, "A", 86400, EVIL_NS_IP),
    ]
    debug_extra = [
        (
            f"{_iso(POISON_TS + 0.090)} DEBUG cache_insert source=Authority "
            f"owner={VICTIM_DOMAIN} type=NS data={EVIL_NS_DOMAIN} "
            f"qname={TRIGGER_QNAME} policy=legacy_accept"
        ),
        (
            f"{_iso(POISON_TS + 0.091)} DEBUG cache_insert source=Additional "
            f"owner={EVIL_NS_DOMAIN} type=A data={EVIL_NS_IP} "
            f"qname={TRIGGER_QNAME} policy=legacy_accept"
        ),
    ]
    return _flow(
        rng,
        POISON_TS,
        "10.13.37.45",
        TRIGGER_QNAME,
        "A",
        ATTACKER_AUTH_IP,
        [answer],
        authority=authority,
        additional=additional,
        cache_extra=poison_cache,
        debug_extra=debug_extra,
    )


def _victim_followup_flow(rng: random.Random) -> FlowResult:
    answer = DNSRR(rrname=VICTIM_DOMAIN, type="A", ttl=300, rdata=EVIL_NS_IP)
    victim_cache = [CacheEvent(VICTIM_QUERY_TS + 0.080, VICTIM_DOMAIN, "A", 300, EVIL_NS_IP)]
    debug_extra = [
        (
            f"{_iso(VICTIM_QUERY_TS + 0.004)} DEBUG cache_hit owner={VICTIM_DOMAIN} "
            f"type=NS data={EVIL_NS_DOMAIN}"
        ),
        (
            f"{_iso(VICTIM_QUERY_TS + 0.090)} DEBUG cache_insert source=Answer "
            f"owner={VICTIM_DOMAIN} type=A data={EVIL_NS_IP} "
            f"qname={VICTIM_DOMAIN} upstream={EVIL_NS_DOMAIN}"
        ),
    ]
    return _flow(
        rng,
        VICTIM_QUERY_TS,
        "10.13.37.88",
        VICTIM_DOMAIN,
        "A",
        EVIL_NS_IP,
        [answer],
        cache_extra=victim_cache,
        debug_extra=debug_extra,
    )


def _baseline_cache(rng: random.Random) -> list[CacheEvent]:
    events: list[CacheEvent] = [
        CacheEvent(BASE_TS - 7200, "victim.com", "NS", 86400, "ns1.victim-dns.net"),
        CacheEvent(BASE_TS - 7200, "victim.com", "NS", 86400, "ns2.victim-dns.net"),
        CacheEvent(BASE_TS - 7200, "bank.victim.com", "NS", 86400, "ns1.bank.victim.com"),
        CacheEvent(BASE_TS - 7200, "bank.victim.com", "NS", 86400, "ns2.bank.victim.com"),
        CacheEvent(BASE_TS - 7200, "ns1.bank.victim.com", "A", 86400, "192.0.2.41"),
        CacheEvent(BASE_TS - 7200, "ns2.bank.victim.com", "A", 86400, "192.0.2.42"),
    ]
    zones = list(LEGIT_AUTHS)
    for _ in range(140):
        zone = rng.choice(zones)
        qname = f"{rng.choice(SUBDOMAIN_PREFIXES)}-{_hex_label(rng, 4)}.{zone}"
        events.append(
            CacheEvent(
                BASE_TS - rng.randint(60, 6000),
                qname,
                "A",
                rng.randint(900, 7200),
                _random_ip(rng),
            )
        )
    decoy_ns = [
        ("bank-victim.com", "NS", "ns1.bank-victim-safe.example"),
        ("bank.victim.co", "NS", "ns1.victim-co.example"),
        ("fakevictim.com", "NS", "ns1.parking.example"),
        ("victim.com.attacker.net", "NS", "ns1.attacker.net"),
    ]
    for name, rtype, data in decoy_ns:
        events.append(CacheEvent(BASE_TS - rng.randint(120, 2400), name, rtype, 86400, data))
    return events


def _scheduled_times(
    rng: random.Random,
    count: int,
    start: float,
    end: float,
) -> list[float]:
    span = end - start
    return sorted(start + (idx + rng.random()) * span / count for idx in range(count))


def _build_artifacts(seed: int) -> tuple[list[PktSpec], list[CacheEvent], list[str], list[str], dict[str, Any]]:
    rng = random.Random(seed)
    decoy_pool = list(DECOY_FLAGS)
    rng.shuffle(decoy_pool)
    decoy_pool = decoy_pool[:TXT_DECOY_BUDGET]

    deck = (
        ["benign"] * BENIGN_FLOWS
        + ["recon"] * ATTACKER_RECON_FLOWS
        + ["referral"] * LEGIT_REFERRAL_FLOWS
        + ["oob"] * OOB_DECOY_FLOWS
        + ["lookalike"] * LOOKALIKE_DECOY_FLOWS
        + ["glue"] * ADDITIONAL_GLUE_DECOY_FLOWS
    )
    rng.shuffle(deck)

    before_count = int(len(deck) * 0.42)
    between_count = int(len(deck) * 0.38)
    after_count = len(deck) - before_count - between_count
    times = (
        _scheduled_times(rng, before_count, BASE_TS + 2, POISON_TS - 2)
        + _scheduled_times(rng, between_count, AFTER1_TS + 1, VICTIM_QUERY_TS - 2)
        + _scheduled_times(rng, after_count, AFTER2_TS + 1, BASE_TS + 900)
    )

    packets: list[PktSpec] = []
    cache_events = _baseline_cache(rng)
    resolver_log: list[str] = []
    debug_log: list[str] = [
        f"{_iso(BASE_TS)} INFO technitium_dns version=8.0.0 mode=recursive",
        f"{_iso(BASE_TS)} INFO capture_window opened sensor=resolver-span",
    ]

    def add_flow(flow: FlowResult) -> None:
        packets.extend(flow.packets)
        cache_events.extend(flow.cache_events)
        resolver_log.extend(flow.resolver_log)
        debug_log.extend(flow.debug_log)

    for kind, ts in zip(deck, times):
        if kind == "benign":
            add_flow(_benign_flow(rng, ts, decoy_pool))
        elif kind == "recon":
            add_flow(_attacker_recon_flow(rng, ts, decoy_pool))
        elif kind == "referral":
            add_flow(_legit_referral_flow(rng, ts, decoy_pool))
        elif kind == "oob":
            add_flow(_oob_decoy_flow(rng, ts, decoy_pool))
        elif kind == "lookalike":
            add_flow(_lookalike_decoy_flow(rng, ts, decoy_pool))
        elif kind == "glue":
            add_flow(_additional_glue_decoy_flow(rng, ts, decoy_pool))
        else:
            raise ValueError(kind)

    poison = _poison_flow(rng)
    add_flow(poison)
    followup = _victim_followup_flow(rng)
    add_flow(followup)

    packets.sort(key=lambda p: p.timestamp)
    resolver_log.sort()
    debug_log.sort()

    poison_packet_number = 0
    for idx, spec in enumerate(packets, start=1):
        pkt = spec.pkt
        if not pkt.haslayer(DNS):
            continue
        dns = pkt[DNS]
        if (
            dns.qr == 1
            and pkt[IP].src == ATTACKER_AUTH_IP
            and dns.qd is not None
            and _rdata_name(dns.qd.qname) == TRIGGER_QNAME
            and dns.nscount > 0
        ):
            poison_packet_number = idx
            break
    if poison_packet_number == 0:
        raise RuntimeError("failed to locate poison packet after generation")

    evidence = {
        "victim_domain": VICTIM_DOMAIN,
        "malicious_ns": EVIL_NS_DOMAIN,
        "malicious_ns_ip": EVIL_NS_IP,
        "trigger_qname": TRIGGER_QNAME,
        "poison_packet_number": poison_packet_number,
        "poison_dns_txid": f"0x{poison.upstream_txid:04x}",
        "first_cache_seen": _iso(AFTER1_TS),
        "first_victim_query": _iso(VICTIM_QUERY_TS),
    }
    evidence_material = (
        f"{evidence['victim_domain']}|{evidence['malicious_ns']}|"
        f"{evidence['malicious_ns_ip']}|{evidence['trigger_qname']}|"
        f"{evidence['poison_packet_number']}"
    )
    evidence["evidence_token"] = "CTF{" + hashlib.sha256(evidence_material.encode()).hexdigest()[:16] + "}"
    evidence["notes"] = {
        "packet_number_basis": "Wireshark/tshark frame number, 1-based, no display filter",
        "real_flag_in_pcap": False,
        "txt_records_are_decoys": True,
    }
    return packets, cache_events, resolver_log, debug_log, evidence


def _snapshot_entries(cache_events: list[CacheEvent], snapshot_ts: float) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in cache_events:
        if event.timestamp > snapshot_ts:
            continue
        remaining = event.ttl - int(snapshot_ts - event.timestamp)
        if remaining <= 0:
            continue
        rows.append(
            {
                "name": event.name.rstrip(".").lower(),
                "type": event.rtype,
                "ttl": remaining,
                "data": event.data.rstrip(".") if event.rtype != "TXT" else event.data,
            }
        )
    # Deduplicate by current rr tuple, keeping the row with the highest TTL.
    dedup: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (row["name"], row["type"], row["data"])
        if key not in dedup or row["ttl"] > dedup[key]["ttl"]:
            dedup[key] = row
    return sorted(dedup.values(), key=lambda r: (r["name"], r["type"], r["data"]))


def _format_cache_snapshot(name: str, snapshot_ts: float, rows: list[dict[str, Any]]) -> str:
    lines = [
        "=== Technitium DNS Server 8.0.0 Cache Snapshot ===",
        f"Snapshot: {name}",
        f"Generated: {_iso(snapshot_ts)}",
        f"Entries: {len(rows)}",
        "",
        f"{'Domain':<54} {'Type':<6} {'TTL':<7} Data",
        "-" * 118,
    ]
    for row in rows:
        lines.append(f"{row['name']:<54} {row['type']:<6} {row['ttl']:<7} {row['data']}")
    lines.append("")
    lines.append("=== End of cache snapshot ===")
    return "\n".join(lines) + "\n"


def _write_pcapng(path: Path, packets: list[PktSpec]) -> None:
    writer = PcapNgWriter(str(path))
    try:
        for spec in packets:
            writer.write(spec.pkt)
    finally:
        writer.close()


def _write_known_good(path: Path) -> None:
    lines = [
        "# Asset inventory / known-good DNS delegations.",
        "# This is not a complete Internet root; use it to eliminate false positives.",
        "",
        "victim.com NS ns1.victim-dns.net",
        "victim.com NS ns2.victim-dns.net",
        "bank.victim.com NS ns1.bank.victim.com",
        "bank.victim.com NS ns2.bank.victim.com",
        "ns1.bank.victim.com A 192.0.2.41",
        "ns2.bank.victim.com A 192.0.2.42",
        "attacker.net NS ns1.attacker.net",
        "attacker.net NS ns2.attacker.net",
        "ns1.attacker.net A 203.0.113.66",
        "ns2.attacker.net A 203.0.113.67",
        "",
    ]
    for zone in sorted(LEGIT_AUTHS):
        lines.append(f"{zone} NS ns1.{zone}")
        lines.append(f"{zone} NS ns2.{zone}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_submit_format(path: Path) -> None:
    path.write_text(
        """# Submit Format

Submit a single JSON object to the checker.

Required fields:

```json
{
  "victim_domain": "domain that received the poisoned delegation",
  "malicious_ns": "nameserver injected by the malicious response",
  "malicious_ns_ip": "A record/glue address for that nameserver",
  "trigger_qname": "query name that caused the resolver to ask attacker-controlled auth",
  "poison_packet_number": 0,
  "poison_dns_txid": "0x0000",
  "first_cache_seen": "YYYY-MM-DDTHH:MM:SSZ",
  "first_victim_query": "YYYY-MM-DDTHH:MM:SSZ"
}
```

Notes:

- `poison_packet_number` is the Wireshark/tshark frame number in the full
  capture, starting at 1, without a display filter.
- `poison_dns_txid` is accepted as a cross-check and should come from the same
  DNS response.
- Normalize domain names to lowercase and omit the trailing dot.
- TXT records containing `CTF{...}` are canaries, not the final answer.
""",
        encoding="utf-8",
    )


def _write_player_readme(path: Path) -> None:
    path.write_text(
        """# Bailiwick Breakout 2: Trust Boundary

## Scenario

Bạn là SOC analyst điều tra một sự cố DNS cache poisoning trên recursive
resolver nội bộ. Người dùng báo rằng `bank.victim.com` thỉnh thoảng trả về
một địa chỉ lạ sau khi họ mở một trang có quảng cáo bên thứ ba.

Bạn được giao packet capture, nhiều cache snapshot và log resolver. Nhiệm vụ
không phải là tìm một flag lộ trong packet. Hãy tái dựng chuỗi tấn công và
submit evidence JSON cuối cùng.

## Artifacts

| File | Nội dung |
|---|---|
| `capture.pcapng` | DNS traffic tại resolver, gồm traffic thật và decoy |
| `cache_before.txt` | Cache trước khung giờ nghi vấn |
| `cache_after_1.txt` | Cache ngay sau trigger query |
| `cache_after_2.txt` | Cache sau khi user truy cập victim domain |
| `resolver.log` | Query log của resolver |
| `technitium_debug.log` | Debug log có cache insert event và noise |
| `known_good_zones.txt` | Delegation hợp lệ theo asset inventory |
| `submit_format.md` | Format JSON cần submit |

## Mission

Xác định poisoned delegation, malicious authoritative response và timeline
chứng minh resolver đã dùng delegation giả đó. Submit JSON theo
`submit_format.md`.

Các TXT record chứa `CTF{...}` trong pcap là canary/decoy.

## Submit

Tạo `evidence.json` theo khung:

```json
{
  "victim_domain": "domain bị poisoned delegation",
  "malicious_ns": "nameserver độc được inject",
  "malicious_ns_ip": "IP/glue của nameserver độc",
  "trigger_qname": "query đã khiến resolver hỏi authoritative attacker",
  "poison_packet_number": 0,
  "poison_dns_txid": "0x0000",
  "first_cache_seen": "YYYY-MM-DDTHH:MM:SSZ",
  "first_victim_query": "YYYY-MM-DDTHH:MM:SSZ"
}
```

```bash
curl -X POST http://<checker-host>:5000/submit \\
  -H "Content-Type: application/json" \\
  -d @evidence.json
```

## Hints

- Suspicious data is not necessarily in the Answer section.
- A DNS response containing a record is not enough; prove that it entered cache.
- Compare Authority-section NS records with cache snapshots and known-good
  delegations.
- Watch for lookalike domains. `name.endswith(zone)` without a dot boundary is
  a trap.
""",
        encoding="utf-8",
    )


def _parse_seed(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError:
        return int(value, 10)


def _default_expected_path(repo_root: Path, out_dir: Path) -> Path:
    if out_dir == (repo_root / "challenge").resolve():
        return (repo_root / "server" / "expected_solution.json").resolve()
    return (out_dir / "expected_solution.json").resolve()


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out",
        default=str(repo_root / "challenge"),
        help="Output directory (default: <repo_root>/challenge)",
    )
    parser.add_argument(
        "--expected-out",
        default=None,
        help=(
            "Private expected-solution path. Default is server/expected_solution.json "
            "when writing to the repo challenge directory, otherwise <out>/expected_solution.json."
        ),
    )
    parser.add_argument(
        "--seed",
        type=_parse_seed,
        default=0xC0FFEE,
        help="Deterministic seed; decimal and 0x-prefixed hex are accepted",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    out_dir = Path(args.out).resolve()
    expected_path = (
        Path(args.expected_out).resolve()
        if args.expected_out
        else _default_expected_path(repo_root, out_dir)
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    expected_path.parent.mkdir(parents=True, exist_ok=True)
    log.info("Output dir: %s", out_dir)
    log.info("Expected solution: %s", expected_path)
    log.info("Seed: 0x%x", args.seed)

    packets, cache_events, resolver_log, debug_log, evidence = _build_artifacts(args.seed)
    log.info("Generated %d packets", len(packets))
    log.info("Poison packet number: %s", evidence["poison_packet_number"])
    log.info("Poison DNS TXID: %s", evidence["poison_dns_txid"])

    # Remove legacy beginner artifacts so the player cannot solve the old path.
    for legacy in ("capture.pcap", "cache_dump.txt"):
        legacy_path = out_dir / legacy
        if legacy_path.exists():
            legacy_path.unlink()
    stale_public_answer = (out_dir / "expected_solution.json").resolve()
    if stale_public_answer != expected_path and stale_public_answer.exists():
        stale_public_answer.unlink()

    _write_pcapng(out_dir / "capture.pcapng", packets)
    (out_dir / "resolver.log").write_text("\n".join(resolver_log) + "\n", encoding="utf-8")
    (out_dir / "technitium_debug.log").write_text("\n".join(debug_log) + "\n", encoding="utf-8")
    (out_dir / "cache_before.txt").write_text(
        _format_cache_snapshot("cache_before", BASE_TS, _snapshot_entries(cache_events, BASE_TS)),
        encoding="utf-8",
    )
    (out_dir / "cache_after_1.txt").write_text(
        _format_cache_snapshot("cache_after_1", AFTER1_TS, _snapshot_entries(cache_events, AFTER1_TS)),
        encoding="utf-8",
    )
    (out_dir / "cache_after_2.txt").write_text(
        _format_cache_snapshot("cache_after_2", AFTER2_TS, _snapshot_entries(cache_events, AFTER2_TS)),
        encoding="utf-8",
    )
    _write_known_good(out_dir / "known_good_zones.txt")
    _write_submit_format(out_dir / "submit_format.md")
    _write_player_readme(out_dir / "README.md")
    expected_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    log.info("Wrote challenge artifacts")
    log.info("Wrote private expected solution")
    log.info("Evidence token for CTFd fallback: %s", evidence["evidence_token"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
