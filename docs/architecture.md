# Architecture

## Service inventory

- **POPS module** (`pops/`): Python implementation cua paper Afek et al.
  (USENIX Security 2025), tu code lai theo Section 2-4 va Algorithm 1-4
  Appendix B. Hoat dong nhu UDP forwarding proxy giua resolver va
  authoritative thuc thuc. Apply Rl1 (CMS), Rl2 (fragment heuristic +
  scapy sniffer), Rl3 (bailiwick check). Mitigation = TC=1 + cleared
  sections.
- **Vulnerable resolver per stage**:
  - `dnsmasq-2.82` cho stage 1 (CVE-2020-25684 / DNSpooq).
  - `vulnerable-resolver` (glibc 2.24 wrapper qua res_send) cho stage 2
    (CVE-2017-12132).
  - `technitium-vulnerable` (Technitium DNS Server v7.0 official image)
    cho stage 3 (CVE-2021-43105).
- **non-compliant-resolver** (chi stage 2): demo limitation cua POPS
  voi resolver khong retry TCP khi nhan TC=1 (paper Section 4.2).
- **NSD authoritative** (`nsd-auth/`): NSD voi watcher reload zone
  dynamic tu shared volume khi registrar ghi.
- **Registrar service**: validate domain/IP, ghi zone file vao shared
  volume, trigger NSD reload.
- **Spoof helper**: raw IP socket UDP send (NET_RAW). Validate src/dst IP
  trong subnet challenge.
- **Flag service**: passive query loop cho flag A; HTTP validator cho
  evidence flag B. POST flag den HTTP listener cua attacker khi cache
  poison thanh cong.

## Stage networks

Moi stage co compose file rieng voi subnet isolated:

- Stage 1: `10.0.0.0/24`. POPS=10.0.0.2, dnsmasq=10.0.0.3, NSD=10.0.0.10,
  flag-service=10.0.0.20, registrar=10.0.0.30, spoof-helper=10.0.0.40.
- Stage 2: `10.0.2.0/24`. POPS=10.0.2.2, vuln-resolver=10.0.2.3,
  non-compliant=10.0.2.4, NSD=10.0.2.10. Flag/registrar/spoof tuong tu.
- Stage 3: `10.0.3.0/24`. POPS=10.0.3.2 (correct), pops-naive=10.0.3.6,
  technitium=10.0.3.3, NSD=10.0.3.10.

`docker-compose.master.yml` kept cho overview, profiles per-stage.

## POPS internals

`pops/source/`:
- `pops_module.py` - entrypoint, doc env, khoi dong proxy + API + sniffer.
- `proxy.py` - UDP forwarding loop, parse DNS, build TC=1 reply.
- `rules.py` - RuleEngine apply Rl2 -> Rl3 -> Rl1, log domain counter.
- `cms.py` - Count-Min Sketch, window-based reset.
- `bailiwick.py` - hai variant (correct + naive). POPS_NAIVE_BAILIWICK=1
  switch sang naive theo Algorithm 4 Appendix B.
- `api.py` - HTTP API: /api/v1/lab/pops-log, /api/v1/lab/check-bailiwick,
  /api/v1/lab/cms-stats, /api/v1/lab/config.

Default param theo paper Section 5: `tau=5, W=1.0s, d=5, w=200`.

## Flag flow

Flag A (reproduction): Passive query loop trong flag-service mac dinh
query target domain moi `QUERY_INTERVAL` giay qua resolver. Khi response
IP khac DEFAULT_IP, flag-service POST flag den IP do tai port 8080.
Player phai chay HTTP listener tai `<attacker_ip>:8080/flag` de nhan flag.

Flag B (evaluation): Player POST evidence den endpoint validator. Validator
check schema + semantic consistency + analysis text. Khi pass tra flag value.

## Limitation va edge cases biet truoc

- **Stage 1 Rl2 disabled**: POPS_FRAG_THRESHOLD=65535 de tat heuristic.
  Stage 1 chi test Rl1.
- **Stage 3 dual POPS**: pops va pops-naive chay song song. Player
  dung pops-naive endpoint cho flag 3B.
- **Technitium image**: `technitium/dns-server:7.0` co the bi xoa khoi
  Docker Hub trong tuong lai. Mitigation: tarball local copy.
- **glibc 2.24 (Stretch archived)**: APT dung snapshot.debian.org.
  Build co the cham vi snapshot mirror toc do thap.
- **Fragment detection**: scapy AsyncSniffer can NET_RAW; neu khong co
  scapy se fallback chi dung size heuristic.
