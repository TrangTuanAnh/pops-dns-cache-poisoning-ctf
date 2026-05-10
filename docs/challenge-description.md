# POPS CTF Challenge - Player Brief

## Premise

Ban dang evaluate mot DNS poisoning prevention system dua tren paper
**Afek, Berger, Bremler-Barr - "POPS: From History to Mitigation of DNS
Cache Poisoning Attacks"** (USENIX Security 25).

Muc tieu KHONG phai bypass POPS. Challenge gom hai loai task moi stage:

- **Flag A** - reproduce mot CVE lich su trong moi truong lab (POPS off);
- **Flag B** - design experiment de document mot limitation hoac
  implementation edge case ma paper de cap.

## Threat model

- Ban la **off-path attacker**: gui packet vao network, co the spoof IP
  cua authoritative trong subnet challenge, KHONG MITM, KHONG truy cap
  truc tiep resolver/POPS.
- Mot so endpoint duoc cap voi label "lab convenience" (vi du
  `/api/v1/lab/spoof-udp`, `/api/v1/lab/pops-log`,
  `/api/v1/lab/check-bailiwick`). Day la abstraction phuc vu lab,
  KHONG phai capability cua attacker that.
- Sau khi giai stage 1 (ca hai flag) ban duoc cap SSH credential cho
  dev VM. Stage 2 unlock root tren dev VM. Stage 3 khong cap them.

## Stage 1 - Rl1 + CVE-2020-25684 (DNSpooq)

Resolver: `dnsmasq 2.82` tai `10.0.0.3`. Authoritative `10.0.0.10`.
POPS o `10.0.0.2`. Target: `corebank.meridian.example`, default IP
`1.2.3.6`.

- **Flag 1A**: poison dnsmasq cache (POPS off). Khi `corebank` resolve
  ve IP cua ban, flag-service POST flag den `<your-ip>:8080/flag`.
- **Flag 1B**: design experiment de demo CMS reset behavior tai bien
  window (footnote 12 paper Section 6.1). POST evidence den
  `/api/v1/stage1/window-evidence`.

References:
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-25684
- JSOF whitepaper: https://www.jsof-tech.com/disclosures/dnspooq/
- Public PoC: https://github.com/knqyf263/dnspooq

## Stage 2 - Rl2 + CVE-2017-12132 (glibc fragmentation)

Resolver: glibc 2.24 wrapper tai `10.0.2.3` (vulnerable),
non-compliant variant tai `10.0.2.4`. Authoritative tra response > MTU
de trigger IP fragmentation. Target: `fragment.meridian-stage2.example`,
default `1.2.3.7`.

- **Flag 2A**: SFrag attack - predict IP-ID, inject second fragment gia
  mao truoc khi second fragment that ve.
- **Flag 2B**: document limitation cua POPS voi resolver KHONG retry TCP
  khi nhan TC=1. So sanh `10.0.2.3` (compliant) va `10.0.2.4`
  (non-compliant). POST evidence den
  `/api/v1/stage2/noncompliant-evidence`. Lead: APNIC measurement
  Bhowmick et al. 2023, paper Section 4.2.

References:
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2017-12132
- glibc bug 21361: https://sourceware.org/bugzilla/show_bug.cgi?id=21361
- Herzberg-Shulman 2013: https://arxiv.org/abs/1205.4011

## Stage 3 - Rl3 + CVE-2021-43105 (Technitium)

Resolver: Technitium DNS Server v7.0 tai `10.0.3.3`. POPS variant
correct tai `10.0.3.2`, naive variant tai `10.0.3.6` (chi cho flag 3B).
Authoritative tai `10.0.3.10`. Target:
`vault.meridian-stage3.example`, default `1.2.3.8`.

- **Flag 3A**: dang ky `<your-zone>.example` qua registrar
  (`POST http://10.0.3.30:8080/api/v1/register`), host authoritative
  gia tai ns_ip cua ban, smuggle NS record cho `meridian-stage3.example`
  trong authority section. Khi Technitium accept (vulnerable bailiwick
  check) va cache, flag-service POST flag.
- **Flag 3B**: dung
  `POST http://10.0.3.6:8080/api/v1/lab/check-bailiwick` de probe naive
  variant. Tim it nhat 2 normalization concern (case, separator dot,
  trailing dot, IDN) ma naive sai khac correct. POST evidence den
  `/api/v1/stage3/normalization-evidence`. Phai dinh vi la "implementation
  pitfall" KHONG noi paper co bug.

References:
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-43105
- Technitium CHANGELOG:
  https://github.com/TechnitiumSoftware/DnsServer/blob/master/CHANGELOG.md
- MaginotDNS (Li et al. USENIX 23): https://www.usenix.org/conference/usenixsecurity23/presentation/li-xiang
- RFC 1035 (case insensitivity): https://www.rfc-editor.org/rfc/rfc1035

## Submitting

- Flag A duoc auto-deliver. Chay HTTP listener tai
  `<your-ip>:8080/flag` de nhan POST `{"flag_id": "1A", "flag": "..."}`.
- Flag B duoc tra trong response cua endpoint khi evidence valid.
- Tu xac thuc lai bang `POST /api/v1/submit/<FLAG_ID>` voi body
  `{"flag": "<chuoi>"}`.

## Lab convenience endpoint

- `POST http://10.0.x.40:8080/api/v1/lab/spoof-udp` - gui UDP spoof.
- `GET  http://10.0.x.2:8080/api/v1/lab/pops-log?domain=...` - counter.
- `POST http://10.0.x.2:8080/api/v1/lab/check-bailiwick` - probe.
- `GET  http://10.0.x.20:8080/api/v1/state` - state hien tai cua flag-service.
