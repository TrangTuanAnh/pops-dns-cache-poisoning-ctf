# POPS CTF - 3-flag scope (cleaned up)

> Bộ challenge research-style đánh giá module phòng thủ POPS theo paper
> "POPS: From History to Mitigation of DNS Cache Poisoning Attacks"
> (Afek et al., USENIX Security 2025).

## Scope

3 flag deterministic, mỗi flag tương ứng một limitation/property paper
thừa nhận:

| Flag | Tên | Rule POPS | Loại thí nghiệm |
|------|-----|-----------|-----------------|
| 1B | Window-edge experiment | Rℓ1 (Excessive Guessing) | Đo CMS reset bias tại biên window |
| 2B | TCP fallback compatibility | Rℓ2 (Fragmentation) | So sánh compliant vs non-compliant resolver |
| 3B | Algorithm 4 normalization | Rℓ3 (Out-of-Bailiwick) | Probe naive vs correct bailiwick check |

> Note: phiên bản trước có 6 flag (3 reproduction CVE + 3 limitation B).
> 3 flag A đã bị cut khỏi scope vì không thể reproduce reliably trong lab
> (port randomization của dnsmasq, SFrag race, Technitium login API quirk
> v7.0). Xem `CLEANUP.md` cho chi tiết.

## Cấu trúc

```text
code/
├── docker-compose.stage1.yml Rℓ1 + window experiment
├── docker-compose.stage2.yml Rℓ2 + TCP fallback
├── docker-compose.stage3.yml Rℓ3 + normalization probe
├── docker-compose.attacker.stage{1,2,3}.yml thêm attacker container
├── pops/ POPS module (cả 3 stage)
│ ├── source/ cms.py, bailiwick.py, rules.py, proxy.py, api.py
│ └── ...
├── dnsmasq-2.82/ Stage 1 resolver
├── vulnerable-resolver/ Stage 2 compliant resolver (glibc 2.24)
├── non-compliant-resolver/ Stage 2 non-compliant (servfail mode)
├── nsd-auth/ Authoritative
├── flag-service/ Validator cho 3 flag B
├── attacker/ Container chạy reference solutions
└── reference-solutions/
    ├── stage1_flag_b.py
    ├── stage2_flag_b.py
    └── stage3_flag_b.py
```

## Setup nhanh

```powershell
Copy-Item .env.example .env

docker compose -f docker-compose.stage1.yml -f docker-compose.attacker.stage1.yml up -d
docker exec pops-ctf-stage1-attacker-1 python /attack/stage1_flag_b.py
docker compose -f docker-compose.stage1.yml -f docker-compose.attacker.stage1.yml down -v

docker compose -f docker-compose.stage2.yml -f docker-compose.attacker.stage2.yml up -d
docker exec pops-ctf-stage2-attacker-1 python /attack/stage2_flag_b.py
docker compose -f docker-compose.stage2.yml -f docker-compose.attacker.stage2.yml down -v

docker compose -f docker-compose.stage3.yml -f docker-compose.attacker.stage3.yml up -d
docker exec pops-ctf-stage3-attacker-1 python /attack/stage3_flag_b.py
docker compose -f docker-compose.stage3.yml -f docker-compose.attacker.stage3.yml down -v
```

(Project name `pops-ctf-stage{1,2,3}` được set từ `name:` trong từng compose
file. Khi chuyển stage, nhớ down stage trước để tránh conflict subnet.)

## POPS implementation note

`pops/source/` là Python implementation theo paper Section 2-4 và
Algorithm 1-4 Appendix B (không phải Zenodo artifact). Default param theo
paper: `τ=5, W=1.0s, d=5, w=200`.

Mitigation strict theo paper: rule trip -> tra reply TC=1 + clear toàn bộ
answer/authority/additional. Resolver tuân thủ RFC retry qua TCP với
authoritative - đây là contract.

Patches đã apply (production-quality fix):

1. **Skip OPT pseudo-RR (RFC 6891)** trong bailiwick check  - 
   `rules.py:_first_out_of_bailiwick`. Tránh false-positive khi resolver
   dùng EDNS0.
2. **Thêm TCP listener** vào `proxy.py`. POPS gốc chỉ UDP, retry path
   không hoạt động.

Xem `writeup/patches/pops-skip-opt-pseudo-rr.patch`.

## Stage flow

**Stage 1:** Attacker -> POPS (port 53) -> NSD. Test 10 query within < 1s
vs 5+5 query split qua biên W. Đo `forwarded` vs `rl1_truncated` qua
`/api/v1/lab/pops-log`. Submit evidence -> flag 1B.

**Stage 2:** Attacker query 2 resolver (compliant + non-compliant) cho
target có response trip Rℓ2 (FRAG_THRESHOLD=50). Compliant retry TCP qua
POPS -> success; non-compliant trả SERVFAIL. Submit evidence -> flag 2B.

**Stage 3:** Attacker probe `/api/v1/lab/check-bailiwick` của 2 POPS
variant (correct + naive) với 4 normalization case. Submit evidence với
test_results + analysis -> flag 3B.

## Writeup chính

`../writeup/writeup_beginner.md` - tutorial style, đầy đủ context paper +
output thật.
