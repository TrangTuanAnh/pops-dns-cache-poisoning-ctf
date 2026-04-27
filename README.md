# POPS CTF - code scaffold

Thu muc nay la phan code cho do an CTF dua tren POPS. Hien tai repo moi o muc setup so bo: da co cau truc thu muc, Docker/Compose skeleton, service stub va tai lieu ngan de team bat dau tach viec. Chua dung lab/exploit hoan chinh.

## Huong tu proposal

Proposal trong `../Doc/POPS_CTF_Proposal_v2.md` chia challenge thanh 3 stage:

- Stage 1: POPS `R_l1`, CVE-2020-25684 / DNSpooq, resolver vulnerable la `dnsmasq 2.82`.
- Stage 2: POPS `R_l2`, CVE-2017-12132, resolver wrapper dua tren `glibc`.
- Stage 3: POPS `R_l3`, CVE-2021-43105, Technitium DNS Server vulnerable va bailiwick checks.

Moi stage se co flag A cho reproduction CVE va flag B cho edge-case/limitation evaluation. Scaffold hien tai giu dung ranh gioi do, nhung cac verifier moi la placeholder.

## Cau truc

```text
code/
├── docker-compose.master.yml
├── docker-compose.stage1.yml
├── docker-compose.stage2.yml
├── docker-compose.stage3.yml
├── pops/
│   ├── Dockerfile
│   ├── entrypoint.sh
│   ├── source/
│   └── patches/
├── dnsmasq-2.82/
├── vulnerable-resolver/
├── technitium-vulnerable/
├── nsd-auth/
│   └── zones/
├── registrar-service/
├── spoof-helper/
├── flag-service/
├── docs/
├── scripts/
└── reference-solutions/
```

## Setup nhanh

```powershell
Copy-Item .env.example .env
.\scripts\check-prereqs.ps1
docker compose -f docker-compose.stage1.yml config
```

Neu chi muon xem service stub chay duoc, co the thu:

```powershell
docker compose -f docker-compose.stage1.yml up --build
```

Luu y: lenh tren chi dung cho smoke test skeleton. POPS source tu Zenodo, exploit code, verifier that va patch lab chua duoc tich hop.

## Viec can lam tiep

1. Tai artifact POPS tu Zenodo vao `pops/source/`, build va ghi lai exact commit/hash.
2. Hoan thien POPS transparent proxy thay cho placeholder trong `pops/entrypoint.sh`.
3. Reproduce Stage 1 voi dnsmasq 2.82 va public PoC DNSpooq.
4. Hoan thien resolver wrapper Stage 2, fragmentation harness va evidence verifier.
5. Chot cach lay Technitium v7.0 cho Stage 3, uu tien pin release artifact hoac local image.
6. Doi flag-service placeholder thanh verifier co replay/evidence validation.

## Ghi chu release

`reference-solutions/` khong release cho player. `docs/challenge-description.md` la ban player-facing so bo, can bo sung link paper/CVE va topology truoc khi mo challenge.

