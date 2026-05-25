# Bailiwick Breakout 2: Trust Boundary

Đây là một bài CTF forensic về DNS cache poisoning dựa trên
**CVE-2021-43105** trong Technitium DNS Server. Bản này được thiết kế theo
hướng điều tra incident thật: người chơi phải correlate pcap, cache snapshot
và log để chứng minh poisoned delegation đã đi vào cache.

Không có flag thật nằm plaintext trong packet. Các chuỗi `CTF{...}` trong
pcap là decoy.

## Bạn muốn làm gì?

### Chơi challenge

Vào [`challenge/`](challenge/):

```text
challenge/
├── README.md
├── capture.pcapng
├── cache_before.txt
├── cache_after_1.txt
├── cache_after_2.txt
├── resolver.log
├── technitium_debug.log
├── known_good_zones.txt
└── submit_format.md
```

Mục tiêu là dựng lại evidence JSON gồm victim domain, malicious NS, glue IP,
trigger query, packet number/TXID và timeline.

### Host checker

Vào [`server/`](server/). Checker Flask nhận `POST /submit` với evidence JSON
và validate bằng file private `server/expected_solution.json` sinh từ generator.
Không phát file này trong bundle cho người chơi.
Nếu file private chưa có, chạy `python tools/generator/gen_challenge.py` trước.

```bash
cd server
docker compose up -d --build
```

### Regen artifact hoặc verify

Vào [`tools/`](tools/):

```bash
# Sinh lại challenge hard-only
python tools/generator/gen_challenge.py

# Auto dựng evidence để kiểm tra pipeline
python tools/solver/solve.py
```

## Tài liệu học thêm

- [`docs/khai-niem-co-ban.md`](docs/khai-niem-co-ban.md) — DNS, recursive
  resolver, authoritative, bailiwick.
- [`docs/giai-thich-cve.md`](docs/giai-thich-cve.md) — CVE-2021-43105 hoạt
  động ra sao.
- [`docs/huong-dan-giai.md`](docs/huong-dan-giai.md) — walkthrough đầy đủ,
  có spoiler.

## Một dòng tóm tắt

> Có người đã khiến recursive resolver tin một delegation ngoài thẩm quyền.
> Hãy chứng minh chain đó bằng evidence, không phải bằng cách grep flag.
