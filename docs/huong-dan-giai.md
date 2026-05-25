# Hướng dẫn giải — Bailiwick Breakout 2

> SPOILER. Chỉ đọc khi bạn đã thử phân tích artifact.

## Ý tưởng

Lỗ hổng nằm ở việc resolver cache record trong Authority/Additional section
mà không kiểm tra bailiwick. Vì vậy lời giải đúng không phải là tìm TXT flag,
mà là chứng minh:

1. Một response từ authoritative attacker đã chứa delegation ngoài thẩm quyền.
2. Delegation đó xuất hiện trong cache snapshot sau trigger.
3. Resolver sau đó dùng delegation giả để resolve victim domain.

Các TXT `CTF{...}` trong pcap đều là decoy.

## Step 1 — So cache snapshot

Parse `cache_before.txt` và `cache_after_1.txt`, tìm NS entry mới:

```text
bank.victim.com    NS    ...    ns.evilcorp.example
```

Đây là delegation bị poison. Trong cùng snapshot cũng có glue:

```text
ns.evilcorp.example    A    ...    6.6.6.6
```

So với `known_good_zones.txt`, delegation hợp lệ của `bank.victim.com` phải
trỏ về `ns1.bank.victim.com`/`ns2.bank.victim.com`.

## Step 2 — Tìm response đã inject delegation

Trong `capture.pcapng`, lọc DNS response có Authority record:

```text
dns.flags.response == 1 and dns.ns
```

Không chọn candidate chỉ vì nó out-of-bailiwick. Có nhiều decoy. Candidate
đúng phải vừa:

- có Authority `bank.victim.com NS ns.evilcorp.example`
- xuất phát từ response cho query thuộc attacker-controlled zone
- trùng với cache delta ở Step 1

Ghi lại:

- `trigger_qname`
- frame number trong Wireshark/tshark
- DNS transaction ID

## Step 3 — Lấy glue IP

Trong cùng response, xem Additional section:

```text
ns.evilcorp.example    A    6.6.6.6
```

Đối chiếu với `cache_after_1.txt`. Nếu chỉ thấy record trong pcap mà không có
trong cache, đó có thể là decoy.

## Step 4 — Chứng minh resolver đã dùng fake NS

Trong `cache_after_2.txt`, tìm victim A record mới:

```text
bank.victim.com    A    ...    6.6.6.6
```

Trong pcap/log, tìm query đầu tiên của user tới `bank.victim.com` sau thời
điểm poison. Resolver sẽ hỏi upstream `6.6.6.6`, tức nameserver giả.

## Step 5 — Submit evidence

Format:

```json
{
  "victim_domain": "bank.victim.com",
  "malicious_ns": "ns.evilcorp.example",
  "malicious_ns_ip": "6.6.6.6",
  "trigger_qname": "promo.attacker.net",
  "poison_packet_number": 0,
  "poison_dns_txid": "0x0000",
  "first_cache_seen": "2026-05-21T10:03:14Z",
  "first_victim_query": "2026-05-21T10:07:18Z"
}
```

Packet number và TXID phụ thuộc artifact đã generate, nên lấy từ pcap thật.

## Script reference

Repo có solver nội bộ:

```bash
python tools/solver/solve.py
```

Nó dựng evidence bằng cache correlation, không đọc `expected_solution.json`.

## Lỗi hay gặp

| Cách sai | Vì sao sai |
|---|---|
| `strings capture.pcapng | grep CTF` | TXT chỉ là canary/decoy |
| Chọn mọi Authority OOB | Có nhiều OOB decoy không vào cache |
| Dùng `name.endswith(zone)` ngây thơ | Dính lookalike như `fakevictim.com` |
| Nhìn mỗi pcap | Không chứng minh record đã được cache |
| Nhìn mỗi cache | Không xác định được malicious response/trigger |
