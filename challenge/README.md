# Bailiwick Breakout 2: Trust Boundary

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
curl -X POST http://<checker-host>:5000/submit \
  -H "Content-Type: application/json" \
  -d @evidence.json
```

## Hints

- Suspicious data is not necessarily in the Answer section.
- A DNS response containing a record is not enough; prove that it entered cache.
- Compare Authority-section NS records with cache snapshots and known-good
  delegations.
- Watch for lookalike domains. `name.endswith(zone)` without a dot boundary is
  a trap.
