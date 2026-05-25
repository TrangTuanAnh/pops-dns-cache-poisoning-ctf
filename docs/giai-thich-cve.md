# CVE-2021-43105 — Giải thích cho người mới

> Lỗ hổng Technitium DNS Server cho phép cache poisoning qua
> out-of-bailiwick NS injection.
>
> Đọc cái này SAU khi bạn đã chơi xong (vì hơi spoiler).

## Phần mềm dính lỗ hổng

**Technitium DNS Server** — một DNS server mã nguồn mở (C#/.NET) khá phổ
biến cho self-host. Các version ≤ **8.0** bị dính.

Fix ở version **8.0.1** trở đi.

## Mô tả lỗ hổng

Khi Technitium làm recursive resolver và nhận response từ một
authoritative, code không verify rằng các record trong **Authority** và
**Additional** section thuộc bailiwick của authoritative đang trả lời.

Hậu quả: attacker control một authoritative bất kỳ (vd authoritative cho
`attacker.net` mà attacker thuê) có thể inject NS/A record giả cho **bất
kỳ domain nào** vào cache của Technitium.

## Tấn công đi qua bước nào?

```
[1] Attacker đặt 1 web ad trỏ tới x.attacker.net (hoặc dùng cách khác
    để dụ resolver query domain mà attacker control).

[2] Resolver query: x.attacker.net A?

[3] Authoritative của attacker.net (do attacker quản lý) trả về:

    Question:
      x.attacker.net A
    Answer:
      x.attacker.net A 1.2.3.4              <- hợp lệ
    Authority:
      bank.victim.com NS ns.evilcorp.example  <- OOB! Không thuộc attacker.net
    Additional:
      ns.evilcorp.example A 6.6.6.6          <- glue cho NS giả

[4] Vulnerable Technitium thấy mọi record là "hợp lệ" → cache:
      bank.victim.com → ns.evilcorp.example
      ns.evilcorp.example → 6.6.6.6

[5] Lần sau, user trong công ty query bank.victim.com:
      Resolver có cache → hỏi ns.evilcorp.example (do attacker control).
      ns.evilcorp.example trả về: bank.victim.com A 6.6.6.6 (IP attacker)
      User vào "bank.victim.com" → kết nối thực sự tới server attacker.
      Attacker show trang giả ngân hàng → cướp credential.
```

Tất cả không cần brute-force gì cả. Không cần spoofed source IP. Không
cần race condition. Chỉ cần **một authoritative attacker control + dụ
resolver query nó một lần**.

## Tại sao bug tồn tại?

Code recursive resolver có 2 bước:

1. **Process answer**: trích các record từ response.
2. **Cache**: nhét vào cache.

Giữa hai bước phải có **bailiwick validation**:
```
for each record in (Authority, Additional):
    if record.name không thuộc bailiwick của authoritative trả lời:
        DROP record (không cache)
```

Code Technitium ≤ 8.0 thiếu bước này (hoặc làm sai). Mọi record được
cache thẳng.

## Tại sao bailiwick quan trọng?

Internet DNS hoạt động dựa trên **niềm tin có giới hạn**: bạn tin
authoritative cho `.com` cho biết NS của `example.com`. Bạn tin
authoritative cho `example.com` cho biết NS của `mail.example.com`.

Nhưng bạn **không nên** tin một authoritative cho `attacker.net` về bất
cứ gì ngoài `attacker.net`. Đó là rule. Bailiwick check là cách enforce
rule.

## Lịch sử các bug tương tự

CVE này không phải đầu tiên. DNS đã có nhiều thế hệ bug bailiwick:

| Năm | Bug | Tóm tắt |
|-----|-----|---------|
| 1997 | "Bailiwick patches" cho BIND | Bug bailiwick đầu tiên được công khai |
| 2008 | Kaminsky attack | Khác — race TXID, không phải bailiwick |
| 2021 | **CVE-2021-43105 (Technitium)** | Modern version của bug 1997 |
| 2023 | MaginotDNS (USENIX) | Inconsistent bailiwick check giữa hot/cold path |

Bug cùng pattern cứ tái xuất hiện trong DNS implementations mới. Người
viết DNS resolver hay quên bailiwick check hoặc làm check bằng suffix quá
ngây thơ.

## Fix như thế nào?

Technitium fix ở version 8.0.1:

```csharp
// Trước (vulnerable):
foreach (var record in response.AuthorityRecords)
    cache.Insert(record);

// Sau (fixed):
foreach (var record in response.AuthorityRecords)
    if (IsWithinBailiwick(record.Name, response.AuthoritativeZone))
        cache.Insert(record);
    else
        log.Warn("Dropped OOB record: {record}");
```

`IsWithinBailiwick(name, zone)` tối thiểu phải normalize case, bỏ trailing
dot, rồi kiểm tra boundary nhãn:

```text
name == zone OR name ends with "." + zone
```

Không nên chỉ dùng `name.EndsWith(zone)`, vì sẽ nhầm các tên kiểu
`fakevictim.com` hoặc `notvictim.com`.

## Liên quan tới paper POPS (USENIX 2025)

Paper POPS đề xuất một module phòng thủ chạy ngoài resolver. Một trong 3
rule của POPS là **R_l3 (out-of-bailiwick)** — về bản chất chính là cái
bailiwick check ở trên, nhưng implement ở proxy thay vì sửa từng resolver.

POPS được trích dẫn CVE-2021-43105 làm motivation. Logic R_l3 (Algorithm
4 trong Appendix B paper) chính xác là cái Technitium 8.0.1 đã thêm.

## Phòng ngừa

Nếu bạn vận hành Technitium DNS Server, upgrade lên ≥ 8.0.1.

Nếu bạn viết DNS resolver code, hãy **luôn** validate bailiwick trước
khi cache. Không có shortcut.

## Tham khảo

- **NVD entry**: https://nvd.nist.gov/vuln/detail/CVE-2021-43105
- **Technitium changelog**: https://github.com/TechnitiumSoftware/DnsServer/releases
- **MaginotDNS paper** (USENIX 2023): https://www.usenix.org/conference/usenixsecurity23/presentation/li-xiang
- **RFC 7719** (DNS Terminology — bailiwick definition)
- **POPS paper** (USENIX 2025) — Algorithm 4 R_l3
