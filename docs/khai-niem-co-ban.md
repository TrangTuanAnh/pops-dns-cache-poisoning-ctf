# Khái niệm cơ bản — cho người mới

Tài liệu nhanh về DNS để chơi được bài này. Nếu bạn đã biết DNS thì skip.

## DNS là gì?

DNS = Domain Name System = hệ thống ánh xạ tên miền sang IP.

Bạn gõ `google.com` vào trình duyệt. Trình duyệt không biết "google.com"
ở đâu — nó cần một IP, vd `142.250.80.100`. Việc tra cứu đó gọi là **phân
giải tên miền** (DNS resolution).

Có 3 vai chính:

| Vai | Việc làm |
|-----|----------|
| **Client** | Máy của bạn. Hỏi "google.com là IP nào?" |
| **Resolver** | Máy chuyên trả lời câu hỏi đó. Thường do ISP / công ty / Cloudflare (1.1.1.1) cung cấp. |
| **Authoritative** | Máy chính thức quản lý một zone. Vd Google vận hành authoritative cho `google.com`. |

Flow điển hình:

```
Client → Resolver:        google.com là IP nào?
Resolver → root:          .com nameserver ở đâu?
root → Resolver:          hỏi a.gtld-servers.net
Resolver → gtld-servers:  google.com nameserver ở đâu?
gtld-servers → Resolver:  hỏi ns1.google.com
Resolver → ns1.google:    google.com là IP nào?
ns1.google → Resolver:    142.250.80.100
Resolver → Client:        142.250.80.100
```

Resolver phải đi nhiều bước. Để tiết kiệm, nó **cache** kết quả. Lần sau
client hỏi `google.com`, resolver trả luôn IP đã cache.

## DNS message gồm 4 section

Mỗi DNS query hoặc response chia thành 4 phần:

| Section | Nội dung |
|---------|----------|
| **Question** | Câu hỏi (vd "google.com qtype=A") |
| **Answer** | Câu trả lời trực tiếp (vd "google.com A 142.250.80.100") |
| **Authority** | Nameserver nào quản lý zone này (vd "google.com NS ns1.google.com") |
| **Additional** | Thông tin phụ — glue records, EDNS, hint... |

Section nào quan trọng phụ thuộc vào tình huống. Khi cache poisoning,
section **Authority** và **Additional** là chỗ attacker hay nhét trojan.

## Bailiwick là gì?

Bailiwick là "phạm vi thẩm quyền". Authoritative server cho `example.com`
chỉ được phép cung cấp record cho domain **dưới** `example.com`:

- ✅ `example.com A ...` — OK
- ✅ `www.example.com A ...` — OK (subdomain)
- ✅ `mail.example.com MX ...` — OK
- ❌ `google.com A ...` — KHÔNG OK (vượt thẩm quyền)
- ❌ `bank.victim.com NS ...` — KHÔNG OK

Khi authoritative trả về record vượt thẩm quyền, đó gọi là
**out-of-bailiwick** (OOB).

Resolver tốt sẽ **từ chối** record OOB. Resolver buggy thì **tin** và
cache nó. Đó là CVE-2021-43105.

## Cache poisoning là gì?

Cache poisoning = chèn record giả vào cache của resolver.

Mục tiêu: lần sau client query một domain, resolver trả IP của attacker
(thay vì IP thật). Attacker từ đó:
- Lừa user vào trang phishing giống y hệt trang ngân hàng.
- Đánh cắp credential, session cookie.
- MITM (man-in-the-middle) traffic HTTP.

Một số cách classic:
- **Kaminsky attack** (2008): brute-force TXID/port của response.
- **DNSpooq** (2020-2021, CVE-2020-25684): exploit dnsmasq.
- **Out-of-bailiwick injection** (CVE-2021-43105): inject NS qua
  Authority section, không cần brute-force gì cả.

Bài này là về **cách thứ 3**.

## pcap là gì?

`.pcap` / `.pcapng` = file lưu lại **gói tin** (network packet) bắt được
tại một interface. Tool điển hình:

- **Wireshark** — GUI để mở pcap, xem từng packet chi tiết. Có filter
  rất mạnh.
- **tshark** — CLI version của Wireshark.
- **tcpdump** — tool Unix classic để bắt + xem pcap.
- **scapy** (Python) — đọc / sửa / tạo pcap programmatically.

Trong bài này, `capture.pcapng` chứa traffic DNS bắt tại resolver công ty
trong khoảng thời gian xảy ra attack.

## DNS record types phổ biến

| Type | Mục đích |
|------|----------|
| **A** | IPv4 address. Vd `google.com A 142.250.80.100` |
| **AAAA** | IPv6 address |
| **CNAME** | Alias. Vd `www.example.com CNAME example.com` |
| **MX** | Mail server. Vd `example.com MX 10 mail.example.com` |
| **NS** | Name server quản lý zone. Vd `example.com NS ns1.example.com` |
| **TXT** | Text record. Linh tinh — SPF, DKIM, verification, canary... |
| **PTR** | Reverse DNS (IP → name) |

Trong bài này:
- **NS** là vector của attacker (inject NS giả qua Authority OOB).
- **TXT** chỉ là nhiễu/canary; không phải đáp án thật.

## Câu hỏi nhanh tự kiểm tra

1. Resolver vs authoritative — khác nhau chỗ nào?
2. Authority section có nhiệm vụ gì?
3. Bailiwick — định nghĩa 1 câu?
4. Nếu authoritative cho `attacker.net` trả về record cho `victim.com`
   thì sao?

Trả lời được hết → đủ kiến thức chơi bài này.

## Đọc thêm

- **DNS for beginners**: https://www.cloudflare.com/learning/dns/what-is-dns/
- **RFC 1035** (DNS standard): mô tả gốc về DNS.
- **RFC 7719**: terminology DNS (định nghĩa "bailiwick" chính thức).
- **Wireshark DNS filter**: https://wiki.wireshark.org/DNS
