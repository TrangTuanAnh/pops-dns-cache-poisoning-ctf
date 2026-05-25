# Đề xuất cải tiến CTF: Bailiwick Breakout — phiên bản nâng cao cho người chuyên môn

## 1. Tóm tắt đề xuất

Challenge hiện tại **Bailiwick Breakout** đang phù hợp để dạy người mới hiểu về DNS cache poisoning, bailiwick, Authority section, Additional section và CVE-2021-43105. Tuy nhiên, với người chơi có chuyên môn về network security, DNS hoặc incident response, độ khó hiện tại chưa đủ cao vì hướng giải vẫn khá trực tiếp: đọc cache dump, tìm NS record bất thường trong pcap, rồi lấy flag trong TXT record.

Đề xuất này cải tiến challenge từ dạng **forensic tìm flag trong pcap** thành dạng **điều tra DNS cache poisoning như incident thật**. Người chơi sẽ không thể chỉ `grep CTF{}` hoặc click Wireshark theo vài filter đơn giản, mà phải tái dựng toàn bộ attack chain, xác định bằng chứng, phân biệt decoy, và có thể phải viết detector script để chứng minh kết quả.

Tên đề xuất cho phiên bản mới:

```text
Bailiwick Breakout 2: Trust Boundary
```

Mục tiêu chính:

- Không chia challenge thành nhiều mức; bản phát ra mặc định là cấu hình khó nhất, nhiều nhiễu nhất.
- Giữ nguyên core concept: out-of-bailiwick NS injection.
- Loại bỏ flag lộ liễu trong TXT record.
- Bắt người chơi correlate nhiều nguồn dữ liệu: pcap, cache snapshot, resolver log, debug log.
- Thêm decoy đủ tinh vi để người chơi chuyên môn vẫn phải phân tích cẩn thận.
- Có thể mở rộng thành challenge chấm tự động bằng JSON evidence hoặc solver script.

---

## 2. Hiện trạng challenge hiện tại

### 2.1. Ý tưởng gốc

Challenge dựa trên lỗ hổng **CVE-2021-43105** của Technitium DNS Server. Khi hoạt động như recursive resolver, phiên bản vulnerable tin tưởng các record trong Authority và Additional section mà không kiểm tra đúng bailiwick. Attacker có thể điều khiển một authoritative server cho domain của mình, sau đó nhét NS record giả cho domain nạn nhân vào Authority section.

Luồng tấn công gốc:

```text
Client / Resolver query: x.attacker.net A?

Authoritative attacker.net trả lời:

Answer:
  x.attacker.net A 1.2.3.4

Authority:
  bank.victim.com NS ns.evilcorp.example

Additional:
  ns.evilcorp.example A 6.6.6.6
  ns.evilcorp.example TXT "CTF{...}"
```

Resolver vulnerable cache lại delegation giả:

```text
bank.victim.com NS ns.evilcorp.example
ns.evilcorp.example A 6.6.6.6
```

Sau đó khi user query `bank.victim.com`, resolver hỏi attacker-controlled nameserver thay vì nameserver thật.

### 2.2. Điểm mạnh của bản hiện tại

- Dễ hiểu, phù hợp cho người mới học DNS.
- Có đầy đủ tài liệu nền tảng: DNS, resolver, authoritative, Authority, Additional, bailiwick, pcap.
- Có forensic path rõ ràng: cache dump → pcap → Authority section → Additional TXT.
- Có decoy cơ bản để tránh việc submit flag đầu tiên tìm được.
- Phù hợp làm bài nhập môn về CVE-2021-43105.

### 2.3. Điểm yếu nếu nhắm tới người chuyên môn

- Flag nằm trực tiếp trong TXT record nên có thể bị tìm bằng `strings`, `grep`, Wireshark display filter hoặc script đơn giản.
- Chỉ cần correlate một cặp rõ ràng giữa `cache_dump.txt` và `capture.pcap`.
- Resolver log không bắt buộc, chỉ đóng vai trò noise.
- Decoy chưa đủ tinh vi; chủ yếu là flag giả hoặc random victim domain.
- Người chơi không cần chứng minh attack thành công qua timeline.
- Không bắt buộc hiểu sâu các edge case của bailiwick validation.
- Không cần viết detector hoặc phân tích programmatic.

---

## 3. Mục tiêu cải tiến

Phiên bản nâng cấp cần đạt các mục tiêu sau:

### 3.1. Về kiến thức

Người chơi sau khi giải xong phải hiểu và chứng minh được:

1. Resolver vulnerable đã cache record ngoài bailiwick.
2. Authoritative server của attacker đã trả về delegation giả.
3. Record xuất hiện trong packet chưa đủ; cần chứng minh record đó đã đi vào cache.
4. Additional section cũng nguy hiểm, không chỉ Authority section.
5. Bailiwick check ngây thơ bằng `endswith()` có thể bị bypass.
6. Timeline DNS có thể được tái dựng từ pcap, cache snapshot và log.

### 3.2. Về kỹ năng

Challenge nên kiểm tra các kỹ năng:

- Phân tích pcap bằng Wireshark/tshark/scapy.
- Đọc và hiểu DNS message structure.
- Correlate nhiều nguồn log.
- Viết script phát hiện out-of-bailiwick record.
- Loại bỏ false positive.
- Phân biệt evidence thật và decoy.
- Tái dựng attack timeline.
- Hiểu ranh giới trust boundary trong recursive DNS.

### 3.3. Về trải nghiệm CTF

- Không giải được bằng cách `grep CTF{}`.
- Không giải được chỉ bằng một filter Wireshark đơn giản.
- Có nhiều hướng tiếp cận: manual forensic, tshark pipeline, Python script.
- Có thể chấm bằng flag truyền thống hoặc JSON evidence.
- Có hint chung nhưng không chia hint theo mức dễ/trung bình/khó.

---

## 4. Thiết kế challenge mới

## 4.1. Tên challenge

```text
Bailiwick Breakout 2: Trust Boundary
```

## 4.2. Mô tả ngắn cho người chơi

```markdown
A company suspects its internal recursive DNS resolver was poisoned.
You are given packet captures, resolver cache snapshots, and resolver logs.
Find the poisoned delegation, identify the malicious authoritative response,
and reconstruct the attack chain.

Submit the final evidence token.
```

Bản tiếng Việt:

```markdown
Một công ty nghi ngờ recursive DNS resolver nội bộ đã bị cache poisoning.
Bạn được cung cấp pcap, snapshot cache và log resolver.
Hãy xác định delegation bị poison, gói tin độc hại và tái dựng chuỗi tấn công.

Submit evidence token cuối cùng.
```

## 4.3. File phát cho người chơi

Đề xuất bộ artifact:

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

### Vai trò từng file

| File | Vai trò |
|---|---|
| `README.md` | Mô tả incident, thời gian nghi vấn, yêu cầu submit |
| `capture.pcapng` | DNS traffic chính, có cả packet thật và decoy |
| `cache_before.txt` | Cache trước khi bị poison |
| `cache_after_1.txt` | Cache ngay sau trigger query |
| `cache_after_2.txt` | Cache sau khi user truy cập victim domain |
| `resolver.log` | Log truy vấn của resolver |
| `technitium_debug.log` | Log debug có noise, timestamp, cache insert event |
| `known_good_zones.txt` | Danh sách delegation hợp lệ để hỗ trợ loại false positive |
| `submit_format.md` | Mô tả format submit evidence |

---

# 5. Thay đổi cốt lõi so với bản hiện tại

## 5.1. Bỏ flag TXT khỏi packet

### Vấn đề hiện tại

Flag nằm trong Additional TXT record. Dù có decoy, người chơi vẫn có thể dùng chiến thuật liệt kê tất cả TXT chứa `CTF{}` rồi thử.

### Cải tiến

Không đặt flag trực tiếp trong pcap.

Thay vào đó, flag được sinh từ bằng chứng:

```text
CTF{sha256(victim_domain|fake_ns|fake_ns_ip|trigger_qname|packet_number)[:16]}
```

Ví dụ evidence thật:

```text
victim_domain   = bank.victim.com
fake_ns         = ns.evilcorp.example
fake_ns_ip      = 6.6.6.6
trigger_qname   = promo.attacker.net
packet_number   = 482
```

Flag sinh ra:

```text
CTF{7c1d9a2f91b03e44}
```

Người chơi không thể tìm flag bằng grep. Họ phải tìm đủ thành phần.

---

## 5.2. Chuyển từ “tìm flag” sang “submit evidence”

Có hai lựa chọn chấm.

### Option A — Flag truyền thống

Người chơi submit token đã hash từ evidence.

Ưu điểm:

- Dễ tích hợp với CTFd.
- Không cần custom checker phức tạp.

Nhược điểm:

- Người chơi có thể sai một phần evidence nhưng vẫn mò được nếu leak format.

### Option B — JSON evidence

Người chơi submit JSON:

```json
{
  "victim_domain": "bank.victim.com",
  "malicious_ns": "ns.evilcorp.example",
  "malicious_ns_ip": "6.6.6.6",
  "trigger_qname": "promo.attacker.net",
  "poison_packet_number": 482,
  "first_cache_seen": "2026-05-21T10:04:32Z",
  "first_victim_query": "2026-05-21T10:07:18Z"
}
```

Checker validate từng field.

Ưu điểm:

- Tốt hơn cho challenge chuyên môn.
- Chấm được partial hoặc strict.
- Buộc người chơi hiểu attack chain.

Nhược điểm:

- Cần viết checker riêng.

Khuyến nghị: dùng **Option B** nếu tổ chức có khả năng chạy checker custom. Nếu dùng CTFd cơ bản thì dùng Option A.

---

## 5.3. Thêm nhiều cache snapshot

Thay vì chỉ có một `cache_dump.txt`, dùng nhiều snapshot:

```text
cache_before.txt
cache_after_1.txt
cache_after_2.txt
```

### Mục tiêu

Người chơi phải chứng minh record poison không chỉ xuất hiện trong packet mà đã thật sự vào cache.

### Ví dụ

`cache_before.txt`:

```text
example.com            NS    172800    a.iana-servers.net
victim.com             NS    86400     ns1.victim-dns.net
```

`cache_after_1.txt`:

```text
bank.victim.com        NS    86394     ns.evilcorp.example
ns.evilcorp.example    A     86394     6.6.6.6
```

`cache_after_2.txt`:

```text
bank.victim.com        NS    86121     ns.evilcorp.example
bank.victim.com        A     300       6.6.6.6
```

### Ý nghĩa

- `cache_after_1`: chứng minh delegation giả đã được cache.
- `cache_after_2`: chứng minh resolver đã dùng fake NS để resolve victim domain.

---

# 6. Decoy và false positive nên thêm

## 6.1. Decoy loại 1 — TXT flag giả

Vẫn có thể giữ một số TXT flag giả để đánh lừa người chơi yếu:

```text
CTF{honeypot_canary_001}
CTF{dns_txt_is_not_always_flag}
CTF{wrong_authority_section}
```

Nhưng flag thật không nằm trong TXT.

## 6.2. Decoy loại 2 — OOB nhưng không vào cache

Packet có Authority OOB nhưng không xuất hiện trong cache snapshot.

Ví dụ:

```text
shop.demobank.example NS ns.bad.example
```

Lý do sai:

- Không trùng cache.
- TTL = 0.
- Response bị SERVFAIL.
- Response không liên quan tới trigger query thật.

## 6.3. Decoy loại 3 — Domain gần giống

Thêm các domain dễ nhầm:

```text
bank.victim.com
bank-victim.com
bank.victim.co
login.bank.victim.com
bank.víctim.com
bank.victim.com.attacker.net
```

Mục tiêu: kiểm tra người chơi có normalize domain và hiểu boundary hay không.

## 6.4. Decoy loại 4 — `endswith()` bypass

Tạo case để người chơi dùng bailiwick check sai bị false positive/false negative.

Ví dụ:

```text
notvictim.com
fakevictim.com
victim.com.attacker.net
```

Nếu script dùng:

```python
name.endswith(zone)
```

thì dễ nhận nhầm. Logic đúng phải là:

```python
name == zone or name.endswith("." + zone)
```

sau khi normalize lowercase, trailing dot và IDN/punycode nếu cần.

## 6.5. Decoy loại 5 — Additional glue nguy hiểm

Không chỉ poison NS trong Authority, thêm case Additional glue bị lợi dụng:

```text
Question:
  x.attacker.net A

Answer:
  x.attacker.net A 1.2.3.4

Authority:
  victim.com NS ns1.victim.com

Additional:
  ns1.victim.com A 6.6.6.6
```

Người chơi phải hiểu Additional section cũng cần validation trước khi cache.

---

# 7. Attack chain đề xuất

## 7.1. Timeline thật

```text
10:00:00  Resolver cache bình thường
10:03:12  Client truy cập ad/tracker: promo.attacker.net
10:03:12  Resolver query authoritative attacker.net
10:03:13  attacker.net authoritative trả response có OOB NS injection
10:03:13  Resolver vulnerable cache bank.victim.com NS ns.evilcorp.example
10:07:18  User query bank.victim.com
10:07:18  Resolver hỏi ns.evilcorp.example
10:07:19  ns.evilcorp.example trả bank.victim.com A 6.6.6.6
10:07:20  User kết nối tới 6.6.6.6
```

## 7.2. Packet độc hại chính

```text
Question:
  promo.attacker.net A

Answer:
  promo.attacker.net A 198.51.100.24

Authority:
  bank.victim.com NS ns.evilcorp.example

Additional:
  ns.evilcorp.example A 6.6.6.6
```

## 7.3. Bằng chứng cần tìm

Người chơi cần xác định:

| Field | Giá trị |
|---|---|
| Trigger query | `promo.attacker.net` |
| Attacker authoritative zone | `attacker.net` |
| Victim domain | `bank.victim.com` |
| Fake NS | `ns.evilcorp.example` |
| Fake NS IP | `6.6.6.6` |
| Poison packet number | ví dụ `482` |
| First cache snapshot containing poison | `cache_after_1.txt` |
| First victim query using fake NS | timestamp trong pcap/log |

---

# 8. Yêu cầu submit

## 8.1. Format đề xuất

```json
{
  "victim_domain": "bank.victim.com",
  "malicious_ns": "ns.evilcorp.example",
  "malicious_ns_ip": "6.6.6.6",
  "trigger_qname": "promo.attacker.net",
  "poison_packet_number": 482
}
```

## 8.2. Checker logic

Checker kiểm tra:

1. `victim_domain` đúng domain bị poison.
2. `malicious_ns` đúng NS attacker inject.
3. `malicious_ns_ip` đúng IP glue/fake NS.
4. `trigger_qname` đúng query ban đầu khiến resolver hỏi attacker authoritative.
5. `poison_packet_number` đúng hoặc nằm trong khoảng chấp nhận nếu pcap index khác giữa tool.

Với packet number, nên chấp nhận thêm một field thay thế:

```json
"poison_dns_txid": "0x4a91"
```

vì packet number có thể khác giữa Wireshark, tshark và scapy nếu có frame filtering.

---

# 9. Hint system không phân tầng

Không chia hint theo nhẹ/trung bình/mạnh. Nếu cần phát hint, dùng một cụm gợi ý
chung để giữ challenge ở cùng một cấu hình khó:

```text
Suspicious data is not necessarily in the Answer section.
A record appearing in a DNS response is not enough; prove that it entered cache.
Compare Authority-section NS records with cache snapshots and known-good delegations.
Watch for lookalike domains and bad suffix checks.
```

---

# 10. Solver reference cho ban tổ chức

## 10.1. Logic phát hiện

Pseudo-code:

```python
for packet in pcap:
    if not is_dns_response(packet):
        continue

    qname = normalize(packet.question.name)
    authority_zone = infer_zone_from_qname(qname)

    for rr in packet.authority_records:
        rr_name = normalize(rr.name)

        if rr.type == "NS" and not in_bailiwick(rr_name, authority_zone):
            candidate = {
                "packet": packet.number,
                "trigger_qname": qname,
                "victim_domain": rr_name,
                "malicious_ns": rr.value
            }
            check_candidate_against_cache(candidate)
```

## 10.2. Hàm normalize

```python
def normalize_name(name: str) -> str:
    name = name.strip().lower()
    if name.endswith("."):
        name = name[:-1]
    return name
```

## 10.3. Hàm bailiwick đúng tối thiểu

```python
def in_bailiwick(name: str, zone: str) -> bool:
    name = normalize_name(name)
    zone = normalize_name(zone)
    return name == zone or name.endswith("." + zone)
```

## 10.4. Lưu ý

Không dùng logic này:

```python
def bad_in_bailiwick(name, zone):
    return name.endswith(zone)
```

Vì có thể bị nhầm với:

```text
notvictim.com
fakevictim.com
victim.com.attacker.net
```

---

# 11. Tiêu chí bản triển khai duy nhất

| Tiêu chí | Mức |
|---|---|
| Kiến thức DNS | Cao |
| Pcap analysis | Cao |
| Scripting | Gần như bắt buộc nếu muốn giải gọn |
| Decoy | Nhiều, tinh vi |
| Correlation | 4–5 nguồn: pcap + cache snapshots + resolver log + debug log |
| Flag extraction | Không trực tiếp |
| Cấu hình phát hành | Một bản duy nhất, mặc định là nhiều nhiễu nhất |

---

# 12. Roadmap triển khai

## Giai đoạn 1 — Thiết kế dữ liệu

Việc cần làm:

- Chọn victim domain.
- Chọn attacker domain.
- Chọn fake NS và IP.
- Thiết kế timeline.
- Thiết kế danh sách decoy.
- Quyết định format submit: flag hash hay JSON evidence.

Output:

```text
design.md
expected_solution.json
```

## Giai đoạn 2 — Sinh pcap

Có thể sinh bằng Scapy.

Yêu cầu pcap:

- Có traffic DNS benign.
- Có query tới attacker domain.
- Có response poison thật.
- Có nhiều OOB decoy.
- Có TXT decoy.
- Có follow-up query tới victim domain.
- Có query từ resolver tới fake NS.
- Có response fake A record.

Output:

```text
capture.pcapng
```

## Giai đoạn 3 — Sinh cache snapshot

Tạo các file:

```text
cache_before.txt
cache_after_1.txt
cache_after_2.txt
```

Yêu cầu:

- `cache_before`: chưa có poison.
- `cache_after_1`: có fake delegation.
- `cache_after_2`: có victim A record từ fake NS.

## Giai đoạn 4 — Sinh log

Tạo:

```text
resolver.log
technitium_debug.log
```

Nên có:

- Query log.
- Cache insert log.
- Một số warning/noise.
- Timestamp khớp với pcap.
- Log decoy để gây nhiễu.

## Giai đoạn 5 — Viết checker

Nếu dùng JSON evidence:

- Parse JSON.
- Validate từng field.
- Cho message lỗi vừa đủ, không leak đáp án.

Ví dụ response:

```json
{
  "verdict": "invalid",
  "message": "victim_domain is correct, but malicious_ns does not match the cached delegation"
}
```

Hoặc strict hơn:

```json
{
  "verdict": "invalid",
  "message": "Evidence does not match incident timeline"
}
```

## Giai đoạn 6 — Playtest

Playtest chỉ kiểm tra một bản duy nhất:

- Người chơi có thể dựng được evidence bằng correlation thật hay không.
- Decoy có loại được các shortcut như grep TXT, filter Answer-only, hoặc OOB-only hay không.
- Packet number/TXID/timestamp có đủ rõ để submit nghiêm ngặt hay không.

---

# 13. Checklist triển khai

## Artifact

- [ ] `README.md`
- [ ] `capture.pcapng`
- [ ] `cache_before.txt`
- [ ] `cache_after_1.txt`
- [ ] `cache_after_2.txt`
- [ ] `resolver.log`
- [ ] `technitium_debug.log`
- [ ] `submit_format.md`
- [ ] `expected_solution.json`
- [ ] `checker.py`
- [ ] `solve.py` nội bộ cho ban tổ chức

## Nội dung kỹ thuật

- [ ] Có ít nhất 1 poison chain thật.
- [ ] Có ít nhất 10 benign DNS responses.
- [ ] Có ít nhất 5 OOB decoy.
- [ ] Có ít nhất 3 TXT decoy.
- [ ] Có ít nhất 2 domain gần giống victim.
- [ ] Có ít nhất 1 Additional glue decoy.
- [ ] Có cache snapshot chứng minh poison thành công.
- [ ] Có follow-up query chứng minh resolver dùng fake NS.
- [ ] Có timestamp nhất quán giữa pcap và log.

## Chống shortcut

- [ ] Không có flag thật dạng plaintext trong pcap.
- [ ] `strings capture.pcapng | grep CTF` chỉ ra decoy.
- [ ] Không thể giải chỉ bằng TXT record.
- [ ] Không thể giải nếu chỉ nhìn Answer section.
- [ ] Packet OOB decoy không trùng cache.
- [ ] Cache decoy không trùng timeline.

---

# 14. Cấu hình phát hành

Không tách bài theo mức dễ/vừa/khó và không giữ bản nhập môn song song trong
bộ artifact này. Bản phát hành duy nhất:

```text
Category: Forensics / Network / DNS
Mode: Evidence-based incident reconstruction
Scoring: JSON evidence checker
Estimated solve time: 60–120 minutes
```

Nếu cần dạy người mới, tạo tài liệu training riêng thay vì hạ noise hoặc chia
challenge thành nhiều mức.

---

# 15. Rủi ro và cách giảm

## Rủi ro 1 — Challenge quá rối

Cách giảm:

- Có một cụm hint chung, không phân tầng.
- README nói rõ cần correlate cache với pcap.
- Cho `known_good_zones.txt` để giảm ambiguity.

## Rủi ro 2 — Nhiều đáp án hợp lý

Cách giảm:

- Thiết kế chỉ có một poison chain thật đi vào cache.
- Decoy không được xuất hiện trong cache thật.
- Timestamp phải rõ ràng.

## Rủi ro 3 — Packet number khác nhau giữa tool

Cách giảm:

- Cho phép submit DNS transaction ID.
- Hoặc submit tuple:

```json
{
  "src_ip": "203.0.113.53",
  "dst_ip": "10.0.0.53",
  "dns_txid": "0x4a91",
  "trigger_qname": "promo.attacker.net"
}
```

## Rủi ro 4 — Người chơi brute-force flag hash

Cách giảm:

- Dùng JSON evidence thay vì hash flag.
- Nếu vẫn dùng hash, thêm secret salt server-side không phát cho người chơi.

---

# 16. Kết luận

Bản hiện tại của Bailiwick Breakout rất tốt để dạy người mới vì đường giải rõ ràng và concept gọn. Tuy nhiên, để trở thành challenge khó hơn cho người chuyên môn, cần chuyển trọng tâm từ **tìm flag trong packet** sang **chứng minh một DNS cache poisoning incident thật sự đã xảy ra**.

Ba cải tiến quan trọng nhất nên làm ngay:

1. **Bỏ flag TXT thật khỏi pcap.**
2. **Thêm cache snapshot theo thời gian để bắt buộc reconstruct timeline.**
3. **Chấm bằng JSON evidence hoặc flag sinh từ evidence thay vì flag plaintext.**

Nếu triển khai đúng, phiên bản mới sẽ kiểm tra được cả kiến thức DNS, kỹ năng forensic, khả năng viết detector và tư duy incident response. Đây là hướng nâng cấp hợp lý để challenge đủ sức làm khó người chơi có chuyên môn mà vẫn giữ được giá trị giáo dục ban đầu.
