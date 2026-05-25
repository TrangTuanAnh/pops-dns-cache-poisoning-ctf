# Bắt đầu nhanh

Hướng dẫn ngắn để chạy thử pipeline của challenge.

## Cần gì?

- Python 3.10+
- Wireshark/tshark nếu muốn phân tích thủ công
- Docker nếu muốn chạy checker

## Đọc đề

Mở [`challenge/README.md`](challenge/README.md). Artifact chính:

```text
capture.pcapng
cache_before.txt
cache_after_1.txt
cache_after_2.txt
resolver.log
technitium_debug.log
known_good_zones.txt
submit_format.md
```

Không tìm flag trong TXT record. Các `CTF{...}` trong pcap là decoy.

## Verify bằng solver

```bash
cd tools/solver
pip install -r requirements.txt
python solve.py
```

Solver sẽ in evidence JSON gồm poisoned delegation, malicious response và
timeline.

## Chạy checker

```bash
cd server
docker compose up -d --build
```

Submit bằng solver:

```bash
cd ../tools/solver
python solve.py --submit http://127.0.0.1:5000
```

Nếu đúng, checker trả:

```json
{"message":"Evidence accepted. The poisoned delegation chain is complete.","verdict":"valid"}
```

## Phân tích thủ công nhanh

1. So `cache_before.txt` với `cache_after_1.txt` để tìm NS entry mới.
2. Trong Wireshark, lọc `dns.flags.response == 1 and dns.ns`.
3. Tìm response có Authority NS trùng cache delta và nằm ngoài bailiwick.
4. Lấy glue IP từ Additional/cache.
5. So `cache_after_2.txt` và log để chứng minh user query victim domain đã
   đi qua fake NS.

Walkthrough chi tiết nằm ở [`docs/huong-dan-giai.md`](docs/huong-dan-giai.md).
