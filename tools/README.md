# Tools — Generator + Solver

Hai script này dành cho admin/dev:

- `generator/gen_challenge.py` sinh lại artifact của challenge.
- `solver/solve.py` dựng evidence JSON từ artifact để verify pipeline.

Generator chỉ có một cấu hình mặc định: bản nhiều nhiễu, nhiều decoy, không
có tier dễ/vừa/khó.

## Cấu trúc

```text
tools/
├── generator/
│   ├── gen_challenge.py
│   └── requirements.txt
└── solver/
    ├── solve.py
    └── requirements.txt
```

## Generator

```bash
cd tools/generator
pip install -r requirements.txt
python gen_challenge.py
```

Tham số còn lại:

| Param | Ý nghĩa |
|---|---|
| `--out` | Output directory, mặc định là `<repo>/challenge` |
| `--expected-out` | Path private cho đáp án checker |
| `--seed` | RNG seed để tạo variant deterministic |
| `--verbose` | In debug log khi generate |

Output chính:

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

Khi output là `<repo>/challenge`, generator mặc định ghi đáp án private vào
`server/expected_solution.json` để tránh lẫn vào bundle public. Nếu dùng
`--out` tới thư mục khác, đáp án mặc định nằm ở `<out>/expected_solution.json`
trừ khi bạn truyền `--expected-out`.

## Solver

```bash
cd tools/solver
pip install -r requirements.txt
python solve.py
```

Solver làm các bước:

1. Parse `cache_before.txt`, `cache_after_1.txt`, `cache_after_2.txt`.
2. Tìm NS entry mới xuất hiện sau trigger.
3. Quét `capture.pcapng` để tìm DNS response có Authority NS out-of-bailiwick
   trùng cache delta.
4. Lấy glue IP, packet number, DNS TXID và timestamp user query.
5. In evidence JSON.

Submit luôn qua checker:

```bash
python solve.py --submit http://127.0.0.1:5000
```

Ghi evidence ra file:

```bash
python solve.py --out evidence.json
```

## Pipeline test

```bash
python tools/generator/gen_challenge.py
docker compose -f server/docker-compose.yml up -d --build
python tools/solver/solve.py --submit http://127.0.0.1:5000
```

Kết quả đúng sẽ trả `{"verdict":"valid"}`.
