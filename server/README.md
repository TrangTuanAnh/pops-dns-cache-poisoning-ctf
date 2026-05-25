# Server — Evidence Checker

Checker Flask nhận evidence JSON qua HTTP và kiểm tra với đáp án trong
file private `server/expected_solution.json`.

## Chạy bằng Docker

```bash
cd server
docker compose up -d --build
```

`docker-compose.yml` mount file `./expected_solution.json` vào
container ở `/app/expected_solution.json`. Nếu file này chưa có sau khi clone
sạch, chạy `python ../tools/generator/gen_challenge.py` một lần để sinh lại.

Health check:

```bash
curl http://127.0.0.1:5000/health
```

Output có `expected_loaded: true` là checker đã đọc được đáp án.

## Submit

`POST /submit` nhận JSON theo `challenge/submit_format.md`:

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

Ví dụ test bằng solver:

```bash
python ../tools/solver/solve.py --submit http://127.0.0.1:5000
```

Response:

- `200` + `{"verdict":"valid"}` nếu evidence đúng.
- `401` + `{"verdict":"invalid"}` nếu evidence không khớp incident.
- `400` nếu thiếu field hoặc sai kiểu dữ liệu.
- `429` nếu spam quá nhanh.

## Variant với seed khác

Regen artifact:

```bash
python ../tools/generator/gen_challenge.py --seed 42
docker compose up -d --build --force-recreate
```

Generator mặc định ghi đáp án private vào `server/expected_solution.json`, nên
không cần sửa env khi đổi seed nếu bạn dùng compose mặc định.

## Chạy không dùng mounted file

Có thể set `EXPECTED_SOLUTION_JSON` hoặc toàn bộ field riêng lẻ trong env. Xem
`.env.example` để biết tên biến.
