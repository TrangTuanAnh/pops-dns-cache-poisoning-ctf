# POPS module - lab implementation

Thư mục này chứa implementation Python của POPS cho lab CTF. Implementation
viết từ đầu, bám sát mô tả trong paper Afek et al. (USENIX Security 2025)
Section 2-4 và pseudo-code Algorithm 1-4 ở Appendix B.

## Lý do không dùng artifact Zenodo nguyên bản

Paper provide source code tại Zenodo (https://zenodo.org/records/15688589),
nhưng artifact đó tối ưu cho measurement experiments của paper, không phải
một transparent UDP proxy plug-and-play. Cho mục đích challenge giáo dục,
implementation mới ở đây có một số lợi thế:

- Tự container hoá, không cần build dependency phức tạp.
- Có sẵn lab convenience endpoint (`/api/v1/lab/pops-log`,
  `/api/v1/lab/check-bailiwick`) phục vụ flag B của 3 stage.
- Hai variant `IsWithinBailiwick` (correct và naive) bật/tắt qua env var,
  phục vụ flag 3B.
- Mitigation đúng spec paper: set TC=1, clear answer/authority/additional
  section, gửi response giả về resolver.

Implementation áp dụng cùng tham số mặc định như paper Section 5:
`tau = 5, W = 1.0s, CMS depth d = 5, width w = 200`.

## File layout

- `pops_module.py` - entry point, khởi động UDP proxy + HTTP API + fragment sniffer.
- `rules.py` - ba detection rule R_l1, R_l2, R_l3.
- `cms.py` - Count-Min Sketch theo Algorithm 2 Appendix B.
- `bailiwick.py` - hai variant của `IsWithinBailiwick`.
- `proxy.py` - UDP forwarding loop.
- `api.py` - HTTP API cho lab endpoint.

## Swap với Zenodo source nếu cần

Để chuyển sang artifact Zenodo nguyên bản: clone về `pops/source/zenodo/`,
update `pops/Dockerfile` build từ thư mục đó, expose cùng UDP port 53. Chú ý
artifact gốc không có HTTP API cho lab convenience nên flag B sẽ cần
endpoint riêng (ví dụ tách ra service `pops-lab-api`).
