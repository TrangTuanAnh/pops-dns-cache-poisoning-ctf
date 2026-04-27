# flag-service

Placeholder verifier for all three stages. It exposes the planned API surface
but returns `501 not_implemented` until the real lab evidence checks exist.

Planned endpoints:

- `POST /api/v1/stage1/reproduction`
- `POST /api/v1/stage1/window-evidence`
- `POST /api/v1/stage2/fragmentation-evidence`
- `POST /api/v1/stage2/noncompliant-evidence`
- `POST /api/v1/stage3/bailiwick-evidence`
- `POST /api/v1/stage3/normalization-evidence`

Keep actual flag values in `.env`, not in source control.

