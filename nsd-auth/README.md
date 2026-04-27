# nsd-auth

Shared authoritative DNS container for the scaffold. The zone files provide
stable names used by each stage:

- `corebank.meridian.example` for Stage 1;
- `fragment.meridian-stage2.example` for Stage 2;
- `vault.meridian-stage3.example` for Stage 3.

When the real registrar service starts editing zones, add a safe reload path
instead of rewriting these base files directly.

