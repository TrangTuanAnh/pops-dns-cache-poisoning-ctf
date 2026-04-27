# Architecture draft

The scaffold follows the proposal inventory:

- POPS module between resolver and authoritative DNS.
- Vulnerable resolver per stage.
- NSD authoritative server with local challenge zones.
- Registrar service for lab-controlled delegation records.
- Spoof helper for controlled UDP spoofing experiments.
- Flag service for evidence validation.

## Stage networks

The per-stage Compose files use isolated subnets:

- Stage 1: `10.0.0.0/24`
- Stage 2: `10.0.2.0/24`
- Stage 3: `10.0.3.0/24`

The master Compose file uses `10.10.0.0/16` with profiles and is mainly for
overview or shared-service experiments.

## Current status

This is not a complete lab yet. The POPS container, Technitium target, raw spoof
helper and verifier logic are placeholders. They exist so the repo shape and
integration points are stable before the expensive reproduction work starts.

