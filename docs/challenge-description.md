# POPS CTF challenge description draft

This is a player-facing draft. It should be tightened before release.

## Premise

You are evaluating a DNS poisoning prevention system based on POPS. The goal is
not to claim a POPS bypass. The challenge is about reproducing historical DNS
cache poisoning CVEs and documenting how POPS reacts under controlled lab
conditions.

## Stages

Stage 1 focuses on excessive guessing and CVE-2020-25684 in dnsmasq 2.82.

Stage 2 focuses on DNS fragmentation and CVE-2017-12132 in a glibc-based
resolver setup.

Stage 3 focuses on out-of-bailiwick records and CVE-2021-43105 in Technitium
DNS Server v7.0.

Each stage has two flags:

- Flag A: reproduce the historical vulnerability in the lab.
- Flag B: submit evidence for a limitation or implementation edge case discussed
  in the project brief.

## Threat model

Treat yourself as an off-path attacker. Some lab endpoints may give controlled
convenience access, such as spoofed UDP sending or evidence submission. Those
endpoints are lab abstractions, not extra attacker capabilities in the real
world.

## References to add

- POPS paper and Zenodo artifact.
- NVD/vendor pages for CVE-2020-25684, CVE-2017-12132 and CVE-2021-43105.
- DNSpooq whitepaper.
- Herzberg-Shulman fragmentation paper.
- MaginotDNS paper.
- RFC 1035, RFC 5452 and RFC 6891.

