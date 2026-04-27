# dnsmasq 2.82

Stage 1 uses dnsmasq 2.82 as the vulnerable resolver for CVE-2020-25684
(DNSpooq). This Dockerfile compiles dnsmasq from the upstream source archive.

Before using this in the final lab, verify:

- the source archive URL is still reachable;
- the downloaded archive hash is recorded;
- the public PoC behavior is reproducible in the local Docker network;
- the upstream path really goes through POPS, not directly to NSD.

