# vulnerable-resolver

Stage 2 eventually needs a resolver wrapper that reproduces CVE-2017-12132
behavior with an appropriate glibc version. The current file is only a small
`getaddrinfo` loop so Compose has a real container target while the lab is still
being assembled.

Next work:

- decide whether to pin a Debian Stretch/glibc 2.24 image or build a controlled
  resolver harness;
- add fragmentation-specific test traffic;
- document exactly where behavior is CVE reproduction versus lab simulation.

