#!/bin/sh
set -eu

# Docker injects its own /etc/resolv.conf at container start (overriding
# the COPY in Dockerfile). Re-write at runtime de res_send forward len
# POPS upstream chu khong phai Docker DNS bridge resolver (127.0.0.11).
cat > /etc/resolv.conf <<EOF
nameserver 10.0.2.2
options edns0 timeout:3 attempts:2
EOF

if [ -n "${UPSTREAM_DELAY_MS:-}" ] && [ "${UPSTREAM_DELAY_MS}" != "0" ]; then
    tc qdisc add dev eth0 root netem delay "${UPSTREAM_DELAY_MS}ms" || true
fi

ldd --version | head -1 || true
echo "[$(date -Iseconds)] vulnerable-resolver (glibc-based) starting"
echo "[$(date -Iseconds)] CVE-2017-12132 affects res_send with EDNS0 enabled"
echo "[$(date -Iseconds)] /etc/resolv.conf:"
cat /etc/resolv.conf
exec /usr/local/bin/resolver_wrapper
