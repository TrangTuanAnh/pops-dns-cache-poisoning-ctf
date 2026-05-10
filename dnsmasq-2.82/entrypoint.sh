#!/bin/bash
# dnsmasq entrypoint cho stage 1.
# Optional: ap dung tc netem delay tren outbound queries de paper window-edge
# experiment co the chay duoc (RTT > W = 1.0s lam window straddling kha thi).
set -eu

if [ -n "${UPSTREAM_DELAY_MS:-}" ] && [ "${UPSTREAM_DELAY_MS}" != "0" ]; then
    echo "[$(date -Iseconds)] applying tc netem delay ${UPSTREAM_DELAY_MS}ms on eth0"
    tc qdisc add dev eth0 root netem delay "${UPSTREAM_DELAY_MS}ms" || true
fi

exec dnsmasq --keep-in-foreground --conf-file=/etc/dnsmasq.conf
