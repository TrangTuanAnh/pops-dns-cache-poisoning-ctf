#!/bin/bash
# Technitium v7.0 entrypoint cho stage 3.
# Khoi dong Technitium service binh thuong, sau do dung HTTP API
# (default :5380) de configure forwarder upstream tro ve POPS thay vi
# resolve qua public root hierarchy.
set -eu

UPSTREAM_FORWARDER="${UPSTREAM_FORWARDER:-10.0.3.2}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"

echo "[$(date -Iseconds)] Technitium v7.0 starting (vulnerable cho CVE-2021-43105)"

# Khoi dong Technitium service trong background. Tim binary o cac path
# co the (image path thay doi giua versions: v7.0 dung /etc/dns/, ban
# moi co the dung /opt/technitium/dns/).
if [ -x /etc/dns/start.sh ]; then
    cd /etc/dns && /etc/dns/start.sh &
elif [ -x /opt/technitium/dns/start.sh ]; then
    /opt/technitium/dns/start.sh &
elif [ -f /etc/dns/DnsServerApp.dll ]; then
    cd /etc/dns && /usr/bin/dotnet /etc/dns/DnsServerApp.dll &
elif [ -f /opt/technitium/dns/DnsServerApp.dll ]; then
    /usr/share/dotnet/dotnet /opt/technitium/dns/DnsServerApp.dll &
else
    echo "ERROR: cannot find Technitium binary"
    exit 1
fi
TECH_PID=$!

# Doi service san sang
echo "[$(date -Iseconds)] waiting for Technitium API on :5380..."
for i in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:5380/api/user/login?user=admin&pass=${ADMIN_PASSWORD}" >/dev/null 2>&1; then
        echo "[$(date -Iseconds)] API up"
        break
    fi
    sleep 1
done

# Configure forwarder qua API
TOKEN=$(curl -sf "http://127.0.0.1:5380/api/user/login?user=admin&pass=${ADMIN_PASSWORD}" | sed 's/.*"token":"\([^"]*\)".*/\1/' || true)
if [ -n "$TOKEN" ]; then
    echo "[$(date -Iseconds)] configuring forwarder=${UPSTREAM_FORWARDER}"
    curl -sf "http://127.0.0.1:5380/api/settings/set?token=${TOKEN}&forwarders=${UPSTREAM_FORWARDER}&forwarderProtocol=Udp&recursion=Allow&useNxDomainForBlocking=false" >/dev/null || true
fi

# Forward signals va wait
trap "kill -TERM $TECH_PID 2>/dev/null || true; wait $TECH_PID" TERM INT
wait $TECH_PID
