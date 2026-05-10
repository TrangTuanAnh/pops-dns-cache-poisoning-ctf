#!/bin/bash
# nsd-auth entrypoint.
# Watch /shared/reload-trigger.txt; khi thay doi, sync zone file tu
# /shared/zones/ vao /etc/nsd/zones/dynamic/, copy zones-dynamic.conf
# vao /etc/nsd/, va reload NSD bang nsd-control hoac restart nsd.

set -eu

CONF=/etc/nsd/nsd.conf
DYN_DIR=/etc/nsd/zones/dynamic
SHARED_TRIGGER=/shared/reload-trigger.txt
SHARED_ZONES=/shared/zones
SHARED_INCLUDE=/shared/zones-dynamic.conf

mkdir -p "$DYN_DIR" "$SHARED_ZONES"
touch "$SHARED_TRIGGER" "$SHARED_INCLUDE"

# Start nsd in background
nsd -d -c "$CONF" &
NSD_PID=$!

reload_zones() {
    echo "[$(date -Iseconds)] reload zones triggered"
    cp -f "$SHARED_ZONES"/*.zone "$DYN_DIR"/ 2>/dev/null || true
    if [ -s "$SHARED_INCLUDE" ]; then
        # Append (idempotent) include into nsd.conf if not present
        if ! grep -q "DYNAMIC_INCLUDE_BEGIN" "$CONF"; then
            {
                echo ""
                echo "# DYNAMIC_INCLUDE_BEGIN"
                cat "$SHARED_INCLUDE"
                echo "# DYNAMIC_INCLUDE_END"
            } >> "$CONF"
        else
            # Replace block
            awk '
                /DYNAMIC_INCLUDE_BEGIN/{print; system("cat /shared/zones-dynamic.conf"); skip=1; next}
                /DYNAMIC_INCLUDE_END/{skip=0}
                !skip{print}
            ' "$CONF" > "$CONF.new" && mv "$CONF.new" "$CONF"
        fi
    fi
    # Restart nsd to pick up zone changes (nsd-control add/reload requires
    # control socket setup which is more complex; restart is robust for lab).
    kill -TERM "$NSD_PID" 2>/dev/null || true
    wait "$NSD_PID" 2>/dev/null || true
    nsd -d -c "$CONF" &
    NSD_PID=$!
    echo "[$(date -Iseconds)] nsd restarted pid=$NSD_PID"
}

# Initial reload if shared content already present
if [ -s "$SHARED_INCLUDE" ]; then
    reload_zones
fi

# Watch trigger file
while inotifywait -e modify -e create "$SHARED_TRIGGER" >/dev/null 2>&1; do
    sleep 1   # debounce: cho registrar ghi xong file
    reload_zones
done

wait "$NSD_PID"
