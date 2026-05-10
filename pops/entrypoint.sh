#!/bin/sh
set -eu

mkdir -p /var/log/pops

cat >/var/log/pops/boot.log <<EOF
POPS module booting
stage=${POPS_STAGE:-unknown}
upstream=${POPS_UPSTREAM:-unset}
tau=${POPS_TAU:-5}
window=${POPS_WINDOW:-1.0}
cms_w=${POPS_CMS_W:-200}
cms_d=${POPS_CMS_D:-5}
frag_threshold=${POPS_FRAG_THRESHOLD:-1232}
bailiwick_origin=${POPS_BAILIWICK_ORIGIN:-}
naive_bailiwick=${POPS_NAIVE_BAILIWICK:-0}
EOF

echo "POPS module starting (stage=${POPS_STAGE:-unknown})"
exec python /app/pops_module.py
