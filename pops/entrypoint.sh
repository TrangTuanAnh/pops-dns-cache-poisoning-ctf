#!/bin/sh
set -eu

mkdir -p /var/log/pops

cat >/var/log/pops/boot.log <<EOF
POPS scaffold started
stage=${POPS_STAGE:-unknown}
mode=${POPS_MODE:-dry-run}
tau=${POPS_TAU:-5}
window=${POPS_WINDOW:-1.0}
cms_w=${POPS_CMS_W:-200}
cms_d=${POPS_CMS_D:-5}
upstream=${POPS_UPSTREAM:-unset}
EOF

echo "POPS scaffold running in ${POPS_MODE:-dry-run} mode"
echo "Replace this entrypoint after importing the POPS Zenodo artifact."

tail -f /var/log/pops/boot.log

