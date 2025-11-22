#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/test_common.sh"

header "Category 5: Security"

secure_quarantine="$ROOT_DIR/test_output/quarantine_secure"
mkdir -p "$secure_quarantine"
chmod 700 "$secure_quarantine"

export WINNCORE_QUARANTINE_DIR="$secure_quarantine"

fail=0

if "${AV_CMD[@]}" quarantine list >/dev/null 2>&1; then
    echo "  ✅ Quarantine list works with locked-down dir"
else
    echo "  ❌ Quarantine list failed"
    fail=$((fail + 1))
fi

quar_perms=$(stat -c "%a" "$secure_quarantine")
if [[ $quar_perms -le 750 ]]; then
    echo "  ✅ Quarantine perms: $quar_perms"
else
    echo "  ❌ Quarantine perms too loose: $quar_perms"
    fail=$((fail + 1))
fi

sig_perms=$(stat -c "%a" "$ROOT_DIR/signatures")
if [[ $sig_perms -le 755 ]]; then
    echo "  ✅ Signatures directory perms: $sig_perms"
else
    echo "  ❌ Signatures directory perms too loose: $sig_perms"
    fail=$((fail + 1))
fi

config_perms=$(stat -c "%a" "$ROOT_DIR/config")
if [[ $config_perms -le 755 ]]; then
    echo "  ✅ Config directory perms: $config_perms"
else
    echo "  ❌ Config directory perms too loose: $config_perms"
    fail=$((fail + 1))
fi

if [[ $fail -gt 0 ]]; then
    exit 1
fi

exit 0
