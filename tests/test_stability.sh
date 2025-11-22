#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/test_common.sh"

header "Category 4: Stability & Reliability"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

touch "$workdir/empty.bin"
dd if=/dev/zero of="$workdir/zeros.bin" bs=1 count=0 2>/dev/null
dd if=/dev/zero of="$workdir/truncated.elf" bs=1 count=4 2>/dev/null
dd if=/dev/urandom of="$workdir/random.bin" bs=1024 count=1 2>/dev/null

declare -a paths=(
    "$workdir/empty.bin"
    "$workdir/zeros.bin"
    "$workdir/truncated.elf"
    "$workdir/random.bin"
)

fail=0

for path in "${paths[@]}"; do
    if "${AV_CMD[@]}" scan file "$path" >/dev/null 2>&1; then
        echo "  ✅ Handled: $(basename "$path")"
    else
        echo "  ❌ Failure: $(basename "$path")"
        fail=$((fail + 1))
    fi
done

if "${AV_CMD[@]}" scan dir "$workdir" >/dev/null 2>&1; then
    echo "  ✅ Directory scan survived malformed inputs"
else
    echo "  ❌ Directory scan failed on malformed inputs"
    fail=$((fail + 1))
fi

if [[ $fail -gt 0 ]]; then
    exit 1
fi

exit 0
