#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/test_common.sh"

header "Category 6: Edge Cases"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

declare -a files=(
    "$workdir/empty.txt"
    "$workdir/with spaces.bin"
    "$workdir/non_ascii_label.bin"
)

touch "$workdir/empty.txt"
printf "data" > "$workdir/with spaces.bin"
printf "random" > "$workdir/non_ascii_label.bin"

fail=0

for f in "${files[@]}"; do
    if "${AV_CMD[@]}" scan file "$f" >/dev/null 2>&1; then
        echo "  ✅ Handled: $(basename "$f")"
    else
        echo "  ❌ Failed: $(basename "$f")"
        fail=$((fail + 1))
    fi
done

if "${AV_CMD[@]}" scan dir "$workdir" >/dev/null 2>&1; then
    echo "  ✅ Directory scan handled edge cases"
else
    echo "  ❌ Directory scan failed on edge cases"
    fail=$((fail + 1))
fi

if [[ $fail -gt 0 ]]; then
    exit 1
fi

exit 0
