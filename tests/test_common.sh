#!/usr/bin/env bash
set -euo pipefail

# Shared helpers for the WinnCoreAV test suite. All category scripts source
# this file to resolve paths, standardize scan commands, and keep outputs
# consistent.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AV_CMD=(cargo run --quiet --release --bin av-cli --)

# Use a sandboxed quarantine directory to avoid polluting user state.
export WINNCORE_QUARANTINE_DIR="${WINNCORE_QUARANTINE_DIR:-$ROOT_DIR/malware_testing/quarantine}"
mkdir -p "$WINNCORE_QUARANTINE_DIR"

header() {
    local title="$1"
    echo "═══ ${title} ═══"
}

extract_json_block() {
    # The scanner prints logs before the JSON payload; strip to the JSON block.
    sed -n '/^{/,$p' <<<"$1"
}

json_field() {
    local json="$1"
    local field="$2"
    JSON_INPUT="$json" python3 - "$field" <<'PY'
import json
import os
import sys

payload = os.environ.get("JSON_INPUT", "")
field = sys.argv[1]
try:
    data = json.loads(payload)
    parts = field.split(".")
    for part in parts:
        if isinstance(data, dict):
            data = data.get(part)
        else:
            data = None
            break
    if data is None:
        sys.exit(1)
    print(data)
except Exception:
    sys.exit(1)
PY
}

scan_file_to_json() {
    local path="$1"
    local raw
    if ! raw=$("${AV_CMD[@]}" scan file "$path" --json 2>&1); then
        echo "SCAN_ERROR"
        return 1
    fi

    local json
    json=$(extract_json_block "$raw")
    if [[ -z "$json" ]]; then
        echo "PARSE_ERROR"
        return 1
    fi

    printf "%s" "$json"
}
