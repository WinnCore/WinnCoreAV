#!/usr/bin/env bash
# Generate detection baseline from the current environment.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE_DIR="$ROOT_DIR/baselines"
BASELINE_FILE="$BASELINE_DIR/detection.json"

mkdir -p "$BASELINE_DIR"

OUTPUT="$BASELINE_DIR/current_detection.json"
"$ROOT_DIR/scripts/run-detection-suite.sh" --output "$OUTPUT"

mv "$OUTPUT" "$BASELINE_FILE"

echo "Baseline updated: $BASELINE_FILE"
