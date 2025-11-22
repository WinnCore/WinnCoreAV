#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/test_common.sh"

header "Category 7: Integration"

if cargo test --workspace --all-features -- --nocapture; then
    echo "  ✅ Workspace tests passed"
    exit 0
else
    echo "  ❌ Workspace tests failed"
    exit 1
fi
