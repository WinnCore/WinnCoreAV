#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/test_common.sh"

header "Category 2: False Positives"

declare -a samples=(
    "test_samples/benign_arm64"
)

MAX_FALSE_POSITIVE_RATE=${MAX_FALSE_POSITIVE_RATE:-2}

total=0
flagged=0
false_positives=()

for sample in "${samples[@]}"; do
    path="$ROOT_DIR/$sample"
    if [[ ! -f "$path" ]]; then
        echo "⚠️  Skipping missing benign sample: $sample"
        continue
    fi

    total=$((total + 1))
    json=$(scan_file_to_json "$path") || { false_positives+=("$sample (scan error)"); flagged=$((flagged + 1)); continue; }

    action=$(json_field "$json" "recommended_action" || echo "unknown")
    score=$(json_field "$json" "heuristic_score" || echo "0")
    is_flagged=$(python3 - <<PY
score = float("${score:-0}")
action = "${action}"
print("1" if action != "Allow" or score >= 0.5 else "0")
PY
)

    if [[ "$is_flagged" == "1" ]]; then
        echo "  ❌ False positive: $sample (action=${action}, score=${score})"
        false_positives+=("$sample")
        flagged=$((flagged + 1))
    else
        echo "  ✅ Allowed: $sample (score=${score})"
    fi
done

if [[ $total -eq 0 ]]; then
    echo "⚠️  No benign samples found; skipping false-positive rate check."
    exit 0
fi

fp_rate=$((flagged * 100 / total))
echo ""
echo "False positive rate: ${fp_rate}% (${flagged}/${total})."

if [[ $fp_rate -gt $MAX_FALSE_POSITIVE_RATE ]]; then
    echo "⚠️  False positive rate above target (${MAX_FALSE_POSITIVE_RATE}%)."
    printf 'Flagged samples: %s\n' "${false_positives[*]:-none}"
    exit 1
fi

exit 0
