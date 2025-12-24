# WinnCoreAV Autonomous Validation System

This document defines the always-on validation pipeline for WinnCoreAV. The goal is to run
continuous checks across detection integrity, performance, resilience, and compliance without
blocking engineering velocity.

## Core Scripts

- `scripts/autonomous-validation.sh`
  - Orchestrates multi-phase validation with optional auto-fix and retry loops.
- `scripts/run-detection-suite.sh`
  - Runs attack simulations and optional malware corpus scans.
- `scripts/check_regression.py`
  - Computes Negative Flip Rate (NFR) and fails when above threshold.
- `scripts/check_perf_regression.py`
  - Compares Criterion baselines to detect regressions.
- `scripts/collect_compliance_evidence.py`
  - Gathers evidence artifacts for compliance reporting.

## Recommended Workflow

```bash
# Fast local loop
WINNCORE_VALIDATION_MODE=fast ./scripts/autonomous-validation.sh

# Full validation (CI/weekly)
WINNCORE_VALIDATION_MODE=full ./scripts/autonomous-validation.sh
```

## Reference Manifests

- `validation/autonomous-test-loop.yaml`
- `validation/gameday-scenarios.yaml`
- `validation/techniques-administration.yaml`

## Detection Regression (NFR)

Baseline results live under `baselines/` and are compared against current results.

```bash
./scripts/run-detection-suite.sh --output results.json
python3 scripts/check_regression.py --current results.json --baseline baselines/detection.json --max-nfr 0.01
```

## CI/CD Notes

- GitHub workflows in `.github/workflows/` use the scripts above.
- The self-healing workflow optionally runs `cargo fmt` and `cargo clippy --fix` when enabled.

## Long-Running Tests

Some phases can be expensive (fuzzing, mutation tests, soak tests). These are gated behind
`WINNCORE_VALIDATION_MODE=full` and will be skipped in `fast` mode.

## Artifacts

Results are stored under `test-results/` and include:

- `detection_suite_*/results.json`
- `detection_suite_*/alerts.jsonl`
- `validation_reports/*.json`
