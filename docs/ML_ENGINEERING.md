# WinnCoreAV ML Engineering Notes

• - ML feature extractors in Rust:
      - 14-feature path (used by MlDetector): file_size, entropy, entry_point, num_sections, num_segments, text_size, data_size, rodata_size, bss_size, num_dynsym,
        num_symtab, is_stripped, is_pie, suspicious_strings.
      - 52-feature enhanced path (used by EnsembleDetector) with header, entropy, symbol, instruction, and string density metrics (see av-ml-detector/src/lib.rs,
        ENHANCED_FEATURE_ORDER).
      - Non-ELF or non-ARM64 inputs return neutral features (score defaults to 0) instead of errors.
  - Models available/used:
      - models/gbm_v3_hardened.onnx (active single-model path).
      - Also present: gbm_v4_final.onnx, lotl_detector.onnx (checked in Python validator).
      - Ensemble lookup expects models/{lgbm_model,xgb_model,mlp_model}.onnx if provided.
  - Python validation harness:
      - tests/validate_ml.py now uses tools/ml_pipeline/feature_extraction.py shim (14 features), skips non-ELF samples gracefully, and passes if at least one of the
        known models exists.
  - Files added for ML validation:
      - tools/ml_pipeline/feature_extraction.py, __init__.py (Python extractor shim).
      - ARM64 ELF fixtures in test_samples/elf/:
          - benign_hello (score ~0.0065 → Allow)
          - benign_pie (PIE, score ~0.0065 → Allow)
          - malicious_suspicious (many embedded bad strings, stripped; score ~0.999 → Quarantine)
      - Existing sample: malware_testing/samples/arm64/malicious1.elf (score ~0.877 → Quarantine).
  - Heuristics ML path behavior (av-core/src/heuristics.rs):
      - Skips ML for non-ELF inputs; returns neutral score (half-threshold fallback no longer triggered by junk data).
      - Searches for models in repo paths and $HOME/projects/WinnCoreAV/models.
  - Robustness tweaks in detector (av-ml-detector):
      - Invalid/short/non-ELF → neutral features instead of errors; warnings logged.
      - Entropy helper unchanged; neutral_features helper added.
  - Tests run and passing:
      - Full workspace tests: cargo test --workspace --tests -- --nocapture ✅
      - Heavy stress: cargo test --release -p av-core stress_concurrent_scanning_heavy -- --ignored --nocapture ✅
      - Targeted scans of all fixtures (scores above).

  - ML decision policy:
      - Document the current score thresholds and actions (e.g., low scores → Allow, high scores → Quarantine, mid-range → Log-only / Monitor).
      - Clarify that thresholds and actions are centrally configured (single source of truth), not hard-coded in multiple call sites.
      - Note that ML is treated as a signal in the overall verdict pipeline (can be combined with heuristics, whitelists, LOTL rules, etc.).

  - Failure and fallback behavior:
      - Explicitly state that missing/bad models, parse failures, or invalid feature vectors never crash the scanner; they degrade to neutral score with warnings logged.
      - Call out that non-ELF / non-ARM64 input is intentionally treated as “unsupported but safe” rather than “error,” to keep scans resilient.
      - Mention that ML can be fully disabled via config/env without changing the rest of av-core.

  - Training and evaluation assets:
      - Reference the training/eval artifacts (e.g., synthetic dataset generator, training loop, and eval/report_v3_hardened.md or equivalent report file).
      - Briefly describe the training set composition at a high level (benign vs malicious ARM64 ELF samples, obfuscated / stripped binaries, LOTL-style samples).
      - Note that models are exported to ONNX and validated end-to-end via the Python harness before being checked into models/.

  - Integration into AV/EDR pipeline:
      - Describe where in the scan pipeline ML runs (e.g., after static heuristics, before final verdict).
      - Mention that per-sample ML scores and decisions are logged to support later analysis / tuning.
      - Clarify that the ML path is per-sample and side-effect-free beyond logging, so it can be safely parallelized with concurrent scanning.

  - Operator-facing documentation:
      - Add a short “How to tune the ML detector” section pointing operators to:
          - model directory layout (models/*.onnx),
          - config flags / env vars,
          - and the recommended workflow for testing new models against the fixture set before promotion.
      - Include a brief “Limitations” note (ARM64/ELF focus, static-only behavior, etc.) so expectations are realistic.
