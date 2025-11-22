## Adversarial Augmentation Toolkit

Purpose: generate safe augmentations of ARM64 ELF samples to harden the ML training pipeline against common evasion tactics.

Transforms implemented in `augment.py`:
- Section padding (NOP-like bytes)
- Benign string injection
- Symbol stripping (where safe)
- Section reordering simulation (metadata shuffling)

Usage:
```
python3 augment.py --input <input_dir> --output tools/adversarial/out --benign-subdir benign --malicious-subdir malicious
```

Outputs land under:
- `tools/adversarial/out/benign_augmented/`
- `tools/adversarial/out/malicious_augmented/`

Intended use:
- Feed augmented samples into ML retraining to increase robustness to packing/evasion.
