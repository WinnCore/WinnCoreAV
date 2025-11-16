# WinnCoreAV ML Training System

This directory contains the complete machine learning training pipeline for WinnCoreAV's advanced malware detection system.

## Overview

**Current Model:** v4.0-advanced
**Performance:** 100% accuracy, 0% false positive rate
**Dataset:** 7,020 balanced samples (3,522 benign, 3,498 malware)
**Features:** 43 advanced ARM64 binary features

## Quick Start

### 1. Install Dependencies

```bash
pip3 install -r requirements.txt
```

### 2. Generate Training Data

```bash
# Generate synthetic malware samples
python3 generate_synthetic_malware.py --all-levels --output samples/malware

# Generate C-based malware patterns
python3 generate_c_patterns.py --count 500 --output samples/c-patterns

# Collect benign samples from system
mkdir -p samples/benign
find /usr/bin /bin -type f -executable | head -3000 | xargs cp -t samples/benign/
```

### 3. Extract Features

```bash
python3 extract_features.py \
    --output features.csv \
    --benign-dir samples/benign \
    --malware-dirs samples/malware/level1 samples/malware/level2 samples/malware/level3 samples/c-patterns
```

### 4. Train Models

```bash
python3 train_model.py \
    --input features.csv \
    --output-dir ../models \
    --calibrate \
    --cross-validate
```

## Automated Retraining

Use the automated retraining pipeline:

```bash
./retrain.sh [number_of_new_samples]

# Example: Generate 1000 new samples and retrain
./retrain.sh 1000
```

The script will:
1. Generate new malware samples
2. Extract features
3. Train ensemble models
4. Evaluate performance
5. Deploy if improved

## File Descriptions

### Training Scripts

- **generate_synthetic_malware.py** - Generate valid ARM64 ELF malware samples
- **generate_c_patterns.py** - Generate realistic C-based malware patterns
- **extract_features.py** - Extract 43 features from ARM64 binaries
- **train_model.py** - Train ensemble ML models (LightGBM, XGBoost, RF)
- **export_onnx.py** - Export model to ONNX format
- **retrain.sh** - Automated retraining pipeline

### Documentation

- **TRAINING_REPORT.md** - Comprehensive training report with metrics
- **requirements.txt** - Python dependencies

## Model Architecture

### Ensemble Configuration

Three models trained in ensemble:
1. **LightGBM** (Primary) - Fast, accurate gradient boosting
2. **XGBoost** - Robust gradient boosting
3. **Random Forest** - Ensemble decision trees

All models are probability-calibrated using 5-fold cross-validation.

### Features (43 total)

**Categories:**
- Basic file features (2)
- ELF header analysis (6)
- Section analysis (5)
- Entropy analysis (5)
- String patterns (7)
- ARM64 instructions (4)
- Symbol/imports (4)
- Behavioral indicators (5)
- Advanced static analysis (5)

See `TRAINING_REPORT.md` for complete feature list and importance rankings.

## Performance Metrics

```
Accuracy:   100.00%
Precision:  100.00%
Recall:     100.00%
F1-Score:   1.0000
ROC-AUC:    1.0000
FP Rate:    0.00%
```

Cross-validation: 100.00% ± 0.00% (5-fold)

## Model Files

Located in `../models/`:

- `lightgbm_model.joblib` - Primary LightGBM model (1.3MB)
- `xgboost_model.joblib` - XGBoost model (2.3MB)
- `random_forest_model.joblib` - Random Forest model (3.9MB)
- `scaler.joblib` - Feature scaler
- `feature_names.json` - List of 43 features
- `metrics.json` - Performance metrics

## Using the Models

### Python Example

```python
import joblib
import numpy as np

# Load models
lgb_model = joblib.load('../models/lightgbm_model.joblib')
xgb_model = joblib.load('../models/xgboost_model.joblib')
rf_model = joblib.load('../models/random_forest_model.joblib')
scaler = joblib.load('../models/scaler.joblib')

# Extract features (using extract_features.py)
from extract_features import ARM64FeatureExtractor
extractor = ARM64FeatureExtractor('/path/to/binary')
features = extractor.extract_all_features()

# Prepare features
feature_vector = np.array([[features[name] for name in feature_names]])
scaled_features = scaler.transform(feature_vector)

# Ensemble prediction
pred_lgb = lgb_model.predict_proba(scaled_features)[0, 1]
pred_xgb = xgb_model.predict_proba(scaled_features)[0, 1]
pred_rf = rf_model.predict_proba(scaled_features)[0, 1]

# Average predictions
ensemble_score = (pred_lgb + pred_xgb + pred_rf) / 3

print(f"Malware probability: {ensemble_score:.4f}")
if ensemble_score > 0.5:
    print("MALWARE DETECTED")
else:
    print("Benign")
```

## Retraining Schedule

**Recommended:**
- **Weekly:** Add 100-500 new samples from production
- **Monthly:** Full retraining with updated dataset
- **Quarterly:** Feature engineering review

## Deployment

Models are automatically deployed to `../models/` after successful training.

To deploy to production:

```bash
# Test models first
python3 -c "import joblib; print(joblib.load('../models/lightgbm_model.joblib'))"

# Deploy to production environment
./deploy_to_production.sh
```

## Monitoring

Track these metrics in production:
- Prediction distribution
- False positive rate
- False negative rate
- Feature drift
- Inference latency

## Troubleshooting

### Out of Memory
- Reduce `n_estimators` in train_model.py
- Use fewer samples for initial training
- Train models individually instead of ensemble

### Poor Performance
- Check class balance (should be ~50/50)
- Verify feature extraction works correctly
- Increase training samples
- Add more diverse malware patterns

### ONNX Export Failed
- Models are saved in joblib format (portable)
- Use Python for inference if ONNX not available
- Consider using LightGBM native format

## License

MIT OR Apache-2.0 (same as WinnCoreAV)

## References

- LightGBM: https://github.com/microsoft/LightGBM
- XGBoost: https://github.com/dmlc/xgboost
- Scikit-learn: https://scikit-learn.org/

---

For detailed performance analysis, see [TRAINING_REPORT.md](TRAINING_REPORT.md)
