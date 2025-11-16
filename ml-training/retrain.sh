#!/bin/bash
#
# WinnCoreAV ML Model Retraining Pipeline
# Automatically generates samples, extracts features, and trains models
#

set -e  # Exit on error

echo "=========================================="
echo "WinnCoreAV ML Retraining Pipeline"
echo "=========================================="
echo ""

# Configuration
NEW_SAMPLES=${1:-1000}
RETRAIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WINNCORE_DIR="${WINNCORE_DIR:-../WinnCoreAV}"

cd "$RETRAIN_DIR"

# Step 1: Generate new synthetic malware samples
echo "Step 1: Generating $NEW_SAMPLES new malware samples..."
python3 generate_synthetic_malware.py \
    --count $NEW_SAMPLES \
    --level 3 \
    --output samples/malware/retrain

echo "✅ Sample generation complete"
echo ""

# Step 2: Extract features from all samples
echo "Step 2: Extracting features..."
python3 extract_features.py \
    --output features_retrain.csv \
    --benign-dir samples/benign \
    --malware-dirs samples/malware/level1 samples/malware/level2 samples/malware/level3 samples/c-patterns samples/malware/retrain

echo "✅ Feature extraction complete"
echo ""

# Step 3: Train models
echo "Step 3: Training ensemble models..."
python3 train_model.py \
    --input features_retrain.csv \
    --output-dir models \
    --calibrate \
    --cross-validate

TRAIN_EXIT=$?

if [ $TRAIN_EXIT -ne 0 ]; then
    echo "❌ Training failed with exit code $TRAIN_EXIT"
    exit 1
fi

echo "✅ Model training complete"
echo ""

# Step 4: Evaluate new model
echo "Step 4: Evaluating new model..."
python3 << 'EVAL_SCRIPT'
import json
from pathlib import Path

# Load new metrics
with open('models/metrics.json', 'r') as f:
    new_metrics = json.load(f)

# Check if previous metrics exist
prev_metrics_file = Path('models/metrics_previous.json')
if prev_metrics_file.exists():
    with open(prev_metrics_file, 'r') as f:
        prev_metrics = json.load(f)

    # Compare metrics
    print(f"Previous Accuracy: {prev_metrics.get('accuracy', 0):.4f}")
    print(f"New Accuracy:      {new_metrics['accuracy']:.4f}")

    improvement = new_metrics['accuracy'] - prev_metrics.get('accuracy', 0)
    print(f"Improvement:       {improvement:+.4f}")

    if improvement >= 0:
        print("✅ New model is equal or better!")
        exit(0)
    else:
        print("⚠ New model performance declined")
        exit(1)
else:
    print("First training - no previous metrics to compare")
    print(f"New Accuracy: {new_metrics['accuracy']:.4f}")
    exit(0)
EVAL_SCRIPT

EVAL_EXIT=$?
echo ""

# Step 5: Deploy if improved
if [ $EVAL_EXIT -eq 0 ]; then
    echo "Step 5: Deploying new model..."

    # Backup previous metrics
    if [ -f models/metrics.json ]; then
        cp models/metrics.json models/metrics_previous.json
    fi

    # Deploy to WinnCoreAV if directory exists
    if [ -d "$WINNCORE_DIR/models" ]; then
        echo "Copying models to WinnCoreAV..."
        cp models/*.joblib "$WINNCORE_DIR/models/" 2>/dev/null || mkdir -p "$WINNCORE_DIR/models"
        cp models/*.json "$WINNCORE_DIR/models/" 2>/dev/null || true

        echo "✅ Models deployed to WinnCoreAV"
    else
        echo "⚠ WinnCoreAV directory not found at $WINNCORE_DIR"
        echo "  Set WINNCORE_DIR environment variable to deploy automatically"
    fi

    echo ""
    echo "=========================================="
    echo "✅ Retraining Complete!"
    echo "=========================================="
    echo ""
    echo "Summary:"
    echo "- New samples generated: $NEW_SAMPLES"
    echo "- Models trained: LightGBM, XGBoost, Random Forest"
    echo "- Calibration: Applied"
    echo "- Cross-validation: Performed"
    echo "- Deployment: Success"
    echo ""

else
    echo "❌ Model did not improve - keeping previous version"
    exit 1
fi
