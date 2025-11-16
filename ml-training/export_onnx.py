#!/usr/bin/env python3
"""Export trained model to ONNX format for WinnCoreAV"""

import joblib
import numpy as np
from pathlib import Path
import json

# Try different ONNX conversion methods
def try_onnxmltools():
    """Try using onnxmltools for LightGBM"""
    try:
        import onnxmltools
        from onnxmltools.convert import convert_lightgbm
        from onnxmltools.convert.common.data_types import FloatTensorType

        print("Using onnxmltools for LightGBM conversion...")

        # Load the calibrated model (which wraps LightGBM)
        model = joblib.load('models/lightgbm_model.joblib')

        # Extract the base estimator if it's a calibrated classifier
        if hasattr(model, 'base_estimator'):
            base_model = model.base_estimator
        else:
            base_model = model

        # Load feature names
        with open('models/feature_names.json', 'r') as f:
            feature_names = json.load(f)

        print(f"Model loaded with {len(feature_names)} features")

        # Define input type
        initial_types = [('input', FloatTensorType([None, len(feature_names)]))]

        # Convert to ONNX
        onnx_model = convert_lightgbm(base_model, initial_types=initial_types, target_opset=12)

        return onnx_model

    except Exception as e:
        print(f"onnxmltools failed: {e}")
        return None

def try_manual_export():
    """Manually export using LightGBM's booster"""
    try:
        print("Trying manual LightGBM export...")

        model = joblib.load('models/lightgbm_model.joblib')

        # Extract booster if available
        if hasattr(model, 'base_estimator'):
            base_model = model.base_estimator
        else:
            base_model = model

        if hasattr(base_model, 'booster_'):
            # Save as LightGBM model file
            base_model.booster_.save_model('models/gbm_v4_advanced.txt')
            print("✅ Saved as LightGBM text format: models/gbm_v4_advanced.txt")
            return True

    except Exception as e:
        print(f"Manual export failed: {e}")
        return False

# Main export logic
print("Loading trained LightGBM model...")

# Try onnxmltools first
onnx_model = try_onnxmltools()

if onnx_model:
    # Save ONNX model
    output_file = 'models/gbm_v4_advanced.onnx'
    with open(output_file, 'wb') as f:
        f.write(onnx_model.SerializeToString())

    print(f"✅ Model exported to {output_file}")
    print(f"   Model size: {Path(output_file).stat().st_size / 1024:.1f} KB")
else:
    # Try manual export as fallback
    success = try_manual_export()
    if not success:
        print("\n⚠ ONNX export failed. Model saved in joblib format only.")
        print("   You can load it with: joblib.load('models/lightgbm_model.joblib')")
