#!/usr/bin/env python3
"""
WinnCoreAV - Advanced ML Model Training
Trains ensemble models with hyperparameter tuning for malware detection
"""

import os
import sys
import pandas as pd
import numpy as np
from pathlib import Path
import joblib
import json
from datetime import datetime
from typing import Tuple, Dict

# ML libraries
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier

# Gradient boosting libraries
import lightgbm as lgb

try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("Warning: XGBoost not installed. Install with: pip install xgboost")

try:
    import optuna
    HAS_OPTUNA = True
except ImportError:
    HAS_OPTUNA = False
    print("Warning: Optuna not installed. Install with: pip install optuna")

# ONNX export
try:
    import onnx
    import skl2onnx
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False
    print("Warning: ONNX conversion not available. Install with: pip install onnx skl2onnx")


class AdvancedMalwareDetector:
    """Advanced ensemble ML model for malware detection"""

    def __init__(self, use_optuna: bool = False):
        self.use_optuna = use_optuna and HAS_OPTUNA
        self.scaler = StandardScaler()
        self.models = {}
        self.feature_names = []
        self.metrics = {}

    def load_data(self, csv_path: str) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Load and split dataset"""
        print(f"Loading dataset from {csv_path}...")

        df = pd.read_csv(csv_path)

        # Remove non-feature columns
        feature_cols = [col for col in df.columns if col not in ['label', 'file_path']]
        self.feature_names = feature_cols

        X = df[feature_cols].values
        y = df['label'].values

        print(f"Dataset loaded:")
        print(f"  Total samples: {len(y)}")
        print(f"  Malware: {sum(y == 1)} ({sum(y == 1)/len(y)*100:.1f}%)")
        print(f"  Benign: {sum(y == 0)} ({sum(y == 0)/len(y)*100:.1f}%)")
        print(f"  Features: {len(feature_cols)}")

        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Scale features
        X_train = self.scaler.fit_transform(X_train)
        X_test = self.scaler.transform(X_test)

        return X_train, X_test, y_train, y_test

    def train_lightgbm(self, X_train, y_train, params: Dict = None) -> lgb.LGBMClassifier:
        """Train LightGBM model"""
        print("\nTraining LightGBM model...")

        if params is None:
            params = {
                'num_leaves': 31,
                'learning_rate': 0.05,
                'n_estimators': 500,
                'max_depth': -1,
                'min_child_samples': 20,
                'subsample': 0.8,
                'colsample_bytree': 0.8,
                'reg_alpha': 0.1,
                'reg_lambda': 0.1,
                'random_state': 42,
                'n_jobs': -1,
                'verbose': -1,
            }

        model = lgb.LGBMClassifier(**params)
        model.fit(X_train, y_train)

        return model

    def train_xgboost(self, X_train, y_train, params: Dict = None) -> 'xgb.XGBClassifier':
        """Train XGBoost model"""
        if not HAS_XGBOOST:
            print("XGBoost not available, skipping...")
            return None

        print("\nTraining XGBoost model...")

        if params is None:
            params = {
                'max_depth': 6,
                'learning_rate': 0.05,
                'n_estimators': 500,
                'subsample': 0.8,
                'colsample_bytree': 0.8,
                'reg_alpha': 0.1,
                'reg_lambda': 0.1,
                'random_state': 42,
                'n_jobs': -1,
                'eval_metric': 'logloss',
            }

        model = xgb.XGBClassifier(**params)
        model.fit(X_train, y_train)

        return model

    def train_random_forest(self, X_train, y_train, params: Dict = None) -> RandomForestClassifier:
        """Train Random Forest model"""
        print("\nTraining Random Forest model...")

        if params is None:
            params = {
                'n_estimators': 500,
                'max_depth': 20,
                'min_samples_split': 5,
                'min_samples_leaf': 2,
                'max_features': 'sqrt',
                'random_state': 42,
                'n_jobs': -1,
            }

        model = RandomForestClassifier(**params)
        model.fit(X_train, y_train)

        return model

    def optimize_lightgbm_params(self, X_train, y_train) -> Dict:
        """Optimize LightGBM hyperparameters using Optuna"""
        if not self.use_optuna:
            return None

        print("\nOptimizing LightGBM hyperparameters with Optuna...")

        def objective(trial):
            params = {
                'num_leaves': trial.suggest_int('num_leaves', 20, 100),
                'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.3),
                'n_estimators': trial.suggest_int('n_estimators', 100, 1000),
                'max_depth': trial.suggest_int('max_depth', 3, 12),
                'min_child_samples': trial.suggest_int('min_child_samples', 5, 50),
                'subsample': trial.suggest_float('subsample', 0.6, 1.0),
                'colsample_bytree': trial.suggest_float('colsample_bytree', 0.6, 1.0),
                'reg_alpha': trial.suggest_float('reg_alpha', 0.0, 1.0),
                'reg_lambda': trial.suggest_float('reg_lambda', 0.0, 1.0),
                'random_state': 42,
                'n_jobs': -1,
                'verbose': -1,
            }

            model = lgb.LGBMClassifier(**params)

            # Cross-validation
            skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
            scores = cross_val_score(model, X_train, y_train, cv=skf, scoring='roc_auc', n_jobs=-1)

            return scores.mean()

        study = optuna.create_study(direction='maximize', study_name='lightgbm_optimization')
        study.optimize(objective, n_trials=50, show_progress_bar=True)

        print(f"Best ROC-AUC: {study.best_value:.4f}")
        print(f"Best params: {study.best_params}")

        return study.best_params

    def train_ensemble(self, X_train, y_train):
        """Train ensemble of models"""
        print("\n" + "="*60)
        print("Training Ensemble Models")
        print("="*60)

        # Optimize LightGBM if using Optuna
        lgb_params = None
        if self.use_optuna:
            lgb_params = self.optimize_lightgbm_params(X_train, y_train)

        # Train individual models
        self.models['lightgbm'] = self.train_lightgbm(X_train, y_train, lgb_params)
        self.models['random_forest'] = self.train_random_forest(X_train, y_train)

        if HAS_XGBOOST:
            self.models['xgboost'] = self.train_xgboost(X_train, y_train)

        print(f"\n✅ Trained {len(self.models)} models in ensemble")

    def calibrate_models(self, X_train, y_train):
        """Calibrate model probabilities"""
        print("\nCalibrating model probabilities...")

        calibrated_models = {}

        for name, model in self.models.items():
            if model is not None:
                print(f"  Calibrating {name}...")
                calibrated = CalibratedClassifierCV(model, cv=5, method='sigmoid')
                calibrated.fit(X_train, y_train)
                calibrated_models[name] = calibrated

        self.models = calibrated_models
        print("✅ Model calibration complete")

    def predict_ensemble(self, X) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions using ensemble voting"""
        predictions = []
        probabilities = []

        for name, model in self.models.items():
            if model is not None:
                pred = model.predict(X)
                proba = model.predict_proba(X)[:, 1]
                predictions.append(pred)
                probabilities.append(proba)

        # Average predictions
        if predictions:
            ensemble_proba = np.mean(probabilities, axis=0)
            ensemble_pred = (ensemble_proba >= 0.5).astype(int)
            return ensemble_pred, ensemble_proba
        else:
            return None, None

    def evaluate(self, X_test, y_test):
        """Evaluate model performance"""
        print("\n" + "="*60)
        print("Model Evaluation")
        print("="*60)

        # Get ensemble predictions
        y_pred, y_proba = self.predict_ensemble(X_test)

        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_proba)

        self.metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'roc_auc': roc_auc,
        }

        print(f"\nEnsemble Model Performance:")
        print(f"  Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"  Precision: {precision:.4f} ({precision*100:.2f}%)")
        print(f"  Recall:    {recall:.4f} ({recall*100:.2f}%)")
        print(f"  F1-Score:  {f1:.4f}")
        print(f"  ROC-AUC:   {roc_auc:.4f}")

        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        print(f"\nConfusion Matrix:")
        print(f"  TN: {cm[0,0]:5d}  |  FP: {cm[0,1]:5d}")
        print(f"  FN: {cm[1,0]:5d}  |  TP: {cm[1,1]:5d}")

        # False positive rate
        fp_rate = cm[0,1] / (cm[0,0] + cm[0,1])
        print(f"\nFalse Positive Rate: {fp_rate:.4f} ({fp_rate*100:.2f}%)")

        # Evaluate individual models
        print(f"\nIndividual Model Performance:")
        for name, model in self.models.items():
            if model is not None:
                pred = model.predict(X_test)
                acc = accuracy_score(y_test, pred)
                print(f"  {name:15s}: {acc:.4f}")

        return self.metrics

    def cross_validate(self, X, y, n_splits: int = 5):
        """Perform cross-validation"""
        print(f"\nPerforming {n_splits}-fold cross-validation...")

        skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
        cv_scores = []

        for fold, (train_idx, val_idx) in enumerate(skf.split(X, y), 1):
            X_train_cv, X_val_cv = X[train_idx], X[val_idx]
            y_train_cv, y_val_cv = y[train_idx], y[val_idx]

            # Train LightGBM for CV
            model = self.train_lightgbm(X_train_cv, y_train_cv)
            y_pred = model.predict(X_val_cv)
            score = accuracy_score(y_val_cv, y_pred)
            cv_scores.append(score)

            print(f"  Fold {fold}: {score:.4f}")

        mean_score = np.mean(cv_scores)
        std_score = np.std(cv_scores)

        print(f"\nCross-validation results:")
        print(f"  Mean Accuracy: {mean_score:.4f} ± {std_score:.4f}")

        self.metrics['cv_mean'] = mean_score
        self.metrics['cv_std'] = std_score

        return mean_score, std_score

    def save_models(self, output_dir: str = 'models'):
        """Save trained models"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        print(f"\nSaving models to {output_dir}...")

        # Save individual models
        for name, model in self.models.items():
            if model is not None:
                model_file = output_path / f"{name}_model.joblib"
                joblib.dump(model, model_file)
                print(f"  Saved {name} to {model_file}")

        # Save scaler
        scaler_file = output_path / "scaler.joblib"
        joblib.dump(self.scaler, scaler_file)

        # Save feature names
        feature_file = output_path / "feature_names.json"
        with open(feature_file, 'w') as f:
            json.dump(self.feature_names, f, indent=2)

        # Save metrics
        metrics_file = output_path / "metrics.json"
        with open(metrics_file, 'w') as f:
            json.dump(self.metrics, f, indent=2)

        print("✅ Models saved successfully")

    def export_to_onnx(self, output_file: str = 'models/ensemble_model.onnx'):
        """Export primary model to ONNX format"""
        if not HAS_ONNX:
            print("ONNX export not available")
            return

        print(f"\nExporting model to ONNX format...")

        # Use LightGBM as primary model for ONNX export
        primary_model = self.models.get('lightgbm')

        if primary_model is None:
            print("No LightGBM model available for ONNX export")
            return

        try:
            # Define input type
            initial_type = [('float_input', FloatTensorType([None, len(self.feature_names)]))]

            # Convert to ONNX
            onnx_model = convert_sklearn(primary_model, initial_types=initial_type)

            # Save ONNX model
            with open(output_file, "wb") as f:
                f.write(onnx_model.SerializeToString())

            print(f"✅ ONNX model exported to {output_file}")

        except Exception as e:
            print(f"Error exporting to ONNX: {e}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Train advanced ML models for malware detection')
    parser.add_argument('--input', '-i', default='features.csv',
                       help='Input CSV file with features')
    parser.add_argument('--output-dir', '-o', default='models',
                       help='Output directory for models')
    parser.add_argument('--use-optuna', action='store_true',
                       help='Use Optuna for hyperparameter tuning')
    parser.add_argument('--calibrate', action='store_true',
                       help='Apply probability calibration')
    parser.add_argument('--cross-validate', action='store_true',
                       help='Perform cross-validation')
    parser.add_argument('--export-onnx', default='models/gbm_v4_advanced.onnx',
                       help='Export model to ONNX format')

    args = parser.parse_args()

    # Initialize detector
    detector = AdvancedMalwareDetector(use_optuna=args.use_optuna)

    # Load data
    X_train, X_test, y_train, y_test = detector.load_data(args.input)

    # Cross-validation
    if args.cross_validate:
        X_all = np.vstack([X_train, X_test])
        y_all = np.hstack([y_train, y_test])
        detector.cross_validate(X_all, y_all)

    # Train ensemble
    detector.train_ensemble(X_train, y_train)

    # Calibrate models
    if args.calibrate:
        detector.calibrate_models(X_train, y_train)

    # Evaluate
    metrics = detector.evaluate(X_test, y_test)

    # Save models
    detector.save_models(args.output_dir)

    # Export to ONNX
    if args.export_onnx:
        detector.export_to_onnx(args.export_onnx)

    print("\n" + "="*60)
    print("✅ Training Complete!")
    print("="*60)

    # Check if success metrics are met
    success = True
    if metrics['accuracy'] < 0.99:
        print(f"⚠ Accuracy ({metrics['accuracy']:.4f}) below target (0.99)")
        success = False

    fp_rate = 1 - metrics['precision']  # Approximation
    if fp_rate > 0.001:
        print(f"⚠ False positive rate ({fp_rate:.4f}) above target (0.001)")
        success = False

    if success:
        print("🎉 All success metrics achieved!")


if __name__ == '__main__':
    main()
