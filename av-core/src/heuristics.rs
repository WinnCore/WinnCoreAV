#![allow(dead_code)]
#![allow(unused_variables)]

use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::config::ScannerConfig;
use crate::engine::SignatureMatch;
use av_ml_detector::MlDetector;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct Score(pub f32);

/// Score a file using ML malware detection
/// 
/// This function:
/// 1. Loads the trained ONNX model
/// 2. Extracts 14 features from the binary
/// 3. Runs ML inference
/// 4. Returns malware probability as score
pub fn score(path: &Path, _data: &[u8], config: &ScannerConfig) -> Score {
    // Try to load ML detector and scan
    match load_and_scan_ml(path) {
        Ok(score) => Score(score),
        Err(e) => {
            tracing::warn!("ML detection failed for {:?}: {}", path, e);
            // Fall back to placeholder on error
            Score(config.heuristic_threshold / 2.0)
        }
    }
}

/// Load ML detector and scan a file
fn load_and_scan_ml(path: &Path) -> anyhow::Result<f32> {
    // FIXED: Search for model in common locations (works from any directory)
    let possible_paths = vec![
        "/home/user/WinnCoreAV/models/gbm_v3_hardened.onnx",  // Absolute path (most reliable)
        "models/gbm_v3_hardened.onnx",                         // Relative from project root
        "../models/gbm_v3_hardened.onnx",                      // Relative from subdirectory
    ];

    let model_path = possible_paths.into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .ok_or_else(|| anyhow::anyhow!("Cannot find gbm_v3_hardened.onnx model file. Searched: /home/user/WinnCoreAV/models/, models/, ../models/"))?;

    tracing::info!("Loading ML model from: {}", model_path);

    // Load ML detector
    let detector = MlDetector::new(model_path)?;

    // Scan file
    let detection = detector.scan(path)?;

    // Log detection for debugging
    tracing::info!(
        "ML scan: {:?} - score: {:.3}, malicious: {}, confidence: {:?}",
        path.file_name().unwrap_or_default(),
        detection.score,
        detection.is_malicious,
        detection.confidence
    );

    // Return score (0.0 - 1.0)
    Ok(detection.score)
}

pub fn recommend(
    matches: &[SignatureMatch],
    score: Score,
    config: &ScannerConfig,
) -> crate::RecommendedAction {
    // YARA signature match = immediate quarantine
    if !matches.is_empty() {
        return crate::RecommendedAction::Quarantine;
    }
    
    // ML-based decision thresholds
    if score.0 >= config.heuristic_threshold {
        crate::RecommendedAction::Quarantine
    } else if score.0 >= config.heuristic_threshold * 0.6 {
        crate::RecommendedAction::Monitor
    } else {
        crate::RecommendedAction::Allow
    }
}
