#![allow(dead_code)]
#![allow(unused_variables)]

use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::config::ScannerConfig;
use crate::engine::SignatureMatch;
use av_ml_detector::MlDetector;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct Score(pub f32);

pub fn score(path: &Path, _data: &[u8], config: &ScannerConfig) -> Score {
    eprintln!("🔍 [HEURISTICS] Starting ML scan for: {:?}", path);
    
    match load_and_scan_ml(path) {
        Ok(score) => {
            eprintln!("✅ [HEURISTICS] ML returned score: {}", score);
            Score(score)
        }
        Err(e) => {
            eprintln!("❌ [HEURISTICS] ML FAILED: {:?}", e);
            eprintln!("   Error details: {}", e);
            let mut source = e.source();
            while let Some(s) = source {
                eprintln!("   Caused by: {}", s);
                source = s.source();
            }
            Score(config.heuristic_threshold / 2.0)
        }
    }
}

fn load_and_scan_ml(path: &Path) -> anyhow::Result<f32> {
    let possible_paths = vec![
        std::env::var("HOME").ok()
            .map(|h| format!("{}/projects/WinnCoreAV/models/gbm_v3_hardened.onnx", h)),
        Some("/home/zacharywinn/projects/WinnCoreAV/models/gbm_v3_hardened.onnx".to_string()),
        Some("models/gbm_v3_hardened.onnx".to_string()),
        Some("../models/gbm_v3_hardened.onnx".to_string()),
    ];
    
    eprintln!("🔍 [ML] Searching for model file...");
    let mut model_path = None;
    for p in possible_paths.into_iter().flatten() {
        eprintln!("   Trying: {}", p);
        if std::path::Path::new(&p).exists() {
            eprintln!("   ✅ Found at: {}", p);
            model_path = Some(p);
            break;
        } else {
            eprintln!("   ❌ Not found");
        }
    }
    
    let model_path = model_path.ok_or_else(|| anyhow::anyhow!("Model file not found in any location"))?;
    
    eprintln!("🔍 [ML] Loading detector from: {}", model_path);
    let detector = MlDetector::new(&model_path)
        .map_err(|e| {
            eprintln!("❌ [ML] MlDetector::new() failed: {:?}", e);
            e
        })?;
    
    eprintln!("🔍 [ML] Scanning file: {:?}", path);
    let detection = detector.scan(path)
        .map_err(|e| {
            eprintln!("❌ [ML] detector.scan() failed: {:?}", e);
            e
        })?;
    
    eprintln!("✅ [ML] Scan complete - score: {:.3}, malicious: {}", 
              detection.score, detection.is_malicious);
    
    Ok(detection.score)
}

pub fn recommend(
    matches: &[SignatureMatch],
    score: Score,
    config: &ScannerConfig,
) -> crate::RecommendedAction {
    if !matches.is_empty() {
        return crate::RecommendedAction::Quarantine;
    }
    
    if score.0 >= config.heuristic_threshold {
        crate::RecommendedAction::Quarantine
    } else if score.0 >= config.heuristic_threshold * 0.6 {
        crate::RecommendedAction::Monitor
    } else {
        crate::RecommendedAction::Allow
    }
}
