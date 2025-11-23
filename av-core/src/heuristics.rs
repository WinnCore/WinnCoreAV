#![allow(dead_code)]
#![allow(unused_variables)]

use crate::config::ScannerConfig;
use crate::engine::SignatureMatch;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[cfg(feature = "ml-detector")]
use crate::logging;
#[cfg(feature = "ml-detector")]
use av_ml_detector::{EnhancedFeatureExtractor, EnsembleDetector, MlDetector};
#[cfg(feature = "ml-detector")]
use std::fs::File;
#[cfg(feature = "ml-detector")]
use std::io::Read;
#[cfg(feature = "ml-detector")]
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct Score(pub f32);

#[cfg(feature = "ml-detector")]
pub fn score(path: &Path, _data: &[u8], config: &ScannerConfig) -> Score {
    eprintln!("🔍 [HEURISTICS] Starting ML scan for: {:?}", path);

    if !config.enable_ml {
        eprintln!("ℹ️  [HEURISTICS] ML disabled via config; returning neutral score.");
        return Score(0.0);
    }

    match load_and_scan_ml(path, config) {
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

#[cfg(not(feature = "ml-detector"))]
pub fn score(_path: &Path, _data: &[u8], _config: &ScannerConfig) -> Score {
    eprintln!(
        "ℹ️  [HEURISTICS] ML detector not compiled (feature disabled); returning neutral score."
    );
    Score(0.0)
}

#[cfg(feature = "ml-detector")]
fn load_and_scan_ml(path: &Path, config: &ScannerConfig) -> anyhow::Result<f32> {
    if !looks_like_elf(path)? {
        let emit = logging::log_non_elf_skip_should_emit(config.log_verbose_non_elf_skips);
        if emit {
            eprintln!("ℹ️  [ML] Skipping ML scan for non-ELF input: {:?}", path);
        }
        return Ok(0.0);
    }

    if let Some((lgb, xgb, mlp)) = find_ensemble_models() {
        eprintln!(
            "🔍 [ML] Using ensemble models: {}, {}, {}",
            lgb.display(),
            xgb.display(),
            mlp.display()
        );
        let extractor = EnhancedFeatureExtractor::new()
            .map_err(|e| anyhow::anyhow!("Failed to build enhanced extractor: {}", e))?;
        let features = extractor.extract_features(path)?;
        let detector = EnsembleDetector::new(&lgb, &xgb, &mlp)
            .map_err(|e| anyhow::anyhow!("EnsembleDetector init failed: {}", e))?;
        let result = detector
            .predict(&features)
            .map_err(|e| anyhow::anyhow!("Ensemble predict failed: {}", e))?;
        eprintln!(
            "✅ [ML] Ensemble score {:.3} (agreement {:.2})",
            result.confidence, result.model_agreement
        );
        return Ok(result.confidence);
    }

    let possible_paths = vec![
        std::env::var("HOME")
            .ok()
            .map(|h| format!("{}/projects/WinnCoreAV/models/gbm_v3_hardened.onnx", h)),
        Some("/home/zacharywinn/projects/WinnCoreAV/models/gbm_v3_hardened.onnx".to_string()),
        Some("models/manifest.json".to_string()), // manifest path
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

    let model_path =
        model_path.ok_or_else(|| anyhow::anyhow!("Model file not found in any location"))?;

    // If model_path is a manifest, resolve via manifest selection
    let model_path = if model_path.ends_with("manifest.json") {
        if let Ok(manifest) =
            av_ml_detector::update::ModelManifest::load(std::path::Path::new(&model_path))
        {
            if let Some(entry) = av_ml_detector::update::select_model_from_manifest(
                &manifest,
                config.model_updates.model_lock_version.as_deref(),
            ) {
                let p = entry
                    .path
                    .unwrap_or_else(|| format!("models/{}.onnx", entry.model_name));
                eprintln!(
                    "ℹ️  [ML] Manifest selected model {} version {} at {}",
                    entry.model_name, entry.version, p
                );
                p
            } else {
                model_path
            }
        } else {
            model_path
        }
    } else {
        model_path
    };

    let checksum = logging::sha256_file(std::path::Path::new(&model_path)).ok();
    let ts = logging::iso_timestamp();

    eprintln!("🔍 [ML] Loading detector from: {}", model_path);
    let detector = MlDetector::new(&model_path).map_err(|e| {
        eprintln!("❌ [ML] MlDetector::new() failed: {:?}", e);
        e
    })?;

    eprintln!("🔍 [ML] Scanning file: {:?}", path);
    let detection = detector.scan(path).map_err(|e| {
        eprintln!("❌ [ML] detector.scan() failed: {:?}", e);
        e
    })?;

    if let Some(cs) = &checksum {
        eprintln!(
            "ℹ️  [ML] Model metadata ts={} path={} sha256={}",
            ts, model_path, cs
        );
    }

    eprintln!(
        "✅ [ML] Scan complete - score: {:.3}, malicious: {}",
        detection.score, detection.is_malicious
    );

    Ok(detection.score)
}

#[cfg(feature = "ml-detector")]
fn looks_like_elf(path: &Path) -> anyhow::Result<bool> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 4];
    let read = file.read(&mut magic)?;
    Ok(read == 4 && magic == [0x7F, b'E', b'L', b'F'])
}

#[cfg(feature = "ml-detector")]
fn find_ensemble_models() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let mut roots: Vec<PathBuf> = vec![PathBuf::from("models"), PathBuf::from("../models")];

    if let Ok(home) = std::env::var("HOME") {
        roots.push(PathBuf::from(format!("{home}/projects/WinnCoreAV/models")));
    }

    for root in roots {
        let lgb = root.join("lgbm_model.onnx");
        let xgb = root.join("xgb_model.onnx");
        let mlp = root.join("mlp_model.onnx");
        if lgb.exists() && xgb.exists() && mlp.exists() {
            return Some((lgb, xgb, mlp));
        }
    }

    None
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
