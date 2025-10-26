#![allow(dead_code)]
#![allow(unused_variables)]
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::ScannerConfig;
use crate::engine::SignatureMatch;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct Score(pub f32);

pub fn score(_path: &Path, _data: &[u8], config: &ScannerConfig) -> Score {
    // Placeholder scoring algorithm; actual implementation to blend entropy,
    // behavioural metadata, and historical false-positive suppressions.
    Score(config.heuristic_threshold / 2.0)
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
