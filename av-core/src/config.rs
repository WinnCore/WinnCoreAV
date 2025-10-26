#![allow(dead_code)]
#![allow(unused_variables)]
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level configuration for the scanning engine.
///
/// Values default to conservative, read-only behaviour. Mutation-capable
/// workflows are disabled unless explicitly toggled by the user and
/// confirmed through higher-level UI layers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub signature_sources: Vec<SignatureSource>,
    pub heuristic_threshold: f32,
    pub bloom_filter_bits: usize,
    pub max_scan_depth: usize,
    pub thread_pool_size: usize,
    pub enable_entropy_analysis: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            signature_sources: vec![],
            heuristic_threshold: 0.8,
            bloom_filter_bits: 1 << 18,
            max_scan_depth: 4,
            thread_pool_size: 4,
            enable_entropy_analysis: true,
        }
    }
}

impl ScannerConfig {
    /// Validate the configuration so the daemon can fail fast in case
    /// prerequisites are missing. This allows us to gracefully degrade
    /// without ever dropping into destructive fallbacks.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.heuristic_threshold >= 0.0 && self.heuristic_threshold <= 1.0);
        anyhow::ensure!(self.thread_pool_size >= 1 && self.thread_pool_size <= 32);
        Ok(())
    }
}

/// Describes how signature bundles are sourced.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureSource {
    pub name: String,
    pub url: url::Url,
    pub pinned_spki_sha256: String,
    pub local_cache: PathBuf,
}
