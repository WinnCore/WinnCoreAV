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
    pub enable_ml: bool,
    pub ml_threshold: f32,
    pub allowlist_hashes: Vec<String>,
    pub allowlist_paths: Vec<PathBuf>,
    pub log_json: bool,
    pub log_verbose_non_elf_skips: bool,
    pub mitre_tagging: bool,
    pub eicar_detection: bool,
    pub threat_intel: ThreatIntelConfig,
    pub model_updates: ModelUpdateConfig,
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
            enable_ml: true,
            ml_threshold: 0.5,
            allowlist_hashes: Vec::new(),
            allowlist_paths: Vec::new(),
            log_json: true,
            log_verbose_non_elf_skips: false,
            mitre_tagging: true,
            eicar_detection: true,
            threat_intel: ThreatIntelConfig::default(),
            model_updates: ModelUpdateConfig::default(),
        }
    }
}

impl ScannerConfig {
    /// Validate the configuration so the daemon can fail fast in case
    /// prerequisites are missing. This allows us to gracefully degrade
    /// without ever dropping into destructive fallbacks.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.heuristic_threshold >= 0.0 && self.heuristic_threshold <= 1.0);
        anyhow::ensure!(self.ml_threshold >= 0.0 && self.ml_threshold <= 1.0);
        anyhow::ensure!(self.thread_pool_size >= 1 && self.thread_pool_size <= 32);
        Ok(())
    }

    /// Load configuration from a TOML file, falling back to defaults on failure.
    pub fn load_from_path(path: &PathBuf) -> Self {
        if let Ok(data) = std::fs::read_to_string(path) {
            if let Ok(cfg) = toml::from_str::<ScannerConfig>(&data) {
                return cfg;
            }
        }
        ScannerConfig::default()
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    pub yara_rules_dir: Option<PathBuf>,
    pub ioc_cache_path: Option<PathBuf>,
    pub taxii_collection: Option<String>,
    pub taxii_url: Option<String>,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            yara_rules_dir: None,
            ioc_cache_path: Some(PathBuf::from("threat_intel/cache/iocs.json")),
            taxii_collection: None,
            taxii_url: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelUpdateConfig {
    pub manifest_url: Option<String>,
    pub public_key_path: Option<PathBuf>,
    pub model_lock_version: Option<String>,
}

impl Default for ModelUpdateConfig {
    fn default() -> Self {
        Self {
            manifest_url: None,
            public_key_path: Some(PathBuf::from("config/model_pubkey.pem")),
            model_lock_version: None,
        }
    }
}
