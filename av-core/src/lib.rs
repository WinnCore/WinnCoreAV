#![allow(dead_code)]
#![allow(unused_variables)]
//! Core scanning library for the WinnCore ARM64 antivirus suite.
//!
//! This crate stays entirely in user space, obeying read-only defaults.
//! It exposes scanning primitives, heuristics, and extension points that
//! higher-level components (daemon, CLI, GUI) consume. All potentially
//! destructive actions (quarantine, remediation) are modelled as opt-in
//! workflows where callers must explicitly request mutation.
//!
//! Safety guarantees:
//! - All file interactions default to read-only and buffer bounded I/O.
//! - Heavy workloads flow through a bounded task pool to preserve system
//!   responsiveness on Snapdragon 8cx hardware.
//! - Optional NEON acceleration is guard-railed behind the `neon_accel`
//!   feature and runtime CPU feature detection.
//! - YARA-compatible rules are validated before execution, and every
//!   decision passes through the heuristic fusion layer for suppressions.

pub mod allocator;
pub mod arm64_security;
pub mod bounded;
pub mod config;
pub mod encrypted_strings;
pub mod engine;
pub mod heuristics;
pub mod logging;
pub mod monitoring;
pub mod mte;
pub mod retry;
pub mod secure_mem;
pub mod selfprotect;
pub mod signatures;
pub mod telemetry;
pub mod threat_intel;
pub mod validation;

pub use allocator::{configure_secure_allocator, get_allocator_stats, verify_heap_integrity};
pub use bounded::{BoundedMap, BoundedQueue, RateLimitedCounter};
pub use config::ScannerConfig;
pub use encrypted_strings::{EncryptedString, RuntimeEncrypted};
pub use logging::{init_logging, LogConfig, LogSampler, SamplerStats};
pub use mte::{init_mte, is_mte_active, is_mte_supported, MteError, MteMode};
pub use retry::{with_retry, with_retry_context, RetryConfig, RetryResult, RetryableError};
pub use secure_mem::{
    constant_time_eq, disable_core_dumps, secret_bytes_eq, SecretBytes, SecretVec,
};
pub use validation::{
    sanitize_filename, validate_sha256, ConfigValidator, PathValidator, ValidationError,
};

use std::path::Path;

/// High-level scanning interface that callers use to analyse a path.
///
/// Scanning is strictly read-only: callers receive a `ScanOutcome`
/// describing detections and recommended next steps. Escalations such as
/// quarantine must be carried out by the quarantine manager and require
/// explicit authorization from the initiating user.
pub struct Scanner {
    config: ScannerConfig,
}

impl Scanner {
    /// Construct a new scanner with the supplied configuration. The
    /// configuration is validated early so that feature-specific
    /// requirements (fanotify availability, NEON support, etc.) are surfaced
    /// before monitoring begins.
    pub fn new(config: ScannerConfig) -> anyhow::Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Perform a synchronous scan of the provided path.
    ///
    /// This method never mutates the target; it reads data using buffered
    /// I/O and returns heuristic scores and signature matches.
    pub async fn scan_path<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<ScanOutcome> {
        let context = engine::ScanContext::new(path.as_ref().to_path_buf());
        let result = engine::scan_path(&self.config, &context).await?;
        Ok(result)
    }
}

/// Result of a scan, containing structured metadata suitable for JSON
/// serialization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanOutcome {
    pub path: String,
    pub signatures: Vec<engine::SignatureMatch>,
    pub heuristic_score: heuristics::Score,
    pub entropy: engine::EntropyReport,
    pub recommended_action: RecommendedAction,
    pub mitre_tags: Vec<String>,
    pub ioc_hits: Vec<String>,
    pub yara_matches: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arm64_protection: Option<arm64_security::BinaryProtectionStatus>,
}

/// The scanner only *recommends* actions; mutating options are left to
/// higher-level components that enforce opt-in, reversible workflows.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum RecommendedAction {
    /// No malicious indicators were observed.
    Allow,
    /// Suspicious traits were observed; suggest monitoring.
    Monitor,
    /// High confidence detection; quarantine recommended but not automatic.
    Quarantine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Binary,
    JavaScript,
    Python,
    PowerShell,
    Bash,
    Archive,
    Document,
    Unknown,
}

impl FileType {
    pub fn from_path(path: &std::path::Path) -> Self {
        match path.extension().and_then(|e| e.to_str()) {
            Some("exe" | "dll" | "so" | "elf" | "bin") => Self::Binary,
            Some("js" | "mjs" | "cjs") => Self::JavaScript,
            Some("py" | "pyw" | "pyc") => Self::Python,
            Some("ps1" | "psm1" | "psd1") => Self::PowerShell,
            Some("sh" | "bash" | "zsh") => Self::Bash,
            Some("zip" | "rar" | "7z" | "tar" | "gz") => Self::Archive,
            Some("pdf" | "doc" | "docx" | "xls" | "xlsx") => Self::Document,
            _ => Self::Unknown,
        }
    }
}
