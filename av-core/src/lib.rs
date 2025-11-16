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

pub mod behavioral;
pub mod behavioral_score;
pub mod config;
pub mod engine;
pub mod fileless;
pub mod heuristics;
pub mod monitoring;
pub mod network_monitor;
pub mod process_tree;
pub mod response;
pub mod signatures;
pub mod telemetry;

pub use behavioral::{BehavioralMonitor, EventSummary, LotlEvent, LotlEventType};
pub use behavioral_score::{BehavioralScore, BehavioralScoringEngine, ComponentScores, RiskLevel};
pub use config::ScannerConfig;
pub use fileless::{FilelessDetector, FilelessEvent, FilelessStats, FilelessTechnique};
pub use network_monitor::{NetworkEvent, NetworkEventType, NetworkMonitor, NetworkStats};
pub use process_tree::{ProcessTree, ProcessRelationship, analyze_relationship, build_process_tree};
pub use response::{ResponseAction, ResponseEngine, ResponseResult};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavioral_summary: Option<EventSummary>,
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
