//! Behavioral detection engine for WinnCore.
//!
//! This crate provides:
//! - YAML-based detection rules with MITRE ATT&CK mappings
//! - Event correlation to chain related events into attack narratives
//! - Process tree tracking for parent-child analysis
//! - Real-time alerting based on rule matches

pub mod alerts;
pub mod correlation;
pub mod process_tree;
pub mod rules;

pub use alerts::{Alert, AlertSeverity};
pub use correlation::{AttackChain, CorrelationEngine};
pub use process_tree::{ProcessInfo, ProcessTree};
pub use rules::{Rule, RuleEngine, RuleMatch, Severity};
