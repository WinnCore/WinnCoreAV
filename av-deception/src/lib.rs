//! Deception technology: canary files and honeypots.
//!
//! Canary files provide near-zero false-positive detection for intrusions.

pub mod canary;
pub mod generator;
pub mod monitor;

pub use canary::{default_canary_locations, Canary, CanarySeverity, CanaryType};
pub use generator::{deploy_default_canaries, generate_canary};
pub use monitor::{CanaryAlert, CanaryEventType, CanaryMonitor};
