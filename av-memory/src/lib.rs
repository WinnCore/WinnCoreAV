//! Memory scanning primitives for spotting fileless threats.

pub mod anomaly;
pub mod patterns;
pub mod scanner;

pub use anomaly::{AnomalySeverity, MemoryAnomaly};
pub use patterns::ShellcodePatterns;
pub use scanner::{
    MemoryRegion, MemoryScanResult, MemoryScanner, MemoryThreat, MemoryThreatType, ThreatSeverity,
};
