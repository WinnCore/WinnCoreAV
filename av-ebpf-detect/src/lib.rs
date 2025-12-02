//! eBPF rootkit detection.
//!
//! Enumerates loaded eBPF programs and compares them against a known-good
//! baseline to spot rootkits like TripleCross or BPFDoor.

pub mod analysis;
pub mod baseline;
pub mod enumerate;

pub use analysis::{analyze_bpf_programs, BpfAnalysisResult, HighRiskProgram, Severity};
pub use baseline::BpfBaseline;
pub use enumerate::{enumerate_bpf_programs, BpfProgInfo, BpfProgType};
