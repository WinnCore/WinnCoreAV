//! ARM64 hardware security feature monitoring.
//!
//! ARM64 provides hardware security features that x86 lacks:
//! - MTE (Memory Tagging Extension): Catches use-after-free, buffer overflow
//! - PAC (Pointer Authentication): Prevents ROP/JOP attacks
//! - BTI (Branch Target Identification): Prevents arbitrary code execution
//!
//! When these features detect an attack, they generate signals/faults
//! that we can monitor.

pub mod bti_monitor;
pub mod mte_monitor;
pub mod pac_monitor;
pub mod pmu;

pub use bti_monitor::{
    get_bti_violation_count, is_bti_supported, record_bti_violation, BranchType, BtiViolation,
};
pub use mte_monitor::{
    analyze_sigsegv, get_mte_stats, is_mte_supported, record_mte_violation, MteStats, MteViolation,
    MteViolationType,
};
pub use pac_monitor::{
    get_pac_failure_count, is_pac_failure, is_pac_supported, record_pac_failure, PacFailure,
};
pub use pmu::{is_pmu_available, sample_process, PmuSample};
