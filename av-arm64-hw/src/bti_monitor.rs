//! BTI (Branch Target Identification) violation monitoring.
//!
//! BTI prevents indirect branches to arbitrary code locations.
//! On violation, a Branch Target Exception is raised.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use tracing::warn;

static BTI_VIOLATIONS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize)]
pub struct BtiViolation {
    pub pid: u32,
    pub faulting_pc: u64,
    pub branch_type: BranchType,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum BranchType {
    Call, // BLR instruction
    Jump, // BR instruction
    Unknown,
}

/// Check if BTI is supported.
pub fn is_bti_supported() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        let hwcap2 = unsafe { libc::getauxval(libc::AT_HWCAP2) };
        const HWCAP2_BTI: u64 = 1 << 17;
        hwcap2 & HWCAP2_BTI != 0
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

/// BTI violations generate SIGILL with specific codes.
/// ILL_ILLOPC is used for BTI failures.
pub fn is_bti_violation(si_code: i32) -> bool {
    // BTI violations are reported as SIGILL with ILL_ILLOPC
    const ILL_ILLOPC: i32 = 1;
    si_code == ILL_ILLOPC
}

pub fn record_bti_violation(violation: BtiViolation) {
    BTI_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
    warn!(
        "BTI violation: pid={} pc=0x{:016x} type={:?}",
        violation.pid, violation.faulting_pc, violation.branch_type
    );
}

pub fn get_bti_violation_count() -> u64 {
    BTI_VIOLATIONS.load(Ordering::Relaxed)
}
