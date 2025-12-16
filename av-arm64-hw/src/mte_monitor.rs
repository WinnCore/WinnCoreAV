//! MTE (Memory Tagging Extension) violation monitoring.
//!
//! MTE assigns 4-bit tags to memory and pointers. On mismatch:
//! - Sync mode: SIGSEGV with si_code SEGV_MTESERR (exact address)
//! - Async mode: SIGSEGV with si_code SEGV_MTEAERR (no address)

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use tracing::warn;

// Signal codes for MTE violations
const SEGV_MTESERR: i32 = 9; // Sync MTE error
const SEGV_MTEAERR: i32 = 10; // Async MTE error

static MTE_SYNC_VIOLATIONS: AtomicU64 = AtomicU64::new(0);
static MTE_ASYNC_VIOLATIONS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize)]
pub struct MteViolation {
    pub pid: u32,
    pub tid: u32,
    pub violation_type: MteViolationType,
    pub fault_address: Option<u64>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum MteViolationType {
    /// Synchronous: exact fault address known
    Sync,
    /// Asynchronous: address unknown (deferred reporting)
    Async,
}

/// Check if MTE is supported on this system.
pub fn is_mte_supported() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        // Check HWCAP2 for MTE support
        let hwcap2 = unsafe { libc::getauxval(libc::AT_HWCAP2) };
        const HWCAP2_MTE: u64 = 1 << 18;
        hwcap2 & HWCAP2_MTE != 0
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

/// Get MTE violation statistics.
pub fn get_mte_stats() -> MteStats {
    MteStats {
        sync_violations: MTE_SYNC_VIOLATIONS.load(Ordering::Relaxed),
        async_violations: MTE_ASYNC_VIOLATIONS.load(Ordering::Relaxed),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MteStats {
    pub sync_violations: u64,
    pub async_violations: u64,
}

/// Record an MTE violation (called from signal handler or ptrace).
pub fn record_mte_violation(violation: MteViolation) {
    match violation.violation_type {
        MteViolationType::Sync => {
            MTE_SYNC_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
            warn!(
                "MTE sync violation: pid={} addr={:?}",
                violation.pid, violation.fault_address
            );
        }
        MteViolationType::Async => {
            MTE_ASYNC_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
            warn!("MTE async violation: pid={}", violation.pid);
        }
    }
}

/// Analyze a SIGSEGV to check if it's an MTE violation.
pub fn analyze_sigsegv(si_code: i32, _si_addr: u64) -> Option<MteViolationType> {
    match si_code {
        SEGV_MTESERR => Some(MteViolationType::Sync),
        SEGV_MTEAERR => Some(MteViolationType::Async),
        _ => None,
    }
}
