//! PAC (Pointer Authentication Code) failure monitoring.
//!
//! PAC cryptographically signs return addresses and data pointers.
//! On authentication failure, the pointer is corrupted, causing
//! a fault when used.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use tracing::warn;

static PAC_FAILURES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize)]
pub struct PacFailure {
    pub pid: u32,
    pub faulting_pc: u64,
    pub timestamp: u64,
}

/// Check if PAC is supported.
pub fn is_pac_supported() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        let hwcap = unsafe { libc::getauxval(libc::AT_HWCAP) };
        // Check for any PAC capability
        const HWCAP_PACA: u64 = 1 << 30;
        const HWCAP_PACG: u64 = 1 << 31;
        return hwcap & (HWCAP_PACA | HWCAP_PACG) != 0;
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

/// PAC failures manifest as crashes with specific PC patterns.
/// The upper bits of PC will be corrupted (non-canonical address).
pub fn is_pac_failure(faulting_pc: u64) -> bool {
    // PAC corruption sets upper bits (above VA space)
    // Valid addresses on ARM64 Linux are in:
    // - User: 0x0000_0000_0000_0000 to 0x0000_FFFF_FFFF_FFFF
    // - Kernel: 0xFFFF_0000_0000_0000 to 0xFFFF_FFFF_FFFF_FFFF

    let upper = faulting_pc >> 48;
    upper != 0x0000 && upper != 0xFFFF
}

pub fn record_pac_failure(failure: PacFailure) {
    PAC_FAILURES.fetch_add(1, Ordering::Relaxed);
    warn!(
        "PAC failure detected: pid={} pc=0x{:016x}",
        failure.pid, failure.faulting_pc
    );
}

pub fn get_pac_failure_count() -> u64 {
    PAC_FAILURES.load(Ordering::Relaxed)
}
