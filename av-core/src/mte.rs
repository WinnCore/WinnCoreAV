//! ARM64 Memory Tagging Extension (MTE) support.
//!
//! MTE adds a 4-bit tag to every 16-byte granule and checks tags on access.
//! This catches use-after-free and some overflow classes on supported ARMv8.5+
//! hardware (e.g., Graviton3/4, Snapdragon X). Apple Silicon does not expose
//! MTE. On unsupported platforms these APIs are safe no-ops.

use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info, warn};

static MTE_ENABLED: AtomicBool = AtomicBool::new(false);

/// MTE operating modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MteMode {
    Disabled,
    Sync,
    Async,
    Asymm,
}

/// MTE-related errors.
#[derive(Debug, Clone)]
pub enum MteError {
    NotSupported,
    EnableFailed(String),
    TaggingFailed(String),
}

impl std::fmt::Display for MteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MteError::NotSupported => write!(f, "MTE not supported on this platform"),
            MteError::EnableFailed(e) => write!(f, "Failed to enable MTE: {}", e),
            MteError::TaggingFailed(e) => write!(f, "Tagging operation failed: {}", e),
        }
    }
}

impl std::error::Error for MteError {}

/// Check if MTE is supported (ARM64 Linux only).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
pub fn is_mte_supported() -> bool {
    const HWCAP2_MTE: u64 = 1 << 18;
    let hwcap2 = unsafe { libc::getauxval(libc::AT_HWCAP2) };
    if hwcap2 & HWCAP2_MTE != 0 {
        debug!("MTE supported (HWCAP2)");
        return true;
    }
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        if cpuinfo.contains("mte") {
            debug!("MTE supported (cpuinfo)");
            return true;
        }
    }
    debug!("MTE not supported");
    false
}

#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
pub fn is_mte_supported() -> bool {
    false
}

/// Enable MTE for the current thread.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
pub fn enable_mte(mode: MteMode) -> Result<MteMode, MteError> {
    use libc::{prctl, PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE};

    if !is_mte_supported() {
        return Err(MteError::NotSupported);
    }
    if mode == MteMode::Disabled {
        return Ok(MteMode::Disabled);
    }

    // Constants from linux/uapi/prctl.h
    const PR_MTE_TCF_SHIFT: u64 = 1;
    const PR_MTE_TCF_NONE: u64 = 0 << PR_MTE_TCF_SHIFT;
    const PR_MTE_TCF_SYNC: u64 = 1 << PR_MTE_TCF_SHIFT;
    const PR_MTE_TCF_ASYNC: u64 = 2 << PR_MTE_TCF_SHIFT;
    const PR_MTE_TAG_SHIFT: u64 = 3;

    let tag_mask: u64 = 0xfffe << PR_MTE_TAG_SHIFT; // enable tags 1-15
    let tcf_mode = match mode {
        MteMode::Disabled => PR_MTE_TCF_NONE,
        MteMode::Sync => PR_MTE_TCF_SYNC,
        MteMode::Async => PR_MTE_TCF_ASYNC,
        MteMode::Asymm => PR_MTE_TCF_SYNC | PR_MTE_TCF_ASYNC,
    };

    let flags = PR_TAGGED_ADDR_ENABLE | tcf_mode | tag_mask;
    let result = unsafe { prctl(PR_SET_TAGGED_ADDR_CTRL, flags, 0, 0, 0) };
    if result == 0 {
        MTE_ENABLED.store(true, Ordering::SeqCst);
        info!(mode = ?mode, "MTE enabled");
        Ok(mode)
    } else {
        let err = std::io::Error::last_os_error();
        warn!(error = %err, "Failed to enable MTE");
        Err(MteError::EnableFailed(err.to_string()))
    }
}

#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
pub fn enable_mte(_mode: MteMode) -> Result<MteMode, MteError> {
    Err(MteError::NotSupported)
}

/// Check if MTE is active.
pub fn is_mte_active() -> bool {
    MTE_ENABLED.load(Ordering::SeqCst)
}

/// Get a random tag (1-15). Falls back to software RNG if MTE inactive.
#[cfg(all(target_arch = "aarch64", target_os = "linux", target_feature = "mte"))]
#[inline]
pub fn get_random_tag() -> u8 {
    if !is_mte_active() {
        return (rand::random::<u8>() & 0x0F).max(1);
    }
    let tag: u64;
    unsafe {
        std::arch::asm!(
            "irg {0}, {0}",
            inout(reg) 0u64 => tag,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((tag >> 56) & 0x0F) as u8
}

#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
#[inline]
pub fn get_random_tag() -> u8 {
    (rand::random::<u8>() & 0x0F).max(1)
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    not(target_feature = "mte")
))]
#[inline]
pub fn get_random_tag() -> u8 {
    (rand::random::<u8>() & 0x0F).max(1)
}

/// Tag a 16-byte aligned region. No-op if MTE inactive or unsupported.
#[cfg(all(target_arch = "aarch64", target_os = "linux", target_feature = "mte"))]
pub unsafe fn tag_memory(ptr: *mut u8, len: usize, tag: u8) -> Result<(), MteError> {
    if !is_mte_active() {
        return Ok(());
    }
    if ptr as usize % 16 != 0 {
        return Err(MteError::TaggingFailed(
            "Pointer not 16-byte aligned".into(),
        ));
    }
    if len % 16 != 0 {
        return Err(MteError::TaggingFailed("Length not 16-byte aligned".into()));
    }

    let tagged_ptr = (ptr as u64) | ((tag as u64 & 0x0F) << 56);
    for offset in (0..len).step_by(16) {
        let addr = tagged_ptr + offset as u64;
        std::arch::asm!(
            "stg {0}, [{0}]",
            in(reg) addr,
            options(nostack, preserves_flags)
        );
    }
    Ok(())
}

#[cfg(any(
    not(all(target_arch = "aarch64", target_os = "linux")),
    not(target_feature = "mte")
))]
/// Tag a memory region with the provided tag.
///
/// On targets without hardware MTE support, this is a no-op.
///
/// # Safety
///
/// Callers must ensure `_ptr` is valid for `_len` bytes and meets any alignment
/// requirements when running on MTE-capable platforms.
pub unsafe fn tag_memory(_ptr: *mut u8, _len: usize, _tag: u8) -> Result<(), MteError> {
    Ok(())
}

#[inline]
pub fn tag_pointer<T>(ptr: *mut T, tag: u8) -> *mut T {
    let addr = ptr as u64;
    let tagged = (addr & 0x00FF_FFFF_FFFF_FFFF) | ((tag as u64 & 0x0F) << 56);
    tagged as *mut T
}

#[inline]
pub fn get_pointer_tag<T>(ptr: *const T) -> u8 {
    ((ptr as u64 >> 56) & 0x0F) as u8
}

#[inline]
pub fn untag_pointer<T>(ptr: *mut T) -> *mut T {
    let addr = ptr as u64 & 0x00FF_FFFF_FFFF_FFFF;
    addr as *mut T
}

/// Initialize MTE with a best-effort mode.
pub fn init_mte() -> Result<MteMode, MteError> {
    if !is_mte_supported() {
        return Ok(MteMode::Disabled);
    }
    match enable_mte(MteMode::Sync) {
        Ok(mode) => Ok(mode),
        Err(e) => {
            warn!("Sync MTE failed, trying async: {}", e);
            enable_mte(MteMode::Async).or(Ok(MteMode::Disabled))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pointer_tagging_roundtrip() {
        let v: u64 = 0xABCD;
        let ptr = &v as *const u64 as *mut u64;
        let tagged = tag_pointer(ptr, 0x0A);
        assert_eq!(get_pointer_tag(tagged), 0x0A);
        assert_eq!(untag_pointer(tagged), ptr);
    }

    #[test]
    fn test_random_tag_range() {
        for _ in 0..100 {
            let tag = get_random_tag();
            assert!(tag > 0 && tag <= 0x0F);
        }
    }
}
