//! Stack trace validation for detecting direct syscalls.
//!
//! When malware makes inline syscalls, the return address will point into
//! attacker code rather than libc. This crate helps validate syscall return
//! addresses given the process map layout.

pub mod maps;
pub mod validator;

pub use maps::{find_region, parse_maps, MemoryRegion};
pub use validator::{
    scan_for_direct_syscalls, DirectSyscallProcess, RegionInfo, SyscallValidator, ValidationResult,
};
