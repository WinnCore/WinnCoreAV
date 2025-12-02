//! Rootkit and kernel tampering detection stubs.

pub mod filesystem;
pub mod modules;
pub mod network;
pub mod process;

pub use filesystem::{check_common_hiding_spots, scan_hidden_files};
pub use modules::{scan_kernel_modules, KernelModuleResult};
pub use network::{scan_hidden_connections, HiddenConnectionResult, NetworkConnection};
pub use process::{scan_hidden_processes, HiddenProcessResult, SuspiciousPid};
