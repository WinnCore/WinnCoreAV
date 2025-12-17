//! Fileless malware detection.
//!
//! Linux fileless techniques:
//! 1. memfd_create() + fexecve(): Execute from anonymous memory
//! 2. /dev/shm execution: tmpfs-based execution
//! 3. execve(/proc/self/fd/N): Execute from fd
//! 4. ptrace injection: Inject into running process
//!
//! Tools using these techniques:
//! - fireELF, Ezuri, Pupy RAT, THC Bincrypter
//!
//! Detection:
//! - Hook memfd_create() syscall
//! - Scan `/proc/\[pid\]/exe` for "memfd:" or "(deleted)"
//! - Monitor /dev/shm for executables
//! - Track fexecve() calls

pub mod hooks;
pub mod scanner;

pub use scanner::{check_process, scan_devshm, scan_for_fileless, FilelessProcess, FilelessType};
