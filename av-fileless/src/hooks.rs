//! Hooks for fileless execution primitives.
//!
//! This module is a placeholder for syscall hooks (memfd_create, fexecve, etc.)
//! that would typically be implemented with eBPF or ptrace. For now, it just
//! exposes the function names so callers can gate on platform support.

/// Whether runtime hooks are available (stub for now).
pub fn hooks_available() -> bool {
    false
}
