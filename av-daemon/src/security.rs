#![allow(dead_code)]
#![allow(unused_variables)]
//! Sandboxing helpers for AppArmor, seccomp-bpf, and Landlock.
//!
//! Runtime behaviour is feature-detected. The daemon remains functional in
//! audit-only mode if any mechanism is unavailable, preserving the hard
//! requirement for graceful degradation on Ubuntu 25.10 pre-release builds.

use tracing::warn;

pub fn install_seccomp_filter() {
    #[cfg(feature = "landlock_confine")]
    {
        warn!("Landlock confinement requested but not yet wired - placeholder");
    }
    warn!("Seccomp filter installation is a stub in the scaffold");
}

pub fn load_apparmor_profile() {
    warn!("AppArmor profile loading is deferred to systemd unit postinst");
}
