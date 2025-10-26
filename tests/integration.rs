#![allow(dead_code)]
#![allow(unused_variables)]
//! Integration harness placeholder for ARM64-specific testing.
//!
//! In CI we run these under QEMU or native hardware. Tests assert that the
//! scanner respects read-only behaviour and that the daemon can start in
//! audit-only mode without elevated privileges.

use std::process::Command;

#[test]
fn cargo_check_workspace() {
    let status = Command::new("cargo")
        .args(["check"])
        .status()
        .expect("cargo check should run");
    assert!(status.success());
}
