#![allow(dead_code, unused_imports)]
//! Binary integrity verification and anti-tampering.

use sha2::{Digest, Sha256};
use std::io::{BufReader, Read};
use std::sync::OnceLock;
use tracing::{error, info, warn};

static TEXT_HASH: OnceLock<[u8; 32]> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityStatus {
    Ok,
    MemoryTampered,
    DebuggerPresent,
    TracerPresent,
    VerificationFailed(String),
}

impl IntegrityStatus {
    pub fn is_tampered(&self) -> bool {
        !matches!(self, IntegrityStatus::Ok)
    }
}

#[cfg(target_os = "linux")]
const SELF_EXE: &str = "/proc/self/exe";
#[cfg(target_os = "macos")]
const SELF_EXE: &str = "";

pub fn hash_self_exe() -> Result<[u8; 32], std::io::Error> {
    #[cfg(target_os = "linux")]
    {
        let file = std::fs::File::open(SELF_EXE)?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        return Ok(hasher.finalize().into());
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Not implemented",
        ))
    }
}

pub fn init_integrity() -> Result<(), std::io::Error> {
    let hash = hash_self_exe()?;
    info!(
        hash_prefix = hex::encode(&hash[..4]),
        "Integrity baseline set"
    );
    TEXT_HASH
        .set(hash)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::AlreadyExists, "Already initialized"))
}

pub fn verify_binary_integrity() -> IntegrityStatus {
    let baseline = match TEXT_HASH.get() {
        Some(h) => h,
        None => return IntegrityStatus::VerificationFailed("Not initialized".into()),
    };
    match hash_self_exe() {
        Ok(cur) => {
            if cur != *baseline {
                IntegrityStatus::MemoryTampered
            } else {
                IntegrityStatus::Ok
            }
        }
        Err(e) => IntegrityStatus::VerificationFailed(e.to_string()),
    }
}

#[cfg(target_os = "linux")]
pub fn check_debugger() -> IntegrityStatus {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("TracerPid:") {
                let pid: i32 = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                if pid != 0 {
                    warn!(tracer_pid = pid, "Tracer detected");
                    return IntegrityStatus::TracerPresent;
                }
            }
        }
    }
    IntegrityStatus::Ok
}

#[cfg(not(target_os = "linux"))]
pub fn check_debugger() -> IntegrityStatus {
    IntegrityStatus::Ok
}

pub fn full_integrity_check() -> IntegrityStatus {
    let dbg = check_debugger();
    if dbg.is_tampered() {
        return dbg;
    }
    verify_binary_integrity()
}

pub enum TamperResponse {
    LogOnly,
    Shutdown,
    Abort,
}

pub fn handle_violation(status: IntegrityStatus, response: TamperResponse) {
    match response {
        TamperResponse::LogOnly => {
            error!(status = ?status, "Integrity violation detected");
        }
        TamperResponse::Shutdown => {
            error!(status = ?status, "Integrity violation - shutting down");
            std::process::exit(1);
        }
        TamperResponse::Abort => {
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_self_ok() {
        let _ = hash_self_exe();
    }
}
