//! Tamper detection helpers (detection only, not prevention).
//!
//! Honest limitations:
//! - Attackers with root can bypass these checks.
//! - Hash baselines can be poisoned before startup.
//! - Alerts indicate tampering after it occurred.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct ProtectedResources {
    pub protected_processes: HashSet<String>,
    pub protected_files: HashSet<PathBuf>,
    pub protected_dirs: HashSet<PathBuf>,
}

impl Default for ProtectedResources {
    fn default() -> Self {
        let mut processes = HashSet::new();
        processes.insert("av-daemon".to_string());
        processes.insert("av-ebpf-loader".to_string());
        processes.insert("av-watchdog".to_string());

        let mut files = HashSet::new();
        files.insert(PathBuf::from("/etc/winncore/config.toml"));
        files.insert(PathBuf::from("/usr/lib/winncore/av-daemon"));
        files.insert(PathBuf::from("/usr/lib/winncore/av-ebpf-loader"));

        let mut dirs = HashSet::new();
        dirs.insert(PathBuf::from("/etc/winncore"));
        dirs.insert(PathBuf::from("/var/lib/winncore"));
        dirs.insert(PathBuf::from("/sys/fs/bpf/winncore"));

        Self {
            protected_processes: processes,
            protected_files: files,
            protected_dirs: dirs,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SelfProtectionAlert {
    pub alert_type: SelfProtectionAlertType,
    pub actor_pid: u32,
    pub actor_comm: String,
    pub actor_uid: u32,
    pub target: String,
}

#[derive(Debug, Clone)]
pub enum SelfProtectionAlertType {
    ProcessKillAttempt,
    ConfigModification,
    BinaryModification,
    BpfMapAccess,
}

/// Self-protection monitor.
pub struct SelfProtection {
    resources: Arc<RwLock<ProtectedResources>>,
    alert_callback: Box<dyn Fn(SelfProtectionAlert) + Send + Sync>,
}

impl SelfProtection {
    pub fn new<F>(alert_callback: F) -> Self
    where
        F: Fn(SelfProtectionAlert) + Send + Sync + 'static,
    {
        Self {
            resources: Arc::new(RwLock::new(ProtectedResources::default())),
            alert_callback: Box::new(alert_callback),
        }
    }

    pub async fn check_process_kill(&self, target_comm: &str, actor_pid: u32, actor_uid: u32) {
        let resources = self.resources.read().await;
        if resources.protected_processes.contains(target_comm) {
            let actor_comm = get_process_comm(actor_pid).unwrap_or_default();
            warn!(
                actor_pid,
                actor_comm, target_comm, "Self-protection: attempted kill of protected process"
            );
            (self.alert_callback)(SelfProtectionAlert {
                alert_type: SelfProtectionAlertType::ProcessKillAttempt,
                actor_pid,
                actor_comm,
                actor_uid,
                target: target_comm.to_string(),
            });
        }
    }

    pub async fn check_file_modification(
        &self,
        path: &std::path::Path,
        actor_pid: u32,
        actor_uid: u32,
    ) {
        let resources = self.resources.read().await;
        let is_protected = resources.protected_files.contains(path)
            || resources.protected_dirs.iter().any(|d| path.starts_with(d));

        if is_protected {
            let actor_comm = get_process_comm(actor_pid).unwrap_or_default();
            if actor_uid == 0 && is_legitimate_updater(&actor_comm) {
                info!(
                    actor = %actor_comm,
                    path = %path.display(),
                    "Legitimate update to protected file"
                );
                return;
            }

            warn!(
                actor_pid,
                actor_comm,
                path = %path.display(),
                "Self-protection: protected file touched"
            );

            (self.alert_callback)(SelfProtectionAlert {
                alert_type: SelfProtectionAlertType::ConfigModification,
                actor_pid,
                actor_comm,
                actor_uid,
                target: path.display().to_string(),
            });
        }
    }

    /// Verify on-disk hashes of key binaries.
    pub async fn verify_binary_integrity(&self) -> Result<(), Vec<String>> {
        let mut failures = Vec::new();
        let binaries = [
            "/usr/lib/winncore/av-daemon",
            "/usr/lib/winncore/av-ebpf-loader",
            "/usr/lib/winncore/av-watchdog",
        ];

        for binary in binaries {
            if let Err(e) = verify_file_hash(binary) {
                failures.push(format!("{}: {}", binary, e));
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures)
        }
    }

    pub async fn verify_bpf_maps(&self) -> Result<(), String> {
        let maps = ["events", "config", "stats"];
        for map in maps {
            let path = format!("/sys/fs/bpf/winncore/{}", map);
            if !std::path::Path::new(&path).exists() {
                return Err(format!("BPF map {} missing or unpinned", map));
            }
        }
        Ok(())
    }
}

fn is_legitimate_updater(comm: &str) -> bool {
    const LEGITIMATE: &[&str] = &["apt", "apt-get", "dpkg", "rpm", "yum", "dnf", "systemctl"];
    LEGITIMATE.contains(&comm)
}

fn get_process_comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}

fn verify_file_hash(path: &str) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let hash_path = format!(
        "/var/lib/winncore/hashes/{}.sha256",
        std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
    );

    let stored_hash = std::fs::read_to_string(&hash_path)
        .map_err(|e| format!("Cannot read stored hash: {}", e))?
        .trim()
        .to_string();

    let mut file = std::fs::File::open(path).map_err(|e| format!("Cannot open binary: {}", e))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| format!("Cannot read binary: {}", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    let current_hash = format!("{:x}", hasher.finalize());

    if current_hash != stored_hash {
        Err(format!(
            "Hash mismatch: expected {}, got {}",
            stored_hash, current_hash
        ))
    } else {
        Ok(())
    }
}
