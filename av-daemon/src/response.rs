//! Threat response actions - quarantine, kill, alert

use crate::config::ResponseConfig;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{error, info, warn};

#[derive(Debug, Clone, PartialEq)]
pub enum ResponseAction {
    Log,
    Alert,
    Kill,
    Quarantine,
}

/// Paths that should never be quarantined (build tools, system binaries)
const EXCLUDED_PATHS: &[&str] = &[
    "cargo",
    "rustc",
    "rustup",
    "build-script",
    "cc",
    "ld",
    "/usr/bin",
    "/usr/lib",
    "/.cargo/",
    "/.rustup/",
    "/proc/",
];

pub struct ResponseEngine {
    config: ResponseConfig,
}

impl ResponseEngine {
    pub fn new(config: ResponseConfig) -> Self {
        info!(
            enabled = config.enabled,
            auto_quarantine = config.auto_quarantine,
            auto_kill = config.auto_kill_critical,
            quarantine_dir = %config.quarantine_dir.display(),
            "ResponseEngine initialized"
        );
        Self { config }
    }

    pub fn determine_response(&self, severity: &str) -> ResponseAction {
        if !self.config.enabled {
            return ResponseAction::Log;
        }

        match severity.to_lowercase().as_str() {
            "critical" => {
                if self.config.auto_kill_critical {
                    ResponseAction::Kill
                } else {
                    ResponseAction::Alert
                }
            }
            "high" => {
                if self.config.auto_quarantine {
                    ResponseAction::Quarantine
                } else {
                    ResponseAction::Alert
                }
            }
            "medium" => ResponseAction::Alert,
            "low" => ResponseAction::Log,
            _ => ResponseAction::Log,
        }
    }

    pub fn kill_process(&self, pid: u32) -> Result<(), String> {
        if !self.config.enabled {
            info!(pid = pid, "Response disabled - would kill");
            return Ok(());
        }

        if pid <= 1 {
            return Err("Refusing to kill PID 0 or 1".to_string());
        }

        warn!(pid = pid, "KILLING malicious process");

        // SIGTERM first
        let _ = Command::new("kill")
            .args(["-15", &pid.to_string()])
            .output();
        std::thread::sleep(std::time::Duration::from_millis(100));

        // SIGKILL if still alive
        match Command::new("kill").args(["-9", &pid.to_string()]).output() {
            Ok(output) if output.status.success() => {
                info!(pid = pid, "Process killed");
                Ok(())
            }
            _ => Err(format!("Failed to kill pid {}", pid)),
        }
    }

    pub fn quarantine_file(&self, path: &Path) -> Result<PathBuf, String> {
        if !self.config.enabled {
            info!(path = %path.display(), "Response disabled - would quarantine");
            return Ok(PathBuf::new());
        }

        if !self.config.auto_quarantine {
            info!(path = %path.display(), "Auto-quarantine disabled - skipping");
            return Ok(PathBuf::new());
        }

        if is_excluded_quarantine_path(path) {
            info!(path = %path.display(), "Skipping quarantine for excluded path");
            return Ok(PathBuf::new());
        }

        if !path.exists() {
            return Err(format!("File not found: {}", path.display()));
        }

        // Create quarantine dir
        fs::create_dir_all(&self.config.quarantine_dir)
            .map_err(|e| format!("Failed to create quarantine dir: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(
                &self.config.quarantine_dir,
                fs::Permissions::from_mode(0o700),
            );
        }

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let quarantine_name = format!("{}_{}.quarantine", timestamp, filename);
        let quarantine_path = self.config.quarantine_dir.join(&quarantine_name);

        fs::rename(path, &quarantine_path).map_err(|e| format!("Quarantine failed: {}", e))?;

        warn!(
            original = %path.display(),
            quarantined = %quarantine_path.display(),
            "FILE QUARANTINED"
        );

        Ok(quarantine_path)
    }

    pub fn respond(&self, severity: &str, pid: u32, exe_path: Option<&Path>) {
        let action = self.determine_response(severity);

        info!(
            severity = severity,
            pid = pid,
            action = ?action,
            exe = exe_path.map(|p| p.display().to_string()).unwrap_or_default(),
            "Response action triggered"
        );

        match action {
            ResponseAction::Kill => {
                if let Err(e) = self.kill_process(pid) {
                    error!(error = %e, "Kill failed");
                }
                if let Some(path) = exe_path {
                    let _ = self.quarantine_file(path);
                }
            }
            ResponseAction::Quarantine => {
                if let Some(path) = exe_path {
                    if let Err(e) = self.quarantine_file(path) {
                        error!(error = %e, "Quarantine failed");
                    }
                } else {
                    // Try to get exe path from /proc
                    let exe_link = format!("/proc/{}/exe", pid);
                    if let Ok(real_path) = std::fs::read_link(&exe_link) {
                        if let Err(e) = self.quarantine_file(&real_path) {
                            error!(error = %e, "Quarantine from /proc failed");
                        }
                    } else {
                        warn!(pid = pid, "Cannot quarantine - no exe path available");
                    }
                }
            }
            ResponseAction::Alert => {
                warn!(
                    severity = severity,
                    pid = pid,
                    "🚨 ALERT: Threat requires attention"
                );
            }
            ResponseAction::Log => {
                info!(pid = pid, severity = severity, "Threat logged");
            }
        }
    }
}

impl Default for ResponseEngine {
    fn default() -> Self {
        Self::new(ResponseConfig::default())
    }
}

fn is_excluded_quarantine_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    if EXCLUDED_PATHS.iter().any(|p| path_str.contains(p)) {
        return true;
    }

    match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => EXCLUDED_PATHS.contains(&name),
        None => false,
    }
}
