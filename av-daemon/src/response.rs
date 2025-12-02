// Threat response actions
// Automated response to detected threats

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{error, info, warn};

/// Response action types
#[derive(Debug, Clone, PartialEq)]
pub enum ResponseAction {
    Log,        // Just log the alert
    Alert,      // Alert + notification
    Kill,       // Terminate the process
    Quarantine, // Move file to quarantine
    Block,      // Block network access
}

/// Configuration for response engine
pub struct ResponseConfig {
    pub enabled: bool,
    pub auto_kill_critical: bool,
    pub auto_quarantine: bool,
    pub quarantine_dir: PathBuf,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_kill_critical: false, // Safe default
            auto_quarantine: false,    // Safe default
            quarantine_dir: PathBuf::from("/var/lib/winncore/quarantine"),
        }
    }
}

/// Response engine for automated threat response
pub struct ResponseEngine {
    config: ResponseConfig,
}

impl ResponseEngine {
    pub fn new(config: ResponseConfig) -> Self {
        Self { config }
    }

    /// Determine appropriate response based on severity
    pub fn determine_response(&self, severity: &str) -> ResponseAction {
        match severity.to_lowercase().as_str() {
            "critical" => {
                if self.config.auto_kill_critical {
                    ResponseAction::Kill
                } else {
                    ResponseAction::Alert
                }
            }
            "high" => ResponseAction::Alert,
            "medium" => ResponseAction::Log,
            "low" => ResponseAction::Log,
            _ => ResponseAction::Log,
        }
    }

    /// Kill a process by PID
    pub fn kill_process(&self, pid: u32) -> Result<(), String> {
        if !self.config.enabled {
            info!("Response disabled - would kill pid {}", pid);
            return Ok(());
        }

        warn!("Killing malicious process: pid={}", pid);

        // Try graceful termination first
        let term_result = Command::new("kill")
            .args(["-15", &pid.to_string()])
            .output();

        if let Ok(output) = term_result {
            if output.status.success() {
                info!("Process {} terminated with SIGTERM", pid);
                return Ok(());
            }
        }

        // Force kill
        let kill_result = Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output()
            .map_err(|e| format!("Failed to kill: {}", e))?;

        if kill_result.status.success() {
            info!("Process {} killed with SIGKILL", pid);
            Ok(())
        } else {
            Err(format!("Failed to kill pid {}", pid))
        }
    }

    /// Quarantine a suspicious file
    pub fn quarantine_file(&self, path: &Path) -> Result<PathBuf, String> {
        if !self.config.enabled || !self.config.auto_quarantine {
            info!("Would quarantine: {:?}", path);
            return Ok(PathBuf::new());
        }

        if !path.exists() {
            return Err("File does not exist".to_string());
        }

        // Ensure quarantine directory exists
        fs::create_dir_all(&self.config.quarantine_dir)
            .map_err(|e| format!("Failed to create quarantine dir: {}", e))?;

        // Generate quarantine path
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let quarantine_name = format!("{}_{}.quarantine", timestamp, filename);
        let quarantine_path = self.config.quarantine_dir.join(quarantine_name);

        // Move file
        fs::rename(path, &quarantine_path).map_err(|e| format!("Failed to quarantine: {}", e))?;

        warn!("Quarantined {:?} -> {:?}", path, quarantine_path);
        Ok(quarantine_path)
    }

    /// Execute response for an alert
    pub fn respond(&self, severity: &str, pid: u32, exe_path: Option<&Path>) {
        let action = self.determine_response(severity);

        match action {
            ResponseAction::Kill => {
                if let Err(e) = self.kill_process(pid) {
                    error!("Kill failed: {}", e);
                }
                if let Some(path) = exe_path {
                    let _ = self.quarantine_file(path);
                }
            }
            ResponseAction::Quarantine => {
                if let Some(path) = exe_path {
                    let _ = self.quarantine_file(path);
                }
            }
            ResponseAction::Alert => {
                warn!("ALERT: Critical threat detected - pid={}", pid);
            }
            ResponseAction::Block => {
                info!("Network block requested for pid={}", pid);
                // Network blocking would require iptables/nftables
            }
            ResponseAction::Log => {
                info!("Threat logged: pid={}", pid);
            }
        }
    }

    /// Enable/disable auto-kill for critical threats
    pub fn set_auto_kill(&mut self, enabled: bool) {
        self.config.auto_kill_critical = enabled;
        info!("Auto-kill critical: {}", enabled);
    }
}

impl Default for ResponseEngine {
    fn default() -> Self {
        Self::new(ResponseConfig::default())
    }
}
