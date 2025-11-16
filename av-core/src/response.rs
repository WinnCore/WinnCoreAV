//! Real-time response actions for threat mitigation
//!
//! This module provides automated and manual response capabilities including:
//! - Process termination (kill suspicious processes)
//! - Network blocking (isolate malicious processes)
//! - File quarantine (move malicious files to secure storage)
//! - Alert generation (notify administrators)

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResponseAction {
    /// Kill a process by PID
    KillProcess,
    /// Block all network access for a process
    BlockNetwork,
    /// Quarantine a file
    QuarantineFile,
    /// Generate alert only (no automated action)
    Alert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseResult {
    pub action: ResponseAction,
    pub success: bool,
    pub details: String,
    pub timestamp: u64,
}

/// Response engine for automated threat mitigation
pub struct ResponseEngine {
    /// Whether automated responses are enabled
    auto_respond: bool,
    /// Minimum risk score to trigger automated response (0.0-1.0)
    auto_respond_threshold: f32,
}

impl ResponseEngine {
    /// Create new response engine with automated responses disabled
    pub fn new() -> Self {
        Self {
            auto_respond: false,
            auto_respond_threshold: 0.85, // Only auto-respond to high/critical threats
        }
    }

    /// Create response engine with automated responses enabled
    pub fn with_auto_respond(threshold: f32) -> Self {
        Self {
            auto_respond: true,
            auto_respond_threshold: threshold.clamp(0.0, 1.0),
        }
    }

    /// Enable automated responses
    pub fn enable_auto_respond(&mut self, threshold: f32) {
        self.auto_respond = true;
        self.auto_respond_threshold = threshold.clamp(0.0, 1.0);
    }

    /// Disable automated responses
    pub fn disable_auto_respond(&mut self) {
        self.auto_respond = false;
    }

    /// Determine if automated response should be triggered
    pub fn should_auto_respond(&self, threat_score: f32) -> bool {
        self.auto_respond && threat_score >= self.auto_respond_threshold
    }

    /// Kill a suspicious process
    pub fn kill_process(&self, pid: u32, reason: &str) -> ResponseResult {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if process exists
        if !process_exists(pid) {
            return ResponseResult {
                action: ResponseAction::KillProcess,
                success: false,
                details: format!("Process {} does not exist", pid),
                timestamp,
            };
        }

        // Attempt to kill process with SIGTERM first
        let result = Command::new("kill")
            .arg("-15") // SIGTERM
            .arg(pid.to_string())
            .output();

        let success = match result {
            Ok(output) => output.status.success(),
            Err(e) => {
                return ResponseResult {
                    action: ResponseAction::KillProcess,
                    success: false,
                    details: format!("Failed to kill process {}: {}", pid, e),
                    timestamp,
                };
            }
        };

        if success {
            // Wait briefly and check if process is gone
            std::thread::sleep(std::time::Duration::from_millis(100));

            if process_exists(pid) {
                // Still alive, try SIGKILL
                let kill_result = Command::new("kill")
                    .arg("-9") // SIGKILL
                    .arg(pid.to_string())
                    .output();

                match kill_result {
                    Ok(output) if output.status.success() => ResponseResult {
                        action: ResponseAction::KillProcess,
                        success: true,
                        details: format!("Killed process {} (SIGKILL). Reason: {}", pid, reason),
                        timestamp,
                    },
                    _ => ResponseResult {
                        action: ResponseAction::KillProcess,
                        success: false,
                        details: format!("Failed to force kill process {}", pid),
                        timestamp,
                    },
                }
            } else {
                ResponseResult {
                    action: ResponseAction::KillProcess,
                    success: true,
                    details: format!("Killed process {} (SIGTERM). Reason: {}", pid, reason),
                    timestamp,
                }
            }
        } else {
            ResponseResult {
                action: ResponseAction::KillProcess,
                success: false,
                details: format!("Failed to kill process {}: insufficient permissions", pid),
                timestamp,
            }
        }
    }

    /// Block network access for a process using iptables owner match
    pub fn block_network(&self, pid: u32, comm: &str) -> ResponseResult {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if !process_exists(pid) {
            return ResponseResult {
                action: ResponseAction::BlockNetwork,
                success: false,
                details: format!("Process {} does not exist", pid),
                timestamp,
            };
        }

        // Get UID of process to use owner matching (more reliable than PID)
        let uid = match get_process_uid(pid) {
            Some(uid) => uid,
            None => {
                return ResponseResult {
                    action: ResponseAction::BlockNetwork,
                    success: false,
                    details: format!("Could not determine UID for process {}", pid),
                    timestamp,
                };
            }
        };

        // Block outbound traffic for this process using iptables
        // Format: iptables -A OUTPUT -m owner --uid-owner <uid> -m comment --comment "WinnCore: blocked PID <pid> (<comm>)" -j DROP
        let result = Command::new("iptables")
            .args([
                "-A", "OUTPUT",
                "-m", "owner",
                "--uid-owner", &uid.to_string(),
                "-m", "comment",
                "--comment", &format!("WinnCore: blocked PID {} ({})", pid, comm),
                "-j", "DROP",
            ])
            .output();

        match result {
            Ok(output) if output.status.success() => ResponseResult {
                action: ResponseAction::BlockNetwork,
                success: true,
                details: format!(
                    "Blocked network for process {} (UID {}, {}). All outbound traffic blocked.",
                    pid, uid, comm
                ),
                timestamp,
            },
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                ResponseResult {
                    action: ResponseAction::BlockNetwork,
                    success: false,
                    details: format!(
                        "Failed to block network for process {}: {}",
                        pid, stderr
                    ),
                    timestamp,
                }
            }
            Err(e) => ResponseResult {
                action: ResponseAction::BlockNetwork,
                success: false,
                details: format!("Failed to execute iptables: {}", e),
                timestamp,
            },
        }
    }

    /// Quarantine a file (placeholder for av-quarantine integration)
    pub fn quarantine_file(&self, file_path: &str, reason: &str) -> ResponseResult {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Quarantine integration would be done at CLI/daemon level with av-quarantine crate
        // This is a placeholder for future integration
        ResponseResult {
            action: ResponseAction::QuarantineFile,
            success: false,
            details: format!(
                "Quarantine integration pending for file: {}. Reason: {}",
                file_path, reason
            ),
            timestamp,
        }
    }

    /// Generate alert for manual review
    pub fn generate_alert(&self, details: &str) -> ResponseResult {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Log to syslog
        let _ = Command::new("logger")
            .args([
                "-t", "winncore-av",
                "-p", "security.warning",
                &format!("THREAT DETECTED: {}", details),
            ])
            .output();

        ResponseResult {
            action: ResponseAction::Alert,
            success: true,
            details: format!("Alert generated: {}", details),
            timestamp,
        }
    }

    /// Execute appropriate response based on behavioral score
    pub fn respond_to_threat(
        &self,
        behavioral_score: &crate::behavioral_score::BehavioralScore,
        summary: &crate::EventSummary,
    ) -> Vec<ResponseResult> {
        let mut results = Vec::new();

        // Check if we should auto-respond
        if !self.should_auto_respond(behavioral_score.overall_score) {
            // Just generate alert
            let alert = self.generate_alert(&behavioral_score.assessment);
            results.push(alert);
            return results;
        }

        // Auto-response is enabled and score is above threshold
        // Respond to high-risk LOTL events
        if let Some(event) = &summary.most_recent {
            if event.suspicion_score >= 0.85 {
                // Kill the process
                let kill_result = self.kill_process(
                    event.pid,
                    &format!("{:?}: {}", event.event_type, event.details),
                );
                results.push(kill_result);
            }
        }

        // Respond to network threats
        for net_event in &summary.network_events {
            if net_event.suspicion_score >= 0.90 {
                // Block network for this process
                let block_result = self.block_network(net_event.pid, &net_event.comm);
                results.push(block_result);
            }
        }

        // Respond to fileless malware
        for fileless_event in &summary.fileless_events {
            if fileless_event.suspicion_score >= 0.90 {
                // Kill the attacker process
                let kill_result = self.kill_process(
                    fileless_event.pid,
                    &format!("{:?}: {}", fileless_event.technique, fileless_event.details),
                );
                results.push(kill_result);

                // If it's injection, also kill the target
                if let Some(target_pid) = fileless_event.target_pid {
                    let kill_target = self.kill_process(
                        target_pid,
                        "Injection target - may be compromised",
                    );
                    results.push(kill_target);
                }
            }
        }

        // Always generate alert for high-risk scenarios
        let alert = self.generate_alert(&format!(
            "AUTO-RESPONSE TRIGGERED: {} (score: {:.2})",
            behavioral_score.assessment, behavioral_score.overall_score
        ));
        results.push(alert);

        results
    }
}

impl Default for ResponseEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a process exists
fn process_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}

/// Get UID of a process
fn get_process_uid(pid: u32) -> Option<u32> {
    let status_path = format!("/proc/{}/status", pid);
    let content = std::fs::read_to_string(status_path).ok()?;

    for line in content.lines() {
        if line.starts_with("Uid:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse().ok();
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_engine_creation() {
        let engine = ResponseEngine::new();
        assert!(!engine.auto_respond);
        assert_eq!(engine.auto_respond_threshold, 0.85);
    }

    #[test]
    fn test_auto_respond_threshold() {
        let engine = ResponseEngine::with_auto_respond(0.75);
        assert!(engine.auto_respond);
        assert!(engine.should_auto_respond(0.80));
        assert!(!engine.should_auto_respond(0.70));
    }

    #[test]
    fn test_process_exists() {
        // PID 1 (init/systemd) should always exist
        assert!(process_exists(1));
        // Very high PID unlikely to exist
        assert!(!process_exists(999999));
    }

    #[test]
    fn test_get_process_uid() {
        // PID 1 should have UID 0 (root)
        assert_eq!(get_process_uid(1), Some(0));
    }
}
