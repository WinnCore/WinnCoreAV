//! Persistence mechanism detection (T1053, T1543, T1547)
//!
//! Detects:
//! - Cron job creation/modification
//! - Systemd service installation
//! - SSH `authorized_keys` modification
//! - Shell profile/rc file modification
//! - Kernel module loading

use super::{Confidence, DetectionRule, MitreMapping, Severity};
use std::fs;

/// Critical paths for persistence detection.
pub const CRON_PATHS: &[&str] = &[
    "/etc/crontab",
    "/etc/cron.d/",
    "/etc/cron.hourly/",
    "/etc/cron.daily/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
    "/var/spool/cron/",
    "/var/spool/cron/crontabs/",
];

pub const SYSTEMD_PATHS: &[&str] = &[
    "/etc/systemd/system/",
    "/usr/lib/systemd/system/",
    "/lib/systemd/system/",
    "/run/systemd/system/",
    "~/.config/systemd/user/",
];

pub const SHELL_RC_PATHS: &[&str] = &[
    "/etc/profile",
    "/etc/profile.d/",
    "/etc/bash.bashrc",
    "/etc/bashrc",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.zshrc",
    "~/.zprofile",
];

pub const SSH_PATHS: &[&str] = &[
    "~/.ssh/authorized_keys",
    "~/.ssh/authorized_keys2",
    "/root/.ssh/authorized_keys",
    "/etc/ssh/sshd_config",
];

/// Detect cron-based persistence.
pub fn detect_cron_modification(
    path: &str,
    operation: FileOperation,
    pid: u32,
    comm: &str,
) -> Option<PersistenceAlert> {
    let is_cron_path = CRON_PATHS.iter().any(|p| path.starts_with(p));
    if !is_cron_path {
        return None;
    }

    // Legitimate cron managers.
    let legitimate = [
        "cron", "anacron", "crond", "systemd", "apt", "dpkg", "yum", "dnf", "pacman",
    ];
    if legitimate.iter().any(|l| comm.to_lowercase().contains(l)) {
        return None;
    }

    let severity = match operation {
        FileOperation::Create | FileOperation::Write => Severity::High,
        FileOperation::Delete | FileOperation::Chmod => Severity::Medium,
        _ => Severity::Low,
    };

    Some(PersistenceAlert {
        path: path.to_string(),
        operation,
        pid,
        comm: comm.to_string(),
        persistence_type: PersistenceType::Cron,
        rule: DetectionRule {
            id: "PERSIST-001".to_string(),
            name: "Cron Job Modification".to_string(),
            description: format!("Process {} ({}) modified cron path: {}", comm, pid, path),
            severity,
            confidence: Confidence::High,
            mitre: MitreMapping::new("T1053.003"),
            false_positive_notes: vec![
                "Package managers may modify cron".to_string(),
                "Legitimate admin scripts".to_string(),
            ],
            references: vec!["https://attack.mitre.org/techniques/T1053/003/".to_string()],
        },
    })
}

/// Detect systemd service persistence.
pub fn detect_systemd_modification(
    path: &str,
    operation: FileOperation,
    pid: u32,
    comm: &str,
) -> Option<PersistenceAlert> {
    let home = std::env::var("HOME").unwrap_or_default();
    let is_systemd_path = SYSTEMD_PATHS.iter().any(|p| {
        let expanded = p.replace('~', &home);
        path.starts_with(&expanded)
    });
    if !is_systemd_path {
        return None;
    }

    // Must be a service/timer/socket file.
    if !path.ends_with(".service") && !path.ends_with(".timer") && !path.ends_with(".socket") {
        return None;
    }

    // Legitimate systemd managers.
    let legitimate = ["systemd", "apt", "dpkg", "yum", "dnf", "rpm", "pacman"];
    if legitimate.iter().any(|l| comm.to_lowercase().contains(l)) {
        return None;
    }

    // Read service file to check for suspicious content.
    let suspicious_content = if matches!(operation, FileOperation::Create | FileOperation::Write) {
        check_suspicious_service_content(path)
    } else {
        None
    };

    let severity = if suspicious_content.is_some() {
        Severity::Critical
    } else {
        Severity::High
    };

    Some(PersistenceAlert {
        path: path.to_string(),
        operation,
        pid,
        comm: comm.to_string(),
        persistence_type: PersistenceType::Systemd,
        rule: DetectionRule {
            id: "PERSIST-002".to_string(),
            name: "Systemd Service Installation".to_string(),
            description: format!(
                "Process {} ({}) created/modified systemd service: {}{}",
                comm,
                pid,
                path,
                suspicious_content
                    .map(|s| format!(" [SUSPICIOUS: {}]", s))
                    .unwrap_or_default()
            ),
            severity,
            confidence: Confidence::High,
            mitre: MitreMapping::new("T1543.002"),
            false_positive_notes: vec![
                "Package managers install services".to_string(),
                "Legitimate application installers".to_string(),
            ],
            references: vec!["https://attack.mitre.org/techniques/T1543/002/".to_string()],
        },
    })
}

fn check_suspicious_service_content(path: &str) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let content_lower = content.to_lowercase();

    let suspicious_patterns = [
        ("curl", "Downloads content at startup"),
        ("wget", "Downloads content at startup"),
        ("/dev/tcp", "Bash reverse shell"),
        ("nc -e", "Netcat reverse shell"),
        ("/tmp/", "Executes from temp directory"),
        ("/dev/shm/", "Executes from shared memory"),
        ("base64 -d", "Decodes base64 at startup"),
        ("eval", "Dynamic code execution"),
        ("python -c", "Python one-liner execution"),
    ];

    for (pattern, description) in suspicious_patterns {
        if content_lower.contains(pattern) {
            return Some(description.to_string());
        }
    }

    None
}

/// Detect SSH authorized_keys modification.
pub fn detect_ssh_key_modification(
    path: &str,
    operation: FileOperation,
    pid: u32,
    comm: &str,
) -> Option<PersistenceAlert> {
    let is_ssh_path = path.contains("authorized_keys") || path.contains("sshd_config");
    if !is_ssh_path {
        return None;
    }

    // Legitimate SSH key managers.
    let legitimate = ["ssh-", "sshd", "ssh-keygen", "cloud-init"];
    if legitimate.iter().any(|l| comm.starts_with(l)) {
        return None;
    }

    Some(PersistenceAlert {
        path: path.to_string(),
        operation,
        pid,
        comm: comm.to_string(),
        persistence_type: PersistenceType::SshKey,
        rule: DetectionRule {
            id: "PERSIST-003".to_string(),
            name: "SSH Authorized Keys Modification".to_string(),
            description: format!(
                "Process {} ({}) modified SSH authentication: {}",
                comm, pid, path
            ),
            severity: Severity::High,
            confidence: Confidence::High,
            mitre: MitreMapping::new("T1098.004"),
            false_positive_notes: vec![
                "Legitimate SSH key management".to_string(),
                "Cloud provisioning (cloud-init)".to_string(),
            ],
            references: vec!["https://attack.mitre.org/techniques/T1098/004/".to_string()],
        },
    })
}

/// Detect shell RC file modification.
pub fn detect_shell_rc_modification(
    path: &str,
    operation: FileOperation,
    pid: u32,
    comm: &str,
) -> Option<PersistenceAlert> {
    let home = std::env::var("HOME").unwrap_or_default();
    let is_rc_path = SHELL_RC_PATHS.iter().any(|p| {
        let expanded = p.replace('~', &home);
        path == expanded || path.starts_with(&expanded)
    });
    if !is_rc_path {
        return None;
    }

    let suspicious_content = if matches!(operation, FileOperation::Write) {
        check_suspicious_rc_content(path)
    } else {
        None
    };

    let (severity, confidence) = if suspicious_content.is_some() {
        (Severity::Critical, Confidence::High)
    } else {
        (Severity::Medium, Confidence::Medium)
    };

    Some(PersistenceAlert {
        path: path.to_string(),
        operation,
        pid,
        comm: comm.to_string(),
        persistence_type: PersistenceType::ShellRc,
        rule: DetectionRule {
            id: "PERSIST-004".to_string(),
            name: "Shell Profile Modification".to_string(),
            description: format!(
                "Process {} ({}) modified shell profile: {}{}",
                comm,
                pid,
                path,
                suspicious_content
                    .map(|s| format!(" [SUSPICIOUS: {}]", s))
                    .unwrap_or_default()
            ),
            severity,
            confidence,
            mitre: MitreMapping::new("T1546.004"),
            false_positive_notes: vec![
                "User customization of shell".to_string(),
                "Package managers adding to PATH".to_string(),
                "Development tool installations".to_string(),
            ],
            references: vec!["https://attack.mitre.org/techniques/T1546/004/".to_string()],
        },
    })
}

fn check_suspicious_rc_content(path: &str) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let last_lines: Vec<&str> = content.lines().rev().take(20).collect();
    let recent_content = last_lines.join("\n").to_lowercase();

    let suspicious_patterns = [
        ("curl | bash", "Downloads and executes script"),
        ("wget -o - | sh", "Downloads and executes script"),
        ("/dev/tcp/", "Reverse shell"),
        ("base64 -d", "Decodes obfuscated content"),
        ("eval $(", "Dynamic code execution"),
        ("nohup", "Background process persistence"),
    ];

    for (pattern, description) in suspicious_patterns {
        if recent_content.contains(pattern) {
            return Some(description.to_string());
        }
    }

    None
}

/// Detect kernel module loading.
pub fn detect_kernel_module_load(
    module_name: &str,
    pid: u32,
    comm: &str,
) -> Option<PersistenceAlert> {
    let legitimate_loaders = ["modprobe", "insmod", "systemd", "udevd", "kmod"];

    let mut severity = if legitimate_loaders
        .iter()
        .any(|l| comm.to_lowercase().contains(l))
    {
        Severity::Medium
    } else {
        Severity::Critical
    };

    let suspicious_modules = ["reptile", "diamorphine", "rootkit", "hide", "stealth"];
    let is_suspicious_name = suspicious_modules
        .iter()
        .any(|s| module_name.to_lowercase().contains(s));

    if is_suspicious_name {
        severity = Severity::Critical;
    }

    Some(PersistenceAlert {
        path: module_name.to_string(),
        operation: FileOperation::ModuleLoad,
        pid,
        comm: comm.to_string(),
        persistence_type: PersistenceType::KernelModule,
        rule: DetectionRule {
            id: "PERSIST-005".to_string(),
            name: "Kernel Module Loading".to_string(),
            description: format!(
                "Process {} ({}) loading kernel module: {}",
                comm, pid, module_name
            ),
            severity,
            confidence: if is_suspicious_name {
                Confidence::Critical
            } else {
                Confidence::Medium
            },
            mitre: MitreMapping::new("T1547.006"),
            false_positive_notes: vec![
                "Driver installation".to_string(),
                "Hardware detection".to_string(),
                "VirtualBox/VMware modules".to_string(),
            ],
            references: vec!["https://attack.mitre.org/techniques/T1547/006/".to_string()],
        },
    })
}

#[derive(Debug, Clone, Copy)]
pub enum FileOperation {
    Create,
    Write,
    Delete,
    Rename,
    Chmod,
    Chown,
    ModuleLoad,
}

#[derive(Debug, Clone)]
pub enum PersistenceType {
    Cron,
    Systemd,
    SshKey,
    ShellRc,
    KernelModule,
    InitScript,
}

#[derive(Debug, Clone)]
pub struct PersistenceAlert {
    pub path: String,
    pub operation: FileOperation,
    pub pid: u32,
    pub comm: String,
    pub persistence_type: PersistenceType,
    pub rule: DetectionRule,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cron_detection() {
        let result = detect_cron_modification(
            "/etc/cron.d/malicious",
            FileOperation::Create,
            1234,
            "suspicious_process",
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule.severity, Severity::High);
    }

    #[test]
    fn test_legitimate_cron() {
        let result =
            detect_cron_modification("/etc/cron.d/package", FileOperation::Create, 1234, "apt");
        assert!(result.is_none());
    }

    #[test]
    fn test_systemd_detection() {
        let result = detect_systemd_modification(
            "/etc/systemd/system/backdoor.service",
            FileOperation::Create,
            1234,
            "suspicious",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_ssh_key_detection() {
        let result = detect_ssh_key_modification(
            "/root/.ssh/authorized_keys",
            FileOperation::Write,
            1234,
            "suspicious",
        );
        assert!(result.is_some());
    }
}
