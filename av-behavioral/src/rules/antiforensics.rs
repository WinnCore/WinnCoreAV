//! Anti-forensics and log tampering detection.
//!
//! MITRE ATT&CK: T1070 (Indicator Removal on Host)

use std::path::Path;

/// Critical log/history paths commonly targeted for tampering.
pub const CRITICAL_LOG_FILES: &[&str] = &[
    // System logs
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/kern.log",
    "/var/log/dmesg",
    // Auth logs
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/faillog",
    "/var/log/lastlog",
    "/var/log/wtmp",
    "/var/log/btmp",
    // Audit logs
    "/var/log/audit/audit.log",
    // Web logs
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    // Shell history
    "/.bash_history",
    "/.zsh_history",
    "/.sh_history",
];

#[derive(Debug, Clone)]
pub struct LogTamperingIndicator {
    pub tampering_type: TamperingType,
    pub target: String,
    pub evidence: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TamperingType {
    LogTruncation,
    LogDeletion,
    HistoryClearing,
    TimestampModification,
    AuditDisable,
    JournalClearing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
}

pub fn detect_log_tampering(cmdline: &str) -> Option<LogTamperingIndicator> {
    let lower = cmdline.to_lowercase();

    for log_file in CRITICAL_LOG_FILES {
        if cmdline.contains(log_file) {
            if lower.contains("truncate")
                || lower.contains("cat /dev/null")
                || lower.contains("> /var/log")
                || lower.contains("echo '' >")
                || lower.contains("echo \"\" >")
            {
                return Some(LogTamperingIndicator {
                    tampering_type: TamperingType::LogTruncation,
                    target: (*log_file).to_string(),
                    evidence: cmdline.to_string(),
                    severity: Severity::Critical,
                });
            }

            if lower.contains("rm ") || lower.contains("shred") {
                return Some(LogTamperingIndicator {
                    tampering_type: TamperingType::LogDeletion,
                    target: (*log_file).to_string(),
                    evidence: cmdline.to_string(),
                    severity: Severity::Critical,
                });
            }
        }
    }

    if lower.contains("history -c")
        || lower.contains("unset histfile")
        || lower.contains("histsize=0")
        || lower.contains("histfilesize=0")
        || (lower.contains("rm") && lower.contains("history"))
    {
        return Some(LogTamperingIndicator {
            tampering_type: TamperingType::HistoryClearing,
            target: "shell history".to_string(),
            evidence: cmdline.to_string(),
            severity: Severity::High,
        });
    }

    if lower.contains("touch -t") || lower.contains("touch -d") || lower.contains("touch -r") {
        let is_sensitive_target = cmdline.contains("/var/")
            || cmdline.contains("/etc/")
            || cmdline.contains("/usr/")
            || cmdline.contains(".log")
            || cmdline.contains(".sh");

        if is_sensitive_target {
            return Some(LogTamperingIndicator {
                tampering_type: TamperingType::TimestampModification,
                target: "file timestamps".to_string(),
                evidence: cmdline.to_string(),
                severity: Severity::High,
            });
        }
    }

    if lower.contains("auditctl -e 0")
        || (lower.contains("auditd") && (lower.contains("stop") || lower.contains("disable")))
    {
        return Some(LogTamperingIndicator {
            tampering_type: TamperingType::AuditDisable,
            target: "audit subsystem".to_string(),
            evidence: cmdline.to_string(),
            severity: Severity::Critical,
        });
    }

    if lower.contains("journalctl") && (lower.contains("--vacuum") || lower.contains("--rotate")) {
        return Some(LogTamperingIndicator {
            tampering_type: TamperingType::JournalClearing,
            target: "systemd journal".to_string(),
            evidence: cmdline.to_string(),
            severity: Severity::Critical,
        });
    }

    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOperation {
    Read,
    Write,
    Truncate,
    Delete,
    Unlink,
    Rename,
}

pub fn check_log_file_operation(
    path: &Path,
    operation: FileOperation,
) -> Option<LogTamperingIndicator> {
    let path_str = path.to_string_lossy();

    let is_critical = CRITICAL_LOG_FILES
        .iter()
        .any(|&log| path_str.contains(log) || path_str.ends_with(log));

    let is_log_like = is_critical
        || path_str.contains("/var/log/")
        || path_str.ends_with(".log")
        || path_str.contains("history");

    if !is_log_like {
        return None;
    }

    match operation {
        FileOperation::Truncate | FileOperation::Write => Some(LogTamperingIndicator {
            tampering_type: TamperingType::LogTruncation,
            target: path_str.to_string(),
            evidence: format!("{:?} operation on log-like file", operation),
            severity: Severity::Critical,
        }),
        FileOperation::Delete | FileOperation::Unlink => Some(LogTamperingIndicator {
            tampering_type: TamperingType::LogDeletion,
            target: path_str.to_string(),
            evidence: format!("{:?} operation on log-like file", operation),
            severity: Severity::Critical,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_truncation() {
        let cases = vec![
            ("truncate -s 0 /var/log/auth.log", true),
            ("> /var/log/syslog", true),
            ("cat /dev/null > /var/log/messages", true),
            ("cat /var/log/syslog", false),
        ];

        for (cmd, should_detect) in cases {
            let result = detect_log_tampering(cmd);
            assert_eq!(result.is_some(), should_detect, "Failed for: {}", cmd);
        }
    }

    #[test]
    fn test_history_clearing() {
        assert!(detect_log_tampering("history -c").is_some());
        assert!(detect_log_tampering("export HISTSIZE=0").is_some());
        assert!(detect_log_tampering("rm ~/.bash_history").is_some());
    }

    #[test]
    fn test_audit_tampering() {
        assert!(detect_log_tampering("auditctl -e 0").is_some());
        assert!(detect_log_tampering("systemctl stop auditd").is_some());
    }

    #[test]
    fn test_timestomping() {
        assert!(detect_log_tampering("touch -t 202001010000 /var/log/auth.log").is_some());
        assert!(detect_log_tampering("touch -d '2020-01-01' /etc/passwd").is_some());
        assert!(detect_log_tampering("touch /tmp/myfile").is_none());
    }

    #[test]
    fn test_log_file_operation() {
        let indicator =
            check_log_file_operation(Path::new("/var/log/auth.log"), FileOperation::Truncate);
        assert!(indicator.is_some());

        let none = check_log_file_operation(Path::new("/tmp/notes.txt"), FileOperation::Write);
        assert!(none.is_none());
    }
}
