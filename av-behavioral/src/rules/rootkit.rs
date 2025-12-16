//! Rootkit indicator detection.
//!
//! MITRE ATT&CK: T1014 (Rootkit)

use std::path::Path;

/// Suspicious kernel module operations.
pub const SUSPICIOUS_MODULE_OPS: &[&str] = &[
    "insmod /tmp/",
    "insmod /dev/shm/",
    "insmod /var/tmp/",
    "insmod ./",
    "insmod ~",
    "modprobe -f",
    "rmmod --force",
];

/// Rootkit-related file paths and patterns (best-effort substrings).
pub const ROOTKIT_FILE_PATTERNS: &[&str] = &[
    "/dev/shm/.",
    "/dev/.",
    "/tmp/.",
    "/.hidden",
    "/usr/include/.",
    "/etc/ld.so.preload",
    "/lib/modules/",
    "/lib/security/.",
    "/lib64/security/.",
];

#[derive(Debug, Clone)]
pub struct RootkitIndicator {
    pub indicator_type: RootkitType,
    pub evidence: String,
    pub severity: Severity,
    pub persistence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootkitType {
    KernelModule,
    LdPreload,
    LibraryHijack,
    HiddenFile,
    BinaryReplacement,
    ProcessHiding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
}

pub fn detect_rootkit_command(cmdline: &str) -> Option<RootkitIndicator> {
    let lower = cmdline.to_lowercase();

    for pattern in SUSPICIOUS_MODULE_OPS {
        if lower.contains(pattern) {
            return Some(RootkitIndicator {
                indicator_type: RootkitType::KernelModule,
                evidence: cmdline.to_string(),
                severity: Severity::Critical,
                persistence: true,
            });
        }
    }

    if cmdline.contains("/etc/ld.so.preload") {
        let is_write = lower.contains("echo")
            || lower.contains("> ")
            || lower.contains("cp ")
            || lower.contains("mv ");
        if is_write {
            return Some(RootkitIndicator {
                indicator_type: RootkitType::LdPreload,
                evidence: cmdline.to_string(),
                severity: Severity::Critical,
                persistence: true,
            });
        }
    }

    if (lower.contains("/lib/security/") || lower.contains("/lib64/security/"))
        && (lower.contains("cp ") || lower.contains("mv ") || lower.contains("install "))
    {
        return Some(RootkitIndicator {
            indicator_type: RootkitType::LibraryHijack,
            evidence: cmdline.to_string(),
            severity: Severity::Critical,
            persistence: true,
        });
    }

    if lower.contains("touch /dev/shm/.")
        || lower.contains("mkdir /dev/shm/.")
        || lower.contains("> /dev/shm/.")
        || lower.contains("touch /tmp/.")
        || lower.contains("mkdir /tmp/.")
    {
        return Some(RootkitIndicator {
            indicator_type: RootkitType::HiddenFile,
            evidence: cmdline.to_string(),
            severity: Severity::High,
            persistence: false,
        });
    }

    let system_dirs = ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"];
    let copy_ops = ["cp ", "mv ", "install "];

    for dir in &system_dirs {
        if !cmdline.contains(dir) {
            continue;
        }
        for op in &copy_ops {
            if lower.contains(op)
                && (cmdline.contains("/tmp/")
                    || cmdline.contains("/dev/shm/")
                    || cmdline.contains("/var/tmp/"))
            {
                return Some(RootkitIndicator {
                    indicator_type: RootkitType::BinaryReplacement,
                    evidence: cmdline.to_string(),
                    severity: Severity::Critical,
                    persistence: true,
                });
            }
        }
    }

    if (lower.contains("chattr +i") || lower.contains("chattr +a"))
        && (cmdline.contains("/tmp/")
            || cmdline.contains(".sh")
            || cmdline.contains("backdoor")
            || cmdline.contains("/etc/"))
    {
        return Some(RootkitIndicator {
            indicator_type: RootkitType::ProcessHiding,
            evidence: cmdline.to_string(),
            severity: Severity::High,
            persistence: true,
        });
    }

    None
}

pub fn check_rootkit_file(path: &Path, operation: &str) -> Option<RootkitIndicator> {
    let path_str = path.to_string_lossy();

    for pattern in ROOTKIT_FILE_PATTERNS {
        if !path_str.contains(pattern) {
            continue;
        }

        let (indicator_type, severity) = if path_str.contains("ld.so.preload") {
            (RootkitType::LdPreload, Severity::Critical)
        } else if path_str.contains("/lib/modules/") {
            (RootkitType::KernelModule, Severity::Critical)
        } else {
            (RootkitType::HiddenFile, Severity::High)
        };

        return Some(RootkitIndicator {
            indicator_type,
            evidence: format!("{} on {}", operation, path_str),
            severity,
            persistence: true,
        });
    }

    None
}

/// Best-effort hidden process detection.
///
/// Returns PIDs whose `/proc/<pid>/cmdline` is unreadable. This is not definitive;
/// permissions and short-lived processes can cause false positives.
pub fn detect_hidden_processes() -> Vec<u32> {
    let mut hidden = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return hidden;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };

        let cmdline_path = format!("/proc/{}/cmdline", pid);
        if std::fs::read(&cmdline_path).is_err() {
            hidden.push(pid);
        }
    }

    hidden
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_module_detection() {
        assert!(detect_rootkit_command("insmod /tmp/evil.ko").is_some());
        assert!(detect_rootkit_command("insmod /dev/shm/rootkit.ko").is_some());
        assert!(detect_rootkit_command("modprobe -f evil").is_some());
        assert!(detect_rootkit_command("modprobe nvidia").is_none());
    }

    #[test]
    fn test_ld_preload_detection() {
        assert!(detect_rootkit_command("echo '/tmp/evil.so' >> /etc/ld.so.preload").is_some());
        assert!(detect_rootkit_command("cp /tmp/evil.so /etc/ld.so.preload").is_some());
    }

    #[test]
    fn test_hidden_file_detection() {
        assert!(detect_rootkit_command("touch /dev/shm/.hidden").is_some());
        assert!(detect_rootkit_command("mkdir /tmp/.secret").is_some());
    }

    #[test]
    fn test_binary_replacement() {
        assert!(detect_rootkit_command("cp /tmp/evil /bin/ls").is_some());
        assert!(detect_rootkit_command("mv /dev/shm/backdoor /usr/bin/sshd").is_some());
    }
}
