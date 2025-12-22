//! Fileless malware detection (T1620, T1055)
//!
//! Detects:
//! - `memfd_create()` abuse for fileless execution
//! - execution from deleted binaries
//! - suspicious `LD_PRELOAD` / `/etc/ld.so.preload`
//! - ptrace-based process injection

use super::{Confidence, DetectionRule, MitreMapping, Severity};
use std::fs;

/// Detect memfd_create fileless execution.
///
/// `memfd_create()` creates anonymous memory-backed files that appear
/// as `/memfd:<name>` symlinks. Malware uses this to execute code
/// without touching disk.
pub fn detect_memfd_execution(pid: u32) -> Option<FilelessAlert> {
    let exe_link = format!("/proc/{}/exe", pid);

    let target = fs::read_link(&exe_link).ok()?;
    let target_str = target.to_string_lossy().to_string();

    // Check for memfd execution.
    if target_str.contains("memfd:") || target_str.starts_with("/memfd:") {
        let comm = get_comm(pid);
        let cmdline = get_cmdline(pid);

        // Check for legitimate cases (JIT compilers, etc.)
        let legitimate_parents = ["java", "node", "python", "ruby", "mono"];
        let parent_comm = get_ppid(pid)
            .and_then(|p| fs::read_to_string(format!("/proc/{}/comm", p)).ok())
            .unwrap_or_default();

        let is_legitimate = legitimate_parents
            .iter()
            .any(|p| parent_comm.to_lowercase().contains(p));

        if is_legitimate {
            return None;
        }

        return Some(FilelessAlert {
            pid,
            exe_path: target_str.clone(),
            comm,
            cmdline,
            technique: "memfd_create".to_string(),
            rule: DetectionRule {
                id: "FILELESS-001".to_string(),
                name: "Fileless Execution via memfd_create".to_string(),
                description: format!(
                    "Process {} executing from memory-backed file: {}",
                    pid, target_str
                ),
                severity: Severity::Critical,
                confidence: Confidence::High,
                mitre: MitreMapping::new("T1620"),
                false_positive_notes: vec![
                    "JIT compilers (Java, Node.js) may use memfd legitimately".to_string(),
                    "Some containers use memfd for efficiency".to_string(),
                ],
                references: vec![
                    "https://attack.mitre.org/techniques/T1620/".to_string(),
                    "https://blog.f-secure.com/detecting-linux-memfd-malware/".to_string(),
                ],
            },
        });
    }

    // Check for deleted executable (process running from unlinked file).
    if target_str.contains("(deleted)") {
        return Some(FilelessAlert {
            pid,
            exe_path: target_str.clone(),
            comm: get_comm(pid),
            cmdline: get_cmdline(pid),
            technique: "deleted_exe".to_string(),
            rule: DetectionRule {
                id: "FILELESS-002".to_string(),
                name: "Execution from Deleted File".to_string(),
                description: format!(
                    "Process {} running from deleted executable: {}",
                    pid, target_str
                ),
                severity: Severity::High,
                confidence: Confidence::Medium,
                mitre: MitreMapping::new("T1620"),
                false_positive_notes: vec!["Package updates may briefly show this".to_string()],
                references: vec![],
            },
        });
    }

    None
}

/// Detect `LD_PRELOAD` injection.
///
/// `LD_PRELOAD` forces loading a shared library before all others,
/// allowing function hooking and code injection.
pub fn detect_ld_preload_injection(pid: u32) -> Option<FilelessAlert> {
    // Check process environment.
    let environ_path = format!("/proc/{}/environ", pid);
    let environ = fs::read(&environ_path).ok()?;

    for var in environ.split(|&b| b == 0) {
        if var.starts_with(b"LD_PRELOAD=") {
            let value = String::from_utf8_lossy(&var[11..]).to_string();

            if value.trim().is_empty() {
                continue;
            }

            // Check if preloaded library is suspicious.
            let suspicious_paths = ["/tmp/", "/dev/shm/", "/var/tmp/", "/."];
            let is_suspicious = suspicious_paths.iter().any(|p| value.contains(p));

            if is_suspicious {
                return Some(FilelessAlert {
                    pid,
                    exe_path: value.clone(),
                    comm: get_comm(pid),
                    cmdline: get_cmdline(pid),
                    technique: "ld_preload".to_string(),
                    rule: DetectionRule {
                        id: "FILELESS-003".to_string(),
                        name: "Suspicious LD_PRELOAD Injection".to_string(),
                        description: format!(
                            "Process {} has suspicious LD_PRELOAD: {}",
                            pid, value
                        ),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        mitre: MitreMapping::new("T1574.006"),
                        false_positive_notes: vec![
                            "Some debugging tools use LD_PRELOAD".to_string()
                        ],
                        references: vec![
                            "https://attack.mitre.org/techniques/T1574/006/".to_string()
                        ],
                    },
                });
            }
        }
    }

    // Also check system-wide `/etc/ld.so.preload` (not tied to a specific PID).
    if let Ok(content) = fs::read_to_string("/etc/ld.so.preload") {
        let content = content.trim();
        if !content.is_empty() {
            return Some(FilelessAlert {
                pid: 0,
                exe_path: content.to_string(),
                comm: "system".to_string(),
                cmdline: String::new(),
                technique: "ld_so_preload".to_string(),
                rule: DetectionRule {
                    id: "FILELESS-004".to_string(),
                    name: "System-wide LD_PRELOAD Persistence".to_string(),
                    description: format!("Suspicious /etc/ld.so.preload entry: {}", content),
                    severity: Severity::Critical,
                    confidence: Confidence::Critical,
                    mitre: MitreMapping::new("T1574.006"),
                    false_positive_notes: vec!["Rarely used legitimately".to_string()],
                    references: vec![],
                },
            });
        }
    }

    None
}

/// Detect ptrace-based process injection.
pub fn detect_ptrace_injection(pid: u32, target_pid: u32, request: u32) -> Option<FilelessAlert> {
    // PTRACE_ATTACH = 16, PTRACE_SEIZE = 0x4206
    let is_attach = request == 16 || request == 0x4206;
    if !is_attach {
        return None;
    }

    // Self-debugging is usually legitimate.
    if pid == target_pid {
        return None;
    }

    // Debuggers attaching are usually legitimate.
    let comm = get_comm(pid);
    let debuggers = ["gdb", "lldb", "strace", "ltrace", "perf", "valgrind"];
    if debuggers.iter().any(|d| comm.to_lowercase().contains(d)) {
        return None;
    }

    Some(FilelessAlert {
        pid,
        exe_path: format!("target_pid={}", target_pid),
        comm: comm.clone(),
        cmdline: get_cmdline(pid),
        technique: "ptrace".to_string(),
        rule: DetectionRule {
            id: "FILELESS-005".to_string(),
            name: "Process Injection via ptrace".to_string(),
            description: format!(
                "Process {} (PID {}) attaching to process {}",
                comm, pid, target_pid
            ),
            severity: Severity::Critical,
            confidence: Confidence::High,
            mitre: MitreMapping::new("T1055.008"),
            false_positive_notes: vec![
                "Debuggers (gdb, lldb) use ptrace legitimately".to_string(),
                "strace/ltrace are legitimate tracing tools".to_string(),
            ],
            references: vec!["https://attack.mitre.org/techniques/T1055/008/".to_string()],
        },
    })
}

#[derive(Debug, Clone)]
pub struct FilelessAlert {
    pub pid: u32,
    pub exe_path: String,
    pub comm: String,
    pub cmdline: String,
    pub technique: String,
    pub rule: DetectionRule,
}

fn get_ppid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if line.starts_with("PPid:") {
            return line.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

fn get_comm(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn get_cmdline(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{}/cmdline", pid))
        .unwrap_or_default()
        .replace('\0', " ")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_current_process() {
        let pid = std::process::id();
        assert!(detect_memfd_execution(pid).is_none());
    }

    #[test]
    fn test_get_comm() {
        let pid = std::process::id();
        let comm = get_comm(pid);
        assert!(!comm.is_empty());
    }
}
