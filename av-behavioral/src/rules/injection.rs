use std::path::Path;

/// Process injection detection patterns.
///
/// Maps to MITRE ATT&CK:
/// - T1055 (Process Injection)
/// - T1574.006 (LD_PRELOAD Hijacking)

#[derive(Debug, Clone)]
pub struct InjectionIndicator {
    pub technique: InjectionTechnique,
    pub severity: Severity,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectionTechnique {
    /// T1055.001 - DLL Injection (Linux: `.so` injection)
    SharedObjectInjection,
    /// T1055.008 - Ptrace System Calls
    PtraceInjection,
    /// T1055.009 - Proc Memory (`/proc/<pid>/mem`)
    ProcMemInjection,
    /// T1574.006 - LD_PRELOAD Hijacking
    LdPreloadHijack,
    /// T1055.012 - Process Hollowing (placeholder)
    ProcessHollowing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

/// Check command line for injection indicators.
pub fn check_cmdline_injection(cmdline: &str) -> Option<InjectionIndicator> {
    // LD_PRELOAD injection - common Linux technique.
    if cmdline.contains("LD_PRELOAD=")
        && (cmdline.contains("LD_PRELOAD=/tmp/")
            || cmdline.contains("LD_PRELOAD=/dev/shm/")
            || cmdline.contains("LD_PRELOAD=./")
            || cmdline.contains("LD_PRELOAD=/var/tmp/"))
    {
        return Some(InjectionIndicator {
            technique: InjectionTechnique::LdPreloadHijack,
            severity: Severity::Critical,
            evidence: format!("Suspicious LD_PRELOAD path in: {}", cmdline),
        });
    }

    // ptrace attachment
    if cmdline.contains("ptrace")
        && (cmdline.contains("PTRACE_ATTACH") || cmdline.contains("PTRACE_POKETEXT"))
    {
        return Some(InjectionIndicator {
            technique: InjectionTechnique::PtraceInjection,
            severity: Severity::Critical,
            evidence: format!("Ptrace injection pattern: {}", cmdline),
        });
    }

    // gdb attach to running process (potential injection).
    if cmdline.contains("gdb") && cmdline.contains("-p") {
        return Some(InjectionIndicator {
            technique: InjectionTechnique::PtraceInjection,
            severity: Severity::Medium,
            evidence: format!("GDB attach to process: {}", cmdline),
        });
    }

    None
}

/// Check for `/proc/<pid>/mem` access.
pub fn check_proc_mem_access(path: &Path) -> Option<InjectionIndicator> {
    let path_str = path.to_string_lossy();

    // Pattern: /proc/[0-9]+/mem
    if path_str.starts_with("/proc/") && path_str.ends_with("/mem") {
        let parts: Vec<&str> = path_str.split('/').collect();
        if parts.len() >= 4 && parts[2].parse::<u32>().is_ok() {
            return Some(InjectionIndicator {
                technique: InjectionTechnique::ProcMemInjection,
                severity: Severity::Critical,
                evidence: format!("Process memory access: {}", path_str),
            });
        }
    }

    // Pattern: /proc/[0-9]+/maps (recon for injection)
    if path_str.starts_with("/proc/") && path_str.ends_with("/maps") {
        let parts: Vec<&str> = path_str.split('/').collect();
        if parts.len() >= 4 && parts[2].parse::<u32>().is_ok() {
            return Some(InjectionIndicator {
                technique: InjectionTechnique::ProcMemInjection,
                severity: Severity::Medium,
                evidence: format!("Process memory mapping read: {}", path_str),
            });
        }
    }

    None
}

/// Check environment for injection-related variables.
pub fn check_env_injection(env_vars: &[(String, String)]) -> Option<InjectionIndicator> {
    for (key, value) in env_vars {
        match key.as_str() {
            "LD_PRELOAD" => {
                // Suspicious if pointing to non-standard locations.
                if !value.starts_with("/usr/lib") && !value.starts_with("/lib") {
                    return Some(InjectionIndicator {
                        technique: InjectionTechnique::LdPreloadHijack,
                        severity: Severity::Critical,
                        evidence: format!("LD_PRELOAD set to suspicious path: {}", value),
                    });
                }
            }
            "LD_LIBRARY_PATH" => {
                // Path manipulation.
                if value.contains("/tmp") || value.contains("/dev/shm") {
                    return Some(InjectionIndicator {
                        technique: InjectionTechnique::SharedObjectInjection,
                        severity: Severity::High,
                        evidence: format!("LD_LIBRARY_PATH contains suspicious dir: {}", value),
                    });
                }
            }
            "LD_AUDIT" => {
                // Less commonly abused but dangerous.
                return Some(InjectionIndicator {
                    technique: InjectionTechnique::SharedObjectInjection,
                    severity: Severity::High,
                    evidence: format!("LD_AUDIT set: {}", value),
                });
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ld_preload_detection() {
        let cases = vec![
            ("LD_PRELOAD=/tmp/evil.so ./target", true),
            ("LD_PRELOAD=/dev/shm/hook.so bash", true),
            ("LD_PRELOAD=/usr/lib/libasan.so ./test", false),
            ("echo hello", false),
        ];

        for (cmdline, should_detect) in cases {
            let result = check_cmdline_injection(cmdline);
            assert_eq!(result.is_some(), should_detect, "Failed for: {}", cmdline);
        }
    }

    #[test]
    fn test_ptrace_detection() {
        assert!(check_cmdline_injection("ptrace(PTRACE_ATTACH, pid)").is_some());
        assert!(check_cmdline_injection("gdb -p 1234").is_some());
        assert!(check_cmdline_injection("strace ls").is_none());
    }

    #[test]
    fn test_proc_mem_access() {
        let critical = check_proc_mem_access(Path::new("/proc/1234/mem"));
        assert!(critical.is_some());
        assert!(matches!(critical.unwrap().severity, Severity::Critical));

        let medium = check_proc_mem_access(Path::new("/proc/1234/maps"));
        assert!(medium.is_some());
        assert!(matches!(medium.unwrap().severity, Severity::Medium));

        let none = check_proc_mem_access(Path::new("/proc/1234/status"));
        assert!(none.is_none());
    }

    #[test]
    fn test_env_injection() {
        let suspicious = vec![("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string())];
        assert!(check_env_injection(&suspicious).is_some());

        let legitimate = vec![("LD_PRELOAD".to_string(), "/usr/lib/libasan.so".to_string())];
        assert!(check_env_injection(&legitimate).is_none());
    }
}
