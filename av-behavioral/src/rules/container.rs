use std::path::Path;

/// Container escape detection patterns.
///
/// Maps to MITRE ATT&CK T1611 (Escape to Host).

#[derive(Debug, Clone)]
pub struct ContainerEscapeIndicator {
    pub technique: EscapeTechnique,
    pub severity: Severity,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscapeTechnique {
    /// Docker socket access.
    DockerSocketAccess,
    /// Kubernetes service account abuse.
    KubeServiceAccount,
    /// cgroups escape.
    CgroupsEscape,
    /// `/proc/sys` access (namespace escape / kernel tuning).
    ProcSysWrite,
    /// Device access (`--privileged` patterns).
    PrivilegedDeviceAccess,
    /// Capability manipulation (e.g., CAP_SYS_ADMIN).
    CapSysAdminAbuse,
    /// `nsenter` to host namespaces.
    NsenterEscape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
}

/// Check if we're running inside a container.
pub fn is_containerized() -> bool {
    Path::new("/.dockerenv").exists()
        || std::fs::read_to_string("/proc/1/cgroup")
            .map(|s| s.contains("docker") || s.contains("kubepods") || s.contains("containerd"))
            .unwrap_or(false)
}

/// Check file access for container escape patterns.
pub fn check_container_escape_file(path: &Path) -> Option<ContainerEscapeIndicator> {
    let path_str = path.to_string_lossy();

    // Docker socket access - CRITICAL.
    if path_str == "/var/run/docker.sock" || path_str == "/run/docker.sock" {
        return Some(ContainerEscapeIndicator {
            technique: EscapeTechnique::DockerSocketAccess,
            severity: Severity::Critical,
            evidence: "Docker socket access detected - potential container escape".to_string(),
        });
    }

    // Kubernetes service account token.
    if path_str.contains("/var/run/secrets/kubernetes.io") {
        return Some(ContainerEscapeIndicator {
            technique: EscapeTechnique::KubeServiceAccount,
            severity: Severity::High,
            evidence: format!("Kubernetes service account access: {}", path_str),
        });
    }

    // cgroups escape paths.
    if path_str.contains("/sys/fs/cgroup")
        && (path_str.contains("release_agent") || path_str.contains("notify_on_release"))
    {
        return Some(ContainerEscapeIndicator {
            technique: EscapeTechnique::CgroupsEscape,
            severity: Severity::Critical,
            evidence: format!("cgroups escape attempt: {}", path_str),
        });
    }

    // /proc/sys access (potential namespace escape).
    if path_str.starts_with("/proc/sys/") && !path_str.contains("/proc/sys/kernel/random") {
        return Some(ContainerEscapeIndicator {
            technique: EscapeTechnique::ProcSysWrite,
            severity: Severity::High,
            evidence: format!("/proc/sys access: {}", path_str),
        });
    }

    // Raw device access (indicates `--privileged` or host escape attempts).
    if path_str.starts_with("/dev/") {
        let dangerous_devices = [
            "/dev/sda",
            "/dev/sdb",
            "/dev/nvme",
            "/dev/vda",
            "/dev/mem",
            "/dev/kmem",
        ];
        for dev in &dangerous_devices {
            if path_str.starts_with(dev) {
                return Some(ContainerEscapeIndicator {
                    technique: EscapeTechnique::PrivilegedDeviceAccess,
                    severity: Severity::Critical,
                    evidence: format!("Raw device access: {}", path_str),
                });
            }
        }
    }

    None
}

/// Check command line for container escape patterns.
pub fn check_container_escape_cmd(cmdline: &str) -> Option<ContainerEscapeIndicator> {
    // nsenter to host namespace.
    if cmdline.contains("nsenter")
        && (cmdline.contains("-t 1")
            || cmdline.contains("--target 1")
            || cmdline.contains("/proc/1/ns"))
    {
        return Some(ContainerEscapeIndicator {
            technique: EscapeTechnique::NsenterEscape,
            severity: Severity::Critical,
            evidence: format!("nsenter to host namespace: {}", cmdline),
        });
    }

    // Docker escape via docker command inside container.
    if cmdline.contains("docker")
        && (cmdline.contains("run") || cmdline.contains("exec"))
        && (cmdline.contains("--privileged")
            || cmdline.contains("-v /:/host")
            || cmdline.contains("--pid=host"))
    {
        return Some(ContainerEscapeIndicator {
            technique: EscapeTechnique::DockerSocketAccess,
            severity: Severity::Critical,
            evidence: format!("Docker escape command: {}", cmdline),
        });
    }

    // capsh for capability manipulation.
    if cmdline.contains("capsh") && cmdline.contains("--") {
        return Some(ContainerEscapeIndicator {
            technique: EscapeTechnique::CapSysAdminAbuse,
            severity: Severity::High,
            evidence: format!("Capability manipulation: {}", cmdline),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docker_socket_detection() {
        let result = check_container_escape_file(Path::new("/var/run/docker.sock"));
        assert!(result.is_some());
        assert!(matches!(
            result.unwrap().technique,
            EscapeTechnique::DockerSocketAccess
        ));
    }

    #[test]
    fn test_cgroups_escape_detection() {
        let result = check_container_escape_file(Path::new("/sys/fs/cgroup/memory/release_agent"));
        assert!(result.is_some());
        assert!(matches!(
            result.unwrap().technique,
            EscapeTechnique::CgroupsEscape
        ));
    }

    #[test]
    fn test_nsenter_escape() {
        let result = check_container_escape_cmd("nsenter -t 1 -m -u -i -n -p -- /bin/bash");
        assert!(result.is_some());
        assert!(matches!(
            result.unwrap().technique,
            EscapeTechnique::NsenterEscape
        ));
    }

    #[test]
    fn test_device_access() {
        let result = check_container_escape_file(Path::new("/dev/sda"));
        assert!(result.is_some());
        assert!(matches!(
            result.unwrap().technique,
            EscapeTechnique::PrivilegedDeviceAccess
        ));

        // /dev/null should not trigger.
        let safe = check_container_escape_file(Path::new("/dev/null"));
        assert!(safe.is_none());
    }
}
