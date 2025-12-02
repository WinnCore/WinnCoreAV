//! Container escape attempt detection heuristics.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::context::{ContainerContext, ContainerRuntime};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContainerThreat {
    DockerSocketAccess {
        pid: u32,
        comm: String,
    },
    K8sTokenTheft {
        pid: u32,
        comm: String,
        token_path: String,
    },
    SensitiveMount {
        pid: u32,
        comm: String,
        source: String,
        target: String,
    },
    NamespaceEscape {
        pid: u32,
        comm: String,
        namespace_type: String,
        target_ns: String,
    },
    CgroupEscape {
        pid: u32,
        comm: String,
        technique: String,
    },
    PrivilegedAbuse {
        pid: u32,
        comm: String,
        operation: String,
    },
    ProcSysAbuse {
        pid: u32,
        comm: String,
        path: String,
        operation: String,
    },
    CapabilityAbuse {
        pid: u32,
        comm: String,
        capability: String,
        operation: String,
    },
}

pub struct ContainerDetector {
    context: ContainerContext,
    k8s_token_whitelist: HashSet<String>,
    docker_socket_whitelist: HashSet<String>,
}

impl ContainerDetector {
    pub fn new() -> Self {
        let mut k8s_whitelist = HashSet::new();
        k8s_whitelist.insert("kubelet".to_string());
        k8s_whitelist.insert("kube-proxy".to_string());

        let mut docker_whitelist = HashSet::new();
        docker_whitelist.insert("dockerd".to_string());
        docker_whitelist.insert("containerd".to_string());

        Self {
            context: ContainerContext::detect(),
            k8s_token_whitelist: k8s_whitelist,
            docker_socket_whitelist: docker_whitelist,
        }
    }

    pub fn in_container(&self) -> bool {
        self.context.runtime != ContainerRuntime::None
    }

    pub fn is_risky_container(&self) -> bool {
        self.context.is_high_risk()
    }

    pub fn check_file_access(
        &self,
        pid: u32,
        comm: &str,
        path: &str,
        flags: u32,
    ) -> Option<ContainerThreat> {
        if !self.in_container() {
            return None;
        }

        if path == "/var/run/docker.sock" || path == "/run/docker.sock" {
            if !self.docker_socket_whitelist.contains(comm) {
                return Some(ContainerThreat::DockerSocketAccess {
                    pid,
                    comm: comm.to_string(),
                });
            }
        }

        if path.contains("/var/run/secrets/kubernetes.io/serviceaccount/token") {
            if !self.k8s_token_whitelist.contains(comm) {
                return Some(ContainerThreat::K8sTokenTheft {
                    pid,
                    comm: comm.to_string(),
                    token_path: path.to_string(),
                });
            }
        }

        if path.starts_with("/proc/sys/") && (flags & 0x1 != 0) {
            return Some(ContainerThreat::ProcSysAbuse {
                pid,
                comm: comm.to_string(),
                path: path.to_string(),
                operation: "write".to_string(),
            });
        }

        if path.starts_with("/sys/fs/cgroup/") && (flags & 0x1 != 0) {
            return Some(ContainerThreat::CgroupEscape {
                pid,
                comm: comm.to_string(),
                technique: format!("cgroup write: {}", path),
            });
        }

        None
    }

    pub fn check_namespace_syscall(
        &self,
        pid: u32,
        comm: &str,
        syscall: &str,
        namespace_fd: Option<&str>,
    ) -> Option<ContainerThreat> {
        if !self.in_container() {
            return None;
        }
        if syscall == "setns" {
            return Some(ContainerThreat::NamespaceEscape {
                pid,
                comm: comm.to_string(),
                namespace_type: "setns".to_string(),
                target_ns: namespace_fd.unwrap_or("?").to_string(),
            });
        }
        if syscall == "unshare" {
            return Some(ContainerThreat::NamespaceEscape {
                pid,
                comm: comm.to_string(),
                namespace_type: "unshare".to_string(),
                target_ns: "new".to_string(),
            });
        }
        None
    }

    pub fn check_mount(
        &self,
        pid: u32,
        comm: &str,
        source: &str,
        target: &str,
        fstype: &str,
    ) -> Option<ContainerThreat> {
        if !self.in_container() {
            return None;
        }

        let sensitive_sources = [
            "/", "/etc", "/root", "/home", "/var", "/proc", "/sys", "/dev/sd",
        ];
        if sensitive_sources.iter().any(|s| source.starts_with(s)) {
            return Some(ContainerThreat::SensitiveMount {
                pid,
                comm: comm.to_string(),
                source: source.to_string(),
                target: target.to_string(),
            });
        }

        if fstype == "proc" || fstype == "sysfs" {
            return Some(ContainerThreat::ProcSysAbuse {
                pid,
                comm: comm.to_string(),
                path: target.to_string(),
                operation: format!("mount {}", fstype),
            });
        }

        None
    }

    pub fn check_privileged_operation(
        &self,
        pid: u32,
        comm: &str,
        operation: &str,
    ) -> Option<ContainerThreat> {
        if !self.in_container() || !self.context.is_privileged {
            return None;
        }
        let risky_ops = [
            "insmod", "modprobe", "iptables", "nftables", "dmsetup", "losetup",
        ];
        if risky_ops.iter().any(|op| operation.contains(op)) {
            return Some(ContainerThreat::PrivilegedAbuse {
                pid,
                comm: comm.to_string(),
                operation: operation.to_string(),
            });
        }
        None
    }

    pub fn context(&self) -> &ContainerContext {
        &self.context
    }
}
