//! Container context detection utilities.

use std::fs;
use std::path::Path;
use tracing::debug;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerRuntime {
    None,
    Docker,
    Containerd,
    Podman,
    Kubernetes,
    LXC,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ContainerContext {
    pub runtime: ContainerRuntime,
    pub container_id: Option<String>,
    pub is_privileged: bool,
    pub has_host_pid: bool,
    pub has_host_network: bool,
    pub has_host_ipc: bool,
    pub mounted_docker_socket: bool,
    pub has_sensitive_mounts: Vec<String>,
    pub k8s_namespace: Option<String>,
    pub k8s_pod_name: Option<String>,
    pub k8s_service_account: Option<String>,
}

impl ContainerContext {
    pub fn detect() -> Self {
        let mut ctx = Self {
            runtime: ContainerRuntime::None,
            container_id: None,
            is_privileged: false,
            has_host_pid: false,
            has_host_network: false,
            has_host_ipc: false,
            mounted_docker_socket: false,
            has_sensitive_mounts: Vec::new(),
            k8s_namespace: None,
            k8s_pod_name: None,
            k8s_service_account: None,
        };

        ctx.runtime = detect_runtime();
        if ctx.runtime != ContainerRuntime::None {
            ctx.container_id = get_container_id();
            ctx.is_privileged = check_privileged();
            ctx.has_host_pid = check_host_pid_ns();
            ctx.has_host_network = check_host_net_ns();
            ctx.has_host_ipc = check_host_ipc_ns();
            ctx.mounted_docker_socket = check_docker_socket_mount();
            ctx.has_sensitive_mounts = find_sensitive_mounts();

            if let Ok(ns) = std::env::var("KUBERNETES_NAMESPACE") {
                ctx.k8s_namespace = Some(ns);
            } else if Path::new("/var/run/secrets/kubernetes.io").exists() {
                ctx.k8s_namespace =
                    fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
                        .ok();
            }

            ctx.k8s_pod_name = std::env::var("HOSTNAME").ok();
            ctx.k8s_service_account =
                fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
                    .ok()
                    .map(|_| "present".to_string());
        }

        debug!("Container context: {:?}", ctx);
        ctx
    }

    pub fn is_high_risk(&self) -> bool {
        self.is_privileged
            || self.has_host_pid
            || self.has_host_network
            || self.mounted_docker_socket
            || !self.has_sensitive_mounts.is_empty()
    }
}

fn detect_runtime() -> ContainerRuntime {
    if Path::new("/.dockerenv").exists() {
        return ContainerRuntime::Docker;
    }
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        if cgroup.contains("/docker/") {
            return ContainerRuntime::Docker;
        }
        if cgroup.contains("/kubepods/") {
            return ContainerRuntime::Kubernetes;
        }
        if cgroup.contains("/lxc/") {
            return ContainerRuntime::LXC;
        }
        if cgroup.contains("/containerd") {
            return ContainerRuntime::Containerd;
        }
        if cgroup
            .lines()
            .any(|l| l.split(':').nth(2).map(|p| p.len() > 1).unwrap_or(false))
        {
            return ContainerRuntime::Unknown;
        }
    }
    if let Ok(mounts) = fs::read_to_string("/proc/1/mounts") {
        if mounts.contains("/var/lib/docker") {
            return ContainerRuntime::Docker;
        }
        if mounts.contains("/var/lib/containerd") {
            return ContainerRuntime::Containerd;
        }
    }
    ContainerRuntime::None
}

fn get_container_id() -> Option<String> {
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        for line in cgroup.lines() {
            if let Some(path) = line.split(':').nth(2) {
                if let Some(id) = path.rsplit('/').next() {
                    if id.len() >= 12 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Some(id[..12].to_string());
                    }
                }
            }
        }
    }
    None
}

fn check_privileged() -> bool {
    if let Ok(status) = fs::read_to_string("/proc/1/status") {
        for line in status.lines() {
            if line.starts_with("CapEff:") {
                let cap_hex = line.split_whitespace().nth(1).unwrap_or("0");
                if let Ok(caps) = u64::from_str_radix(cap_hex.trim_start_matches("0"), 16) {
                    return caps & (1 << 21) != 0;
                }
            }
        }
    }
    false
}

fn check_host_pid_ns() -> bool {
    if let Ok(cmdline) = fs::read_to_string("/proc/1/cmdline") {
        return cmdline.contains("systemd") || cmdline.contains("/sbin/init");
    }
    false
}

fn check_host_net_ns() -> bool {
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        let iface_count = entries.count();
        return iface_count > 5;
    }
    false
}

fn check_host_ipc_ns() -> bool {
    if let Ok(entries) = fs::read_dir("/dev/shm") {
        return entries.count() > 10;
    }
    false
}

fn check_docker_socket_mount() -> bool {
    Path::new("/var/run/docker.sock").exists() || Path::new("/run/docker.sock").exists()
}

fn find_sensitive_mounts() -> Vec<String> {
    let mut sensitive = Vec::new();
    let dangerous_paths = [
        "/etc/shadow",
        "/etc/passwd",
        "/root",
        "/home",
        "/var/run/docker.sock",
        "/var/lib/kubelet",
        "/etc/kubernetes",
        "/var/lib/etcd",
        "/proc/sys",
        "/sys/fs/cgroup",
    ];
    if let Ok(mounts) = fs::read_to_string("/proc/1/mounts") {
        for mount in mounts.lines() {
            let parts: Vec<&str> = mount.split_whitespace().collect();
            if parts.len() >= 2 {
                let mount_point = parts[1];
                for dangerous in &dangerous_paths {
                    if mount_point.starts_with(dangerous) {
                        sensitive.push(mount_point.to_string());
                    }
                }
            }
        }
    }
    sensitive
}
