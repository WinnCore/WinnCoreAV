#![allow(dead_code, unused_imports, unused_unsafe)]
//! Linux namespace isolation helpers.

use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    Pid,
    Mount,
    Network,
    User,
    Uts,
    Ipc,
    Cgroup,
}

impl Namespace {
    fn clone_flag(&self) -> i32 {
        match self {
            Namespace::Pid => libc::CLONE_NEWPID,
            Namespace::Mount => libc::CLONE_NEWNS,
            Namespace::Network => libc::CLONE_NEWNET,
            Namespace::User => libc::CLONE_NEWUSER,
            Namespace::Uts => libc::CLONE_NEWUTS,
            Namespace::Ipc => libc::CLONE_NEWIPC,
            Namespace::Cgroup => libc::CLONE_NEWCGROUP,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BindMount {
    pub source: String,
    pub target: String,
    pub read_only: bool,
}

impl BindMount {
    pub fn ro(path: impl Into<String>) -> Self {
        let p = path.into();
        Self {
            source: p.clone(),
            target: p,
            read_only: true,
        }
    }

    pub fn rw(path: impl Into<String>) -> Self {
        let p = path.into();
        Self {
            source: p.clone(),
            target: p,
            read_only: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    pub isolate_pid: bool,
    pub isolate_mount: bool,
    pub isolate_network: bool,
    pub isolate_ipc: bool,
    pub isolate_uts: bool,
    pub bind_mounts: Vec<BindMount>,
    pub read_only_root: bool,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            isolate_pid: true,
            isolate_mount: true,
            isolate_network: false,
            isolate_ipc: true,
            isolate_uts: true,
            bind_mounts: vec![
                BindMount::ro("/"),
                BindMount::ro("/proc"),
                BindMount::ro("/sys"),
                BindMount::ro("/dev"),
                BindMount::rw("/var/lib/winncore"),
                BindMount::rw("/var/log/winncore"),
                BindMount::rw("/run/winncore"),
                BindMount::rw("/tmp/winncore"),
            ],
            read_only_root: true,
        }
    }
}

impl NamespaceConfig {
    pub fn development() -> Self {
        Self {
            isolate_pid: false,
            isolate_mount: false,
            isolate_network: false,
            isolate_ipc: false,
            isolate_uts: false,
            bind_mounts: vec![],
            read_only_root: false,
        }
    }

    pub fn production() -> Self {
        Self::default()
    }
}

#[derive(Debug)]
pub enum NamespaceError {
    NotSupported(String),
    SyscallFailed(&'static str, std::io::Error),
    MountFailed(String, std::io::Error),
    ForkFailed(std::io::Error),
}

impl std::fmt::Display for NamespaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NamespaceError::NotSupported(msg) => write!(f, "Not supported: {}", msg),
            NamespaceError::SyscallFailed(op, e) => write!(f, "{} failed: {}", op, e),
            NamespaceError::MountFailed(p, e) => write!(f, "Mount {} failed: {}", p, e),
            NamespaceError::ForkFailed(e) => write!(f, "Fork failed: {}", e),
        }
    }
}

impl std::error::Error for NamespaceError {}

#[cfg(target_os = "linux")]
pub fn can_use_namespaces() -> bool {
    if let Ok(content) = fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        if content.trim() == "0" {
            debug!("User namespaces disabled via sysctl");
            return false;
        }
    }
    true
}

#[cfg(not(target_os = "linux"))]
pub fn can_use_namespaces() -> bool {
    false
}

#[cfg(target_os = "linux")]
pub fn enter_namespaces(config: &NamespaceConfig) -> Result<(), NamespaceError> {
    use std::ffi::CString;
    use std::ptr;

    let mut flags = 0;
    if config.isolate_pid {
        flags |= libc::CLONE_NEWPID;
    }
    if config.isolate_mount {
        flags |= libc::CLONE_NEWNS;
    }
    if config.isolate_network {
        flags |= libc::CLONE_NEWNET;
    }
    if config.isolate_ipc {
        flags |= libc::CLONE_NEWIPC;
    }
    if config.isolate_uts {
        flags |= libc::CLONE_NEWUTS;
    }
    if flags == 0 {
        info!("Namespace isolation disabled");
        return Ok(());
    }

    if unsafe { libc::unshare(flags) } != 0 {
        return Err(NamespaceError::SyscallFailed(
            "unshare",
            std::io::Error::last_os_error(),
        ));
    }

    if config.isolate_pid {
        let pid = unsafe { libc::fork() };
        match pid {
            -1 => {
                return Err(NamespaceError::ForkFailed(std::io::Error::last_os_error()));
            }
            0 => {
                debug!("Entered PID namespace (child)");
            }
            _ => {
                let mut status = 0;
                unsafe {
                    libc::waitpid(pid, &mut status, 0);
                }
                std::process::exit(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    1
                });
            }
        }
    }

    if config.isolate_mount {
        let _ = unsafe {
            libc::mount(
                ptr::null(),
                c"/".as_ptr(),
                ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                ptr::null(),
            )
        };

        for m in &config.bind_mounts {
            if !Path::new(&m.source).exists() {
                debug!(source = %m.source, "Skipping missing bind mount source");
                continue;
            }
            let _ = fs::create_dir_all(&m.target);
            let source = CString::new(m.source.as_str()).unwrap();
            let target = CString::new(m.target.as_str()).unwrap();
            let mut mflags = libc::MS_BIND | libc::MS_REC;
            if m.read_only {
                mflags |= libc::MS_RDONLY;
            }
            let res = unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    ptr::null(),
                    mflags,
                    ptr::null(),
                )
            };
            if res != 0 {
                warn!(
                    source = %m.source,
                    target = %m.target,
                    error = %std::io::Error::last_os_error(),
                    "Bind mount failed"
                );
            }
        }

        if config.read_only_root {
            let res = unsafe {
                libc::mount(
                    ptr::null(),
                    c"/".as_ptr(),
                    ptr::null(),
                    libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_BIND,
                    ptr::null(),
                )
            };
            if res != 0 {
                warn!(error = %std::io::Error::last_os_error(), "Failed to remount / read-only");
            }
        }
    }

    if config.isolate_uts {
        let hostname = b"winncore-sandbox\0";
        unsafe {
            libc::sethostname(hostname.as_ptr() as *const _, hostname.len() - 1);
        }
    }

    info!("Namespace isolation active");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enter_namespaces(_config: &NamespaceConfig) -> Result<(), NamespaceError> {
    warn!("Namespaces not available on this platform");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let cfg = NamespaceConfig::default();
        assert!(cfg.isolate_pid);
        assert!(cfg.isolate_mount);
    }
}
