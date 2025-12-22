//! Userspace eBPF loader helpers shared by the daemon and the standalone loader binary.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use aya::programs::KProbe;
use aya::Ebpf;
use tracing::{debug, info, warn};

pub const DEFAULT_OBJECT_ENV: &str = "WINNCORE_EBPF_OBJECT";

#[derive(Debug, Clone)]
pub struct EbpfAttachConfig {
    pub execve: bool,
    pub execveat: bool,
    pub connect: bool,
    pub openat: bool,
    pub ptrace: bool,
    pub init_module: bool,
}

impl Default for EbpfAttachConfig {
    fn default() -> Self {
        Self {
            execve: true,
            execveat: true,
            connect: true,
            openat: true,
            ptrace: true,
            init_module: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EbpfLoadConfig {
    pub object_path: PathBuf,
    pub attach: EbpfAttachConfig,
}

/// Attempts to resolve the eBPF object path used by `aya::Ebpf::load_file`.
pub fn resolve_bpf_object_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var(DEFAULT_OBJECT_ENV) {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }

    // Production install path.
    let candidates = [
        "/usr/lib/winncore/winncore-ebpf",
        "/usr/lib/winncore/winncore-ebpf.o",
        // Workspace default when building the probes crate locally.
        "av-ebpf-probes/target/bpfel-unknown-none/release/winncore-ebpf",
        "av-ebpf-probes/target/bpfel-unknown-none/debug/winncore-ebpf",
    ];

    for candidate in candidates {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Some(p);
        }
    }

    None
}

pub fn bump_memlock_rlimit() -> Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        let lim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };

        if libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim) != 0 {
            return Err(anyhow!(
                "setrlimit(RLIMIT_MEMLOCK) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    Ok(())
}

pub fn load_and_attach(config: &EbpfLoadConfig) -> Result<Ebpf> {
    bump_memlock_rlimit().ok();

    let mut bpf = Ebpf::load_file(&config.object_path).with_context(|| {
        format!(
            "failed to load eBPF object from {}",
            config.object_path.display()
        )
    })?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        debug!(error = %e, "eBPF logger not initialized");
    }

    if config.attach.execve {
        attach_kprobe_any(
            &mut bpf,
            "kprobe_execve",
            &["__x64_sys_execve", "__arm64_sys_execve", "__se_sys_execve"],
        )?;
    }

    if config.attach.execveat {
        attach_kprobe_any(
            &mut bpf,
            "kprobe_execveat",
            &[
                "__x64_sys_execveat",
                "__arm64_sys_execveat",
                "__se_sys_execveat",
            ],
        )?;
    }

    if config.attach.connect {
        attach_kprobe_any(
            &mut bpf,
            "kprobe_connect",
            &[
                "__x64_sys_connect",
                "__arm64_sys_connect",
                "__se_sys_connect",
            ],
        )?;
    }

    if config.attach.openat {
        attach_kprobe_any(
            &mut bpf,
            "kprobe_openat",
            &["__x64_sys_openat", "__arm64_sys_openat", "__se_sys_openat"],
        )?;
    }

    if config.attach.ptrace {
        attach_kprobe_any(
            &mut bpf,
            "kprobe_ptrace",
            &["__x64_sys_ptrace", "__arm64_sys_ptrace", "__se_sys_ptrace"],
        )?;
    }

    if config.attach.init_module {
        attach_kprobe_any(
            &mut bpf,
            "kprobe_init_module",
            &[
                "__x64_sys_init_module",
                "__arm64_sys_init_module",
                "__se_sys_init_module",
            ],
        )?;
    }

    Ok(bpf)
}

fn attach_kprobe_any(bpf: &mut Ebpf, program_name: &str, candidates: &[&str]) -> Result<()> {
    let program: &mut KProbe = bpf
        .program_mut(program_name)
        .with_context(|| format!("missing eBPF program `{}` in object", program_name))?
        .try_into()
        .with_context(|| format!("program `{}` is not a KProbe", program_name))?;

    program
        .load()
        .with_context(|| format!("failed to load `{}`", program_name))?;

    let mut last_err = None;
    for candidate in candidates {
        match program.attach(candidate, 0) {
            Ok(_) => {
                info!(
                    program = program_name,
                    target = *candidate,
                    "Attached kprobe"
                );
                return Ok(());
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    let detail = last_err
        .map(|e| e.to_string())
        .unwrap_or_else(|| "no candidates attempted".to_string());

    warn!(
        program = program_name,
        targets = ?candidates,
        error = %detail,
        "Failed to attach kprobe"
    );
    Err(anyhow!(
        "failed to attach kprobe `{}` to any target (last error: {})",
        program_name,
        detail
    ))
}
