#![cfg(feature = "behavior_monitor")]

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::maps::perf::AsyncPerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use av_ebpf_common::{
    BpfEvent, EventType, FileAccessEvent, KernelModuleEvent, NetworkConnectEvent, ProcessExecEvent,
    PtraceEvent, MAX_ARGS_LEN,
};

use crate::behavioral_pipeline::BehavioralEvent;

#[derive(Debug, Clone)]
pub struct EbpfMonitorConfig {
    pub enable_execve: bool,
    pub enable_execveat: bool,
    pub enable_connect: bool,
    pub enable_openat: bool,
    pub enable_ptrace: bool,
    pub enable_init_module: bool,
    pub buffer_pages: usize,
}

impl Default for EbpfMonitorConfig {
    fn default() -> Self {
        Self {
            enable_execve: true,
            enable_execveat: true,
            enable_connect: true,
            enable_openat: true,
            enable_ptrace: true,
            enable_init_module: true,
            buffer_pages: 64,
        }
    }
}

pub struct EbpfMonitorHandle {
    _bpf: aya::Ebpf,
}

pub struct EbpfMonitor {
    config: EbpfMonitorConfig,
    event_tx: mpsc::Sender<BehavioralEvent>,
}

impl EbpfMonitor {
    pub fn new(config: EbpfMonitorConfig, event_tx: mpsc::Sender<BehavioralEvent>) -> Self {
        Self { config, event_tx }
    }

    pub async fn start(self) -> Result<EbpfMonitorHandle> {
        let object_path = resolve_object_path()
            .context("eBPF object not found (set WINNCORE_EBPF_OBJECT or build av-ebpf-probes)")?;

        let attach = av_ebpf_loader::EbpfAttachConfig {
            execve: self.config.enable_execve,
            execveat: self.config.enable_execveat,
            connect: self.config.enable_connect,
            openat: self.config.enable_openat,
            ptrace: self.config.enable_ptrace,
            init_module: self.config.enable_init_module,
        };

        let load_cfg = av_ebpf_loader::EbpfLoadConfig {
            object_path,
            attach,
        };

        info!("Loading and attaching eBPF programs");
        let mut bpf = av_ebpf_loader::load_and_attach(&load_cfg)?;

        let events_map = bpf
            .take_map("EVENTS")
            .context("eBPF map `EVENTS` not found in object")?;
        let mut perf_array = AsyncPerfEventArray::try_from(events_map)
            .context("failed to open eBPF perf event array")?;

        let cpus = online_cpus()
            .map_err(|(context, err)| anyhow::anyhow!("online_cpus: {}: {}", context, err))?;
        info!(cpu_count = cpus.len(), "Starting eBPF perf buffers");

        for cpu_id in cpus {
            let mut buf = perf_array
                .open(cpu_id, Some(self.config.buffer_pages))
                .with_context(|| format!("failed to open perf buffer for CPU {}", cpu_id))?;

            let tx = self.event_tx.clone();
            tokio::spawn(async move {
                let mut buffers = (0..16)
                    .map(|_| BytesMut::with_capacity(std::mem::size_of::<BpfEvent>()))
                    .collect::<Vec<_>>();

                loop {
                    let events = match buf.read_events(&mut buffers).await {
                        Ok(events) => events,
                        Err(e) => {
                            error!(cpu_id, error = %e, "Error reading eBPF perf events");
                            continue;
                        }
                    };

                    for i in 0..events.read {
                        let bytes = buffers[i].as_ref();
                        if let Err(e) = dispatch_event(bytes, &tx).await {
                            debug!(cpu_id, error = %e, "Failed to dispatch eBPF event");
                        }
                    }
                }
            });
        }

        info!("eBPF monitor started");
        Ok(EbpfMonitorHandle { _bpf: bpf })
    }
}

async fn dispatch_event(bytes: &[u8], tx: &mpsc::Sender<BehavioralEvent>) -> Result<()> {
    if bytes.len() < std::mem::size_of::<BpfEvent>() {
        anyhow::bail!("short eBPF event ({} bytes)", bytes.len());
    }

    let event: BpfEvent = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const BpfEvent) };

    match event.event_type {
        EventType::ProcessExec => {
            let exec: ProcessExecEvent = unsafe { event.payload.process_exec };
            let tx = tx.clone();
            tokio::spawn(async move {
                let hydrated = hydrate_exec_event(exec).await;
                let _ = tx.send(BehavioralEvent::ProcessExecEbpf(hydrated)).await;
            });
        }
        EventType::NetworkConnect => {
            let net: NetworkConnectEvent = unsafe { event.payload.network_connect };
            tx.send(BehavioralEvent::NetworkConnect(net)).await?;
        }
        EventType::FileAccess => {
            let file: FileAccessEvent = unsafe { event.payload.file_access };
            tx.send(BehavioralEvent::FileAccess(file)).await?;
        }
        EventType::Ptrace => {
            let ptrace: PtraceEvent = unsafe { event.payload.ptrace };
            tx.send(BehavioralEvent::Ptrace(ptrace)).await?;
        }
        EventType::KernelModule => {
            let km: KernelModuleEvent = unsafe { event.payload.kernel_module };
            tx.send(BehavioralEvent::KernelModule(km)).await?;
        }
        _ => {
            debug!(event_type = ?event.event_type, "Ignoring unsupported eBPF event");
        }
    }

    Ok(())
}

async fn hydrate_exec_event(mut event: ProcessExecEvent) -> ProcessExecEvent {
    let pid = event.pid;

    // Best-effort fill-in: at syscall entry, /proc may still reflect the old image.
    let mut cmdline = String::new();
    let mut comm = String::new();
    let mut exe_path = String::new();

    for attempt in 0..12 {
        cmdline = read_proc_cmdline(pid).await;
        comm = read_proc_comm(pid).await;
        exe_path = read_proc_exe(pid).await;

        if !cmdline.is_empty() && !exe_path.is_empty() {
            break;
        }

        if attempt < 11 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    if let Some(ppid) = read_proc_ppid(pid).await {
        event.ppid = ppid;
    }

    if let Some((uid, gid)) = read_proc_uid_gid(pid).await {
        event.uid = uid;
        event.gid = gid;
    }

    if !comm.is_empty() {
        write_bytes(&mut event.comm, comm.as_bytes());
    }

    if !exe_path.is_empty() {
        write_bytes(&mut event.filename, exe_path.as_bytes());
    }

    if !cmdline.is_empty() {
        let bytes = cmdline.as_bytes();
        let len = bytes.len().min(MAX_ARGS_LEN.saturating_sub(1));
        event.args[..len].copy_from_slice(&bytes[..len]);
        event.args_len = len as u32;
    }

    event
}

fn write_bytes<const N: usize>(dest: &mut [u8; N], src: &[u8]) {
    dest.fill(0);
    let len = src.len().min(N.saturating_sub(1));
    dest[..len].copy_from_slice(&src[..len]);
}

async fn read_proc_comm(pid: u32) -> String {
    tokio::fs::read_to_string(format!("/proc/{}/comm", pid))
        .await
        .unwrap_or_default()
        .trim()
        .to_string()
}

async fn read_proc_cmdline(pid: u32) -> String {
    let bytes = tokio::fs::read(format!("/proc/{}/cmdline", pid))
        .await
        .unwrap_or_default();
    String::from_utf8_lossy(&bytes)
        .replace('\0', " ")
        .trim()
        .to_string()
}

async fn read_proc_exe(pid: u32) -> String {
    tokio::fs::read_link(format!("/proc/{}/exe", pid))
        .await
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

async fn read_proc_ppid(pid: u32) -> Option<u32> {
    let stat = tokio::fs::read_to_string(format!("/proc/{}/stat", pid))
        .await
        .ok()?;
    let close_paren = stat.rfind(')')?;
    let after_comm = &stat[close_paren + 2..];
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    fields.get(1).and_then(|s| s.parse().ok())
}

async fn read_proc_uid_gid(pid: u32) -> Option<(u32, u32)> {
    let status = tokio::fs::read_to_string(format!("/proc/{}/status", pid))
        .await
        .ok()?;
    let mut uid = None;
    let mut gid = None;
    for line in status.lines() {
        if line.starts_with("Uid:") {
            uid = line.split_whitespace().nth(1).and_then(|s| s.parse().ok());
        } else if line.starts_with("Gid:") {
            gid = line.split_whitespace().nth(1).and_then(|s| s.parse().ok());
        }
        if uid.is_some() && gid.is_some() {
            break;
        }
    }
    Some((uid?, gid?))
}

fn resolve_object_path() -> Option<PathBuf> {
    av_ebpf_loader::resolve_bpf_object_path()
}

pub fn ebpf_available() -> bool {
    if !std::path::Path::new("/sys/fs/bpf").exists() {
        return false;
    }

    // Best-effort kernel version check (5.8+ recommended).
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let parts: Vec<&str> = release.trim().split('.').collect();
    let (Ok(major), Ok(minor)) = (
        parts.get(0).unwrap_or(&"0").parse::<u32>(),
        parts.get(1).unwrap_or(&"0").parse::<u32>(),
    ) else {
        return true;
    };

    major > 5 || (major == 5 && minor >= 8)
}

pub fn has_ebpf_permissions() -> bool {
    unsafe { libc::geteuid() == 0 }
}
