#![allow(dead_code)]
//! Event consumers for eBPF ring buffers and procfs fallback.

use crate::bpf_types::{
    ConnectEventData, ExecEventData, ExitEventData, MmapEventData, OpenEventData, PtraceEventData,
    RawBpfEvent, EVENT_CONNECT, EVENT_EXEC, EVENT_EXIT, EVENT_MMAP, EVENT_OPEN, EVENT_PTRACE,
    MAX_FILENAME_LEN,
};
use crate::events::*;
use anyhow::Result;
use std::collections::HashSet;
use std::path::Path;
use tokio::sync::mpsc;
use tracing::{info, warn};

const BPF_PIN_PATH: &str = "/sys/fs/bpf/winncore";

/// Event consumer that reads from a pinned eBPF ring buffer.
pub struct EbpfEventConsumer {
    event_tx: mpsc::Sender<BehavioralEvent>,
}

impl EbpfEventConsumer {
    pub fn from_pinned(event_tx: mpsc::Sender<BehavioralEvent>) -> Result<Self> {
        let events_path = format!("{}/events", BPF_PIN_PATH);

        if !Path::new(&events_path).exists() {
            anyhow::bail!(
                "eBPF events map not found at {}. Is the loader running?",
                events_path
            );
        }

        // TODO: wire ring buffer consumption once pinned map layout is finalized.
        info!(
            "eBPF map present at {}; ring buffer consumer not yet wired",
            events_path
        );
        Ok(Self { event_tx })
    }

    pub async fn run(&mut self) -> Result<()> {
        warn!("eBPF consumer is a stub; no kernel events will be processed yet");
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        Ok(())
    }

    fn parse_event(data: &[u8]) -> Result<BehavioralEvent> {
        if data.len() < std::mem::size_of::<RawBpfEvent>() {
            anyhow::bail!("event payload too small");
        }

        let raw: &RawBpfEvent = unsafe { &*(data.as_ptr() as *const RawBpfEvent) };
        let event_type_id = raw.event_type;
        let pid = raw.pid;
        let uid = raw.uid;
        let gid = raw.gid;

        let event_type = match event_type_id {
            EVENT_EXEC => Self::parse_exec(raw)?,
            EVENT_EXIT => Self::parse_exit(raw)?,
            EVENT_OPEN => Self::parse_open(raw)?,
            EVENT_CONNECT => Self::parse_connect(raw)?,
            EVENT_MMAP => Self::parse_mmap(raw)?,
            EVENT_PTRACE => Self::parse_ptrace(raw)?,
            _ => anyhow::bail!("unknown event type {}", event_type_id),
        };

        let proc_path = format!("/proc/{}", pid);
        let exe_path = std::fs::read_link(format!("{}/exe", proc_path))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let cmdline = std::fs::read_to_string(format!("{}/cmdline", proc_path))
            .map(|s| s.replace('\0', " ").trim().to_string())
            .unwrap_or_default();
        let cwd = std::fs::read_link(format!("{}/cwd", proc_path))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let ppid = std::fs::read_to_string(format!("{}/stat", proc_path))
            .ok()
            .and_then(|s| s.split_whitespace().nth(3).and_then(|p| p.parse().ok()))
            .unwrap_or(0);

        Ok(BehavioralEvent {
            timestamp: chrono::Utc::now(),
            event_type,
            pid,
            ppid,
            uid,
            gid,
            comm: raw.comm_str().to_string(),
            exe_path,
            cmdline,
            cwd,
            severity: Severity::Info,
            mitre_techniques: vec![],
            raw_data: std::collections::HashMap::new(),
        })
    }

    fn parse_exec(raw: &RawBpfEvent) -> Result<EventType> {
        let data: &ExecEventData = unsafe { &*(raw.data.as_ptr() as *const ExecEventData) };
        let filename = string_from_bytes(&data.filename);
        Ok(EventType::ProcessExec(ProcessExecEvent {
            filename,
            args: Vec::new(),
            env_vars: std::collections::HashMap::new(),
            interpreter: None,
            is_script: false,
            is_setuid: false,
            is_setgid: false,
        }))
    }

    fn parse_exit(raw: &RawBpfEvent) -> Result<EventType> {
        let data: &ExitEventData = unsafe { &*(raw.data.as_ptr() as *const ExitEventData) };
        let exit_code = data.exit_code;
        Ok(EventType::ProcessExit(ProcessExitEvent {
            exit_code,
            signal: if exit_code > 128 {
                Some(exit_code - 128)
            } else {
                None
            },
        }))
    }

    fn parse_open(raw: &RawBpfEvent) -> Result<EventType> {
        let data: &OpenEventData = unsafe { &*(raw.data.as_ptr() as *const OpenEventData) };
        let filename = string_from_bytes(&data.filename);
        let flags = data.flags as u32;
        let is_sensitive = is_sensitive_path(&filename);
        Ok(EventType::FileOpen(FileOpenEvent {
            path: filename,
            flags,
            mode: 0,
            is_sensitive,
            is_executable: false,
        }))
    }

    fn parse_connect(raw: &RawBpfEvent) -> Result<EventType> {
        let data: &ConnectEventData = unsafe { &*(raw.data.as_ptr() as *const ConnectEventData) };
        let dst_addr = std::net::Ipv4Addr::from(data.dst_addr);
        let dst_port = u16::from_be(data.dst_port);

        let is_external = !dst_addr.is_private() && !dst_addr.is_loopback();

        Ok(EventType::NetworkConnect(NetworkConnectEvent {
            protocol: "tcp".to_string(),
            src_addr: String::new(),
            src_port: 0,
            dst_addr: dst_addr.to_string(),
            dst_port,
            is_external,
            is_known_bad: false,
            geo_info: None,
        }))
    }

    fn parse_mmap(raw: &RawBpfEvent) -> Result<EventType> {
        let data: &MmapEventData = unsafe { &*(raw.data.as_ptr() as *const MmapEventData) };
        let is_rwx = (data.prot & 0x7) == 0x7;

        Ok(EventType::MemoryMap(MemoryMapEvent {
            address: data.addr,
            length: data.len,
            protection: data.prot,
            flags: data.flags,
            is_anonymous: (data.flags & 0x20) != 0,
            is_rwx,
            backing_file: None,
        }))
    }

    fn parse_ptrace(raw: &RawBpfEvent) -> Result<EventType> {
        let data: &PtraceEventData = unsafe { &*(raw.data.as_ptr() as *const PtraceEventData) };

        Ok(EventType::SyscallAnomaly(SyscallAnomalyEvent {
            syscall_id: 101,
            syscall_name: "ptrace".into(),
            anomaly_type: SyscallAnomalyType::RareSyscall,
            args: vec![data.request as u64, data.target_pid as u64],
        }))
    }
}

/// Fallback to procfs when eBPF is unavailable.
pub struct ProcfsEventConsumer {
    event_tx: mpsc::Sender<BehavioralEvent>,
    known_pids: HashSet<u32>,
}

impl ProcfsEventConsumer {
    pub fn new(event_tx: mpsc::Sender<BehavioralEvent>) -> Self {
        Self {
            event_tx,
            known_pids: HashSet::new(),
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("Starting procfs fallback event consumer");
        warn!("eBPF unavailable - using procfs polling (reduced visibility)");

        loop {
            self.poll_processes().await?;
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    async fn poll_processes(&mut self) -> Result<()> {
        let current_pids: HashSet<u32> = std::fs::read_dir("/proc")?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str()?.parse().ok())
            .collect();

        for &pid in current_pids.difference(&self.known_pids) {
            if let Ok(event) = self.create_process_event(pid) {
                let _ = self.event_tx.send(event).await;
            }
        }

        self.known_pids = current_pids;
        Ok(())
    }

    fn create_process_event(&self, pid: u32) -> Result<BehavioralEvent> {
        let proc_path = format!("/proc/{}", pid);
        let exe_path = std::fs::read_link(format!("{}/exe", proc_path))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let cmdline = std::fs::read_to_string(format!("{}/cmdline", proc_path))
            .map(|s| s.replace('\0', " ").trim().to_string())
            .unwrap_or_default();
        let stat = std::fs::read_to_string(format!("{}/stat", proc_path))?;
        let parts: Vec<&str> = stat.split_whitespace().collect();
        let comm = parts
            .get(1)
            .map(|s| s.trim_matches(['(', ')']))
            .unwrap_or("")
            .to_string();
        let ppid: u32 = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);

        let status = std::fs::read_to_string(format!("{}/status", proc_path))?;
        let uid: u32 = status
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Ok(BehavioralEvent {
            timestamp: chrono::Utc::now(),
            event_type: EventType::ProcessExec(ProcessExecEvent {
                filename: exe_path.clone(),
                args: cmdline.split_whitespace().map(String::from).collect(),
                env_vars: std::collections::HashMap::new(),
                interpreter: None,
                is_script: false,
                is_setuid: false,
                is_setgid: false,
            }),
            pid,
            ppid,
            uid,
            gid: 0,
            comm,
            exe_path,
            cmdline,
            cwd: std::fs::read_link(format!("{}/cwd", proc_path))
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            severity: Severity::Info,
            mitre_techniques: vec![],
            raw_data: std::collections::HashMap::new(),
        })
    }
}

fn string_from_bytes(bytes: &[u8]) -> String {
    let nul = bytes
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(MAX_FILENAME_LEN.min(bytes.len()));
    String::from_utf8_lossy(&bytes[..nul]).to_string()
}

fn is_sensitive_path(path: &str) -> bool {
    const SENSITIVE: &[&str] = &[
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/.ssh/",
        "/.aws/",
    ];
    SENSITIVE.iter().any(|p| path.contains(p))
}
