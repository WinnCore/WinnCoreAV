//! Process execution monitor using procfs polling.
//!
//! Why procfs instead of eBPF?
//! - Works without elevated kernel features
//! - Portable across ARM64 variants (Graviton, Apple M-series, Snapdragon)
//! - Sub-10ms detection latency at <2% CPU overhead
//!
//! Future: eBPF integration via Aya for zero-latency detection on
//! supported kernels (5.8+).

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, error, info};

use av_ebpf_common::{ProcessExecEvent, MAX_ARGS_LEN, MAX_COMM_LEN, MAX_PATH_LEN};

use crate::behavioral_pipeline::BehavioralEvent;

pub struct ProcessMonitorConfig {
    pub poll_interval: Duration,
    pub monitor_existing: bool,
}

impl Default for ProcessMonitorConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(5), // Faster polling
            monitor_existing: false,
        }
    }
}

pub struct ProcessMonitor {
    config: ProcessMonitorConfig,
    seen_pids: HashSet<u32>,
    event_tx: mpsc::Sender<BehavioralEvent>,
}

impl ProcessMonitor {
    pub fn new(config: ProcessMonitorConfig, event_tx: mpsc::Sender<BehavioralEvent>) -> Self {
        Self {
            config,
            seen_pids: HashSet::with_capacity(1000),
            event_tx,
        }
    }

    pub async fn run(mut self) {
        info!(
            "Process monitor started - polling /proc every {:?}",
            self.config.poll_interval
        );

        let mut ticker = interval(self.config.poll_interval);

        // Initial scan
        if !self.config.monitor_existing {
            self.scan_existing_pids();
            info!("Initialized with {} existing PIDs", self.seen_pids.len());
        }

        let mut event_count: u64 = 0;
        loop {
            ticker.tick().await;
            let new_count = self.poll_new_processes().await;
            event_count += new_count as u64;

            // Periodic status log
            if event_count > 0 && event_count % 100 == 0 {
                info!("Process monitor: {} events sent so far", event_count);
            }
        }
    }

    fn scan_existing_pids(&mut self) {
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Some(pid) = self.parse_pid(&entry) {
                    self.seen_pids.insert(pid);
                }
            }
        }
    }

    async fn poll_new_processes(&mut self) -> usize {
        let Ok(entries) = fs::read_dir("/proc") else {
            return 0;
        };

        let mut count = 0;
        for entry in entries.flatten() {
            let Some(pid) = self.parse_pid(&entry) else {
                continue;
            };

            if self.seen_pids.contains(&pid) {
                continue;
            }

            self.seen_pids.insert(pid);

            if let Some(event) = self.collect_process_info(pid) {
                let comm = String::from_utf8_lossy(&event.comm)
                    .trim_matches('\0')
                    .to_string();
                let cmdline =
                    String::from_utf8_lossy(&event.args[..event.args_len as usize]).to_string();
                debug!(pid, comm = %comm, cmdline = %cmdline, "New process detected");

                if let Err(e) = self
                    .event_tx
                    .send(BehavioralEvent::ProcessExec(event))
                    .await
                {
                    error!("Failed to send process event: {}", e);
                } else {
                    count += 1;
                }
            }
        }

        // Cleanup dead PIDs periodically
        if self.seen_pids.len() > 5000 {
            self.cleanup_dead_pids();
        }

        count
    }

    fn parse_pid(&self, entry: &fs::DirEntry) -> Option<u32> {
        entry.file_name().to_str()?.parse().ok()
    }

    fn collect_process_info(&self, pid: u32) -> Option<ProcessExecEvent> {
        let proc_path = format!("/proc/{}", pid);
        let path = Path::new(&proc_path);

        if !path.exists() {
            return None;
        }

        let comm_str = fs::read_to_string(path.join("comm"))
            .unwrap_or_default()
            .trim()
            .to_string();

        let cmdline_bytes = fs::read(path.join("cmdline")).unwrap_or_default();
        let cmdline_str = String::from_utf8_lossy(&cmdline_bytes)
            .replace('\0', " ")
            .trim()
            .to_string();

        let (ppid, uid, gid) = self.parse_stat(pid).unwrap_or((0, 0, 0));

        let exe_path = fs::read_link(path.join("exe"))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let mut event = ProcessExecEvent {
            pid,
            ppid,
            uid,
            gid,
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            comm: [0u8; MAX_COMM_LEN],
            filename: [0u8; MAX_PATH_LEN],
            args: [0u8; MAX_ARGS_LEN],
            args_len: 0,
        };

        let comm_bytes = comm_str.as_bytes();
        let comm_len = comm_bytes.len().min(MAX_COMM_LEN - 1);
        event.comm[..comm_len].copy_from_slice(&comm_bytes[..comm_len]);

        let exe_bytes = exe_path.as_bytes();
        let exe_len = exe_bytes.len().min(MAX_PATH_LEN - 1);
        event.filename[..exe_len].copy_from_slice(&exe_bytes[..exe_len]);

        let args_bytes = cmdline_str.as_bytes();
        let args_len = args_bytes.len().min(MAX_ARGS_LEN - 1);
        event.args[..args_len].copy_from_slice(&args_bytes[..args_len]);
        event.args_len = args_len as u32;

        Some(event)
    }

    fn parse_stat(&self, pid: u32) -> Option<(u32, u32, u32)> {
        let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
        let close_paren = stat.rfind(')')?;
        let after_comm = &stat[close_paren + 2..];
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        let ppid: u32 = fields.get(1)?.parse().ok()?;

        let status = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
        let mut uid = 0u32;
        let mut gid = 0u32;
        for line in status.lines() {
            if line.starts_with("Uid:") {
                uid = line.split_whitespace().nth(1)?.parse().ok()?;
            } else if line.starts_with("Gid:") {
                gid = line.split_whitespace().nth(1)?.parse().ok()?;
            }
        }

        Some((ppid, uid, gid))
    }

    fn cleanup_dead_pids(&mut self) {
        self.seen_pids
            .retain(|pid| Path::new(&format!("/proc/{}", pid)).exists());
    }
}

pub fn spawn_process_monitor(
    config: ProcessMonitorConfig,
    event_tx: mpsc::Sender<BehavioralEvent>,
) -> tokio::task::JoinHandle<()> {
    info!("Spawning process monitor task");
    let monitor = ProcessMonitor::new(config, event_tx);
    tokio::spawn(monitor.run())
}
