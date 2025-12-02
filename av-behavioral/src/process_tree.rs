//! Process tree tracking.
//!
//! Maintains a view of running processes and their parent-child relationships.
//! Essential for detecting suspicious process ancestry (e.g., apache -> bash).

use std::collections::HashMap;

use av_ebpf_common::{ProcessExecEvent, ProcessExitEvent};
use tracing::debug;

/// Information about a running process.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub filename: String,
    pub start_time_ns: u64,
}

/// Tracks running processes and their relationships.
pub struct ProcessTree {
    processes: HashMap<u32, ProcessInfo>,
    /// Limit size to prevent unbounded growth from leaked PIDs
    max_processes: usize,
}

impl ProcessTree {
    pub fn new() -> Self {
        Self {
            processes: HashMap::with_capacity(10000),
            max_processes: 100000,
        }
    }

    /// Initialize from /proc at startup.
    /// Gives us a baseline of running processes before eBPF kicks in.
    pub fn init_from_proc(&mut self) -> std::io::Result<usize> {
        let mut count = 0;

        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Only numeric directories are PIDs
            if let Ok(pid) = name_str.parse::<u32>() {
                if let Ok(info) = self.read_proc_info(pid) {
                    self.processes.insert(pid, info);
                    count += 1;
                }
            }
        }

        debug!("Initialized process tree with {} processes", count);
        Ok(count)
    }

    fn read_proc_info(&self, pid: u32) -> std::io::Result<ProcessInfo> {
        let stat_path = format!("/proc/{}/stat", pid);
        let stat_content = std::fs::read_to_string(&stat_path)?;

        // Parse /proc/[pid]/stat
        // Format: pid (comm) state ppid ...
        // Comm can contain spaces and parens, so find the last ')'
        let comm_start = stat_content
            .find('(')
            .ok_or(std::io::ErrorKind::InvalidData)?;
        let comm_end = stat_content
            .rfind(')')
            .ok_or(std::io::ErrorKind::InvalidData)?;
        let comm = stat_content[comm_start + 1..comm_end].to_string();

        let rest = &stat_content[comm_end + 2..];
        let fields: Vec<&str> = rest.split_whitespace().collect();

        let ppid: u32 = fields.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

        // Get UID from /proc/[pid]/status
        let status_path = format!("/proc/{}/status", pid);
        let uid = if let Ok(status) = std::fs::read_to_string(&status_path) {
            status
                .lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        } else {
            0
        };

        // Get exe path
        let exe_path = format!("/proc/{}/exe", pid);
        let filename = std::fs::read_link(&exe_path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        Ok(ProcessInfo {
            pid,
            ppid,
            uid,
            gid: 0,
            comm,
            filename,
            start_time_ns: 0,
        })
    }

    /// Record a new process from execve event.
    pub fn add_process(&mut self, event: &ProcessExecEvent) {
        // Evict old entries if at capacity
        if self.processes.len() >= self.max_processes {
            // Simple strategy: remove random entry
            // Better: LRU or by start time
            if let Some(&pid) = self.processes.keys().next() {
                self.processes.remove(&pid);
            }
        }

        let info = ProcessInfo {
            pid: event.pid,
            ppid: event.ppid,
            uid: event.uid,
            gid: event.gid,
            comm: event.comm_str().to_string(),
            filename: event.filename_str().to_string(),
            start_time_ns: event.timestamp_ns,
        };

        self.processes.insert(event.pid, info);
    }

    /// Record process exit.
    pub fn remove_process(&mut self, event: &ProcessExitEvent) {
        self.processes.remove(&event.pid);
    }

    /// Get process info by PID.
    pub fn get_process(&self, pid: u32) -> Option<&ProcessInfo> {
        self.processes.get(&pid)
    }

    /// Get parent process's comm.
    pub fn get_parent_comm(&self, ppid: u32) -> Option<&str> {
        self.processes.get(&ppid).map(|p| p.comm.as_str())
    }

    /// Get the full ancestry chain (up to max_depth).
    pub fn get_ancestry(&self, pid: u32, max_depth: usize) -> Vec<&ProcessInfo> {
        let mut chain = Vec::new();
        let mut current_pid = pid;

        for _ in 0..max_depth {
            if let Some(info) = self.processes.get(&current_pid) {
                chain.push(info);
                if info.ppid == 0 || info.ppid == current_pid {
                    break; // Reached init or self-parent
                }
                current_pid = info.ppid;
            } else {
                break;
            }
        }

        chain
    }

    /// Check if a process is a descendant of another.
    pub fn is_descendant_of(&self, pid: u32, ancestor_comm: &str) -> bool {
        self.get_ancestry(pid, 20)
            .iter()
            .any(|p| p.comm == ancestor_comm)
    }

    /// Get count of tracked processes.
    pub fn len(&self) -> usize {
        self.processes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }
}
