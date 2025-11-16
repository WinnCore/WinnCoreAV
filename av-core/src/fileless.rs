//! Fileless malware detection
//!
//! This module detects advanced in-memory execution techniques including:
//! - memfd_create() for memory-resident executables
//! - Process injection (ptrace, /proc/pid/mem writes)
//! - Reflective DLL injection
//! - Shellcode execution in memory

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FilelessTechnique {
    /// memfd_create() system call - creates anonymous file in RAM
    MemfdCreate,
    /// Process injection via ptrace
    PtraceInjection,
    /// Direct memory write to /proc/pid/mem
    ProcMemWrite,
    /// Execution from /dev/shm (shared memory)
    ShmExecution,
    /// Execution from /tmp with execute permission
    TmpExecution,
    /// Python/Perl/Ruby executing from stdin
    StdinExecution,
    /// Base64 decode piped to bash
    Base64Execution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilelessEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub target_pid: Option<u32>,
    pub comm: String,
    pub technique: FilelessTechnique,
    pub details: String,
    pub suspicion_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilelessDetector {
    /// Track memfd file descriptors by PID
    memfd_fds: HashMap<u32, Vec<(i32, u64)>>, // PID -> [(fd, timestamp)]
    /// Track processes being injected into
    injection_targets: HashMap<u32, Vec<u32>>, // target_pid -> [attacker_pids]
}

impl FilelessDetector {
    pub fn new() -> Self {
        Self {
            memfd_fds: HashMap::new(),
            injection_targets: HashMap::new(),
        }
    }

    /// Detect memfd_create usage
    pub fn detect_memfd_create(
        &mut self,
        pid: u32,
        comm: &str,
        fd: i32,
        timestamp: u64,
    ) -> FilelessEvent {
        // Track this memfd for later execve detection
        self.memfd_fds
            .entry(pid)
            .or_insert_with(Vec::new)
            .push((fd, timestamp));

        FilelessEvent {
            timestamp,
            pid,
            target_pid: None,
            comm: comm.to_string(),
            technique: FilelessTechnique::MemfdCreate,
            details: format!("Created memory-resident file descriptor {}", fd),
            suspicion_score: 0.85, // High suspicion but not necessarily malicious
        }
    }

    /// Detect process injection via ptrace
    pub fn detect_ptrace_injection(
        &mut self,
        attacker_pid: u32,
        attacker_comm: &str,
        target_pid: u32,
        timestamp: u64,
    ) -> FilelessEvent {
        // Track injection attempts
        self.injection_targets
            .entry(target_pid)
            .or_insert_with(Vec::new)
            .push(attacker_pid);

        let suspicion_score = self.calculate_injection_score(attacker_comm, target_pid);

        FilelessEvent {
            timestamp,
            pid: attacker_pid,
            target_pid: Some(target_pid),
            comm: attacker_comm.to_string(),
            technique: FilelessTechnique::PtraceInjection,
            details: format!(
                "Process {} attempting ptrace injection into PID {}",
                attacker_pid, target_pid
            ),
            suspicion_score,
        }
    }

    /// Detect direct memory writes to /proc/pid/mem
    pub fn detect_proc_mem_write(
        &mut self,
        attacker_pid: u32,
        attacker_comm: &str,
        target_pid: u32,
        bytes_written: usize,
        timestamp: u64,
    ) -> FilelessEvent {
        let suspicion_score = if bytes_written > 4096 {
            0.95 // Large writes are very suspicious
        } else {
            0.85
        };

        FilelessEvent {
            timestamp,
            pid: attacker_pid,
            target_pid: Some(target_pid),
            comm: attacker_comm.to_string(),
            technique: FilelessTechnique::ProcMemWrite,
            details: format!(
                "Wrote {} bytes to /proc/{}/mem",
                bytes_written, target_pid
            ),
            suspicion_score,
        }
    }

    /// Detect execution from shared memory
    pub fn detect_shm_execution(
        pid: u32,
        comm: &str,
        shm_path: &str,
        timestamp: u64,
    ) -> FilelessEvent {
        FilelessEvent {
            timestamp,
            pid,
            target_pid: None,
            comm: comm.to_string(),
            technique: FilelessTechnique::ShmExecution,
            details: format!("Executing from shared memory: {}", shm_path),
            suspicion_score: 0.90,
        }
    }

    /// Detect suspicious /tmp execution
    pub fn detect_tmp_execution(
        pid: u32,
        comm: &str,
        tmp_path: &str,
        timestamp: u64,
    ) -> FilelessEvent {
        // Check if it's a random name (likely malicious)
        let is_random = tmp_path
            .chars()
            .filter(|c| c.is_alphanumeric())
            .take(8)
            .collect::<String>()
            .chars()
            .all(|c| c.is_ascii_hexdigit());

        let suspicion_score = if is_random { 0.80 } else { 0.60 };

        FilelessEvent {
            timestamp,
            pid,
            target_pid: None,
            comm: comm.to_string(),
            technique: FilelessTechnique::TmpExecution,
            details: format!("Executing from /tmp: {}", tmp_path),
            suspicion_score,
        }
    }

    /// Detect stdin execution (python -c, bash -c from pipe)
    pub fn detect_stdin_execution(
        pid: u32,
        comm: &str,
        command: &str,
        timestamp: u64,
    ) -> FilelessEvent {
        FilelessEvent {
            timestamp,
            pid,
            target_pid: None,
            comm: comm.to_string(),
            technique: FilelessTechnique::StdinExecution,
            details: format!("Executing from stdin: {}", command),
            suspicion_score: 0.75,
        }
    }

    /// Detect base64 decode to execution
    pub fn detect_base64_execution(
        pid: u32,
        comm: &str,
        details: &str,
        timestamp: u64,
    ) -> FilelessEvent {
        FilelessEvent {
            timestamp,
            pid,
            target_pid: None,
            comm: comm.to_string(),
            technique: FilelessTechnique::Base64Execution,
            details: details.to_string(),
            suspicion_score: 0.88,
        }
    }

    /// Calculate injection suspicion score based on context
    fn calculate_injection_score(&self, attacker_comm: &str, target_pid: u32) -> f32 {
        // Legitimate debuggers have lower suspicion
        let legitimate_debuggers = ["gdb", "lldb", "strace", "ltrace"];
        if legitimate_debuggers.contains(&attacker_comm) {
            return 0.30; // Low suspicion for debuggers
        }

        // Check if this target is being attacked by multiple processes
        let attack_count = self
            .injection_targets
            .get(&target_pid)
            .map(|v| v.len())
            .unwrap_or(0);

        if attack_count > 2 {
            0.98 // Very high suspicion - coordinated attack
        } else if attack_count > 1 {
            0.90 // High suspicion - multiple attackers
        } else {
            0.85 // Medium-high suspicion
        }
    }

    /// Get statistics on fileless activity
    pub fn get_stats(&self) -> FilelessStats {
        let total_memfd_processes = self.memfd_fds.len();
        let total_injection_targets = self.injection_targets.len();

        let total_memfd_fds: usize = self.memfd_fds.values().map(|v| v.len()).sum();

        FilelessStats {
            total_memfd_processes,
            total_memfd_fds,
            total_injection_targets,
        }
    }

    /// Clean up old tracking data
    pub fn cleanup_old_data(&mut self, current_time: u64, window_secs: u64) {
        let cutoff = current_time.saturating_sub(window_secs);

        // Clean memfd tracking
        for fds in self.memfd_fds.values_mut() {
            fds.retain(|(_, timestamp)| *timestamp >= cutoff);
        }
        self.memfd_fds.retain(|_, fds| !fds.is_empty());
    }
}

impl Default for FilelessDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilelessStats {
    pub total_memfd_processes: usize,
    pub total_memfd_fds: usize,
    pub total_injection_targets: usize,
}

/// Parse fileless event from log line
/// Format examples:
/// [timestamp] [PID:comm] MEMFD_CREATE: fd=3
/// [timestamp] [PID:comm] PTRACE: target_pid=1234
/// [timestamp] [PID:comm] PROC_MEM_WRITE: target_pid=1234 bytes=4096
pub fn parse_fileless_event(line: &str) -> Option<FilelessEvent> {
    let parts: Vec<&str> = line.split(']').collect();
    if parts.len() < 3 {
        return None;
    }

    // Extract timestamp
    let timestamp: u64 = parts[0].trim_start_matches('[').trim().parse().ok()?;

    // Extract PID and comm
    let pid_comm_str = parts[1].trim_start_matches('[').trim();
    let pid_comm_parts: Vec<&str> = pid_comm_str.split(':').collect();
    if pid_comm_parts.len() < 3 {
        return None;
    }

    let pid: u32 = pid_comm_parts[1].parse().ok()?;
    let comm = pid_comm_parts[2].to_string();

    // Extract event details
    let details = parts[2..].join("]").trim().to_string();

    // Determine technique type
    if details.contains("MEMFD_CREATE") || details.contains("memfd_create") {
        let fd = details
            .split("fd=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(0);

        let mut detector = FilelessDetector::new();
        return Some(detector.detect_memfd_create(pid, &comm, fd, timestamp));
    }

    if details.contains("PTRACE") || details.contains("ptrace") {
        let target_pid = details
            .split("target_pid=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let mut detector = FilelessDetector::new();
        return Some(detector.detect_ptrace_injection(pid, &comm, target_pid, timestamp));
    }

    if details.contains("PROC_MEM_WRITE") || details.contains("proc_mem_write") {
        let target_pid = details
            .split("target_pid=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let bytes = details
            .split("bytes=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);

        let mut detector = FilelessDetector::new();
        return Some(detector.detect_proc_mem_write(pid, &comm, target_pid, bytes, timestamp));
    }

    if details.contains("/dev/shm/") {
        let path = details
            .split("/dev/shm/")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("unknown");
        return Some(FilelessDetector::detect_shm_execution(
            pid,
            &comm,
            &format!("/dev/shm/{}", path),
            timestamp,
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memfd_detection() {
        let mut detector = FilelessDetector::new();
        let event = detector.detect_memfd_create(1234, "malware", 3, 1700000000);

        assert_eq!(event.technique, FilelessTechnique::MemfdCreate);
        assert_eq!(event.pid, 1234);
        assert!(event.suspicion_score >= 0.8);
    }

    #[test]
    fn test_ptrace_injection() {
        let mut detector = FilelessDetector::new();
        let event = detector.detect_ptrace_injection(1234, "attacker", 5678, 1700000000);

        assert_eq!(event.technique, FilelessTechnique::PtraceInjection);
        assert_eq!(event.target_pid, Some(5678));
        assert!(event.suspicion_score >= 0.8);
    }

    #[test]
    fn test_gdb_low_suspicion() {
        let mut detector = FilelessDetector::new();
        let event = detector.detect_ptrace_injection(1234, "gdb", 5678, 1700000000);

        // GDB should have low suspicion score
        assert!(event.suspicion_score < 0.5);
    }

    #[test]
    fn test_proc_mem_write() {
        let mut detector = FilelessDetector::new();
        let event = detector.detect_proc_mem_write(1234, "injector", 5678, 8192, 1700000000);

        assert_eq!(event.technique, FilelessTechnique::ProcMemWrite);
        assert!(event.suspicion_score >= 0.9); // Large write = high suspicion
    }

    #[test]
    fn test_shm_execution() {
        let event =
            FilelessDetector::detect_shm_execution(1234, "malware", "/dev/shm/evil", 1700000000);

        assert_eq!(event.technique, FilelessTechnique::ShmExecution);
        assert!(event.suspicion_score >= 0.8);
    }
}
