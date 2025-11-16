//! Network behavior detection for C2 (Command and Control) communication
//!
//! This module analyzes network activity patterns to detect malicious communications
//! including beaconing, data exfiltration, and connections to known malicious IPs.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub comm: String,
    pub event_type: NetworkEventType,
    pub remote_ip: String,
    pub remote_port: u16,
    pub bytes_sent: usize,
    pub suspicion_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NetworkEventType {
    /// Periodic beaconing to remote server
    Beacon,
    /// Connection to known malicious IP
    MaliciousIP,
    /// Large data upload (potential exfiltration)
    DataExfiltration,
    /// Connection to suspicious port
    SuspiciousPort,
    /// DNS tunneling attempt
    DnsTunneling,
    /// Reverse shell connection
    ReverseShell,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Pattern {
    pub pattern_type: String,
    pub description: String,
    pub indicators: Vec<String>,
    pub suspicion_score: f32,
}

/// Known malicious IP addresses and ranges
pub struct MaliciousIPList {
    ips: HashSet<String>,
}

impl MaliciousIPList {
    pub fn new() -> Self {
        let mut ips = HashSet::new();

        // Example malicious IPs (these would be updated from threat intel feeds)
        // Using private IPs for testing - in production these would be real threat IPs
        ips.insert("192.0.2.1".to_string()); // TEST-NET-1
        ips.insert("198.51.100.1".to_string()); // TEST-NET-2
        ips.insert("203.0.113.1".to_string()); // TEST-NET-3

        // Common C2 infrastructure IPs (example placeholder ranges)
        ips.insert("1.2.3.4".to_string());
        ips.insert("5.6.7.8".to_string());
        ips.insert("evil.com".to_string());

        Self { ips }
    }

    /// Load malicious IPs from a file or threat intelligence feed
    pub fn load_from_file(&mut self, path: &str) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(path)?;
        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                self.ips.insert(line.to_string());
            }
        }
        Ok(())
    }

    /// Check if an IP is in the malicious list
    pub fn is_malicious(&self, ip: &str) -> bool {
        self.ips.contains(ip)
    }

    /// Add an IP to the malicious list
    pub fn add_ip(&mut self, ip: String) {
        self.ips.insert(ip);
    }
}

impl Default for MaliciousIPList {
    fn default() -> Self {
        Self::new()
    }
}

/// Suspicious ports commonly used by malware
const SUSPICIOUS_PORTS: &[u16] = &[
    4444,  // Common Metasploit default
    5555,  // Common reverse shell
    6666,  // Common malware C2
    7777,  // Common malware C2
    8888,  // Common malware C2
    9999,  // Common malware C2
    31337, // Elite/leet port
    12345, // NetBus
    54321, // Back Orifice
];

/// Network behavior analyzer
pub struct NetworkMonitor {
    malicious_ips: MaliciousIPList,
    /// Connection history for beacon detection: (IP, port) -> timestamps
    connection_history: HashMap<(String, u16), Vec<u64>>,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        Self {
            malicious_ips: MaliciousIPList::new(),
            connection_history: HashMap::new(),
        }
    }

    /// Load malicious IP list from file
    pub fn load_malicious_ips(&mut self, path: &str) -> anyhow::Result<()> {
        self.malicious_ips.load_from_file(path)
    }

    /// Analyze a network connection for suspicious patterns
    pub fn analyze_connection(
        &mut self,
        pid: u32,
        comm: &str,
        remote_ip: &str,
        remote_port: u16,
        bytes_sent: usize,
        timestamp: u64,
    ) -> Option<NetworkEvent> {
        let mut suspicion_score = 0.0f32;
        let mut event_type = None;

        // Check 1: Known malicious IP
        if self.malicious_ips.is_malicious(remote_ip) {
            suspicion_score = 0.95;
            event_type = Some(NetworkEventType::MaliciousIP);
        }

        // Check 2: Suspicious port
        if SUSPICIOUS_PORTS.contains(&remote_port) {
            suspicion_score = suspicion_score.max(0.85);
            if event_type.is_none() {
                event_type = Some(NetworkEventType::SuspiciousPort);
            }
        }

        // Check 3: Large data transfer (potential exfiltration)
        if bytes_sent > 10 * 1024 * 1024 {
            // > 10MB
            suspicion_score = suspicion_score.max(0.70);
            if event_type.is_none() {
                event_type = Some(NetworkEventType::DataExfiltration);
            }
        }

        // Check 4: Beaconing detection
        let key = (remote_ip.to_string(), remote_port);
        self.connection_history
            .entry(key.clone())
            .or_insert_with(Vec::new)
            .push(timestamp);

        if let Some(timestamps) = self.connection_history.get(&key) {
            if self.is_beaconing(timestamps) {
                suspicion_score = suspicion_score.max(0.80);
                if event_type.is_none() {
                    event_type = Some(NetworkEventType::Beacon);
                }
            }
        }

        // Check 5: Reverse shell patterns (common ports + shell process names)
        if self.is_reverse_shell(comm, remote_port) {
            suspicion_score = suspicion_score.max(0.90);
            event_type = Some(NetworkEventType::ReverseShell);
        }

        // Only create event if something suspicious was found
        if let Some(evt_type) = event_type {
            Some(NetworkEvent {
                timestamp,
                pid,
                comm: comm.to_string(),
                event_type: evt_type,
                remote_ip: remote_ip.to_string(),
                remote_port,
                bytes_sent,
                suspicion_score,
            })
        } else {
            None
        }
    }

    /// Detect beaconing behavior: regular, periodic connections
    fn is_beaconing(&self, timestamps: &[u64]) -> bool {
        if timestamps.len() < 3 {
            return false; // Need at least 3 connections to detect pattern
        }

        // Calculate intervals between connections
        let mut intervals = Vec::new();
        for i in 1..timestamps.len() {
            intervals.push(timestamps[i] - timestamps[i - 1]);
        }

        // Check if intervals are regular (within 20% variance)
        if intervals.len() < 2 {
            return false;
        }

        let avg_interval = intervals.iter().sum::<u64>() / intervals.len() as u64;
        if avg_interval == 0 {
            return false;
        }

        let max_variance = avg_interval / 5; // 20% variance

        for &interval in &intervals {
            if interval.abs_diff(avg_interval) > max_variance {
                return false; // Too much variance
            }
        }

        // Intervals are regular - likely beaconing
        true
    }

    /// Detect reverse shell patterns
    fn is_reverse_shell(&self, comm: &str, port: u16) -> bool {
        let shell_names = ["bash", "sh", "zsh", "dash", "nc", "ncat", "socat"];

        // Shell process connecting to suspicious port
        if shell_names.contains(&comm) && SUSPICIOUS_PORTS.contains(&port) {
            return true;
        }

        // Netcat variants on any non-standard port
        if ["nc", "ncat", "socat"].contains(&comm) && port > 1024 && port != 8080 && port != 8443 {
            return true;
        }

        false
    }

    /// Get network statistics
    pub fn get_stats(&self) -> NetworkStats {
        let total_connections = self.connection_history.len();
        let mut beaconing_connections = 0;

        for timestamps in self.connection_history.values() {
            if self.is_beaconing(timestamps) {
                beaconing_connections += 1;
            }
        }

        NetworkStats {
            total_connections,
            beaconing_connections,
            malicious_ip_count: self.malicious_ips.ips.len(),
        }
    }

    /// Clear old connection history (older than window)
    pub fn cleanup_old_connections(&mut self, current_time: u64, window_secs: u64) {
        let cutoff = current_time.saturating_sub(window_secs);

        self.connection_history.retain(|_, timestamps| {
            timestamps.retain(|&ts| ts >= cutoff);
            !timestamps.is_empty()
        });
    }
}

impl Default for NetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub total_connections: usize,
    pub beaconing_connections: usize,
    pub malicious_ip_count: usize,
}

/// Parse network event from log line
/// Format: [timestamp] [PID:comm] NETWORK: remote_ip:port bytes_sent
pub fn parse_network_event(line: &str) -> Option<NetworkEvent> {
    // Example: [1700000000] [PID:1234:bash] NETWORK: 1.2.3.4:4444 512 bytes
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

    // Extract network details
    let network_part = parts[2..].join("]");
    if !network_part.contains("NETWORK:") {
        return None;
    }

    let network_details: Vec<&str> = network_part.split_whitespace().collect();
    if network_details.len() < 2 {
        return None;
    }

    // Parse IP:port
    let ip_port: Vec<&str> = network_details[1].split(':').collect();
    if ip_port.len() != 2 {
        return None;
    }

    let remote_ip = ip_port[0].to_string();
    let remote_port: u16 = ip_port[1].parse().ok()?;

    // Parse bytes
    let bytes_sent = network_details
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Determine event type and score based on IP and port
    let mut monitor = NetworkMonitor::new();
    monitor.analyze_connection(pid, &comm, &remote_ip, remote_port, bytes_sent, timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malicious_ip_detection() {
        let mut monitor = NetworkMonitor::new();
        // Use a non-shell process to test pure malicious IP detection
        let event = monitor.analyze_connection(
            1234,
            "python",
            "1.2.3.4",
            8080,
            100,
            1700000000,
        );

        assert!(event.is_some());
        let event = event.unwrap();
        assert_eq!(event.event_type, NetworkEventType::MaliciousIP);
        assert!(event.suspicion_score >= 0.9);
    }

    #[test]
    fn test_suspicious_port_detection() {
        let mut monitor = NetworkMonitor::new();
        let event = monitor.analyze_connection(
            1234,
            "python",
            "8.8.8.8",
            4444,
            100,
            1700000000,
        );

        assert!(event.is_some());
        let event = event.unwrap();
        assert_eq!(event.event_type, NetworkEventType::SuspiciousPort);
    }

    #[test]
    fn test_beaconing_detection() {
        let mut monitor = NetworkMonitor::new();

        // Simulate regular connections every 60 seconds
        let base_time = 1700000000u64;
        for i in 0..5 {
            monitor.analyze_connection(
                1234,
                "malware",
                "10.0.0.1",
                8080,
                100,
                base_time + (i * 60),
            );
        }

        let stats = monitor.get_stats();
        assert_eq!(stats.beaconing_connections, 1);
    }

    #[test]
    fn test_reverse_shell_detection() {
        let mut monitor = NetworkMonitor::new();
        let event = monitor.analyze_connection(
            1234,
            "bash",
            "10.0.0.1",
            4444,
            100,
            1700000000,
        );

        assert!(event.is_some());
        let event = event.unwrap();
        assert_eq!(event.event_type, NetworkEventType::ReverseShell);
        assert!(event.suspicion_score >= 0.85);
    }
}
