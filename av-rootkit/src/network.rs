use std::collections::HashSet;
use std::fs;
use tracing::warn;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct NetworkConnection {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
}

#[derive(Debug, Clone)]
pub struct HiddenConnectionResult {
    pub proc_connections: HashSet<NetworkConnection>,
    pub ss_connections: HashSet<NetworkConnection>,
    pub hidden_connections: Vec<NetworkConnection>,
}

pub fn scan_hidden_connections() -> HiddenConnectionResult {
    let proc_conns = get_proc_net_connections();
    let ss_conns = HashSet::new(); // placeholder
    let mut hidden = Vec::new();
    for conn in &ss_conns {
        if !proc_conns.contains(conn) {
            warn!(
                "Connection present in ss but missing from /proc: {:?}",
                conn
            );
            hidden.push(conn.clone());
        }
    }
    HiddenConnectionResult {
        proc_connections: proc_conns,
        ss_connections: ss_conns,
        hidden_connections: hidden,
    }
}

fn get_proc_net_connections() -> HashSet<NetworkConnection> {
    let mut connections = HashSet::new();
    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        for line in content.lines().skip(1) {
            if let Some(conn) = parse_proc_net_line(line) {
                connections.insert(conn);
            }
        }
    }
    connections
}

fn parse_proc_net_line(line: &str) -> Option<NetworkConnection> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let (local_addr, local_port) = parse_addr_port(parts[1])?;
    let (remote_addr, remote_port) = parse_addr_port(parts[2])?;
    Some(NetworkConnection {
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        state: parts[3].to_string(),
    })
}

fn parse_addr_port(s: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let port = u16::from_str_radix(parts[1], 16).ok()?;
    let addr_hex = parts[0];
    if addr_hex.len() == 8 {
        let addr_int = u32::from_str_radix(addr_hex, 16).ok()?;
        let octets = addr_int.to_le_bytes();
        let addr = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
        return Some((addr, port));
    }
    Some((addr_hex.to_string(), port))
}
