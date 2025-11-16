//! Process tree analysis for detecting suspicious parent-child relationships
//!
//! This module detects Living Off The Land (LOTL) attacks by identifying
//! unusual process chains like web servers spawning shells or cron jobs
//! executing network tools.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTree {
    pub pid: u32,
    pub name: String,
    pub parent_pid: u32,
    pub parent_name: Option<String>,
    pub chain: Vec<ProcessNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRelationship {
    pub parent: String,
    pub child: String,
    pub suspicion_score: f32,
    pub reason: String,
}

/// Builds a process tree by walking up the parent chain from a given PID
pub fn build_process_tree(pid: u32) -> anyhow::Result<ProcessTree> {
    let mut chain = Vec::new();
    let mut current_pid = pid;
    let process_name = get_process_name(pid)?;

    // Walk up the parent chain (max 10 levels to prevent infinite loops)
    for _ in 0..10 {
        let name = get_process_name(current_pid).unwrap_or_else(|_| "unknown".to_string());
        chain.push(ProcessNode {
            pid: current_pid,
            name: name.clone(),
        });

        match get_parent_pid(current_pid) {
            Ok(ppid) if ppid > 1 => current_pid = ppid,
            _ => break,
        }
    }

    let parent_pid = get_parent_pid(pid)?;
    let parent_name = get_process_name(parent_pid).ok();

    Ok(ProcessTree {
        pid,
        name: process_name,
        parent_pid,
        parent_name,
        chain,
    })
}

/// Reads the process name from /proc/PID/comm
fn get_process_name(pid: u32) -> anyhow::Result<String> {
    let comm_path = format!("/proc/{}/comm", pid);
    let name = fs::read_to_string(&comm_path)?
        .trim()
        .to_string();
    Ok(name)
}

/// Reads the parent PID from /proc/PID/status
fn get_parent_pid(pid: u32) -> anyhow::Result<u32> {
    let status_path = format!("/proc/{}/status", pid);

    if !Path::new(&status_path).exists() {
        anyhow::bail!("Process {} does not exist", pid);
    }

    let status = fs::read_to_string(&status_path)?;

    for line in status.lines() {
        if line.starts_with("PPid:") {
            let ppid_str = line.split_whitespace()
                .nth(1)
                .ok_or_else(|| anyhow::anyhow!("Failed to parse PPid"))?;
            return ppid_str.parse::<u32>()
                .map_err(|e| anyhow::anyhow!("Failed to parse PPid: {}", e));
        }
    }

    anyhow::bail!("PPid not found in /proc/{}/status", pid)
}

/// Analyzes a parent-child relationship and returns suspicion score
pub fn analyze_relationship(parent: &str, child: &str) -> Option<ProcessRelationship> {
    let patterns = get_suspicious_patterns();

    // Check if this parent-child combination is suspicious
    let key = format!("{}→{}", parent, child);

    // Exact match
    if let Some(&(score, reason)) = patterns.get(key.as_str()) {
        return Some(ProcessRelationship {
            parent: parent.to_string(),
            child: child.to_string(),
            suspicion_score: score,
            reason: reason.to_string(),
        });
    }

    // Partial matches using pattern matching
    for (pattern_key, &(score, reason)) in &patterns {
        if pattern_matches(pattern_key, parent, child) {
            return Some(ProcessRelationship {
                parent: parent.to_string(),
                child: child.to_string(),
                suspicion_score: score,
                reason: reason.to_string(),
            });
        }
    }

    None
}

/// Pattern matching for flexible parent→child detection
fn pattern_matches(pattern: &str, parent: &str, child: &str) -> bool {
    let parts: Vec<&str> = pattern.split('→').collect();
    if parts.len() != 2 {
        return false;
    }

    let parent_pattern = parts[0];
    let child_pattern = parts[1];

    pattern_component_matches(parent_pattern, parent) &&
    pattern_component_matches(child_pattern, child)
}

fn pattern_component_matches(pattern: &str, process: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.starts_with('*') && pattern.ends_with('*') {
        let core = &pattern[1..pattern.len()-1];
        return process.contains(core);
    }

    if pattern.starts_with('*') {
        return process.ends_with(&pattern[1..]);
    }

    if pattern.ends_with('*') {
        return process.starts_with(&pattern[..pattern.len()-1]);
    }

    pattern == process
}

/// Database of suspicious parent→child process patterns
fn get_suspicious_patterns() -> HashMap<&'static str, (f32, &'static str)> {
    let mut patterns = HashMap::new();

    // Web servers spawning shells (high risk)
    patterns.insert("apache2→bash", (0.95, "Web server spawning bash shell"));
    patterns.insert("apache2→sh", (0.95, "Web server spawning sh shell"));
    patterns.insert("nginx→bash", (0.95, "Nginx spawning bash shell"));
    patterns.insert("nginx→sh", (0.95, "Nginx spawning sh shell"));
    patterns.insert("httpd→bash", (0.95, "HTTP daemon spawning bash shell"));
    patterns.insert("httpd→sh", (0.95, "HTTP daemon spawning sh shell"));
    patterns.insert("php-fpm→bash", (0.90, "PHP-FPM spawning bash shell"));
    patterns.insert("php-fpm→sh", (0.90, "PHP-FPM spawning sh shell"));

    // Cron spawning network tools (medium-high risk)
    patterns.insert("cron→curl", (0.85, "Cron job executing curl"));
    patterns.insert("cron→wget", (0.85, "Cron job executing wget"));
    patterns.insert("cron→nc", (0.90, "Cron job executing netcat"));
    patterns.insert("cron→ncat", (0.90, "Cron job executing ncat"));
    patterns.insert("cron→bash", (0.75, "Cron job spawning bash shell"));

    // Init/systemd spawning unusual binaries (medium risk)
    patterns.insert("systemd→sh", (0.70, "Systemd spawning shell directly"));
    patterns.insert("systemd→bash", (0.70, "Systemd spawning bash directly"));
    patterns.insert("init→curl", (0.80, "Init process executing curl"));
    patterns.insert("init→wget", (0.80, "Init process executing wget"));

    // SSH spawning suspicious tools (medium risk)
    patterns.insert("sshd→python", (0.65, "SSH session running Python"));
    patterns.insert("sshd→python3", (0.65, "SSH session running Python3"));
    patterns.insert("sshd→perl", (0.70, "SSH session running Perl"));
    patterns.insert("sshd→ruby", (0.70, "SSH session running Ruby"));

    // Database servers spawning shells (high risk)
    patterns.insert("mysqld→bash", (0.95, "MySQL spawning bash shell"));
    patterns.insert("mysqld→sh", (0.95, "MySQL spawning sh shell"));
    patterns.insert("postgres→bash", (0.95, "PostgreSQL spawning bash shell"));
    patterns.insert("postgres→sh", (0.95, "PostgreSQL spawning sh shell"));

    // Container runtime spawning direct shells (high risk)
    patterns.insert("containerd→bash", (0.90, "Containerd spawning bash shell"));
    patterns.insert("containerd→sh", (0.90, "Containerd spawning sh shell"));
    patterns.insert("dockerd→bash", (0.90, "Docker daemon spawning bash shell"));
    patterns.insert("dockerd→sh", (0.90, "Docker daemon spawning sh shell"));

    // Shell spawning encoders (medium-high risk)
    patterns.insert("bash→base64", (0.80, "Bash executing base64 (possible obfuscation)"));
    patterns.insert("sh→base64", (0.80, "Shell executing base64 (possible obfuscation)"));
    patterns.insert("bash→xxd", (0.75, "Bash executing xxd (possible obfuscation)"));

    // Network tools spawning shells (very high risk - reverse shell)
    patterns.insert("nc→bash", (0.98, "Netcat spawning bash (reverse shell)"));
    patterns.insert("nc→sh", (0.98, "Netcat spawning sh (reverse shell)"));
    patterns.insert("ncat→bash", (0.98, "Ncat spawning bash (reverse shell)"));
    patterns.insert("ncat→sh", (0.98, "Ncat spawning sh (reverse shell)"));
    patterns.insert("socat→bash", (0.98, "Socat spawning bash (reverse shell)"));
    patterns.insert("socat→sh", (0.98, "Socat spawning sh (reverse shell)"));

    patterns
}

/// Analyzes an entire process tree and returns all suspicious relationships
pub fn analyze_process_tree(tree: &ProcessTree) -> Vec<ProcessRelationship> {
    let mut suspicious = Vec::new();

    // Check each parent-child pair in the chain
    for i in 0..tree.chain.len().saturating_sub(1) {
        let child = &tree.chain[i];
        let parent = &tree.chain[i + 1];

        if let Some(relationship) = analyze_relationship(&parent.name, &child.name) {
            suspicious.push(relationship);
        }
    }

    suspicious
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suspicious_patterns() {
        let rel = analyze_relationship("apache2", "bash");
        assert!(rel.is_some());
        assert_eq!(rel.unwrap().suspicion_score, 0.95);

        let rel = analyze_relationship("cron", "curl");
        assert!(rel.is_some());
        assert_eq!(rel.unwrap().suspicion_score, 0.85);

        let rel = analyze_relationship("bash", "ls");
        assert!(rel.is_none());
    }

    #[test]
    fn test_pattern_matching() {
        assert!(pattern_matches("apache2→bash", "apache2", "bash"));
        assert!(!pattern_matches("apache2→bash", "nginx", "bash"));
    }
}
