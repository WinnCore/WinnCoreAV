use std::collections::HashSet;
use std::fs;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct HiddenProcessResult {
    pub proc_pids: HashSet<u32>,
    pub other_pids: HashSet<u32>,
    pub hidden_pids: HashSet<u32>,
    pub suspicious_pids: Vec<SuspiciousPid>,
}

#[derive(Debug, Clone)]
pub struct SuspiciousPid {
    pub pid: u32,
    pub reason: String,
}

pub fn scan_hidden_processes() -> HiddenProcessResult {
    let proc_pids = get_proc_pids();
    let other_pids = get_pids_from_alternatives();
    let mut hidden = HashSet::new();
    for pid in &other_pids {
        if !proc_pids.contains(pid) {
            hidden.insert(*pid);
            warn!("Potential hidden process: {}", pid);
        }
    }
    let mut suspicious = Vec::new();
    for pid in &proc_pids {
        if let Some(s) = check_pid_suspicious(*pid) {
            suspicious.push(s);
        }
    }
    HiddenProcessResult {
        proc_pids,
        other_pids,
        hidden_pids: hidden,
        suspicious_pids: suspicious,
    }
}

fn get_proc_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(pid) = name.parse::<u32>() {
                    pids.insert(pid);
                }
            }
        }
    }
    pids
}

fn get_pids_from_alternatives() -> HashSet<u32> {
    let mut pids = HashSet::new();
    for pid in 1..32768u32 {
        let stat_path = format!("/proc/{}/stat", pid);
        if fs::metadata(&stat_path).is_ok() {
            pids.insert(pid);
        }
    }
    pids
}

fn check_pid_suspicious(pid: u32) -> Option<SuspiciousPid> {
    let exe_path = format!("/proc/{}/exe", pid);
    if let Ok(exe) = fs::read_link(&exe_path) {
        let exe_str = exe.to_string_lossy();
        if exe_str.contains("(deleted)") {
            return Some(SuspiciousPid {
                pid,
                reason: "Executable deleted".to_string(),
            });
        }
    }
    None
}
