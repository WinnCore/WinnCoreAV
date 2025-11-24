use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity levels for behavioral alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// MITRE ATT&CK technique mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
}

/// Types of behavioral events collected from kernel or procfs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    ProcessExec(ProcessExecEvent),
    ProcessExit(ProcessExitEvent),
    FileOpen(FileOpenEvent),
    FileWrite(FileWriteEvent),
    NetworkConnect(NetworkConnectEvent),
    MemoryMap(MemoryMapEvent),
    SyscallAnomaly(SyscallAnomalyEvent),
}

/// Base behavioral event used by the rule engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub cmdline: String,
    pub cwd: String,
    pub severity: Severity,
    pub mitre_techniques: Vec<MitreTechnique>,
    pub raw_data: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExecEvent {
    pub filename: String,
    pub args: Vec<String>,
    pub env_vars: HashMap<String, String>,
    pub interpreter: Option<String>,
    pub is_script: bool,
    pub is_setuid: bool,
    pub is_setgid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExitEvent {
    pub exit_code: i32,
    pub signal: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOpenEvent {
    pub path: String,
    pub flags: u32,
    pub mode: u32,
    pub is_sensitive: bool,
    pub is_executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileWriteEvent {
    pub path: String,
    pub bytes_written: u64,
    pub is_executable_content: bool,
    pub is_autostart_location: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectEvent {
    pub protocol: String,
    pub src_addr: String,
    pub src_port: u16,
    pub dst_addr: String,
    pub dst_port: u16,
    pub is_external: bool,
    pub is_known_bad: bool,
    pub geo_info: Option<GeoInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub country_code: String,
    pub country_name: String,
    pub is_sanctioned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMapEvent {
    pub address: u64,
    pub length: u64,
    pub protection: u32,
    pub flags: u32,
    pub is_anonymous: bool,
    pub is_rwx: bool,
    pub backing_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallAnomalyEvent {
    pub syscall_id: u32,
    pub syscall_name: String,
    pub anomaly_type: SyscallAnomalyType,
    pub args: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyscallAnomalyType {
    RareSyscall,
    UnusualArguments,
    HighFrequency,
    SuspiciousSequence,
}
