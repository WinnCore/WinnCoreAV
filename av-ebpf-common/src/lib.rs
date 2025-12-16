//! Shared types between eBPF probes and userspace consumers.
//!
//! Keep these repr(C) layouts stable; both kernel-side probes and userspace
//! parsers depend on the exact field ordering and sizing.

#![cfg_attr(feature = "bpf", no_std)]
#![allow(dead_code)]

#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

pub const MAX_PATH_LEN: usize = 256;
pub const MAX_COMM_LEN: usize = 16; // TASK_COMM_LEN
pub const MAX_ARGS_LEN: usize = 512;

/// Event discriminator for the unified payload.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
pub enum EventType {
    ProcessExec = 1,
    ProcessExit = 2,
    NetworkConnect = 3,
    DnsQuery = 4,
    FileAccess = 5,
    PrivilegeChange = 6,
    Ptrace = 7,
    ModuleLoad = 8,
    KernelModule = 9,
}

/// Process execution event — fired on execve() syscall.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub filename: [u8; MAX_PATH_LEN],
    pub args: [u8; MAX_ARGS_LEN],
    pub args_len: u32,
}

/// Process exit event — for tracking process lifetimes.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessExitEvent {
    pub pid: u32,
    pub ppid: u32,
    pub exit_code: i32,
    pub timestamp_ns: u64,
    pub comm: [u8; MAX_COMM_LEN],
}

/// Network connection event — fired on connect() syscall.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NetworkConnectEvent {
    pub pid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub family: u16,
    pub protocol: u16,
    pub dest_port: u16,
    pub src_port: u16,
    pub dest_addr_v4: u32,
    pub dest_addr_v6: [u8; 16],
}

/// DNS query event.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DnsQueryEvent {
    pub pid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub query_name: [u8; MAX_PATH_LEN],
    pub query_type: u16,
}

/// File access event for sensitive paths.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileAccessEvent {
    pub pid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub filename: [u8; MAX_PATH_LEN],
    pub flags: u32,
    pub access_type: FileAccessType,
}

/// Why a file access was flagged.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileAccessType {
    Normal = 0,
    Credential = 1,
    SshKey = 2,
    BrowserCreds = 3,
    SensitiveConfig = 4,
}

/// Privilege change event — setuid/setgid/capset.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PrivilegeChangeEvent {
    pub pid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub old_uid: u32,
    pub new_uid: u32,
    pub old_gid: u32,
    pub new_gid: u32,
    pub change_type: PrivilegeChangeType,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PrivilegeChangeType {
    SetUid = 0,
    SetGid = 1,
    SetResUid = 2,
    SetResGid = 3,
    Capset = 4,
}

/// ptrace event — process injection detection.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PtraceEvent {
    pub pid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub target_pid: u32,
    pub request: u32,
}

/// Shared library load event.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ModuleLoadEvent {
    pub pid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub module_path: [u8; MAX_PATH_LEN],
    pub is_preload: u8,
}

/// Kernel module load/unload event.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KernelModuleEvent {
    pub pid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub module_name: [u8; 64],
    pub is_load: u8,
}

/// Unified event envelope.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BpfEvent {
    pub event_type: EventType,
    pub payload: EventPayload,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union EventPayload {
    pub process_exec: ProcessExecEvent,
    pub process_exit: ProcessExitEvent,
    pub network_connect: NetworkConnectEvent,
    pub dns_query: DnsQueryEvent,
    pub file_access: FileAccessEvent,
    pub privilege_change: PrivilegeChangeEvent,
    pub ptrace: PtraceEvent,
    pub module_load: ModuleLoadEvent,
    pub kernel_module: KernelModuleEvent,
}

impl core::fmt::Debug for EventPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EventPayload(..)")
    }
}

#[cfg(feature = "user")]
impl ProcessExecEvent {
    pub fn comm_str(&self) -> &str {
        let len = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_COMM_LEN);
        core::str::from_utf8(&self.comm[..len]).unwrap_or("<invalid>")
    }

    pub fn filename_str(&self) -> &str {
        let len = self
            .filename
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_PATH_LEN);
        core::str::from_utf8(&self.filename[..len]).unwrap_or("<invalid>")
    }

    pub fn args_str(&self) -> &str {
        let len = (self.args_len as usize).min(MAX_ARGS_LEN);
        core::str::from_utf8(&self.args[..len]).unwrap_or("<invalid>")
    }
}

#[cfg(feature = "user")]
impl NetworkConnectEvent {
    pub fn dest_addr_str(&self) -> String {
        match self.family {
            2 => {
                let octets = self.dest_addr_v4.to_be_bytes();
                format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
            }
            10 => {
                let bytes = self.dest_addr_v6;
                format!(
                    "{:02x}{:02x}:{:02x}{:02x}:...",
                    bytes[0], bytes[1], bytes[2], bytes[3]
                )
            }
            _ => "<unknown>".to_string(),
        }
    }
}
