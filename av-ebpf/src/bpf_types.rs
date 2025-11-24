//! Shared types that must match the C BPF definitions exactly.

pub const MAX_COMM_LEN: usize = 16;
pub const MAX_FILENAME_LEN: usize = 256;
pub const EVENT_DATA_SIZE: usize = 280;

pub const EVENT_EXEC: u32 = 1;
pub const EVENT_EXIT: u32 = 2;
pub const EVENT_OPEN: u32 = 3;
pub const EVENT_CONNECT: u32 = 4;
pub const EVENT_MMAP: u32 = 5;
pub const EVENT_PTRACE: u32 = 6;

/// Raw BPF event structure - packed to match C layout.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct RawBpfEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub event_type: u32,
    pub _pad0: u32,
    pub comm: [u8; MAX_COMM_LEN],
    pub data: [u8; EVENT_DATA_SIZE],
}

const _: () = assert!(
    core::mem::size_of::<RawBpfEvent>()
        == 8 + 4 + 4 + 4 + 4 + 4 + 4 + MAX_COMM_LEN + EVENT_DATA_SIZE
);

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ExecEventData {
    pub filename: [u8; MAX_FILENAME_LEN],
    pub retval: i32,
    pub _pad: [u8; EVENT_DATA_SIZE - MAX_FILENAME_LEN - 4],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct OpenEventData {
    pub filename: [u8; MAX_FILENAME_LEN],
    pub flags: i32,
    pub retval: i32,
    pub _pad: [u8; EVENT_DATA_SIZE - MAX_FILENAME_LEN - 8],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ConnectEventData {
    pub dst_addr: u32,
    pub dst_port: u16,
    pub protocol: u16,
    pub _pad: [u8; EVENT_DATA_SIZE - 8],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MmapEventData {
    pub addr: u64,
    pub len: u64,
    pub prot: u32,
    pub flags: u32,
    pub _pad: [u8; EVENT_DATA_SIZE - 24],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct PtraceEventData {
    pub request: u32,
    pub target_pid: u32,
    pub _pad: [u8; EVENT_DATA_SIZE - 8],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ExitEventData {
    pub exit_code: i32,
    pub _pad: [u8; EVENT_DATA_SIZE - 4],
}

impl RawBpfEvent {
    pub fn comm_str(&self) -> &str {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_COMM_LEN);
        std::str::from_utf8(&self.comm[..end]).unwrap_or("")
    }
}
