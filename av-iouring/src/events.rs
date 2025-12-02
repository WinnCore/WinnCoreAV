use serde::{Deserialize, Serialize};

/// io_uring operation codes we care about for security monitoring.
/// These map to IORING_OP_* constants from the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IoUringOp {
    Nop = 0,
    Readv = 1,
    Writev = 2,
    Fsync = 3,
    ReadFixed = 4,
    WriteFixed = 5,
    PollAdd = 6,
    PollRemove = 7,
    SyncFileRange = 8,
    Sendmsg = 9,
    Recvmsg = 10,
    Timeout = 11,
    TimeoutRemove = 12,
    Accept = 13,
    AsyncCancel = 14,
    LinkTimeout = 15,
    Connect = 16,
    Fallocate = 17,
    Openat = 18,
    Close = 19,
    FilesUpdate = 20,
    Statx = 21,
    Read = 22,
    Write = 23,
    Fadvise = 24,
    Madvise = 25,
    Send = 26,
    Recv = 27,
    Openat2 = 28,
    EpollCtl = 29,
    Splice = 30,
    ProvideBuffers = 31,
    RemoveBuffers = 32,
    Tee = 33,
    Shutdown = 34,
    Renameat = 35,
    Unlinkat = 36,
    Mkdirat = 37,
    Symlinkat = 38,
    Linkat = 39,
    MsgRing = 40,
    Fsetxattr = 41,
    Setxattr = 42,
    Fgetxattr = 43,
    Getxattr = 44,
    Socket = 45,
    UringCmd = 46,
    SendZc = 47,
    SendmsgZc = 48,
    Unknown(u8),
}

impl From<u8> for IoUringOp {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Nop,
            1 => Self::Readv,
            2 => Self::Writev,
            9 => Self::Sendmsg,
            10 => Self::Recvmsg,
            13 => Self::Accept,
            16 => Self::Connect,
            18 => Self::Openat,
            19 => Self::Close,
            22 => Self::Read,
            23 => Self::Write,
            26 => Self::Send,
            27 => Self::Recv,
            28 => Self::Openat2,
            34 => Self::Shutdown,
            35 => Self::Renameat,
            36 => Self::Unlinkat,
            45 => Self::Socket,
            _ => Self::Unknown(v),
        }
    }
}

impl IoUringOp {
    /// Is this operation security-sensitive?
    pub fn is_sensitive(&self) -> bool {
        matches!(
            self,
            Self::Openat
                | Self::Openat2
                | Self::Read
                | Self::Readv
                | Self::Write
                | Self::Writev
                | Self::Connect
                | Self::Accept
                | Self::Send
                | Self::Sendmsg
                | Self::Recv
                | Self::Recvmsg
                | Self::Socket
                | Self::Unlinkat
                | Self::Renameat
        )
    }

    /// Get MITRE ATT&CK technique if applicable.
    pub fn mitre_technique(&self) -> Option<&'static str> {
        match self {
            Self::Connect | Self::Send | Self::Sendmsg => Some("T1071"), // C2
            Self::Openat | Self::Openat2 | Self::Read => Some("T1005"),  // Data from local system
            Self::Unlinkat => Some("T1070.004"),                         // File deletion
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,      // Normal io_uring usage
    Medium,   // Suspicious but could be legitimate
    High,     // Likely malicious
    Critical, // Almost certainly malicious
}

/// Detected io_uring activity.
#[derive(Debug, Clone, Serialize)]
pub struct IoUringEvent {
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
    pub timestamp_ns: u64,
    pub ring_fd: i32,
    pub operation: IoUringOp,
    /// For file ops: the target fd or path
    pub target: Option<String>,
    /// For network ops: address info
    pub addr_info: Option<String>,
    /// Risk assessment
    pub risk_level: RiskLevel,
}
