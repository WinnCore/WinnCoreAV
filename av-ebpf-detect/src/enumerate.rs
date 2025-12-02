//! Enumerate loaded eBPF programs and maps.

use std::ffi::CStr;
use std::mem;
use std::os::raw::c_int;

use serde::{Deserialize, Serialize};
use tracing::{debug, info};

// BPF syscall command numbers
const BPF_PROG_GET_NEXT_ID: c_int = 11;
const BPF_PROG_GET_FD_BY_ID: c_int = 13;
const BPF_OBJ_GET_INFO_BY_FD: c_int = 15;

// BPF program types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum BpfProgType {
    Unspec = 0,
    SocketFilter = 1,
    Kprobe = 2,
    SchedCls = 3, // TC classifier
    SchedAct = 4, // TC action
    Tracepoint = 5,
    Xdp = 6, // eXpress Data Path - HIGH RISK
    PerfEvent = 7,
    RawTracepoint = 17,
    Tracing = 26,
    Lsm = 29, // LSM hooks - VERY HIGH RISK
    Syscall = 31,
    Unknown(u32),
}

impl From<u32> for BpfProgType {
    fn from(v: u32) -> Self {
        match v {
            0 => Self::Unspec,
            1 => Self::SocketFilter,
            2 => Self::Kprobe,
            3 => Self::SchedCls,
            4 => Self::SchedAct,
            5 => Self::Tracepoint,
            6 => Self::Xdp,
            7 => Self::PerfEvent,
            17 => Self::RawTracepoint,
            26 => Self::Tracing,
            29 => Self::Lsm,
            31 => Self::Syscall,
            _ => Self::Unknown(v),
        }
    }
}

impl BpfProgType {
    /// Is this program type commonly used by rootkits?
    pub fn is_high_risk(&self) -> bool {
        matches!(
            self,
            Self::Xdp
                | Self::SchedCls
                | Self::SchedAct
                | Self::Kprobe
                | Self::Tracepoint
                | Self::RawTracepoint
                | Self::Tracing
                | Self::Lsm
                | Self::Syscall
        )
    }

    pub fn as_raw(&self) -> u32 {
        match self {
            Self::Unspec => 0,
            Self::SocketFilter => 1,
            Self::Kprobe => 2,
            Self::SchedCls => 3,
            Self::SchedAct => 4,
            Self::Tracepoint => 5,
            Self::Xdp => 6,
            Self::PerfEvent => 7,
            Self::RawTracepoint => 17,
            Self::Tracing => 26,
            Self::Lsm => 29,
            Self::Syscall => 31,
            Self::Unknown(v) => *v,
        }
    }
}

/// Information about a loaded BPF program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfProgInfo {
    pub id: u32,
    pub prog_type: BpfProgType,
    pub name: String,
    pub tag: [u8; 8], // Hash of program
    pub jited_prog_len: u32,
    pub xlated_prog_len: u32,
    pub load_time: u64, // Nanoseconds since boot
    pub created_by_uid: u32,
    pub nr_map_ids: u32,
    /// Is this program attached?
    pub attached: bool,
}

impl BpfProgInfo {
    pub fn tag_hex(&self) -> String {
        hex::encode(&self.tag)
    }

    pub fn is_suspicious(&self) -> bool {
        // Unnamed programs are suspicious
        if self.name.is_empty() {
            return true;
        }

        // Programs loaded by non-root
        if self.created_by_uid != 0 {
            return true;
        }

        // High-risk program types
        self.prog_type.is_high_risk()
    }
}

/// Enumerate all loaded BPF programs.
pub fn enumerate_bpf_programs() -> Vec<BpfProgInfo> {
    let mut programs = Vec::new();
    let mut id: u32 = 0;

    loop {
        // Get next program ID
        match bpf_prog_get_next_id(id) {
            Some(next_id) => {
                id = next_id;

                // Get program info
                if let Some(info) = get_prog_info(id) {
                    debug!(
                        "Found BPF program: id={} type={:?} name={}",
                        id, info.prog_type, info.name
                    );
                    programs.push(info);
                }
            }
            None => break,
        }
    }

    info!("Enumerated {} BPF programs", programs.len());
    programs
}

fn bpf_prog_get_next_id(start_id: u32) -> Option<u32> {
    let mut attr = BpfAttrGetId {
        start_id,
        next_id: 0,
        open_flags: 0,
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_GET_NEXT_ID,
            &mut attr as *mut _ as *mut libc::c_void,
            mem::size_of::<BpfAttrGetId>() as u32,
        )
    };

    if ret == 0 {
        Some(attr.next_id)
    } else {
        None
    }
}

fn get_prog_info(id: u32) -> Option<BpfProgInfo> {
    // First, get FD for this program ID
    let mut attr = BpfAttrGetId {
        start_id: id,
        next_id: 0,
        open_flags: 0,
    };

    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_GET_FD_BY_ID,
            &mut attr as *mut _ as *mut libc::c_void,
            mem::size_of::<BpfAttrGetId>() as u32,
        )
    };

    if fd < 0 {
        return None;
    }

    // Now get info from FD
    let mut info = BpfProgInfoKernel::default();
    let mut info_attr = BpfAttrGetInfo {
        bpf_fd: fd as u32,
        info_len: mem::size_of::<BpfProgInfoKernel>() as u32,
        info: &mut info as *mut _ as u64,
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET_INFO_BY_FD,
            &mut info_attr as *mut _ as *mut libc::c_void,
            mem::size_of::<BpfAttrGetInfo>() as u32,
        )
    };

    // Close the FD
    unsafe {
        libc::close(fd as c_int);
    }

    if ret < 0 {
        return None;
    }

    // Extract name
    let name = unsafe { CStr::from_ptr(info.name.as_ptr() as *const libc::c_char) }
        .to_string_lossy()
        .to_string();

    Some(BpfProgInfo {
        id: info.id,
        prog_type: BpfProgType::from(info.prog_type),
        name,
        tag: info.tag,
        jited_prog_len: info.jited_prog_len,
        xlated_prog_len: info.xlated_prog_len,
        load_time: info.load_time,
        created_by_uid: info.created_by_uid,
        nr_map_ids: info.nr_map_ids,
        attached: false,
    })
}

// Kernel structures for bpf() syscall
#[repr(C)]
struct BpfAttrGetId {
    start_id: u32,
    next_id: u32,
    open_flags: u32,
}

#[repr(C)]
struct BpfAttrGetInfo {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

#[repr(C)]
#[derive(Default)]
struct BpfProgInfoKernel {
    prog_type: u32,
    id: u32,
    tag: [u8; 8],
    jited_prog_len: u32,
    xlated_prog_len: u32,
    jited_prog_insns: u64,
    xlated_prog_insns: u64,
    load_time: u64,
    created_by_uid: u32,
    nr_map_ids: u32,
    map_ids: u64,
    name: [i8; 16],
    ifindex: u32,
    gpl_compatible: u32,
    netns_dev: u64,
    netns_ino: u64,
    nr_jited_ksyms: u32,
    nr_jited_func_lens: u32,
    jited_ksyms: u64,
    jited_func_lens: u64,
    btf_id: u32,
    func_info_rec_size: u32,
    func_info: u64,
    nr_func_info: u32,
    nr_line_info: u32,
    line_info: u64,
    jited_line_info: u64,
    nr_jited_line_info: u32,
    line_info_rec_size: u32,
    jited_line_info_rec_size: u32,
    nr_prog_tags: u32,
    prog_tags: u64,
    run_time_ns: u64,
    run_cnt: u64,
    recursion_misses: u64,
}
