//! WinnCore eBPF probes — kernel-side behavioral monitoring.
//!
//! These probes attach to various kernel tracepoints and kprobes to observe
//! system behavior. Events are sent to userspace via perf buffers.
//!
//! Building requires: rustup target add bpfel-unknown-none
//!                    cargo install bpf-linker

#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::{ProbeContext, TracePointContext},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user,
    },
};
use aya_log_ebpf::info;
use av_ebpf_common::*;

#[map]
static mut EVENTS: PerfEventArray<BpfEvent> = PerfEventArray::new(0);

#[map]
static mut TRACKED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(10240, 0);

// ─────────────────────────────────────────────────────────────────────────────
// Process Execution
// ─────────────────────────────────────────────────────────────────────────────

#[tracepoint]
pub fn trace_execve(ctx: TracePointContext) -> u32 {
    match handle_execve(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn handle_execve(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let ppid = 0;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;

    let mut event = BpfEvent {
        event_type: EventType::ProcessExec,
        payload: EventPayload {
            process_exec: ProcessExecEvent {
                pid,
                ppid,
                uid,
                gid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                comm: [0u8; MAX_COMM_LEN],
                filename: [0u8; MAX_PATH_LEN],
                args: [0u8; MAX_ARGS_LEN],
                args_len: 0,
            },
        },
    };

    unsafe {
        bpf_get_current_comm(&mut event.payload.process_exec.comm)?;
    }

    unsafe {
        let filename_ptr: *const u8 = ctx.read_at(16)?;
        bpf_probe_read_user(
            event.payload.process_exec.filename.as_mut_ptr(),
            MAX_PATH_LEN as u32,
            filename_ptr as *const _,
        )?;
    }

    unsafe { EVENTS.output(ctx, &event, 0) };
    Ok(())
}

#[tracepoint]
pub fn trace_exit(ctx: TracePointContext) -> u32 {
    match handle_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn handle_exit(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let mut event = BpfEvent {
        event_type: EventType::ProcessExit,
        payload: EventPayload {
            process_exit: ProcessExitEvent {
                pid,
                ppid: 0,
                exit_code: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                comm: [0u8; MAX_COMM_LEN],
            },
        },
    };

    unsafe {
        bpf_get_current_comm(&mut event.payload.process_exit.comm)?;
        EVENTS.output(ctx, &event, 0);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Network Monitoring (placeholder)
// ─────────────────────────────────────────────────────────────────────────────

#[kprobe]
pub fn kprobe_tcp_connect(ctx: ProbeContext) -> u32 {
    match handle_tcp_connect(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn handle_tcp_connect(ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    let mut event = BpfEvent {
        event_type: EventType::NetworkConnect,
        payload: EventPayload {
            network_connect: NetworkConnectEvent {
                pid,
                uid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                comm: [0u8; MAX_COMM_LEN],
                family: 2,
                protocol: 6,
                dest_port: 0,
                src_port: 0,
                dest_addr_v4: 0,
                dest_addr_v6: [0u8; 16],
            },
        },
    };

    unsafe {
        bpf_get_current_comm(&mut event.payload.network_connect.comm)?;
        EVENTS.output(ctx, &event, 0);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Privilege Changes
// ─────────────────────────────────────────────────────────────────────────────

#[kprobe]
pub fn kprobe_commit_creds(ctx: ProbeContext) -> u32 {
    match handle_commit_creds(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn handle_commit_creds(ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let mut event = BpfEvent {
        event_type: EventType::PrivilegeChange,
        payload: EventPayload {
            privilege_change: PrivilegeChangeEvent {
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                comm: [0u8; MAX_COMM_LEN],
                old_uid: 0,
                new_uid: 0,
                old_gid: 0,
                new_gid: 0,
                change_type: PrivilegeChangeType::SetUid,
            },
        },
    };

    unsafe {
        bpf_get_current_comm(&mut event.payload.privilege_change.comm)?;
        EVENTS.output(ctx, &event, 0);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ptrace / injection
// ─────────────────────────────────────────────────────────────────────────────

#[tracepoint]
pub fn trace_ptrace(ctx: TracePointContext) -> u32 {
    match handle_ptrace(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn handle_ptrace(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    let request: u32 = unsafe { ctx.read_at(0)? };
    let target_pid: u32 = unsafe { ctx.read_at(8)? };

    if request != 16 && request != 0x4206 && request != 4 && request != 5 {
        return Ok(());
    }

    let mut event = BpfEvent {
        event_type: EventType::Ptrace,
        payload: EventPayload {
            ptrace: PtraceEvent {
                pid,
                uid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                comm: [0u8; MAX_COMM_LEN],
                target_pid,
                request,
            },
        },
    };

    unsafe {
        bpf_get_current_comm(&mut event.payload.ptrace.comm)?;
        EVENTS.output(ctx, &event, 0);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Sensitive file access (openat)
// ─────────────────────────────────────────────────────────────────────────────

#[tracepoint]
pub fn trace_openat(ctx: TracePointContext) -> u32 {
    match handle_openat(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn handle_openat(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    let filename_ptr: *const u8 = unsafe { ctx.read_at(24)? };
    let mut filename = [0u8; MAX_PATH_LEN];
    unsafe {
        bpf_probe_read_user(filename.as_mut_ptr(), MAX_PATH_LEN as u32, filename_ptr as *const _)?;
    }

    let flags: u32 = unsafe { ctx.read_at(32)? };
    let access_type = classify_sensitive(&filename);
    if access_type == FileAccessType::Normal {
        return Ok(());
    }

    let mut event = BpfEvent {
        event_type: EventType::FileAccess,
        payload: EventPayload {
            file_access: FileAccessEvent {
                pid,
                uid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                comm: [0u8; MAX_COMM_LEN],
                filename,
                flags,
                access_type,
            },
        },
    };

    unsafe {
        bpf_get_current_comm(&mut event.payload.file_access.comm)?;
        EVENTS.output(ctx, &event, 0);
    }

    Ok(())
}

fn classify_sensitive(path: &[u8; MAX_PATH_LEN]) -> FileAccessType {
    if path.starts_with(b"/etc/shadow") || path.starts_with(b"/etc/passwd") {
        return FileAccessType::Credential;
    }
    if path.windows(5).any(|w| w == b".ssh/") {
        return FileAccessType::SshKey;
    }
    if path.windows(11).any(|w| w == b"Login Data") || path.windows(8).any(|w| w == b"logins.json") {
        return FileAccessType::BrowserCreds;
    }
    FileAccessType::Normal
}

// ─────────────────────────────────────────────────────────────────────────────
// Kernel module load/unload
// ─────────────────────────────────────────────────────────────────────────────

#[tracepoint]
pub fn trace_module_load(ctx: TracePointContext) -> u32 {
    match handle_module_load(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn handle_module_load(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    let mut event = BpfEvent {
        event_type: EventType::KernelModule,
        payload: EventPayload {
            kernel_module: KernelModuleEvent {
                pid,
                uid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                module_name: [0u8; 64],
                is_load: 1,
            },
        },
    };

    unsafe { EVENTS.output(ctx, &event, 0) };
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
