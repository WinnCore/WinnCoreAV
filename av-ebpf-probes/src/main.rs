//! WinnCore eBPF probes — kernel-side behavioral monitoring.
//!
//! These probes attach to syscall entrypoints (kprobes) and emit typed events
//! via a perf event array.

#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use core::ptr;

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, map},
    maps::{PerCpuArray, PerfEventArray},
    programs::ProbeContext,
};

use av_ebpf_common::*;

#[map]
static mut EVENTS: PerfEventArray<BpfEvent> = PerfEventArray::new(0);

/// Scratch event buffer to avoid exceeding the eBPF stack limit.
#[map]
static mut EVENT_BUF: PerCpuArray<BpfEvent> = PerCpuArray::with_max_entries(1, 0);

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[repr(C)]
struct SockAddr {
    family: u16,
    data: [u8; 14],
}

#[repr(C)]
struct SockAddrIn {
    family: u16,
    port: u16,
    addr: u32,
    zero: [u8; 8],
}

#[repr(C)]
struct SockAddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// execve / execveat
// ─────────────────────────────────────────────────────────────────────────────

#[kprobe]
pub fn kprobe_execve(ctx: ProbeContext) -> u32 {
    match try_execve(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_execve(ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;

    let filename_ptr: *const u8 = ctx.arg(0).ok_or(1i64)?;

    let event_ptr = unsafe { EVENT_BUF.get_ptr_mut(0).ok_or(1i64)? };
    unsafe { ptr::write_bytes(event_ptr, 0, 1) };
    let event = unsafe { &mut *event_ptr };

    event.event_type = EventType::ProcessExec;
    let exec = unsafe { &mut event.payload.process_exec };
    exec.pid = pid;
    exec.ppid = 0;
    exec.uid = uid;
    exec.gid = gid;
    exec.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    exec.comm = bpf_get_current_comm()?;
    exec.filename.fill(0);
    exec.args.fill(0);
    exec.args_len = 0;

    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut exec.filename);
        EVENTS.output(ctx, event, 0);
    }

    Ok(())
}

#[kprobe]
pub fn kprobe_execveat(ctx: ProbeContext) -> u32 {
    match try_execveat(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_execveat(ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;

    // execveat(dfd, filename, argv, envp, flags)
    let filename_ptr: *const u8 = ctx.arg(1).ok_or(1i64)?;

    let event_ptr = unsafe { EVENT_BUF.get_ptr_mut(0).ok_or(1i64)? };
    unsafe { ptr::write_bytes(event_ptr, 0, 1) };
    let event = unsafe { &mut *event_ptr };

    event.event_type = EventType::ProcessExec;
    let exec = unsafe { &mut event.payload.process_exec };
    exec.pid = pid;
    exec.ppid = 0;
    exec.uid = uid;
    exec.gid = gid;
    exec.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    exec.comm = bpf_get_current_comm()?;
    exec.filename.fill(0);
    exec.args.fill(0);
    exec.args_len = 0;

    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut exec.filename);
        EVENTS.output(ctx, event, 0);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// connect()
// ─────────────────────────────────────────────────────────────────────────────

#[kprobe]
pub fn kprobe_connect(ctx: ProbeContext) -> u32 {
    match try_connect(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_connect(ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    // connect(fd, uservaddr, addrlen)
    let uservaddr: *const u8 = ctx.arg(1).ok_or(1i64)?;
    let header: SockAddr = unsafe { bpf_probe_read_user(uservaddr as *const SockAddr)? };

    let event_ptr = unsafe { EVENT_BUF.get_ptr_mut(0).ok_or(1i64)? };
    unsafe { ptr::write_bytes(event_ptr, 0, 1) };
    let event = unsafe { &mut *event_ptr };

    event.event_type = EventType::NetworkConnect;
    let net = unsafe { &mut event.payload.network_connect };
    net.pid = pid;
    net.uid = uid;
    net.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    net.comm = bpf_get_current_comm()?;
    net.family = header.family;
    net.protocol = 0;
    net.dest_port = 0;
    net.src_port = 0;
    net.dest_addr_v4 = 0;
    net.dest_addr_v6 = [0u8; 16];

    match header.family {
        AF_INET => {
            let sin: SockAddrIn = unsafe { bpf_probe_read_user(uservaddr as *const SockAddrIn)? };
            net.dest_port = u16::from_be(sin.port);
            net.dest_addr_v4 = u32::from_be(sin.addr);
        }
        AF_INET6 => {
            let sin6: SockAddrIn6 =
                unsafe { bpf_probe_read_user(uservaddr as *const SockAddrIn6)? };
            net.dest_port = u16::from_be(sin6.port);
            net.dest_addr_v6 = sin6.addr;
        }
        _ => return Ok(()),
    }

    unsafe { EVENTS.output(ctx, event, 0) };
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// openat()
// ─────────────────────────────────────────────────────────────────────────────

#[kprobe]
pub fn kprobe_openat(ctx: ProbeContext) -> u32 {
    match try_openat(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_openat(ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    // openat(dfd, filename, flags, mode)
    let filename_ptr: *const u8 = ctx.arg(1).ok_or(1i64)?;
    let flags: u64 = ctx.arg(2).unwrap_or(0);

    let event_ptr = unsafe { EVENT_BUF.get_ptr_mut(0).ok_or(1i64)? };
    unsafe { ptr::write_bytes(event_ptr, 0, 1) };
    let event = unsafe { &mut *event_ptr };

    event.event_type = EventType::FileAccess;
    let file = unsafe { &mut event.payload.file_access };
    file.pid = pid;
    file.uid = uid;
    file.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    file.comm = bpf_get_current_comm()?;
    file.filename.fill(0);
    file.flags = flags as u32;
    file.access_type = FileAccessType::Normal;

    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut file.filename);
    }

    let access_type = classify_sensitive(&file.filename);
    if access_type == FileAccessType::Normal {
        return Ok(());
    }
    file.access_type = access_type;

    unsafe { EVENTS.output(ctx, event, 0) };
    Ok(())
}

fn classify_sensitive(path: &[u8; MAX_PATH_LEN]) -> FileAccessType {
    if path.starts_with(b"/etc/shadow") || path.starts_with(b"/etc/passwd") {
        return FileAccessType::Credential;
    }
    if path.windows(5).any(|w| w == b".ssh/") {
        return FileAccessType::SshKey;
    }
    if path.windows(11).any(|w| w == b"Login Data") || path.windows(8).any(|w| w == b"logins.json")
    {
        return FileAccessType::BrowserCreds;
    }
    FileAccessType::Normal
}

// ─────────────────────────────────────────────────────────────────────────────
// ptrace()
// ─────────────────────────────────────────────────────────────────────────────

#[kprobe]
pub fn kprobe_ptrace(ctx: ProbeContext) -> u32 {
    match try_ptrace(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_ptrace(ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    // ptrace(request, pid, addr, data)
    let request: u64 = ctx.arg(0).ok_or(1i64)?;
    let target_pid: u64 = ctx.arg(1).unwrap_or(0);
    let request_u32 = request as u32;

    // PTRACE_ATTACH (16) / PTRACE_SEIZE (0x4206) / a couple other high-signal requests.
    if request_u32 != 16 && request_u32 != 0x4206 && request_u32 != 4 && request_u32 != 5 {
        return Ok(());
    }

    let event_ptr = unsafe { EVENT_BUF.get_ptr_mut(0).ok_or(1i64)? };
    unsafe { ptr::write_bytes(event_ptr, 0, 1) };
    let event = unsafe { &mut *event_ptr };

    event.event_type = EventType::Ptrace;
    let ptrace_evt = unsafe { &mut event.payload.ptrace };
    ptrace_evt.pid = pid;
    ptrace_evt.uid = uid;
    ptrace_evt.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    ptrace_evt.comm = bpf_get_current_comm()?;
    ptrace_evt.target_pid = target_pid as u32;
    ptrace_evt.request = request_u32;

    unsafe { EVENTS.output(ctx, event, 0) };
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// init_module()
// ─────────────────────────────────────────────────────────────────────────────

#[kprobe]
pub fn kprobe_init_module(ctx: ProbeContext) -> u32 {
    match try_init_module(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_init_module(ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    let event_ptr = unsafe { EVENT_BUF.get_ptr_mut(0).ok_or(1i64)? };
    unsafe { ptr::write_bytes(event_ptr, 0, 1) };
    let event = unsafe { &mut *event_ptr };

    event.event_type = EventType::KernelModule;
    let km = unsafe { &mut event.payload.kernel_module };
    km.pid = pid;
    km.uid = uid;
    km.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    km.module_name = [0u8; 64];
    km.is_load = 1;

    unsafe { EVENTS.output(ctx, event, 0) };
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

