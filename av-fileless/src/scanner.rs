//! Scan for processes running from memory or deleted files.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde::Serialize;
use tracing::{info, warn};

/// Types of fileless execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FilelessType {
    /// memfd_create: /memfd:name
    MemfdCreate,
    /// Deleted executable: /path (deleted)
    DeletedExe,
    /// Execution from /dev/shm
    DevShm,
    /// Execution from /proc/self/fd
    ProcFd,
    /// Execution from /tmp with deletion
    TmpDeleted,
}

/// A detected fileless process.
#[derive(Debug, Clone, Serialize)]
pub struct FilelessProcess {
    pub pid: u32,
    pub comm: String,
    pub exe_path: String,
    pub fileless_type: FilelessType,
    pub parent_pid: u32,
    pub parent_comm: String,
    pub cmdline: String,
    pub uid: u32,
    pub memory_hash: Option<String>,
}

/// Scan all processes for fileless execution.
pub fn scan_for_fileless() -> Vec<FilelessProcess> {
    let mut results = Vec::new();

    let proc_dir = Path::new("/proc");

    for entry in fs::read_dir(proc_dir).into_iter().flatten().flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if let Ok(pid) = name_str.parse::<u32>() {
            if let Some(fileless) = check_process(pid) {
                warn!(
                    "Fileless process detected: PID={} type={:?} exe={}",
                    pid, fileless.fileless_type, fileless.exe_path
                );
                results.push(fileless);
            }
        }
    }

    info!("Fileless scan complete: {} processes found", results.len());
    results
}

/// Check a single process for fileless execution.
pub fn check_process(pid: u32) -> Option<FilelessProcess> {
    let exe_path = format!("/proc/{}/exe", pid);

    // Read the exe symlink
    let exe_target = match fs::read_link(&exe_path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => return None, // Process may have exited
    };

    let fileless_type = classify_exe_path(&exe_target)?;

    // Gather process info
    let comm = read_proc_file(pid, "comm").unwrap_or_default();
    let cmdline = read_proc_file(pid, "cmdline")
        .unwrap_or_default()
        .replace('\0', " ");
    let status = read_proc_file(pid, "status").unwrap_or_default();

    let ppid = parse_status_field(&status, "PPid").unwrap_or(0);
    let uid = parse_status_field(&status, "Uid").unwrap_or(0);
    let parent_comm = read_proc_file(ppid, "comm").unwrap_or_default();

    // For memfd processes, try to hash the memory contents
    let memory_hash = if fileless_type == FilelessType::MemfdCreate {
        hash_memfd_contents(pid)
    } else {
        None
    };

    Some(FilelessProcess {
        pid,
        comm,
        exe_path: exe_target,
        fileless_type,
        parent_pid: ppid,
        parent_comm,
        cmdline,
        uid,
        memory_hash,
    })
}

fn classify_exe_path(path: &str) -> Option<FilelessType> {
    // memfd_create: /memfd:name (deleted)
    if path.starts_with("/memfd:") {
        return Some(FilelessType::MemfdCreate);
    }

    // Execution from /dev/shm
    if path.starts_with("/dev/shm/") {
        return Some(FilelessType::DevShm);
    }

    // Execution via /proc/self/fd
    if path.contains("/proc/") && path.contains("/fd/") {
        return Some(FilelessType::ProcFd);
    }

    // Deleted executable
    if path.ends_with(" (deleted)") {
        // Distinguish between tmp and others
        if path.starts_with("/tmp/") || path.starts_with("/var/tmp/") {
            return Some(FilelessType::TmpDeleted);
        }
        return Some(FilelessType::DeletedExe);
    }

    None
}

fn read_proc_file(pid: u32, name: &str) -> Option<String> {
    let path = format!("/proc/{}/{}", pid, name);
    fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

fn parse_status_field(status: &str, field: &str) -> Option<u32> {
    for line in status.lines() {
        if line.starts_with(field) {
            return line.split_whitespace().nth(1).and_then(|s| s.parse().ok());
        }
    }
    None
}

/// Hash the contents of a memfd-based process's executable memory.
/// This allows us to track the same fileless payload across executions.
fn hash_memfd_contents(pid: u32) -> Option<String> {
    use sha2::{Digest, Sha256};

    // Read /proc/[pid]/exe contents (the memfd)
    let exe_path = format!("/proc/{}/exe", pid);

    let content = fs::read(&exe_path).ok()?;

    let mut hasher = Sha256::new();
    hasher.update(&content);
    Some(hex::encode(hasher.finalize()))
}

/// Monitor /dev/shm for new executables.
pub fn scan_devshm() -> Vec<ShmExecutable> {
    let mut results = Vec::new();
    let shm_dir = Path::new("/dev/shm");

    for entry in fs::read_dir(shm_dir).into_iter().flatten().flatten() {
        let path = entry.path();

        if let Ok(metadata) = entry.metadata() {
            // Check if executable
            let mode = metadata.permissions().mode();
            if mode & 0o111 != 0 {
                results.push(ShmExecutable {
                    path: path.to_string_lossy().to_string(),
                    size: metadata.len(),
                    mode,
                    is_elf: is_elf_file(&path),
                });
            }
        }
    }

    results
}

#[derive(Debug, Clone, Serialize)]
pub struct ShmExecutable {
    pub path: String,
    pub size: u64,
    pub mode: u32,
    pub is_elf: bool,
}

fn is_elf_file(path: &Path) -> bool {
    if let Ok(mut file) = fs::File::open(path) {
        use std::io::Read;
        let mut magic = [0u8; 4];
        if file.read_exact(&mut magic).is_ok() {
            return &magic == b"\x7fELF";
        }
    }
    false
}
