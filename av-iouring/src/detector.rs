use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, info, warn};

use crate::events::{IoUringEvent, IoUringOp, RiskLevel};

/// Tracks io_uring rings per process.
#[derive(Debug, Clone)]
pub struct IoUringRing {
    pub fd: i32,
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub created_at: u64,
    /// Total operations submitted through this ring
    pub total_ops: u64,
    /// Sensitive operations count
    pub sensitive_ops: u64,
}

/// Process io_uring context.
#[derive(Debug, Clone)]
pub struct ProcessIoUringContext {
    pub pid: u32,
    pub comm: String,
    pub rings: Vec<IoUringRing>,
    /// Is this process expected to use io_uring?
    pub expected_user: bool,
    /// Suspicious activity score
    pub risk_score: u32,
}

/// Known legitimate io_uring users.
/// These processes commonly use io_uring for performance.
const EXPECTED_IOURING_USERS: &[&str] = &[
    "postgres",
    "mysql",
    "mariadbd",
    "mongod", // Databases
    "nginx",
    "envoy",
    "haproxy", // Proxies
    "fio",
    "io_uring", // Benchmarks
    "rocksdb",
    "tikv",            // Storage engines
    "systemd-journal", // System
];

/// The io_uring detector.
pub struct IoUringDetector {
    /// Process contexts: pid -> context
    contexts: Arc<RwLock<HashMap<u32, ProcessIoUringContext>>>,
    /// High-risk processes to monitor closely
    high_risk_pids: Arc<RwLock<HashSet<u32>>>,
    /// Alert callback
    on_alert: Option<Box<dyn Fn(IoUringEvent) + Send + Sync>>,
}

impl IoUringDetector {
    pub fn new() -> Self {
        Self {
            contexts: Arc::new(RwLock::new(HashMap::new())),
            high_risk_pids: Arc::new(RwLock::new(HashSet::new())),
            on_alert: None,
        }
    }

    /// Set alert callback.
    pub fn on_alert<F>(&mut self, callback: F)
    where
        F: Fn(IoUringEvent) + Send + Sync + 'static,
    {
        self.on_alert = Some(Box::new(callback));
    }

    /// Called when io_uring_setup() is detected.
    /// This is hooked via eBPF tracepoint on sys_enter_io_uring_setup.
    #[allow(clippy::too_many_arguments)]
    pub fn on_ring_setup(
        &self,
        pid: u32,
        tid: u32,
        ring_fd: i32,
        sq_entries: u32,
        cq_entries: u32,
    ) {
        let comm = get_comm(pid).unwrap_or_else(|| "<unknown>".to_string());
        let expected = EXPECTED_IOURING_USERS.iter().any(|u| comm.contains(u));

        let mut contexts = self.contexts.write();
        let ctx = contexts
            .entry(pid)
            .or_insert_with(|| ProcessIoUringContext {
                pid,
                comm: comm.clone(),
                rings: Vec::new(),
                expected_user: expected,
                risk_score: 0,
            });

        ctx.rings.push(IoUringRing {
            fd: ring_fd,
            sq_entries,
            cq_entries,
            created_at: current_time_ns(),
            total_ops: 0,
            sensitive_ops: 0,
        });

        // Unexpected io_uring user = suspicious
        if !expected {
            ctx.risk_score += 10;
            info!(
                "Unexpected io_uring user: {} (PID {}), risk_score={}",
                comm, pid, ctx.risk_score
            );

            // Add to high-risk monitoring
            self.high_risk_pids.write().insert(pid);
        }

        debug!(
            "io_uring_setup: pid={} tid={} comm={} fd={} sq={} cq={} expected={}",
            pid, tid, comm, ring_fd, sq_entries, cq_entries, expected
        );
    }

    /// Called when io_uring_enter() is detected with submission queue activity.
    /// The eBPF probe should extract key SQE fields.
    pub fn on_ring_enter(
        &self,
        pid: u32,
        tid: u32,
        ring_fd: i32,
        to_submit: u32,
        operations: Vec<(u8, i32, u64)>, // (opcode, fd, offset/addr)
    ) {
        let mut contexts = self.contexts.write();

        let ctx = match contexts.get_mut(&pid) {
            Some(c) => c,
            None => {
                // Ring we didn't see created — might have started before us
                warn!(
                    "io_uring_enter for unknown ring: pid={} fd={}",
                    pid, ring_fd
                );
                return;
            }
        };

        // Find the ring
        let Some(ring) = ctx.rings.iter_mut().find(|r| r.fd == ring_fd) else {
            return;
        };

        ring.total_ops += to_submit as u64;

        // Analyze each operation
        for (opcode, target_fd, _addr) in operations {
            let op = IoUringOp::from(opcode);

            if op.is_sensitive() {
                ring.sensitive_ops += 1;
                ctx.risk_score += 1;

                // Check for specific high-risk patterns
                let risk_level = self.assess_operation_risk(pid, &ctx.comm, &op, target_fd);

                if risk_level >= RiskLevel::High {
                    let event = IoUringEvent {
                        pid,
                        tid,
                        comm: ctx.comm.clone(),
                        timestamp_ns: current_time_ns(),
                        ring_fd,
                        operation: op,
                        target: resolve_fd(pid, target_fd),
                        addr_info: None,
                        risk_level,
                    };

                    warn!(
                        "High-risk io_uring operation: {:?} by {} (PID {})",
                        op, ctx.comm, pid
                    );

                    if let Some(ref callback) = self.on_alert {
                        callback(event);
                    }
                }
            }
        }

        // Escalate if too many sensitive ops
        if ring.sensitive_ops > 100 && !ctx.expected_user {
            ctx.risk_score += 50;
            self.high_risk_pids.write().insert(pid);
        }
    }

    fn assess_operation_risk(
        &self,
        pid: u32,
        comm: &str,
        op: &IoUringOp,
        target_fd: i32,
    ) -> RiskLevel {
        // High-risk: Network operations from unexpected process
        if matches!(
            op,
            IoUringOp::Connect | IoUringOp::Send | IoUringOp::Sendmsg
        ) && !EXPECTED_IOURING_USERS.iter().any(|u| comm.contains(u))
        {
            return RiskLevel::High;
        }

        // High-risk: File operations on sensitive paths
        if matches!(
            op,
            IoUringOp::Openat | IoUringOp::Openat2 | IoUringOp::Read | IoUringOp::Write
        ) {
            if let Some(path) = resolve_fd(pid, target_fd) {
                if is_sensitive_path(&path) {
                    return RiskLevel::High;
                }
            }
        }

        // Critical: Shell spawning io_uring
        if matches!(comm, "sh" | "bash" | "dash")
            && matches!(op, IoUringOp::Connect | IoUringOp::Send)
        {
            return RiskLevel::Critical;
        }

        // Medium: Any unexpected io_uring user doing I/O
        if !EXPECTED_IOURING_USERS.iter().any(|u| comm.contains(u)) {
            return RiskLevel::Medium;
        }

        RiskLevel::Low
    }

    /// Scan all processes for io_uring usage.
    /// Useful at startup to find existing rings.
    pub fn scan_existing_rings(&self) {
        let proc_dir = Path::new("/proc");

        for entry in fs::read_dir(proc_dir).into_iter().flatten().flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if let Ok(pid) = name_str.parse::<u32>() {
                if let Some(ring_count) = count_iouring_fds(pid) {
                    if ring_count > 0 {
                        let comm = get_comm(pid).unwrap_or_default();
                        info!(
                            "Found existing io_uring rings: pid={} comm={} count={}",
                            pid, comm, ring_count
                        );

                        // Initialize context
                        let expected = EXPECTED_IOURING_USERS.iter().any(|u| comm.contains(u));
                        self.contexts.write().insert(
                            pid,
                            ProcessIoUringContext {
                                pid,
                                comm,
                                rings: Vec::new(), // We don't know the actual ring FDs
                                expected_user: expected,
                                risk_score: if expected { 0 } else { 10 },
                            },
                        );
                    }
                }
            }
        }
    }

    /// Get current high-risk PIDs for intensive monitoring.
    pub fn get_high_risk_pids(&self) -> Vec<u32> {
        self.high_risk_pids.read().iter().copied().collect()
    }

    /// Get statistics.
    pub fn stats(&self) -> IoUringStats {
        let contexts = self.contexts.read();
        let mut total_rings = 0;
        let mut total_ops = 0;
        let mut suspicious_processes = 0;

        for ctx in contexts.values() {
            total_rings += ctx.rings.len();
            for ring in &ctx.rings {
                total_ops += ring.total_ops;
            }
            if ctx.risk_score > 10 {
                suspicious_processes += 1;
            }
        }

        IoUringStats {
            tracked_processes: contexts.len(),
            total_rings,
            total_operations: total_ops,
            suspicious_processes,
            high_risk_pids: self.high_risk_pids.read().len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IoUringStats {
    pub tracked_processes: usize,
    pub total_rings: usize,
    pub total_operations: u64,
    pub suspicious_processes: usize,
    pub high_risk_pids: usize,
}

// ════════════════════════════════════════════════════════════════════════════
// Helper functions
// ════════════════════════════════════════════════════════════════════════════

fn get_comm(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}

fn current_time_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn resolve_fd(pid: u32, fd: i32) -> Option<String> {
    if fd < 0 {
        return None;
    }
    fs::read_link(format!("/proc/{}/fd/{}", pid, fd))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

fn count_iouring_fds(pid: u32) -> Option<usize> {
    // io_uring fds show as "anon_inode:[io_uring]" in /proc/[pid]/fd
    let fd_dir = format!("/proc/{}/fd", pid);
    let mut count = 0;

    for entry in fs::read_dir(&fd_dir).ok()?.flatten() {
        if let Ok(target) = fs::read_link(entry.path()) {
            if target.to_string_lossy().contains("io_uring") {
                count += 1;
            }
        }
    }

    Some(count)
}

fn is_sensitive_path(path: &str) -> bool {
    let sensitive = [
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/etc/ssh",
        "/.ssh/",
        "/root/",
        "/home/",
        "/var/run/secrets/", // K8s
        "/proc/",
        "/sys/",
    ];
    sensitive.iter().any(|s| path.contains(s))
}

impl Default for IoUringDetector {
    fn default() -> Self {
        Self::new()
    }
}
