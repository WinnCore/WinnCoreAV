//! Parse io_uring submission queue entries.
//!
//! When we need deep inspection, we can read the SQ directly from process memory.
//! This is expensive but provides complete visibility.

use crate::events::IoUringOp;

/// Submission Queue Entry (SQE) structure.
/// This matches the kernel's io_uring_sqe struct.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoUringSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off_addr2: u64,   // offset or addr2
    pub addr_splice: u64, // addr or splice_off_in
    pub len: u32,
    pub op_flags: u32, // union of various op-specific flags
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub addr3: u64,
    pub resv: u64,
}

impl IoUringSqe {
    pub fn operation(&self) -> IoUringOp {
        IoUringOp::from(self.opcode)
    }

    pub fn target_fd(&self) -> i32 {
        self.fd
    }

    pub fn is_sensitive(&self) -> bool {
        self.operation().is_sensitive()
    }
}

/// Read SQEs from a process's io_uring submission queue.
///
/// This requires:
/// 1. Finding the ring's mmap region in `/proc/\[pid\]/maps`
/// 2. Reading the sq_head/sq_tail from the ring
/// 3. Reading pending SQEs from the array
///
/// Returns None if we can't read (permission denied, process exited, etc.)
pub fn read_pending_sqes(_pid: u32, _ring_fd: i32) -> Option<Vec<IoUringSqe>> {
    // This is complex and requires understanding io_uring internals.
    // The ring is mmap'd into userspace at specific offsets.
    // For now, return None — the eBPF approach is more reliable.
    //
    // Real implementation would:
    // 1. Parse /proc/[pid]/maps to find io_uring mmap regions
    // 2. Attach via ptrace or open /proc/[pid]/mem
    // 3. Read the io_sq_ring structure to get head/tail
    // 4. Read SQE array entries between head and tail
    None
}

/// Identify io_uring mmap regions in a process's address space.
pub fn find_iouring_mmaps(pid: u32) -> Vec<IoUringMmap> {
    let mut regions = Vec::new();

    let maps_path = format!("/proc/{}/maps", pid);
    let maps = match std::fs::read_to_string(&maps_path) {
        Ok(m) => m,
        Err(_) => return regions,
    };

    for line in maps.lines() {
        // io_uring regions are anonymous but have specific sizes
        // SQ ring: 256KB typical
        // CQ ring: 512KB typical
        // SQE array: varies by sq_entries

        if line.contains("anon_inode:[io_uring]") || (line.contains("rw-s") && !line.contains('/'))
        {
            // Parse the line: start-end perms offset dev inode pathname
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                let addrs: Vec<&str> = parts[0].split('-').collect();
                if addrs.len() == 2 {
                    if let (Ok(start), Ok(end)) = (
                        u64::from_str_radix(addrs[0], 16),
                        u64::from_str_radix(addrs[1], 16),
                    ) {
                        regions.push(IoUringMmap {
                            start,
                            end,
                            size: end - start,
                        });
                    }
                }
            }
        }
    }

    regions
}

#[derive(Debug, Clone)]
pub struct IoUringMmap {
    pub start: u64,
    pub end: u64,
    pub size: u64,
}
