//! Parse /proc/[pid]/maps to find legitimate code regions.

use std::fs;

use serde::Serialize;

/// Memory region from /proc/[pid]/maps.
#[derive(Debug, Clone, Serialize)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub offset: u64,
    pub path: String,
    pub is_executable: bool,
}

impl MemoryRegion {
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    pub fn is_libc(&self) -> bool {
        self.path.contains("libc") || self.path.contains("ld-linux")
    }

    pub fn is_anonymous(&self) -> bool {
        self.path.is_empty()
            || self.path == "[heap]"
            || self.path == "[stack]"
            || self.path.starts_with("[anon")
    }

    pub fn is_legitimate_syscall_source(&self) -> bool {
        // Legitimate sources of syscalls:
        // - libc.so
        // - ld-linux.so (dynamic linker)
        // - vdso (kernel-provided)
        // - Some JIT regions for JITted syscalls (rare)
        self.is_libc() || self.path.contains("[vdso]") || self.path.contains("ld-linux")
    }
}

/// Parse memory maps for a process.
pub fn parse_maps(pid: u32) -> Option<Vec<MemoryRegion>> {
    let maps_path = format!("/proc/{}/maps", pid);
    let content = fs::read_to_string(&maps_path).ok()?;

    let mut regions = Vec::new();

    for line in content.lines() {
        if let Some(region) = parse_maps_line(line) {
            regions.push(region);
        }
    }

    Some(regions)
}

fn parse_maps_line(line: &str) -> Option<MemoryRegion> {
    // Format: start-end perms offset dev inode [pathname]
    // Example: 7f9c4e000000-7f9c4e001000 r-xp 00000000 08:01 12345 /usr/lib/libc.so.6

    let parts: Vec<&str> = line.splitn(6, ' ').collect();
    if parts.len() < 5 {
        return None;
    }

    let addrs: Vec<&str> = parts[0].split('-').collect();
    if addrs.len() != 2 {
        return None;
    }

    let start = u64::from_str_radix(addrs[0], 16).ok()?;
    let end = u64::from_str_radix(addrs[1], 16).ok()?;
    let permissions = parts[1].to_string();
    let offset = u64::from_str_radix(parts[2], 16).unwrap_or(0);
    let path = parts
        .get(5)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let is_executable = permissions.contains('x');

    Some(MemoryRegion {
        start,
        end,
        permissions,
        offset,
        path,
        is_executable,
    })
}

/// Find the region containing an address.
pub fn find_region(regions: &[MemoryRegion], addr: u64) -> Option<&MemoryRegion> {
    regions.iter().find(|r| r.contains(addr))
}

/// Get all libc regions for a process.
pub fn get_libc_regions(pid: u32) -> Option<Vec<MemoryRegion>> {
    let regions = parse_maps(pid)?;
    Some(regions.into_iter().filter(|r| r.is_libc()).collect())
}
