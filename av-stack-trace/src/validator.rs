//! Validate syscall return addresses.

use std::collections::HashMap;

use serde::Serialize;
use tracing::warn;

use crate::maps::{find_region, parse_maps, MemoryRegion};

/// Result of validating a syscall's return address.
#[derive(Debug, Clone, Serialize)]
pub enum ValidationResult {
    /// Normal syscall through libc
    Legitimate { return_addr: u64, source: String },
    /// Direct syscall - suspicious
    DirectSyscall {
        return_addr: u64,
        region: Option<RegionInfo>,
    },
    /// Unknown - couldn't determine
    Unknown { return_addr: u64, reason: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct RegionInfo {
    pub start: u64,
    pub end: u64,
    pub path: String,
}

/// Stack trace validator.
pub struct SyscallValidator {
    /// Cache of process memory maps
    maps_cache: HashMap<u32, Vec<MemoryRegion>>,
}

impl SyscallValidator {
    pub fn new() -> Self {
        Self {
            maps_cache: HashMap::new(),
        }
    }

    /// Validate a syscall return address.
    ///
    /// `pid`: Process ID
    /// `return_addr`: Value of X30 (ARM64) or stack return address (x86_64)
    /// `syscall_nr`: Syscall number (for context)
    pub fn validate(&mut self, pid: u32, return_addr: u64, syscall_nr: u32) -> ValidationResult {
        // Get or refresh maps
        let regions = match self.get_maps(pid) {
            Some(r) => r,
            None => {
                return ValidationResult::Unknown {
                    return_addr,
                    reason: "Could not read process maps".to_string(),
                };
            }
        };

        // Find the region containing the return address
        let region = find_region(regions, return_addr);

        match region {
            Some(r) if r.is_legitimate_syscall_source() => ValidationResult::Legitimate {
                return_addr,
                source: r.path.clone(),
            },
            Some(r) => {
                // Return address is in a non-libc region
                warn!(
                    "Direct syscall detected: pid={} syscall={} return_addr=0x{:x} region={}",
                    pid, syscall_nr, return_addr, r.path
                );

                ValidationResult::DirectSyscall {
                    return_addr,
                    region: Some(RegionInfo {
                        start: r.start,
                        end: r.end,
                        path: r.path.clone(),
                    }),
                }
            }
            None => {
                // Return address doesn't map to any region - very suspicious
                warn!(
                    "Direct syscall from unmapped memory: pid={} return_addr=0x{:x}",
                    pid, return_addr
                );

                ValidationResult::DirectSyscall {
                    return_addr,
                    region: None,
                }
            }
        }
    }

    fn get_maps(&mut self, pid: u32) -> Option<&Vec<MemoryRegion>> {
        // Simple caching - in production, would need TTL
        if let std::collections::hash_map::Entry::Vacant(entry) = self.maps_cache.entry(pid) {
            if let Some(maps) = parse_maps(pid) {
                entry.insert(maps);
            }
        }
        self.maps_cache.get(&pid)
    }

    /// Clear maps cache for a process (call on process exit).
    pub fn invalidate_cache(&mut self, pid: u32) {
        self.maps_cache.remove(&pid);
    }

    /// Syscalls that should ALWAYS come from libc (high-value targets).
    pub fn is_high_value_syscall(syscall_nr: u32) -> bool {
        // ARM64 syscall numbers
        matches!(
            syscall_nr,
            221   // execve
                | 281  // execveat
                | 203  // connect
                | 206  // sendto
                | 198  // socket
                | 56   // openat
                | 63   // read
                | 64   // write
                | 93   // exit
                | 94 // exit_group
        )
    }
}

impl Default for SyscallValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Detect direct syscalls across all processes.
/// This is expensive - use sparingly or on high-risk processes only.
pub fn scan_for_direct_syscalls() -> Vec<DirectSyscallProcess> {
    // This would require ptrace or eBPF to catch syscalls in flight.
    // For now, return empty - actual implementation is via eBPF hooks.
    Vec::new()
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectSyscallProcess {
    pub pid: u32,
    pub comm: String,
    pub direct_syscall_count: u32,
    pub syscalls: Vec<u32>,
}
