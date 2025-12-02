#![allow(dead_code, unused_imports)]
//! Runtime memory permission auditing for self-protection (Linux).

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::RwLock;
use tracing::{error, info, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub private: bool,
    pub offset: u64,
    pub device: String,
    pub inode: u64,
    pub pathname: Option<String>,
}

impl MemoryRegion {
    pub fn is_rwx(&self) -> bool {
        self.read && self.write && self.execute
    }
    pub fn is_executable(&self) -> bool {
        self.execute
    }
    pub fn size(&self) -> u64 {
        self.end - self.start
    }
    pub fn is_text_section(&self, exe_path: &str) -> bool {
        self.execute
            && !self.write
            && self
                .pathname
                .as_ref()
                .map(|p| p == exe_path)
                .unwrap_or(false)
    }
}

#[cfg(target_os = "linux")]
pub fn get_memory_regions() -> Result<Vec<MemoryRegion>, std::io::Error> {
    let file = File::open("/proc/self/maps")?;
    let reader = BufReader::new(file);
    let mut regions = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if let Some(region) = parse_maps_line(&line) {
            regions.push(region);
        }
    }
    Ok(regions)
}

#[cfg(not(target_os = "linux"))]
pub fn get_memory_regions() -> Result<Vec<MemoryRegion>, std::io::Error> {
    Ok(Vec::new())
}

fn parse_maps_line(line: &str) -> Option<MemoryRegion> {
    let mut parts = line.split_whitespace();
    let addr_range = parts.next()?;
    let mut addrs = addr_range.split('-');
    let start = u64::from_str_radix(addrs.next()?, 16).ok()?;
    let end = u64::from_str_radix(addrs.next()?, 16).ok()?;
    let perms = parts.next()?;
    let perms_bytes = perms.as_bytes();
    if perms_bytes.len() < 4 {
        return None;
    }
    let read = perms_bytes[0] == b'r';
    let write = perms_bytes[1] == b'w';
    let execute = perms_bytes[2] == b'x';
    let private = perms_bytes[3] == b'p';
    let offset = u64::from_str_radix(parts.next()?, 16).ok()?;
    let device = parts.next()?.to_string();
    let inode = parts.next()?.parse().ok()?;
    let pathname = parts.next().map(|s| {
        let rest: Vec<&str> = parts.collect();
        if rest.is_empty() {
            s.to_string()
        } else {
            format!("{} {}", s, rest.join(" "))
        }
    });
    Some(MemoryRegion {
        start,
        end,
        read,
        write,
        execute,
        private,
        offset,
        device,
        inode,
        pathname,
    })
}

#[derive(Debug, Clone)]
pub struct MemoryAuditResult {
    pub rwx_regions: Vec<MemoryRegion>,
    pub new_executable_regions: Vec<MemoryRegion>,
    pub text_modified: bool,
    pub total_regions: usize,
    pub executable_regions: usize,
    pub total_memory: u64,
}

impl MemoryAuditResult {
    pub fn has_violations(&self) -> bool {
        !self.rwx_regions.is_empty() || self.text_modified
    }
}

pub struct MemoryAuditor {
    exe_path: String,
    text_hash: RwLock<Option<[u8; 32]>>,
    known_executable: RwLock<HashMap<(u64, u64), String>>,
}

impl MemoryAuditor {
    pub fn new() -> Self {
        let exe_path = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        Self {
            exe_path,
            text_hash: RwLock::new(None),
            known_executable: RwLock::new(HashMap::new()),
        }
    }

    pub fn init_baseline(&self) -> Result<(), std::io::Error> {
        let regions = get_memory_regions()?;
        let hash = self.hash_text_section(&regions)?;
        *self.text_hash.write().unwrap() = Some(hash);
        let mut known = self.known_executable.write().unwrap();
        for r in &regions {
            if r.is_executable() {
                known.insert((r.start, r.end), r.pathname.clone().unwrap_or_default());
            }
        }
        info!(
            regions = regions.len(),
            executable = known.len(),
            "Memory audit baseline established"
        );
        Ok(())
    }

    fn hash_text_section(&self, regions: &[MemoryRegion]) -> Result<[u8; 32], std::io::Error> {
        let mut hasher = Sha256::new();
        for r in regions {
            if r.is_text_section(&self.exe_path) {
                let slice =
                    unsafe { std::slice::from_raw_parts(r.start as *const u8, r.size() as usize) };
                hasher.update(slice);
            }
        }
        Ok(hasher.finalize().into())
    }

    pub fn audit(&self) -> Result<MemoryAuditResult, std::io::Error> {
        let regions = get_memory_regions()?;
        let rwx_regions: Vec<_> = regions.iter().filter(|r| r.is_rwx()).cloned().collect();
        let known = self.known_executable.read().unwrap();
        let new_exec: Vec<_> = regions
            .iter()
            .filter(|r| r.is_executable())
            .filter(|r| !known.contains_key(&(r.start, r.end)))
            .cloned()
            .collect();
        let text_modified = if let Some(baseline) = *self.text_hash.read().unwrap() {
            match self.hash_text_section(&regions) {
                Ok(cur) => cur != baseline,
                Err(_) => true,
            }
        } else {
            false
        };
        let exec_count = regions.iter().filter(|r| r.is_executable()).count();
        let total_mem: u64 = regions.iter().map(|r| r.size()).sum();
        Ok(MemoryAuditResult {
            rwx_regions,
            new_executable_regions: new_exec,
            text_modified,
            total_regions: regions.len(),
            executable_regions: exec_count,
            total_memory: total_mem,
        })
    }

    pub fn check_and_log(&self) -> bool {
        match self.audit() {
            Ok(res) => {
                if !res.rwx_regions.is_empty() {
                    for r in &res.rwx_regions {
                        error!(
                            start = format!("{:#x}", r.start),
                            end = format!("{:#x}", r.end),
                            path = ?r.pathname,
                            "RWX region detected"
                        );
                    }
                }
                if !res.new_executable_regions.is_empty() {
                    for r in &res.new_executable_regions {
                        warn!(
                            start = format!("{:#x}", r.start),
                            end = format!("{:#x}", r.end),
                            path = ?r.pathname,
                            "New executable region detected"
                        );
                    }
                }
                if res.text_modified {
                    error!("Executable text section modified");
                }
                !res.has_violations()
            }
            Err(e) => {
                warn!(error = %e, "Memory audit failed");
                true
            }
        }
    }

    pub fn update_baseline(&self) -> Result<(), std::io::Error> {
        let regions = get_memory_regions()?;
        let mut known = self.known_executable.write().unwrap();
        known.clear();
        for r in &regions {
            if r.is_executable() {
                known.insert((r.start, r.end), r.pathname.clone().unwrap_or_default());
            }
        }
        Ok(())
    }
}

impl Default for MemoryAuditor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_line() {
        let line = "7f9c4e000000-7f9c4e001000 r-xp 00000000 08:01 12345 /usr/bin/foo";
        let region = parse_maps_line(line).unwrap();
        assert!(region.read);
        assert!(region.execute);
    }
}
