use std::fs;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use tracing::debug;

use crate::anomaly::MemoryAnomaly;
use crate::patterns::ShellcodePatterns;

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub pathname: String,
}

impl MemoryRegion {
    pub fn size(&self) -> u64 {
        self.end - self.start
    }
    pub fn is_readable(&self) -> bool {
        self.permissions.starts_with('r')
    }
    pub fn is_writable(&self) -> bool {
        self.permissions.chars().nth(1) == Some('w')
    }
    pub fn is_executable(&self) -> bool {
        self.permissions.chars().nth(2) == Some('x')
    }
    pub fn is_rwx(&self) -> bool {
        self.is_readable() && self.is_writable() && self.is_executable()
    }
    pub fn is_anonymous(&self) -> bool {
        self.pathname.is_empty() || self.pathname.starts_with('[')
    }
}

#[derive(Debug, Clone)]
pub struct MemoryScanResult {
    pub pid: u32,
    pub comm: String,
    pub threats_found: Vec<MemoryThreat>,
    pub anomalies: Vec<MemoryAnomaly>,
    pub regions_scanned: usize,
    pub bytes_scanned: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryThreatType {
    Shellcode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct MemoryThreat {
    pub threat_type: MemoryThreatType,
    pub region: MemoryRegion,
    pub offset_in_region: u64,
    pub description: String,
    pub severity: ThreatSeverity,
    pub evidence: Vec<u8>,
}

pub struct MemoryScanner {
    patterns: ShellcodePatterns,
    max_region_size: u64,
    max_bytes_per_process: u64,
}

impl MemoryScanner {
    pub fn new() -> Self {
        Self {
            patterns: ShellcodePatterns::new(),
            max_region_size: 50 * 1024 * 1024,
            max_bytes_per_process: 200 * 1024 * 1024,
        }
    }

    pub fn scan_process(&self, pid: u32) -> Result<MemoryScanResult, ScanError> {
        let comm = self.get_comm(pid)?;
        let regions = self.get_memory_regions(pid)?;
        let mut result = MemoryScanResult {
            pid,
            comm: comm.clone(),
            threats_found: Vec::new(),
            anomalies: Vec::new(),
            regions_scanned: 0,
            bytes_scanned: 0,
        };

        for region in &regions {
            if region.is_rwx() {
                result.anomalies.push(MemoryAnomaly::RwxRegion {
                    address: region.start,
                    size: region.size(),
                    pathname: region.pathname.clone(),
                });
            }
            if region.is_executable() && region.is_anonymous() {
                result.anomalies.push(MemoryAnomaly::AnonymousExecutable {
                    address: region.start,
                    size: region.size(),
                });
            }
        }

        let mem_path = format!("/proc/{}/mem", pid);
        let mut mem_file = match File::open(&mem_path) {
            Ok(f) => f,
            Err(e) => {
                debug!("Cannot open {}: {}", mem_path, e);
                return Ok(result);
            }
        };

        for region in &regions {
            if !self.should_scan_region(region) {
                continue;
            }
            if result.bytes_scanned >= self.max_bytes_per_process {
                break;
            }
            if let Some(threats) = self.scan_region(&mut mem_file, region)? {
                result.threats_found.extend(threats);
            }
            result.regions_scanned += 1;
            result.bytes_scanned += region.size();
        }

        Ok(result)
    }

    fn get_comm(&self, pid: u32) -> Result<String, ScanError> {
        let path = format!("/proc/{}/comm", pid);
        fs::read_to_string(&path)
            .map(|s| s.trim().to_string())
            .map_err(|_| ScanError::ProcessNotFound(pid))
    }

    fn get_memory_regions(&self, pid: u32) -> Result<Vec<MemoryRegion>, ScanError> {
        let maps_path = format!("/proc/{}/maps", pid);
        let content =
            fs::read_to_string(&maps_path).map_err(|_| ScanError::ProcessNotFound(pid))?;
        let mut regions = Vec::new();
        for line in content.lines() {
            if let Some(r) = parse_maps_line(line) {
                regions.push(r);
            }
        }
        Ok(regions)
    }

    fn should_scan_region(&self, region: &MemoryRegion) -> bool {
        region.is_readable()
            && region.size() <= self.max_region_size
            && (region.is_executable() || region.is_rwx())
    }

    fn scan_region(
        &self,
        mem_file: &mut File,
        region: &MemoryRegion,
    ) -> Result<Option<Vec<MemoryThreat>>, ScanError> {
        if mem_file.seek(SeekFrom::Start(region.start)).is_err() {
            return Ok(None);
        }
        let size = region.size().min(self.max_region_size) as usize;
        let mut buf = vec![0u8; size];
        if mem_file.read_exact(&mut buf).is_err() {
            return Ok(None);
        }
        let mut threats = Vec::new();
        for (offset, name) in self.patterns.scan(&buf) {
            let evidence_end = (offset + 64).min(buf.len());
            threats.push(MemoryThreat {
                threat_type: MemoryThreatType::Shellcode,
                region: region.clone(),
                offset_in_region: offset as u64,
                description: format!("Shellcode pattern: {}", name),
                severity: ThreatSeverity::Critical,
                evidence: buf[offset..evidence_end].to_vec(),
            });
        }
        if threats.is_empty() {
            Ok(None)
        } else {
            Ok(Some(threats))
        }
    }
}

fn parse_maps_line(line: &str) -> Option<MemoryRegion> {
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
    Some(MemoryRegion {
        start,
        end,
        permissions: parts[1].to_string(),
        pathname: parts
            .get(5)
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
    })
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("Process {0} not found or not accessible")]
    ProcessNotFound(u32),
    #[error("Memory read error: {0}")]
    ReadError(String),
}
