#![allow(dead_code, unused_imports)]
//! ASLR verification helpers.

use std::collections::HashSet;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub struct AslrCheckResult {
    pub system_aslr_level: u8,
    pub is_pie: bool,
    pub stack_addr: Option<u64>,
    pub heap_addr: Option<u64>,
    pub exe_addr: Option<u64>,
    pub lib_addrs: Vec<u64>,
    pub estimated_entropy_bits: Option<u32>,
    pub is_sufficient: bool,
    pub warnings: Vec<String>,
}

impl AslrCheckResult {
    pub fn is_ok(&self) -> bool {
        self.system_aslr_level >= 2 && self.is_pie && self.is_sufficient
    }
}

#[cfg(target_os = "linux")]
pub fn get_system_aslr_level() -> u8 {
    std::fs::read_to_string("/proc/sys/kernel/randomize_va_space")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
pub fn get_system_aslr_level() -> u8 {
    2
}

#[cfg(target_os = "linux")]
pub fn is_process_pie() -> bool {
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        if let Some(first_line) = maps.lines().next() {
            if let Some(addr_range) = first_line.split_whitespace().next() {
                if let Some(addr_str) = addr_range.split('-').next() {
                    if let Ok(addr) = u64::from_str_radix(addr_str, 16) {
                        return addr > 0x10000000 && addr != 0x400000;
                    }
                }
            }
        }
    }
    if let Ok(exe_path) = std::fs::read_link("/proc/self/exe") {
        if let Ok(data) = std::fs::read(&exe_path) {
            if data.len() > 18 && &data[0..4] == b"\x7fELF" {
                let e_type = u16::from_le_bytes([data[16], data[17]]);
                return e_type == 3;
            }
        }
    }
    true
}

#[cfg(not(target_os = "linux"))]
pub fn is_process_pie() -> bool {
    true
}

fn get_stack_address() -> Option<u64> {
    let local: u64 = 0;
    Some(&local as *const _ as u64)
}

fn get_heap_address() -> Option<u64> {
    let b = Box::new(0u64);
    Some(&*b as *const _ as u64)
}

#[cfg(target_os = "linux")]
fn get_exe_base_address() -> Option<u64> {
    let exe = std::fs::read_link("/proc/self/exe").ok()?;
    let exe_str = exe.to_string_lossy();
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        if line.contains(&*exe_str) && line.contains("r-x") {
            if let Some(range) = line.split_whitespace().next() {
                if let Some(addr) = range.split('-').next() {
                    if let Ok(v) = u64::from_str_radix(addr, 16) {
                        return Some(v);
                    }
                }
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn get_exe_base_address() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn get_library_addresses() -> Vec<u64> {
    let mut addrs = Vec::new();
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        let mut seen = HashSet::new();
        for line in maps.lines() {
            if line.contains(".so") && line.contains("r-x") {
                if let Some(path) = line.split_whitespace().last() {
                    if path.contains(".so") && seen.insert(path.to_string()) {
                        if let Some(range) = line.split_whitespace().next() {
                            if let Some(addr) = range.split('-').next() {
                                if let Ok(v) = u64::from_str_radix(addr, 16) {
                                    addrs.push(v);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    addrs
}

#[cfg(not(target_os = "linux"))]
fn get_library_addresses() -> Vec<u64> {
    Vec::new()
}

fn estimate_entropy(exe_addr: Option<u64>) -> Option<u32> {
    if let Some(addr) = exe_addr {
        if cfg!(target_arch = "aarch64") {
            if addr >= 0x5500_0000_00 {
                return Some(28);
            } else if addr == 0x400000 {
                return Some(0);
            }
        } else if cfg!(target_arch = "x86_64") {
            if addr >= 0x5555_0000_0000 {
                return Some(28);
            } else if addr == 0x400000 {
                return Some(0);
            }
        }
    }
    Some(20)
}

pub fn verify_aslr() -> AslrCheckResult {
    let system_level = get_system_aslr_level();
    let is_pie = is_process_pie();
    let stack_addr = get_stack_address();
    let heap_addr = get_heap_address();
    let exe_addr = get_exe_base_address();
    let lib_addrs = get_library_addresses();
    let estimated_entropy = estimate_entropy(exe_addr);

    let mut warnings = Vec::new();
    if system_level < 2 {
        warnings.push(format!("System ASLR level {} (want 2)", system_level));
    }
    if !is_pie {
        warnings.push("Process not PIE; base address fixed".into());
    }
    if let Some(bits) = estimated_entropy {
        if bits < 20 {
            warnings.push(format!("Estimated ASLR entropy {} bits (low)", bits));
        }
    }

    let is_sufficient =
        system_level >= 2 && is_pie && estimated_entropy.map(|b| b >= 20).unwrap_or(true);

    AslrCheckResult {
        system_aslr_level: system_level,
        is_pie,
        stack_addr,
        heap_addr,
        exe_addr,
        lib_addrs,
        estimated_entropy_bits: estimated_entropy,
        is_sufficient,
        warnings,
    }
}

pub fn check_and_log_aslr() -> bool {
    let result = verify_aslr();
    info!(
        system_level = result.system_aslr_level,
        is_pie = result.is_pie,
        entropy_bits = ?result.estimated_entropy_bits,
        sufficient = result.is_sufficient,
        "ASLR verification"
    );
    if let Some(addr) = result.exe_addr {
        debug!(addr = format!("{:#x}", addr), "Executable base address");
    }
    for w in &result.warnings {
        warn!("{}", w);
    }
    if !result.is_sufficient {
        error!("ASLR verification failed");
    }
    result.is_sufficient
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aslr_level() {
        let _ = get_system_aslr_level();
    }

    #[test]
    fn pie_detection() {
        let _ = is_process_pie();
    }
}
