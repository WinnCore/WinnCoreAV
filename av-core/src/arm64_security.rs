//! # ARM64 Security Capability Detection
//!
//! Introspects hardware-backed control-flow protections that only exist on
//! 64-bit ARM systems. The capabilities we surface (PAC, BTI, MTE) are used
//! to decide whether to enable hardened monitoring paths and to flag binaries
//! that ship without architectural protections.
//!
//! ## Architecture
//! - Primary detection path reads `ID_AA64ISAR1_EL1` and `ID_AA64PFR1_EL1`
//!   via inline assembly when running on AArch64.
//! - Secondary path parses `/proc/cpuinfo` feature flags to remain functional
//!   on constrained or virtualized environments where system registers are
//!   masked.
//! - Results are cached in-process via `once_cell::sync::Lazy` to avoid
//!   re-reading registers or files on hot paths.
//!
//! ## Performance Considerations
//! - Single-shot register reads and a small string parse; no heap growth after
//!   the first call thanks to caching.
//! - Intended to run during startup/config validation, not per-file scan.
//!
//! ## Safety Notes
//! - Inline assembly is isolated behind `target_arch = "aarch64"` guards.
//! - All failures degrade gracefully to `DetectionMethod::Unknown` so callers
//!   never hit a panic or unwrap.

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, instrument, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Arm64SecurityCapabilities {
    pub has_pac: bool,
    pub has_bti: bool,
    pub has_mte: bool,
    pub detection_method: DetectionMethod,
    pub is_aarch64: bool,
    pub notes: Vec<String>,
}

/// ELF-level protection markers for AArch64 binaries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BinaryProtectionStatus {
    pub is_aarch64_elf: bool,
    pub has_gnu_property_note: bool,
    pub pac_marked: bool,
    pub bti_marked: bool,
    pub parsing_notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DetectionMethod {
    SystemRegister,
    CpuInfo,
    Mixed,
    Unknown,
}

#[derive(Debug, Error)]
pub enum Arm64SecurityError {
    #[error("system register access not available")]
    SysRegUnavailable,

    #[error("failed to read /proc/cpuinfo: {source}")]
    CpuInfo {
        #[from]
        source: std::io::Error,
    },
}

#[derive(Debug)]
struct SystemRegisters {
    isar1: u64,
    pfr1: u64,
}

#[derive(Debug, Default, Clone, Copy)]
struct CpuInfoFeatures {
    pac: bool,
    bti: bool,
    mte: bool,
    matched_line: bool,
}

static DETECTED_CAPABILITIES: Lazy<Arm64SecurityCapabilities> =
    Lazy::new(|| match detect_arm64_capabilities() {
        Ok(capabilities) => capabilities,
        Err(err) => {
            warn!(
                ?err,
                "ARM64 capability detection failed; returning conservative defaults"
            );
            Arm64SecurityCapabilities {
                has_pac: false,
                has_bti: false,
                has_mte: false,
                detection_method: DetectionMethod::Unknown,
                is_aarch64: cfg!(target_arch = "aarch64"),
                notes: vec![format!("Detection failed: {err}")],
            }
        }
    });

/// Return cached ARM64 security capabilities. The first call executes the
/// detection routine; subsequent calls are zero-allocation reads.
pub fn capabilities() -> Arm64SecurityCapabilities {
    DETECTED_CAPABILITIES.clone()
}

/// Parse an ELF (if present) and attempt to discover GNU property bits that
/// declare PAC/BTI enablement for ARM64. Returns `BinaryProtectionStatus`
/// describing what we found without failing the scan if parsing fails.
pub fn analyze_elf_protections(bytes: &[u8]) -> BinaryProtectionStatus {
    match goblin::elf::Elf::parse(bytes) {
        Ok(elf) => analyze_gnu_properties(bytes, &elf),
        Err(err) => BinaryProtectionStatus {
            parsing_notes: vec![format!("Not an ELF: {err}")],
            ..BinaryProtectionStatus::default()
        },
    }
}

#[instrument]
fn detect_arm64_capabilities() -> Result<Arm64SecurityCapabilities, Arm64SecurityError> {
    #[cfg(target_arch = "aarch64")]
    {
        match read_system_registers() {
            Ok(registers) => {
                let mut notes = vec![
                    format!("ID_AA64ISAR1_EL1=0x{:016x}", registers.isar1),
                    format!("ID_AA64PFR1_EL1=0x{:016x}", registers.pfr1),
                ];

                let pac = has_pac_from_isar1(registers.isar1);
                let bti = has_bti_from_pfr1(registers.pfr1);
                let mte = has_mte_from_pfr1(registers.pfr1);

                let mut method = DetectionMethod::SystemRegister;
                if let Ok(cpuinfo) = parse_cpuinfo_fallback() {
                    // Combine register-backed and CPU-info backed views so we
                    // stay resilient to virtualization quirks.
                    let merged_pac = pac || cpuinfo.pac;
                    let merged_bti = bti || cpuinfo.bti;
                    let merged_mte = mte || cpuinfo.mte;
                    if cpuinfo.matched_line {
                        method = DetectionMethod::Mixed;
                        notes.push("Validated features against /proc/cpuinfo".to_string());
                    }
                    return Ok(Arm64SecurityCapabilities {
                        has_pac: merged_pac,
                        has_bti: merged_bti,
                        has_mte: merged_mte,
                        detection_method: method,
                        is_aarch64: true,
                        notes,
                    });
                }

                Ok(Arm64SecurityCapabilities {
                    has_pac: pac,
                    has_bti: bti,
                    has_mte: mte,
                    detection_method: method,
                    is_aarch64: true,
                    notes,
                })
            }
            Err(err) => {
                debug!(
                    ?err,
                    "System register access unavailable; falling back to cpuinfo"
                );
                let mut caps = cpuinfo_only_capabilities()?;
                caps.notes
                    .push("System registers unavailable; used cpuinfo fallback".to_string());
                Ok(caps)
            }
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        let mut caps = cpuinfo_only_capabilities()?;
        caps.notes
            .push("Not running on aarch64 target; inline register reads skipped".to_string());
        return Ok(caps);
    }
}

fn cpuinfo_only_capabilities() -> Result<Arm64SecurityCapabilities, Arm64SecurityError> {
    let features = parse_cpuinfo_fallback()?;
    let mut notes = vec!["Parsed /proc/cpuinfo for ARM64 features".to_string()];
    if !features.matched_line {
        notes.push("No feature line found; capabilities default to false".to_string());
    }
    Ok(Arm64SecurityCapabilities {
        has_pac: features.pac,
        has_bti: features.bti,
        has_mte: features.mte,
        detection_method: DetectionMethod::CpuInfo,
        is_aarch64: cfg!(target_arch = "aarch64"),
        notes,
    })
}

#[cfg(target_arch = "aarch64")]
fn read_system_registers() -> Result<SystemRegisters, Arm64SecurityError> {
    let isar1: u64;
    let pfr1: u64;
    unsafe {
        core::arch::asm!("mrs {0}, ID_AA64ISAR1_EL1", out(reg) isar1);
        core::arch::asm!("mrs {0}, ID_AA64PFR1_EL1", out(reg) pfr1);
    }
    Ok(SystemRegisters { isar1, pfr1 })
}

#[cfg(not(target_arch = "aarch64"))]
fn read_system_registers() -> Result<SystemRegisters, Arm64SecurityError> {
    Err(Arm64SecurityError::SysRegUnavailable)
}

fn parse_cpuinfo_fallback() -> Result<CpuInfoFeatures, Arm64SecurityError> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo")?;
    Ok(parse_cpuinfo_features(&cpuinfo))
}

fn parse_cpuinfo_features(cpuinfo: &str) -> CpuInfoFeatures {
    let mut features = CpuInfoFeatures::default();
    for line in cpuinfo.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("features") || lower.starts_with("flags") {
            features.matched_line = true;
            for token in lower.split_whitespace() {
                match token.trim_end_matches(':') {
                    "paca" | "pacg" | "pauth" => features.pac = true,
                    "bti" => features.bti = true,
                    "mte" => features.mte = true,
                    _ => {}
                }
            }
        }
    }
    features
}

fn has_pac_from_isar1(register: u64) -> bool {
    const FIELD_MASK: u64 = 0xF;
    const APA_SHIFT: u64 = 4;
    const API_SHIFT: u64 = 8;
    const GPA_SHIFT: u64 = 24;
    const GPI_SHIFT: u64 = 28;

    // ARM ID registers encode pointer authentication capabilities in four
    // nibble-sized fields. Any non-zero value indicates support.
    let fields = [
        (register >> APA_SHIFT) & FIELD_MASK,
        (register >> API_SHIFT) & FIELD_MASK,
        (register >> GPA_SHIFT) & FIELD_MASK,
        (register >> GPI_SHIFT) & FIELD_MASK,
    ];
    fields.iter().any(|field| *field > 0)
}

fn has_bti_from_pfr1(register: u64) -> bool {
    const FIELD_MASK: u64 = 0xF;
    const BTI_SHIFT: u64 = 4;
    ((register >> BTI_SHIFT) & FIELD_MASK) > 0
}

fn has_mte_from_pfr1(register: u64) -> bool {
    const FIELD_MASK: u64 = 0xF;
    const MTE_SHIFT: u64 = 8;
    ((register >> MTE_SHIFT) & FIELD_MASK) > 0
}

const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc0000000;
const GNU_PROPERTY_AARCH64_FEATURE_1_BTI: u32 = 1;
const GNU_PROPERTY_AARCH64_FEATURE_1_PAC: u32 = 2;

fn analyze_gnu_properties(bytes: &[u8], elf: &goblin::elf::Elf) -> BinaryProtectionStatus {
    if elf.header.e_machine != goblin::elf::header::EM_AARCH64 {
        return BinaryProtectionStatus {
            parsing_notes: vec!["ELF not AArch64; skipping GNU property analysis".to_string()],
            ..BinaryProtectionStatus::default()
        };
    }

    let mut status = BinaryProtectionStatus {
        is_aarch64_elf: true,
        ..BinaryProtectionStatus::default()
    };

    for ph in &elf.program_headers {
        if ph.p_type != goblin::elf::program_header::PT_NOTE
            && ph.p_type != goblin::elf::program_header::PT_GNU_PROPERTY
        {
            continue;
        }
        let start = ph.p_offset as usize;
        let end = start.saturating_add(ph.p_filesz as usize);
        if end > bytes.len() || start >= end {
            status
                .parsing_notes
                .push("Invalid PT_NOTE bounds".to_string());
            continue;
        }
        let mut cursor = start;
        while cursor + 12 <= end {
            let namesz = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
            let descsz =
                u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
            let note_type = u32::from_le_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap());

            let name_start = cursor + 12;
            let name_end = name_start.saturating_add(namesz);
            if name_end > end {
                status
                    .parsing_notes
                    .push("Note name exceeds bounds".to_string());
                break;
            }
            let desc_start = align_to(name_end, 4);
            let desc_end = desc_start.saturating_add(descsz);
            if desc_end > end {
                status
                    .parsing_notes
                    .push("Note desc exceeds bounds".to_string());
                break;
            }

            if note_type == NT_GNU_PROPERTY_TYPE_0 {
                status.has_gnu_property_note = true;
                let mut desc_cursor = desc_start;
                while desc_cursor + 8 <= desc_end {
                    let pr_type =
                        u32::from_le_bytes(bytes[desc_cursor..desc_cursor + 4].try_into().unwrap());
                    let pr_datasz = u32::from_le_bytes(
                        bytes[desc_cursor + 4..desc_cursor + 8].try_into().unwrap(),
                    ) as usize;
                    let data_start = desc_cursor + 8;
                    let data_end = data_start.saturating_add(pr_datasz);
                    if data_end > desc_end {
                        status
                            .parsing_notes
                            .push("Property data exceeds desc bounds".to_string());
                        break;
                    }
                    if pr_type == GNU_PROPERTY_AARCH64_FEATURE_1_AND && pr_datasz >= 4 {
                        let features = u32::from_le_bytes(
                            bytes[data_start..data_start + 4].try_into().unwrap(),
                        );
                        if features & GNU_PROPERTY_AARCH64_FEATURE_1_BTI != 0 {
                            status.bti_marked = true;
                        }
                        if features & GNU_PROPERTY_AARCH64_FEATURE_1_PAC != 0 {
                            status.pac_marked = true;
                        }
                    }
                    desc_cursor = align_to(data_end, 8);
                }
            }

            cursor = align_to(desc_end, 4);
        }
    }

    if !status.has_gnu_property_note {
        status
            .parsing_notes
            .push("No GNU property note advertising PAC/BTI".to_string());
    }

    status
}

const fn align_to(value: usize, align: usize) -> usize {
    (value + (align - 1)) & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pac_fields_from_isar1() {
        // Set APA and GPA fields to non-zero values.
        let register = (0x1 << 4) | (0x1 << 24);
        assert!(has_pac_from_isar1(register));
    }

    #[test]
    fn detects_absent_pac_fields() {
        assert!(!has_pac_from_isar1(0));
    }

    #[test]
    fn parses_bti_and_mte_from_pfr1() {
        let register = (0x1 << 4) | (0x2 << 8);
        assert!(has_bti_from_pfr1(register));
        assert!(has_mte_from_pfr1(register));
    }

    #[test]
    fn parses_cpuinfo_features_line() {
        let cpuinfo = "Features\t: fp asimd bti paca pacg mte\n";
        let parsed = parse_cpuinfo_features(cpuinfo);
        assert!(parsed.pac);
        assert!(parsed.bti);
        assert!(parsed.mte);
        assert!(parsed.matched_line);
    }

    #[test]
    fn parses_gnu_property_feature_bits() {
        let mut bytes = vec![0u8; 0x200];
        // ELF header magic
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2; // 64-bit
        bytes[5] = 1; // little endian
        bytes[6] = 1; // version
                      // e_machine = EM_AARCH64 (183)
        bytes[18] = 183u8;
        // e_phoff = 0x40, e_ehsize = 0x40
        bytes[32..40].copy_from_slice(&(0x40u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&(0x40u16).to_le_bytes());
        // e_phentsize = 56, e_phnum = 1
        bytes[54..56].copy_from_slice(&(56u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&(1u16).to_le_bytes());

        // Program header at 0x40
        let ph_offset = 0x40;
        let note_offset = 0x100u64;
        let note_size = 0x40u64;
        // p_type = PT_NOTE (4)
        bytes[ph_offset..ph_offset + 4]
            .copy_from_slice(&(goblin::elf::program_header::PT_NOTE).to_le_bytes());
        // p_offset
        bytes[ph_offset + 8..ph_offset + 16].copy_from_slice(&note_offset.to_le_bytes());
        // p_filesz
        bytes[ph_offset + 32..ph_offset + 40].copy_from_slice(&note_size.to_le_bytes());

        // Note payload at 0x100
        let mut cursor = note_offset as usize;
        let namesz: u32 = 4;
        let descsz: u32 = 0x18;
        let note_type: u32 = NT_GNU_PROPERTY_TYPE_0;
        bytes[cursor..cursor + 4].copy_from_slice(&namesz.to_le_bytes());
        bytes[cursor + 4..cursor + 8].copy_from_slice(&descsz.to_le_bytes());
        bytes[cursor + 8..cursor + 12].copy_from_slice(&note_type.to_le_bytes());
        cursor += 12;
        bytes[cursor..cursor + 4].copy_from_slice(b"GNU\0");
        cursor = align_to(cursor + 4, 4);

        // Property entry: type AND, data size 4, value BTI|PAC
        bytes[cursor..cursor + 4]
            .copy_from_slice(&GNU_PROPERTY_AARCH64_FEATURE_1_AND.to_le_bytes());
        bytes[cursor + 4..cursor + 8].copy_from_slice(&(4u32).to_le_bytes());
        bytes[cursor + 8..cursor + 12].copy_from_slice(
            &(GNU_PROPERTY_AARCH64_FEATURE_1_BTI | GNU_PROPERTY_AARCH64_FEATURE_1_PAC)
                .to_le_bytes(),
        );

        let status = analyze_elf_protections(&bytes);
        assert!(status.is_aarch64_elf);
        assert!(status.has_gnu_property_note);
        assert!(status.pac_marked);
        assert!(status.bti_marked);
    }

    #[cfg(not(target_arch = "aarch64"))]
    #[test]
    fn detection_degrades_gracefully_on_non_arm() {
        let caps = capabilities();
        assert!(!caps.has_pac);
        assert!(!caps.has_bti);
        assert!(!caps.has_mte);
        assert!(matches!(
            caps.detection_method,
            DetectionMethod::CpuInfo | DetectionMethod::Unknown
        ));
    }
}
