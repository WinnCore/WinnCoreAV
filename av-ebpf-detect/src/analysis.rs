//! eBPF program analysis for threat detection.

use serde::Serialize;
use tracing::warn;

use crate::{
    baseline::BpfBaseline,
    enumerate::{BpfProgInfo, BpfProgType},
};

/// Result of eBPF security analysis.
#[derive(Debug, Clone, Serialize)]
pub struct BpfAnalysisResult {
    pub total_programs: usize,
    pub unknown_programs: Vec<UnknownProgram>,
    pub suspicious_combinations: Vec<SuspiciousCombination>,
    pub high_risk_programs: Vec<HighRiskProgram>,
    pub possible_rootkit: bool,
    pub risk_score: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnknownProgram {
    pub id: u32,
    pub name: String,
    pub prog_type: String,
    pub tag: String,
    pub loaded_by_uid: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuspiciousCombination {
    pub description: String,
    pub program_ids: Vec<u32>,
    pub mitre_technique: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HighRiskProgram {
    pub id: u32,
    pub name: String,
    pub reason: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum Severity {
    Medium,
    High,
    Critical,
}

/// Analyze eBPF programs for threats.
pub fn analyze_bpf_programs(programs: &[BpfProgInfo], baseline: &BpfBaseline) -> BpfAnalysisResult {
    let mut result = BpfAnalysisResult {
        total_programs: programs.len(),
        unknown_programs: Vec::new(),
        suspicious_combinations: Vec::new(),
        high_risk_programs: Vec::new(),
        possible_rootkit: false,
        risk_score: 0,
    };

    // Find unknown programs
    for prog in programs {
        if !baseline.is_known(prog) {
            result.unknown_programs.push(UnknownProgram {
                id: prog.id,
                name: prog.name.clone(),
                prog_type: format!("{:?}", prog.prog_type),
                tag: prog.tag_hex(),
                loaded_by_uid: prog.created_by_uid,
            });
            result.risk_score += 10;
        }

        // Check for high-risk programs
        if let Some(high_risk) = check_high_risk(prog) {
            result.high_risk_programs.push(high_risk);
            result.risk_score += 25;
        }
    }

    // Check for suspicious combinations
    result.suspicious_combinations = check_combinations(programs);
    for _ in &result.suspicious_combinations {
        result.risk_score += 50;
    }

    // Rootkit indicators
    if has_rootkit_indicators(programs, &result) {
        result.possible_rootkit = true;
        result.risk_score += 100;
        warn!("Possible eBPF rootkit detected!");
    }

    result
}

fn check_high_risk(prog: &BpfProgInfo) -> Option<HighRiskProgram> {
    // XDP programs can intercept ALL packets before the kernel sees them
    if prog.prog_type == BpfProgType::Xdp {
        if prog.name.is_empty() || !is_known_xdp(&prog.name) {
            return Some(HighRiskProgram {
                id: prog.id,
                name: prog.name.clone(),
                reason: "Unknown XDP program - can intercept all network traffic".to_string(),
                severity: Severity::High,
            });
        }
    }

    // LSM programs can bypass security checks
    if prog.prog_type == BpfProgType::Lsm {
        if prog.name.is_empty() {
            return Some(HighRiskProgram {
                id: prog.id,
                name: prog.name.clone(),
                reason: "Unnamed LSM BPF program - can bypass security".to_string(),
                severity: Severity::Critical,
            });
        }
    }

    // Programs loaded by non-root
    if prog.created_by_uid != 0 && prog.prog_type.is_high_risk() {
        return Some(HighRiskProgram {
            id: prog.id,
            name: prog.name.clone(),
            reason: format!(
                "High-risk program loaded by non-root (uid={})",
                prog.created_by_uid
            ),
            severity: Severity::High,
        });
    }

    // Unnamed programs
    if prog.name.is_empty() && prog.prog_type.is_high_risk() {
        return Some(HighRiskProgram {
            id: prog.id,
            name: "<unnamed>".to_string(),
            reason: "Unnamed high-risk BPF program".to_string(),
            severity: Severity::Medium,
        });
    }

    None
}

fn check_combinations(programs: &[BpfProgInfo]) -> Vec<SuspiciousCombination> {
    let mut combos = Vec::new();

    // TripleCross pattern: XDP + TC + kprobe on getdents
    let has_xdp = programs.iter().any(|p| p.prog_type == BpfProgType::Xdp);
    let has_tc = programs
        .iter()
        .any(|p| p.prog_type == BpfProgType::SchedCls || p.prog_type == BpfProgType::SchedAct);
    let has_kprobe = programs.iter().any(|p| p.prog_type == BpfProgType::Kprobe);

    if has_xdp && has_tc && has_kprobe {
        let ids: Vec<u32> = programs
            .iter()
            .filter(|p| {
                matches!(
                    p.prog_type,
                    BpfProgType::Xdp
                        | BpfProgType::SchedCls
                        | BpfProgType::SchedAct
                        | BpfProgType::Kprobe
                )
            })
            .map(|p| p.id)
            .collect();

        combos.push(SuspiciousCombination {
            description: "XDP + TC + Kprobe combination (TripleCross pattern)".to_string(),
            program_ids: ids,
            mitre_technique: Some("T1014".to_string()), // Rootkit
        });
    }

    // BPFDoor pattern: many socket filters
    let socket_filters: Vec<_> = programs
        .iter()
        .filter(|p| p.prog_type == BpfProgType::SocketFilter)
        .collect();
    if socket_filters.len() > 3 {
        combos.push(SuspiciousCombination {
            description: format!(
                "Multiple socket filters ({}) - possible BPFDoor",
                socket_filters.len()
            ),
            program_ids: socket_filters.iter().map(|p| p.id).collect(),
            mitre_technique: Some("T1205.001".to_string()), // Traffic Signaling: Port Knocking
        });
    }

    combos
}

fn has_rootkit_indicators(programs: &[BpfProgInfo], analysis: &BpfAnalysisResult) -> bool {
    // Multiple unknown high-risk programs
    let unknown_high_risk = analysis
        .unknown_programs
        .iter()
        .filter(|p| {
            matches!(
                p.prog_type.as_str(),
                "Xdp" | "Kprobe" | "Tracepoint" | "RawTracepoint" | "Lsm"
            )
        })
        .count();

    if unknown_high_risk >= 3 {
        return true;
    }

    // Suspicious combination detected
    if !analysis.suspicious_combinations.is_empty() {
        return true;
    }

    // Multiple unnamed programs
    let unnamed = programs
        .iter()
        .filter(|p| p.name.is_empty() && p.prog_type.is_high_risk())
        .count();
    if unnamed >= 2 {
        return true;
    }

    false
}

fn is_known_xdp(name: &str) -> bool {
    let known = ["cilium", "calico", "xdp_", "af_xdp", "libbpf", "bpftrace"];
    known.iter().any(|k| name.contains(k))
}
