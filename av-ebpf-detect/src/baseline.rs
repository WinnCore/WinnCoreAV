//! eBPF program baseline management.
//!
//! We maintain a baseline of "known good" eBPF programs.
//! Any new program not in the baseline is suspicious.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::enumerate::BpfProgInfo;

/// Baseline entry for a known eBPF program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub name: String,
    pub prog_type: u32,
    pub tag_hex: String,
    pub expected_uid: u32,
    pub description: String,
    pub source: String, // e.g., "systemd", "cilium", "falco"
}

/// eBPF baseline database.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BpfBaseline {
    /// Programs indexed by tag (hash)
    pub by_tag: HashMap<String, BaselineEntry>,
    /// Programs indexed by name
    pub by_name: HashMap<String, Vec<BaselineEntry>>,
    /// Known legitimate program sources
    pub known_sources: HashSet<String>,
    /// When baseline was created
    pub created_at: String,
}

impl BpfBaseline {
    pub fn new() -> Self {
        let mut baseline = Self::default();
        baseline.add_default_entries();
        baseline
    }

    /// Add default known-good programs.
    fn add_default_entries(&mut self) {
        // Common system eBPF programs
        let defaults = vec![
            ("sd_", "systemd", "System service management"),
            ("trace_", "kernel", "Kernel tracing infrastructure"),
            ("cgroup_", "systemd", "Cgroup management"),
            ("kprobe_", "kernel", "Performance monitoring"),
            ("cilium", "cilium", "Kubernetes CNI"),
            ("calico", "calico", "Kubernetes CNI"),
            ("falco", "falco", "Runtime security"),
            ("tetragon", "tetragon", "Security observability"),
            ("bpftrace", "bpftrace", "Tracing tool"),
        ];

        for (_prefix, source, _desc) in defaults {
            self.known_sources.insert(source.to_string());
        }
    }

    /// Load baseline from JSON file.
    pub fn load(path: &Path) -> Result<Self, std::io::Error> {
        let content = fs::read_to_string(path)?;
        let baseline: Self = serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        info!(
            "Loaded eBPF baseline with {} entries",
            baseline.by_tag.len()
        );
        Ok(baseline)
    }

    /// Save baseline to JSON file.
    pub fn save(&self, path: &Path) -> Result<(), std::io::Error> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(path, content)
    }

    /// Create baseline from current system state.
    pub fn create_from_current() -> Self {
        let mut baseline = Self::new();

        let programs = crate::enumerate_bpf_programs();
        for prog in programs {
            // Only baseline programs that look legitimate
            if !prog.name.is_empty() && prog.created_by_uid == 0 {
                let entry = BaselineEntry {
                    name: prog.name.clone(),
                    prog_type: prog.prog_type.as_raw(),
                    tag_hex: prog.tag_hex(),
                    expected_uid: prog.created_by_uid,
                    description: String::new(),
                    source: guess_source(&prog.name),
                };

                baseline.by_tag.insert(prog.tag_hex(), entry.clone());
                baseline
                    .by_name
                    .entry(prog.name.clone())
                    .or_default()
                    .push(entry);
            }
        }

        baseline.created_at = chrono::Utc::now().to_rfc3339();
        info!(
            "Created eBPF baseline with {} programs",
            baseline.by_tag.len()
        );
        baseline
    }

    /// Check if a program is in the baseline.
    pub fn is_known(&self, prog: &BpfProgInfo) -> bool {
        // Check by tag first (most reliable)
        if self.by_tag.contains_key(&prog.tag_hex()) {
            return true;
        }

        // Check by name with matching type
        if let Some(entries) = self.by_name.get(&prog.name) {
            for entry in entries {
                if entry.prog_type == prog.prog_type.as_raw() {
                    return true;
                }
            }
        }

        // Check if name matches known source prefixes
        for source in &self.known_sources {
            if prog.name.starts_with(source) {
                return true;
            }
        }

        false
    }

    /// Get list of unknown programs.
    pub fn find_unknown<'a>(&self, programs: &'a [BpfProgInfo]) -> Vec<&'a BpfProgInfo> {
        programs.iter().filter(|p| !self.is_known(p)).collect()
    }
}

fn guess_source(name: &str) -> String {
    if name.starts_with("sd_") || name.contains("systemd") {
        "systemd".to_string()
    } else if name.contains("cilium") {
        "cilium".to_string()
    } else if name.contains("calico") {
        "calico".to_string()
    } else if name.contains("falco") {
        "falco".to_string()
    } else {
        "unknown".to_string()
    }
}
