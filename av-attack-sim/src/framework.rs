//! Attack simulation framework core.

use crate::alert_monitor::AlertMonitor;
use colored::*;
use libc::geteuid;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

/// MITRE ATT&CK Tactic
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl std::fmt::Display for Tactic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Tactic::Reconnaissance => "TA0043: Reconnaissance",
            Tactic::ResourceDevelopment => "TA0042: Resource Development",
            Tactic::InitialAccess => "TA0001: Initial Access",
            Tactic::Execution => "TA0002: Execution",
            Tactic::Persistence => "TA0003: Persistence",
            Tactic::PrivilegeEscalation => "TA0004: Privilege Escalation",
            Tactic::DefenseEvasion => "TA0005: Defense Evasion",
            Tactic::CredentialAccess => "TA0006: Credential Access",
            Tactic::Discovery => "TA0007: Discovery",
            Tactic::LateralMovement => "TA0008: Lateral Movement",
            Tactic::Collection => "TA0009: Collection",
            Tactic::CommandAndControl => "TA0011: Command and Control",
            Tactic::Exfiltration => "TA0010: Exfiltration",
            Tactic::Impact => "TA0040: Impact",
        };
        write!(f, "{}", s)
    }
}

/// Attack simulation definition
#[derive(Clone)]
pub struct AttackSimulation {
    pub id: String,
    pub name: String,
    pub technique_id: String,
    pub tactic: Tactic,
    pub description: String,
    pub expected_alert: String,
    pub should_detect: bool,
    pub requires_root: bool,
    pub executor: Arc<dyn Fn() -> SimulationExecution + Send + Sync>,
}

pub struct SimulationExecution {
    pub commands: Vec<String>,
    pub cleanup: Vec<String>,
    pub artifacts: Vec<String>,
}

/// Result of running a simulation
#[derive(Debug, Clone, Serialize)]
pub struct SimulationResult {
    pub id: String,
    pub name: String,
    pub technique_id: String,
    pub tactic: String,
    pub should_detect: bool,
    pub detected: bool,
    pub detection_time_ms: Option<u64>,
    pub alert_message: Option<String>,
    pub error: Option<String>,
    pub skipped: bool,
    pub skip_reason: Option<String>,
}

/// The attack simulator
pub struct AttackSimulator {
    simulations: Vec<AttackSimulation>,
    alert_monitor: AlertMonitor,
}

impl AttackSimulator {
    pub fn new(alert_monitor: AlertMonitor) -> Self {
        Self {
            simulations: Vec::new(),
            alert_monitor,
        }
    }

    pub fn register(&mut self, sim: AttackSimulation) {
        self.simulations.push(sim);
    }

    pub async fn run_all(&mut self) -> Vec<SimulationResult> {
        let total = self.simulations.len();
        let mut results = Vec::new();

        for (idx, sim) in self.simulations.iter().enumerate() {
            let num = format!("[{:02}/{}]", idx + 1, total);
            println!(
                "{} {} - {}",
                num.cyan(),
                sim.technique_id.yellow(),
                sim.name.white().bold()
            );
            println!("        {}: {}", "Simulation".dimmed(), sim.description);
            println!("        {}: {}", "Expected".dimmed(), sim.expected_alert);

            let result = self.run_simulation(sim).await;

            if result.skipped {
                println!(
                    "        {}: {} {}",
                    "Result".dimmed(),
                    "○ SKIPPED".yellow(),
                    result.skip_reason.as_deref().unwrap_or("")
                );
            } else if result.detected {
                println!(
                    "        {}: {} in {}ms",
                    "Result".dimmed(),
                    "✓ DETECTED".green().bold(),
                    result.detection_time_ms.unwrap_or(0)
                );
                if let Some(ref alert) = result.alert_message {
                    println!("        {}: \"{}\"", "Alert".dimmed(), alert.green());
                }
            } else if result.should_detect {
                println!(
                    "        {}: {}",
                    "Result".dimmed(),
                    "✗ NOT DETECTED".red().bold()
                );
                if let Some(ref err) = result.error {
                    println!("        {}: {}", "Error".dimmed(), err.red());
                }
            } else {
                println!(
                    "        {}: {} (expected)",
                    "Result".dimmed(),
                    "○ NOT DETECTED".dimmed()
                );
            }

            println!();
            results.push(result);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        results
    }

    async fn run_simulation(&self, sim: &AttackSimulation) -> SimulationResult {
        if sim.requires_root && unsafe { geteuid() } != 0 {
            return SimulationResult {
                id: sim.id.clone(),
                name: sim.name.clone(),
                technique_id: sim.technique_id.clone(),
                tactic: sim.tactic.to_string(),
                should_detect: sim.should_detect,
                detected: false,
                detection_time_ms: None,
                alert_message: None,
                error: None,
                skipped: true,
                skip_reason: Some("Requires root".to_string()),
            };
        }

        self.alert_monitor.clear().await;

        let execution = (sim.executor)();

        let start = Instant::now();
        for cmd in &execution.commands {
            let result = tokio::process::Command::new("bash")
                .args(["-c", cmd])
                .output()
                .await;

            if let Err(e) = result {
                return SimulationResult {
                    id: sim.id.clone(),
                    name: sim.name.clone(),
                    technique_id: sim.technique_id.clone(),
                    tactic: sim.tactic.to_string(),
                    should_detect: sim.should_detect,
                    detected: false,
                    detection_time_ms: None,
                    alert_message: None,
                    error: Some(format!("Execution failed: {}", e)),
                    skipped: false,
                    skip_reason: None,
                };
            }
        }

        let alert = self
            .alert_monitor
            .wait_for_alert(&sim.technique_id, std::time::Duration::from_secs(3))
            .await;

        let detection_time = start.elapsed();

        for cmd in &execution.cleanup {
            let _ = tokio::process::Command::new("bash")
                .args(["-c", cmd])
                .output()
                .await;
        }

        SimulationResult {
            id: sim.id.clone(),
            name: sim.name.clone(),
            technique_id: sim.technique_id.clone(),
            tactic: sim.tactic.to_string(),
            should_detect: sim.should_detect,
            detected: alert.is_some(),
            detection_time_ms: alert.as_ref().map(|_| detection_time.as_millis() as u64),
            alert_message: alert,
            error: None,
            skipped: false,
            skip_reason: None,
        }
    }
}
