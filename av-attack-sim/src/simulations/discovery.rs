//! TA0007: Discovery technique simulations.

use crate::framework::{AttackSimulation, AttackSimulator, SimulationExecution, Tactic};
use std::sync::Arc;

pub fn register(simulator: &mut AttackSimulator) {
    // T1082 - System information
    simulator.register(AttackSimulation {
        id: "disc-001".to_string(),
        name: "System Information Discovery".to_string(),
        technique_id: "T1082".to_string(),
        tactic: Tactic::Discovery,
        description: "Gather system information".to_string(),
        expected_alert: "System enumeration detected".to_string(),
        should_detect: false,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["uname -a && cat /etc/os-release".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1087.001 - Local user enumeration
    simulator.register(AttackSimulation {
        id: "disc-002".to_string(),
        name: "Local Account Discovery".to_string(),
        technique_id: "T1087.001".to_string(),
        tactic: Tactic::Discovery,
        description: "Enumerate local users".to_string(),
        expected_alert: "User enumeration detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["cat /etc/passwd | cut -d: -f1".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1046 - Network scanning
    simulator.register(AttackSimulation {
        id: "disc-003".to_string(),
        name: "Network Port Scan".to_string(),
        technique_id: "T1046".to_string(),
        tactic: Tactic::Discovery,
        description: "Scan network ports".to_string(),
        expected_alert: "Port scanning detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "nmap -sn 127.0.0.1 2>/dev/null || echo 'nmap not installed'".to_string(),
            ],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1049 - Network connections
    simulator.register(AttackSimulation {
        id: "disc-004".to_string(),
        name: "Network Connection Discovery".to_string(),
        technique_id: "T1049".to_string(),
        tactic: Tactic::Discovery,
        description: "List network connections".to_string(),
        expected_alert: "Network enumeration detected".to_string(),
        should_detect: false,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "ss -tunapl 2>/dev/null || netstat -tunapl 2>/dev/null || true".to_string(),
            ],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1057 - Process discovery
    simulator.register(AttackSimulation {
        id: "disc-005".to_string(),
        name: "Process Discovery".to_string(),
        technique_id: "T1057".to_string(),
        tactic: Tactic::Discovery,
        description: "List running processes".to_string(),
        expected_alert: "Process enumeration detected".to_string(),
        should_detect: false,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["ps auxf".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1083 - File/directory discovery
    simulator.register(AttackSimulation {
        id: "disc-006".to_string(),
        name: "Sensitive File Discovery".to_string(),
        technique_id: "T1083".to_string(),
        tactic: Tactic::Discovery,
        description: "Search for sensitive files".to_string(),
        expected_alert: "Sensitive file search detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["find /home -name '*.key' -o -name '*.pem' -o -name 'id_rsa' 2>/dev/null | head -5 || true".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1518.001 - Security software discovery
    simulator.register(AttackSimulation {
        id: "disc-007".to_string(),
        name: "Security Software Discovery".to_string(),
        technique_id: "T1518.001".to_string(),
        tactic: Tactic::Discovery,
        description: "Check for security tools".to_string(),
        expected_alert: "Security tool enumeration detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "which clamav ossec auditd 2>/dev/null || true".to_string(),
                "ps aux | grep -E 'clamav|ossec|auditd|falcon' | head -5 || true".to_string(),
            ],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });
}
