//! TA0008: Lateral Movement technique simulations.

use crate::framework::{AttackSimulation, AttackSimulator, SimulationExecution, Tactic};
use std::sync::Arc;

pub fn register(simulator: &mut AttackSimulator) {
    // T1021.004 - SSH
    simulator.register(AttackSimulation {
        id: "lateral-001".to_string(),
        name: "SSH Connection Attempt".to_string(),
        technique_id: "T1021.004".to_string(),
        tactic: Tactic::LateralMovement,
        description: "Attempt SSH connection".to_string(),
        expected_alert: "Internal SSH detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "ssh -o ConnectTimeout=1 -o BatchMode=yes nonexistent@127.0.0.1 2>&1 || true"
                    .to_string(),
            ],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1021.002 - SMB (smbclient)
    simulator.register(AttackSimulation {
        id: "lateral-002".to_string(),
        name: "SMB Connection Attempt".to_string(),
        technique_id: "T1021.002".to_string(),
        tactic: Tactic::LateralMovement,
        description: "Attempt SMB connection".to_string(),
        expected_alert: "SMB connection detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "smbclient -N -L 127.0.0.1 2>&1 | head -5 || echo 'smbclient not installed'"
                    .to_string(),
            ],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1570 - Lateral tool transfer
    simulator.register(AttackSimulation {
        id: "lateral-003".to_string(),
        name: "Tool Transfer Pattern".to_string(),
        technique_id: "T1570".to_string(),
        tactic: Tactic::LateralMovement,
        description: "Transfer tools between systems".to_string(),
        expected_alert: "Lateral tool transfer detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "echo 'scp /tmp/tool user@10.0.0.2:/tmp/' > /tmp/winncore-transfer-test"
                    .to_string(),
            ],
            cleanup: vec!["rm -f /tmp/winncore-transfer-test".to_string()],
            artifacts: vec!["/tmp/winncore-transfer-test".to_string()],
        }),
    });
}
