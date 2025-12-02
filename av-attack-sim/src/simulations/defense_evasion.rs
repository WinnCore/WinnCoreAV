//! TA0005: Defense Evasion technique simulations.

use crate::framework::{AttackSimulation, AttackSimulator, SimulationExecution, Tactic};
use std::sync::Arc;

pub fn register(simulator: &mut AttackSimulator) {
    // T1070.003 - Clear bash history
    simulator.register(AttackSimulation {
        id: "evasion-001".to_string(),
        name: "Clear Bash History".to_string(),
        technique_id: "T1070.003".to_string(),
        tactic: Tactic::DefenseEvasion,
        description: "Clear command history".to_string(),
        expected_alert: "History clearing detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["history -c 2>/dev/null || true".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1070.004 - File deletion
    simulator.register(AttackSimulation {
        id: "evasion-002".to_string(),
        name: "Log File Deletion".to_string(),
        technique_id: "T1070.004".to_string(),
        tactic: Tactic::DefenseEvasion,
        description: "Delete log file".to_string(),
        expected_alert: "Log deletion detected".to_string(),
        should_detect: true,
        requires_root: true,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "touch /var/log/winncore-test.log".to_string(),
                "rm /var/log/winncore-test.log".to_string(),
            ],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1070.006 - Timestomp
    simulator.register(AttackSimulation {
        id: "evasion-003".to_string(),
        name: "Timestomp".to_string(),
        technique_id: "T1070.006".to_string(),
        tactic: Tactic::DefenseEvasion,
        description: "Modify file timestamps".to_string(),
        expected_alert: "Timestamp manipulation detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "touch /tmp/winncore-timestomp-test".to_string(),
                "touch -t 202001010000 /tmp/winncore-timestomp-test".to_string(),
            ],
            cleanup: vec!["rm -f /tmp/winncore-timestomp-test".to_string()],
            artifacts: vec!["/tmp/winncore-timestomp-test".to_string()],
        }),
    });

    // T1027 - Obfuscated files
    simulator.register(AttackSimulation {
        id: "evasion-004".to_string(),
        name: "Obfuscated Script".to_string(),
        technique_id: "T1027".to_string(),
        tactic: Tactic::DefenseEvasion,
        description: "Create highly obfuscated script".to_string(),
        expected_alert: "Obfuscated code detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                r#"echo 'eval $(echo "dGVzdA==" | base64 -d)' > /tmp/winncore-obfuscated.sh"#
                    .to_string(),
            ],
            cleanup: vec!["rm -f /tmp/winncore-obfuscated.sh".to_string()],
            artifacts: vec!["/tmp/winncore-obfuscated.sh".to_string()],
        }),
    });

    // T1620 - Fileless execution via memfd
    simulator.register(AttackSimulation {
        id: "evasion-005".to_string(),
        name: "memfd_create Fileless Execution".to_string(),
        technique_id: "T1620".to_string(),
        tactic: Tactic::DefenseEvasion,
        description: "Check for memfd-based execution".to_string(),
        expected_alert: "Fileless execution detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "ls -la /proc/*/exe 2>/dev/null | grep memfd || echo 'no memfd processes'"
                    .to_string(),
            ],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1620 - /dev/shm execution
    simulator.register(AttackSimulation {
        id: "evasion-006".to_string(),
        name: "/dev/shm Execution".to_string(),
        technique_id: "T1620".to_string(),
        tactic: Tactic::DefenseEvasion,
        description: "Execute from tmpfs".to_string(),
        expected_alert: "Execution from tmpfs detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "echo '#!/bin/sh\necho test' > /dev/shm/winncore-shm-test".to_string(),
                "chmod +x /dev/shm/winncore-shm-test".to_string(),
                "/dev/shm/winncore-shm-test".to_string(),
            ],
            cleanup: vec!["rm -f /dev/shm/winncore-shm-test".to_string()],
            artifacts: vec!["/dev/shm/winncore-shm-test".to_string()],
        }),
    });

    // T1140 - Deobfuscate/Decode
    simulator.register(AttackSimulation {
        id: "evasion-007".to_string(),
        name: "Base64 Decode to Execute".to_string(),
        technique_id: "T1140".to_string(),
        tactic: Tactic::DefenseEvasion,
        description: "Decode and execute payload".to_string(),
        expected_alert: "Decode-execute pattern detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "echo 'IyEvYmluL3NoCmVjaG8gdGVzdA==' > /tmp/winncore-encoded".to_string(),
                "base64 -d /tmp/winncore-encoded | sh".to_string(),
            ],
            cleanup: vec!["rm -f /tmp/winncore-encoded".to_string()],
            artifacts: vec!["/tmp/winncore-encoded".to_string()],
        }),
    });

    // T1036.005 - Match legitimate name
    simulator.register(AttackSimulation {
        id: "evasion-008".to_string(),
        name: "Process Name Masquerading".to_string(),
        technique_id: "T1036.005".to_string(),
        tactic: Tactic::DefenseEvasion,
        description: "Execute with misleading process name".to_string(),
        expected_alert: "Process masquerading detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![r#"(exec -a '[systemd]' bash -c 'sleep 0.1') &"#.to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });
}
