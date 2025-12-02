//! TA0040: Impact technique simulations.

use crate::framework::{AttackSimulation, AttackSimulator, SimulationExecution, Tactic};
use std::sync::Arc;

pub fn register(simulator: &mut AttackSimulator) {
    // T1485 - Data destruction pattern
    simulator.register(AttackSimulation {
        id: "impact-001".to_string(),
        name: "Data Destruction Pattern".to_string(),
        technique_id: "T1485".to_string(),
        tactic: Tactic::Impact,
        description: "Commands indicating data destruction".to_string(),
        expected_alert: "Data destruction detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![r#"cat > /tmp/winncore-destruct-test << 'EOF'
rm -rf /
dd if=/dev/zero of=/dev/sda
shred -vfz /dev/sda
EOF"#
                .to_string()],
            cleanup: vec!["rm -f /tmp/winncore-destruct-test".to_string()],
            artifacts: vec!["/tmp/winncore-destruct-test".to_string()],
        }),
    });

    // T1486 - Ransomware pattern
    simulator.register(AttackSimulation {
        id: "impact-002".to_string(),
        name: "Ransomware Pattern".to_string(),
        technique_id: "T1486".to_string(),
        tactic: Tactic::Impact,
        description: "Ransomware indicators".to_string(),
        expected_alert: "Ransomware detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                r#"cat > /tmp/winncore-ransom-test << 'EOF'
YOUR FILES HAVE BEEN ENCRYPTED!
Send 1 BTC to: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
Contact: ransom@evil.com
EOF"#
                    .to_string(),
                "touch /tmp/winncore-file.encrypted".to_string(),
                "touch /tmp/winncore-data.locked".to_string(),
            ],
            cleanup: vec![
                "rm -f /tmp/winncore-ransom-test".to_string(),
                "rm -f /tmp/winncore-*.encrypted".to_string(),
                "rm -f /tmp/winncore-*.locked".to_string(),
            ],
            artifacts: vec!["/tmp/winncore-ransom-test".to_string()],
        }),
    });

    // T1489 - Service stop
    simulator.register(AttackSimulation {
        id: "impact-003".to_string(),
        name: "Service Stop Pattern".to_string(),
        technique_id: "T1489".to_string(),
        tactic: Tactic::Impact,
        description: "Stopping critical services".to_string(),
        expected_alert: "Service disruption detected".to_string(),
        should_detect: true,
        requires_root: true,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "systemctl list-units --type=service --state=running | head -5".to_string(),
            ],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1490 - Inhibit system recovery
    simulator.register(AttackSimulation {
        id: "impact-004".to_string(),
        name: "Recovery Inhibition Pattern".to_string(),
        technique_id: "T1490".to_string(),
        tactic: Tactic::Impact,
        description: "Commands to inhibit recovery".to_string(),
        expected_alert: "Recovery inhibition detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![r#"cat > /tmp/winncore-recovery-test << 'EOF'
rm -rf /boot
rm -rf /var/log
systemctl disable --now systemd-journald
EOF"#
                .to_string()],
            cleanup: vec!["rm -f /tmp/winncore-recovery-test".to_string()],
            artifacts: vec!["/tmp/winncore-recovery-test".to_string()],
        }),
    });
}
