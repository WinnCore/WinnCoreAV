//! TA0003: Persistence technique simulations.

use crate::framework::{AttackSimulation, AttackSimulator, SimulationExecution, Tactic};
use std::sync::Arc;

pub fn register(simulator: &mut AttackSimulator) {
    // T1053.003 - Cron
    simulator.register(AttackSimulation {
        id: "persist-001".to_string(),
        name: "Crontab Modification".to_string(),
        technique_id: "T1053.003".to_string(),
        tactic: Tactic::Persistence,
        description: "Add entry to user crontab".to_string(),
        expected_alert: "Crontab modification detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "echo '* * * * * echo winncore-test' > /tmp/winncore-cron-test".to_string(),
                "crontab /tmp/winncore-cron-test 2>/dev/null || true".to_string(),
            ],
            cleanup: vec![
                "crontab -r 2>/dev/null || true".to_string(),
                "rm -f /tmp/winncore-cron-test".to_string(),
            ],
            artifacts: vec![],
        }),
    });

    // T1053.003 - Cron directory
    simulator.register(AttackSimulation {
        id: "persist-002".to_string(),
        name: "Cron.d File Creation".to_string(),
        technique_id: "T1053.003".to_string(),
        tactic: Tactic::Persistence,
        description: "Create file in /etc/cron.d".to_string(),
        expected_alert: "Cron persistence detected".to_string(),
        should_detect: true,
        requires_root: true,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "echo '* * * * * root echo test' > /etc/cron.d/winncore-test".to_string(),
            ],
            cleanup: vec!["rm -f /etc/cron.d/winncore-test".to_string()],
            artifacts: vec!["/etc/cron.d/winncore-test".to_string()],
        }),
    });

    // T1546.004 - .bashrc modification
    simulator.register(AttackSimulation {
        id: "persist-003".to_string(),
        name: "Bashrc Modification".to_string(),
        technique_id: "T1546.004".to_string(),
        tactic: Tactic::Persistence,
        description: "Append command to .bashrc".to_string(),
        expected_alert: "Shell config modification detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "cp ~/.bashrc ~/.bashrc.winncore-backup 2>/dev/null || true".to_string(),
                "echo '# winncore-test-marker' >> ~/.bashrc".to_string(),
            ],
            cleanup: vec![
                "mv ~/.bashrc.winncore-backup ~/.bashrc 2>/dev/null || sed -i '/winncore-test-marker/d' ~/.bashrc".to_string(),
            ],
            artifacts: vec![],
        }),
    });

    // T1543.002 - Systemd service
    simulator.register(AttackSimulation {
        id: "persist-004".to_string(),
        name: "Systemd Service Creation".to_string(),
        technique_id: "T1543.002".to_string(),
        tactic: Tactic::Persistence,
        description: "Create systemd service file".to_string(),
        expected_alert: "Systemd persistence detected".to_string(),
        should_detect: true,
        requires_root: true,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![r#"cat > /etc/systemd/system/winncore-test.service << 'EOF'
[Unit]
Description=WinnCore Test Service
[Service]
ExecStart=/bin/echo test
[Install]
WantedBy=multi-user.target
EOF"#
                .to_string()],
            cleanup: vec![
                "rm -f /etc/systemd/system/winncore-test.service".to_string(),
                "systemctl daemon-reload 2>/dev/null || true".to_string(),
            ],
            artifacts: vec!["/etc/systemd/system/winncore-test.service".to_string()],
        }),
    });

    // T1547.006 - Kernel module
    simulator.register(AttackSimulation {
        id: "persist-005".to_string(),
        name: "Kernel Module Load Attempt".to_string(),
        technique_id: "T1547.006".to_string(),
        tactic: Tactic::Persistence,
        description: "Attempt to load kernel module".to_string(),
        expected_alert: "Kernel module operation detected".to_string(),
        should_detect: true,
        requires_root: true,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "lsmod | head -5".to_string(),
                "modprobe nonexistent_winncore_module 2>/dev/null || true".to_string(),
            ],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1136.001 - Local account creation
    simulator.register(AttackSimulation {
        id: "persist-006".to_string(),
        name: "Local User Creation".to_string(),
        technique_id: "T1136.001".to_string(),
        tactic: Tactic::Persistence,
        description: "Create local user account".to_string(),
        expected_alert: "User account creation detected".to_string(),
        should_detect: true,
        requires_root: true,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["useradd -M winncore-test-user 2>/dev/null || true".to_string()],
            cleanup: vec!["userdel winncore-test-user 2>/dev/null || true".to_string()],
            artifacts: vec![],
        }),
    });

    // T1222.002 - File permission modification
    simulator.register(AttackSimulation {
        id: "persist-007".to_string(),
        name: "SUID Binary Creation".to_string(),
        technique_id: "T1222.002".to_string(),
        tactic: Tactic::Persistence,
        description: "Create SUID binary".to_string(),
        expected_alert: "SUID modification detected".to_string(),
        should_detect: true,
        requires_root: true,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "cp /bin/echo /tmp/winncore-suid-test".to_string(),
                "chmod u+s /tmp/winncore-suid-test".to_string(),
            ],
            cleanup: vec!["rm -f /tmp/winncore-suid-test".to_string()],
            artifacts: vec!["/tmp/winncore-suid-test".to_string()],
        }),
    });
}
