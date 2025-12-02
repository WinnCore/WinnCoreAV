//! TA0006: Credential Access technique simulations.

use crate::framework::{AttackSimulation, AttackSimulator, SimulationExecution, Tactic};
use std::sync::Arc;

pub fn register(simulator: &mut AttackSimulator) {
    // T1003.008 - /etc/shadow
    simulator.register(AttackSimulation {
        id: "cred-001".to_string(),
        name: "/etc/shadow Access".to_string(),
        technique_id: "T1003.008".to_string(),
        tactic: Tactic::CredentialAccess,
        description: "Read shadow password file".to_string(),
        expected_alert: "Shadow file access detected".to_string(),
        should_detect: true,
        requires_root: true,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["cat /etc/shadow > /dev/null".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1552.001 - Credentials in files
    simulator.register(AttackSimulation {
        id: "cred-002".to_string(),
        name: "Credential File Search".to_string(),
        technique_id: "T1552.001".to_string(),
        tactic: Tactic::CredentialAccess,
        description: "Search for passwords in files".to_string(),
        expected_alert: "Credential hunting detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["grep -ri 'password' /etc 2>/dev/null | head -5 || true".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1552.004 - SSH keys
    simulator.register(AttackSimulation {
        id: "cred-003".to_string(),
        name: "SSH Private Key Access".to_string(),
        technique_id: "T1552.004".to_string(),
        tactic: Tactic::CredentialAccess,
        description: "Access SSH private keys".to_string(),
        expected_alert: "SSH key access detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["cat ~/.ssh/id_rsa 2>/dev/null || cat ~/.ssh/id_ed25519 2>/dev/null || echo 'no keys'".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1552.003 - Bash history
    simulator.register(AttackSimulation {
        id: "cred-004".to_string(),
        name: "Bash History Access".to_string(),
        technique_id: "T1552.003".to_string(),
        tactic: Tactic::CredentialAccess,
        description: "Read bash history for credentials".to_string(),
        expected_alert: "History file access detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["cat ~/.bash_history 2>/dev/null | head -10 || true".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1555.001 - Keychain/password managers
    simulator.register(AttackSimulation {
        id: "cred-005".to_string(),
        name: "GNOME Keyring Access".to_string(),
        technique_id: "T1555.001".to_string(),
        tactic: Tactic::CredentialAccess,
        description: "Access GNOME keyring files".to_string(),
        expected_alert: "Keyring access detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["ls -la ~/.local/share/keyrings/ 2>/dev/null || true".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1552.001 - AWS credentials
    simulator.register(AttackSimulation {
        id: "cred-006".to_string(),
        name: "AWS Credentials Access".to_string(),
        technique_id: "T1552.001".to_string(),
        tactic: Tactic::CredentialAccess,
        description: "Access AWS credential files".to_string(),
        expected_alert: "Cloud credentials access detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["cat ~/.aws/credentials 2>/dev/null || true".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // T1110.001 - Brute force pattern
    simulator.register(AttackSimulation {
        id: "cred-007".to_string(),
        name: "Login Brute Force Pattern".to_string(),
        technique_id: "T1110.001".to_string(),
        tactic: Tactic::CredentialAccess,
        description: "Rapid authentication attempts".to_string(),
        expected_alert: "Brute force pattern detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "for i in 1 2 3 4 5; do su - nonexistent 2>/dev/null; done || true".to_string(),
            ],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });
}
