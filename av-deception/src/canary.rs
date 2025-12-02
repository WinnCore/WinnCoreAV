//! Canary file definitions.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Types of canary files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanaryType {
    /// Fake credential file (passwords, keys)
    Credential,
    /// Fake document (financial, HR)
    Document,
    /// Fake config file (AWS, Docker, K8s)
    Config,
    /// Fake SSH key
    SshKey,
    /// Fake database file
    Database,
    /// Fake executable/script
    Executable,
}

/// A canary file definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Canary {
    pub id: String,
    pub path: PathBuf,
    pub canary_type: CanaryType,
    pub description: String,
    /// Alert severity if accessed
    pub severity: CanarySeverity,
    /// MITRE technique detected
    pub mitre_technique: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CanarySeverity {
    Medium,
    High,
    Critical,
}

impl Canary {
    pub fn credential(path: impl Into<PathBuf>, name: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            path: path.into(),
            canary_type: CanaryType::Credential,
            description: format!("Credential canary: {}", name),
            severity: CanarySeverity::Critical,
            mitre_technique: Some("T1552".to_string()), // Unsecured Credentials
        }
    }

    pub fn ssh_key(path: impl Into<PathBuf>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            path: path.into(),
            canary_type: CanaryType::SshKey,
            description: "SSH key canary".to_string(),
            severity: CanarySeverity::Critical,
            mitre_technique: Some("T1552.004".to_string()), // Private Keys
        }
    }

    pub fn document(path: impl Into<PathBuf>, name: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            path: path.into(),
            canary_type: CanaryType::Document,
            description: format!("Document canary: {}", name),
            severity: CanarySeverity::High,
            mitre_technique: Some("T1005".to_string()), // Data from Local System
        }
    }

    pub fn config(path: impl Into<PathBuf>, service: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            path: path.into(),
            canary_type: CanaryType::Config,
            description: format!("Config canary for {}", service),
            severity: CanarySeverity::High,
            mitre_technique: Some("T1552.001".to_string()), // Credentials In Files
        }
    }
}

/// Predefined canary locations.
pub fn default_canary_locations() -> Vec<Canary> {
    vec![
        // Credential canaries
        Canary::credential("/root/.aws/credentials.bak", "AWS credentials backup"),
        Canary::credential("/home/*/.aws/credentials.old", "AWS credentials old"),
        Canary::credential("/root/passwords.txt", "Password file"),
        Canary::credential("/var/backup/shadow.bak", "Shadow backup"),
        // SSH key canaries
        Canary::ssh_key("/root/.ssh/id_rsa.bak"),
        Canary::ssh_key("/root/.ssh/admin_key"),
        Canary::ssh_key("/home/*/.ssh/production_key"),
        // Document canaries
        Canary::document(
            "/root/Documents/financial_report_2024.xlsx",
            "Financial report",
        ),
        Canary::document("/home/*/Desktop/employee_salaries.csv", "Salary data"),
        Canary::document("/var/www/backup/database_dump.sql", "Database dump"),
        // Config canaries
        Canary::config("/root/.docker/config.json.bak", "Docker"),
        Canary::config("/root/.kube/config.old", "Kubernetes"),
        Canary::config("/etc/wireguard/wg0.conf.bak", "WireGuard"),
    ]
}
