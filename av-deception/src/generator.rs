//! Generate realistic-looking canary file contents.

use std::fs;
use std::io::Write;

use tracing::{error, info};

use crate::canary::{Canary, CanaryType};

/// Generate a canary file with realistic content.
pub fn generate_canary(canary: &Canary) -> Result<(), std::io::Error> {
    let content = match canary.canary_type {
        CanaryType::Credential => generate_credential_content(),
        CanaryType::SshKey => generate_ssh_key_content(),
        CanaryType::Document => generate_document_content(),
        CanaryType::Config => generate_config_content(&canary.description),
        CanaryType::Database => generate_database_content(),
        CanaryType::Executable => generate_executable_content(),
    };

    // Create parent directories if needed
    if let Some(parent) = canary.path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Write the canary file
    let mut file = fs::File::create(&canary.path)?;
    file.write_all(content.as_bytes())?;

    // Set appropriate permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = match canary.canary_type {
            CanaryType::SshKey => fs::Permissions::from_mode(0o600),
            CanaryType::Executable => fs::Permissions::from_mode(0o755),
            _ => fs::Permissions::from_mode(0o644),
        };
        fs::set_permissions(&canary.path, perms)?;
    }

    info!("Created canary: {:?}", canary.path);
    Ok(())
}

fn generate_credential_content() -> String {
    // Looks like AWS credentials but tokens are fake
    r#"[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-west-2

[production]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
region = us-east-1
"#
    .to_string()
}

fn generate_ssh_key_content() -> String {
    // Fake RSA private key (not a real key, just looks like one)
    r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAk3xM3z7Q8FAKECANARYKEYNOTREALFAKECANARYKEYNOTREAL
FAKECANARYKEYNOTREALCANARYK3YNOTREALFAKECANARYKEYNOTREALCANARYK3YNOT
REALFAKECANARYKEYNOTREALCANARYK3YNOTREALCANARYK3YNOTREALCANARYK3YNOT
REALFAKECANARYKEYNOTREALCANARYK3YNOTREALCANARYK3YNOTREALCANARYK3YNOT
REALCANARYKEYNOTREALCANARYAAAAAwEAAQ==
-----END OPENSSH PRIVATE KEY-----
"#
    .to_string()
}

fn generate_document_content() -> String {
    // CSV that looks like salary data
    r#"Employee ID,Name,Department,Salary,SSN
EMP001,John Smith,Engineering,185000,123-45-6789
EMP002,Jane Doe,Marketing,145000,234-56-7890
EMP003,Bob Wilson,Sales,165000,345-67-8901
EMP004,Alice Johnson,HR,125000,456-78-9012
"#
    .to_string()
}

fn generate_config_content(service: &str) -> String {
    if service.contains("Docker") {
        r#"{
    "auths": {
        "https://index.docker.io/v1/": {
            "auth": "dXNlcm5hbWU6cGFzc3dvcmQ="
        },
        "gcr.io": {
            "auth": "X2pzb25fa2V5OmV5SmhiR2NpT2lKU1V6STFOaUo5"
        }
    }
}"#
        .to_string()
    } else if service.contains("Kubernetes") {
        r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://production.k8s.example.com:6443
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t
  name: production
users:
- name: admin
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t
    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==
"#
        .to_string()
    } else {
        format!(
            "# Configuration for {}\napi_key = \"fake_api_key_canary_token\"\n",
            service
        )
    }
}

fn generate_database_content() -> String {
    "-- Database dump (canary)\n-- This file is monitored\nINSERT INTO users VALUES (1, 'admin', 'password123');\n".to_string()
}

fn generate_executable_content() -> String {
    "#!/bin/bash\n# This script is a canary\necho \"Canary triggered\"\n".to_string()
}

/// Deploy all default canaries.
pub fn deploy_default_canaries() -> Vec<Canary> {
    let canaries = crate::canary::default_canary_locations();
    let mut deployed = Vec::new();

    for canary in canaries {
        // Skip wildcard paths (would need expansion)
        if canary.path.to_string_lossy().contains('*') {
            continue;
        }

        match generate_canary(&canary) {
            Ok(_) => deployed.push(canary),
            Err(e) => error!("Failed to deploy canary {:?}: {}", canary.path, e),
        }
    }

    info!("Deployed {} canary files", deployed.len());
    deployed
}
