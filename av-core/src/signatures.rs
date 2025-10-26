#![allow(dead_code)]
#![allow(unused_variables)]
//! Signature management primitives: validation, provenance, and AB testing.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub id: String,
    pub description: String,
    pub provenance: String,
    pub ab_bucket: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleBundle {
    pub version: semver::Version,
    pub rules: HashMap<String, RuleMetadata>,
    pub checksum: String,
}

impl RuleBundle {
    pub fn verify(&self, expected_checksum: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.checksum == expected_checksum,
            "bundle checksum mismatch"
        );
        Ok(())
    }
}
