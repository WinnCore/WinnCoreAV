use crate::MlError;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("IO error: {0}")]
    Io(String),
    #[error("Signature verification failed")]
    BadSignature,
    #[error("Checksum mismatch for {0}")]
    BadChecksum(String),
    #[error("Manifest parse failed: {0}")]
    Manifest(String),
    #[error("Model error: {0}")]
    Ml(#[from] MlError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelManifest {
    pub models: Vec<ModelEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelEntry {
    pub model_name: String,
    pub version: String,
    pub sha256: String,
    pub created_at: Option<String>,
    pub description: Option<String>,
    pub path: Option<String>,
    pub current: Option<bool>,
}

impl ModelManifest {
    pub fn load(path: &Path) -> Result<Self, UpdateError> {
        let data = fs::read_to_string(path).map_err(|e| UpdateError::Io(e.to_string()))?;
        serde_json::from_str(&data).map_err(|e| UpdateError::Manifest(e.to_string()))
    }

    pub fn verify_checksum(&self, model_path: &Path) -> Result<(), UpdateError> {
        let Some(entry) = self.models.iter().find(|m| {
            let fname = model_path
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("");
            if let Some(p) = &m.path {
                p == fname || p == model_path.to_string_lossy().as_ref()
            } else {
                fname.contains(&m.model_name)
            }
        }) else {
            return Err(UpdateError::BadChecksum(model_path.display().to_string()));
        };
        verify_entry_checksum(entry, model_path)
    }
}

pub fn verify_manifest_signature(
    manifest_path: &Path,
    signature_path: &Path,
    pubkey: &VerifyingKey,
) -> Result<(), UpdateError> {
    let manifest_data = fs::read(manifest_path).map_err(|e| UpdateError::Io(e.to_string()))?;
    let sig_bytes = fs::read(signature_path).map_err(|e| UpdateError::Io(e.to_string()))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| UpdateError::BadSignature)?;
    pubkey
        .verify_strict(&manifest_data, &sig)
        .map_err(|_| UpdateError::BadSignature)?;
    Ok(())
}

pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey, UpdateError> {
    let bytes = fs::read(path).map_err(|e| UpdateError::Io(e.to_string()))?;
    if bytes.len() == ed25519_dalek::PUBLIC_KEY_LENGTH {
        let mut arr = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
        arr.copy_from_slice(&bytes[..ed25519_dalek::PUBLIC_KEY_LENGTH]);
        VerifyingKey::from_bytes(&arr).map_err(|_| UpdateError::BadSignature)
    } else {
        Err(UpdateError::BadSignature)
    }
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn verify_entry_checksum(entry: &ModelEntry, model_path: &Path) -> Result<(), UpdateError> {
    let hash = sha256_file(model_path).map_err(|e| UpdateError::Io(e.to_string()))?;
    if hash.eq_ignore_ascii_case(&entry.sha256) {
        Ok(())
    } else {
        Err(UpdateError::BadChecksum(model_path.display().to_string()))
    }
}

pub fn select_model_from_manifest(
    manifest: &ModelManifest,
    lock_version: Option<&str>,
) -> Option<ModelEntry> {
    if let Some(lock) = lock_version {
        if let Some(found) = manifest.models.iter().find(|m| m.version == lock).cloned() {
            return Some(found);
        }
    }
    if let Some(current) = manifest
        .models
        .iter()
        .find(|m| m.current.unwrap_or(false))
        .cloned()
    {
        return Some(current);
    }
    // fallback: highest semver if parseable, else first
    let mut parsed: Vec<(semver::Version, ModelEntry)> = manifest
        .models
        .iter()
        .filter_map(|m| {
            semver::Version::parse(&m.version)
                .ok()
                .map(|v| (v, m.clone()))
        })
        .collect();
    parsed.sort_by(|a, b| b.0.cmp(&a.0));
    if let Some((_, entry)) = parsed.first() {
        return Some(entry.clone());
    }
    manifest.models.first().cloned()
}
