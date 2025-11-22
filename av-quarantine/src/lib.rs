#![allow(dead_code)]
#![allow(unused_variables)]
//! Encrypted quarantine manager with metadata tracking. Designed to stay
//! simple and self-contained while matching the architecture requirements
//! (AES-256-GCM encryption, hash verification, metadata export).

use anyhow::Context;
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_KEY_NAME: &str = ".quarantine.key";
const INDEX_FILE: &str = "quarantine_index.jsonl";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    pub quarantine_dir: PathBuf,
    /// Optional path to a persistent AES key. If missing, a new key is
    /// generated and written to `<quarantine_dir>/.quarantine.key`.
    pub key_path: Option<PathBuf>,
    /// When supplied, use this key instead of generating/loading from disk.
    pub encryption_key: Option<[u8; 32]>,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            quarantine_dir: PathBuf::from("/var/lib/winncore/quarantine"),
            key_path: None,
            encryption_key: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub sha256: String,
    pub sha512: String,
    pub file_size: u64,
    pub detection_time: DateTime<Utc>,
    pub detection_reason: String,
    pub threat_score: f32,
    pub restored: bool,
    pub encrypted: bool,
}

pub type QuarantineRecord = QuarantineEntry;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct QuarantineStats {
    pub total_files: usize,
    pub total_size_bytes: u64,
    pub avg_threat_score: f32,
    pub restored_count: usize,
}

pub struct QuarantineManager {
    cfg: QuarantineConfig,
    key: [u8; 32],
    index_path: PathBuf,
}

impl QuarantineManager {
    pub fn new(cfg: QuarantineConfig) -> anyhow::Result<Self> {
        fs::create_dir_all(&cfg.quarantine_dir).context("Failed to create quarantine directory")?;

        let key = Self::load_or_generate_key(&cfg)?;
        let index_path = cfg.quarantine_dir.join(INDEX_FILE);
        if !index_path.exists() {
            fs::write(&index_path, b"")?;
        }

        Ok(Self {
            cfg,
            key,
            index_path,
        })
    }

    /// Quarantine a file with metadata and encryption.
    pub fn quarantine_file(
        &self,
        source: &Path,
        detection_reason: impl Into<String>,
        threat_score: f32,
    ) -> anyhow::Result<QuarantineEntry> {
        let data =
            fs::read(source).with_context(|| format!("Failed to read {}", source.display()))?;

        let sha256 = hex::encode(Sha256::digest(&data));
        let sha512 = hex::encode(Sha512::digest(&data));
        let file_size = data.len() as u64;
        let detection_time = Utc::now();

        let encrypted = self.encrypt(&data)?;

        let id = format!("{}-{}", detection_time.timestamp(), &sha256[..8]);
        let quarantine_path = self.cfg.quarantine_dir.join(format!("{id}.enc"));

        fs::write(&quarantine_path, &encrypted)
            .with_context(|| format!("Failed to write {}", quarantine_path.display()))?;

        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: source.to_path_buf(),
            quarantine_path: quarantine_path.clone(),
            sha256,
            sha512,
            file_size,
            detection_time,
            detection_reason: detection_reason.into(),
            threat_score,
            restored: false,
            encrypted: true,
        };

        let mut entries = self.load_index()?;
        entries.push(entry.clone());
        self.persist_index(&entries)?;

        // Remove original after successful encryption write.
        if let Err(err) = fs::remove_file(source) {
            tracing::warn!("Failed to remove original file {}: {err}", source.display());
        }

        Ok(entry)
    }

    /// Compatibility wrapper for previous API.
    pub fn quarantine(&self, source: &Path) -> anyhow::Result<QuarantineEntry> {
        self.quarantine_file(source, "manual", 0.0)
    }

    /// Restore a quarantined file to a destination path.
    pub fn restore_file(
        &self,
        entry_id: &str,
        destination: &Path,
    ) -> anyhow::Result<QuarantineEntry> {
        let mut entries = self.load_index()?;
        let mut entry = entries
            .iter_mut()
            .find(|e| e.id == entry_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Entry {entry_id} not found"))?;

        let encrypted = fs::read(&entry.quarantine_path)
            .with_context(|| format!("Failed to read {}", entry.quarantine_path.display()))?;
        let decrypted = self.decrypt(&encrypted)?;

        let sha256 = hex::encode(Sha256::digest(&decrypted));
        if sha256 != entry.sha256 {
            return Err(anyhow::anyhow!(
                "Hash mismatch - quarantined data corrupted"
            ));
        }

        fs::write(destination, &decrypted)
            .with_context(|| format!("Failed to write {}", destination.display()))?;

        // Update metadata
        for e in entries.iter_mut().filter(|e| e.id == entry_id) {
            e.restored = true;
        }
        self.persist_index(&entries)?;

        entry.restored = true;
        Ok(entry)
    }

    /// Backwards-compatible restore API used by av-cli.
    pub fn restore(&self, record: &QuarantineRecord, destination: &Path) -> anyhow::Result<()> {
        self.restore_file(&record.id, destination)?;
        Ok(())
    }

    /// Delete a quarantined entry and its metadata.
    pub fn delete(&self, record: &QuarantineRecord) -> anyhow::Result<()> {
        if record.quarantine_path.exists() {
            fs::remove_file(&record.quarantine_path)?;
        }
        let mut entries = self.load_index()?;
        entries.retain(|e| e.id != record.id);
        self.persist_index(&entries)?;
        Ok(())
    }

    pub fn list(&self) -> anyhow::Result<Vec<QuarantineEntry>> {
        self.load_index()
    }

    pub fn stats(&self) -> anyhow::Result<QuarantineStats> {
        let entries = self.load_index()?;
        let total_files = entries.len();
        let total_size_bytes = entries.iter().map(|e| e.file_size).sum();
        let avg_threat_score = if total_files == 0 {
            0.0
        } else {
            entries.iter().map(|e| e.threat_score).sum::<f32>() / total_files as f32
        };
        let restored_count = entries.iter().filter(|e| e.restored).count();

        Ok(QuarantineStats {
            total_files,
            total_size_bytes,
            avg_threat_score,
            restored_count,
        })
    }

    fn load_index(&self) -> anyhow::Result<Vec<QuarantineEntry>> {
        let contents = fs::read_to_string(&self.index_path)
            .with_context(|| format!("Failed to read {}", self.index_path.display()))?;
        let mut entries = Vec::new();
        for line in contents.lines().filter(|l| !l.trim().is_empty()) {
            if let Ok(entry) = serde_json::from_str::<QuarantineEntry>(line) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    fn persist_index(&self, entries: &[QuarantineEntry]) -> anyhow::Result<()> {
        let mut buf = String::new();
        for entry in entries {
            buf.push_str(&serde_json::to_string(entry)?);
            buf.push('\n');
        }
        fs::write(&self.index_path, buf)
            .with_context(|| format!("Failed to update {}", self.index_path.display()))
    }

    fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let key = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &self.key)
                .map_err(|_| anyhow::anyhow!("invalid AES-256-GCM key"))?,
        );

        let mut buffer = plaintext.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::empty(),
            &mut buffer,
        )
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;

        // Prepend nonce so we can decrypt later.
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&buffer);
        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(ciphertext.len() >= 12, "ciphertext too short");
        let (nonce_bytes, encrypted) = ciphertext.split_at(12);

        let key = UnboundKey::new(&AES_256_GCM, &self.key)
            .map_err(|_| anyhow::anyhow!("invalid AES-256-GCM key"))?;
        let key = LessSafeKey::new(key);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| anyhow::anyhow!("invalid nonce"))?;

        let mut buffer = encrypted.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut buffer)
            .map_err(|_| anyhow::anyhow!("decryption failed"))?
            .to_vec();
        Ok(plaintext)
    }

    fn load_or_generate_key(cfg: &QuarantineConfig) -> anyhow::Result<[u8; 32]> {
        if let Some(key) = cfg.encryption_key {
            return Ok(key);
        }

        let key_path = cfg
            .key_path
            .clone()
            .unwrap_or_else(|| cfg.quarantine_dir.join(DEFAULT_KEY_NAME));

        if let Ok(data) = fs::read(&key_path) {
            if data.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&data);
                return Ok(key);
            }
        }

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        fs::write(&key_path, key)
            .with_context(|| format!("Failed to write {}", key_path.display()))?;
        Ok(key)
    }
}
