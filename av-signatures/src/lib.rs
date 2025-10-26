#![allow(dead_code)]
#![allow(unused_variables)]
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSource {
    pub name: String,
    pub url: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBundle {
    pub version: semver::Version,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(with = "base64_serde")]
    pub signature: Vec<u8>,
    pub rules: String,
}

mod base64_serde {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug)]
pub struct SignatureManager {
    sources: Vec<SignatureSource>,
    cache_dir: PathBuf,
}

impl SignatureManager {
    pub fn new(sources: Vec<SignatureSource>, cache_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&cache_dir)?;
        Ok(Self { sources, cache_dir })
    }
    async fn fetch_latest(&self, source: &SignatureSource) -> Result<SignedBundle> {
        let response = reqwest::get(&source.url).await?;
        let bundle: SignedBundle = response.json().await?;
        Ok(bundle)
    }
    pub fn verify_signature(
        &self,
        bundle: &SignedBundle,
        source: &SignatureSource,
    ) -> Result<bool> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let key_bytes = STANDARD.decode(&source.public_key)?;
        let public_key = VerifyingKey::from_bytes(
            &key_bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid key length"))?,
        )?;
        let signature = Signature::from_bytes(
            &bundle
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("Invalid signature"))?,
        );
        let message = format!("{}:{}", bundle.version, bundle.timestamp);
        match public_key.verify(message.as_bytes(), &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    pub async fn update(&mut self) -> Result<Vec<PathBuf>> {
        let mut updated = Vec::new();
        for source in &self.sources {
            tracing::info!("Checking for updates from {}", source.name);
            match self.fetch_latest(source).await {
                Ok(bundle) => {
                    if self.verify_signature(&bundle, source)? {
                        let path = self.cache_dir.join(format!("{}.yar", source.name));
                        std::fs::write(&path, &bundle.rules)?;
                        updated.push(path);
                        tracing::info!("Updated signature from {}", source.name);
                    } else {
                        tracing::warn!("Signature verification failed for {}", source.name);
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to fetch update from {}: {}", source.name, e);
                }
            }
        }
        Ok(updated)
    }
}
