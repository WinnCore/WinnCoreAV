#![allow(dead_code)]
#![allow(unused_variables)]
use anyhow::{anyhow, Result};
use av_core::ScannerConfig;
use std::path::PathBuf;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SignatureSource {
    pub name: String,
    pub url: url::Url,
    pub public_key: String,
    pub version: semver::Version,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SignedBundle {
    pub version: semver::Version,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(with = "serde_with::hex::Hex")]
    pub signature: Vec<u8>, // Changed from [u8; 64] to Vec<u8>
    pub rules: String,
}

pub struct SignatureUpdater {
    sources: Vec<SignatureSource>,
    cache_dir: PathBuf,
}

impl SignatureUpdater {
    pub fn new(cache_dir: PathBuf) -> Self {
        Self {
            sources: Vec::new(),
            cache_dir,
        }
    }

    pub fn add_source(&mut self, source: SignatureSource) {
        self.sources.push(source);
    }

    pub async fn fetch_latest(&self, source: &SignatureSource) -> Result<SignedBundle> {
        let response = reqwest::get(source.url.clone()).await?;
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
                        std::fs::write(&path, bundle.rules)?;
                        updated.push(path);
                        tracing::info!("Updated signatures from {}", source.name);
                    } else {
                        tracing::warn!("Signature verification failed for {}", source.name);
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to fetch from {}: {}", source.name, e);
                }
            }
        }

        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_updater() {
        let updater = SignatureUpdater::new(PathBuf::from("/tmp"));
        assert_eq!(updater.sources.len(), 0);
    }
}
