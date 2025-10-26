//! Signed rule bundle management and update verification.

use std::path::{Path, PathBuf};

use anyhow::Context;
use ed25519_dalek::{Signature, VerifyingKey};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use av_core::signatures::RuleBundle;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateSource {
    pub name: String,
    pub url: url::Url,
    pub public_key: String,
    pub pin_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateConfig {
    pub sources: Vec<UpdateSource>,
    pub cache_dir: PathBuf,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            sources: vec![],
            cache_dir: PathBuf::from("/var/lib/av/signatures"),
        }
    }
}

pub struct Updater {
    http: Client,
    cfg: UpdateConfig,
}

impl Updater {
    pub fn new(cfg: UpdateConfig) -> anyhow::Result<Self> {
        let http = Client::builder().use_rustls_tls().build()?;
        Ok(Self { http, cfg })
    }

    pub async fn update(&self) -> anyhow::Result<Vec<RuleBundle>> {
        let mut bundles = Vec::new();
        for source in &self.cfg.sources {
            let bundle = self.fetch_bundle(source).await?;
            bundles.push(bundle);
        }
        Ok(bundles)
    }

    async fn fetch_bundle(&self, source: &UpdateSource) -> anyhow::Result<RuleBundle> {
        let response = self.http.get(source.url.clone()).send().await?;
        let body = response.bytes().await?;
        let signed: SignedBundle = serde_json::from_slice(&body)?;
        let bundle = signed.bundle;
        let sig = Signature::from_bytes(&signed.signature);
        let key_bytes = base64::decode(&source.public_key)?;
        let key = VerifyingKey::try_from(&key_bytes[..]).context("invalid ed25519 key")?;
        key.verify_strict(serde_json::to_string(&bundle)?.as_bytes(), &sig)
            .context("signature verification failed")?;
        bundle.verify(&signed.bundle_checksum)?;
        Ok(bundle)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedBundle {
    bundle_checksum: String,
    bundle: RuleBundle,
    signature: [u8; 64],
}
