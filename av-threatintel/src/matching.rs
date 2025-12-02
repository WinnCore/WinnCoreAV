use std::fs::File;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};
use tracing::warn;

use crate::ioc::IocDatabase;

#[derive(Debug, Clone)]
pub struct IocMatch {
    pub indicator: String,
    pub indicator_type: String,
    pub confidence: u8,
}

pub struct IocMatcher {
    db: IocDatabase,
}

impl IocMatcher {
    pub fn new(db: IocDatabase) -> Self {
        Self { db }
    }

    pub fn check_ip(&self, ip: &str) -> Option<IocMatch> {
        if self.db.check_ip(ip) {
            return Some(IocMatch {
                indicator: ip.to_string(),
                indicator_type: "ip".to_string(),
                confidence: 90,
            });
        }
        None
    }

    pub fn check_domain(&self, domain: &str) -> Option<IocMatch> {
        if self.db.check_domain(domain) {
            return Some(IocMatch {
                indicator: domain.to_string(),
                indicator_type: "domain".to_string(),
                confidence: 90,
            });
        }
        None
    }

    pub fn check_file(&self, path: &Path) -> Option<IocMatch> {
        match calculate_sha256(path) {
            Ok(hash) => self.check_hash(&hash),
            Err(e) => {
                warn!("Hash calc failed for {}: {}", path.display(), e);
                None
            }
        }
    }

    pub fn check_hash(&self, hash: &str) -> Option<IocMatch> {
        if self.db.check_hash(hash) {
            return Some(IocMatch {
                indicator: hash.to_string(),
                indicator_type: "hash".to_string(),
                confidence: 95,
            });
        }
        None
    }
}

fn calculate_sha256(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}
