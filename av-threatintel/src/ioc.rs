use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IocType {
    IpAddress(String),
    Domain(String),
    FileHash { hash_type: HashType, value: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMetadata {
    pub source: String,
    pub added: String,
    pub expires: Option<String>,
    pub confidence: u8,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub ioc_type: IocType,
    pub metadata: IocMetadata,
}

/// In-memory IOC database for quick lookups.
pub struct IocDatabase {
    ips: HashSet<String>,
    domains: HashSet<String>,
    sha256: HashSet<String>,
    sha1: HashSet<String>,
    md5: HashSet<String>,
}

impl IocDatabase {
    pub fn new() -> Self {
        Self {
            ips: HashSet::new(),
            domains: HashSet::new(),
            sha256: HashSet::new(),
            sha1: HashSet::new(),
            md5: HashSet::new(),
        }
    }

    pub fn load_json(&mut self, json: &str) -> Result<usize, serde_json::Error> {
        let iocs: Vec<Ioc> = serde_json::from_str(json)?;
        let count = iocs.len();
        for ioc in iocs {
            self.add(ioc);
        }
        Ok(count)
    }

    pub fn add(&mut self, ioc: Ioc) {
        match ioc.ioc_type {
            IocType::IpAddress(ip) => {
                self.ips.insert(ip.to_lowercase());
            }
            IocType::Domain(d) => {
                self.domains.insert(d.to_lowercase());
            }
            IocType::FileHash { hash_type, value } => {
                let v = value.to_lowercase();
                match hash_type {
                    HashType::Sha256 => {
                        self.sha256.insert(v);
                    }
                    HashType::Sha1 => {
                        self.sha1.insert(v);
                    }
                    HashType::Md5 => {
                        self.md5.insert(v);
                    }
                }
            }
        }
    }

    pub fn check_ip(&self, ip: &str) -> bool {
        self.ips.contains(&ip.to_lowercase())
    }

    pub fn check_domain(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();
        if self.domains.contains(&lower) {
            return true;
        }
        for blocked in &self.domains {
            if lower.ends_with(&format!(".{}", blocked)) {
                return true;
            }
        }
        false
    }

    pub fn check_hash(&self, hash: &str) -> bool {
        let lower = hash.to_lowercase();
        match lower.len() {
            64 => self.sha256.contains(&lower),
            40 => self.sha1.contains(&lower),
            32 => self.md5.contains(&lower),
            _ => false,
        }
    }
}

impl Default for IocDatabase {
    fn default() -> Self {
        Self::new()
    }
}
