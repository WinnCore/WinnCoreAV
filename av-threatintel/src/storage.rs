//! High-performance IOC storage using Bloom filters and RocksDB
//!
//! Architecture:
//! - Bloom filter for fast negative lookups (99% of checks)
//! - DashMap for hot/recent IOCs (in-memory cache)
//! - RocksDB for persistent storage (millions of IOCs)

use crate::ioc::{Ioc, IocType};
use bloomfilter::Bloom;
use dashmap::DashMap;
use rocksdb::{DB, IteratorMode, Options, WriteBatch};
use std::path::Path;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::{info, warn};

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] rocksdb::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("IOC not found: {0}")]
    NotFound(String),
    #[error("Invalid IOC: {0}")]
    InvalidIoc(String),
}

/// High-performance IOC database
pub struct IocDatabase {
    /// Bloom filter for fast negative lookups
    bloom_hashes: RwLock<Bloom<String>>,
    bloom_ips: RwLock<Bloom<String>>,
    bloom_domains: RwLock<Bloom<String>>,

    /// In-memory cache for hot IOCs
    cache_hashes: DashMap<String, Arc<Ioc>>,
    cache_ips: DashMap<String, Arc<Ioc>>,
    cache_domains: DashMap<String, Arc<Ioc>>,

    /// Persistent storage
    db: DB,

    /// Statistics
    stats: RwLock<DbStats>,
}

#[derive(Debug, Default, Clone)]
pub struct DbStats {
    pub total_iocs: u64,
    pub hash_iocs: u64,
    pub ip_iocs: u64,
    pub domain_iocs: u64,
    pub url_iocs: u64,
    pub other_iocs: u64,
    pub bloom_false_positives: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub db_lookups: u64,
}

impl IocDatabase {
    /// Create or open IOC database
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_max_open_files(256);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB write buffer
        opts.optimize_for_point_lookup(64 * 1024 * 1024); // 64MB block cache

        let db = DB::open(&opts, path)?;

        // Initialize bloom filters
        // Expected 1M items, 0.01% false positive rate
        let bloom_hashes = Bloom::new_for_fp_rate(1_000_000, 0.0001);
        let bloom_ips = Bloom::new_for_fp_rate(500_000, 0.0001);
        let bloom_domains = Bloom::new_for_fp_rate(500_000, 0.0001);

        let database = Self {
            bloom_hashes: RwLock::new(bloom_hashes),
            bloom_ips: RwLock::new(bloom_ips),
            bloom_domains: RwLock::new(bloom_domains),
            cache_hashes: DashMap::with_capacity(100_000),
            cache_ips: DashMap::with_capacity(50_000),
            cache_domains: DashMap::with_capacity(50_000),
            db,
            stats: RwLock::new(DbStats::default()),
        };

        // Rebuild bloom filters from existing data
        database.rebuild_bloom_filters()?;

        Ok(database)
    }

    /// Rebuild bloom filters from database
    fn rebuild_bloom_filters(&self) -> Result<(), StorageError> {
        info!("Rebuilding bloom filters from database...");

        let mut count = 0u64;

        for result in self.db.iterator(IteratorMode::Start) {
            let (key, _value) = result?;
            let key_str = String::from_utf8_lossy(&key);

            // Parse prefix to determine IOC type
            if let Some(lookup_key) = key_str.strip_prefix("hash:") {
                self.bloom_hashes
                    .write()
                    .unwrap()
                    .set(&lookup_key.to_string());
            } else if let Some(lookup_key) = key_str.strip_prefix("ip:") {
                self.bloom_ips
                    .write()
                    .unwrap()
                    .set(&lookup_key.to_string());
            } else if let Some(lookup_key) = key_str.strip_prefix("domain:") {
                self.bloom_domains
                    .write()
                    .unwrap()
                    .set(&lookup_key.to_string());
            }

            count += 1;
        }

        info!("Rebuilt bloom filters with {} IOCs", count);
        self.stats.write().unwrap().total_iocs = count;

        Ok(())
    }

    /// Generate storage key for IOC
    fn storage_key(ioc_type: IocType, value: &str) -> String {
        let prefix = match ioc_type {
            IocType::Sha256 | IocType::Sha1 | IocType::Md5 => "hash",
            IocType::Ipv4 | IocType::Ipv6 => "ip",
            IocType::Domain => "domain",
            IocType::Url => "url",
            IocType::Email => "email",
            _ => "other",
        };
        format!("{}:{}", prefix, value.to_lowercase())
    }

    /// Insert an IOC
    pub fn insert(&self, ioc: Ioc) -> Result<(), StorageError> {
        let key = Self::storage_key(ioc.ioc_type, ioc.lookup_key());
        let value = serde_json::to_vec(&ioc)?;

        // Insert into RocksDB
        self.db.put(&key, &value)?;

        // Update bloom filter
        match ioc.ioc_type {
            IocType::Sha256 | IocType::Sha1 | IocType::Md5 => {
                self.bloom_hashes
                    .write()
                    .unwrap()
                    .set(&ioc.lookup_key().to_string());
                self.cache_hashes
                    .insert(ioc.lookup_key().to_string(), Arc::new(ioc.clone()));
            }
            IocType::Ipv4 | IocType::Ipv6 => {
                self.bloom_ips
                    .write()
                    .unwrap()
                    .set(&ioc.lookup_key().to_string());
                self.cache_ips
                    .insert(ioc.lookup_key().to_string(), Arc::new(ioc.clone()));
            }
            IocType::Domain => {
                self.bloom_domains
                    .write()
                    .unwrap()
                    .set(&ioc.lookup_key().to_string());
                self.cache_domains
                    .insert(ioc.lookup_key().to_string(), Arc::new(ioc.clone()));
            }
            _ => {}
        }

        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.total_iocs += 1;
        match ioc.ioc_type {
            IocType::Sha256 | IocType::Sha1 | IocType::Md5 => stats.hash_iocs += 1,
            IocType::Ipv4 | IocType::Ipv6 => stats.ip_iocs += 1,
            IocType::Domain => stats.domain_iocs += 1,
            IocType::Url => stats.url_iocs += 1,
            _ => stats.other_iocs += 1,
        }

        Ok(())
    }

    /// Bulk insert IOCs (much faster than individual inserts)
    pub fn insert_batch(&self, iocs: Vec<Ioc>) -> Result<usize, StorageError> {
        let mut batch = WriteBatch::default();
        let mut count = 0;

        for ioc in &iocs {
            let key = Self::storage_key(ioc.ioc_type, ioc.lookup_key());
            let value = serde_json::to_vec(&ioc)?;
            batch.put(&key, &value);

            // Update bloom filters
            match ioc.ioc_type {
                IocType::Sha256 | IocType::Sha1 | IocType::Md5 => {
                    self.bloom_hashes
                        .write()
                        .unwrap()
                        .set(&ioc.lookup_key().to_string());
                }
                IocType::Ipv4 | IocType::Ipv6 => {
                    self.bloom_ips
                        .write()
                        .unwrap()
                        .set(&ioc.lookup_key().to_string());
                }
                IocType::Domain => {
                    self.bloom_domains
                        .write()
                        .unwrap()
                        .set(&ioc.lookup_key().to_string());
                }
                _ => {}
            }

            count += 1;
        }

        self.db.write(batch)?;

        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.total_iocs += count as u64;

        info!("Inserted {} IOCs in batch", count);
        Ok(count)
    }

    /// Fast lookup for hash IOCs
    pub fn lookup_hash(&self, hash: &str) -> Option<Arc<Ioc>> {
        let hash_lower = hash.to_lowercase();

        // Check bloom filter first (fast negative)
        if !self.bloom_hashes.read().unwrap().check(&hash_lower) {
            return None;
        }

        // Check cache
        if let Some(ioc) = self.cache_hashes.get(&hash_lower) {
            self.stats.write().unwrap().cache_hits += 1;
            return Some(ioc.clone());
        }

        self.stats.write().unwrap().cache_misses += 1;

        // Check database
        self.lookup_from_db(IocType::Sha256, &hash_lower)
    }

    /// Fast lookup for IP IOCs
    pub fn lookup_ip(&self, ip: &str) -> Option<Arc<Ioc>> {
        let ip_normalized = ip.to_string();

        // Check bloom filter
        if !self.bloom_ips.read().unwrap().check(&ip_normalized) {
            return None;
        }

        // Check cache
        if let Some(ioc) = self.cache_ips.get(&ip_normalized) {
            self.stats.write().unwrap().cache_hits += 1;
            return Some(ioc.clone());
        }

        self.stats.write().unwrap().cache_misses += 1;

        // Check database
        let ioc_type = if ip.contains(':') {
            IocType::Ipv6
        } else {
            IocType::Ipv4
        };
        self.lookup_from_db(ioc_type, &ip_normalized)
    }

    /// Fast lookup for domain IOCs (with subdomain matching)
    pub fn lookup_domain(&self, domain: &str) -> Option<Arc<Ioc>> {
        let domain_lower = domain.to_lowercase();
        let domain_clean = domain_lower.strip_suffix('.').unwrap_or(&domain_lower);

        // Try exact match first
        if self
            .bloom_domains
            .read()
            .unwrap()
            .check(&domain_clean.to_string())
        {
            if let Some(ioc) = self.cache_domains.get(domain_clean) {
                self.stats.write().unwrap().cache_hits += 1;
                return Some(ioc.clone());
            }

            if let Some(ioc) = self.lookup_from_db(IocType::Domain, domain_clean) {
                return Some(ioc);
            }
        }

        // Try parent domains (subdomain matching)
        let parts: Vec<&str> = domain_clean.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if self.bloom_domains.read().unwrap().check(&parent) {
                if let Some(ioc) = self.lookup_from_db(IocType::Domain, &parent) {
                    return Some(ioc);
                }
            }
        }

        None
    }

    /// Fast lookup for domain IOCs (exact match only)
    pub fn lookup_domain_exact(&self, domain: &str) -> Option<Arc<Ioc>> {
        let domain_lower = domain.to_lowercase();
        let domain_clean = domain_lower.strip_suffix('.').unwrap_or(&domain_lower);

        if !self
            .bloom_domains
            .read()
            .unwrap()
            .check(&domain_clean.to_string())
        {
            return None;
        }

        if let Some(ioc) = self.cache_domains.get(domain_clean) {
            self.stats.write().unwrap().cache_hits += 1;
            return Some(ioc.clone());
        }

        self.stats.write().unwrap().cache_misses += 1;
        self.lookup_from_db(IocType::Domain, domain_clean)
    }

    /// Generic lookup from database
    fn lookup_from_db(&self, ioc_type: IocType, value: &str) -> Option<Arc<Ioc>> {
        let key = Self::storage_key(ioc_type, value);

        self.stats.write().unwrap().db_lookups += 1;

        match self.db.get(&key) {
            Ok(Some(data)) => match serde_json::from_slice::<Ioc>(&data) {
                Ok(ioc) => {
                    let arc_ioc = Arc::new(ioc);

                    // Populate cache for next time
                    match ioc_type {
                        IocType::Sha256 | IocType::Sha1 | IocType::Md5 => {
                            self.cache_hashes.insert(value.to_string(), arc_ioc.clone());
                        }
                        IocType::Ipv4 | IocType::Ipv6 => {
                            self.cache_ips.insert(value.to_string(), arc_ioc.clone());
                        }
                        IocType::Domain => {
                            self.cache_domains.insert(value.to_string(), arc_ioc.clone());
                        }
                        _ => {}
                    }

                    Some(arc_ioc)
                }
                Err(e) => {
                    warn!("Failed to deserialize IOC: {}", e);
                    None
                }
            },
            Ok(None) => {
                // Bloom filter false positive
                self.stats.write().unwrap().bloom_false_positives += 1;
                None
            }
            Err(e) => {
                warn!("Database lookup error: {}", e);
                None
            }
        }
    }

    /// Get database statistics
    pub fn stats(&self) -> DbStats {
        self.stats.read().unwrap().clone()
    }

    /// Clear all IOCs
    pub fn clear(&self) -> Result<(), StorageError> {
        // Clear RocksDB
        for result in self.db.iterator(IteratorMode::Start) {
            let (key, _) = result?;
            self.db.delete(&key)?;
        }

        // Clear caches
        self.cache_hashes.clear();
        self.cache_ips.clear();
        self.cache_domains.clear();

        // Reset bloom filters
        *self.bloom_hashes.write().unwrap() = Bloom::new_for_fp_rate(1_000_000, 0.0001);
        *self.bloom_ips.write().unwrap() = Bloom::new_for_fp_rate(500_000, 0.0001);
        *self.bloom_domains.write().unwrap() = Bloom::new_for_fp_rate(500_000, 0.0001);

        // Reset stats
        *self.stats.write().unwrap() = DbStats::default();

        Ok(())
    }

    /// Remove expired IOCs
    pub fn cleanup_expired(&self) -> Result<usize, StorageError> {
        let mut removed = 0;
        let mut to_remove = Vec::new();

        for result in self.db.iterator(IteratorMode::Start) {
            let (key, value) = result?;
            if let Ok(ioc) = serde_json::from_slice::<Ioc>(&value) {
                if ioc.is_expired() || ioc.is_stale() {
                    to_remove.push(key.to_vec());
                }
            }
        }

        for key in to_remove {
            self.db.delete(&key)?;
            removed += 1;
        }

        info!("Removed {} expired/stale IOCs", removed);
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_database_operations() {
        let dir = tempdir().unwrap();
        let db = IocDatabase::open(dir.path()).unwrap();

        // Insert hash IOC
        let ioc = Ioc::new(IocType::Sha256, "a".repeat(64), "test");
        db.insert(ioc.clone()).unwrap();

        // Lookup should succeed
        let result = db.lookup_hash(&"a".repeat(64));
        assert!(result.is_some());

        // Non-existent should return None
        let result = db.lookup_hash(&"b".repeat(64));
        assert!(result.is_none());
    }

    #[test]
    fn test_domain_subdomain_matching() {
        let dir = tempdir().unwrap();
        let db = IocDatabase::open(dir.path()).unwrap();

        // Insert parent domain
        let ioc = Ioc::new(IocType::Domain, "malware.com", "test");
        db.insert(ioc).unwrap();

        // Exact match
        assert!(db.lookup_domain("malware.com").is_some());

        // Subdomain should match parent
        assert!(db.lookup_domain("evil.malware.com").is_some());
        assert!(db.lookup_domain("very.evil.malware.com").is_some());

        // Different domain should not match
        assert!(db.lookup_domain("malware.org").is_none());
    }

    #[test]
    fn test_batch_insert() {
        let dir = tempdir().unwrap();
        let db = IocDatabase::open(dir.path()).unwrap();

        let iocs: Vec<Ioc> = (0..1000)
            .map(|i| Ioc::new(IocType::Ipv4, format!("10.0.0.{}", i % 256), "test"))
            .collect();

        let count = db.insert_batch(iocs).unwrap();
        assert_eq!(count, 1000);

        // Verify some lookups
        assert!(db.lookup_ip("10.0.0.1").is_some());
        assert!(db.lookup_ip("10.0.0.255").is_some());
    }
}
