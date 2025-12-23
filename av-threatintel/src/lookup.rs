//! High-performance lookup engine for real-time IOC matching
//!
//! Integrates with the detection pipeline for instant threat correlation.

use crate::ioc::{IocMatch, IocType, MatchContext, MatchType};
use crate::storage::IocDatabase;
use chrono::Utc;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::trace;

/// High-performance lookup engine
pub struct LookupEngine {
    database: Arc<IocDatabase>,

    /// Enable subdomain matching for domains
    subdomain_matching: bool,

    /// Enable CIDR matching for IPs (future)
    cidr_matching: bool,

    /// Minimum confidence level for matches
    min_confidence: u8,
}

impl LookupEngine {
    pub fn new(database: Arc<IocDatabase>) -> Self {
        Self {
            database,
            subdomain_matching: true,
            cidr_matching: false,
            min_confidence: 0,
        }
    }

    /// Configure subdomain matching
    pub fn with_subdomain_matching(mut self, enabled: bool) -> Self {
        self.subdomain_matching = enabled;
        self
    }

    /// Configure minimum confidence threshold
    pub fn with_min_confidence(mut self, min: u8) -> Self {
        self.min_confidence = min;
        self
    }

    /// Look up a file hash (SHA256, SHA1, or MD5)
    pub fn lookup_hash(&self, hash: &str, context: MatchContext) -> Option<IocMatch> {
        let hash_clean = hash.trim().to_lowercase();

        // Validate hash format
        let expected_len = match hash_clean.len() {
            64 => 64, // SHA256
            40 => 40, // SHA1
            32 => 32, // MD5
            _ => return None,
        };

        if hash_clean.len() != expected_len || !hash_clean.chars().all(|c| c.is_ascii_hexdigit())
        {
            return None;
        }

        trace!("Looking up hash: {}", hash_clean);

        if let Some(ioc) = self.database.lookup_hash(&hash_clean) {
            if ioc.confidence as u8 >= self.min_confidence && ioc.active && !ioc.is_expired() {
                return Some(IocMatch {
                    ioc: (*ioc).clone(),
                    matched_value: hash_clean,
                    match_type: MatchType::Exact,
                    matched_at: Utc::now(),
                    context,
                });
            }
        }

        None
    }

    /// Look up an IP address
    pub fn lookup_ip(&self, ip: &str, context: MatchContext) -> Option<IocMatch> {
        let ip_clean = ip.trim();

        // Validate IP format
        if ip_clean.parse::<IpAddr>().is_err() {
            return None;
        }

        trace!("Looking up IP: {}", ip_clean);

        // Exact match
        if let Some(ioc) = self.database.lookup_ip(ip_clean) {
            if ioc.confidence as u8 >= self.min_confidence && ioc.active && !ioc.is_expired() {
                return Some(IocMatch {
                    ioc: (*ioc).clone(),
                    matched_value: ip_clean.to_string(),
                    match_type: MatchType::Exact,
                    matched_at: Utc::now(),
                    context,
                });
            }
        }

        if self.cidr_matching {
            // TODO: CIDR matching for network ranges
        }

        None
    }

    /// Look up a domain (with optional subdomain matching)
    pub fn lookup_domain(&self, domain: &str, context: MatchContext) -> Option<IocMatch> {
        let domain_clean = domain.trim().to_lowercase();
        let domain_clean = domain_clean.strip_suffix('.').unwrap_or(&domain_clean);

        trace!("Looking up domain: {}", domain_clean);

        let lookup = if self.subdomain_matching {
            self.database.lookup_domain(domain_clean)
        } else {
            self.database.lookup_domain_exact(domain_clean)
        };

        if let Some(ioc) = lookup {
            if ioc.confidence as u8 >= self.min_confidence && ioc.active && !ioc.is_expired() {
                let match_type = if ioc.value.to_lowercase() == domain_clean {
                    MatchType::Exact
                } else {
                    MatchType::Subdomain
                };

                return Some(IocMatch {
                    ioc: (*ioc).clone(),
                    matched_value: domain_clean.to_string(),
                    match_type,
                    matched_at: Utc::now(),
                    context,
                });
            }
        }

        None
    }

    /// Look up a URL
    pub fn lookup_url(&self, url: &str, context: MatchContext) -> Option<IocMatch> {
        // Extract domain from URL and check it
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                // Check domain
                if let Some(mut m) = self.lookup_domain(host, context.clone()) {
                    m.matched_value = url.to_string();
                    return Some(m);
                }

                // Check IP if host is IP
                if host.parse::<IpAddr>().is_ok() {
                    if let Some(mut m) = self.lookup_ip(host, context) {
                        m.matched_value = url.to_string();
                        return Some(m);
                    }
                }
            }
        }

        None
    }

    /// Auto-detect IOC type and look up
    pub fn lookup_auto(&self, value: &str, context: MatchContext) -> Option<IocMatch> {
        let value = value.trim();

        // Try to detect type
        if let Some(ioc_type) = IocType::from_value(value) {
            match ioc_type {
                IocType::Sha256 | IocType::Sha1 | IocType::Md5 => {
                    self.lookup_hash(value, context)
                }
                IocType::Ipv4 | IocType::Ipv6 => self.lookup_ip(value, context),
                IocType::Domain => self.lookup_domain(value, context),
                IocType::Url => self.lookup_url(value, context),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Batch lookup for multiple values
    pub fn lookup_batch(&self, values: &[String], context: MatchContext) -> Vec<IocMatch> {
        values
            .iter()
            .filter_map(|v| self.lookup_auto(v, context.clone()))
            .collect()
    }

    /// Get database statistics
    pub fn stats(&self) -> crate::storage::DbStats {
        self.database.stats()
    }
}

/// Thread-safe wrapper for async usage
pub struct AsyncLookupEngine {
    inner: Arc<LookupEngine>,
}

impl AsyncLookupEngine {
    pub fn new(engine: LookupEngine) -> Self {
        Self {
            inner: Arc::new(engine),
        }
    }

    pub async fn lookup_hash(&self, hash: &str, context: MatchContext) -> Option<IocMatch> {
        let engine = self.inner.clone();
        let hash = hash.to_string();
        tokio::task::spawn_blocking(move || engine.lookup_hash(&hash, context))
            .await
            .ok()
            .flatten()
    }

    pub async fn lookup_ip(&self, ip: &str, context: MatchContext) -> Option<IocMatch> {
        let engine = self.inner.clone();
        let ip = ip.to_string();
        tokio::task::spawn_blocking(move || engine.lookup_ip(&ip, context))
            .await
            .ok()
            .flatten()
    }

    pub async fn lookup_domain(&self, domain: &str, context: MatchContext) -> Option<IocMatch> {
        let engine = self.inner.clone();
        let domain = domain.to_string();
        tokio::task::spawn_blocking(move || engine.lookup_domain(&domain, context))
            .await
            .ok()
            .flatten()
    }

    pub async fn lookup_auto(&self, value: &str, context: MatchContext) -> Option<IocMatch> {
        let engine = self.inner.clone();
        let value = value.to_string();
        tokio::task::spawn_blocking(move || engine.lookup_auto(&value, context))
            .await
            .ok()
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::Ioc;
    use tempfile::tempdir;

    fn create_test_engine() -> LookupEngine {
        let dir = tempdir().unwrap();
        let db = IocDatabase::open(dir.path()).unwrap();

        // Add test IOCs
        db.insert(Ioc::new(IocType::Sha256, "a".repeat(64), "test"))
            .unwrap();
        db.insert(Ioc::new(IocType::Ipv4, "10.0.0.1", "test"))
            .unwrap();
        db.insert(Ioc::new(IocType::Domain, "malware.com", "test"))
            .unwrap();

        LookupEngine::new(Arc::new(db))
    }

    #[test]
    fn test_hash_lookup() {
        let engine = create_test_engine();
        let context = MatchContext::default();

        let result = engine.lookup_hash(&"a".repeat(64), context.clone());
        assert!(result.is_some());

        let result = engine.lookup_hash(&"b".repeat(64), context);
        assert!(result.is_none());
    }

    #[test]
    fn test_ip_lookup() {
        let engine = create_test_engine();
        let context = MatchContext::default();

        let result = engine.lookup_ip("10.0.0.1", context.clone());
        assert!(result.is_some());

        let result = engine.lookup_ip("10.0.0.2", context);
        assert!(result.is_none());
    }

    #[test]
    fn test_auto_detection() {
        let engine = create_test_engine();
        let context = MatchContext::default();

        // Hash
        let result = engine.lookup_auto(&"a".repeat(64), context.clone());
        assert!(result.is_some());

        // IP
        let result = engine.lookup_auto("10.0.0.1", context.clone());
        assert!(result.is_some());

        // Domain
        let result = engine.lookup_auto("malware.com", context);
        assert!(result.is_some());
    }
}
