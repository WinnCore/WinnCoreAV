//! Indicator of Compromise (IOC) types and structures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

/// Types of IOCs we support
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    Sha256,
    Sha1,
    Md5,
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Email,
    Filename,
    FilePath,
    RegistryKey,
    MutexName,
    YaraRule,
    SslCertHash,
    JarmHash,
    Ja3Hash,
}

impl IocType {
    pub fn from_value(value: &str) -> Option<Self> {
        let value = value.trim().to_lowercase();

        // Hash detection by length and charset
        if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(IocType::Sha256);
        }
        if value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(IocType::Sha1);
        }
        if value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(IocType::Md5);
        }

        // IP detection
        if value.parse::<std::net::Ipv4Addr>().is_ok() {
            return Some(IocType::Ipv4);
        }
        if value.parse::<std::net::Ipv6Addr>().is_ok() {
            return Some(IocType::Ipv6);
        }

        // URL detection
        if value.starts_with("http://") || value.starts_with("https://") {
            return Some(IocType::Url);
        }

        // Email detection
        if value.contains('@') && value.contains('.') {
            return Some(IocType::Email);
        }

        // Domain detection (basic)
        if value.contains('.') && !value.contains('/') && !value.contains('@') {
            return Some(IocType::Domain);
        }

        None
    }
}

/// Confidence level in the IOC
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Unknown = 0,
    Low = 25,
    Medium = 50,
    High = 75,
    Confirmed = 100,
}

impl Default for Confidence {
    fn default() -> Self {
        Confidence::Medium
    }
}

impl From<u8> for Confidence {
    fn from(value: u8) -> Self {
        match value {
            0..=12 => Confidence::Unknown,
            13..=37 => Confidence::Low,
            38..=62 => Confidence::Medium,
            63..=87 => Confidence::High,
            88..=100 => Confidence::Confirmed,
            _ => Confidence::Unknown,
        }
    }
}

/// Threat severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatLevel {
    Unknown = 0,
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl Default for ThreatLevel {
    fn default() -> Self {
        ThreatLevel::Medium
    }
}

/// Indicator of Compromise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    /// Unique identifier
    pub id: String,

    /// The IOC type
    pub ioc_type: IocType,

    /// The actual value (hash, IP, domain, etc.)
    pub value: String,

    /// Normalized/canonicalized value for lookup
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_value: Option<String>,

    /// Confidence in this IOC
    pub confidence: Confidence,

    /// Threat severity
    pub threat_level: ThreatLevel,

    /// Source feed/provider
    pub source: String,

    /// Feed-specific ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,

    /// Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Associated malware families
    #[serde(default)]
    pub malware_families: Vec<String>,

    /// Associated threat actors
    #[serde(default)]
    pub threat_actors: Vec<String>,

    /// MITRE ATT&CK technique IDs
    #[serde(default)]
    pub mitre_techniques: Vec<String>,

    /// Associated campaigns
    #[serde(default)]
    pub campaigns: Vec<String>,

    /// Tags for categorization
    #[serde(default)]
    pub tags: HashSet<String>,

    /// When the IOC was first seen
    pub first_seen: DateTime<Utc>,

    /// When the IOC was last seen active
    pub last_seen: DateTime<Utc>,

    /// When this record was created locally
    pub created_at: DateTime<Utc>,

    /// When this record was last updated
    pub updated_at: DateTime<Utc>,

    /// When this IOC expires (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Whether this IOC is currently active
    pub active: bool,

    /// Number of times this IOC was matched
    #[serde(default)]
    pub hit_count: u64,

    /// Last time this IOC was matched
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_hit: Option<DateTime<Utc>>,

    /// Related IOC IDs
    #[serde(default)]
    pub related_iocs: Vec<String>,

    /// Additional metadata
    #[serde(default)]
    pub metadata: serde_json::Value,
}

impl Ioc {
    pub fn new(ioc_type: IocType, value: impl Into<String>, source: impl Into<String>) -> Self {
        let value = value.into();
        let normalized = Self::normalize_value(ioc_type, &value);
        let now = Utc::now();

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            ioc_type,
            value,
            normalized_value: normalized,
            confidence: Confidence::Medium,
            threat_level: ThreatLevel::Medium,
            source: source.into(),
            source_id: None,
            description: None,
            malware_families: Vec::new(),
            threat_actors: Vec::new(),
            mitre_techniques: Vec::new(),
            campaigns: Vec::new(),
            tags: HashSet::new(),
            first_seen: now,
            last_seen: now,
            created_at: now,
            updated_at: now,
            expires_at: None,
            active: true,
            hit_count: 0,
            last_hit: None,
            related_iocs: Vec::new(),
            metadata: serde_json::Value::Null,
        }
    }

    /// Normalize IOC value for consistent lookup
    fn normalize_value(ioc_type: IocType, value: &str) -> Option<String> {
        match ioc_type {
            IocType::Sha256 | IocType::Sha1 | IocType::Md5 => Some(value.to_lowercase()),
            IocType::Domain => {
                // Remove trailing dot, lowercase
                let domain = value.trim().to_lowercase();
                let domain = domain.strip_suffix('.').unwrap_or(&domain);
                Some(domain.to_string())
            }
            IocType::Url => {
                // Normalize URL
                if let Ok(mut url) = url::Url::parse(value) {
                    // Remove default ports
                    if url.scheme() == "http" && url.port() == Some(80) {
                        let _ = url.set_port(None);
                    }
                    if url.scheme() == "https" && url.port() == Some(443) {
                        let _ = url.set_port(None);
                    }
                    // Lowercase host
                    if let Some(host) = url.host_str() {
                        let _ = url.set_host(Some(&host.to_lowercase()));
                    }
                    Some(url.to_string())
                } else {
                    Some(value.to_lowercase())
                }
            }
            IocType::Ipv4 | IocType::Ipv6 => {
                // Parse and re-format for consistent representation
                if let Ok(ip) = value.parse::<IpAddr>() {
                    Some(ip.to_string())
                } else {
                    Some(value.to_string())
                }
            }
            IocType::Email => Some(value.to_lowercase()),
            _ => None,
        }
    }

    /// Get the lookup key for this IOC
    pub fn lookup_key(&self) -> &str {
        self.normalized_value.as_ref().unwrap_or(&self.value)
    }

    /// Check if IOC has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            Utc::now() > expires
        } else {
            false
        }
    }

    /// Check if IOC is stale (not seen in 90 days)
    pub fn is_stale(&self) -> bool {
        let stale_threshold = chrono::Duration::days(90);
        Utc::now() - self.last_seen > stale_threshold
    }

    /// Record a hit on this IOC
    pub fn record_hit(&mut self) {
        self.hit_count += 1;
        self.last_hit = Some(Utc::now());
    }

    /// Builder pattern methods
    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_threat_level(mut self, level: ThreatLevel) -> Self {
        self.threat_level = level;
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn with_malware(mut self, family: impl Into<String>) -> Self {
        self.malware_families.push(family.into());
        self
    }

    pub fn with_mitre(mut self, technique: impl Into<String>) -> Self {
        self.mitre_techniques.push(technique.into());
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.insert(tag.into());
        self
    }

    pub fn with_expiry(mut self, expires: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires);
        self
    }
}

/// Result of an IOC lookup match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch {
    /// The matched IOC
    pub ioc: Ioc,

    /// What was matched (the input value)
    pub matched_value: String,

    /// Match type (exact, subdomain, CIDR, etc.)
    pub match_type: MatchType,

    /// When the match occurred
    pub matched_at: DateTime<Utc>,

    /// Context about where the match occurred
    pub context: MatchContext,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchType {
    Exact,
    Subdomain,
    Cidr,
    Wildcard,
    Fuzzy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchContext {
    /// Process ID that triggered the match
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,

    /// Process name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,

    /// File path if file-related
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,

    /// Network connection details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<ConnectionContext>,

    /// Detection source
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionContext {
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
}

impl Default for MatchContext {
    fn default() -> Self {
        Self {
            pid: None,
            process_name: None,
            file_path: None,
            connection: None,
            source: "unknown".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioc_type_detection() {
        assert_eq!(
            IocType::from_value("a".repeat(64).as_str()),
            Some(IocType::Sha256)
        );
        assert_eq!(
            IocType::from_value("a".repeat(40).as_str()),
            Some(IocType::Sha1)
        );
        assert_eq!(
            IocType::from_value("a".repeat(32).as_str()),
            Some(IocType::Md5)
        );
        assert_eq!(IocType::from_value("192.168.1.1"), Some(IocType::Ipv4));
        assert_eq!(IocType::from_value("::1"), Some(IocType::Ipv6));
        assert_eq!(IocType::from_value("example.com"), Some(IocType::Domain));
        assert_eq!(
            IocType::from_value("https://example.com/path"),
            Some(IocType::Url)
        );
        assert_eq!(
            IocType::from_value("user@example.com"),
            Some(IocType::Email)
        );
    }

    #[test]
    fn test_ioc_normalization() {
        let ioc = Ioc::new(IocType::Domain, "EXAMPLE.COM.", "test");
        assert_eq!(ioc.lookup_key(), "example.com");

        let ioc = Ioc::new(
            IocType::Sha256,
            "ABC123".to_string() + &"0".repeat(58),
            "test",
        );
        assert!(ioc
            .lookup_key()
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn test_ioc_expiry() {
        let mut ioc = Ioc::new(IocType::Ipv4, "1.2.3.4", "test");
        assert!(!ioc.is_expired());

        ioc.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(ioc.is_expired());
    }
}
