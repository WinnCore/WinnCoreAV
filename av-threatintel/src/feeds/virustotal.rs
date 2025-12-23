//! VirusTotal API v3 client
//!
//! Provides file/URL/domain reputation lookups and hunting capabilities.

use crate::ioc::{Confidence, Ioc, IocType, ThreatLevel};
use governor::{Quota, RateLimiter};
use reqwest::Client;
use serde::Deserialize;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum VtError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Rate limited - quota exceeded")]
    RateLimited,
    #[error("Not found")]
    NotFound,
    #[error("API error: {0}")]
    ApiError(String),
}

/// VirusTotal API response wrapper
#[derive(Debug, Deserialize)]
pub struct VtResponse<T> {
    pub data: T,
}

/// VirusTotal file report
#[derive(Debug, Deserialize)]
pub struct VtFileReport {
    pub id: String,
    #[serde(rename = "type")]
    pub item_type: String,
    pub attributes: VtFileAttributes,
}

#[derive(Debug, Deserialize)]
pub struct VtFileAttributes {
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,
    pub meaningful_name: Option<String>,
    pub type_description: Option<String>,
    pub size: Option<u64>,
    pub last_analysis_stats: Option<VtAnalysisStats>,
    pub last_analysis_results: Option<serde_json::Value>,
    pub popular_threat_classification: Option<VtThreatClassification>,
    pub tags: Option<Vec<String>>,
    pub names: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct VtAnalysisStats {
    pub malicious: u32,
    pub suspicious: u32,
    pub undetected: u32,
    pub harmless: u32,
    pub timeout: u32,
    #[serde(rename = "type-unsupported")]
    pub type_unsupported: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct VtThreatClassification {
    pub suggested_threat_label: Option<String>,
    pub popular_threat_category: Option<Vec<VtCategory>>,
    pub popular_threat_name: Option<Vec<VtCategory>>,
}

#[derive(Debug, Deserialize)]
pub struct VtCategory {
    pub count: u32,
    pub value: String,
}

/// VirusTotal domain report
#[derive(Debug, Deserialize)]
pub struct VtDomainReport {
    pub id: String,
    pub attributes: VtDomainAttributes,
}

#[derive(Debug, Deserialize)]
pub struct VtDomainAttributes {
    pub last_analysis_stats: Option<VtAnalysisStats>,
    pub categories: Option<serde_json::Value>,
    pub registrar: Option<String>,
    pub creation_date: Option<i64>,
    pub last_dns_records: Option<Vec<VtDnsRecord>>,
}

#[derive(Debug, Deserialize)]
pub struct VtDnsRecord {
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
    pub ttl: Option<u32>,
}

/// VirusTotal IP report
#[derive(Debug, Deserialize)]
pub struct VtIpReport {
    pub id: String,
    pub attributes: VtIpAttributes,
}

#[derive(Debug, Deserialize)]
pub struct VtIpAttributes {
    pub last_analysis_stats: Option<VtAnalysisStats>,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub as_owner: Option<String>,
    pub continent: Option<String>,
}

/// VirusTotal client configuration
#[derive(Debug, Clone)]
pub struct VtConfig {
    pub api_key: Zeroizing<String>,
    /// Requests per minute (free tier: 4, premium: varies)
    pub rate_limit: u32,
    pub timeout_secs: u64,
}

/// VirusTotal API client with rate limiting
pub struct VtClient {
    config: VtConfig,
    client: Client,
    rate_limiter: Arc<
        RateLimiter<
            governor::state::NotKeyed,
            governor::state::InMemoryState,
            governor::clock::DefaultClock,
        >,
    >,
}

impl VtClient {
    pub fn new(config: VtConfig) -> Result<Self, VtError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()?;

        // Rate limiter: config.rate_limit requests per minute
        let quota = Quota::per_minute(NonZeroU32::new(config.rate_limit).unwrap());
        let rate_limiter = Arc::new(RateLimiter::direct(quota));

        Ok(Self {
            config,
            client,
            rate_limiter,
        })
    }

    /// Wait for rate limiter before making request
    async fn wait_for_rate_limit(&self) {
        self.rate_limiter.until_ready().await;
    }

    async fn get(&self, url: &str) -> Result<reqwest::Response, VtError> {
        self.wait_for_rate_limit().await;

        Ok(self
            .client
            .get(url)
            .header("x-apikey", self.config.api_key.as_str())
            .send()
            .await?)
    }

    /// Get file report by hash
    pub async fn get_file_report(&self, hash: &str) -> Result<VtFileReport, VtError> {
        let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);

        let response = self.get(&url).await?;

        match response.status().as_u16() {
            200 => {
                let vt_response: VtResponse<VtFileReport> = response.json().await?;
                Ok(vt_response.data)
            }
            404 => Err(VtError::NotFound),
            429 => Err(VtError::RateLimited),
            code => {
                let body = response.text().await.unwrap_or_default();
                Err(VtError::ApiError(format!("HTTP {}: {}", code, body)))
            }
        }
    }

    /// Get domain report
    pub async fn get_domain_report(&self, domain: &str) -> Result<VtDomainReport, VtError> {
        let url = format!("https://www.virustotal.com/api/v3/domains/{}", domain);

        let response = self.get(&url).await?;

        match response.status().as_u16() {
            200 => {
                let vt_response: VtResponse<VtDomainReport> = response.json().await?;
                Ok(vt_response.data)
            }
            404 => Err(VtError::NotFound),
            429 => Err(VtError::RateLimited),
            code => {
                let body = response.text().await.unwrap_or_default();
                Err(VtError::ApiError(format!("HTTP {}: {}", code, body)))
            }
        }
    }

    /// Get IP address report
    pub async fn get_ip_report(&self, ip: &str) -> Result<VtIpReport, VtError> {
        let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip);

        let response = self.get(&url).await?;

        match response.status().as_u16() {
            200 => {
                let vt_response: VtResponse<VtIpReport> = response.json().await?;
                Ok(vt_response.data)
            }
            404 => Err(VtError::NotFound),
            429 => Err(VtError::RateLimited),
            code => {
                let body = response.text().await.unwrap_or_default();
                Err(VtError::ApiError(format!("HTTP {}: {}", code, body)))
            }
        }
    }

    /// Convert file report to IOC
    pub fn file_report_to_ioc(&self, report: &VtFileReport) -> Option<Ioc> {
        let sha256 = report.attributes.sha256.as_ref()?;

        let mut ioc = Ioc::new(IocType::Sha256, sha256, "virustotal");
        ioc.source_id = Some(report.id.clone());

        // Set threat level based on detection ratio
        if let Some(stats) = &report.attributes.last_analysis_stats {
            let total = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;
            let detection_ratio = if total > 0 {
                (stats.malicious + stats.suspicious) as f32 / total as f32
            } else {
                0.0
            };

            ioc.threat_level = if detection_ratio > 0.5 {
                ThreatLevel::Critical
            } else if detection_ratio > 0.3 {
                ThreatLevel::High
            } else if detection_ratio > 0.1 {
                ThreatLevel::Medium
            } else if detection_ratio > 0.0 {
                ThreatLevel::Low
            } else {
                ThreatLevel::Info
            };

            ioc.confidence = if stats.malicious > 10 {
                Confidence::High
            } else if stats.malicious > 5 {
                Confidence::Medium
            } else {
                Confidence::Low
            };
        }

        // Add malware family from classification
        if let Some(classification) = &report.attributes.popular_threat_classification {
            if let Some(label) = &classification.suggested_threat_label {
                ioc.malware_families.push(label.clone());
                ioc.description = Some(format!("Classified as: {}", label));
            }
        }

        // Add tags
        if let Some(tags) = &report.attributes.tags {
            for tag in tags {
                ioc.tags.insert(tag.clone());
            }
        }

        Some(ioc)
    }

    /// Convert domain report to IOC
    pub fn domain_report_to_ioc(&self, report: &VtDomainReport) -> Option<Ioc> {
        let mut ioc = Ioc::new(IocType::Domain, &report.id, "virustotal");

        if let Some(stats) = &report.attributes.last_analysis_stats {
            let total = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;
            let detection_ratio = if total > 0 {
                (stats.malicious + stats.suspicious) as f32 / total as f32
            } else {
                0.0
            };

            if detection_ratio < 0.05 {
                // Not malicious enough to track
                return None;
            }

            ioc.threat_level = if detection_ratio > 0.3 {
                ThreatLevel::High
            } else if detection_ratio > 0.1 {
                ThreatLevel::Medium
            } else {
                ThreatLevel::Low
            };
        }

        Some(ioc)
    }

    /// Convert IP report to IOC
    pub fn ip_report_to_ioc(&self, report: &VtIpReport) -> Option<Ioc> {
        let ioc_type = if report.id.contains(':') {
            IocType::Ipv6
        } else {
            IocType::Ipv4
        };

        let mut ioc = Ioc::new(ioc_type, &report.id, "virustotal");

        if let Some(stats) = &report.attributes.last_analysis_stats {
            let total = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;
            let detection_ratio = if total > 0 {
                (stats.malicious + stats.suspicious) as f32 / total as f32
            } else {
                0.0
            };

            if detection_ratio < 0.05 {
                return None;
            }

            ioc.threat_level = if detection_ratio > 0.3 {
                ThreatLevel::High
            } else {
                ThreatLevel::Medium
            };
        }

        // Add geolocation as metadata
        if let Some(country) = &report.attributes.country {
            ioc.tags.insert(format!("country:{}", country));
        }
        if let Some(asn) = report.attributes.asn {
            ioc.tags.insert(format!("asn:{}", asn));
        }

        Some(ioc)
    }
}
