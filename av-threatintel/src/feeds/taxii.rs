//! TAXII 2.1 Client for threat intelligence feeds
//!
//! Implements the TAXII 2.1 specification for retrieving STIX 2.1 content
//! from threat intelligence sharing servers.

use crate::feeds::read_env_secret;
use crate::ioc::{Confidence, Ioc, IocType};
use reqwest::{header, Client};
use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info};
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum TaxiiError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("Collection not found: {0}")]
    CollectionNotFound(String),
    #[error("Rate limited")]
    RateLimited,
}

/// TAXII 2.1 Discovery response
#[derive(Debug, Deserialize)]
pub struct TaxiiDiscovery {
    pub title: String,
    pub description: Option<String>,
    pub default: Option<String>,
    pub api_roots: Vec<String>,
}

/// TAXII 2.1 API Root response
#[derive(Debug, Deserialize)]
pub struct TaxiiApiRoot {
    pub title: String,
    pub versions: Vec<String>,
    pub max_content_length: Option<u64>,
}

/// TAXII 2.1 Collection
#[derive(Debug, Deserialize)]
pub struct TaxiiCollection {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub can_read: bool,
    pub can_write: bool,
    pub media_types: Option<Vec<String>>,
}

/// TAXII 2.1 Collections response
#[derive(Debug, Deserialize)]
pub struct TaxiiCollections {
    pub collections: Vec<TaxiiCollection>,
}

/// TAXII 2.1 Envelope (contains STIX objects)
#[derive(Debug, Deserialize)]
pub struct TaxiiEnvelope {
    pub id: Option<String>,
    pub objects: Option<Vec<serde_json::Value>>,
    pub more: Option<bool>,
    pub next: Option<String>,
}

/// TAXII 2.1 client configuration
#[derive(Debug, Clone)]
pub struct TaxiiConfig {
    pub server_url: String,
    pub api_root: String,
    pub collection_id: String,
    pub username: Option<Zeroizing<String>>,
    pub password: Option<Zeroizing<String>>,
    pub api_key: Option<Zeroizing<String>>,
    pub timeout_secs: u64,
    pub page_size: usize,
}

impl TaxiiConfig {
    pub fn with_api_key_env(mut self, var: &str) -> Self {
        self.api_key = read_env_secret(var);
        self
    }

    pub fn with_basic_auth_env(mut self, user_var: &str, pass_var: &str) -> Self {
        self.username = read_env_secret(user_var);
        self.password = read_env_secret(pass_var);
        self
    }
}

/// TAXII 2.1 Client
pub struct TaxiiClient {
    config: TaxiiConfig,
    client: Client,
}

impl TaxiiClient {
    pub fn new(config: TaxiiConfig) -> Result<Self, TaxiiError> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/taxii+json;version=2.1"),
        );
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/taxii+json;version=2.1"),
        );

        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .default_headers(headers)
            .build()?;

        Ok(Self { config, client })
    }

    /// Discover TAXII server capabilities
    pub async fn discover(&self) -> Result<TaxiiDiscovery, TaxiiError> {
        let url = format!("{}/taxii2/", self.config.server_url);

        let response = self.authenticated_get(&url).await?;
        let discovery: TaxiiDiscovery = response.json().await?;

        debug!("TAXII Discovery: {:?}", discovery);
        Ok(discovery)
    }

    /// Get API root information
    pub async fn get_api_root(&self) -> Result<TaxiiApiRoot, TaxiiError> {
        let url = format!("{}/{}/", self.config.server_url, self.config.api_root);

        let response = self.authenticated_get(&url).await?;
        let api_root: TaxiiApiRoot = response.json().await?;

        Ok(api_root)
    }

    /// List available collections
    pub async fn list_collections(&self) -> Result<Vec<TaxiiCollection>, TaxiiError> {
        let url = format!(
            "{}/{}/collections/",
            self.config.server_url, self.config.api_root
        );

        let response = self.authenticated_get(&url).await?;
        let collections: TaxiiCollections = response.json().await?;

        Ok(collections.collections)
    }

    /// Fetch objects from a collection
    pub async fn get_objects(
        &self,
        added_after: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<serde_json::Value>, TaxiiError> {
        let mut url = format!(
            "{}/{}/collections/{}/objects/",
            self.config.server_url, self.config.api_root, self.config.collection_id
        );

        let mut params = Vec::new();
        if let Some(after) = added_after {
            params.push(format!("added_after={}", after));
        }
        let limit = limit.unwrap_or(self.config.page_size);
        if limit > 0 {
            params.push(format!("limit={}", limit));
        }

        if !params.is_empty() {
            url = format!("{}?{}", url, params.join("&"));
        }

        let mut all_objects = Vec::new();
        let mut next_url = Some(url);

        while let Some(current_url) = next_url {
            let response = self.authenticated_get(&current_url).await?;
            let envelope: TaxiiEnvelope = response.json().await?;

            if let Some(objects) = envelope.objects {
                all_objects.extend(objects);
            }

            // Handle pagination
            next_url = if envelope.more.unwrap_or(false) {
                if let Some(next) = envelope.next {
                    if next.starts_with("http://") || next.starts_with("https://") {
                        Some(next)
                    } else {
                        let base = current_url
                            .split('?')
                            .next()
                            .unwrap_or(current_url.as_str());
                        Some(format!("{}?next={}", base, next))
                    }
                } else {
                    None
                }
            } else {
                None
            };
        }

        info!(
            "Retrieved {} STIX objects from TAXII",
            all_objects.len()
        );
        Ok(all_objects)
    }

    /// Convert STIX objects to IOCs
    pub fn stix_to_iocs(&self, objects: Vec<serde_json::Value>) -> Vec<Ioc> {
        let mut iocs = Vec::new();

        for obj in objects {
            if let Some(ioc) = self.parse_stix_object(&obj) {
                iocs.push(ioc);
            }
        }

        info!("Converted {} STIX objects to IOCs", iocs.len());
        iocs
    }

    fn parse_stix_object(&self, obj: &serde_json::Value) -> Option<Ioc> {
        let obj_type = obj.get("type")?.as_str()?;

        match obj_type {
            "indicator" => self.parse_indicator(obj),
            "malware" => self.parse_malware(obj),
            _ => None,
        }
    }

    fn parse_indicator(&self, obj: &serde_json::Value) -> Option<Ioc> {
        let pattern = obj.get("pattern")?.as_str()?;
        let id = obj.get("id")?.as_str()?;

        // Parse STIX pattern: [file:hashes.'SHA-256' = 'abc123']
        let (ioc_type, value) = self.parse_stix_pattern(pattern)?;

        let mut ioc = Ioc::new(ioc_type, value, "taxii");
        ioc.source_id = Some(id.to_string());

        if let Some(name) = obj.get("name").and_then(|v| v.as_str()) {
            ioc.description = Some(name.to_string());
        }

        if let Some(confidence) = obj.get("confidence").and_then(|v| v.as_u64()) {
            ioc.confidence = Confidence::from(confidence as u8);
        }

        // Extract labels as tags
        if let Some(labels) = obj.get("labels").and_then(|v| v.as_array()) {
            for label in labels {
                if let Some(label_str) = label.as_str() {
                    ioc.tags.insert(label_str.to_string());
                }
            }
        }

        // Extract kill chain phases as MITRE techniques
        if let Some(phases) = obj.get("kill_chain_phases").and_then(|v| v.as_array()) {
            for phase in phases {
                if let Some(phase_name) = phase.get("phase_name").and_then(|v| v.as_str()) {
                    ioc.tags.insert(format!("kill_chain:{}", phase_name));
                }
            }
        }

        Some(ioc)
    }

    fn parse_malware(&self, _obj: &serde_json::Value) -> Option<Ioc> {
        // Malware objects describe families, not specific IOCs.
        None
    }

    fn parse_stix_pattern(&self, pattern: &str) -> Option<(IocType, String)> {
        // Parse STIX 2.1 patterns
        // Examples:
        // [file:hashes.'SHA-256' = 'abc123']
        // [ipv4-addr:value = '1.2.3.4']
        // [domain-name:value = 'evil.com']
        // [url:value = 'http://evil.com/malware']

        let pattern = pattern.trim_start_matches('[').trim_end_matches(']');

        if pattern.contains("file:hashes.'SHA-256'") || pattern.contains("file:hashes.SHA256") {
            let value = self.extract_pattern_value(pattern)?;
            return Some((IocType::Sha256, value));
        }
        if pattern.contains("file:hashes.'SHA-1'") || pattern.contains("file:hashes.SHA1") {
            let value = self.extract_pattern_value(pattern)?;
            return Some((IocType::Sha1, value));
        }
        if pattern.contains("file:hashes.MD5") || pattern.contains("file:hashes.'MD5'") {
            let value = self.extract_pattern_value(pattern)?;
            return Some((IocType::Md5, value));
        }
        if pattern.contains("ipv4-addr:value") {
            let value = self.extract_pattern_value(pattern)?;
            return Some((IocType::Ipv4, value));
        }
        if pattern.contains("ipv6-addr:value") {
            let value = self.extract_pattern_value(pattern)?;
            return Some((IocType::Ipv6, value));
        }
        if pattern.contains("domain-name:value") {
            let value = self.extract_pattern_value(pattern)?;
            return Some((IocType::Domain, value));
        }
        if pattern.contains("url:value") {
            let value = self.extract_pattern_value(pattern)?;
            return Some((IocType::Url, value));
        }
        if pattern.contains("email-addr:value") {
            let value = self.extract_pattern_value(pattern)?;
            return Some((IocType::Email, value));
        }

        None
    }

    fn extract_pattern_value(&self, pattern: &str) -> Option<String> {
        // Extract value between quotes after = sign
        let eq_pos = pattern.find('=')?;
        let after_eq = &pattern[eq_pos + 1..];
        let start = after_eq.find('\'')?;
        let after_start = &after_eq[start + 1..];
        let end = after_start.find('\'')?;

        Some(after_start[..end].to_string())
    }

    async fn authenticated_get(&self, url: &str) -> Result<reqwest::Response, TaxiiError> {
        let mut request = self.client.get(url);

        // Add authentication
        if let (Some(user), Some(pass)) = (&self.config.username, &self.config.password) {
            request = request.basic_auth(user.as_str(), Some(pass.as_str()));
        } else if let Some(api_key) = &self.config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key.as_str()));
        }

        let response = request.send().await?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(TaxiiError::AuthenticationFailed);
        }
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(TaxiiError::RateLimited);
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stix_pattern_parsing() {
        let config = TaxiiConfig {
            server_url: "https://example.com".to_string(),
            api_root: "api".to_string(),
            collection_id: "test".to_string(),
            username: None,
            password: None,
            api_key: None,
            timeout_secs: 30,
            page_size: 100,
        };
        let client = TaxiiClient::new(config).unwrap();

        // SHA256
        let pattern = "[file:hashes.'SHA-256' = 'abc123def456']";
        let result = client.parse_stix_pattern(pattern);
        assert!(result.is_some());
        let (ioc_type, value) = result.unwrap();
        assert_eq!(ioc_type, IocType::Sha256);
        assert_eq!(value, "abc123def456");

        // IPv4
        let pattern = "[ipv4-addr:value = '192.168.1.1']";
        let result = client.parse_stix_pattern(pattern);
        assert!(result.is_some());
        let (ioc_type, value) = result.unwrap();
        assert_eq!(ioc_type, IocType::Ipv4);
        assert_eq!(value, "192.168.1.1");

        // Domain
        let pattern = "[domain-name:value = 'evil.com']";
        let result = client.parse_stix_pattern(pattern);
        assert!(result.is_some());
        let (ioc_type, value) = result.unwrap();
        assert_eq!(ioc_type, IocType::Domain);
        assert_eq!(value, "evil.com");
    }
}
