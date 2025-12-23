//! MISP (Malware Information Sharing Platform) client
//!
//! Integrates with MISP instances to fetch threat intelligence.

use crate::ioc::{Confidence, Ioc, IocType};
use reqwest::{header, Client};
use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;
use tracing::debug;
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum MispError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("API error: {0}")]
    ApiError(String),
}

/// MISP Event
#[derive(Debug, Deserialize)]
pub struct MispEvent {
    #[serde(rename = "Event")]
    pub event: MispEventData,
}

#[derive(Debug, Deserialize)]
pub struct MispEventData {
    pub id: String,
    pub info: String,
    pub threat_level_id: String,
    pub date: String,
    #[serde(rename = "Attribute")]
    pub attributes: Option<Vec<MispAttribute>>,
    #[serde(rename = "Tag")]
    pub tags: Option<Vec<MispTag>>,
}

/// MISP Attribute (individual IOC)
#[derive(Debug, Deserialize)]
pub struct MispAttribute {
    pub id: String,
    #[serde(rename = "type")]
    pub attr_type: String,
    pub value: String,
    pub category: String,
    pub to_ids: bool,
    pub comment: Option<String>,
    pub timestamp: String,
    #[serde(rename = "Tag")]
    pub tags: Option<Vec<MispTag>>,
}

/// MISP Tag
#[derive(Debug, Deserialize)]
pub struct MispTag {
    pub name: String,
    pub colour: Option<String>,
}

/// MISP search response
#[derive(Debug, Deserialize)]
pub struct MispSearchResponse {
    pub response: Vec<MispEvent>,
}

/// MISP attribute search response
#[derive(Debug, Deserialize)]
pub struct MispAttributeResponse {
    pub response: MispAttributeResponseInner,
}

#[derive(Debug, Deserialize)]
pub struct MispAttributeResponseInner {
    #[serde(rename = "Attribute")]
    pub attributes: Vec<MispAttribute>,
}

/// MISP client configuration
#[derive(Debug, Clone)]
pub struct MispConfig {
    pub url: String,
    pub api_key: Zeroizing<String>,
    pub verify_ssl: bool,
    pub timeout_secs: u64,
}

/// MISP Client
pub struct MispClient {
    config: MispConfig,
    client: Client,
}

impl MispClient {
    pub fn new(config: MispConfig) -> Result<Self, MispError> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );

        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .danger_accept_invalid_certs(!config.verify_ssl)
            .default_headers(headers)
            .build()?;

        Ok(Self { config, client })
    }

    /// Search for events by various criteria
    pub async fn search_events(
        &self,
        last_days: Option<u32>,
        tags: Option<Vec<&str>>,
        threat_level: Option<u8>,
    ) -> Result<Vec<MispEvent>, MispError> {
        let url = format!("{}/events/restSearch", self.config.url);

        let mut body = serde_json::json!({
            "returnFormat": "json",
            "includeContext": false,
            "includeDecayScore": false,
            "includeSightingdb": false,
        });

        if let Some(days) = last_days {
            body["last"] = serde_json::json!(format!("{}d", days));
        }

        if let Some(tags) = tags {
            body["tags"] = serde_json::json!(tags);
        }

        if let Some(level) = threat_level {
            body["threat_level_id"] = serde_json::json!(level);
        }

        let response = self.authorized_post(&url).json(&body).send().await?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(MispError::AuthenticationFailed);
        }

        let search_response: MispSearchResponse = response.json().await?;

        Ok(search_response.response)
    }

    /// Search for attributes (IOCs) directly
    pub async fn search_attributes(
        &self,
        attr_type: Option<&str>,
        last_days: Option<u32>,
        to_ids_only: bool,
    ) -> Result<Vec<MispAttribute>, MispError> {
        let url = format!("{}/attributes/restSearch", self.config.url);

        let mut body = serde_json::json!({
            "returnFormat": "json",
            "enforceWarninglist": true,
        });

        if let Some(t) = attr_type {
            body["type"] = serde_json::json!(t);
        }

        if let Some(days) = last_days {
            body["last"] = serde_json::json!(format!("{}d", days));
        }

        if to_ids_only {
            body["to_ids"] = serde_json::json!(true);
        }

        let response = self.authorized_post(&url).json(&body).send().await?;

        let attr_response: MispAttributeResponse = response.json().await?;

        Ok(attr_response.response.attributes)
    }

    /// Get all IOC-worthy attributes from recent events
    pub async fn get_iocs(&self, last_days: u32) -> Result<Vec<Ioc>, MispError> {
        // Fetch attributes that are marked for IDS use
        let attributes = self.search_attributes(None, Some(last_days), true).await?;

        let iocs: Vec<Ioc> = attributes
            .into_iter()
            .filter_map(|attr| self.attribute_to_ioc(&attr))
            .collect();

        Ok(iocs)
    }

    fn attribute_to_ioc(&self, attr: &MispAttribute) -> Option<Ioc> {
        let ioc_type = self.misp_type_to_ioc_type(&attr.attr_type)?;

        let mut ioc = Ioc::new(ioc_type, &attr.value, "misp");
        ioc.source_id = Some(attr.id.clone());
        ioc.description = attr.comment.clone();

        // Set confidence based on category
        ioc.confidence = match attr.category.as_str() {
            "Payload delivery" | "Payload installation" => Confidence::High,
            "Network activity" => Confidence::Medium,
            "External analysis" => Confidence::Low,
            _ => Confidence::Medium,
        };

        // Add tags
        if let Some(tags) = &attr.tags {
            for tag in tags {
                ioc.tags.insert(tag.name.clone());

                // Extract MITRE technique IDs from tags
                if tag
                    .name
                    .starts_with("misp-galaxy:mitre-attack-pattern")
                {
                    if let Some(technique) = self.extract_mitre_from_tag(&tag.name) {
                        ioc.mitre_techniques.push(technique);
                    }
                }

                // Extract malware family from tags
                if tag.name.starts_with("misp-galaxy:malpedia") {
                    if let Some(malware) = self.extract_malware_from_tag(&tag.name) {
                        ioc.malware_families.push(malware);
                    }
                }
            }
        }

        Some(ioc)
    }

    fn misp_type_to_ioc_type(&self, misp_type: &str) -> Option<IocType> {
        match misp_type {
            "sha256" | "filename|sha256" => Some(IocType::Sha256),
            "sha1" | "filename|sha1" => Some(IocType::Sha1),
            "md5" | "filename|md5" => Some(IocType::Md5),
            "ip-dst" | "ip-src" => Some(IocType::Ipv4),
            "ip-dst|port" | "ip-src|port" => Some(IocType::Ipv4),
            "domain" | "hostname" => Some(IocType::Domain),
            "url" | "uri" | "link" => Some(IocType::Url),
            "email" | "email-src" | "email-dst" => Some(IocType::Email),
            "filename" => Some(IocType::Filename),
            "ja3-fingerprint-md5" => Some(IocType::Ja3Hash),
            "hassh-md5" | "hasshserver-md5" => Some(IocType::Md5),
            "x509-fingerprint-sha256" => Some(IocType::SslCertHash),
            _ => {
                debug!("Unknown MISP type: {}", misp_type);
                None
            }
        }
    }

    fn extract_mitre_from_tag(&self, tag: &str) -> Option<String> {
        // Tag format: misp-galaxy:mitre-attack-pattern="T1059 - Command and Scripting Interpreter"
        if let Some(start) = tag.find("T1") {
            let after_t = &tag[start..];
            let end = after_t
                .find(|c: char| !c.is_alphanumeric() && c != '.')
                .unwrap_or(after_t.len());
            return Some(after_t[..end].to_string());
        }
        None
    }

    fn extract_malware_from_tag(&self, tag: &str) -> Option<String> {
        // Tag format: misp-galaxy:malpedia="Emotet"
        if let Some(start) = tag.find('"') {
            let after_quote = &tag[start + 1..];
            if let Some(end) = after_quote.find('"') {
                return Some(after_quote[..end].to_string());
            }
        }
        None
    }

    fn authorized_post(&self, url: &str) -> reqwest::RequestBuilder {
        self.client
            .post(url)
            .header("Authorization", self.config.api_key.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_misp_type_conversion() {
        let config = MispConfig {
            url: "https://misp.example.com".to_string(),
            api_key: Zeroizing::new("test".to_string()),
            verify_ssl: true,
            timeout_secs: 30,
        };
        let client = MispClient::new(config).unwrap();

        assert_eq!(client.misp_type_to_ioc_type("sha256"), Some(IocType::Sha256));
        assert_eq!(client.misp_type_to_ioc_type("ip-dst"), Some(IocType::Ipv4));
        assert_eq!(client.misp_type_to_ioc_type("domain"), Some(IocType::Domain));
        assert_eq!(client.misp_type_to_ioc_type("url"), Some(IocType::Url));
    }

    #[test]
    fn test_mitre_extraction() {
        let config = MispConfig {
            url: "https://misp.example.com".to_string(),
            api_key: Zeroizing::new("test".to_string()),
            verify_ssl: true,
            timeout_secs: 30,
        };
        let client = MispClient::new(config).unwrap();

        let tag = "misp-galaxy:mitre-attack-pattern=\"T1059.004 - Unix Shell\"";
        let result = client.extract_mitre_from_tag(tag);
        assert_eq!(result, Some("T1059.004".to_string()));
    }
}
