//! Feed manager for automated IOC updates

use crate::feeds::misp::{MispClient, MispConfig};
use crate::feeds::taxii::{TaxiiClient, TaxiiConfig};
use crate::feeds::virustotal::{VtClient, VtConfig, VtError};
use crate::feeds::read_env_secret;
use crate::ioc::{Confidence, Ioc, IocType, ThreatLevel};
use crate::storage::IocDatabase;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};
use zeroize::Zeroizing;

pub struct FeedManager {
    database: Arc<IocDatabase>,
    feeds: Vec<FeedConfig>,
    http: reqwest::Client,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeedConfig {
    pub name: String,
    pub feed_type: FeedType,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_interval")]
    pub update_interval_mins: u64,
    #[serde(default)]
    pub config: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedType {
    Taxii,
    Misp,
    VirusTotal,
    CsvUrl,
    JsonUrl,
}

fn default_enabled() -> bool {
    true
}

fn default_interval() -> u64 {
    60
}

impl FeedManager {
    pub fn new(database: Arc<IocDatabase>, feeds: Vec<FeedConfig>) -> Self {
        Self {
            database,
            feeds,
            http: reqwest::Client::new(),
        }
    }

    /// Start background feed update tasks
    pub async fn start_background_updates(self: Arc<Self>) {
        for feed in &self.feeds {
            if !feed.enabled {
                continue;
            }

            let manager = self.clone();
            let feed = feed.clone();

            tokio::spawn(async move {
                let mut ticker = interval(Duration::from_secs(feed.update_interval_mins * 60));

                loop {
                    ticker.tick().await;

                    info!(feed = %feed.name, "Updating feed");

                    match manager.update_feed(&feed).await {
                        Ok(count) => {
                            info!(feed = %feed.name, count, "Feed update completed");
                        }
                        Err(e) => {
                            error!(feed = %feed.name, error = %e, "Feed update failed");
                        }
                    }
                }
            });
        }
    }

    /// Update a single feed
    async fn update_feed(
        &self,
        feed: &FeedConfig,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let iocs = match &feed.feed_type {
            FeedType::Taxii => self.fetch_taxii(feed).await?,
            FeedType::Misp => self.fetch_misp(feed).await?,
            FeedType::VirusTotal => self.fetch_virustotal(feed).await?,
            FeedType::CsvUrl => self.fetch_csv(feed).await?,
            FeedType::JsonUrl => self.fetch_json(feed).await?,
        };

        if iocs.is_empty() {
            return Ok(0);
        }

        let count = self.database.insert_batch(iocs)?;
        Ok(count)
    }

    async fn fetch_taxii(
        &self,
        feed: &FeedConfig,
    ) -> Result<Vec<Ioc>, Box<dyn std::error::Error + Send + Sync>> {
        let server_url = required_str(&feed.config, "server_url")?;
        let api_root = required_str(&feed.config, "api_root")?;
        let collection_id = required_str(&feed.config, "collection_id")?;
        let timeout_secs = optional_u64(&feed.config, "timeout_secs").unwrap_or(30);
        let page_size = optional_u64(&feed.config, "page_size").unwrap_or(100) as usize;
        let added_after = optional_str(&feed.config, "added_after");

        let username = env_secret_from_config(&feed.config, "username_env");
        let password = env_secret_from_config(&feed.config, "password_env");
        let api_key = env_secret_from_config(&feed.config, "api_key_env");

        let config = TaxiiConfig {
            server_url,
            api_root,
            collection_id,
            username,
            password,
            api_key,
            timeout_secs,
            page_size,
        };

        let client = TaxiiClient::new(config)?;
        let objects = client.get_objects(added_after.as_deref(), None).await?;
        let mut iocs = client.stix_to_iocs(objects);
        for ioc in &mut iocs {
            ioc.source = feed.name.clone();
        }
        Ok(iocs)
    }

    async fn fetch_misp(
        &self,
        feed: &FeedConfig,
    ) -> Result<Vec<Ioc>, Box<dyn std::error::Error + Send + Sync>> {
        let url = required_str(&feed.config, "url")?;
        let api_key = required_env_secret(&feed.config, "api_key_env")?;
        let verify_ssl = optional_bool(&feed.config, "verify_ssl").unwrap_or(true);
        let timeout_secs = optional_u64(&feed.config, "timeout_secs").unwrap_or(30);
        let last_days = optional_u64(&feed.config, "last_days").unwrap_or(7) as u32;

        let config = MispConfig {
            url,
            api_key,
            verify_ssl,
            timeout_secs,
        };

        let client = MispClient::new(config)?;
        let mut iocs = client.get_iocs(last_days).await?;
        for ioc in &mut iocs {
            ioc.source = feed.name.clone();
        }
        Ok(iocs)
    }

    async fn fetch_virustotal(
        &self,
        feed: &FeedConfig,
    ) -> Result<Vec<Ioc>, Box<dyn std::error::Error + Send + Sync>> {
        let api_key = required_env_secret(&feed.config, "api_key_env")?;
        let rate_limit = optional_u64(&feed.config, "rate_limit").unwrap_or(4) as u32;
        let timeout_secs = optional_u64(&feed.config, "timeout_secs").unwrap_or(30);

        let client = VtClient::new(VtConfig {
            api_key,
            rate_limit,
            timeout_secs,
        })?;

        let mut iocs = Vec::new();
        let hashes = optional_array(&feed.config, "hashes");
        let domains = optional_array(&feed.config, "domains");
        let ips = optional_array(&feed.config, "ips");

        for hash in hashes {
            match client.get_file_report(&hash).await {
                Ok(report) => {
                    if let Some(ioc) = client.file_report_to_ioc(&report) {
                        iocs.push(ioc);
                    }
                }
                Err(VtError::NotFound) => {}
                Err(e) => {
                    warn!(hash = %hash, error = %e, "VirusTotal file lookup failed");
                }
            }
        }

        for domain in domains {
            match client.get_domain_report(&domain).await {
                Ok(report) => {
                    if let Some(ioc) = client.domain_report_to_ioc(&report) {
                        iocs.push(ioc);
                    }
                }
                Err(VtError::NotFound) => {}
                Err(e) => {
                    warn!(domain = %domain, error = %e, "VirusTotal domain lookup failed");
                }
            }
        }

        for ip in ips {
            match client.get_ip_report(&ip).await {
                Ok(report) => {
                    if let Some(ioc) = client.ip_report_to_ioc(&report) {
                        iocs.push(ioc);
                    }
                }
                Err(VtError::NotFound) => {}
                Err(e) => {
                    warn!(ip = %ip, error = %e, "VirusTotal IP lookup failed");
                }
            }
        }

        for ioc in &mut iocs {
            ioc.source = feed.name.clone();
        }
        Ok(iocs)
    }

    async fn fetch_csv(
        &self,
        feed: &FeedConfig,
    ) -> Result<Vec<Ioc>, Box<dyn std::error::Error + Send + Sync>> {
        let url = required_str(&feed.config, "url")?;
        let delimiter = optional_str(&feed.config, "delimiter")
            .and_then(|d| d.as_bytes().first().copied())
            .unwrap_or(b',');
        let source_override = optional_str(&feed.config, "source");

        let response = self.http.get(&url).send().await?;
        let body = response.text().await?;

        let mut reader = csv::ReaderBuilder::new()
            .delimiter(delimiter)
            .from_reader(body.as_bytes());
        let headers = reader.headers()?.clone();

        let mut iocs = Vec::new();
        for record in reader.records() {
            let record = record?;
            let value = match find_field(&record, &headers, &["value", "indicator", "ioc"]) {
                Some(v) => v,
                None => continue,
            };

            let ioc_type = find_field(&record, &headers, &["type", "ioc_type", "indicator_type"])
                .and_then(parse_ioc_type)
                .or_else(|| IocType::from_value(value));
            let Some(ioc_type) = ioc_type else { continue };

            let source = source_override
                .clone()
                .unwrap_or_else(|| feed.name.clone());
            let mut ioc = Ioc::new(ioc_type, value, source);

            if let Some(confidence) =
                find_field(&record, &headers, &["confidence"]).and_then(parse_u8)
            {
                ioc.confidence = Confidence::from(confidence);
            }

            if let Some(level) = find_field(&record, &headers, &["threat_level"]).and_then(|v| {
                parse_threat_level(v)
                    .or_else(|| v.parse::<u8>().ok().and_then(threat_level_from_u8))
            }) {
                ioc.threat_level = level;
            }

            if let Some(desc) = find_field(&record, &headers, &["description"]) {
                ioc.description = Some(desc.to_string());
            }

            iocs.push(ioc);
        }

        Ok(iocs)
    }

    async fn fetch_json(
        &self,
        feed: &FeedConfig,
    ) -> Result<Vec<Ioc>, Box<dyn std::error::Error + Send + Sync>> {
        let url = required_str(&feed.config, "url")?;
        let source_override = optional_str(&feed.config, "source");
        let response = self.http.get(&url).send().await?;
        let body = response.text().await?;
        let json: serde_json::Value = serde_json::from_str(&body)?;

        let mut iocs = Vec::new();
        let Some(items) = json.as_array() else { return Ok(iocs) };

        for item in items {
            if let Some(value) = item.as_str() {
                let Some(ioc_type) = IocType::from_value(value) else { continue };
                let source = source_override
                    .clone()
                    .unwrap_or_else(|| feed.name.clone());
                iocs.push(Ioc::new(ioc_type, value, source));
                continue;
            }

            let Some(obj) = item.as_object() else { continue };
            let value = obj
                .get("value")
                .or_else(|| obj.get("indicator"))
                .and_then(|v| v.as_str());
            let Some(value) = value else { continue };

            let ioc_type = obj
                .get("type")
                .or_else(|| obj.get("ioc_type"))
                .and_then(|v| v.as_str())
                .and_then(parse_ioc_type)
                .or_else(|| IocType::from_value(value));
            let Some(ioc_type) = ioc_type else { continue };

            let source = source_override
                .clone()
                .unwrap_or_else(|| feed.name.clone());
            let mut ioc = Ioc::new(ioc_type, value, source);

            if let Some(confidence) = obj.get("confidence").and_then(|v| v.as_u64()) {
                ioc.confidence = Confidence::from(confidence as u8);
            }
            if let Some(level) = obj.get("threat_level").and_then(|v| v.as_str()) {
                if let Some(parsed) = parse_threat_level(level) {
                    ioc.threat_level = parsed;
                }
            }
            if let Some(desc) = obj.get("description").and_then(|v| v.as_str()) {
                ioc.description = Some(desc.to_string());
            }

            iocs.push(ioc);
        }

        Ok(iocs)
    }
}

fn required_str(
    config: &serde_json::Value,
    key: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    optional_str(config, key)
        .ok_or_else(|| format!("Missing required config field: {}", key).into())
}

fn optional_str(config: &serde_json::Value, key: &str) -> Option<String> {
    config.get(key).and_then(|v| v.as_str()).map(|v| v.to_string())
}

fn optional_u64(config: &serde_json::Value, key: &str) -> Option<u64> {
    config.get(key).and_then(|v| v.as_u64())
}

fn optional_bool(config: &serde_json::Value, key: &str) -> Option<bool> {
    config.get(key).and_then(|v| v.as_bool())
}

fn optional_array(config: &serde_json::Value, key: &str) -> Vec<String> {
    config
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn env_secret_from_config(config: &serde_json::Value, key: &str) -> Option<Zeroizing<String>> {
    config
        .get(key)
        .and_then(|v| v.as_str())
        .and_then(read_env_secret)
}

fn required_env_secret(
    config: &serde_json::Value,
    key: &str,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error + Send + Sync>> {
    let env_var = config
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("Missing required config field: {}", key))?;

    read_env_secret(env_var)
        .ok_or_else(|| format!("Missing environment variable: {}", env_var).into())
}

fn find_field<'a>(
    record: &'a csv::StringRecord,
    headers: &csv::StringRecord,
    names: &[&str],
) -> Option<&'a str> {
    for name in names {
        if let Some(idx) = headers.iter().position(|h| h.eq_ignore_ascii_case(name)) {
            if let Some(value) = record.get(idx) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        }
    }
    None
}

fn parse_ioc_type(value: &str) -> Option<IocType> {
    match value.trim().to_lowercase().as_str() {
        "sha256" => Some(IocType::Sha256),
        "sha1" => Some(IocType::Sha1),
        "md5" => Some(IocType::Md5),
        "ipv4" | "ip" => Some(IocType::Ipv4),
        "ipv6" => Some(IocType::Ipv6),
        "domain" => Some(IocType::Domain),
        "url" => Some(IocType::Url),
        "email" => Some(IocType::Email),
        "filename" => Some(IocType::Filename),
        "filepath" | "file_path" => Some(IocType::FilePath),
        "registry" | "registry_key" => Some(IocType::RegistryKey),
        "mutex" | "mutex_name" => Some(IocType::MutexName),
        "yara" => Some(IocType::YaraRule),
        "ssl_cert" | "ssl_cert_hash" => Some(IocType::SslCertHash),
        "jarm" => Some(IocType::JarmHash),
        "ja3" => Some(IocType::Ja3Hash),
        _ => None,
    }
}

fn parse_threat_level(value: &str) -> Option<ThreatLevel> {
    match value.trim().to_lowercase().as_str() {
        "unknown" => Some(ThreatLevel::Unknown),
        "info" => Some(ThreatLevel::Info),
        "low" => Some(ThreatLevel::Low),
        "medium" => Some(ThreatLevel::Medium),
        "high" => Some(ThreatLevel::High),
        "critical" => Some(ThreatLevel::Critical),
        _ => None,
    }
}

fn threat_level_from_u8(value: u8) -> Option<ThreatLevel> {
    match value {
        0 => Some(ThreatLevel::Unknown),
        1 => Some(ThreatLevel::Info),
        2 => Some(ThreatLevel::Low),
        3 => Some(ThreatLevel::Medium),
        4 => Some(ThreatLevel::High),
        5 => Some(ThreatLevel::Critical),
        _ => None,
    }
}

fn parse_u8(value: &str) -> Option<u8> {
    value.trim().parse::<u8>().ok()
}
