//! Feed clients for threat intelligence ingestion.

pub mod taxii;
pub mod misp;
pub mod virustotal;
pub mod manager;

pub use manager::{FeedConfig, FeedManager, FeedType};

use zeroize::Zeroizing;

pub(crate) fn read_env_secret(var: &str) -> Option<Zeroizing<String>> {
    std::env::var(var)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(Zeroizing::new)
}
