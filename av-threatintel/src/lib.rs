//! Threat Intelligence Integration for WinnCoreAV
//!
//! Provides IOC ingestion, storage, and lookup capabilities
//! supporting STIX/TAXII, MISP, VirusTotal, and custom feeds.

pub mod feeds;
pub mod ioc;
pub mod lookup;
pub mod misp;
pub mod stix;
pub mod storage;
pub mod virustotal;

pub use feeds::{FeedConfig, FeedManager, FeedType};
pub use ioc::{
    Confidence, ConnectionContext, Ioc, IocMatch, IocType, MatchContext, MatchType, ThreatLevel,
};
pub use lookup::{AsyncLookupEngine, LookupEngine};
pub use storage::IocDatabase;
