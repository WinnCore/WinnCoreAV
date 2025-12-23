//! Threat Intelligence Integration for WinnCoreAV
//!
//! Provides IOC ingestion, storage, and lookup capabilities
//! supporting STIX/TAXII, MISP, VirusTotal, and custom feeds.

pub mod ioc;
pub mod storage;
pub mod feeds;
pub mod lookup;

pub use ioc::{
    Confidence, ConnectionContext, Ioc, IocMatch, IocType, MatchContext, MatchType, ThreatLevel,
};
pub use storage::IocDatabase;
pub use lookup::{AsyncLookupEngine, LookupEngine};
