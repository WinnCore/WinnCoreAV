//! Threat Intelligence Integration for WinnCoreAV
//!
//! Provides IOC ingestion, storage, and lookup capabilities
//! supporting STIX/TAXII, MISP, VirusTotal, and custom feeds.

pub mod ioc;
pub mod storage;

pub use ioc::{
    Confidence, ConnectionContext, Ioc, IocMatch, IocType, MatchContext, MatchType, ThreatLevel,
};
pub use storage::IocDatabase;
