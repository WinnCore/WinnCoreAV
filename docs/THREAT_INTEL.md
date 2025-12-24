# Threat Intelligence Integration

## Overview

WinnCoreAV ingests indicators of compromise (IOCs) and performs real-time lookups in the daemon.
The pipeline uses:

- RocksDB-backed storage with Bloom filters and in-memory cache
- High-performance lookup engine for hashes, domains, IPs, and URLs
- Feed clients (TAXII 2.1, MISP, VirusTotal) with env-based secrets

## Runtime Behavior

- Process execution events are hashed (SHA-256) and checked against the IOC database.
- Network connections are checked against IP IOCs (with protocol context).
- Matches emit alerts with source attribution and MITRE context when available.

## Configuration

Threat intel is configured in `config/daemon.toml` under `[threat_intel]`.

Environment override:

- `WINNCORE_THREATINTEL_DB` sets the DB path at runtime.

Key fields:

- `enabled`: master switch for threat intel lookups.
- `db_path`: RocksDB path for IOC storage.
- `min_confidence`: minimum confidence (0-100) for lookup matches.
- `subdomain_matching`: enable parent-domain matching.
- `feeds`: list of feed definitions for background updates.

Example:

```toml
[threat_intel]
enabled = true
db_path = "/var/lib/winncore/threatintel"
min_confidence = 50
subdomain_matching = true

[[threat_intel.feeds]]
name = "misp-prod"
feed_type = "misp"
enabled = true
update_interval_mins = 60
config = { url = "https://misp.example.com", api_key_env = "WINNCORE_MISP_API_KEY", verify_ssl = true, timeout_secs = 30, last_days = 7 }
```

## Environment Variables

API keys must be supplied via env vars referenced in the feed config:

- `WINNCORE_MISP_API_KEY`
- `WINNCORE_TAXII_API_KEY`
- `WINNCORE_VT_API_KEY`

Secrets are stored in zeroized memory when possible.

## Notes

- Feed updates are logged via `tracing`.
- IOC expiration and stale cleanup are available via the storage API and can be scheduled by the daemon if desired.
