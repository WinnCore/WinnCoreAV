# Threat Intelligence Integration

- YARA: configurable rules directory (`threat_intel.yara_rules_dir`); loaded at runtime, matches reported in `yara_matches` and can influence quarantine decisions. Missing rules gracefully skip with a single log.
- STIX/TAXII: `av-cli threat-intel sync-feeds` (planned) fetches bundles into `threat_intel/cache/iocs.json`; runtime loads cache and matches sha256 into `ioc_hits`.
- Logging: JSON detections include `yara_matches`, `ioc_hits`, MITRE tags, and model metadata.
- On-disk layout:
  - `threat_intel/cache/iocs.json` — compact IoC list (sha256 array).
  - `threat_intel/rules/*.yar` — YARA rules to compile.
