# WinnCoreAV Testing Methodology

## Autonomous Validation System

For the full always-on validation pipeline (NFR checks, fuzzing, mutation tests,
performance regression, and compliance evidence), see `docs/VALIDATION_SYSTEM.md`.

## Test Suite Overview

MITRE ATT&CK-aligned atomic behavior tests validating detection rules
and latency on ARM64.

## What These Tests Validate

| Validation | Status |
|------------|--------|
| Rules fire for known atomic behaviors | ✅ |
| Detection latency acceptable (<500ms) | ✅ |
| MITRE ATT&CK technique mapping correct | ✅ |
| Alert pipeline works end-to-end | ✅ |
| ARM64 compatibility | ✅ |

## What These Tests Do NOT Validate

| Gap | Planned |
|-----|---------|
| Obfuscated/encoded variants | v2.0 |
| Slow-burn/low-and-slow attacks | v2.0 |
| Response actions (kill/quarantine) | v1.5 |
| Zero-day detection | Ongoing |
| Evasion resistance | Red team |
| False positive rate | v1.5 |

## Current Coverage

| MITRE Tactic | Techniques | Detection |
|--------------|------------|-----------|
| Execution | T1059.004, T1059.006 | 100% |
| Persistence | T1053.003, T1546.004, T1543.002 | 100% |
| Defense Evasion | T1070.003, T1070.006, T1620, T1036.005 | 100% |
| Credential Access | T1003.008, T1552.004, T1552.001 | 100% |
| Discovery | T1087.001, T1049, T1518.001 | 100% |
| Command & Control | T1071.001, T1105 | 100% |
| Impact | T1486, T1485 | 100% |

**Overall: 95.5% detection (21/22 executed tests)**

## Running Tests

```bash
# Start daemon
sudo ./target/release/av-daemon &

# Run attack simulation
./target/release/attack-sim

# View alerts
cat /var/log/winncore/alerts.json | jq
```

## Interpreting Results

- **95%+ detection** = Rules working correctly for known patterns
- **<500ms latency** = Acceptable real-time performance
- **NOT a claim** of production coverage against all malware variants

## Future Testing Roadmap

- [ ] Multiple variants per technique (3-5 each)
- [ ] Obfuscation variants (encoding, string splitting, environment variables)
- [ ] Response action validation
- [ ] False positive suite (benign commands that look suspicious)
- [ ] Integration with MITRE ATT&CK Evaluations framework
- [ ] Real malware samples in isolated sandbox
