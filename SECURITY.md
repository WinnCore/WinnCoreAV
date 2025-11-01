# Security Policy

## ⚠️ Alpha Software Notice

WinnCoreAV is **alpha-quality software** provided **AS-IS** with **NO WARRANTY** of any kind, express or implied. Use for educational and research purposes only. Not recommended for production environments.

**ARM64-only:** This project targets `aarch64-unknown-linux-gnu` exclusively. No x86/x86_64 support.

## Reporting Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

**Contact:** security@winncore.com  
**Response SLA:** 48 hours acknowledgment  
**Disclosure Policy:** 90-day coordinated disclosure

### Reporting Guidelines

Include:
- Detailed description and reproduction steps
- Affected versions and target architecture (ARM64)
- Proof-of-concept code (if applicable)
- Your contact information for follow-up

## Supported Versions

| Version | Status | Support |
|---------|--------|---------|
| 0.1.x   | Alpha  | ✅ Security fixes |
| < 0.1   | Unsupported | ❌ No support |

## Threat Model

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for complete details.

### In Scope ✅

- File-based malware with known YARA signatures
- EICAR test patterns
- Symlink escape attacks
- Quarantine directory tampering
- Event flood DoS

### Out of Scope ❌

- Kernel-level rootkits
- Fileless/memory-only malware
- Zero-day exploits
- Network-based attacks
- Process/memory monitoring
- Browser runtime protection

## Known Limitations

- **Signature-only detection** (no behavioral analysis)
- **User-space only** (no kernel driver)
- **Limited YARA rule database**
- **False positives possible**
- **ARM64-only** (Snapdragon X, Apple Silicon, Raspberry Pi)

## Security Hardening Checklist

For users:

- [ ] Run as unprivileged user (not root)
- [ ] Monitor quarantine directory (`~/.local/share/winncore-av/quarantine`)
- [ ] Review JSON logs regularly
- [ ] Update YARA signatures (manual until auto-update ships)
- [ ] Use systemd hardening flags (see `winncore-av.service`)
- [ ] Verify quarantine metadata signatures (when implemented)

## Current Hardening Status

### ✅ Implemented
- Worker pool (prevents blocking)
- Path canonicalization (symlink protection)
- 0700 quarantine permissions
- SHA256 forensic hashing
- Bounded queue (backpressure)
- Event debouncing (750ms)

### 🚧 In Progress
- Privilege dropping post-startup
- Seccomp sandboxing
- Quarantine metadata signing
- Signed YARA rule updates

## Disclosure Timeline

1. **T+0:** Vulnerability reported
2. **T+48h:** Acknowledgment sent
3. **T+90d or patch release:** Public disclosure (whichever first)
4. **CVE assignment** if applicable
