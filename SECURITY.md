# Security Policy

## Reporting Vulnerabilities

**DO NOT** open a public issue for security vulnerabilities.

**Email:** security@winncore.com  
**Response Time:** Within 48 hours

We follow responsible disclosure practices.

## Supported Versions

| Version | Status | Supported |
|---------|--------|-----------|
| 0.1.x   | Alpha  | ✅ Yes    |

## Threat Model

### What We Protect Against ✅

- **Malware at rest** - Files on disk with known signatures
- **YARA-detectable threats** - Pattern-matched malware
- **EICAR test patterns** - Standard AV test files
- **File-based droppers** - Basic malware delivery

### What We DON'T Protect Against ❌

- **Kernel-level rootkits** - Requires kernel driver
- **Fileless malware** - Memory-only execution
- **Zero-day exploits** - Unknown attack patterns
- **APTs** - Advanced persistent threats
- **Network attacks** - Not a firewall
- **Browser exploits** - No runtime protection
- **Supply chain attacks** - No build-time scanning

## Known Limitations

⚠️ **This is alpha software:**
- Signature-based detection only (no behavioral analysis)
- File scanning only (no process/memory monitoring)
- Limited signature database
- False positives possible
- ARM64 primary focus (x86_64 less tested)

## Security Hardening Status

### ✅ Implemented
- Worker pool architecture (prevents blocking)
- Path canonicalization (symlink protection)
- Quarantine with 0700 permissions
- SHA256 hashing for forensics
- Bounded queue (prevents memory exhaustion)
- Event debouncing (prevents DoS)

### 🚧 In Progress
- [ ] Drop privileges after startup
- [ ] Seccomp sandboxing
- [ ] Quarantine metadata signing
- [ ] Auto-update with verification
- [ ] AppArmor profile

### 📋 Planned
- [ ] Behavioral heuristics
- [ ] Memory scanning
- [ ] Kernel-level hooks (fanotify/eBPF)
- [ ] Cloud threat intelligence (opt-in)

## Responsible Disclosure

We follow a 90-day disclosure policy:
1. Report received → Acknowledge within 48 hours
2. Fix developed and tested
3. Release prepared
4. Public disclosure after 90 days or patch release (whichever comes first)

## Security Best Practices

When using WinnCoreAV:
1. ✅ Keep signatures updated (when auto-update ships)
2. ✅ Run as unprivileged user
3. ✅ Monitor quarantine directory
4. ✅ Review logs regularly
5. ❌ Don't rely on this as sole security measure

## License

Security fixes are provided under the same MIT license as the project.
