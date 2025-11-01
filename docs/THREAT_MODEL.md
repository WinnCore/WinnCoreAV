# Threat Model

**Related Documentation:**  
[SECURITY.md](../SECURITY.md) · [COMPLIANCE.md](../COMPLIANCE.md) · [README](../README.md)

> ⚠️ **Alpha Software:** ARM64-only. No warranty. Educational/research use.


## Scope

WinnCoreAV is designed for **file-based malware detection** on ARM64 Linux systems.

## Assumptions

### Trust Boundaries
- ✅ User space is trusted (no kernel compromise)
- ✅ File system is readable (not encrypted at kernel level)
- ✅ YARA rules are trusted
- ❌ Network is NOT trusted
- ❌ Downloaded files are NOT trusted

### Attack Surface
1. **Files in monitored directories**
   - Downloads, Desktop, Documents
   - User-writable locations
2. **Quarantine directory**
   - Must be protected (0700 perms)
3. **YARA rule updates**
   - Need signature verification (TODO)

## Threats We Mitigate

| Threat | Mitigation | Status |
|--------|------------|--------|
| Known malware signatures | YARA detection | ✅ Implemented |
| Symlink escape | Path canonicalization | ✅ Implemented |
| Quarantine tampering | 0700 permissions | ✅ Implemented |
| Event flood DoS | Bounded queue + debounce | ✅ Implemented |
| Large file DoS | 64MB size gate | ✅ Implemented |

## Threats Out of Scope

| Threat | Reason | Future? |
|--------|--------|---------|
| Zero-day exploits | No behavioral analysis | Maybe |
| Kernel rootkits | User-space only | Unlikely |
| Memory-only malware | No memory scanning | Maybe |
| Network attacks | Not a firewall | No |
| Social engineering | Out of technical scope | No |

## Attack Scenarios

### Scenario 1: Malicious Download
**Attack:** User downloads malware  
**Detection:** YARA signature match  
**Response:** Automatic quarantine  
**Status:** ✅ Working

### Scenario 2: Symlink Attack
**Attack:** Symlink to /etc/shadow  
**Defense:** Canonicalize paths, check against watch roots  
**Status:** ✅ Implemented

### Scenario 3: Quarantine Escape
**Attack:** Malware tries to restore itself  
**Defense:** 0700 perms, separate directory  
**Status:** ✅ Implemented

### Scenario 4: DoS via Events
**Attack:** Generate millions of file events  
**Defense:** Bounded queue, drops tracked  
**Status:** ✅ Implemented

## Security Assumptions

We assume:
1. The OS is not compromised
2. The user is not malicious (no insider threat model)
3. YARA rules are from trusted sources
4. File system metadata is accurate

## Future Hardening

1. **Privilege separation** - Drop caps after startup
2. **Sandboxing** - Seccomp filter
3. **Signing** - Verify quarantine integrity
4. **Updates** - Signed rule updates
