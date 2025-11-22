# WinnCoreAV 🛡️

**ARM64-Native Antivirus Research Project** | ML Detection + Behavioral Analysis

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-ARM64-green.svg)]()
[![Status](https://img.shields.io/badge/status-research%20prototype-yellow.svg)]()

> Research prototype exploring ARM64-native antivirus detection using machine learning, behavioral analysis, and signature matching. Built to learn modern security engineering and explore the underserved ARM64 security ecosystem.

**⚠️ Project Status: Research Prototype**  
This is a learning project demonstrating AV/EDR concepts, not production security software. Detection rates and performance claims are based on limited test datasets.

---

## 🎯 What This Actually Is

**Implemented:**
- ✅ Multi-layer detection architecture (heuristics → ML → signatures → IoC)
- ✅ LightGBM-based ML classifier (14 features, ONNX runtime)
- ✅ ARM64 ELF binary feature extraction
- ✅ YARA-X signature matching integration (basic)
- ✅ Structured JSON logging with MITRE ATT&CK tags
- ✅ Configuration governance via TOML
- ✅ Model management with checksums and manifests
- ✅ Basic explainable AI (feature importance)

**Planned/In Progress:**
- 🚧 eBPF behavioral monitoring (framework present, limited detections)
- 🚧 Real-time file monitoring with fanotify
- 🚧 Comprehensive threat intelligence feeds
- 🚧 Advanced explainable AI (SHAP/LIME)
- 🚧 Production-scale testing and hardening
- 🚧 Full CLI interface for operators

**Not Yet Implemented:**
- ❌ Production-grade detection rates (limited training data)
- ❌ Enterprise-scale performance testing
- ❌ Advanced adversarial robustness
- ❌ Multi-platform support (ARM64 Linux only)
- ❌ Real-world deployment validation

---

## 💡 Why This Project Exists

**Learning Objectives:**
1. Understand modern AV/EDR architecture (multi-layer defense)
2. Apply machine learning to security problems
3. Master ARM64 platform and optimization opportunities
4. Build production-quality Rust systems software
5. Explore security engineering career opportunities

**Market Gap Being Explored:**
- ARM64 processors dominate mobile, IoT, and increasingly enterprise (Apple Silicon, AWS Graviton)
- Most antivirus software lacks ARM64-native optimization
- Open-source security tools lag commercial offerings by 5-10 years in ML adoption
- Opportunity to build modern, ARM-optimized security tools

---

## 🏗️ Architecture
```
┌─────────────────────────────────────────────────┐
│              File Scan Request                  │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│    Allowlist Check (paths, SHA256 hashes)       │
│              → Early Allow                      │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│         Heuristic Detection                     │
│    • EICAR signature                            │
│    • ELF header validation                      │
│    • Basic static analysis                      │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│         ML Classification (ONNX)                │
│    • Extract 14 binary features                 │
│    • LightGBM inference                         │
│    • Feature importance (basic XAI)             │
│    • Score: 0.0 (benign) → 1.0 (malicious)      │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│         Signature Matching (YARA-X)             │
│    • Pattern-based detection                    │
│    • Community rule support                     │
│    • (Basic integration)                        │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│         IoC Lookup                              │
│    • Hash-based threat intel                    │
│    • Known-bad indicator matching               │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│         Decision & Logging                      │
│    • Apply thresholds                           │
│    • Tag with MITRE ATT&CK techniques           │
│    • Structured JSON output                     │
│    • Action: Allow / Quarantine / Neutral       │
└─────────────────────────────────────────────────┘
```

---

## 📊 Performance & Detection (Caveats)

**Lab Benchmarks (Single-threaded, small dataset):**
- CPU: <5% idle on Snapdragon X Elite
- Memory: ~4-5MB footprint
- SHA-512: 400+ MB/s throughput
- Scan time: ~26ms average per file

**Detection Performance (Limited test set):**
- Training: 2,631 synthetic + real samples
- Test: 700 malware + 50 benign samples
- **"100% detection"*** on this narrow test set

**⚠️ Reality Check:**
- Small dataset (not production-scale)
- Likely overfit to test samples
- Synthetic malware generation is basic augmentation, not adversarial training
- No real-world deployment validation
- ARM64-specific malware is rare, limiting testing

**What this demonstrates:** Understanding of AV architecture and ML fundamentals, not production-ready detection.

---

## 🧪 Technical Implementation

### ML Pipeline
```python
# Feature extraction (Rust) → Training (Python) → ONNX export

# 14 Features extracted from ARM64 ELF:
- file_size, entropy, entry_point
- num_sections, num_segments
- text_size, data_size, rodata_size, bss_size
- num_dynsym, num_symtab
- is_stripped, is_pie
- suspicious_strings

# Model: LightGBM → ONNX Runtime
# Governance: Checksums, manifests, version control
```

### Rust Components
```rust
// av-core: Core scanning engine
pub fn scan_file(path: &Path, config: &ScannerConfig) 
    -> Result<ScanOutcome>;

// av-ml-detector: ML inference
pub fn predict(&self, features: &[f32]) 
    -> Result<MlDetection>;

// av-cli: Operator interface (minimal)
av-cli model verify --model ./models/model.onnx
av-cli model test --model ./models/model.onnx --input sample.bin
```

### Configuration
```toml
# scanner.toml - Single governance file
[ml]
enabled = true
threshold_malicious = 0.7
threshold_suspicious = 0.5

[threat_intel]
yara_rules_dir = "threat_intel/yara_rules"
ioc_cache_path = "threat_intel/cache/iocs.json"

[logging]
json_enabled = true
mitre_tagging = true
```

---

## 🧠 What I Learned

**Security Engineering:**
- Multi-layer defense architecture (defense in depth)
- MITRE ATT&CK framework for threat modeling
- Threat intelligence integration patterns
- Detection engineering vs. signature-based AV

**Machine Learning:**
- Feature engineering for binary malware detection
- Model governance (versioning, checksums, manifests)
- Basic explainable AI (feature importance)
- Understanding of adversarial ML challenges (even if not fully solved)

**Systems Programming:**
- High-performance Rust for security applications
- ONNX runtime integration
- ARM64 binary analysis (ELF parsing)
- Structured logging and observability

**Platform Expertise:**
- ARM64 architecture and optimization opportunities
- NEON SIMD and crypto acceleration
- Cross-platform challenges

---

## 🛠️ Development Approach

**Built by [WinnCore](https://github.com/WinnCore)** | AI-Accelerated Development

This project demonstrates modern software engineering:
- **Architecture & Design:** Human-driven technical decisions, research, planning
- **Implementation:** AI-assisted code generation (Claude, Codex)
- **Testing & Validation:** Comprehensive human-verified test suites
- **Learning:** Deep dive into ARM64, ML, security, and Rust

**Philosophy:** Use AI as a force multiplier while maintaining deep understanding and ownership of the codebase. Every line of AI-generated code is reviewed, tested, and integrated thoughtfully.

**Why this matters:** Effective use of AI tools is itself a valuable skill. This project shows:
1. Ability to architect complex systems
2. Skill in directing AI to implement specifications
3. Rigorous testing and validation
4. Technical depth in security, ML, and systems programming

---

## 📚 Documentation

- [ML Engineering Guide](docs/ML_ENGINEERING.md) - Architecture, features, models
- [Threat Intel Integration](docs/THREAT_INTEL.md) - YARA, IoC patterns
- [Adversarial Toolkit](tools/adversarial/README.md) - Basic augmentation

---

## 🛣️ Roadmap

**Phase 4 (Current): Advanced Detection**
- [ ] Complete scan-dir CLI command
- [ ] ARM64 hardware security monitoring (PAC, BTI)
- [ ] Enhanced explainable AI (SHAP/LIME)
- [ ] Living-off-the-land binary detection
- [ ] Comprehensive stress testing

**Phase 5: Production Hardening**
- [ ] Larger, more diverse training dataset
- [ ] Real-world malware validation
- [ ] Performance optimization at scale
- [ ] Advanced adversarial robustness
- [ ] 24hr+ stability testing

**Future Vision:**
- Federated learning for privacy-preserving threat sharing
- Multi-platform support (Windows, macOS)
- Container/Kubernetes security integration
- Advanced behavioral analysis with eBPF

---

## 🎓 Educational Value

**For Employers/Clients:**

This project demonstrates:
1. **Security Fundamentals:** Understanding of modern AV/EDR architecture
2. **ML Engineering:** Feature engineering, model governance, XAI concepts
3. **Systems Programming:** High-performance Rust, async/concurrent design
4. **Platform Expertise:** ARM64 architecture and optimization
5. **Modern Development:** Effective AI tool usage + rigorous validation
6. **Honest Communication:** Accurate technical assessment of capabilities and limitations

**Skill Level Assessment:**
- Intermediate-to-advanced in **concept and architecture** ✅
- Early-stage in **production implementation and scale** 🚧
- Strong **learning velocity and technical curiosity** 🚀

This is a portfolio piece showing **potential and learning ability**, not a finished commercial product.

---

## 🤝 Contributing

Contributions welcome! This is a learning project, so:
- Don't expect production-grade code review turnaround
- Focus on educational value over production features
- Help improve documentation and accuracy

Areas needing improvement:
- Larger, more diverse training datasets
- Real ARM64 malware samples for testing
- Advanced adversarial ML techniques
- Production-scale performance testing
- Better eBPF integration

---

## 📄 License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- YARA-X project for ARM64-native signature matching
- MITRE ATT&CK framework for threat taxonomy
- Rust community for excellent tooling and libraries
- Anthropic Claude & OpenAI Codex for development acceleration
- Security research community for public knowledge sharing

---

**Built by [WinnCore](https://github.com/WinnCore) 🚀**

_Exploring ARM64 security through hands-on learning - architected by humans, accelerated by AI._

**Status:** Research prototype demonstrating AV/EDR concepts  
**Goal:** Learn modern security engineering while building something genuinely useful  
**Honesty:** This is a learning project, not production software (yet)
EOF
**[← Back to Main README](README.md)** | **[View Full Documentation →](docs/)**
