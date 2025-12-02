# WinnCoreAV 🛡️

## 🎥 Investor Demo

![Demo Preview](assets/demo_preview.gif)

*30-second preview - [Run full 5-7 minute demo](demos/investor_demo.sh) or [view recording](demos/investor_demo.cast)*

**Comprehensive investor presentation** covering:
- Technical architecture & ARM64 optimization
- Performance benchmarks (honest comparisons)
- Business model & revenue projections  
- Roadmap & what we need to succeed
- Contact: zw@winncore.com

**[📁 All Demo Files](https://github.com/WinnCore/WinnCoreAV/tree/main/demos)**

---






**ARM64-Native Malware Detection - Learning Project**

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-learning%20project-yellow.svg)]()

> Learning modern AV/EDR concepts by building an ARM64-native malware detector with machine learning.

## What's Actually Implemented

### ✅ Complete: ML Detection Pipeline
- **Feature extraction** from ARM64 ELF binaries (14 features)
- **LightGBM model** trained on 2,631 samples → ONNX runtime
- **Model governance**: checksums, manifests, version control
- **Basic XAI**: feature importance attribution
- **CLI tools**: model verify, model test
- Clean, modular Rust code in `av-ml-detector` crate

**This part works well** and demonstrates ML engineering fundamentals.

### 🚧 Partial: Core Scanning Engine
- Basic scanning pipeline structure exists (`av-core`)
- YARA-X integration is **stubbed** (loads rules, but limited actual scanning)
- IoC cache is **basic** (hash lookup structure, minimal testing)
- eBPF monitoring is **framework only** (not production detections)
- Configuration system works (TOML governance)

**This shows architectural understanding** but needs more implementation work.

### ❌ Not Yet: Production Features
- Real-time file monitoring
- Behavioral detection patterns
- Comprehensive threat intelligence feeds
- Full operator CLI (`scan-dir` command)
- Real-world malware validation
- Enterprise-scale testing

## Why This Project Exists

**Learning objectives:**
1. Understand ML-based malware detection
2. Learn Rust systems programming
3. Explore ARM64 platform opportunities
4. Build portfolio demonstrating potential

**Market context:**
- ARM64 lacks native security tooling
- Open-source AV lags commercial offerings
- Good learning opportunity in underserved niche

## What This Demonstrates

**Technical Skills:**
- ML pipeline (feature engineering → training → ONNX deployment)
- Rust systems programming (async, error handling, testing)
- ARM64 binary analysis (ELF parsing)
- Software architecture (multi-crate workspace, clean APIs)
- Modern development (AI-assisted coding, comprehensive testing)

**Honest Self-Assessment:**
- Strong on **concepts and architecture** ✅
- Early-stage on **complete implementation** 🚧
- Learning **quickly with good fundamentals** 🚀

## Tech Stack

**Core:**
- Rust (memory-safe, high-performance)
- ONNX Runtime (ML inference)
- LightGBM (malware classification)

**Partial/Planned:**
- YARA-X (signature matching)
- eBPF (behavioral monitoring)
- MITRE ATT&CK (threat taxonomy)

## Repository Structure
```
├── av-ml-detector/    # ✅ Complete: ML inference pipeline
├── av-core/           # 🚧 Partial: Scanning engine framework  
├── av-cli/            # 🚧 Partial: Basic CLI (verify/test only)
├── tools/
│   └── ml_pipeline/   # ✅ Complete: Training scripts
├── models/            # ✅ Complete: ONNX models with manifests
└── docs/              # 🚧 Partial: Architecture documentation
```

## Development Approach

**Built by WinnCore** with AI-accelerated development (Claude/Codex).

- **Human:** Architecture, design, research, testing, validation
- **AI:** Code generation, boilerplate, test scaffolding
- **Result:** Fast learning while maintaining code understanding

Using AI tools effectively is itself a valuable skill.

## Current Limitations

Be honest about what this is:
- **Small dataset** (2,631 training samples)
- **Likely overfit** to test set (need more diverse data)
- **Partial implementation** (ML works, rest is framework)
- **Not production-ready** (learning project, not deployment)
- **ARM64 Linux only** (no multi-platform support yet)

## What's Next

**Immediate priorities:**
1. Complete `scan-dir` CLI command
2. Finish YARA integration (actual scanning, not just loading)
3. Add real behavioral detection patterns
4. Expand dataset with diverse samples
5. Comprehensive testing and validation

**Long-term vision:**
- Real-world malware validation
- Production-grade performance
- Advanced XAI (SHAP/LIME)
- Multi-platform support

## For Employers/Recruiters

This project shows:
- **Learning ability** - picked up security, ML, Rust quickly
- **Architectural thinking** - understands modern AV/EDR concepts
- **Clean code** - modular, tested, documented
- **Honest communication** - accurate self-assessment
- **Modern tooling** - effective use of AI for acceleration

It's a **portfolio piece demonstrating potential**, not a finished product.

## Documentation

- [ML Pipeline](docs/ML_ENGINEERING.md) - Feature extraction, training, deployment
- [Architecture](docs/) - System design and component overview

## License

Apache 2.0

---

**Built by [WinnCore](https://github.com/WinnCore) 🚀**

_Learning ARM64 security engineering - honest about current state, excited about future potential_
