# WinnCoreAV Architecture

## Overview

WinnCoreAV is an ARM64-native EDR built in Rust, targeting cloud workloads on AWS Graviton, Apple Silicon, and Qualcomm Snapdragon platforms.

## Components

### av-daemon
The main detection engine. Runs as a system service.

### av-core
Shared scanning primitives: YARA integration, ML model inference.

### av-behavioral
Rule engine for MITRE ATT&CK behavioral detection.

### av-cli
Command-line interface for manual scans and configuration.

### av-gui (planned)
Tauri-based desktop interface for real-time monitoring.

## Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                           av-daemon                                  │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────────────┐  │
│  │  Process    │    │  Behavioral  │    │     Alert Logger      │  │
│  │  Monitor    │───▶│  Pipeline    │───▶│  /var/log/winncore/   │  │
│  │ (/proc poll)│    │ (rule match) │    │     alerts.json       │  │
│  └─────────────┘    └──────────────┘    └───────────────────────┘  │
│        │                   │                       │                │
│        ▼                   ▼                       ▼                │
│  ProcessExecEvent    Vec<Alert>              JSON Lines            │
└─────────────────────────────────────────────────────────────────────┘
```
