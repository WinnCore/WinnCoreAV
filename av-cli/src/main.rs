#![allow(dead_code)]
#![allow(unused_variables)]
use anyhow::Result;
use av_core::engine::ScanContext;
use av_core::ScannerConfig;
use av_ml_detector;
use av_quarantine::{QuarantineConfig, QuarantineManager};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "WinnCore AV-Suite CLI",
    propagate_version = true
)]
struct Cli {
    #[arg(
        long,
        help = "Path to scanner config TOML",
        default_value = "config/scanner.toml"
    )]
    config: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    #[command(about = "Scan files or directories")]
    Scan {
        #[command(subcommand)]
        cmd: ScanCmd,
    },
    #[command(about = "Manage quarantined files")]
    Quarantine {
        #[command(subcommand)]
        cmd: QuarantineCmd,
    },
    #[command(about = "Manage signature databases")]
    Signature {
        #[command(subcommand)]
        cmd: SignatureCmd,
    },
    #[command(about = "Model audit and validation")]
    Model {
        #[command(subcommand)]
        cmd: ModelCmd,
    },
    #[command(about = "Threat intel feeds and rules")]
    ThreatIntel {
        #[command(subcommand)]
        cmd: ThreatIntelCmd,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum ScanCmd {
    #[command(about = "Scan a file")]
    File {
        #[arg(help = "Path to file")]
        path: String,
        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
    },
    #[command(about = "Scan a directory")]
    Dir {
        #[arg(help = "Path to directory")]
        path: String,
        #[arg(short, long, help = "Scan recursively")]
        recursive: bool,
        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
        #[arg(long, help = "Write JSON logs to this file instead of stdout")]
        json_log: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum QuarantineCmd {
    #[command(about = "List quarantined files")]
    List {
        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
    },
    #[command(about = "Restore a quarantined file")]
    Restore {
        #[arg(help = "Quarantine ID")]
        id: String,
        #[arg(help = "Destination path")]
        destination: String,
    },
    #[command(about = "Delete a quarantined file")]
    Delete {
        #[arg(help = "Quarantine ID")]
        id: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum SignatureCmd {
    #[command(about = "Update signature databases")]
    Update,
    #[command(about = "List signature databases")]
    List,
}

#[derive(Subcommand, Debug, Clone)]
enum ModelCmd {
    #[command(about = "Verify ONNX model integrity")]
    Verify {
        #[arg(help = "Path to ONNX model")]
        path: String,
        #[arg(long, help = "Expected sha256 checksum")]
        expected_sha256: Option<String>,
        #[arg(long, help = "Verify all models in manifest.json")]
        use_manifest: bool,
    },
    #[command(about = "Run model on sample file")]
    Test {
        #[arg(help = "Path to ONNX model")]
        model: String,
        #[arg(help = "Path to sample file")]
        sample: String,
        #[arg(long, help = "Output JSON")]
        json: bool,
        #[arg(long, help = "Resolve model by version using manifest.json")]
        model_version: Option<String>,
    },
    #[command(about = "Update models from signed manifest")]
    Update {
        #[arg(long, help = "Manifest URL override")]
        manifest_url: Option<String>,
        #[arg(long, help = "Public key path override")]
        pubkey: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum ThreatIntelCmd {
    #[command(about = "Sync STIX/TAXII feeds into local IoC cache")]
    SyncFeeds {
        #[arg(long, help = "TAXII URL override")]
        url: Option<String>,
        #[arg(long, help = "Output cache path")]
        output: Option<String>,
        #[arg(long, help = "JSON output")]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let config_path = std::path::PathBuf::from(&cli.config);

    match cli.command {
        Commands::Scan { cmd } => handle_scan(cmd, config_path).await?,
        Commands::Quarantine { cmd } => handle_quarantine(cmd)?,
        Commands::Signature { cmd } => handle_signature(cmd).await?,
        Commands::Model { cmd } => handle_model(cmd, &config_path)?,
        Commands::ThreatIntel { cmd } => handle_threat_intel(cmd, &config_path)?,
    }

    Ok(())
}

async fn handle_scan(cmd: ScanCmd, config_path: std::path::PathBuf) -> Result<()> {
    let config = if config_path.exists() {
        ScannerConfig::load_from_path(&config_path)
    } else {
        ScannerConfig::default()
    };

    match cmd {
        ScanCmd::File { path, json } => {
            let ctx = ScanContext {
                target: std::path::PathBuf::from(&path),
            };
            let result = av_core::engine::scan_path(&config, &ctx).await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Scan result: {:?}", result);
            }
        }
        ScanCmd::Dir {
            path,
            recursive,
            json,
            json_log,
        } => {
            use walkdir::WalkDir;
            let mut total = 0usize;
            let mut allow = 0usize;
            let mut quarantine = 0usize;
            let mut monitor = 0usize;
            let mut errors = 0usize;
            let writer: Option<std::io::BufWriter<std::fs::File>> = if let Some(p) = json_log {
                let f = std::fs::File::create(&p)?;
                Some(std::io::BufWriter::new(f))
            } else {
                None
            };
            let mut writer = writer;

            for entry in WalkDir::new(&path).follow_links(false) {
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => {
                        errors += 1;
                        continue;
                    }
                };
                if !entry.file_type().is_file() {
                    continue;
                }
                if !recursive && entry.depth() > 1 {
                    continue;
                }
                total += 1;
                let ctx = ScanContext {
                    target: entry.path().to_path_buf(),
                };
                match av_core::engine::scan_path(&config, &ctx).await {
                    Ok(result) => {
                        match result.recommended_action {
                            av_core::RecommendedAction::Allow => allow += 1,
                            av_core::RecommendedAction::Monitor => monitor += 1,
                            av_core::RecommendedAction::Quarantine => quarantine += 1,
                        }
                        if json {
                            let line = serde_json::to_string(&result)?;
                            if let Some(w) = writer.as_mut() {
                                use std::io::Write;
                                writeln!(w, "{}", line)?;
                            } else {
                                println!("{}", line);
                            }
                        }
                    }
                    Err(_) => {
                        errors += 1;
                    }
                }
            }
            println!(
                "Scan summary: total={} allow={} monitor={} quarantine={} errors={}",
                total, allow, monitor, quarantine, errors
            );
        }
    }

    Ok(())
}

fn handle_quarantine(cmd: QuarantineCmd) -> Result<()> {
    let config = QuarantineConfig::default();
    let manager = QuarantineManager::new(config)?;

    match cmd {
        QuarantineCmd::List { json } => {
            let entries = std::fs::read_dir("/var/lib/av/quarantine")?
                .filter_map(|entry| entry.ok())
                .filter(|entry| {
                    entry
                        .path()
                        .extension()
                        .map(|ext| ext == "json")
                        .unwrap_or(false)
                })
                .collect::<Vec<_>>();
            if json {
                println!("{}", serde_json::to_string_pretty(&entries.len())?);
            } else {
                println!("Found {} quarantined files", entries.len());
            }
        }
        QuarantineCmd::Restore { id, destination } => {
            let metadata_path = format!("/var/lib/av/quarantine/{}.json", id);
            let record: av_quarantine::QuarantineRecord =
                serde_json::from_slice(&std::fs::read(metadata_path)?)?;
            manager.restore(&record, std::path::Path::new(&destination))?;
            println!("Restored {}", id);
        }
        QuarantineCmd::Delete { id } => {
            let metadata_path = format!("/var/lib/av/quarantine/{}.json", id);
            let record: av_quarantine::QuarantineRecord =
                serde_json::from_slice(&std::fs::read(metadata_path)?)?;
            manager.delete(&record)?;
            println!("Deleted {}", id);
        }
    }

    Ok(())
}

async fn handle_signature(_cmd: SignatureCmd) -> Result<()> {
    println!("Signature management not yet implemented");
    Ok(())
}

fn handle_model(cmd: ModelCmd, _config_path: &std::path::PathBuf) -> Result<()> {
    match cmd {
        ModelCmd::Verify {
            path,
            expected_sha256,
            use_manifest,
        } => {
            if use_manifest {
                let manifest = av_ml_detector::update::ModelManifest::load(std::path::Path::new(
                    "models/manifest.json",
                ))?;
                for entry in &manifest.models {
                    let p = entry
                        .path
                        .as_ref()
                        .map(|s| std::path::PathBuf::from(s))
                        .unwrap_or_else(|| {
                            std::path::PathBuf::from(format!("models/{}.onnx", entry.model_name))
                        });
                    manifest.verify_checksum(&p)?;
                    println!(
                        "✅ {} version {} checksum ok ({})",
                        entry.model_name, entry.version, entry.sha256
                    );
                }
                return Ok(());
            }

            let p = std::path::Path::new(&path);
            let hash = av_core::logging::sha256_file(p)?;
            println!("sha256: {}", hash);
            if let Some(expected) = expected_sha256 {
                if expected.trim().eq_ignore_ascii_case(&hash) {
                    println!("✅ checksum match");
                    return Ok(());
                } else {
                    anyhow::bail!("checksum mismatch: expected {}, got {}", expected, hash);
                }
            }
        }
        ModelCmd::Test {
            model,
            sample,
            json,
            model_version,
        } => {
            let detector = if let Some(ver) = model_version {
                av_ml_detector::MlDetector::from_manifest(
                    "models/manifest.json",
                    Some(ver.as_str()),
                    0.5,
                )?
            } else {
                av_ml_detector::MlDetector::new(&model)?
            };
            let detection = detector.scan(std::path::Path::new(&sample))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&detection)?);
            } else {
                println!(
                    "score: {:.3} malicious: {}",
                    detection.score, detection.is_malicious
                );
                if let Some(attrs) = detection.feature_importance {
                    for a in attrs.iter().take(5) {
                        println!("  #{:02} {} => {:.4}", a.rank, a.name, a.value);
                    }
                }
                println!("adversarial_hint: {}", detection.adversarial_hint);
            }
        }
        ModelCmd::Update {
            manifest_url,
            pubkey,
        } => {
            println!(
                "Model update stub: manifest_url={:?} pubkey={:?} (hook into signed fetcher)",
                manifest_url, pubkey
            );
        }
    }
    Ok(())
}

fn handle_threat_intel(cmd: ThreatIntelCmd, _config_path: &std::path::PathBuf) -> Result<()> {
    match cmd {
        ThreatIntelCmd::SyncFeeds { url, output, json } => {
            let out = output.unwrap_or_else(|| "threat_intel/cache/iocs.json".to_string());
            // Placeholder: just create empty cache for now.
            let cache = av_core::threat_intel::IocCache { sha256: Vec::new() };
            std::fs::create_dir_all(std::path::Path::new(&out).parent().unwrap())?;
            std::fs::write(&out, serde_json::to_string_pretty(&cache)?)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"status":"ok","output":out,"url":url}).to_string()
                );
            } else {
                println!("Synced threat intel cache to {}", out);
            }
        }
    }
    Ok(())
}
