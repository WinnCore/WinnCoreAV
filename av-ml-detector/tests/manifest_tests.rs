use av_ml_detector::update::{select_model_from_manifest, ModelEntry, ModelManifest, UpdateError};
use av_ml_detector::MlDetector;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

fn dummy_manifest() -> ModelManifest {
    ModelManifest {
        models: vec![
            ModelEntry {
                model_name: "gbm_v3".to_string(),
                version: "3.0.0".to_string(),
                sha256: "abc".to_string(),
                created_at: None,
                description: None,
                path: Some("models/gbm_v3.onnx".to_string()),
                current: Some(true),
            },
            ModelEntry {
                model_name: "gbm_v2".to_string(),
                version: "2.0.0".to_string(),
                sha256: "def".to_string(),
                created_at: None,
                description: None,
                path: Some("models/gbm_v2.onnx".to_string()),
                current: Some(false),
            },
        ],
    }
}

#[test]
fn select_current_model() {
    let manifest = dummy_manifest();
    let sel = select_model_from_manifest(&manifest, None).unwrap();
    assert_eq!(sel.version, "3.0.0");
}

#[test]
fn select_locked_model() {
    let manifest = dummy_manifest();
    let sel = select_model_from_manifest(&manifest, Some("2.0.0")).unwrap();
    assert_eq!(sel.version, "2.0.0");
}

#[test]
fn manifest_parse_and_checksum() {
    let tmp = tempdir().unwrap();
    let manifest_path = tmp.path().join("manifest.json");
    let model_path = tmp.path().join("model.onnx");
    fs::write(&model_path, b"dummy").unwrap();
    let sha = av_ml_detector::update::sha256_file(&model_path).unwrap();
    let manifest = ModelManifest {
        models: vec![ModelEntry {
            model_name: "dummy".to_string(),
            version: "1.0.0".to_string(),
            sha256: sha.clone(),
            created_at: None,
            description: None,
            path: Some(model_path.file_name().unwrap().to_string_lossy().to_string()),
            current: Some(true),
        }],
    };
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();
    let loaded = ModelManifest::load(&manifest_path).unwrap();
    loaded.verify_checksum(&model_path).unwrap();
}
