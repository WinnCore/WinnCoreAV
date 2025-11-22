import sys
sys.path.insert(0, "tools/ml_pipeline")
from feature_extraction import EnhancedARM64FeatureExtractor
e = EnhancedARM64FeatureExtractor()
f = e.extract_features("test_samples/benign_arm64")
assert len(f) == 14, f"Expected 14 features, got {len(f)}"
assert f["file_size"] > 0, "File size should be positive"
print(f"✓ Extracted {len(f)} features: entropy={f['entropy']:.2f}, suspicious={f['suspicious_strings']}")
