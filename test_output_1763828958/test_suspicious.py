import sys
sys.path.insert(0, "tools/ml_pipeline")
from feature_extraction import EnhancedARM64FeatureExtractor
e = EnhancedARM64FeatureExtractor()
f = e.extract_features("test_samples/suspicious_arm64")
assert len(f) == 14, f"Expected 14 features, got {len(f)}"
print(f"✓ Suspicious strings: {f['suspicious_strings']}, entropy: {f['entropy']:.2f}")
