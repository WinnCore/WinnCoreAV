#!/usr/bin/env python3
"""Analyze WinnCoreAV detection performance"""
import sys
sys.path.insert(0, 'tools/ml_pipeline')
from feature_extraction import EnhancedARM64FeatureExtractor
from pathlib import Path
import json

print("╔══════════════════════════════════════════════════════════╗")
print("║  WinnCoreAV Detection Analysis                           ║")
print("╚══════════════════════════════════════════════════════════╝\n")

extractor = EnhancedARM64FeatureExtractor()
samples_dir = Path("malware_testing/samples/arm64")
benign_dir = Path("test_samples")

# Analyze malicious samples
print("🔴 MALICIOUS SAMPLES:")
malicious_features = []
for sample in samples_dir.glob("*.elf"):
    features = extractor.extract_features(str(sample))
    malicious_features.append(features)
    print(f"\n📄 {sample.name}")
    print(f"   Entropy: {features['entropy']:.2f} (high=packed/encrypted)")
    print(f"   Suspicious strings: {features['suspicious_strings']}")
    print(f"   File size: {features['file_size']:.0f} bytes")
    print(f"   Stripped: {'Yes' if features['is_stripped'] else 'No'}")
    print(f"   PIE: {'Yes' if features['is_pie'] else 'No'}")

# Analyze benign samples
print("\n" + "="*60)
print("🟢 BENIGN SAMPLES:")
benign_features = []
for sample in benign_dir.glob("*arm64*"):
    if sample.is_file():
        features = extractor.extract_features(str(sample))
        benign_features.append(features)
        print(f"\n📄 {sample.name}")
        print(f"   Entropy: {features['entropy']:.2f}")
        print(f"   Suspicious strings: {features['suspicious_strings']}")
        print(f"   File size: {features['file_size']:.0f} bytes")

# Statistical comparison
if malicious_features and benign_features:
    print("\n" + "="*60)
    print("📊 STATISTICAL COMPARISON:")
    
    mal_avg_entropy = sum(f['entropy'] for f in malicious_features) / len(malicious_features)
    ben_avg_entropy = sum(f['entropy'] for f in benign_features) / len(benign_features)
    
    mal_avg_suspicious = sum(f['suspicious_strings'] for f in malicious_features) / len(malicious_features)
    ben_avg_suspicious = sum(f['suspicious_strings'] for f in benign_features) / len(benign_features)
    
    print(f"\nAverage Entropy:")
    print(f"  Malicious: {mal_avg_entropy:.2f}")
    print(f"  Benign:    {ben_avg_entropy:.2f}")
    print(f"  Difference: {abs(mal_avg_entropy - ben_avg_entropy):.2f}")
    
    print(f"\nAverage Suspicious Strings:")
    print(f"  Malicious: {mal_avg_suspicious:.1f}")
    print(f"  Benign:    {ben_avg_suspicious:.1f}")
    print(f"  Difference: {abs(mal_avg_suspicious - ben_avg_suspicious):.1f}")
    
    # Detectability assessment
    print("\n" + "="*60)
    print("🎯 DETECTABILITY ASSESSMENT:")
    
    if mal_avg_suspicious > ben_avg_suspicious * 2:
        print("  ✅ Strong string-based detection possible")
    else:
        print("  ⚠️  Weak string-based detection - need ML")
    
    if abs(mal_avg_entropy - ben_avg_entropy) > 1.0:
        print("  ✅ Entropy difference significant")
    else:
        print("  ⚠️  Similar entropy - need behavioral analysis")

# Save analysis
analysis = {
    "malicious_samples": len(malicious_features),
    "benign_samples": len(benign_features),
    "malicious_avg_entropy": mal_avg_entropy if malicious_features else 0,
    "benign_avg_entropy": ben_avg_entropy if benign_features else 0,
    "malicious_avg_suspicious": mal_avg_suspicious if malicious_features else 0,
    "benign_avg_suspicious": ben_avg_suspicious if benign_features else 0
}

Path("malware_testing/reports/analysis.json").write_text(json.dumps(analysis, indent=2))
print(f"\n✅ Analysis saved to: malware_testing/reports/analysis.json")
