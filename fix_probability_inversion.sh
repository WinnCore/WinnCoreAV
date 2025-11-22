#!/bin/bash
# Fix the actual probability inversion issue

cd av-ml-detector/src

# Find the line where MlDetection is created and invert the probability
sed -i 's/Ok(MlDetection::from_score(probability, self.threshold))/Ok(MlDetection::from_score(1.0 - probability, self.threshold)) \/\/ FIX: Model predictions inverted/' lib.rs

echo "✅ Applied probability inversion fix"
