#!/bin/bash
echo "1️⃣ Project Structure"
tree -L 2 -I target
echo ""
read -p "Press Enter for next screenshot..."

echo "2️⃣ Build Success"
cargo build --release --all-features
echo ""
read -p "Press Enter for next screenshot..."

echo "3️⃣ Test Results"
cargo test --all-features
echo ""
read -p "Press Enter for next screenshot..."

echo "4️⃣ CLI Help"
cargo run --bin av-cli -- --help
echo ""
read -p "Press Enter for next screenshot..."

echo "5️⃣ Scan File"
cargo run --bin av-cli -- scan file test_samples/eicar.txt
echo ""
read -p "Press Enter for next screenshot..."

echo "6️⃣ Test Samples"
ls -lh test_samples/
echo ""
read -p "Press Enter for next screenshot..."

echo "7️⃣ Dependencies"
cargo tree --depth 2 -p av-cli
echo ""
read -p "Press Enter for next screenshot..."

echo "8️⃣ Binary Sizes"
ls -lh target/release/av-* 2>/dev/null || echo "Build with --release first"
echo ""

echo "✅ All screenshots ready for README!"
