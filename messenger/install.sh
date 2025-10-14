#!/bin/bash
#
# DNA Messenger - Clean Install Script
# Pulls latest code and rebuilds from scratch
#

set -e

echo ""
echo "========================================="
echo " DNA Messenger - Clean Install"
echo "========================================="
echo ""

# Check if we're in the repository
if [ ! -d ".git" ]; then
    echo "❌ Not in a git repository"
    echo "Run this script from the dna-messenger directory"
    exit 1
fi

# Pull latest code
echo "📥 Pulling latest code from GitHub..."
git fetch origin
git reset --hard origin/main
echo "✓ Code updated"
echo ""

# Clean build directory
echo "🧹 Cleaning old build..."
rm -rf build
mkdir build
cd build
echo "✓ Build directory cleaned"
echo ""

# Build
echo "🔨 Building DNA Messenger..."
cmake ..
make -j$(nproc)

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Build successful!"
    echo ""
    echo "========================================="
    echo " Installation Complete"
    echo "========================================="
    echo ""
    echo "Binary: $(pwd)/dna_messenger"
    echo ""
    echo "To run:"
    echo "  ./dna_messenger"
    echo ""
else
    echo ""
    echo "❌ Build failed"
    exit 1
fi
