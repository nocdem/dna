#!/bin/bash
# DNA Nodus Build Script
# Pulls latest code and builds dna-nodus for headless servers

set -e  # Exit on error

echo "=== DNA Nodus Build Script ==="
echo ""

# Change to project directory
cd /opt/dna-messenger

# Pull latest code
echo "Pulling latest code..."
git pull
echo ""

# Get current commit
COMMIT=$(git log --oneline -1)
echo "Current commit: $COMMIT"
echo ""

# Clean and create build directory
echo "Cleaning build directory..."
rm -rf build
mkdir build
cd build
echo ""

# Configure with CMake (GUI disabled for headless server)
echo "Configuring with CMake..."
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=OFF ..
echo ""

# Build dht_lib first (dependency)
echo "Building dht_lib..."
make -j$(nproc) dht_lib
echo ""

# Build dna-nodus
echo "Building dna-nodus..."
make -j$(nproc) dna-nodus
echo ""

# Verify binary
if [ -f vendor/opendht-pq/tools/dna-nodus ]; then
    SIZE=$(ls -lh vendor/opendht-pq/tools/dna-nodus | awk '{print $5}')
    echo "✓ Build SUCCESS"
    echo "Binary: /opt/dna-messenger/build/vendor/opendht-pq/tools/dna-nodus ($SIZE)"
else
    echo "✗ Build FAILED - Binary not found"
    exit 1
fi
