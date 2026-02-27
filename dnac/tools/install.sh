#!/bin/bash
#
# DNAC Installation Script
# Installs dependencies, builds DNA Messenger and DNAC
#
# Usage: curl -sSL <url> | bash
#    or: ./install.sh
#

set -e

echo "=== DNAC Installation Script ==="
echo ""

# Detect OS
if [ -f /etc/debian_version ]; then
    PKG_MANAGER="apt"
elif [ -f /etc/redhat-release ]; then
    PKG_MANAGER="yum"
else
    echo "ERROR: Unsupported OS. Only Debian/Ubuntu and RHEL/CentOS supported."
    exit 1
fi

# Step 1: Install system dependencies
echo "[1/5] Installing system dependencies..."
if [ "$PKG_MANAGER" = "apt" ]; then
    sudo apt update
    sudo apt install -y build-essential cmake pkg-config libssl-dev libsqlite3-dev git
elif [ "$PKG_MANAGER" = "yum" ]; then
    sudo yum groupinstall -y "Development Tools"
    sudo yum install -y cmake3 openssl-devel sqlite-devel git
fi
echo "      Done."

# Step 2: Clone and build DNA Messenger (libdna)
echo "[2/5] Building DNA Messenger (libdna)..."
if [ -d /opt/dna-messenger ]; then
    echo "      /opt/dna-messenger exists, pulling latest..."
    cd /opt/dna-messenger
    git pull origin main || true
else
    sudo mkdir -p /opt/dna-messenger
    sudo chown $USER:$USER /opt/dna-messenger
    git clone https://github.com/nocdem/dna-messenger.git /opt/dna-messenger
fi

cd /opt/dna-messenger
if [ -d build ]; then
    rm -rf build
fi
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc)
echo "      Done. libdna built at /opt/dna-messenger/build/libdna_lib.so"

# Step 3: Clone and build DNAC
echo "[3/5] Building DNAC..."
if [ -d /opt/dnac ]; then
    echo "      /opt/dnac exists, pulling latest..."
    cd /opt/dnac
    git pull origin main || true
else
    sudo mkdir -p /opt/dnac
    sudo chown $USER:$USER /opt/dnac
    git clone https://github.com/nocdem/dnac.git /opt/dnac
fi

cd /opt/dnac
if [ -d build ]; then
    rm -rf build
fi
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc)
echo "      Done. DNAC built at /opt/dnac/build/"

# Step 4: Create DNA identity (if not exists)
echo "[4/5] Checking DNA identity..."
if [ -d ~/.dna/keys ]; then
    echo "      DNA identity already exists at ~/.dna/"
else
    echo "      Creating new DNA identity..."
    cd /opt/dna-messenger/build
    ./dna-cli create "wallet-$(hostname)"
    echo "      Identity created."
fi

# Step 5: Verify installation
echo "[5/5] Verifying installation..."
cd /opt/dnac/build

echo ""
echo "=== DNAC Installation Complete ==="
echo ""
echo "Wallet Address:"
./dnac-cli address
echo ""
echo "Balance:"
./dnac-cli balance
echo ""
echo "Useful commands:"
echo "  dnac-cli info      - Show wallet info and DHT status"
echo "  dnac-cli balance   - Show wallet balance"
echo "  dnac-cli send <fp> <amount> - Send funds"
echo "  dnac-cli sync      - Sync incoming payments"
echo "  dnac-cli history   - Transaction history"
echo ""
echo "Binary location: /opt/dnac/build/dnac-cli"
