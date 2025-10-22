#!/bin/bash
#
# DNA Messenger - Clean Install Script
# Installs dependencies, pulls latest code, and builds from scratch
#

set -e

echo ""
echo "========================================="
echo " DNA Messenger - Clean Install"
echo "========================================="
echo ""

# Detect if we're in a git repo or need to clone
if [ ! -d ".git" ]; then
    echo "📦 Cloning DNA Messenger repository..."
    if [ -d "dna-messenger" ]; then
        echo "❌ Directory 'dna-messenger' already exists"
        echo "Please remove it first or run this script from inside the directory"
        exit 1
    fi
    git clone https://github.com/nocdem/dna-messenger.git
    cd dna-messenger
    echo "✓ Repository cloned"
    echo ""
else
    echo "📥 Pulling latest code from GitHub..."
    git fetch origin
    git reset --hard origin/main
    echo "✓ Code updated"
    echo ""
fi

# Install dependencies
echo "📦 Installing dependencies..."
if command -v apt-get &> /dev/null; then
    # Debian/Ubuntu
    echo "Detected Debian/Ubuntu system"
    sudo apt-get update
    sudo apt-get install -y git cmake gcc g++ libssl-dev libpq-dev libjson-c-dev qtbase5-dev qtbase5-dev-tools qtmultimedia5-dev
elif command -v dnf &> /dev/null; then
    # Fedora/RHEL
    echo "Detected Fedora/RHEL system"
    sudo dnf install -y git cmake gcc openssl-devel libpq-devel json-c-devel
elif command -v pacman &> /dev/null; then
    # Arch Linux
    echo "Detected Arch Linux system"
    sudo pacman -S --noconfirm git cmake gcc openssl postgresql-libs json-c
else
    echo "⚠️  Could not detect package manager"
    echo "Please install manually: git cmake gcc openssl libpq json-c"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi
echo "✓ Dependencies installed"
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
    echo "Binaries:"
    echo "  Messenger CLI: $(pwd)/dna_messenger"
    echo "  Messenger GUI: $(pwd)/gui/dna_messenger_gui"
    echo "  Token Sender:  $(pwd)/dna-send"
    echo "  cpunk Wallet:  $(pwd)/wallet-gui/cpunk-wallet-gui"
    echo ""
    echo "To run:"
    echo "  cd $(pwd)"
    echo "  ./dna_messenger                    # Messenger CLI"
    echo "  ./gui/dna_messenger_gui            # Messenger GUI"
    echo "  ./dna-send --help                  # Token sender CLI"
    echo "  ./wallet-gui/cpunk-wallet-gui      # cpunk Wallet GUI"
    echo ""
    echo "On first run, configure server (option 4):"
    echo "  - Server: ai.cpunk.io"
    echo ""
    echo "Features:"
    echo "  ✓ Post-quantum encryption (Dilithium3 + Kyber512)"
    echo "  ✓ BIP39 seed phrase key generation"
    echo "  ✓ End-to-end encrypted messaging"
    echo "  ✓ Message search & filtering"
    echo "  ✓ Conversation history"
    echo "  ✓ Cross-platform (Linux & Windows)"
    echo ""
else
    echo ""
    echo "❌ Build failed"
    exit 1
fi
