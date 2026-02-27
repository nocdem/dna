#!/bin/bash

# CPUNK Network Installation Script for macOS
# This script installs the CPUNK network configuration for Cellframe node

set -e

echo "============================================"
echo "CPUNK Network Installation Script for macOS"
echo "============================================"
echo ""

# Check if Cellframe node is installed
if [ ! -d "/Applications/CellframeNode.app" ] && [ ! -d "/opt/cellframe-node" ]; then
    echo "Cellframe node not found. Installing..."
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo "Homebrew not found. Installing Homebrew first..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    # Install using Homebrew
    echo "Installing Cellframe node via Homebrew..."
    brew tap cellframe/cellframe
    brew install cellframe-node
    
    # Start the service
    brew services start cellframe-node
fi

# Determine installation path
if [ -d "/opt/cellframe-node" ]; then
    CELLFRAME_PATH="/opt/cellframe-node"
elif [ -d "$HOME/Library/Application Support/CellframeNode" ]; then
    CELLFRAME_PATH="$HOME/Library/Application Support/CellframeNode"
else
    echo "Could not determine Cellframe installation path"
    exit 1
fi

echo "Cellframe node found at $CELLFRAME_PATH. Installing CPUNK network..."

# Create directories
mkdir -p "$CELLFRAME_PATH/etc/network/Cpunk"
mkdir -p "$CELLFRAME_PATH/share/ca"

# Download configuration files
echo "Downloading configuration files..."
curl -fsSL https://cpunk.club/configs/Cpunk.cfg -o "$CELLFRAME_PATH/etc/network/Cpunk.cfg"
curl -fsSL https://cpunk.club/configs/chain-0.cfg -o "$CELLFRAME_PATH/etc/network/Cpunk/chain-0.cfg"
curl -fsSL https://cpunk.club/configs/main.cfg -o "$CELLFRAME_PATH/etc/network/Cpunk/main.cfg"

# Download certificates
echo "Downloading certificates..."
for i in 0 1 2; do
    curl -fsSL https://cpunk.club/certs/cpunk.root.$i.dcert -o "$CELLFRAME_PATH/share/ca/cpunk.root.$i.dcert"
    curl -fsSL https://cpunk.club/certs/cpunk.master.$i.dcert -o "$CELLFRAME_PATH/share/ca/cpunk.master.$i.dcert"
done

# Restart the node
echo "Restarting Cellframe node..."
if command -v brew &> /dev/null && brew services list | grep -q cellframe-node; then
    brew services restart cellframe-node
else
    # Try to restart using launchctl if installed as app
    if [ -f ~/Library/LaunchAgents/com.cellframe.node.plist ]; then
        launchctl unload ~/Library/LaunchAgents/com.cellframe.node.plist
        launchctl load ~/Library/LaunchAgents/com.cellframe.node.plist
    else
        echo "Please restart Cellframe node manually"
    fi
fi

# Wait for node to start
sleep 5

# Find CLI path
if [ -f "/opt/cellframe-node/bin/cellframe-node-cli" ]; then
    CLI_PATH="/opt/cellframe-node/bin/cellframe-node-cli"
elif [ -f "/usr/local/bin/cellframe-node-cli" ]; then
    CLI_PATH="/usr/local/bin/cellframe-node-cli"
else
    CLI_PATH="cellframe-node-cli"
fi

# Verify installation
echo ""
echo "Verifying installation..."
if $CLI_PATH net list | grep -q "Cpunk"; then
    echo ""
    echo "✅ SUCCESS! CPUNK network has been installed."
    echo ""
    echo "You can now use the following commands:"
    echo "  - Check network status: $CLI_PATH net get status -net Cpunk"
    echo "  - Get sync status: $CLI_PATH net get sync_status -net Cpunk"
    echo ""
else
    echo ""
    echo "⚠️  WARNING: CPUNK network not found in network list."
    echo "Please restart Cellframe node and check again."
    echo ""
fi

echo "Installation complete!"