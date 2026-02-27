#!/bin/bash

# CPUNK Network Installation Script for Linux
# This script installs the CPUNK network configuration for Cellframe node

set -e

echo "============================================"
echo "CPUNK Network Installation Script for Linux"
echo "============================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
   echo "Please run as root (use sudo)"
   exit 1
fi

# Check if cellframe-node is installed
if [ ! -d "/opt/cellframe-node" ]; then
    echo "Cellframe node not found. Installing..."
    
    # Detect distribution
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu
        echo "Detected Debian/Ubuntu system"
        wget -qO- https://debian.pub.demlabs.net/public.key | apt-key add -
        echo "deb https://debian.pub.demlabs.net/5.2-stable $(lsb_release -cs) main" > /etc/apt/sources.list.d/cellframe.list
        apt-get update
        apt-get install -y cellframe-node
    elif [ -f /etc/redhat-release ]; then
        # RHEL/CentOS/Fedora
        echo "Detected RedHat-based system"
        rpm --import https://centos.pub.demlabs.net/public.key
        cat > /etc/yum.repos.d/cellframe.repo << EOF
[cellframe]
name=Cellframe repository
baseurl=https://centos.pub.demlabs.net/5.2-stable/
enabled=1
gpgcheck=1
gpgkey=https://centos.pub.demlabs.net/public.key
EOF
        yum install -y cellframe-node
    else
        echo "Unsupported distribution. Please install Cellframe node manually."
        exit 1
    fi
fi

echo "Cellframe node found. Installing CPUNK network..."

# Create directories
mkdir -p /opt/cellframe-node/etc/network/Cpunk
mkdir -p /opt/cellframe-node/share/ca

# Download configuration files
echo "Downloading configuration files..."
wget -q https://cpunk.club/configs/Cpunk.cfg -O /opt/cellframe-node/etc/network/Cpunk.cfg
wget -q https://cpunk.club/configs/chain-0.cfg -O /opt/cellframe-node/etc/network/Cpunk/chain-0.cfg
wget -q https://cpunk.club/configs/main.cfg -O /opt/cellframe-node/etc/network/Cpunk/main.cfg

# Download certificates
echo "Downloading certificates..."
for i in 0 1 2; do
    wget -q https://cpunk.club/certs/cpunk.root.$i.dcert -O /opt/cellframe-node/share/ca/cpunk.root.$i.dcert
    wget -q https://cpunk.club/certs/cpunk.master.$i.dcert -O /opt/cellframe-node/share/ca/cpunk.master.$i.dcert
done

# Set proper permissions (check if cellframe-node user exists)
if id "cellframe-node" &>/dev/null; then
    chown -R cellframe-node:cellframe-node /opt/cellframe-node/etc/network/Cpunk
    chown cellframe-node:cellframe-node /opt/cellframe-node/share/ca/cpunk.*
else
    # Just ensure files are readable
    chmod -R 644 /opt/cellframe-node/etc/network/Cpunk/*
    chmod 644 /opt/cellframe-node/share/ca/cpunk.*
fi

# Restart the node
echo "Restarting Cellframe node..."
systemctl restart cellframe-node

# Wait for node to start
sleep 5

# Verify installation
echo ""
echo "Verifying installation..."
if /opt/cellframe-node/bin/cellframe-node-cli net list | grep -q "Cpunk"; then
    echo ""
    echo "✅ SUCCESS! CPUNK network has been installed."
    echo ""
    echo "You can now use the following commands:"
    echo "  - Check network status: /opt/cellframe-node/bin/cellframe-node-cli net get status -net Cpunk"
    echo "  - Get sync status: /opt/cellframe-node/bin/cellframe-node-cli net get sync_status -net Cpunk"
    echo ""
else
    echo ""
    echo "⚠️  WARNING: CPUNK network not found in network list."
    echo "Please check the logs: journalctl -u cellframe-node -n 50"
    echo ""
fi

echo "Installation complete!"