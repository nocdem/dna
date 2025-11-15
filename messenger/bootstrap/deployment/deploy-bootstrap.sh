#!/bin/bash
# Complete Bootstrap Node Deployment Script
# Builds binary, uploads to VPS, configures systemd service
# Usage: ./deploy-bootstrap.sh <hostname> <ip_address>

set -e

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <hostname> <ip_address>"
    echo ""
    echo "Example: $0 dna-bootstrap-us-1 154.38.182.161"
    echo ""
    echo "Available bootstrap nodes:"
    echo "  dna-bootstrap-us-1  154.38.182.161"
    echo "  dna-bootstrap-eu-1  164.68.105.227"
    echo "  dna-bootstrap-eu-2  164.68.116.180"
    exit 1
fi

HOSTNAME=$1
IP_ADDRESS=$2
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"

echo "============================================"
echo "DNA DHT Bootstrap Node Deployment"
echo "============================================"
echo "Hostname:        $HOSTNAME"
echo "IP Address:      $IP_ADDRESS"
echo "Project Root:    $PROJECT_ROOT"
echo "Build Directory: $BUILD_DIR"
echo "============================================"
echo ""

# Step 1: Build the binary locally
echo "[1/8] Building persistent_bootstrap binary..."
cd "$PROJECT_ROOT"

if [ ! -d "$BUILD_DIR" ]; then
    echo "Creating build directory..."
    mkdir -p "$BUILD_DIR"
fi

cd "$BUILD_DIR"

if [ ! -f "Makefile" ]; then
    echo "Running CMake configuration..."
    cmake ..
fi

echo "Compiling persistent_bootstrap..."
make persistent_bootstrap -j$(nproc)

if [ ! -f "$BUILD_DIR/dht/persistent_bootstrap" ]; then
    echo "ERROR: Build failed - persistent_bootstrap not found"
    exit 1
fi

echo "✓ Build successful"
echo "  Binary: $BUILD_DIR/dht/persistent_bootstrap"
echo "  Size: $(du -h $BUILD_DIR/dht/persistent_bootstrap | cut -f1)"
echo ""

# Step 2: Check SSH connectivity
echo "[2/8] Testing SSH connectivity..."
if ! ssh -o ConnectTimeout=5 root@$IP_ADDRESS "echo 'SSH connection successful'" > /dev/null 2>&1; then
    echo "ERROR: Cannot connect to root@$IP_ADDRESS via SSH"
    echo "Please ensure:"
    echo "  1. SSH key is configured (ssh-copy-id root@$IP_ADDRESS)"
    echo "  2. Server is reachable"
    echo "  3. Root login is enabled"
    exit 1
fi
echo "✓ SSH connectivity verified"
echo ""

# Step 3: Set hostname
echo "[3/8] Setting hostname to $HOSTNAME..."
ssh root@$IP_ADDRESS "hostnamectl set-hostname $HOSTNAME && echo $HOSTNAME > /etc/hostname"
ssh root@$IP_ADDRESS "grep -q '$HOSTNAME' /etc/hosts || echo '127.0.1.1 $HOSTNAME' >> /etc/hosts"
echo "✓ Hostname configured"
echo ""

# Step 4: Install dependencies
echo "[4/8] Installing dependencies..."
ssh root@$IP_ADDRESS "apt-get update -qq && apt-get install -y -qq libopendht-dev libsqlite3-dev > /dev/null 2>&1 || true"
echo "✓ Dependencies checked"
echo ""

# Step 5: Stop any running DHT processes
echo "[5/8] Stopping any running DHT processes..."
ssh root@$IP_ADDRESS "systemctl stop dna-dht-bootstrap.service 2>/dev/null || true"
ssh root@$IP_ADDRESS "pkill -9 persistent_bootstrap 2>/dev/null || true"
echo "✓ Previous processes stopped"
echo ""

# Step 6: Create deployment directory and upload binary
echo "[6/8] Uploading binary to /opt/dna-messenger/dht/build/..."
ssh root@$IP_ADDRESS "mkdir -p /opt/dna-messenger/dht/build"
scp "$BUILD_DIR/dht/persistent_bootstrap" "root@$IP_ADDRESS:/opt/dna-messenger/dht/build/"
ssh root@$IP_ADDRESS "chmod +x /opt/dna-messenger/dht/build/persistent_bootstrap"
echo "✓ Binary deployed"
echo ""

# Step 7: Deploy systemd service
echo "[7/8] Deploying systemd service..."
scp "$SCRIPT_DIR/dna-dht-bootstrap.service" "root@$IP_ADDRESS:/etc/systemd/system/"
ssh root@$IP_ADDRESS "systemctl daemon-reload"
ssh root@$IP_ADDRESS "systemctl enable dna-dht-bootstrap.service"
echo "✓ Systemd service configured"
echo ""

# Step 8: Start service and verify
echo "[8/8] Starting DHT bootstrap service..."
ssh root@$IP_ADDRESS "systemctl start dna-dht-bootstrap.service"
sleep 3

# Check service status
if ssh root@$IP_ADDRESS "systemctl is-active --quiet dna-dht-bootstrap.service"; then
    echo "✓ Service is running"
else
    echo "⚠ Service failed to start - checking logs:"
    ssh root@$IP_ADDRESS "systemctl status dna-dht-bootstrap.service --no-pager | tail -20"
    exit 1
fi

echo ""
echo "============================================"
echo "✅ Deployment Complete!"
echo "============================================"
echo "Hostname:        $HOSTNAME"
echo "IP Address:      $IP_ADDRESS"
echo "Service:         dna-dht-bootstrap.service"
echo "Status:          RUNNING"
echo "DHT Port:        4000 (UDP)"
echo ""
echo "Useful commands:"
echo "  Check status:  ssh root@$IP_ADDRESS 'systemctl status dna-dht-bootstrap'"
echo "  View logs:     ssh root@$IP_ADDRESS 'journalctl -u dna-dht-bootstrap -f'"
echo "  Restart:       ssh root@$IP_ADDRESS 'systemctl restart dna-dht-bootstrap'"
echo "  Stop:          ssh root@$IP_ADDRESS 'systemctl stop dna-dht-bootstrap'"
echo ""
echo "Monitor DHT network:"
echo "  ./monitor-bootstrap.sh $IP_ADDRESS"
echo ""
