#!/bin/bash
# VPS Deployment Script for DNA DHT Bootstrap Nodes
# Usage: ./deploy-vps.sh <hostname> <ip_address>

set -e

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <hostname> <ip_address>"
    echo "Example: $0 dna-bootstrap-us-1 154.38.182.161"
    exit 1
fi

HOSTNAME=$1
IP_ADDRESS=$2

echo "============================================"
echo "Deploying DNA DHT Bootstrap to: $HOSTNAME ($IP_ADDRESS)"
echo "============================================"

# 1. Set hostname
echo "[1/5] Setting hostname to $HOSTNAME..."
ssh root@$IP_ADDRESS "hostnamectl set-hostname $HOSTNAME && echo $HOSTNAME > /etc/hostname"

# 2. Update /etc/hosts
echo "[2/5] Updating /etc/hosts..."
ssh root@$IP_ADDRESS "grep -q '$HOSTNAME' /etc/hosts || echo '127.0.1.1 $HOSTNAME' >> /etc/hosts"

# 3. Stop any running DHT processes
echo "[3/5] Stopping any running DHT processes..."
ssh root@$IP_ADDRESS "pkill -9 persistent_bootstrap || true"

# 4. Deploy systemd service
echo "[4/5] Deploying systemd service..."
scp /opt/dna-messenger/dht/dna-dht-bootstrap.service root@$IP_ADDRESS:/etc/systemd/system/
ssh root@$IP_ADDRESS "systemctl daemon-reload"

# 5. Enable and verify (don't start yet - will start after reboot)
echo "[5/5] Enabling systemd service..."
ssh root@$IP_ADDRESS "systemctl enable dna-dht-bootstrap.service"

echo ""
echo "✅ Deployment complete!"
echo ""
echo "Hostname:        $HOSTNAME"
echo "IP:              $IP_ADDRESS"
echo "Service:         ENABLED (will start on reboot)"
echo ""
echo "Ready for reboot."
