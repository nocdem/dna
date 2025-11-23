#!/bin/bash
# DNA Nodus Deployment Script
# Deploys dna-nodus to VPS bootstrap nodes

set -e

# VPS nodes
NODES=(
    "154.38.182.161:dna-bootstrap-us-1"
    "164.68.105.227:dna-bootstrap-eu-1"
    "164.68.116.180:dna-bootstrap-eu-2"
)

# Build directory
BUILD_DIR="/opt/dna-messenger/vendor/opendht-pq/build"
BINARY="${BUILD_DIR}/tools/dna-nodus"

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "Error: dna-nodus binary not found at $BINARY"
    echo "Please build it first with: cd build && make dna-nodus"
    exit 1
fi

echo "=== DNA Nodus Deployment Script ==="
echo ""

# Create systemd service file
cat > /tmp/dna-nodus.service << 'EOF'
[Unit]
Description=DNA Nodus - Post-Quantum DHT Bootstrap Node
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/dna-nodus -v
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "Created systemd service file"
echo ""

# Function to deploy to a single node
deploy_node() {
    local ip=$1
    local name=$2

    echo "=== Deploying to $name ($ip) ==="

    # Stop existing service if running
    echo "Stopping existing service..."
    ssh root@$ip "systemctl stop dna-nodus || true" 2>/dev/null || true

    # Copy binary
    echo "Copying dna-nodus binary..."
    scp $BINARY root@$ip:/usr/local/bin/dna-nodus
    ssh root@$ip "chmod +x /usr/local/bin/dna-nodus"

    # Copy shared library
    echo "Copying libopendht.so..."
    scp ${BUILD_DIR}/libopendht.so root@$ip:/usr/local/lib/libopendht.so.3
    ssh root@$ip "ldconfig"

    # Copy systemd service
    echo "Installing systemd service..."
    scp /tmp/dna-nodus.service root@$ip:/etc/systemd/system/dna-nodus.service

    # Reload systemd and enable service
    echo "Enabling service..."
    ssh root@$ip "systemctl daemon-reload"
    ssh root@$ip "systemctl enable dna-nodus"

    echo "Deployment to $name complete"
    echo ""
}

# Deploy to all nodes
for node in "${NODES[@]}"; do
    ip="${node%%:*}"
    name="${node##*:}"
    deploy_node "$ip" "$name"
done

echo "=== Configuring Bootstrap Cross-Connection ==="
echo ""

# Update service files with bootstrap configuration
update_bootstrap() {
    local ip=$1
    local name=$2
    local bootstrap_ips=""

    # Build bootstrap string (all other nodes)
    for node in "${NODES[@]}"; do
        other_ip="${node%%:*}"
        if [ "$other_ip" != "$ip" ]; then
            if [ -z "$bootstrap_ips" ]; then
                bootstrap_ips="-b $other_ip:4000"
            else
                # Just use the first one
                break
            fi
        fi
    done

    echo "Configuring $name to bootstrap from: $bootstrap_ips"

    # Update service file with bootstrap
    ssh root@$ip "sed -i 's|ExecStart=/usr/local/bin/dna-nodus -v|ExecStart=/usr/local/bin/dna-nodus $bootstrap_ips -v|g' /etc/systemd/system/dna-nodus.service"
    ssh root@$ip "systemctl daemon-reload"
}

# First node doesn't need bootstrap (it starts standalone)
echo "Node 1 (${NODES[0]%%:*}) will start standalone"

# Other nodes bootstrap from first node
for i in 1 2; do
    node="${NODES[$i]}"
    ip="${node%%:*}"
    name="${node##*:}"
    update_bootstrap "$ip" "$name"
done

echo ""
echo "=== Starting Services ==="
echo ""

# Start services in sequence (first node first, then others)
for node in "${NODES[@]}"; do
    ip="${node%%:*}"
    name="${node##*:}"
    echo "Starting $name ($ip)..."
    ssh root@$ip "systemctl start dna-nodus"
    sleep 3
done

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Check status with:"
for node in "${NODES[@]}"; do
    ip="${node%%:*}"
    name="${node##*:}"
    echo "  ssh root@$ip 'systemctl status dna-nodus'"
done
echo ""
echo "View logs with:"
for node in "${NODES[@]}"; do
    ip="${node%%:*}"
    name="${node##*:}"
    echo "  ssh root@$ip 'journalctl -u dna-nodus -f'"
done
