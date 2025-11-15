#!/bin/bash
# Deploy corrected double-hash fix to all 3 bootstrap nodes

NODES=(
    "154.38.182.161"
    "164.68.105.227"
    "164.68.116.180"
)

echo "=== Deploying and building on all nodes ==="

# Build on each node
for ip in "${NODES[@]}"; do
    echo "[$ip] Building..."
    ssh root@$ip "cd /opt/dna-messenger/build && make -j4 2>&1 | tail -5"
    if [ $? -eq 0 ]; then
        echo "[$ip] ✓ Build complete"
    else
        echo "[$ip] ✗ Build failed"
        exit 1
    fi
done

echo ""
echo "=== Killing old processes ==="
for ip in "${NODES[@]}"; do
    ssh root@$ip "pkill -9 -f persistent_bootstrap"
    echo "[$ip] ✓ Killed"
done

sleep 2

echo ""
echo "=== Restarting all nodes simultaneously ==="
for ip in "${NODES[@]}"; do
    ssh root@$ip "cd /opt/dna-messenger/build/dht && nohup ./persistent_bootstrap 4000 /var/lib/dna-dht/bootstrap.state.values.db &> /tmp/bootstrap.log &" &
done

wait

sleep 3

echo ""
echo "=== Verification ==="
for ip in "${NODES[@]}"; do
    echo "[$ip]:"
    ssh root@$ip "ps aux | grep 'persistent_bootstrap 4000' | grep -v grep"
done

echo ""
echo "=== Checking republish logs (wait 10 sec) ==="
sleep 10

for ip in "${NODES[@]}"; do
    echo "[$ip]:"
    ssh root@$ip "grep -c 'Skipping old-format entry (80-char hex)' /tmp/bootstrap.log"
    ssh root@$ip "grep 'Republish complete' /tmp/bootstrap.log | tail -1"
    echo ""
done

echo "✓ Deployment complete"
