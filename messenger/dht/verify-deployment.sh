#!/bin/bash
# DHT Bootstrap Deployment Verification Script
# Checks all 3 bootstrap nodes status after double-hash bug fix

NODES=(
    "154.38.182.161|US"
    "164.68.105.227|EU-1"
    "164.68.116.180|EU-2"
)

echo "=== DHT Bootstrap Deployment Verification ==="
echo "Date: $(date)"
echo ""

for node in "${NODES[@]}"; do
    IFS='|' read -r ip name <<< "$node"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Bootstrap: $name ($ip)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Check process status
    echo "▸ Process Status:"
    ssh root@$ip "ps aux | grep 'persistent_bootstrap 4000' | grep -v grep" 2>&1 | awk '{print "  PID: "$2" | Started: "$9" | CPU: "$10}'

    # Check DHT port
    echo "▸ DHT Port (4000):"
    ssh root@$ip "ss -tulnp | grep 4000 | grep -v grep" 2>&1 | head -2 | sed 's/^/  /'

    # Check database
    echo "▸ Database:"
    ssh root@$ip "[ -f /root/.dna/persistence_path.values.db ] && echo '  EXISTS' || echo '  NOT CREATED YET (normal for fresh start)'" 2>&1

    # Check recent logs
    echo "▸ Recent Log Activity:"
    ssh root@$ip "tail -5 /tmp/bootstrap.log 2>&1 | sed 's/^/  /'" 2>&1 | head -5

    echo ""
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ Verification Complete"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
