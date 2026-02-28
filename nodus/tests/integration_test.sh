#!/bin/bash
#
# Nodus v5 — Integration Test Suite
#
# Tests the 3-node test cluster (nodus-01, nodus-02, nodus-03).
# Run from any machine with SSH access to all 3 nodes.
#
# Usage: ./integration_test.sh
#

set -euo pipefail

# ── Node Configuration ──────────────────────────────────────────────
NODE1_IP="161.97.85.25"
NODE2_IP="156.67.24.125"
NODE3_IP="156.67.25.251"
PORT=4001

PASS=0
FAIL=0
SKIP=0

# ── Helpers ─────────────────────────────────────────────────────────

cli() {
    local ip="$1"; shift
    ssh -o ConnectTimeout=5 "root@${ip}" "nodus-cli -s 127.0.0.1 -p ${PORT} $*" 2>&1
}

pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
}

skip() {
    echo "  SKIP: $1"
    SKIP=$((SKIP + 1))
}

section() {
    echo ""
    echo "=== $1 ==="
}

# ── Test 1: Bootstrap & Service Health ──────────────────────────────

section "Test 1: Bootstrap & Service Health"

for NODE_IP in "$NODE1_IP" "$NODE2_IP" "$NODE3_IP"; do
    STATUS=$(ssh -o ConnectTimeout=5 "root@${NODE_IP}" \
        'systemctl is-active nodus-v5' 2>&1 || true)
    if [ "$STATUS" = "active" ]; then
        pass "nodus-v5 active on ${NODE_IP}"
    else
        fail "nodus-v5 not active on ${NODE_IP} (status: ${STATUS})"
    fi
done

# ── Test 2: Local Ping ──────────────────────────────────────────────

section "Test 2: Local Ping"

for NODE_IP in "$NODE1_IP" "$NODE2_IP" "$NODE3_IP"; do
    RESULT=$(cli "$NODE_IP" ping)
    if echo "$RESULT" | grep -qi "pong"; then
        pass "ping on ${NODE_IP}"
    else
        fail "ping on ${NODE_IP}: ${RESULT}"
    fi
done

# ── Test 3: Local PUT/GET ───────────────────────────────────────────

section "Test 3: Local PUT/GET"

KEY="test3_local_$(date +%s)"
cli "$NODE1_IP" "put ${KEY} 'local_value_test'" > /dev/null
RESULT=$(cli "$NODE1_IP" "get ${KEY}")
if echo "$RESULT" | grep -q "local_value_test"; then
    pass "local PUT/GET on node1"
else
    fail "local PUT/GET on node1: ${RESULT}"
fi

# ── Test 4: PBFT Ring Formation ─────────────────────────────────────

section "Test 4: PBFT Ring Formation"

for NODE_IP in "$NODE1_IP" "$NODE2_IP" "$NODE3_IP"; do
    PEERS=$(ssh -o ConnectTimeout=5 "root@${NODE_IP}" \
        'journalctl -u nodus-v5 --no-pager -n 50 2>&1 | grep -c "PBFT: discovered real node_id"' 2>&1 || echo "0")
    if [ "$PEERS" -ge 2 ]; then
        pass "PBFT discovered 2 peers on ${NODE_IP}"
    elif [ "$PEERS" -ge 1 ]; then
        pass "PBFT discovered 1 peer on ${NODE_IP} (partial)"
    else
        fail "PBFT no peers discovered on ${NODE_IP}"
    fi
done

# ── Test 5: Cross-Node Replication (PUT on 1, GET from 2 and 3) ────

section "Test 5: Cross-Node Replication"

KEY="test5_repl_$(date +%s)"
VALUE="replicated_value_$(date +%s)"

cli "$NODE1_IP" "put ${KEY} '${VALUE}'" > /dev/null
sleep 1  # Allow replication to complete

RESULT2=$(cli "$NODE2_IP" "get ${KEY}")
RESULT3=$(cli "$NODE3_IP" "get ${KEY}")

if echo "$RESULT2" | grep -q "${VALUE}"; then
    pass "value replicated to node2"
else
    fail "value NOT on node2: ${RESULT2}"
fi

if echo "$RESULT3" | grep -q "${VALUE}"; then
    pass "value replicated to node3"
else
    fail "value NOT on node3: ${RESULT3}"
fi

# ── Test 6: Bi-directional Replication ──────────────────────────────

section "Test 6: Bi-directional Replication"

KEY2="test6_from2_$(date +%s)"
KEY3="test6_from3_$(date +%s)"

cli "$NODE2_IP" "put ${KEY2} 'from_node2'" > /dev/null
cli "$NODE3_IP" "put ${KEY3} 'from_node3'" > /dev/null
sleep 1

R1_K2=$(cli "$NODE1_IP" "get ${KEY2}")
R1_K3=$(cli "$NODE1_IP" "get ${KEY3}")
R3_K2=$(cli "$NODE3_IP" "get ${KEY2}")
R2_K3=$(cli "$NODE2_IP" "get ${KEY3}")

if echo "$R1_K2" | grep -q "from_node2"; then
    pass "node2->node1 replication"
else
    fail "node2->node1 replication: ${R1_K2}"
fi

if echo "$R1_K3" | grep -q "from_node3"; then
    pass "node3->node1 replication"
else
    fail "node3->node1 replication: ${R1_K3}"
fi

if echo "$R3_K2" | grep -q "from_node2"; then
    pass "node2->node3 replication"
else
    fail "node2->node3 replication: ${R3_K2}"
fi

if echo "$R2_K3" | grep -q "from_node3"; then
    pass "node3->node2 replication"
else
    fail "node3->node2 replication: ${R2_K3}"
fi

# ── Test 7: Multi-Writer (same key, different nodes) ────────────────

section "Test 7: Multi-Writer (same key)"

KEY="test7_multiwriter_$(date +%s)"
cli "$NODE1_IP" "put ${KEY} 'version_1'" > /dev/null
sleep 1
cli "$NODE2_IP" "put ${KEY} 'version_2'" > /dev/null
sleep 1

# The latest write should win (or at least one version should be readable)
RESULT=$(cli "$NODE1_IP" "get ${KEY}")
if echo "$RESULT" | grep -q "version_"; then
    pass "multi-writer key readable on node1"
else
    fail "multi-writer key not readable: ${RESULT}"
fi

# ── Test 8: Large Value ─────────────────────────────────────────────

section "Test 8: Large Value (4KB)"

KEY="test8_large_$(date +%s)"
LARGE_VALUE=$(head -c 4096 /dev/urandom | base64 | head -c 4096)

cli "$NODE1_IP" "put ${KEY} '${LARGE_VALUE}'" > /dev/null 2>&1
RESULT=$(cli "$NODE1_IP" "get ${KEY}" 2>&1)

if echo "$RESULT" | grep -q "Value:"; then
    pass "large value (4KB) stored and retrieved"
else
    fail "large value store/retrieve: ${RESULT}"
fi

# ── Test 9: Failover (kill one node, verify others still work) ──────

section "Test 9: Failover"

KEY="test9_prefailover_$(date +%s)"
cli "$NODE1_IP" "put ${KEY} 'before_failover'" > /dev/null
sleep 1

# Stop node3
ssh -o ConnectTimeout=5 "root@${NODE3_IP}" 'systemctl stop nodus-v5' 2>/dev/null

sleep 2

# Verify node1 and node2 still work
RESULT1=$(cli "$NODE1_IP" "get ${KEY}")
RESULT2=$(cli "$NODE2_IP" "get ${KEY}")

if echo "$RESULT1" | grep -q "before_failover"; then
    pass "node1 still serves after node3 down"
else
    fail "node1 failed after node3 down: ${RESULT1}"
fi

if echo "$RESULT2" | grep -q "before_failover"; then
    pass "node2 still serves after node3 down"
else
    fail "node2 failed after node3 down: ${RESULT2}"
fi

# PUT while node3 is down
KEY_DURING="test9_during_$(date +%s)"
cli "$NODE1_IP" "put ${KEY_DURING} 'during_failover'" > /dev/null
sleep 1

RESULT_DURING=$(cli "$NODE2_IP" "get ${KEY_DURING}")
if echo "$RESULT_DURING" | grep -q "during_failover"; then
    pass "replication works with 2 nodes"
else
    fail "replication with 2 nodes: ${RESULT_DURING}"
fi

# ── Test 10: Rejoin ─────────────────────────────────────────────────

section "Test 10: Rejoin"

# Restart node3
ssh -o ConnectTimeout=5 "root@${NODE3_IP}" 'systemctl start nodus-v5' 2>/dev/null
sleep 15  # Wait for PBFT rediscovery

PING3=$(cli "$NODE3_IP" ping)
if echo "$PING3" | grep -qi "pong"; then
    pass "node3 rejoined cluster"
else
    fail "node3 rejoin failed: ${PING3}"
fi

# New PUT should replicate to all 3 again
KEY_AFTER="test10_after_$(date +%s)"
cli "$NODE1_IP" "put ${KEY_AFTER} 'after_rejoin'" > /dev/null
sleep 1

RESULT_AFTER=$(cli "$NODE3_IP" "get ${KEY_AFTER}")
if echo "$RESULT_AFTER" | grep -q "after_rejoin"; then
    pass "replication restored after rejoin"
else
    fail "replication after rejoin: ${RESULT_AFTER}"
fi

# ── Summary ─────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo "  RESULTS: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
