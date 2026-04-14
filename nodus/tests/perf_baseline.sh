#!/bin/bash
#
# Performance baseline capture for the multi-tx block refactor.
#
# Captures latency, IOPS, RSS, and Merkle compute count from a running
# cluster. Run once against v0.11.10 (pre-refactor) and once against the
# new code at Phase 15.3 go/no-go. Phase 15.3 fails on any regression
# > 5 % vs the pre-refactor baseline saved in
# docs/plans/perf_baseline_v0.11.10.txt.
#
# Usage:
#     ./perf_baseline.sh nodus1:4001 nodus2:4001 nodus3:4001 [...]
#
# Output goes to stdout; redirect into a baseline file:
#     ./perf_baseline.sh ... > docs/plans/perf_baseline_v0.11.10.txt

set -e

CLUSTER="$@"
if [ -z "$CLUSTER" ]; then
    echo "usage: perf_baseline.sh <addr:port> [<addr:port> ...]" >&2
    exit 1
fi

NODUS_CLI="${NODUS_CLI:-nodus/build/nodus-cli}"
DNA_CLI="${DNA_CLI:-messenger/build/cli/dna-connect-cli}"

NUM_SPENDS="${PERF_SPENDS:-100}"

echo "# perf_baseline capture $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# cluster: $CLUSTER"
echo "# spend count: $NUM_SPENDS"
echo

# ── Latency: 100 SPEND p50/p95/p99 ────────────────────────────────────
echo "## latency (ms) over $NUM_SPENDS spends"
LATENCIES=$(mktemp)
trap 'rm -f $LATENCIES' EXIT

for i in $(seq 1 "$NUM_SPENDS"); do
    T_START=$(date +%s%N)
    "$DNA_CLI" dna spend \
        --sender chip+punk \
        --recipient nocdem \
        --amount 1 > /dev/null 2>&1
    T_END=$(date +%s%N)
    echo $(( (T_END - T_START) / 1000000 )) >> "$LATENCIES"
done

sort -n "$LATENCIES" -o "$LATENCIES"
COUNT=$(wc -l < "$LATENCIES")
P50_IDX=$((COUNT / 2))
P95_IDX=$((COUNT * 95 / 100))
P99_IDX=$((COUNT * 99 / 100))
P50=$(sed -n "${P50_IDX}p" "$LATENCIES")
P95=$(sed -n "${P95_IDX}p" "$LATENCIES")
P99=$(sed -n "${P99_IDX}p" "$LATENCIES")
echo "p50=$P50"
echo "p95=$P95"
echo "p99=$P99"
echo

# ── IOPS during a 10-TX burst ─────────────────────────────────────────
echo "## iops (during 10-tx burst)"
if command -v iostat > /dev/null 2>&1; then
    iostat -x 1 11 > /tmp/iostat.log 2>&1 &
    IOSTAT_PID=$!
    sleep 1  # warmup
    for i in $(seq 1 10); do
        "$DNA_CLI" dna spend --sender chip+punk --recipient nocdem --amount 1 > /dev/null 2>&1 &
    done
    wait
    sleep 1
    kill $IOSTAT_PID 2>/dev/null || true
    grep -E '^[a-z]+[0-9]' /tmp/iostat.log \
        | awk '{print $1, "r/s="$4, "w/s="$5}' \
        | sort -u
else
    echo "iostat not installed — skipped"
fi
echo

# ── RSS per witness ───────────────────────────────────────────────────
echo "## witness rss (KB)"
"$NODUS_CLI" cluster-status $CLUSTER \
    | grep -oE 'addr=[^ ]+ .*rss_kb=[0-9]+' \
    || echo "(cluster-status format change — re-run with updated parser)"
echo

# ── Merkle compute count ──────────────────────────────────────────────
echo "## merkle compute count (per round, last 10 rounds)"
echo "# parsed from journalctl on each node — manual capture step"
echo "# template: ssh \$NODE 'journalctl -u nodus -n 1000' | grep -c 'state_root computed'"
echo

echo "# perf_baseline complete"
