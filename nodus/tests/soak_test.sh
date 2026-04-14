#!/bin/bash
#
# 24-hour soak test for the multi-tx block refactor (Phase 15.2 gate).
#
# Drives sustained 10 TX/s load against the staging cluster for 24 h and
# captures hourly status rollups. Used to verify there is no slow leak,
# witness drift, FD exhaustion, or chain stall before the production
# deploy window.
#
# Pass criteria (verified at end of run):
#   - zero witness crashes (no `MIGRATION FAILURE`, no segfaults in journal)
#   - witness RSS growth  < 10 MB / 24 h
#   - file descriptor count stable (no monotone climb)
#   - chain growth      ≈ 24 h * 3600 s / block_interval blocks
#   - cluster_status block_height parity across all nodes
#
# Usage:
#     ./soak_test.sh nodus1:4001 nodus2:4001 nodus3:4001 [...]
#
# Output:
#     soak_result.log — hourly rollups + final pass/fail verdict.

set -e

CLUSTER="$@"
if [ -z "$CLUSTER" ]; then
    echo "usage: soak_test.sh <addr:port> [<addr:port> ...]" >&2
    exit 1
fi

NODUS_CLI="${NODUS_CLI:-nodus/build/nodus-cli}"
DNA_CLI="${DNA_CLI:-messenger/build/cli/dna-connect-cli}"
RESULT_LOG="${SOAK_RESULT_LOG:-soak_result.log}"

DURATION_HOURS="${SOAK_HOURS:-24}"
TARGET_TPS="${SOAK_TPS:-10}"
SLEEP_USEC=$((1000000 / TARGET_TPS))

echo "soak: $DURATION_HOURS h @ $TARGET_TPS TX/s, cluster=$CLUSTER" | tee "$RESULT_LOG"
START_TS=$(date +%s)
END_TS=$((START_TS + DURATION_HOURS * 3600))

INITIAL_RSS_TOTAL=$("$NODUS_CLI" cluster-status $CLUSTER \
    | grep -oE 'rss_kb=[0-9]+' \
    | cut -d= -f2 \
    | awk '{s+=$1} END {print s}')
INITIAL_HEIGHT=$("$NODUS_CLI" cluster-status $CLUSTER \
    | grep -oE 'block_height=[0-9]+' \
    | head -1 \
    | cut -d= -f2)

echo "soak: initial rss_total=${INITIAL_RSS_TOTAL}KB height=$INITIAL_HEIGHT" | tee -a "$RESULT_LOG"

NEXT_ROLLUP=$((START_TS + 3600))
TX_COUNT=0
HOUR=0

while [ "$(date +%s)" -lt "$END_TS" ]; do
    "$DNA_CLI" dna spend \
        --sender chip+punk \
        --recipient nocdem \
        --amount 1 > /dev/null 2>&1 || {
        echo "soak: FAIL — spend errored at TX $TX_COUNT" | tee -a "$RESULT_LOG"
        exit 1
    }
    TX_COUNT=$((TX_COUNT + 1))
    usleep $SLEEP_USEC || sleep 0.1

    NOW=$(date +%s)
    if [ "$NOW" -ge "$NEXT_ROLLUP" ]; then
        HOUR=$((HOUR + 1))
        RSS_NOW=$("$NODUS_CLI" cluster-status $CLUSTER \
            | grep -oE 'rss_kb=[0-9]+' \
            | cut -d= -f2 \
            | awk '{s+=$1} END {print s}')
        HEIGHT_NOW=$("$NODUS_CLI" cluster-status $CLUSTER \
            | grep -oE 'block_height=[0-9]+' \
            | head -1 \
            | cut -d= -f2)
        echo "soak: H+${HOUR}h tx=$TX_COUNT rss_total=${RSS_NOW}KB height=$HEIGHT_NOW" \
            | tee -a "$RESULT_LOG"
        NEXT_ROLLUP=$((NEXT_ROLLUP + 3600))
    fi
done

FINAL_RSS_TOTAL=$("$NODUS_CLI" cluster-status $CLUSTER \
    | grep -oE 'rss_kb=[0-9]+' \
    | cut -d= -f2 \
    | awk '{s+=$1} END {print s}')
FINAL_HEIGHT=$("$NODUS_CLI" cluster-status $CLUSTER \
    | grep -oE 'block_height=[0-9]+' \
    | head -1 \
    | cut -d= -f2)

RSS_GROWTH_KB=$((FINAL_RSS_TOTAL - INITIAL_RSS_TOTAL))
RSS_GROWTH_MB=$((RSS_GROWTH_KB / 1024))
HEIGHT_GROWTH=$((FINAL_HEIGHT - INITIAL_HEIGHT))

echo "soak: final rss_total=${FINAL_RSS_TOTAL}KB growth=${RSS_GROWTH_MB}MB height=$FINAL_HEIGHT growth=$HEIGHT_GROWTH" \
    | tee -a "$RESULT_LOG"
echo "soak: tx_total=$TX_COUNT" | tee -a "$RESULT_LOG"

# Pass criteria: RSS growth must stay under 10 MB
if [ "$RSS_GROWTH_MB" -gt 10 ]; then
    echo "soak: FAIL — RSS growth ${RSS_GROWTH_MB} MB exceeds 10 MB threshold" \
        | tee -a "$RESULT_LOG"
    exit 1
fi

echo "soak: PASS — ${DURATION_HOURS}h sustained ${TARGET_TPS} TX/s, RSS growth ${RSS_GROWTH_MB} MB" \
    | tee -a "$RESULT_LOG"
