#!/bin/bash
#
# Post-deploy smoke test for the multi-tx block refactor (Phase 15.6).
#
# Runs a minimal end-to-end verification against a freshly-deployed Nodus
# cluster: cluster-status sanity check, then a canonical chip+punk -> nocdem
# SPEND, then a height re-check to confirm the block landed.
#
# Usage:
#     ./smoke_post_deploy.sh nodus1:4001 nodus2:4001 nodus3:4001 [...]
#
# Exits non-zero on the first failure.

set -e

CLUSTER="$@"
if [ -z "$CLUSTER" ]; then
    echo "usage: smoke_post_deploy.sh <addr:port> [<addr:port> ...]" >&2
    exit 1
fi

NODUS_CLI="${NODUS_CLI:-nodus/build/nodus-cli}"
DNA_CLI="${DNA_CLI:-messenger/build/cli/dna-connect-cli}"

if [ ! -x "$NODUS_CLI" ]; then
    echo "smoke: nodus-cli not found at $NODUS_CLI (set NODUS_CLI=...)" >&2
    exit 1
fi
if [ ! -x "$DNA_CLI" ]; then
    echo "smoke: dna-connect-cli not found at $DNA_CLI (set DNA_CLI=...)" >&2
    exit 1
fi

echo "1. Cluster status — initial..."
"$NODUS_CLI" cluster-status $CLUSTER

INITIAL_HEIGHT=$("$NODUS_CLI" cluster-status $CLUSTER \
    | grep -oE 'block_height=[0-9]+' \
    | head -1 \
    | cut -d= -f2)

if [ -z "$INITIAL_HEIGHT" ]; then
    echo "smoke: FAIL — could not parse initial block_height from cluster-status" >&2
    exit 1
fi
echo "   initial height: $INITIAL_HEIGHT"

echo "2. Canonical SPEND: chip+punk -> nocdem (1000 DNAC)..."
"$DNA_CLI" dna spend \
    --sender chip+punk \
    --recipient nocdem \
    --amount 1000

echo "3. Cluster status — post-spend..."
sleep 5  # one block production interval
NEW_HEIGHT=$("$NODUS_CLI" cluster-status $CLUSTER \
    | grep -oE 'block_height=[0-9]+' \
    | head -1 \
    | cut -d= -f2)

echo "   new height: $NEW_HEIGHT"

if [ -z "$NEW_HEIGHT" ] || [ "$NEW_HEIGHT" -le "$INITIAL_HEIGHT" ]; then
    echo "smoke: FAIL — block height did not advance ($INITIAL_HEIGHT -> $NEW_HEIGHT)" >&2
    exit 1
fi

echo "smoke: PASS — block_height advanced $INITIAL_HEIGHT -> $NEW_HEIGHT"
