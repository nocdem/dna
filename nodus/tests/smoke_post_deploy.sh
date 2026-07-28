#!/bin/bash
#
# Post-deploy smoke test for a Nodus cluster.
#
# REWRITTEN 2026-07-28. The previous version could not run at all and, had it
# run, could not have detected the failure a consensus deploy actually causes:
#   * it grepped cluster-status for `block_height=[0-9]+`, a token that output
#     has never contained (cluster-status prints a TABLE), so it aborted at its
#     own "could not parse" guard before doing anything;
#   * it called `dna spend --sender X --recipient Y --amount N` — no such verb
#     and no such flags (the real one is `dna send <fp> <amount>`, positional,
#     in RAW BASE UNITS, 10^8 per DNAC), so its "1000" meant 0.00001 DNAC;
#   * it took `head -1` of ONE node's height and asserted only that the height
#     advanced. Six nodes advancing while a seventh silently rejects every block
#     would have passed. That is exactly the divergence class the v0.18.17
#     fee-gate fix addresses.
#
# WHAT THIS CHECKS NOW
#   Phase 1 (always, no wallet required) — AGREEMENT:
#     every node UP, and every node reporting the SAME height AND the SAME
#     state_root. Height alone is liveness; agreement is correctness.
#   Phase 2 (opt-in, requires a funded wallet) — LIVENESS:
#     submit a real TX, then re-assert agreement at the NEW height.
#
# Usage:
#     ./nodus/tests/smoke_post_deploy.sh <addr:port> <addr:port> ...
#
#     SMOKE_SPEND_TO=<fingerprint> SMOKE_SPEND_AMOUNT=<raw-base-units> \
#         ./nodus/tests/smoke_post_deploy.sh <addr:port> ...
#
# Exits non-zero on the first failure. Prints `smoke: PASS` on success.

set -euo pipefail

# Resolve paths from the repo root, not the caller's cwd — the old version used
# bare relative paths and only worked when invoked from /opt/dna.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODUS_CLI="${NODUS_CLI:-$REPO_ROOT/nodus/build/nodus-cli}"
DNA_CLI="${DNA_CLI:-$REPO_ROOT/messenger/build/cli/dna-connect-cli}"

# How many times to re-sample while nodes are merely catching up. Heights that
# differ are NOT immediately fatal (a node can be one block behind mid-round);
# heights that are EQUAL with DIFFERENT state_roots are fatal at once.
SETTLE_TRIES="${SMOKE_SETTLE_TRIES:-10}"
SETTLE_SLEEP="${SMOKE_SETTLE_SLEEP:-3}"

if [ "$#" -lt 1 ]; then
    echo "usage: smoke_post_deploy.sh <addr:port> [<addr:port> ...]" >&2
    exit 1
fi
CLUSTER=( "$@" )

if [ ! -x "$NODUS_CLI" ]; then
    echo "smoke: FAIL — nodus-cli not found at $NODUS_CLI (set NODUS_CLI=...)" >&2
    exit 1
fi

# ── cluster-status parsing ────────────────────────────────────────────────
# Output columns (nodus/tools/nodus-cli.c:505-535):
#   ADDR  STATUS  HEIGHT  PEERS  UPTIME  DF%  WALL_CLOCK  STATE_ROOT
# A DOWN node prints only ADDR and STATUS, so $2 discriminates the row shape.
# STATE_ROOT is the first 8 bytes of the 64-byte root, hex, with a trailing
# "..." — enough to detect divergence (two distinct roots would have to collide
# on 64 bits), not enough to prove equality cryptographically.
#
# NOTE: cluster-status exits 1 when any node is DOWN, so it is called with `|| true`
# and the DOWN rows are inspected explicitly — otherwise `set -e` would abort here
# with no diagnosis.

sample_cluster() {
    "$NODUS_CLI" cluster-status "${CLUSTER[@]}" 2>/dev/null || true
}

# Returns 0 when every node is UP and all (height, state_root) agree.
# Returns 2 on same-height/different-root — a real divergence, never retried.
# Returns 1 on any other mismatch (down node, differing heights) — retryable.
check_agreement() {
    local out="$1"
    local down heights roots n_up uniq_h uniq_r

    down=$(echo "$out" | awk '$2=="DOWN" {print $1}')
    if [ -n "$down" ]; then
        echo "   DOWN: $(echo "$down" | tr '\n' ' ')"
        return 1
    fi

    heights=$(echo "$out" | awk '$2=="UP" {print $3}')
    roots=$(echo  "$out" | awk '$2=="UP" {print $8}')
    n_up=$(echo "$heights" | grep -c . || true)

    if [ "$n_up" -ne "${#CLUSTER[@]}" ]; then
        echo "   only $n_up/${#CLUSTER[@]} nodes reported UP"
        return 1
    fi

    uniq_h=$(echo "$heights" | sort -u | wc -l)
    uniq_r=$(echo "$roots"   | sort -u | wc -l)

    if [ "$uniq_h" -eq 1 ] && [ "$uniq_r" -eq 1 ]; then
        return 0
    fi

    if [ "$uniq_h" -eq 1 ] && [ "$uniq_r" -ne 1 ]; then
        # Same height, different roots. This is not a node catching up; it is
        # two nodes disagreeing about the same block. Fail immediately.
        echo "   *** SAME HEIGHT, DIFFERENT state_root — DIVERGENCE ***"
        echo "$out"
        return 2
    fi

    echo "   heights not yet equal ($(echo "$heights" | sort -u | tr '\n' ' '))"
    return 1
}

# Re-samples until agreement or the settle budget runs out.
await_agreement() {
    local label="$1" out rc i
    for (( i = 1; i <= SETTLE_TRIES; i++ )); do
        out="$(sample_cluster)"
        set +e; check_agreement "$out"; rc=$?; set -e
        case "$rc" in
            0) echo "   $label: 7/7 agree — height=$(echo "$out" | awk '$2=="UP"{print $3; exit}') state_root=$(echo "$out" | awk '$2=="UP"{print $8; exit}')"
               AGREED_HEIGHT="$(echo "$out" | awk '$2=="UP"{print $3; exit}')"
               return 0 ;;
            2) echo "smoke: FAIL — $label: nodes disagree on the same height" >&2
               exit 1 ;;
        esac
        [ "$i" -lt "$SETTLE_TRIES" ] && sleep "$SETTLE_SLEEP"
    done
    echo "smoke: FAIL — $label: cluster did not converge within $((SETTLE_TRIES * SETTLE_SLEEP))s" >&2
    echo "$out" >&2
    exit 1
}

# ── Phase 1: agreement ────────────────────────────────────────────────────
echo "1. Cluster agreement (${#CLUSTER[@]} nodes)..."
sample_cluster
AGREED_HEIGHT=""
await_agreement "initial"
INITIAL_HEIGHT="$AGREED_HEIGHT"

# ── Phase 2: liveness (opt-in) ────────────────────────────────────────────
if [ -z "${SMOKE_SPEND_TO:-}" ]; then
    echo
    echo "2. Liveness phase SKIPPED — set SMOKE_SPEND_TO=<fingerprint> and"
    echo "   SMOKE_SPEND_AMOUNT=<raw base units, 10^8 per DNAC> to enable."
    echo "   (Agreement above is the correctness check; this phase only adds"
    echo "    proof that the cluster still produces blocks.)"
    echo
    echo "smoke: PASS — ${#CLUSTER[@]}/${#CLUSTER[@]} agree at height $INITIAL_HEIGHT (agreement only)"
    exit 0
fi

if [ ! -x "$DNA_CLI" ]; then
    echo "smoke: FAIL — dna-connect-cli not found at $DNA_CLI (set DNA_CLI=...)" >&2
    exit 1
fi

SPEND_AMOUNT="${SMOKE_SPEND_AMOUNT:-100000000}"   # default 1 DNAC in raw units

echo
echo "2. Liveness: sync, then send $SPEND_AMOUNT raw units to $SMOKE_SPEND_TO..."
# sync before AND after a send is mandatory in this project — a send built on a
# stale UTXO view produces a TX the cluster will reject for reasons unrelated to
# the deploy being tested.
"$DNA_CLI" dna sync
"$DNA_CLI" dna balance
"$DNA_CLI" dna send "$SMOKE_SPEND_TO" "$SPEND_AMOUNT" "post-deploy smoke"
"$DNA_CLI" dna sync

echo
echo "3. Cluster agreement after the spend..."
await_agreement "post-spend"
NEW_HEIGHT="$AGREED_HEIGHT"

if [ "$NEW_HEIGHT" -le "$INITIAL_HEIGHT" ]; then
    echo "smoke: FAIL — block height did not advance ($INITIAL_HEIGHT -> $NEW_HEIGHT)" >&2
    exit 1
fi

echo
echo "smoke: PASS — ${#CLUSTER[@]}/${#CLUSTER[@]} agree, height advanced $INITIAL_HEIGHT -> $NEW_HEIGHT"
