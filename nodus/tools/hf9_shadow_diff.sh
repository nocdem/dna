#!/usr/bin/env bash
#
# HF-9 shadow-run comparison gate (plan docs/plans/approved/2026-11-04-hf9.md
# §11, test row T-10 / the acceptance record).
#
# Asks every listed node for its shadow log row (`nodus-cli hf9-shadow <h>`,
# the Tier-2 read query dnac_hf9_shadow) and compares, per height, ALL 64
# BYTES of every value: the eight leg roots leg1..leg8 and the four shadow
# compositions core (CORE v4'), stor (STOR v3'), sys (SYS v7'), glob
# (GLOBAL v2'). It is NOT nodus/tests/integration/stagef/stagef_diff.sh,
# which compares only 8 bytes of the committed global root and is not this
# gate. The values are node-local shadow data, never consensus.
#
# THE NODE LIST IS AN ARGUMENT. There is no list in this script: the member
# set is read from the chain by the operator, who passes every node of the
# shadow run (the plan names all eight, 62.171.136.77 included, D12). With
# no node given the script refuses to run.
#
# Usage:
#   hf9_shadow_diff.sh [--from H] [--to H] <host:port> <host:port> ...
#   HF9_NODES="host:port host:port ..." hf9_shadow_diff.sh [--from H] [--to H]
#
#   --from H / --to H   the inclusive height range to compare. Default: the
#                       newest height every node has logged, alone (--to
#                       omitted = that height; --from omitted = --to).
#
# Environment:
#   NODUS_CLI           path of nodus-cli (default: nodus-cli)
#   HF9_CLI_OPTS        extra options placed before the command, for example
#                       "--pin <128 hex> --chain-id <64 hex>" (word-split)
#
# Output: one line per node per height that differs, then the acceptance
# summary (nodes, first/last compared height, heights compared on every
# node, per-node shadow status). A node whose status is not running (1), a
# height some node has no row for and any differing byte make the run FAIL.
# The script cannot know boundaries crossed, restarts, publications or the
# full-check node: those belong to the operator's acceptance record.
#
# Exit: 0 every compared height is identical on every node, every node
#       running; 1 a difference, a missing row, a node not running or a node
#       that did not answer; 2 a usage error.
#
# Verification of this script is `bash -n` only; it is run against live
# nodes by the operator.

set -u

NODUS_CLI="${NODUS_CLI:-nodus-cli}"
HF9_CLI_OPTS="${HF9_CLI_OPTS:-}"
FROM=""
TO=""
NODES=()

usage() {
    sed -n '2,/^set -u/p' "$0" | sed -n '3,$p' | grep '^#' | sed 's/^# \{0,1\}//' >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --from) FROM="${2:-}"; shift 2 || { usage; exit 2; } ;;
        --to)   TO="${2:-}";   shift 2 || { usage; exit 2; } ;;
        -h|--help) usage; exit 2 ;;
        --*) echo "unknown option: $1" >&2; usage; exit 2 ;;
        *) NODES+=("$1"); shift ;;
    esac
done
if [ "${#NODES[@]}" -eq 0 ] && [ -n "${HF9_NODES:-}" ]; then
    # shellcheck disable=SC2206
    NODES=($HF9_NODES)
fi
if [ "${#NODES[@]}" -eq 0 ]; then
    echo "no node given: pass every node of the shadow run as host:port, or set HF9_NODES" >&2
    exit 2
fi
for n in "${NODES[@]}"; do
    case "$n" in
        *:*) ;;
        *) echo "node '$n' is not host:port" >&2; exit 2 ;;
    esac
done
for v in "$FROM" "$TO"; do
    if [ -n "$v" ] && ! [[ "$v" =~ ^[0-9]+$ ]]; then
        echo "--from / --to need a non-negative integer, got '$v'" >&2
        exit 2
    fi
done

KEYS="leg1 leg2 leg3 leg4 leg5 leg6 leg7 leg8 core stor sys glob"

# query <node> <height> -> the node's key=value lines on stdout; non-zero
# when the node did not answer
query() {
    # shellcheck disable=SC2086
    "$NODUS_CLI" $HF9_CLI_OPTS -s "$1" hf9-shadow "$2" 2>/dev/null
}

# field <lines> <key> -> the value of key= in the lines ("" when absent)
field() {
    printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n 1
}

fail=0
declare -A STATUS_OF      # node -> status
declare -A NEWEST_OF      # node -> newest logged height

# the newest row of every node: its status, and the default range
min_newest=""
for n in "${NODES[@]}"; do
    out=$(query "$n" 0) || { echo "FAIL node $n did not answer" ; fail=1; continue; }
    st=$(field "$out" status)
    STATUS_OF[$n]="$st"
    if [ "$(field "$out" found)" = "1" ]; then
        h=$(field "$out" height)
        NEWEST_OF[$n]="$h"
        if [ -z "$min_newest" ] || [ "$h" -lt "$min_newest" ]; then
            min_newest="$h"
        fi
    else
        NEWEST_OF[$n]=""
        echo "FAIL node $n has no shadow log row (status ${st:-unknown})"
        fail=1
    fi
done

if [ -z "$TO" ]; then TO="$min_newest"; fi
if [ -z "$FROM" ]; then FROM="$TO"; fi
if [ -z "$TO" ] || [ -z "$FROM" ]; then
    echo "no height to compare" >&2
    exit 1
fi
if [ "$FROM" -gt "$TO" ]; then
    echo "--from $FROM is above --to $TO" >&2
    exit 2
fi

compared_all=0
first_all=""
last_all=""
h="$FROM"
while [ "$h" -le "$TO" ]; do
    declare -A ROW=()
    have_all=1
    for n in "${NODES[@]}"; do
        out=$(query "$n" "$h") || { echo "FAIL height $h node $n did not answer"; fail=1; have_all=0; continue; }
        if [ "$(field "$out" found)" != "1" ] || [ "$(field "$out" height)" != "$h" ]; then
            echo "FAIL height $h node $n has no row"
            fail=1
            have_all=0
            continue
        fi
        ROW[$n]="$out"
    done
    if [ "$have_all" = "1" ]; then
        ref="${NODES[0]}"
        same=1
        for n in "${NODES[@]:1}"; do
            for k in $KEYS; do
                a=$(field "${ROW[$ref]}" "$k")
                b=$(field "${ROW[$n]}" "$k")
                if [ -z "$a" ] || [ "${#a}" -ne 128 ] || [ "$a" != "$b" ]; then
                    echo "DIFF height $h $k: $ref=${a:-missing} $n=${b:-missing}"
                    same=0
                fi
            done
        done
        if [ "$same" = "1" ]; then
            compared_all=$((compared_all + 1))
            if [ -z "$first_all" ]; then first_all="$h"; fi
            last_all="$h"
        else
            fail=1
        fi
    fi
    unset ROW
    h=$((h + 1))
done

echo "---- HF-9 shadow comparison ----"
echo "nodes (${#NODES[@]}): ${NODES[*]}"
echo "range compared: $FROM..$TO"
echo "heights identical on all ${#NODES[@]} nodes: $compared_all (first ${first_all:-none}, last ${last_all:-none})"
for n in "${NODES[@]}"; do
    st="${STATUS_OF[$n]:-unknown}"
    case "$st" in
        1) name=running ;;
        0) name=stopped ;;
        2) name=faulted ;;
        255) name="never seeded" ;;
        *) name="unknown" ;;
    esac
    echo "node $n status $st ($name) newest logged height ${NEWEST_OF[$n]:-none}"
    if [ "$st" != "1" ]; then
        echo "FAIL node $n shadow status is not running"
        fail=1
    fi
done
if [ "$fail" = "0" ]; then
    echo "RESULT: identical (all 64 bytes of 12 values at every compared height)"
    exit 0
fi
echo "RESULT: FAIL"
exit 1
