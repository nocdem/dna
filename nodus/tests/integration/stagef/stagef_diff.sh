#!/usr/bin/env bash
#
# Stage F harness — state_root assertion helper.
#
# Reads the latest block's state_root from each node's witness DB and
# asserts all are identical. Prints per-node (height, first-8-bytes)
# for human review.
#
# Usage:
#   bash stagef_diff.sh              # silent on pass, verbose on fail
#   bash stagef_diff.sh "label"      # prints label regardless
#   bash stagef_diff.sh --expect-height N   # additionally require height==N
#
# Exit:
#   0 — all 3 identical
#   1 — divergent or a DB missing

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/stagef_env.sh"

LABEL=""
EXPECT_HEIGHT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --expect-height) EXPECT_HEIGHT="$2"; shift 2 ;;
        *) LABEL="$1"; shift ;;
    esac
done

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F run" >&2
    exit 1
fi

declare -a ROWS
divergent=0
first_root=""
first_height=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    if [ -z "$db" ] || [ ! -s "$db" ]; then
        ROWS+=("node$n  MISSING_DB")
        divergent=1
        continue
    fi
    row=$(sqlite3 "$db" \
      "SELECT height || '|' || hex(substr(state_root,1,8)) \
       FROM blocks ORDER BY height DESC LIMIT 1")
    ROWS+=("node$n  $row")
    root=$(echo "$row" | cut -d'|' -f2)
    height=$(echo "$row" | cut -d'|' -f1)
    if [ -z "$first_root" ]; then
        first_root="$root"
        first_height="$height"
    else
        if [ "$root" != "$first_root" ]; then divergent=1; fi
    fi
    if [ -n "$EXPECT_HEIGHT" ] && [ "$height" != "$EXPECT_HEIGHT" ]; then
        divergent=1
    fi
done

if [ $divergent -eq 1 ]; then
    echo "[FAIL] state_root divergence ${LABEL:+($LABEL)}" >&2
    for row in "${ROWS[@]}"; do echo "  $row" >&2; done
    exit 1
fi

if [ -n "$LABEL" ]; then
    echo "[ok] ${LABEL}: ${STAGEF_COMMITTEE_SIZE}/${STAGEF_COMMITTEE_SIZE} state_root identical ($first_height|$first_root)"
fi
exit 0
