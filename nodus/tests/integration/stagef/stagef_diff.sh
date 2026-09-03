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

# ── WHICH LANE IS THIS CHAIN ON, AND WHY THE QUESTION IS NOT OPTIONAL
#
# A pure Ledger V2 chain never writes the legacy `blocks` table — its
# only writer is the legacy finalize path, which a V2 successor does not
# execute. So the original query, `SELECT … FROM blocks ORDER BY height
# DESC LIMIT 1`, returns an EMPTY STRING on every node of a V2 cluster.
# Seven empty strings compare equal, and this script printed
#
#     [ok] label: 7/7 state_root identical (|)
#
# — a green with no height and no root in it, from a comparison that
# read nothing. Every scenario ends with a call to this script, so the
# whole suite would have reported agreement it never measured. Observed
# on the first V2 bring-up, 2026-09-03.
#
# Two independent repairs, and the second matters on the legacy lane too:
#   1. read v2_blocks when the chain is V2;
#   2. an EMPTY read is a FAILURE. "No block to compare" is not
#      "identical" — that is the harness-false-positive class the
#      Genesis Protocol memory names, and it was live here.
lane_query() {
    local db="$1"
    local has_v2 n_v2
    has_v2=$(sqlite3 "$db" \
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
    if [ "${has_v2:-0}" != "0" ]; then
        n_v2=$(sqlite3 "$db" "SELECT COUNT(*) FROM v2_blocks;" 2>/dev/null || echo 0)
        if [ "${n_v2:-0}" != "0" ]; then
            # V2's state_root equivalent is global_root.
            # The lane tag rides on the ROOT, not the height, so lane
            # disagreement is caught by the same root comparison the
            # legacy path always used — no second, stricter check that
            # could redden a scenario for a reason unrelated to lanes.
            sqlite3 "$db" \
              "SELECT global_height || '|v2:' || hex(substr(global_root,1,8)) \
               FROM v2_blocks ORDER BY global_height DESC LIMIT 1"
            return
        fi
    fi
    sqlite3 "$db" \
      "SELECT height || '|' || hex(substr(state_root,1,8)) \
       FROM blocks ORDER BY height DESC LIMIT 1"
}

declare -a ROWS
divergent=0
first_root=""
first_height=""
seen_any=0
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    if [ -z "$db" ] || [ ! -s "$db" ]; then
        ROWS+=("node$n  MISSING_DB")
        divergent=1
        continue
    fi
    row=$(lane_query "$db")
    if [ -z "$row" ]; then
        # NOT a match. This node has no block on either lane.
        ROWS+=("node$n  NO_BLOCK")
        divergent=1
        continue
    fi
    ROWS+=("node$n  $row")
    root=$(echo "$row" | cut -d'|' -f2)
    height=$(echo "$row" | cut -d'|' -f1)
    if [ "$seen_any" = 0 ]; then
        seen_any=1
        first_root="$root"
        first_height="$height"
    else
        # Root only, exactly as before. The lane tag lives inside the
        # root string, so two nodes on different lanes cannot compare
        # equal — the correct verdict, reached without a new check.
        if [ "$root" != "$first_root" ]; then divergent=1; fi
    fi
    if [ -n "$EXPECT_HEIGHT" ] && [ "$height" != "$EXPECT_HEIGHT" ]; then
        divergent=1
    fi
done

# Nothing was read at all: no node had a block. A pass here would be the
# emptiest possible green.
if [ "$seen_any" = 0 ]; then
    divergent=1
fi

if [ $divergent -eq 1 ]; then
    echo "[FAIL] state_root divergence ${LABEL:+($LABEL)}" >&2
    for row in "${ROWS[@]}"; do echo "  $row" >&2; done
    exit 1
fi

if [ -n "$LABEL" ]; then
    echo "[ok] ${LABEL}: ${STAGEF_COMMITTEE_SIZE}/${STAGEF_COMMITTEE_SIZE} state_root identical ($first_height|$first_root)"
fi
exit 0
