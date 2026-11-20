#!/usr/bin/env bash
#
# Stage F harness — global_root + block_id assertion helper.
#
# R3 W4-D deleted the legacy `blocks`-table state_root fallback this file
# used to hold beside the V2 read: every surviving scenario runs a V2 or
# V3 successor chain, so v2_blocks is the only table this script reads.
# Reads the latest block's global_root + block_id from each node's
# witness DB and asserts all are identical — ALL 64 BYTES of each, in every
# mode (see "THE COMPARISON IS ALWAYS WHOLE" below). Prints per-node (height,
# first-8-bytes of each) for human review.
#
# Usage:
#   bash stagef_diff.sh              # silent on pass, verbose on fail
#   bash stagef_diff.sh "label"      # prints label regardless
#   bash stagef_diff.sh --expect-height N   # additionally require height==N
#   bash stagef_diff.sh --at-height N       # compare the ROW AT height N,
#                                            # never each node's current max
#   bash stagef_diff.sh --full ...          # 64-byte mode (below); combines
#                                            # with every flag above
#
# THE COMPARISON IS ALWAYS WHOLE (B-08; supersedes the HF-9 WP7 text
# "the mode is a flag, never a default", plan docs/plans/approved/
# 2026-11-04-hf9.md §12 T-14, which kept an 8-byte default comparison)
#   Every call reads `hex(global_root)` and `hex(block_id)` whole and
#   (1) requires each to be EXACTLY 128 hex characters = 64 bytes (the
#       engine stores both as 64-byte BLOBs, nodus_witness_v2_apply.c
#       out_block_id / global_root); any other length is a [FAIL] on that
#       node — a column that became shorter would otherwise compare "equal"
#       on every node while hiding bytes;
#   (2) compares the full strings across the nodes.
#   `--full` now only changes what is PRINTED (the whole 128-hex fields; the
#   default prints the first 16 hex characters = 8 bytes of each, exactly the
#   text it always printed) and is still accepted by every caller. A default
#   call used to compare only `substr(…,1,8)` yet print "state_root
#   identical" — a split in the other 56 bytes passed.
#   How it can lie: it reads what is STORED; it does not recompute a root
#   (that is the unit tests' and the oracle's).
#
# R3 W3 (C2d) — WHY --at-height EXISTS
#   CreateEmptyBlocks means a Comet-lane chain keeps committing on its
#   own (README.md's flipped rule #1). Reading "each node's CURRENT
#   latest block" is then a race against that idle production: seven
#   sequential SQLite reads spanning even a second or two can catch node
#   3 one idle block ahead of node 5 through nothing but scheduling, and
#   read that as divergence. --at-height asks the honest question
#   instead — "do all seven nodes agree on the row AT height N", for an
#   N every caller already proved every node has reached (e.g. via
#   stagef_cmt_wait_height) — which cannot race the chain's own ongoing
#   production. Every Comet scenario's FINAL diff should use this, not
#   the default latest-row read; --expect-height does NOT do this job:
#   it still reads each node's own max and merely asserts it equals N,
#   which FAILS on a node that has since raced ahead instead of reading
#   its historical row.
#
# Exit:
#   0 — all 3 identical
#   1 — divergent or a DB missing

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/stagef_env.sh"

LABEL=""
EXPECT_HEIGHT=""
AT_HEIGHT=""
FULL=0
while [ $# -gt 0 ]; do
    case "$1" in
        --expect-height) EXPECT_HEIGHT="$2"; shift 2 ;;
        --at-height) AT_HEIGHT="$2"; shift 2 ;;
        --full) FULL=1; shift ;;
        *) LABEL="$1"; shift ;;
    esac
done

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F run" >&2
    exit 1
fi

# ── R3 W4-D — THE LEGACY `blocks` FALLBACK IS DELETED ─────────────────
#
# This function used to check whether a chain was V2 (v2_blocks holds
# rows) or legacy (fall back to the `blocks` table's state_root) before
# every read, because both lanes existed side by side. The closed
# consensus lane is deleted: every surviving scenario (the 11
# test_cmt_*/test_v2_* scripts) runs a V2 or V3 successor chain, and
# every one of them writes v2_blocks on its very first commit. The
# `blocks`-table branch this comment used to describe is gone; only the
# Comet global_root+block_id read remains.
lane_query() {
    local db="$1"
    local at="${2:-}"
    # R3 W3 (C2d) — THE COMET LANE ADDS block_id TO THE COMPARISON.
    #
    # global_root alone was the whole story for the pre-Comet V2 lane
    # (one applier, one root per height). On the Comet lane the row also
    # carries block_id — the Comet BlockID's hash, covering the header
    # (last_commit_hash, validators_hash, consensus_hash, evidence_hash,
    # proposer address, time) that global_root does NOT cover
    # (nodus_witness_v2_apply.c:4805-4816 — the Comet insert names ten
    # columns, dropping `header` and `qc`; block_id is the one column
    # that still speaks for that dropped header). Two nodes could in
    # principle agree on every domain root while committing a different
    # header (a different proposer, a different BFT-time) — global_root
    # alone would not catch that; block_id does.
    # Both columns are read WHOLE and compared whole in every mode (an
    # equality check that looked at 8 of 64 bytes would print "identical"
    # for roots that differ in the other 56). Only what is PRINTED is
    # shortened, and only when `--full` is not given (below).
    if [ -n "$at" ]; then
        sqlite3 "$db" \
          "SELECT global_height || '|v2:' || hex(global_root) \
           || '|bid:' || hex(block_id) \
           FROM v2_blocks WHERE global_height = $at"
    else
        sqlite3 "$db" \
          "SELECT global_height || '|v2:' || hex(global_root) \
           || '|bid:' || hex(block_id) \
           FROM v2_blocks ORDER BY global_height DESC LIMIT 1"
    fi
}

# The printed form of a "<height>|v2:<128 hex>|bid:<128 hex>" row: whole with
# `--full`, otherwise the first 16 hex characters (8 bytes) of each field —
# the text the default mode always printed. Display only; the comparison below
# never sees it.
row_display() {
    local row="$1" height rest gr bid
    if [ "$FULL" = 1 ]; then printf '%s' "$row"; return; fi
    height="${row%%|*}"
    rest="${row#*|}"
    gr="${rest#v2:}";  gr="${gr%%|*}"
    bid="${rest##*|bid:}"
    printf '%s|v2:%s|bid:%s' "$height" "${gr:0:16}" "${bid:0:16}"
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
    row=$(lane_query "$db" "$AT_HEIGHT")
    if [ -z "$row" ]; then
        # NOT a match. This node has no block on either lane (or, with
        # --at-height, has not yet reached that height — a caller must
        # only pass a height it has already proven every node reached).
        ROWS+=("node$n  NO_BLOCK")
        divergent=1
        continue
    fi
    # A row that is not exactly two 128-hex-character (64-byte) fields is
    # never "equal" — it is a FAIL on its own, in every mode (a shortened
    # column would otherwise match on every node and hide bytes).
    if ! [[ "${row#*|}" =~ ^v2:[0-9A-F]{128}\|bid:[0-9A-F]{128}$ ]]; then
        ROWS+=("node$n  $row")
        ROWS+=("node$n  ^^ not two 128-hex (64-byte) fields")
        divergent=1
        continue
    fi
    ROWS+=("node$n  $(row_display "$row")")
    # R3 W3 (C2d) — compare EVERYTHING after the height, not just field 2:
    # a Comet row has two fields there ('v2:<hex>|bid:<hex>') — cutting
    # only field 2 would silently drop block_id from the comparison and
    # defeat the column added above.
    height=$(echo "$row" | cut -d'|' -f1)
    root=$(echo "$row" | cut -d'|' -f2-)
    if [ "$seen_any" = 0 ]; then
        seen_any=1
        first_root="$root"
        first_height="$height"
    else
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
    # What is printed follows the display mode; what was compared was always
    # all 64 bytes of global_root and block_id.
    shown=$(row_display "$first_height|$first_root")
    if [ "$FULL" = 1 ]; then
        echo "[ok] ${LABEL}: ${STAGEF_COMMITTEE_SIZE}/${STAGEF_COMMITTEE_SIZE} state_root identical, all 64 bytes of global_root and block_id (${shown})"
    else
        echo "[ok] ${LABEL}: ${STAGEF_COMMITTEE_SIZE}/${STAGEF_COMMITTEE_SIZE} state_root identical (${shown})"
    fi
fi
exit 0
