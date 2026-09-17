#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_empty_blocks.sh — an idle cometbft chain commits on its own
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That a version-3 (cometbft) chain with NO transaction anywhere in
#   flight still commits blocks, at the CreateEmptyBlocksInterval
#   cadence, and that every node commits the SAME empty block. The
#   property that would be false if it failed: *this build's Comet lane
#   really runs CreateEmptyBlocks=true — a chain that only ever produced
#   a block per transaction would stall here forever.*
#
#   This is the direct negation of the pre-Comet lane's standing rule
#   (README.md: "The chain has no idle block production. A block exists
#   only when a transaction is submitted.") D-4 rev 3 (governing this
#   build's Comet consensus config) sets CreateEmptyBlocks=true and
#   CreateEmptyBlocksInterval=60 000 ms
#   (nodus_witness_cmt_node.c:1699-1700, overriding the library's own
#   0 ms / on-demand-only default at shared/dnac/cmt_config.h:121-122).
#
#   DELTA 1 — MEASURED FACT, CORRECTING THIS SCENARIO'S OWN PREMISE: the
#   60 s interval is NOT the observed pace. Rule N attendance writes the
#   proposer's `last_signed_block` into the validators leaf on every
#   single block (`nodus_witness_v2_apply.c:3801`), so the GLOBAL ROOT
#   changes on every height — which means cometbft's `needProofBlock`
#   (state.go:1106-1129, ported at `cmt_cs.c:1872`) is TRUE at every
#   height in this build, and an empty block is a proof block. A proof
#   block is produced at the `timeout_commit` pace (5 000 ms,
#   nodus_witness_cmt_node.c:1699), NOT the `create_empty_blocks_interval`
#   pace — measured live: seven nodes at ~one block per 6 s. The 60 s
#   figure stays a valid UPPER BOUND for the stall detector below (if
#   this build's `needProofBlock` behaviour ever changed, blocks would
#   still arrive at least that often), but it is not what an operator
#   should expect to see on a clock.
#
# WHAT IT REQUIRES
#   Compile flags: NONE. A default nodus/build binary.
#   Environment: none of its own.
#   ⚠ A cluster from **stagef_up_v2.sh**. On a legacy cluster it exits 99.
#   ⚠ MUST run FIRST in the sweep (genesis_protocol_v2.sh's explicit
#   order does this) — it needs a window with NO transaction of its own
#   or ANY OTHER scenario's in flight, which only the first scenario in
#   a sweep can be sure of. Run standalone against a fresh bring-up if
#   run out of that order.
#   ⏱ In practice takes ~2 x timeout_commit (~10-12 s, measured — see
#   the DELTA 1 note above); the stall bound below still allows up to 4 x
#   60 s as an upper bound on a build that behaves differently.
#
# WHAT IT LEAVES BEHIND
#   The chain a few blocks further on (however many intervals the wait
#   needed). Nothing is claimed, staked, killed, or restarted.
#
# HOW IT CAN LIE
#   - **A late-arriving mempool tx from a PREVIOUS harness run would
#     make this vacuous** — a chain that committed because of leftover
#     demand looks identical to one that committed because of the
#     interval, unless the resulting blocks are checked. The assertion is
#     not just "height advanced" — every block committed inside the
#     observed window must show `tx_count = 0` on the reference node.
#     DELTA 1 (verifier UNCOVERED FINDING 2, CONFIRMED) — **`tx_count = 0`
#     is BLIND to a claim.** `v2_blocks.tx_count` counts applied
#     ENVELOPES only (`nodus_witness_v2_apply.c:4593-4595`); a claim
#     lives in a different array (`blk->claims[]`) that never reaches it.
#     Since a claim is the ONLY transaction a fresh harness identity can
#     submit, a window full of leftover CLAIMS would pass `tx_count = 0`
#     while being anything but idle. Closed with a SECOND guard: no
#     `utxo_set` row (the claim path's own ledger effect — see
#     test_v2_claim.sh) may exist with `block_height` inside the observed
#     window either.
#   - **BFT-TIME MONOTONICITY IS NOT ASSERTED, AND IT CANNOT BE FROM
#     THIS TABLE.** The Comet apply lane's `v2_blocks` row carries NO
#     timestamp column — the insert names exactly ten columns
#     (global_height, block_id, prev_block_id, epoch, tx_root,
#     domain_updates_root, domains_root, global_root, vset_hash,
#     tx_count) and explicitly DROPS `header`
#     (nodus_witness_v2_apply.c:4798-4816, the comment there: "under
#     cometbft the header lives in the block store's BlockMeta ... none
#     of them is the ledger's to keep"). The committed block's BFT time
#     lives only inside the Comet block store's BlockMeta and the
#     `cmt_state` row — both opaque protobuf blobs under a generic
#     key/value schema (`cmt_blockstore`/`cmt_state`, key BLOB, value
#     BLOB — nodus_witness_v2_schema.c:1465-1474), not a column this
#     harness's sqlite3 CLI can read. A per-block BFT-time check would
#     need a decoder this package does not have; reported here rather
#     than invented against a column that does not carry the value.
#   - **A single stalled interval before the height check completes
#     could still be a transient scheduling delay, not a defect** — the
#     wait is bounded by MULTIPLE consecutive stalled intervals
#     (stagef_cmt_wait_height's stall detection), never a single missed
#     poll.
#   - **DELTA 2 — this scenario is UNAFFECTED by the "CheckTx admission
#     is not next-block inclusion" defect other scenarios had.** It
#     asserts ABSENCE over a window (no `tx_count != 0` block, no
#     `utxo_set` row with `block_height` in range), never "my specific
#     submission landed at a particular height" — there is no
#     submission of its own to time at all. A late-arriving effect from
#     an EARLIER scenario would still be caught by these guards no
#     matter which height inside the window it landed at, so the
#     inclusion-delay measurement that changed `test_v2_claim.sh` /
#     `test_v2_stake.sh` / `test_cmt_mempool_flood.sh` has no bearing
#     here.
#   - **rc=99 means the cluster was not Comet.** Coverage that did not
#     happen, never a pass.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

REF=1
die() { echo "[FAIL] $*" >&2; exit 1; }

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ]; then
    echo "[SKIP] not a Comet cluster — use stagef_up_v2.sh"
    exit 99
fi

stagef_cmt_diff_at_floor "pre-cmt-empty-blocks" || exit 2

baseline=$(stagef_cmt_tip "$ref_db")
[ "$baseline" -ge 0 ] || die "node$REF has no Comet block at all — bring-up did not go LIVE"
echo "[ok] baseline tip=$baseline (interval=${STAGEF_CMT_EMPTY_INTERVAL_MS}ms, waiting for >= 2 more)"

# Bounded by PROGRESS: a stall is declared only after 4 consecutive
# empty-block intervals with no height increase, comfortably above the
# 2 intervals this scenario actually needs, so a single slow poll cannot
# fail it.
target=$(( baseline + 2 ))
after=$(stagef_cmt_wait_height "$ref_db" "$target" 4) \
    || die "tip did not reach $target within 4 idle intervals (stuck at $after) — CreateEmptyBlocks did not fire, or this build does not have it on"
echo "[ok] tip advanced with NO transaction submitted: $baseline -> $after"

# ── Anti-vacuity: every block in the window must be EMPTY ───────────
# "Height advanced" is not "idle production happened" — a leftover
# mempool entry from an earlier run would advance height too. Every
# block strictly after $baseline up to $after must show tx_count = 0.
nonzero=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM v2_blocks WHERE global_height > $baseline \
     AND global_height <= $after AND tx_count <> 0;")
if [ "${nonzero:-0}" != "0" ]; then
    sqlite3 "$ref_db" "SELECT global_height, tx_count FROM v2_blocks \
        WHERE global_height > $baseline AND global_height <= $after;" >&2
    die "$nonzero block(s) in the observed window carried a transaction — this measured demand-driven production, not idle CreateEmptyBlocks"
fi
echo "[ok] every block between $baseline and $after carries tx_count=0"

# DELTA 1 (finding 2, second half) — tx_count is blind to a CLAIM (see
# header). Close that blind spot directly: no claim's UTXO may have been
# written at a height inside this window.
claim_rows=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM utxo_set WHERE block_height > $baseline AND block_height <= $after;" \
    2>/dev/null || echo 0)
if [ "${claim_rows:-0}" != "0" ]; then
    sqlite3 "$ref_db" "SELECT hex(tx_hash), block_height FROM utxo_set \
        WHERE block_height > $baseline AND block_height <= $after;" >&2
    die "$claim_rows claim UTXO(s) landed inside the observed window — tx_count=0 missed a CLAIM, not idle production"
fi
echo "[ok] no claim landed inside the window either (utxo_set has no row in that height range)"

stagef_cmt_diff_at_floor "post-cmt-empty-blocks" || exit 2

echo ""
echo "[PASS] the idle Comet chain committed $(( after - baseline )) block(s) with"
echo "       zero transactions in ${STAGEF_CMT_EMPTY_INTERVAL_MS}ms-interval cadence, and every node"
echo "       agrees on block identity at that height. CreateEmptyBlocks is live."
echo "       NOT proven here: BFT-time monotonicity — v2_blocks carries no"
echo "       timestamp column on this lane (see this script's header)."
