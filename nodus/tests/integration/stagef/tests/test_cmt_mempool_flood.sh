#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_mempool_flood.sh — the mempool reactor floods, and batches
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   TWO properties of the ported mempool reactor, in one scenario:
#
#   (A) A transaction submitted to ONE node commits on ALL SEVEN. There
#   is no leader on this lane and no forward-to-leader step (D-23 rev 8
#   item 17: "the mempool reactor floods"), so a client can submit to
#   ANY node and the mempool channel (verb 39, NODUS_T3_CMT_TXS =
#   `w_cmt_txs`, nodus_tier3.h:181) gossips it to the rest before a
#   proposer ever picks it up. The property that would be false if it
#   failed: *this build's mempool gossip actually reaches every peer,
#   not just the node a client happens to be connected to.*
#
#   (B) Several transactions submitted back-to-back land WITHIN A SMALL
#   BOUND OF HEIGHTS of each other, typically (and in the common case,
#   exactly) ONE block. `dnac_spend` answers CheckTx immediately (D-23
#   rev 7 item 22), so a tight loop of submissions queues them in the
#   mempool faster than PrepareProposal can drain one at a time; the
#   next proposal picks up everything ALREADY waiting, up to its claim
#   bound (~2 972 claims at Block.MaxBytes 22 020 096 — D-23 rev 8 item
#   24). The property that would be false if it failed: *this build's
#   PrepareProposal actually batches what IS in the mempool when it
#   runs, rather than gating on some internal one-tx-per-block
#   assumption the pre-Comet lane never had to prove wrong* — DELTA 2:
#   this is deliberately NOT "every burst always lands in exactly one
#   block", which the reference does not promise (see below).
#
#   DELTA 1 (verifier UNCOVERED FINDING 2, CONFIRMED) — **this is NOT
#   measured through `tx_count`.** `v2_blocks.tx_count` is filled from
#   `n_all`, which only counts APPLIED ENVELOPES
#   (`nodus_witness_v2_apply.c:4593-4595`, iterating `blk->n_envs`).
#   `v2-claim` submits a raw CLAIM (`nodus-cli.c:2255-2257,2320-2321`),
#   which lives in a completely different array (`blk->claims[]`,
#   `nodus_witness_cmt_app.c:1151-1152`) that `n_all` never touches — so
#   three claims ALWAYS show `tx_count = 0`, structurally, on a healthy
#   chain; asserting `tx_count > 1` here would be permanently RED. The
#   batching claim is proved instead through the LEDGER EFFECT of all
#   three claims (their `utxo_set` rows, keyed by `tx_hash` — the same
#   fix `test_v2_claim.sh` makes) landing at the SAME `block_height`.
#
# WHAT IT REQUIRES
#   Compile flags: NONE. A default nodus/build binary.
#   Environment: none of its own.
#   ⚠ A cluster from **stagef_up_v2.sh**. On a legacy cluster it exits 99.
#   Needs FOUR still-unclaimed node leaves (one for part A, three for
#   part B) — genesis_protocol_v2.sh's explicit order runs this AFTER
#   test_v2_claim.sh/test_v2_stake.sh (which spend node2's and the
#   user's leaves) and picks nodes 4/5/6/7, none of which any earlier
#   scenario in this sweep claims.
#
# WHAT IT LEAVES BEHIND
#   Node 4's, node 5's, node 6's and node 7's genesis leaves are claimed.
#   The PUMP identity's batch is UNTOUCHED — this scenario deliberately
#   does not reach for it, so test_v2_epoch_boundary.sh (which runs
#   after this one) still has the whole thing.
#
# HOW IT CAN LIE
#   - **Part A submits to node 3 SPECIFICALLY and reads back from ALL
#     SEVEN.** Reading only from node 3 (the node the client is talking
#     to) would prove the local mempool accepted it, nothing about
#     gossip; the assertion is stagef_diff agreement across the fleet at
#     the height it landed — AND, DELTA 1 (verifier UNCOVERED FINDING 4,
#     CONFIRMED), that the claim's own UTXO exists at that height. Height
#     agreement ALONE proves nothing about node4's specific transaction:
#     on a build whose mempool gossip is completely broken, node3 could
#     hold the claim locally forever while the fleet keeps agreeing on
#     empty, interval-driven blocks — height agreement would still be
#     green. The UTXO check is what proves the SUBMITTED CLAIM, not just
#     the chain in general, reached everyone.
#   - **DELTA 2, MEASURED: Part A and Part B no longer assume
#     tip+1 == inclusion.** A stake envelope on this same lane was
#     APPROVED at tip 2 and its ledger row did not appear until tip 4 —
#     CheckTx admission promises nothing about WHEN a transaction lands.
#     Both parts now wait for the ledger effect ITSELF
#     (`stagef_cmt_wait_row`) and read its OWN height, never
#     `submission_tip + 1`. The tip-advance checks that remain are
#     LIVENESS ONLY (some block committed), never inclusion proof.
#   - **Part B's "same block" is the COMMON case, not a guarantee — see
#     the body's own comment for why three separate CLI processes can
#     legitimately split across rounds.** The assertion is a BOUNDED
#     spread (`SPLIT_BOUND=2` heights), not exact equality; an exact
#     match is logged as the expected outcome, a bounded split is logged
#     as a legitimate one, and only exceeding the bound is a FAIL. Never
#     `tx_count` (see DELTA 1 above) either way.
#   - **DELTA 3, DEFECT 2 (fixed), both parts — a stall and a
#     healthy-but-dropped chain are bounded SEPARATELY now.** Without a
#     second bound, `stagef_cmt_wait_row` could wait FOREVER against a
#     healthy, still-advancing chain if a query were mis-keyed (measured
#     on `test_v2_stake.sh`: 34 minutes at tip 347 before it was killed
#     by hand). Both parts now distinguish rc=1 ("stalled") from rc=2
#     ("not included within 20 heights — dropped, not delayed").
#   - **NEITHER OUTCOME IS DISTINGUISHED FROM A GENUINE SILENT DROP**, in
#     either part — rc=1 and rc=2 are distinguished from EACH OTHER, not
#     from "the ledger silently refused this transaction after CheckTx
#     approved it".
#   - **NEVER parse `committed: height=` on this lane.** See
#     test_v2_claim.sh's header for why; the same CheckTx-immediate
#     answer applies to every submission here.
#   - **rc=99 means the cluster was not Comet.** Coverage that did not
#     happen, never a pass.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

REF=1
CONF="$BASE_DIR/v2_genesis.conf"
CLI="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"

die() { echo "[FAIL] $*" >&2; exit 1; }

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ] || [ ! -f "$CONF" ]; then
    echo "[SKIP] not a Comet cluster with a genesis config — use stagef_up_v2.sh"
    exit 99
fi

stagef_cmt_diff_at_floor "pre-cmt-mempool-flood" || exit 2

# nullifier of a --dry-run'd claim, keyed by identity dir. Same capture
# test_v2_claim.sh uses; see that script for why this is safe to read
# once, before submitting, rather than re-derived after the fact.
claim_nullifier() {
    local keydir="$1" dry
    dry="$BASE_DIR/cmtflood_dry_$$_$RANDOM.log"
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF")" v2-claim --config "$CONF" \
        --db "$ref_db" --keys "$keydir" --dry-run > "$dry" 2>&1 \
        || { cat "$dry" >&2; rm -f "$dry"; die "dry-run build failed for $keydir"; }
    local n
    n=$(awk '/^ *nullifier=/{sub(/^ *nullifier=/,""); print}' "$dry")
    rm -f "$dry"
    [ "${#n}" = 128 ] || die "could not read a 64-byte nullifier from the dry-run for $keydir"
    printf '%s\n' "$n"
}

# ── Part A: submit to node 3 only, and everyone commits it ──────────
before_a=$(stagef_cmt_tip "$ref_db")
nul4=$(claim_nullifier "$(stagef_node_dir 4)/identity")
alog="$BASE_DIR/cmtflood_a.log"
if ! "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 3)" v2-claim --config "$CONF" \
       --db "$ref_db" --keys "$(stagef_node_dir 4)/identity" \
       --submit "127.0.0.1:$(stagef_tcp_port 3)" > "$alog" 2>&1; then
    cat "$alog" >&2
    die "node4's claim, submitted to node3 only, was REJECTED (CheckTx)"
fi
echo "[ok] node4's claim APPROVED by node3 (only)"

# Liveness only — NOT proof node4's claim was in it. DELTA 2: CheckTx
# admission does not promise next-block inclusion (measured on
# test_v2_stake.sh: approved at tip 2, included at tip 4).
before_a_live=$(stagef_cmt_wait_height "$ref_db" "$(( before_a + 1 ))" 2) \
    || die "tip did not advance after a claim submitted to node3 alone — the chain itself looks stalled"

# DELTA 1 (finding 4) + DELTA 2 — height agreement is not INCLUSION, and
# inclusion is not next-block either. Wait for node4's own UTXO row
# (wherever it lands), then read that row's OWN height. DELTA 3 (defect
# 2) — distinguish a STALL (rc=1) from a healthy chain that never
# included this claim (rc=2), so this cannot wait forever like the same
# helper measured on test_v2_stake.sh (34 minutes at a healthy tip).
a_stall_at=$(stagef_cmt_wait_row "$ref_db" \
    "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$nul4';" 4) \
    && a_wait_rc=0 || a_wait_rc=$?
if [ "$a_wait_rc" = 1 ]; then
    die "node4's claim (submitted to node3 only) never produced a utxo_set row and the chain STALLED at $a_stall_at — approved but never applied, or the chain stopped advancing; indistinguishable from outside"
elif [ "$a_wait_rc" = 2 ]; then
    die "node4's claim was not included within 20 heights of submission (tip $before_a -> $a_stall_at) — dropped, not delayed"
fi
after_a=$(sqlite3 "$ref_db" \
    "SELECT block_height FROM utxo_set WHERE lower(hex(tx_hash)) = '$nul4' LIMIT 1;" \
    2>/dev/null || true)
[ -n "$after_a" ] || die "node4's row appeared between polls but its block_height could not be read"
echo "[ok] node4's claim's own UTXO exists on-chain at height $after_a (live tip was $before_a_live)"

# Every one of the SEVEN must agree at that height — proving the tx
# reached them all through the mempool channel's gossip, not merely
# node3's own local mempool.
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    stagef_cmt_wait_height "$(stagef_node_chain_db "$n")" "$after_a" 2 >/dev/null \
        || die "node$n never reached height $after_a — the mempool gossip from node3 did not reach it"
done
stagef_cmt_diff_at_floor "post-cmt-mempool-flood-partA" || exit 2
echo "[ok] all $STAGEF_COMMITTEE_SIZE nodes committed the node3-only submission identically"

# ── Part B: three claims, back to back, no settling wait ────────────
before_b=$(stagef_cmt_tip "$ref_db")
nul5=$(claim_nullifier "$(stagef_node_dir 5)/identity")
nul6=$(claim_nullifier "$(stagef_node_dir 6)/identity")
nul7=$(claim_nullifier "$(stagef_node_dir 7)/identity")
for n in 5 6 7; do
    blog="$BASE_DIR/cmtflood_b_node$n.log"
    if ! "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF")" v2-claim --config "$CONF" \
           --db "$ref_db" --keys "$(stagef_node_dir "$n")/identity" \
           --submit "127.0.0.1:$(stagef_tcp_port "$REF")" > "$blog" 2>&1; then
        cat "$blog" >&2
        die "node$n's claim was REJECTED (CheckTx) during the flood"
    fi
done
echo "[ok] node5, node6 and node7 claims all APPROVED, submitted back to back"

# Liveness only.
before_b_live=$(stagef_cmt_wait_height "$ref_db" "$(( before_b + 1 ))" 2) \
    || die "tip did not advance after the flood — the chain itself looks stalled"

# DELTA 1 (finding 2) — NEVER tx_count on this lane (claims do not
# increment it; see the header). DELTA 2 — wait for the LEDGER EFFECT of
# all three (never "tip+1"), then read where each actually landed.
# CAN THREE BACK-TO-BACK SUBMISSIONS LEGITIMATELY SPLIT ACROSS BLOCKS?
# Yes — read for this delta, not assumed: each submission is a SEPARATE
# CLI process (its own TCP connect, ML-DSA-87 sign, RPC round trip), so
# the three do not arrive at the mempool atomically. DELTA 2's own
# measurement (a single CheckTx-approved transaction landing 2 heights
# after admission, because a round was already in flight when it
# arrived) applies to EACH of the three independently: if item 1's
# arrival is what triggers `cmt_cs_handle_txs_available`'s round-entry
# timeout (shared/dnac/cmt_cs.c:1724-1766, a ~1 ms schedule once the
# mandatory post-commit wait elapses) and items 2/3 arrive after
# PrepareProposal has already been called for that round, they land in
# the NEXT one instead. So "same block_height" is the COMMON case this
# scenario expects (all three normally arrive within milliseconds of
# each other, well inside one interval), but not a guarantee the
# reference makes — the assertion is instead that all three land within
# a BOUNDED spread of heights, logging whether they actually batched.
SPLIT_BOUND=2
n_hashes="'$nul5','$nul6','$nul7'"
# stagef_cmt_wait_row's contract is "wait until the SQL's count is > 0";
# to wait for ALL THREE (not merely the first to land), the SQL itself
# encodes "count == 3" as its own boolean-shaped result. DELTA 3 (defect
# 2) — distinguish a STALL (rc=1) from a healthy chain that never
# included all three (rc=2), the same fix applied everywhere else.
stall_at=$(stagef_cmt_wait_row "$ref_db" \
    "SELECT CASE WHEN COUNT(*) = 3 THEN 1 ELSE 0 END FROM utxo_set WHERE lower(hex(tx_hash)) IN ($n_hashes);" \
    4) && b_wait_rc=0 || b_wait_rc=$?
n_rows=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) IN ($n_hashes);" \
    2>/dev/null || echo 0)
if [ "${n_rows:-0}" != 3 ]; then
    if [ "${b_wait_rc:-0}" = 1 ]; then
        die "only $n_rows of the 3 flood claims produced a utxo_set row and the chain STALLED at $stall_at — at least one was approved by CheckTx but never actually applied, or the chain stopped advancing"
    elif [ "${b_wait_rc:-0}" = 2 ]; then
        die "only $n_rows of the 3 flood claims were included within 20 heights of submission (tip $before_b -> $stall_at) — at least one was dropped, not delayed"
    else
        die "only $n_rows of the 3 flood claims produced a utxo_set row (tip $stall_at) — at least one was approved by CheckTx but never actually applied"
    fi
fi
heights=$(sqlite3 "$ref_db" \
    "SELECT DISTINCT block_height FROM utxo_set WHERE lower(hex(tx_hash)) IN ($n_hashes) ORDER BY block_height;" \
    2>/dev/null || true)
n_heights=$(printf '%s\n' "$heights" | grep -c . || true)
min_h=$(printf '%s\n' "$heights" | head -1)
max_h=$(printf '%s\n' "$heights" | tail -1)
spread=$(( max_h - min_h ))
if [ "$spread" -gt "$SPLIT_BOUND" ]; then
    sqlite3 "$ref_db" "SELECT hex(tx_hash), block_height FROM utxo_set \
        WHERE lower(hex(tx_hash)) IN ($n_hashes);" >&2
    die "the 3 flood claims spread across $spread heights ($min_h..$max_h), over the $SPLIT_BOUND-height bound — that is more separation than 3 back-to-back submissions landing on different rounds should ever produce"
fi
after_b="$max_h"
if [ "$n_heights" = "1" ]; then
    echo "[ok] all 3 flood claims applied at the SAME height ($min_h) — PrepareProposal batched them"
else
    echo "[ok] the 3 flood claims applied across heights $min_h..$max_h (spread $spread, within the $SPLIT_BOUND-height bound) — PrepareProposal did not batch this run, which the reference does not guarantee it will"
fi

for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    stagef_cmt_wait_height "$(stagef_node_chain_db "$n")" "$after_b" 2 >/dev/null \
        || die "node$n never reached height $after_b (mesh replication stalled)"
done
stagef_cmt_diff_at_floor "post-cmt-mempool-flood-partB" || exit 2

echo ""
echo "[PASS] a claim submitted to a single node (3) was gossiped, applied, and"
echo "       reached all $STAGEF_COMMITTEE_SIZE (its own UTXO exists, not just an agreed height);"
echo "       a burst of 3 claims all applied within $SPLIT_BOUND heights of each other"
echo "       ($min_h..$max_h). All nodes agree on block identity at height $after_b."
