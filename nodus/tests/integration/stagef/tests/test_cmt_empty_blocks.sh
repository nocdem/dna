#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_empty_blocks.sh — idle chain waits the FULL interval; a real
# transaction wakes it up (tokenomics-v3 P1, D-4 + D-5)
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   TWO properties, both load-bearing for this package and neither
#   provable by the other:
#
#   (1) D-4 — an idle Comet chain commits at the FULL
#       CreateEmptyBlocksInterval cadence (60 s), not faster. The
#       property that would be false if it failed: *attendance still
#       moves system_state_root on an empty block, so needProofBlock is
#       TRUE at every height and the interval this build is configured
#       with (D-4 rev 3) is not the pace an operator actually gets.*
#       Measured directly, at ~1 s polling granularity, as the WALL-CLOCK
#       gap between consecutive committed heights — never assumed from
#       the configured constant, because the constant was WRONG about the
#       observed pace before this package (see HOW IT CAN LIE).
#
#   (2) D-5 — once the probe identity's claim is admitted, it reaches
#       inclusion in well under one interval (asserted < 30 s), because
#       `cmt_mem_enable_txs_available`'s real callback
#       (`node_txs_available_cb`, nodus_witness_cmt_node.c) wakes the
#       consensus round immediately instead of waiting for the next timer
#       tick. Before D-5 was wired the callback was NULL — a transaction
#       still eventually got picked up (CreateEmptyBlocks means a round
#       starts anyway every interval), but only at the NEXT idle-interval
#       boundary, which this measurement would show as close to 60 s, not
#       "well under" it.
#
#   Both measurements are printed, not just asserted, so a future
#   regression shows the actual numbers rather than a bare FAIL.
#
# WHAT IT REQUIRES
#   Compile flags: NONE. A default nodus/build binary.
#   Environment: none of its own — but the CLUSTER must have been brought
#   up by a **stagef_up_v2.sh** that includes the tokenomics-v3 P1 probe
#   identity ($BASE_DIR/v2probe). An older bring-up without it is
#   detected and SKIPPED (rc 99), not silently run against the pump
#   identity or some other substitute — see this package's stagef_up_v2.sh
#   header for why reusing the pump identity was rejected.
#   ⚠ A cluster from **stagef_up_v2.sh**. On a legacy cluster it exits 99.
#   ⚠ MUST run FIRST in the sweep (genesis_protocol_v2.sh's explicit
#   order does this) — Part 1 needs a window with NO transaction of its
#   own or ANY OTHER scenario's in flight, which only the first scenario
#   in a sweep can be sure of. Run standalone against a fresh bring-up if
#   run out of that order.
#   ⏱ Part 1 needs >= 2 full 60 s idle intervals (>= 90-120 s wall clock
#   to collect two >=45 s gaps with polling overhead); Part 2 typically
#   completes in a few seconds. Budget ~3 minutes total.
#
# WHAT IT LEAVES BEHIND
#   The chain a few blocks further on, and the probe identity's ONE
#   genesis leaf claimed (permanently spent — the nullifier makes it
#   one-shot). A re-run of this scenario against the SAME bring-up will
#   fail at the claim step with "already claimed"; bring up a fresh
#   cluster to run it again. Nothing else is claimed, staked, killed, or
#   restarted.
#
# HOW IT CAN LIE
#   - **A late-arriving mempool tx from a PREVIOUS harness run would make
#     Part 1 vacuous** — a chain that committed because of leftover
#     demand looks identical to one that committed because of the
#     interval, unless the resulting blocks are checked. Closed by the
#     SAME two anti-vacuity guards the previous version of this scenario
#     used: every block in the observed window must show `tx_count = 0`
#     AND no `utxo_set` row may exist with `block_height` in that window
#     (a claim is invisible to `tx_count`, which counts envelopes only —
#     nodus_witness_v2_apply.c).
#   - **THE OLD VERSION OF THIS SCENARIO WAS WRONG ABOUT ITS OWN SUBJECT,
#     BY DESIGN, UNTIL THIS PACKAGE.** Its own header stated the 60 s
#     figure was "not the observed pace" and asserted only a >=2-interval
#     STALL BOUND, never a measured gap — because on the code it tested,
#     the true pace WAS ~6 s (every block was a proof block; see
#     stagef_env.sh's now-historical DELTA 1 comment). This version
#     inverts that: the gap is now the ASSERTION, not merely the budget.
#     A regression back to "attendance moves the root on every block"
#     would make Part 1's `gap_floor_s` check FAIL, loudly, which the old
#     version could not have detected (it only checked for a STALL, and a
#     6 s pace is not a stall).
#   - **A single short gap could be a scheduling fluke, not a defect** —
#     Part 1 requires TWO consecutive gaps to each clear the floor, not
#     one, and the floor (45 s) is comfortably below the 60 s target to
#     absorb ordinary polling/scheduling jitter without being so low that
#     a real regression (e.g. back to ~6 s) could slip under it.
#   - **Part 2's 5 s poll granularity (`stagef_cmt_wait_row`) cannot
#     measure "well under 30 s" more precisely than to the nearest ~5 s.**
#     The printed latency is honest to that granularity; the < 30 s
#     assertion is chosen with enough margin (one interval is 60 s, one
#     `timeout_commit` round is ~5 s) that 5 s jitter cannot flip the
#     verdict either way in the cases this scenario is meant to catch
#     (D-5 wired: a few seconds; D-5 unwired: close to 60 s).
#   - **BFT-time monotonicity is NOT asserted, and cannot be from this
#     table** — `v2_blocks` carries no timestamp column on the Comet
#     lane; the BFT time lives only in the opaque `cmt_blockstore` /
#     `cmt_state` protobuf blobs this harness's sqlite3 CLI cannot decode.
#   - **rc=99 means the cluster was not Comet, or predates the probe
#     identity.** Coverage that did not happen, never a pass.
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
PROBE_DIR="$BASE_DIR/v2probe"
CONF="$BASE_DIR/v2_genesis.conf"
if [ ! -d "$PROBE_DIR/identity" ] || [ ! -f "$CONF" ]; then
    echo "[SKIP] no probe identity / genesis config — this bring-up predates tokenomics-v3 P1's stagef_up_v2.sh"
    exit 99
fi
stagef_sentinel SETUP_OK   # W4-H: the runner turns PASS-without-ASSERT_RUN into FAIL

stagef_cmt_diff_at_floor "pre-cmt-empty-blocks" || exit 2

# ════════════════════════════════════════════════════════════════════
# PART 1 — D-4: the idle gap is >= 45 s, twice in a row, at ~1 s polling
# ════════════════════════════════════════════════════════════════════
baseline=$(stagef_cmt_tip "$ref_db")
[ "$baseline" -ge 0 ] || die "node$REF has no Comet block at all — bring-up did not go LIVE"
echo "[ok] baseline tip=$baseline — collecting 2 consecutive idle-block gaps at ~1s polling"

gaps_needed=2
gap_floor_s=45
# A stall here means no new block for this many SECONDS — generous (4
# intervals) because Part 1 is exactly the measurement that would be
# wrong to rush: a real 60 s-paced chain must never be mistaken for a
# stalled one.
stall_budget_s=$(( 4 * (STAGEF_CMT_EMPTY_INTERVAL_MS / 1000) ))

gaps=()
last_h=$baseline
last_t=$(date +%s)
since_progress=0
while [ "${#gaps[@]}" -lt "$gaps_needed" ]; do
    sleep 1
    now=$(date +%s)
    h=$(stagef_cmt_tip "$ref_db")
    [ -n "$h" ] || h=-1
    if [ "$h" -gt "$last_h" ]; then
        gap=$(( now - last_t ))
        gaps+=("$gap")
        echo "[ok] height $last_h -> $h after ${gap}s idle"
        last_h="$h"
        last_t="$now"
        since_progress=0
    else
        since_progress=$(( since_progress + 1 ))
        if [ "$since_progress" -ge "$stall_budget_s" ]; then
            die "no new block for ${stall_budget_s}s while collecting idle gaps — stalled at height $h (CreateEmptyBlocks did not fire, or this build does not have it on)"
        fi
    fi
done
after=$last_h

for g in "${gaps[@]}"; do
    if [ "$g" -lt "$gap_floor_s" ]; then
        die "idle gap ${g}s is BELOW the ${gap_floor_s}s floor (gaps observed: ${gaps[*]}) — this is the D-4 regression shape: attendance moved system_state_root on an empty block, needProofBlock fired, and the chain committed at the ~4-5s timeout_commit pace instead of the 60s CreateEmptyBlocksInterval"
    fi
done
echo "[PASS-PART] D-4: ${#gaps[@]} consecutive idle gaps, all >= ${gap_floor_s}s: ${gaps[*]} (target ${STAGEF_CMT_EMPTY_INTERVAL_MS}ms)"

# ── Anti-vacuity: every block in the observed window must be EMPTY ───
nonzero=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM v2_blocks WHERE global_height > $baseline \
     AND global_height <= $after AND tx_count <> 0;")
if [ "${nonzero:-0}" != "0" ]; then
    sqlite3 "$ref_db" "SELECT global_height, tx_count FROM v2_blocks \
        WHERE global_height > $baseline AND global_height <= $after;" >&2
    die "$nonzero block(s) in the observed window carried a transaction — this measured demand-driven production, not idle CreateEmptyBlocks"
fi
claim_rows=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM utxo_set WHERE block_height > $baseline AND block_height <= $after;" \
    2>/dev/null || echo 0)
if [ "${claim_rows:-0}" != "0" ]; then
    sqlite3 "$ref_db" "SELECT hex(tx_hash), block_height FROM utxo_set \
        WHERE block_height > $baseline AND block_height <= $after;" >&2
    die "$claim_rows claim UTXO(s) landed inside the observed window — tx_count=0 missed a CLAIM, not idle production"
fi
echo "[ok] every block between $baseline and $after is genuinely empty (tx_count=0, no claim UTXO)"

# ════════════════════════════════════════════════════════════════════
# PART 2 — D-5: a real transaction wakes the round; inclusion latency
# ════════════════════════════════════════════════════════════════════
CLI="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"
keys="$PROBE_DIR/identity"

dry="$BASE_DIR/v2claim_probe_dry.log"
if ! "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF")" \
       v2-claim --config "$CONF" --db "$ref_db" --keys "$keys" --dry-run \
       > "$dry" 2>&1; then
    cat "$dry" >&2
    die "the probe's claim could not be BUILT"
fi
grep -q 'LOCAL ADMIT: OK' "$dry" || {
    cat "$dry" >&2
    die "the probe's claim built but the engine would not admit it"
}
nullifier=$(awk '/^ *nullifier=/{sub(/^ *nullifier=/,""); print}' "$dry")
[ "${#nullifier}" = 128 ] || die "could not read a 64-byte nullifier from the probe's dry-run output"
echo "[ok] probe claim builds and admits locally (nullifier ${nullifier:0:16}...)"

submit_t=$(date +%s)
sub="$BASE_DIR/v2claim_probe_submit.log"
if ! "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF")" \
       v2-claim --config "$CONF" --db "$ref_db" --keys "$keys" \
       --submit "127.0.0.1:$(stagef_tcp_port "$REF")" \
       > "$sub" 2>&1; then
    cat "$sub" >&2
    die "the probe's claim submit was REJECTED (CheckTx admission failed)"
fi
echo "[ok] probe claim APPROVED into the mempool at t=$submit_t"

# Wait for the ROW ITSELF, never "one height past submission" — the same
# discipline test_v2_claim.sh documents at length: CheckTx admission does
# not promise next-block inclusion. Bounded by the chain's own stall
# detection (rc=1) and a second, independent height budget (rc=2).
applied_at_h=$(stagef_cmt_wait_row "$ref_db" \
    "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$nullifier';" 4 20) \
    && wait_rc=0 || wait_rc=$?
included_t=$(date +%s)
latency_s=$(( included_t - submit_t ))
if [ "$wait_rc" = 1 ]; then
    die "the probe claim's utxo_set row never appeared and the chain STALLED at $applied_at_h after ${latency_s}s — CheckTx approved it but it was never applied, or the chain stopped advancing"
elif [ "$wait_rc" = 2 ]; then
    die "the probe claim was not included within 20 heights of submission (dropped, not delayed) — ${latency_s}s elapsed"
fi
echo "[ok] probe claim's UTXO landed at height $applied_at_h — submission-to-inclusion latency: ${latency_s}s"

if [ "$latency_s" -ge 30 ]; then
    die "D-5: submission-to-inclusion latency ${latency_s}s is NOT well under one interval (>= 30s) — this is the shape a NULL txsAvailable callback produces: the claim waited for the next idle-interval tick instead of waking the round immediately"
fi
echo "[PASS-PART] D-5: latency ${latency_s}s, well under the 30s bound (interval is ${STAGEF_CMT_EMPTY_INTERVAL_MS}ms)"

for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    stagef_cmt_wait_height "$(stagef_node_chain_db "$n")" "$applied_at_h" 2 >/dev/null \
        || die "node$n never reached height $applied_at_h (mesh replication stalled)"
done

stagef_sentinel ASSERT_RUN   # the terminal assertion is next
stagef_cmt_diff_at_floor "post-cmt-empty-blocks" || exit 2

stagef_sentinel PASS
echo ""
echo "[PASS] D-4: idle gaps ${gaps[*]}s (floor ${gap_floor_s}s) — attendance does not move"
echo "       the root on an empty block. D-5: probe claim included after ${latency_s}s"
echo "       (bound 30s) — txsAvailable wakes the round instead of waiting for the"
echo "       next interval. All $STAGEF_COMMITTEE_SIZE nodes agree at height $applied_at_h."
echo "       NOT proven here: BFT-time monotonicity — v2_blocks carries no"
echo "       timestamp column on this lane (see this script's header)."
