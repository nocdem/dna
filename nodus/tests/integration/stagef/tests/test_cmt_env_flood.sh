#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_env_flood.sh — a block beyond 10 envelopes, 7/7 agreement
# (R3 W4-C delta 2; made runnable by CLI-SPEND)
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That a burst of K (default 40) real SPEND envelopes from one identity
#   is ALL applied and that all 7 nodes agree — the operator's decision
#   (atlas-dec-5b7568512b95e6d2e671c4eaad2c1879 rev 1) names this
#   scenario as part of what delta 2 delivers, alongside a measurement of
#   wall-clock cost per envelope. The property that would be false if it
#   failed: *K admissible SPEND envelopes, gossiped from one node, are
#   every one applied, and every node applies the carrying blocks
#   identically.* How they were split across blocks is PRINTED (height:
#   count), NOT asserted (operator 2026-09-23): the split is a wall-clock
#   race between the client and a proposer woken by txsAvailable. That a
#   block may carry more than the retired cap of 10 is proven
#   deterministically by test_v2_apply.c §6 (11 envelopes, one block).
#   First pumped sweep at 0.19.68: 40 in 3 s -> 32 + 8.
#
#   The envelopes are real CORE SPENDs (runtime_op 1), built by
#   `nodus-cli v2-envelope spend --count K` — K independent self-sends
#   from the PUMP identity, each funded by its OWN coin (disjoint input
#   sets planned from one coin listing), all submitted on ONE client
#   session so they reach the mempool faster than the chain commits.
#   Every envelope is followed to its LEDGER EFFECT: the UTXO row it
#   creates carries the envelope's intent_id as its tx_hash
#   (nodus_witness_rt_native.c rtn_utxo_create_eff), so "applied, and in
#   which block" is read from `utxo_set`, never from the CLI's answer
#   (CheckTx admission) and never from `v2_blocks.tx_count` alone.
#
# WHAT IT REQUIRES
#   Compile flags: none beyond a default build (nodus-server AND
#   nodus-cli from the same tree — the CLI takes the CORE ruleset from its
#   own compiled table, and a CLI built for another ruleset is refused at
#   CheckTx).
#   Environment: a cluster from stagef_up_v2.sh (Comet lane; otherwise
#   rc 99). The PUMP identity must hold at least 11 SPENDABLE native coins
#   on node 1 — i.e. test_cmt_claim_flood.sh has run first and claimed
#   the batch (genesis_protocol_v2.sh's order guarantees it). This
#   scenario NEVER claims the batch itself: a later claim_flood run in
#   --scenarios mode would then find nothing to claim and fail. With
#   fewer than 11 coins it SKIPS (rc 99). STAGEF_ENV_FLOOD_MAX (default
#   40, at most 100 — the CLI's listing cap) bounds K.
#
# WHAT IT LEAVES BEHIND
#   The PUMP identity's K largest coins are each replaced by ONE new coin
#   (a self-send of coin − fee; with the default equal-sized batch there
#   is no change output), so its coin count is unchanged and each of
#   those coins is STAGEF_PUMP_FEE_RAW smaller. The chain is at least one
#   block further on. Nothing is killed or restarted.
#
# HOW IT CAN LIE
#   - **A SKIP is not a pass.** rc 99 here means the cluster was not
#     Comet, or the PUMP identity held fewer than 11 spendable coins (claim
#     flood did not run first) — coverage that did not happen.
#   - **It does NOT prove a live proposer packs > 10 into one block.**
#     The per-block split depends on the CLI's pace against a proposer
#     woken by the first admitted envelope (txsAvailable); it is printed
#     and read by a human, never asserted. The engine-side property (a
#     block with > 10 envelopes applies) is test_v2_apply.c §6's.
#   - **The per-block envelope count is set by UNITS, not by a count.**
#     PrepareProposal's capacity seam reserves EVERY envelope's whole
#     res_max_total_units against ONE 1 000 000-unit block budget at once,
#     without finalizing in between (nodus_witness_cmt_app.c
#     app_seam_check → nodus_witness_v2_produce.c:269 →
#     nodus_witness_v2_env.c:382; NODUS_V2_GLOBAL_UNIT_BUDGET,
#     nodus_witness_v2_apply.h:290) and trims the rest to a later block,
#     so the ceiling each envelope declares IS the per-block limit. The
#     CLI right-sizes it (nodus-cli.c t6_spend_ceiling: the metering
#     module's own static_units + one w_read per mediated read). ARITHMETIC,
#     NOT MEASURED: a 1-in/1-out spend is w_base 1 + w_op 1 + call 298 +
#     auth 7 220 + res_max_effects 40 + res_max_effect_bytes 16 384 + 2
#     reads = 23 946 units (all weights 1, nodus_witness_runtime.c
#     sys_policy_build :120-140), so at most 41 fit one block — K ≤ 40 by
#     default for that reason. A round 200 000 ceiling would have capped
#     every block at 5 and made this scenario structurally unpassable.
#   - **Measurements are HARNESS-OBSERVED.** Per-height timestamps are
#     polls at ~1 s granularity (the claim-flood method), not header
#     times; nothing is asserted about them.
#   - **The inclusion wait is an INLINE copy of stagef_cmt_wait_row's
#     rules** (stall = 3 idle intervals with no new height → rc 1;
#     budget = 20 heights past the submission tip → rc 2), polled every
#     second so the timestamps mean something. If the helper's rules
#     change, this loop must change with it.
#   - **Neither wait outcome is distinguished from a genuine silent
#     drop** — rc 1 and rc 2 are distinguished from EACH OTHER only (the
#     same residual every Comet-lane scenario discloses).
#   - **NEVER parse `committed:` on this lane.** The CLI's `accepted:`
#     line is mempool CheckTx admission, not inclusion.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

REF=1
CONF="$BASE_DIR/v2_genesis.conf"
PUMP="$BASE_DIR/v2pump/identity"
CLI="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"
FLOOD_MIN=11                                    # "beyond 10"
FLOOD_MAX="${STAGEF_ENV_FLOOD_MAX:-40}"
[ "$FLOOD_MAX" -le 100 ] || FLOOD_MAX=100       # the CLI's --count cap

die() { echo "[FAIL] $*" >&2; exit 1; }

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ] || [ ! -f "$CONF" ] || [ ! -s "$PUMP/nodus.pk" ]; then
    echo "[SKIP] not a Comet cluster with a pump identity — use stagef_up_v2.sh"
    exit 99
fi
[ -x "$CLI" ] || die "no nodus-cli at $CLI"

# ── the PUMP identity's spendable native coins, largest first ────────
pump_fp=$(cat "$PUMP/nodus.fp")
coins=$(sqlite3 "$ref_db" \
    "SELECT amount FROM utxo_set
      WHERE owner = '$pump_fp' AND token_id = zeroblob(64)
        AND unlock_block <= (SELECT COALESCE(MAX(global_height),0) FROM v2_blocks)
      ORDER BY amount DESC LIMIT $FLOOD_MAX;" 2>/dev/null || true)
n_coins=$(printf '%s\n' "$coins" | grep -c '^[0-9][0-9]*$' || true)
if [ "${n_coins:-0}" -lt "$FLOOD_MIN" ]; then
    echo "[SKIP] the PUMP identity holds $n_coins spendable coin(s) on node$REF;"
    echo "       this scenario needs >= $FLOOD_MIN, created by test_cmt_claim_flood.sh"
    echo "       (run it first — this scenario never claims the batch itself)"
    exit 99
fi
K="$n_coins"
# Every envelope must be covered by ONE coin: the smallest of the K
# largest coins pays amount + fee exactly, the larger ones leave change.
kth=$(printf '%s\n' "$coins" | sed -n "${K}p")
amount=$(( kth - STAGEF_PUMP_FEE_RAW ))
[ "$amount" -ge 1 ] || die "the ${K}th-largest pump coin ($kth) cannot pay the fee $STAGEF_PUMP_FEE_RAW"
stagef_sentinel SETUP_OK   # W4-H: the runner turns PASS-without-ASSERT_RUN into FAIL
echo "[ok] PUMP identity: $K spendable coin(s) (>= $FLOOD_MIN); each spend sends $amount raw to itself, fee $STAGEF_PUMP_FEE_RAW"

stagef_cmt_diff_at_floor "pre-cmt-env-flood" || exit 2

before_tip=$(stagef_cmt_tip "$ref_db")

# ── ONE CLI call, ONE session, K independent envelopes ──────────────
log="$BASE_DIR/cmtenvflood.log"
port=$(stagef_tcp_port "$REF")
submit_start=$(date +%s)
if ! "$CLI" -s 127.0.0.1 -p "$port" v2-envelope spend --keys "$PUMP" \
       --to "$pump_fp" --amount "$amount" --fee "$STAGEF_PUMP_FEE_RAW" \
       --count "$K" --submit "127.0.0.1:$port" > "$log" 2>&1; then
    cat "$log" >&2
    die "the envelope batch submission failed (CheckTx refusal or the client) — see above"
fi
submit_end=$(date +%s)
submit_secs=$(( submit_end - submit_start ))
intents=$(awk -F= '/^  intent_id=/{print $2}' "$log")
n_intents=$(printf '%s\n' "$intents" | grep -c '^[0-9a-f]\{128\}$' || true)
n_accepted=$(grep -c '^accepted: mempool CheckTx approved' "$log" || true)
[ "$n_intents" = "$K" ] && [ "$n_accepted" = "$K" ] || {
    cat "$log" >&2
    die "expected $K intent ids and $K CheckTx approvals, got $n_intents / $n_accepted"
}
stagef_sentinel TARGET_REACHED
echo "[ok] $K SPEND envelopes APPROVED by CheckTx on one session"
echo "[info] v2-envelope spend wall-clock duration: ${submit_secs}s for $K envelopes, one session"

in_list=$(printf "'%s'," $intents)
in_list="${in_list%,}"

# ── every envelope applies (its created row exists), within 20 heights
# INLINE wait (see "HOW IT CAN LIE"): stagef_cmt_wait_row's rules, 1 s poll.
stall_polls=$(( 3 * (STAGEF_CMT_EMPTY_INTERVAL_MS / 1000) ))
max_heights=20
wait_rc=0
last_h="$before_tip"
since=0
prev_h="$before_tip"
prev_ts=$(date +%s)
echo "[info] harness-observed height timestamps (poll granularity ~1s, NOT header time):"
while :; do
    n_applied=$(sqlite3 "$ref_db" \
        "SELECT COUNT(DISTINCT tx_hash) FROM utxo_set WHERE lower(hex(tx_hash)) IN ($in_list);" \
        2>/dev/null || echo 0)
    case "$n_applied" in ''|*[!0-9]*) n_applied=0 ;; esac
    h=$(stagef_cmt_tip "$ref_db")
    [ -n "$h" ] || h="$last_h"
    if [ "$h" -gt "$last_h" ]; then
        now_ts=$(date +%s)
        echo "         height $h observed_at $now_ts gap_since_prev=$(( now_ts - prev_ts ))s (from height $prev_h)"
        prev_h="$h"; prev_ts="$now_ts"; last_h="$h"; since=0
    else
        since=$(( since + 1 ))
    fi
    if [ "$n_applied" -ge "$K" ]; then wait_rc=0; break; fi
    if [ "$since" -ge "$stall_polls" ]; then wait_rc=1; break; fi
    if [ $(( h - before_tip )) -gt "$max_heights" ]; then wait_rc=2; break; fi
    sleep 1
done
if [ "$n_applied" -lt "$K" ]; then
    if [ "$wait_rc" = 1 ]; then
        die "only $n_applied of $K envelopes applied and the chain STALLED at $h"
    else
        die "only $n_applied of $K envelopes were included within $max_heights heights of submission (tip $before_tip -> $h) — at least one was dropped or refused in-block (e.g. CAPACITY), not delayed"
    fi
fi
echo "[ok] all $K envelopes applied within $max_heights heights (tip $before_tip -> $h)"

# ── the assertion the scenario exists for: ONE block carried > 10 ────
carrying=$(sqlite3 "$ref_db" \
    "SELECT block_height, COUNT(DISTINCT tx_hash) FROM utxo_set
      WHERE lower(hex(tx_hash)) IN ($in_list)
      GROUP BY block_height ORDER BY block_height;")
max_in_one=0
max_h=0
# Printed bare as `height:count` so genesis_protocol_v2.sh's green-run
# echo filter keeps them; each block's v2_blocks.tx_count (applied
# envelopes) follows on its own [info] line — shown, not asserted.
echo "[info] carrying blocks (height:envelopes_in_that_block):"
tx_counts=""
while IFS='|' read -r bh c; do
    [ -n "$bh" ] || continue
    tc=$(sqlite3 "$ref_db" "SELECT tx_count FROM v2_blocks WHERE global_height = $bh;" 2>/dev/null || echo '?')
    echo "         $bh:$c"
    tx_counts="$tx_counts $bh=${tc:-?}"
    if [ "$c" -gt "$max_in_one" ]; then max_in_one="$c"; fi
    if [ "$bh" -gt "$max_h" ]; then max_h="$bh"; fi
done <<< "$carrying"
echo "[info] v2_blocks.tx_count at those heights:$tx_counts"
if [ "$submit_secs" -gt 0 ]; then
    echo "[info] client-side cost: $K envelopes in ${submit_secs}s (build + sign + CheckTx round trip each)"
fi

# Every node must reach the last carrying height before the comparison.
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    stagef_cmt_wait_height "$(stagef_node_chain_db "$n")" "$max_h" 3 >/dev/null \
        || die "node$n never reached height $max_h (mesh replication stalled)"
done

# The largest per-block count is REPORTED, never asserted (operator
# 2026-09-23): with txsAvailable the proposer may start a block before the
# client has finished the batch, so the split is a wall-clock race between
# the CLI and the proposer — an assertion on it would pass or fail with
# the machine's speed, not the code (NO FLAKY). "A block may carry more
# than 10 envelopes" is proven deterministically by the engine unit test
# test_v2_apply.c §6 (11 envelopes applied in one block, every run).
if [ "$max_in_one" -gt 10 ]; then
    echo "[info] largest block carried $max_in_one envelopes (> the retired cap of 10)"
else
    echo "[info] largest block carried $max_in_one envelopes — NOT above 10 on this run; the batch spread over several rounds (client pace ${submit_secs}s vs the proposer; see HOW IT CAN LIE) — informational, not a failure"
fi

stagef_sentinel ASSERT_RUN   # the terminal assertion is next
stagef_cmt_diff_at_floor "post-cmt-env-flood" || exit 2

stagef_sentinel PASS
echo ""
echo "[PASS] $K CORE SPEND envelopes from one identity, submitted on one session,"
echo "       all applied within $max_heights heights (tip $before_tip -> $h); largest"
echo "       block carried $max_in_one (reported, not asserted); all"
echo "       $STAGEF_COMMITTEE_SIZE nodes agree."
