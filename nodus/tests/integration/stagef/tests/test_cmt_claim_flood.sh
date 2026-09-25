#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_claim_flood.sh — the WHOLE pump batch, one v2-claim call,
# past the retired 16-item cap
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That the engine's per-block CLAIM capacity is no longer the flat
#   16-item bound R3-W3-C2a-19 introduced (`NODUS_V2_APPLY_MAX_OPS`, then
#   16 — the fix for the live defect measured at
#   `/tmp/stagef-20260917T034259Z`, where a 40-claim decided block
#   FAULTED every node's FinalizeBlock). R3 W4 package C moved the
#   engine's per-block claim scratch to the heap, sized by the block's
#   own claim count, and re-derived the claim bound from cometbft's own
#   `MaxBlockSizeBytes` (`NODUS_V2_APPLY_MAX_CLAIMS`, 14 162 — nodus_
#   witness_v2_apply.h) — so a single PrepareProposal call is once again
#   free to pack MORE than 16 claims into ONE block, exactly the shape
#   `test_v2_epoch_boundary.sh`'s header used to describe before the
#   16-cap made it false. The property that would be false if the fix
#   regressed: *a proposer handed a burst of admissible claims well
#   inside its byte and per-class bounds packs more than 16 of them into
#   one block, and every node applies that block identically.*
#
#   ⚠ NOT MEASURED THROUGH `v2_blocks.tx_count`. Exactly like
#   test_cmt_mempool_flood.sh's own DELTA 1 finding: `tx_count` is filled
#   from `n_all`, which counts only APPLIED ENVELOPES
#   (`nodus_witness_v2_apply.c`, phase 13's `all_ids`/`n_all` build,
#   `blk->n_envs` loop) — claims live in a separate array (`blk->
#   claims[]`) that phase never touches, so an all-claims block ALWAYS
#   shows `tx_count = 0`, structurally, whether the fix is present or
#   not. The dispatch that requested this scenario named `tx_count` as
#   the per-block count to assert; that is the wrong column for a
#   claims-only flood and would be permanently RED regardless of this
#   package — READ, not assumed, from the same phase-13 code test_cmt_
#   mempool_flood.sh already cites. The assertion below instead uses
#   `v2_claims_spent.claimed_height` (nodus_witness_v2_schema.c's S6
#   migration, one row per applied claim, with the height it applied at
#   as its own column) — the ledger's own, direct record of "how many
#   claims this ONE block actually carried", the same table t_claim_items
#   (test_cmt_app.c) and test_v2_claim.sh already read claim outcomes
#   from.
#
# WHAT IT REQUIRES
#   Compile flags: none beyond a default build.
#   Environment: none of its own — a cluster from **stagef_up_v2.sh**
#   (Comet lane; on a legacy cluster it exits 99), with the PUMP
#   identity's batch UNTOUCHED (this scenario's whole point is to spend
#   it in one call). Sweep position (genesis_protocol_v2.sh): AFTER
#   test_cmt_mempool_flood.sh, which spends only nodes 4-7's OWN leaves
#   and never the pump batch, and BEFORE test_v2_epoch_boundary.sh, the
#   only other scenario that reaches for the pump batch.
#
# WHAT IT LEAVES BEHIND
#   The PUMP identity's ENTIRE batch (however many leaves this genesis
#   config actually carries — read from `v2_genesis.conf`, never assumed
#   to be the harness's own default of 40) is claimed and spent. Every
#   later scenario that references "the pump batch" (test_cmt_mempool_
#   flood.sh's header, test_v2_epoch_boundary.sh's header) inherits an
#   EMPTY one from this point on in the sweep — both already say so and
#   neither depends on it having leaves left. Nothing is killed or
#   restarted.
#
# HOW IT CAN LIE
#   - **The batch lands in one block only if the CLI submits faster
#     than the chain commits — this is a MEASURED fact, not this
#     scenario's premise.** R3 W4-C delta 4 fixed `nodus-cli.c`'s
#     `cmd_v2_claim --submit` loop to open ONE client session for the
#     whole batch (`t6_submit_on`) instead of one per leaf; with that
#     fix, $n_leaves leaves take well under a block interval (measured
#     above as `v2-claim wall-clock duration`). BEFORE delta 4, each
#     leaf paid its own Kyber1024 handshake + T2 auth (~1 s each per
#     node 1's CLIENT_DISCONNECT log spacing) and the 40-leaf batch
#     spread across FOUR blocks — 26:7, 27:16, 28:15, 29:2
#     (`/tmp/stagef-20260917T231618Z`) — which this scenario's own
#     `max_in_one > 16` assertion would have (and did) misreport as
#     "the retired 16-item cap still binds" or "the fix regressed",
#     when the actual cause was the CLI's per-leaf reconnect pace, not
#     the engine. If this duration ever grows back toward a block
#     interval — a slower node, a bigger batch, a future CLI change
#     that reintroduces a per-item connect — this scenario can fail the
#     same way again for the same non-engine reason; the printed
#     duration is what lets a future reader tell the two apart instead
#     of guessing.
#   - **A single CLI call, not 40 dry-runs.** This scenario does not
#     capture each leaf's own nullifier before submitting (unlike
#     test_cmt_mempool_flood.sh's per-identity dry-run, which is cheap
#     for 3-4 leaves and impractical for 40) — it reads `v2_claims_spent`
#     AFTER submission instead, filtered to `claimed_height >
#     $before_tip`. On a chain where some OTHER scenario is ALSO
#     spending claims concurrently, those rows would be double-counted;
#     this harness runs scenarios sequentially, never concurrently, so
#     that condition does not arise here, but it is a real assumption
#     this script leans on and does not verify.
#   - **"included within 20 heights" is `stagef_cmt_wait_row`'s own
#     default budget, not a number this script chose** — same STALL
#     (rc=1) vs HEIGHT-BUDGET-EXCEEDED (rc=2) distinction every other
#     Comet-lane scenario in this suite makes; neither is distinguished
#     from a genuine silent drop (the same residual test_cmt_mempool_
#     flood.sh's header discloses).
#   - **The per-block wall-clock gap printed below is HARNESS-OBSERVED,
#     not the block's own committed header time.** `cmt_blockstore`
#     stores each block keyed by a binary `H:<n>` key with an opaque
#     encoded VALUE (nodus_witness_v2_schema.c's `cmt_blockstore`
#     table: `key BLOB, value BLOB` — no decodable SQL column), so a
#     bash+sqlite3 harness cannot read the header's `Time` field
#     directly without the C-side codec this script does not have.
#     Instead the inclusion wait below polls `v2_blocks`' tip once per
#     second WHILE it waits and timestamps (`date +%s`) the FIRST poll
#     that observes each new height — a proxy for the inter-block gap,
#     coarsened by the 1-second poll granularity. (ORCHESTRATOR
#     correction of the first draft, which measured AFTER the wait had
#     returned and therefore printed one meaningless line.) Printed for
#     the ORCHESTRATOR to eyeball FinalizeBlock cost per claim; THIS
#     SCENARIO ASSERTS NOTHING ABOUT ANY OF THESE NUMBERS — see the
#     primary objective on flaky timing assertions.
#   - **The inclusion wait is an INLINE copy of stagef_cmt_wait_row's
#     rules** (stall = 3 empty-block intervals with no new height,
#     budget = 20 heights past the submission tip), polled every second
#     instead of every five so the timestamps mean something; the rc=1 /
#     rc=2 distinction is preserved. If the helper's rules change, this
#     loop must change with it.
#   - **rc=99 means the cluster was not Comet, or the pump identity was
#     never generated** — coverage that did not happen, never a pass.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

REF=1
CONF="$BASE_DIR/v2_genesis.conf"
PUMP="$BASE_DIR/v2pump/identity"
CLI="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"

die() { echo "[FAIL] $*" >&2; exit 1; }

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ] || [ ! -f "$CONF" ] || [ ! -s "$PUMP/nodus.pk" ]; then
    echo "[SKIP] not a Comet cluster with a pump identity — use stagef_up_v2.sh"
    exit 99
fi
stagef_sentinel SETUP_OK   # W4-H: the runner turns PASS-without-ASSERT_RUN into FAIL

# The EXACT leaf count this genesis config gave the pump identity — read
# from the config itself, never assumed to be the harness's 40-leaf
# default (STAGEF_V2_PUMP_LEAVES can override it at bring-up).
pump_fp=$(cat "$PUMP/nodus.fp")
n_leaves=$(grep -c "^dest_binding = ${pump_fp}\$" "$CONF" || true)
[ "${n_leaves:-0}" -gt 0 ] || die "no pump leaves found for fingerprint $pump_fp in $CONF"
echo "[ok] pump identity holds $n_leaves genesis leaves (read from $CONF)"

stagef_cmt_diff_at_floor "pre-cmt-claim-flood" || exit 2

before_tip=$(stagef_cmt_tip "$ref_db")

# ── ONE v2-claim call over the WHOLE batch ───────────────────────────
# Unlike test_cmt_mempool_flood.sh (a handful of separate CLI processes,
# one leaf each), a single call here submits every currently-unclaimed
# leaf this identity holds — the exact shape the R3 W3 (C2d) rewrite of
# test_v2_epoch_boundary.sh's header describes as "a v2-claim call over
# the whole pump batch queues every leaf in the mempool before the
# client's own loop finishes submitting them". R3 W4-C delta 4 made this
# TRUE at the CLI level (one client session reused for the whole batch,
# nodus-cli.c's t6_submit_on) instead of merely assumed — before delta 4
# `cmd_v2_claim`'s loop opened a NEW session (Kyber1024 handshake + T2
# auth) per leaf and this call's own wall-clock time is what decides
# whether the batch actually lands together, so it is MEASURED below,
# never assumed (see "HOW IT CAN LIE").
log="$BASE_DIR/cmtclaimflood.log"
submit_start=$(date +%s)
if ! "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF")" v2-claim --config "$CONF" \
       --db "$ref_db" --keys "$PUMP" \
       --submit "127.0.0.1:$(stagef_tcp_port "$REF")" > "$log" 2>&1; then
    cat "$log" >&2
    die "the pump batch submission itself failed (CheckTx or the client)"
fi
submit_end=$(date +%s)
submit_secs=$(( submit_end - submit_start ))
echo "[ok] the whole $n_leaves-leaf pump batch submitted in one v2-claim call"
echo "[info] v2-claim wall-clock duration: ${submit_secs}s for $n_leaves leaves, one session (nodus-cli.c t6_submit_on)"

# ── every leaf's claim applies within the DEFAULT 20-height budget ───
# stagef_cmt_wait_row's boolean-shaped query: "have all $n_leaves of
# THIS submission's claims been recorded". claimed_height > $before_tip
# isolates rows THIS call produced from any earlier scenario's claims,
# without needing $n_leaves individual nullifiers up front (see "HOW IT
# CAN LIE" above for the assumption this leans on).
#
# INLINE wait (see "HOW IT CAN LIE"): the same stall / height-budget
# rules as stagef_cmt_wait_row (stagef_env.sh), polled every 1 s so each
# new height's first observation can be timestamped WHILE waiting.
stall_polls=$(( 3 * (STAGEF_CMT_EMPTY_INTERVAL_MS / 1000) ))   # 180 polls @1s
max_heights=20
wait_rc=0
stall_at="$before_tip"
last_h="$before_tip"
since=0
prev_h="$before_tip"
prev_ts=$(date +%s)
height_log="$BASE_DIR/cmtclaimflood.heights"
: > "$height_log"
echo "[info] harness-observed height timestamps (poll granularity ~1s, NOT header time):"
while :; do
    n_spent=$(sqlite3 "$ref_db" \
        "SELECT COUNT(*) FROM v2_claims_spent WHERE claimed_height > $before_tip;" \
        2>/dev/null || echo 0)
    case "$n_spent" in ''|*[!0-9]*) n_spent=0 ;; esac
    h=$(stagef_cmt_tip "$ref_db")
    [ -n "$h" ] || h="$last_h"
    if [ "$h" -gt "$last_h" ]; then
        now_ts=$(date +%s)
        echo "         height $h observed_at $now_ts gap_since_prev=$(( now_ts - prev_ts ))s (from height $prev_h)"
        echo "$h $now_ts" >> "$height_log"
        prev_h="$h"; prev_ts="$now_ts"; last_h="$h"; since=0
    else
        since=$(( since + 1 ))
    fi
    stall_at="$h"
    if [ "$n_spent" -ge "$n_leaves" ]; then wait_rc=0; break; fi
    if [ "$since" -ge "$stall_polls" ]; then wait_rc=1; break; fi
    if [ $(( h - before_tip )) -gt "$max_heights" ]; then wait_rc=2; break; fi
    sleep 1
done
if [ "${n_spent:-0}" != "$n_leaves" ]; then
    if [ "${wait_rc:-0}" = 1 ]; then
        die "only $n_spent of $n_leaves pump claims applied and the chain STALLED at $stall_at — approved by CheckTx but never actually applied, or the chain stopped advancing"
    elif [ "${wait_rc:-0}" = 2 ]; then
        die "only $n_spent of $n_leaves pump claims were included within 20 heights of submission (tip $before_tip -> $stall_at) — at least one was dropped, not delayed"
    else
        die "only $n_spent of $n_leaves pump claims applied (tip $stall_at)"
    fi
fi
echo "[ok] all $n_leaves pump claims applied within 20 heights (tip $before_tip -> $stall_at)"

# ── the assertion the scenario exists for: some ONE block carried MORE
# than the retired flat 16-item cap ──────────────────────────────────
carrying=$(sqlite3 "$ref_db" \
    "SELECT claimed_height, COUNT(*) FROM v2_claims_spent \
     WHERE claimed_height > $before_tip GROUP BY claimed_height \
     ORDER BY claimed_height;")
max_in_one=0
echo "[info] carrying blocks (height:claims_in_that_block):"
while IFS='|' read -r h c; do
    [ -n "$h" ] || continue
    echo "         $h:$c"
    [ "$c" -gt "$max_in_one" ] && max_in_one="$c"
done <<< "$carrying"
[ "$max_in_one" -gt 16 ] || die \
    "no single block carried more than 16 claims (max was $max_in_one) — the 16-item cap this scenario exists to prove gone still appears to bind; either the fixture's $n_leaves leaves batched across too many rounds to exercise it, or the fix regressed"
echo "[ok] one block carried $max_in_one claims — the retired 16-item cap does not bind claims any more"

# (The harness-observed timestamps were printed by the inclusion wait
# above, one line per new height, while the claims were landing — see
# "HOW IT CAN LIE". Nothing about them is asserted.)

stagef_sentinel ASSERT_RUN   # the terminal assertion is next
stagef_cmt_diff_at_floor "post-cmt-claim-flood" || exit 2

stagef_sentinel PASS
echo ""
echo "[PASS] the whole $n_leaves-leaf pump batch, submitted in ONE v2-claim call,"
echo "       applied within 20 heights (tip $before_tip -> $stall_at); one block carried"
echo "       $max_in_one claims — over the retired 16-item cap; all $STAGEF_COMMITTEE_SIZE nodes agree."
