#!/usr/bin/env bash
#
# Stage F.2 test — epoch-boundary settlement consensus check.
#
# Verifies the v0.16 push-per-epoch settlement pipeline behaves
# deterministically across all harness nodes:
#
#   1. After bring-up + user funding, all N nodes share a state_root.
#   2. Inflation accumulates into epoch_state.epoch_pool_accum; when an
#      epoch boundary fires (block_height % DNAC_EPOCH_LENGTH == 0),
#      apply_epoch_settlement DRAINS that pool into synthetic UTXOs for
#      committee validators + delegators, on every node.
#   3. Post-settlement state_root MUST still be identical 7/7. Any
#      divergence is a Stage E determinism bug.
#
# ── WHY THIS TEST PUMPS TRANSACTIONS (2026-08-27) ────────────────────
#
# It used to `sleep EPOCH_LENGTH*5+30` and then re-compare state_roots.
# That is VACUOUS, and it passed for exactly the wrong reason: this chain
# produces a block only when there is a transaction to put in one. An idle
# harness sits at its current height forever, so the sleep expired, the
# two state_root reads were taken from the SAME committed height, they
# were trivially identical, and the test reported PASS having crossed no
# boundary and settled nothing.
#
# A green light that cannot go red is worse than no test. So this
# scenario now DRIVES the chain across a real boundary and asserts the
# settlement observably happened:
#
#   * the pool was non-empty before the boundary,
#   * a new epoch_state row exists AT the boundary height,
#   * the SETTLED epoch's row is GONE, and
#   * new UTXOs appeared — the synthetic payouts themselves.
#
# ── WHY "GONE" AND NOT "DRAINED TO ZERO" (2026-08-28) ────────────────
#
# The third assertion above used to read the accumulator of the HIGHEST
# epoch_state row before and after, and require it to have DECREASED.
# That measured two different epochs against each other and could
# essentially never pass on a live chain.
#
# Settlement does not zero anything. apply_epoch_settlement pays the
# settling epoch out and then DELETES its row — nodus_witness_bft.c, the
# last statement of that function, whose own comment states the design:
# "only the current epoch carries a live row; previous-epoch snapshot is
# discarded". The caller settles `expected_height - DNAC_EPOCH_LENGTH`,
# i.e. the epoch BEFORE the boundary.
#
# So after the boundary the highest row is the NEW epoch, which has been
# accruing inflation ever since — naturally LARGER than the settled one.
# The old check compared epoch A's accumulator with epoch B's and
# reported "the pool was never pushed out" when both halves had in fact
# worked. Observed 2026-08-28 at DNAC_EPOCH_LENGTH=3: payouts emitted
# (utxo_set 16 -> 22), boundary row committed, and the assertion still
# failed on 3200000000 -> 9600000000, on this tree AND on an untouched
# 11309e06 — because the number it read was never the settled epoch's.
#
# The property the test wants is about the SETTLED epoch, and the file
# already had the right tool for it: epoch_row_at(). It is now used for
# both halves — the new row exists at the boundary, and the settled row
# no longer exists.
#
# The same lesson is already recorded in test_vset_grow_shrink.sh:80-84
# ("A blind sleep cannot do this: with no TXs there are no blocks").
#
# For a run to finish in harness time the binary must carry a SHORT epoch
# (-DDNAC_EPOCH_LENGTH=15) and STAGEF_EPOCH_LENGTH must match it. At the
# production 720 this needs 720 blocks and is a ~1h scenario; the test
# still runs, it just takes that long.
#
# Requires an active Stage F harness (stagef_up.sh).
#
# Exit codes:
#   0 = all consensus checks passed
#   1 = no active harness
#   2 = state_root diverged pre-settlement
#   3 = state_root diverged post-settlement
#   4 = settlement did not fire within the expected block window

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

EPOCH_LENGTH="${STAGEF_EPOCH_LENGTH:-720}"
PUMP_LOG="$BASE_DIR/settlement_pump.log"

info() { echo "[info] $*"; }
ok()   { echo "[ok] $*"; }
fail() { echo "[FAIL] $*" >&2; exit "${2:-4}"; }

node1_db()    { stagef_node_chain_db 1; }
head_height() {
    sqlite3 "$(node1_db)" "SELECT COALESCE(MAX(height),0) FROM blocks;"
}
utxo_count()  {
    sqlite3 "$(node1_db)" "SELECT COUNT(*) FROM utxo_set;"
}
# The accumulator of ONE named epoch. Never "the highest row" — that
# identity moves across a boundary, which is exactly how the old drain
# check ended up comparing two different epochs (see the header).
pool_accum_at() {
    sqlite3 "$(node1_db)" \
        "SELECT COALESCE(epoch_pool_accum,0) FROM epoch_state
         WHERE epoch_start_height = $1;"
}
epoch_row_at() {
    sqlite3 "$(node1_db)" \
        "SELECT COUNT(*) FROM epoch_state WHERE epoch_start_height = $1;"
}

# Drive the chain to >= $1 by submitting one minimal TX per block.
# Ported verbatim in spirit from test_vset_grow_shrink.sh's
# `pump_to_height` — including
# the unconditional `dna sync` before every send, which is what keeps the
# wallet from deadlocking on an in-flight change output when a BFT round
# retries (feedback_dnac_sync_between_sends).
pump_to_height() {
    local target="$1" timeout="${2:-600}"
    local deadline=$(( SECONDS + timeout ))
    local h; h=$(head_height)
    local sink; sink=$(cat "$BASE_DIR/node1/identity/nodus.fp")
    while [ "${h:-0}" -lt "$target" ] && [ $SECONDS -lt $deadline ]; do
        stagef_dna -q dna sync >> "$PUMP_LOG" 2>&1 || true
        if ! stagef_dna -q dna send "$sink" 1 "pump" >> "$PUMP_LOG" 2>&1; then
            stagef_dna -q dna sync >> "$PUMP_LOG" 2>&1 || true
            stagef_dna -q dna send "$sink" 1 "pump" >> "$PUMP_LOG" 2>&1 || true
        fi
        sleep 6
        h=$(head_height)
    done
    [ "${h:-0}" -ge "$target" ] || \
        fail "pump: height $h < $target (timeout ${timeout}s)" 4
    info "pumped to height $h (target $target)"
}

# ── Baseline: all nodes agree ─────────────────────────────────────────
bash "$(dirname "$0")/../stagef_diff.sh" "pre-settlement" || exit 2

H0=$(head_height)
info "epoch length: $EPOCH_LENGTH · head height: $H0"

# The next boundary strictly above the current head, plus two blocks so
# the settling block is itself committed and observable.
BOUNDARY=$(( ( H0 / EPOCH_LENGTH + 1 ) * EPOCH_LENGTH ))
TARGET=$(( BOUNDARY + 2 ))
# The epoch that SETTLES at that boundary is the one before it — the
# caller passes `expected_height - DNAC_EPOCH_LENGTH` to
# apply_epoch_settlement. This is the row the assertions below name.
SETTLING=$(( BOUNDARY - EPOCH_LENGTH ))
info "next epoch boundary: $BOUNDARY (pumping to $TARGET) · settling epoch starts at $SETTLING"

# ── The pool must be non-empty, or the boundary settles nothing ───────
[ "$(epoch_row_at "$SETTLING")" -eq 1 ] || \
    fail "no epoch_state row at $SETTLING — there is no epoch to settle
       at boundary $BOUNDARY, so crossing it would prove nothing" 4
POOL_BEFORE=$(pool_accum_at "$SETTLING")
info "epoch_pool_accum of the settling epoch ($SETTLING) before: $POOL_BEFORE"
[ "${POOL_BEFORE:-0}" -gt 0 ] || \
    fail "epoch_pool_accum is 0 before the boundary — nothing to settle,
       so crossing it would prove nothing. Inflation is not accruing." 4

UTXO_BEFORE=$(utxo_count)
info "utxo_set rows before: $UTXO_BEFORE"

# ── Cross a REAL boundary ─────────────────────────────────────────────
echo ""
echo "== Pumping to height $TARGET to cross the epoch boundary at $BOUNDARY =="
# Budget per block, measured rather than assumed: one pump iteration is
# `dna sync` + `dna send` (two client round trips, each waiting on a BFT
# round) plus a 6 s settle, which lands around 30 s per block on the
# 7-node localhost harness — not the 6 s the sleep alone suggests. The
# first version of this test budgeted 12 s/block and died at height 10 of
# 17 with the chain healthy and advancing. 45 s/block leaves headroom for
# a round that has to be retried without hiding a chain that has actually
# stopped: a genuinely wedged chain still fails, just later.
PUMP_TIMEOUT=$(( ( TARGET - H0 ) * 45 + 180 ))
pump_to_height "$TARGET" "$PUMP_TIMEOUT"

# ── The boundary must have FIRED ──────────────────────────────────────
[ "$(epoch_row_at "$BOUNDARY")" -eq 1 ] || \
    fail "no epoch_state row at height $BOUNDARY — the boundary did not
       fire even though the chain passed it" 4
ok "epoch boundary $BOUNDARY fired (epoch_state row committed)"

# ── Settlement must have RETIRED the settled epoch and PAID OUT ───────
UTXO_AFTER=$(utxo_count)
info "utxo_set rows after: $UTXO_AFTER"

[ "${UTXO_AFTER:-0}" -gt "${UTXO_BEFORE:-0}" ] || \
    fail "utxo_set did not grow across the boundary ($UTXO_BEFORE ->
       $UTXO_AFTER) — apply_epoch_settlement emitted no synthetic payout" 4
ok "settlement emitted payouts (utxo_set $UTXO_BEFORE -> $UTXO_AFTER)"

# The settled epoch's row is DELETED, not zeroed — see the header. This
# is the assertion that fails if apply_epoch_settlement never ran for
# this boundary, and it names ONE epoch so it cannot be satisfied by a
# different, later row.
[ "$(epoch_row_at "$SETTLING")" -eq 0 ] || \
    fail "epoch_state row at $SETTLING still exists after the boundary at
       $BOUNDARY — the settlement did not retire the epoch it paid out
       (its accumulator still reads $(pool_accum_at "$SETTLING"))" 4
ok "settled epoch $SETTLING retired (had $POOL_BEFORE, row now gone)"

# ── Post-settlement: state_root MUST still match across all nodes ─────
bash "$(dirname "$0")/../stagef_diff.sh" "post-settlement" || exit 3

echo ""
echo "[PASS] epoch settlement fired at $BOUNDARY, paid out, and left"
echo "       state_root identical across all nodes"
