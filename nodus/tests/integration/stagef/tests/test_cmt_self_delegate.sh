#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_self_delegate.sh — a genesis validator delegates to ITSELF,
# and its voting power grows by exactly that amount (final pre-testnet
# wipe, package W-B)
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   Decision docs/plans/decisions/2026-09-28-treasury-pools-and-exact-
#   self-stake.md item 6 ("Kendine delegasyon serbest … bu miktar
#   sıralamaya ve oy gücüne eklenir"), end to end on a REAL seven-node
#   cometbft cluster:
#   (1) Node 1 — a GENESIS validator — submits a DELEGATE envelope whose
#       delegator and target are BOTH its own key (`nodus-cli v2-envelope
#       delegate --validator <its own pubkey>`). CheckTx admits it and the
#       chain applies it: the envelope's v2_intent_index row exists (a
#       refused item's identity rows roll back with it,
#       nodus_witness_v2_apply.c), before the old Rule S this was a
#       VERDICT refusal.
#   (2) On ALL SEVEN nodes the delegation row (node1 → node1) holds the
#       amount, and node 1's validators row moved total_delegated AND
#       external_delegated by exactly AMOUNT while self_stake stayed
#       exactly 10M (the exact self-bond, decision item 5).
#   (3) The frozen balance copy of the first boundary after it,
#       copy(nb) with nb = ceil(h/E)·E, holds node 1's bond AND its
#       self-delegation as TWO rows — (owner = node 1, kind 0) =
#       10^15 and (owner = node 1, kind 1) = AMOUNT — identically on all
#       seven nodes (the copy is out of every root, so this is compared
#       explicitly; before W-B the two rows collided on the copy's
#       primary key and EVERY node would have halted at that boundary).
#   (4) Node 1's total_stake in snapshot(nb + 2E) — the first set built
#       from copy(nb) (nodus_witness_v2_epoch.h nodus_v2_power_exit_
#       boundary, "okuma B") — equals its total_stake in snapshot(nb + E)
#       plus EXACTLY AMOUNT, identically on all seven nodes: the
#       self-delegation counts toward ranking and voting power
#       (total_stake / DNAC_DECIMAL_UNIT is the power cometbft is told).
#   (5) state_root agrees 7/7 at the floor afterwards.
#   The property that would be false if it failed: *a validator's
#   delegation to itself is an ordinary delegation — admitted, stored,
#   frozen apart from its bond, and counted in its power — on every node
#   alike.*
#
# WHAT IT REQUIRES
#   ⚠ A SHORT-EPOCH BINARY, exported BEFORE stagef_up_v2.sh, or it skips
#   (rc 99):
#     compile: -DDNAC_EPOCH_LENGTH=<E> (15 is the harness convention)
#     env:     STAGEF_EPOCH_LENGTH=<E> matching it.
#   It must reach nb + E (up to three epochs past the delegation); the
#   CLI-SPEND pump (nodus-cli + node 3's genesis leaf, stagef_env.sh)
#   makes that feasible at E = 15 — idle production alone (60 s per
#   block) is over STAGEF_EPOCH_BOUNDARY_BUDGET_S (default 1800, the SKIP
#   feasibility budget shared with test_v2_rewards.sh — never a wait
#   bound) and skips. At the shipped E = 720 it always skips.
#   A cluster from THIS tree's stagef_up_v2.sh, and a nodus-cli from the
#   same tree (the `v2-envelope delegate` builder is W-B; an older CLI
#   prints its usage and the build step FAILS, loudly). No fault-injection
#   environment. No STAGEF_* variable of its own.
#   FUNDING: node 1's own coins. Node 1's genesis leaf (100M NODUS) is
#   claimed here if node 1 does not already hold AMOUNT + a fee margin —
#   test_cmt_token_create.sh, earlier in the sweep, ordinarily already
#   claimed it (and claims it itself if this ran first).
#
# WHAT IT LEAVES BEHIND
#   AMOUNT (1M NODUS) of node 1's coins bonded as a self-delegation that
#   stays (node 1's power is 11M NODUS worth from snapshot(nb + 2E) on;
#   its reward share grows accordingly — test_v2_rewards.sh checks pool
#   → accrual conservation and membership, never per-node amounts, so it
#   is unaffected). Node 1's genesis leaf claimed if it was not already.
#   The chain two to three epochs further on; one STAGEF_PUMP_FEE_RAW
#   per pump step moved from node 3's coin into the reward pool; node 3's
#   leaf claimed if no earlier pump did. Nothing killed or restarted.
#   Placed BEFORE test_cmt_rule_n_retire.sh (which retires node 7) —
#   node 1 must be a seated member of both compared snapshots.
#
# HOW IT CAN LIE
#   - **Epoch length E, not 720.** This proves the LOGIC of the path
#     (admission, storage, the copy's kind split, the power lift) at E; it
#     says nothing about behaviour that depends on the magnitude of E.
#   - **A second run on the same cluster tops the row up instead of
#     opening it.** The row and power assertions are written as deltas
#     from the values read BEFORE the submission, so a top-up still
#     proves (1), (2) and (4); only (3)'s kind-1 amount is then the
#     running total, which is what it asserts (row amount after).
#   - **If another envelope delegated to node 1 between the two
#     snapshots, (4)'s delta would include it.** Nothing else in the
#     sweep delegates (this is the only DELEGATE builder user); the
#     scenario checks node 1's live delegated total moved by exactly
#     AMOUNT across its own window as a guard.
#   - **Membership is read from the chain.** If node 1 is not seated in
#     either compared snapshot (seat target 32, so every ACTIVE tenured
#     validator is seated — tokenomics-v3 P3), the run FAILS rather than
#     comparing nothing.
#   - **NEVER parse `committed: height=`, NEVER key on `wire_id`** — the
#     same traps test_v2_stake.sh's header documents; inclusion is the
#     SUBMIT's intent_id in v2_intent_index, waited for with the
#     stall/height bounds of stagef_cmt_wait_row.
#   - **rc=99 means the coverage did not happen.** Never a pass.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

REF=1
NODE=1                                   # the self-delegating validator
CONF="$BASE_DIR/v2_genesis.conf"
CLI="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"
E_LEN="${STAGEF_EPOCH_LENGTH:-720}"
IDLE_S=$(( STAGEF_CMT_EMPTY_INTERVAL_MS / 1000 ))
AMOUNT=100000000000000                   # 1M NODUS (>= DNAC_MIN_DELEGATION)
SELF_BOND=1000000000000000               # DNAC_SELF_STAKE_AMOUNT, exact
MARGIN=100000000000                      # 1 000 NODUS of fee headroom
VSET_HDR=78                              # shared/dnac/vset_wire.h
VSET_ENTRY=2642
VSET_TOTAL_OFF=2624                      # voter_id 32 + pubkey 2592

die() { echo "[FAIL] $*" >&2; exit 1; }

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
has_kind=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM pragma_table_info('v2_balance_copy') WHERE name='kind';" \
    2>/dev/null || echo 0)
if [ "${has_kind:-0}" = "0" ] || [ ! -f "$CONF" ]; then
    echo "[SKIP] not a W-B Ledger V2 cluster (no v2_balance_copy.kind / no $CONF) — use this tree's stagef_up_v2.sh"
    exit 99
fi

KEYS="$(stagef_node_dir "$NODE")/identity"
[ -s "$KEYS/nodus.pk" ] && [ -s "$KEYS/nodus.fp" ] || die "node$NODE has no identity"
PK=$(xxd -p -c 99999 "$KEYS/nodus.pk")
FP=$(cat "$KEYS/nodus.fp")
[ "${#PK}" = 5184 ] && [ "${#FP}" = 128 ] || die "node$NODE's key or fingerprint has the wrong length"
VOTER="${FP:0:64}"
port=$(stagef_tcp_port "$REF")

# ── pace and feasibility (a PURE check, nothing submitted yet) ───────
pace="idle"
per_block_s="$IDLE_S"
if stagef_cmt_pump_ready "$ref_db"; then
    pace="pumped"
    per_block_s="$STAGEF_CMT_PUMP_BLOCK_S"
fi
head0=$(stagef_cmt_tip "$ref_db")
# the delegation lands at some h > head0; the worst case is h one block
# past a boundary, so nb + E <= head0 + 3E
need=$(( 3 * E_LEN + 2 ))
worst_case_s=$(( need * per_block_s + 4 * IDLE_S ))
STAGEF_EPOCH_BOUNDARY_BUDGET_S="${STAGEF_EPOCH_BOUNDARY_BUDGET_S:-1800}"
if [ "$worst_case_s" -gt "$STAGEF_EPOCH_BOUNDARY_BUDGET_S" ]; then
    echo "[SKIP] snapshot(nb + 2E) is up to $need blocks away (epoch length $E_LEN);"
    echo "       the worst-case $pace wait is ${worst_case_s}s, over this harness's"
    echo "       ${STAGEF_EPOCH_BOUNDARY_BUDGET_S}s patience budget — needs -DDNAC_EPOCH_LENGTH=15 +"
    echo "       STAGEF_EPOCH_LENGTH=15 and the CLI-SPEND pump"
    exit 99
fi
stagef_sentinel SETUP_OK   # W4-H: the runner turns PASS-without-ASSERT_RUN into FAIL
echo "[ok] epoch length $E_LEN, head $head0, pace $pace (worst case ${worst_case_s}s)"

# node 1 must be a BONDED genesis validator (ACTIVE 0 or ELIGIBLE 4 —
# the DELEGATE target rule) holding exactly the self-bond
vrow=$(sqlite3 "$ref_db" "SELECT status || '|' || self_stake || '|' || active_since_block
                            FROM validators WHERE lower(hex(pubkey)) = '$PK';" 2>/dev/null || true)
case "$vrow" in
    0\|$SELF_BOND\|*|4\|$SELF_BOND\|*) ;;
    *) die "node$NODE is not a bonded validator holding exactly $SELF_BOND (row: '${vrow:-absent}')" ;;
esac
asb="${vrow##*|}"
[ "$asb" -le 1 ] || die "node$NODE is not a GENESIS validator (active_since_block $asb)"
echo "[ok] node$NODE is a bonded genesis validator with exactly the 10M self-bond"

stagef_cmt_diff_at_floor "pre-cmt-self-delegate" || exit 2

spendable() {
    sqlite3 "$ref_db" \
        "SELECT COALESCE(SUM(amount),0) FROM (SELECT amount FROM utxo_set
          WHERE owner = '$FP' AND token_id = zeroblob(64)
            AND unlock_block <= (SELECT COALESCE(MAX(global_height),0) FROM v2_blocks)
          ORDER BY amount DESC LIMIT 14);" 2>/dev/null || echo 0
}

# ── Stage 0: fund node 1 from its OWN leaf (if needed) ───────────────
have=$(spendable)
want=$(( AMOUNT + MARGIN ))
if [ "$have" -lt "$want" ]; then
    grep -q "^dest_binding = ${FP}\$" "$CONF" \
        || die "node$NODE holds $have raw spendable (< $want) and the genesis config binds no leaf to it"
    fdry="$BASE_DIR/selfdeleg_claim_dry.log"
    if ! "$CLI" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$ref_db" \
           --keys "$KEYS" --dry-run > "$fdry" 2>&1; then
        cat "$fdry" >&2; die "node$NODE's funding claim could not be BUILT (local self-check failed)"
    fi
    fund_nullifier=$(awk '/^ *nullifier=/{sub(/^ *nullifier=/,""); print}' "$fdry")
    [ "${#fund_nullifier}" = 128 ] || die "could not read a 64-byte nullifier from the funding claim's dry-run"
    flog="$BASE_DIR/selfdeleg_claim.log"
    if ! "$CLI" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$ref_db" \
           --keys "$KEYS" --submit "127.0.0.1:$port" > "$flog" 2>&1; then
        cat "$flog" >&2; die "node$NODE's funding claim was REJECTED (CheckTx) — was its leaf already claimed and spent?"
    fi
    fh=$(stagef_cmt_wait_row "$ref_db" \
        "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$fund_nullifier';" 4) \
        && fwrc=0 || fwrc=$?
    [ "$fwrc" = 1 ] && die "node$NODE's funding claim never appeared and the chain STALLED at $fh"
    [ "$fwrc" = 2 ] && die "node$NODE's funding claim was not included within 20 heights (tip $fh) — dropped, not delayed"
    have=$(spendable)
    [ "$have" -ge "$want" ] || die "node$NODE still holds only $have raw spendable after claiming its leaf (need $want)"
    echo "[ok] node$NODE funded by its own genesis leaf ($have raw spendable, tip $fh)"
else
    echo "[ok] node$NODE already holds $have raw spendable (>= $want) — no claim needed"
fi

# ── the BEFORE values (deltas, so a re-run's top-up still proves) ────
deleg_before=$(sqlite3 "$ref_db" \
    "SELECT COALESCE(SUM(amount),0) FROM delegations
      WHERE lower(hex(delegator_pubkey)) = '$PK' AND lower(hex(validator_pubkey)) = '$PK';" \
    2>/dev/null || echo ERR)
tot_before=$(sqlite3 "$ref_db" \
    "SELECT total_delegated || '|' || external_delegated FROM validators
      WHERE lower(hex(pubkey)) = '$PK';" 2>/dev/null || echo ERR)
case "$deleg_before|$tot_before" in *ERR*|*'||'*) die "could not read node$NODE's delegation state" ;; esac

# ── Stage 1: the self-delegation ─────────────────────────────────────
dlog="$BASE_DIR/selfdeleg_envelope_dry.log"
if ! "$CLI" -s 127.0.0.1 -p "$port" v2-envelope delegate \
       --keys "$KEYS" --validator "$PK" --amount "$AMOUNT" --dry-run > "$dlog" 2>&1; then
    cat "$dlog" >&2
    die "the self-DELEGATE envelope could not be BUILT (self-check against node $REF failed)"
fi
grep -q 'PREFLIGHT SELF-CHECK: OK' "$dlog" \
    || { cat "$dlog" >&2; die "the delegate dry run printed no self-check verdict"; }
echo "[ok] self-DELEGATE envelope builds and self-checks (dry run, nothing submitted)"

t0=$(stagef_cmt_tip "$ref_db")
slog="$BASE_DIR/selfdeleg_envelope.log"
if ! "$CLI" -s 127.0.0.1 -p "$port" v2-envelope delegate \
       --keys "$KEYS" --validator "$PK" --amount "$AMOUNT" \
       --submit "127.0.0.1:$port" > "$slog" 2>&1; then
    cat "$slog" >&2
    die "the self-DELEGATE envelope was REJECTED (CheckTx) — Rule S still in force, or read the log above"
fi
intent_id=$(awk '/^ *intent_id=/{sub(/^ *intent_id=/,""); print}' "$slog")
[ "${#intent_id}" = 128 ] || die "could not read a 64-byte intent_id from the delegate SUBMIT output"
echo "[ok] self-DELEGATE APPROVED into the mempool (amount $AMOUNT, intent_id ${intent_id:0:16}...)"

stall_at=$(stagef_cmt_wait_row "$ref_db" \
    "SELECT COUNT(*) FROM v2_intent_index WHERE lower(hex(intent_id)) = '$intent_id';" 4) \
    && wrc=0 || wrc=$?
[ "$wrc" = 1 ] && die "the self-delegation's v2_intent_index row never appeared and the chain STALLED at $stall_at"
[ "$wrc" = 2 ] && die "the self-delegation was not included within 20 heights (tip $t0 -> $stall_at) — dropped, not delayed"
h=$(sqlite3 "$ref_db" \
    "SELECT global_height FROM v2_intent_index WHERE lower(hex(intent_id)) = '$intent_id' LIMIT 1;" \
    2>/dev/null || true)
[ -n "$h" ] || die "the self-delegation's row appeared but its global_height could not be read"
echo "[ok] the self-delegation applied at height $h"

# ── Stage 2: rows on all seven nodes ─────────────────────────────────
deleg_want=$(( deleg_before + AMOUNT ))
td_before="${tot_before%%|*}"; ed_before="${tot_before##*|}"
row_want="$deleg_want|$SELF_BOND|$(( td_before + AMOUNT ))|$(( ed_before + AMOUNT ))"
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    stagef_cmt_wait_height "$db" "$h" 2 >/dev/null \
        || die "node$n never reached height $h (mesh replication stalled)"
    got=$(sqlite3 "$db" \
        "SELECT (SELECT COALESCE(SUM(amount),0) FROM delegations
                  WHERE lower(hex(delegator_pubkey)) = '$PK'
                    AND lower(hex(validator_pubkey)) = '$PK')
             || '|' || self_stake || '|' || total_delegated || '|' || external_delegated
           FROM validators WHERE lower(hex(pubkey)) = '$PK';" 2>/dev/null || echo ERR)
    [ "$got" = "$row_want" ] || die "node$n: self-delegation|self_stake|total_delegated|external_delegated = '$got', want '$row_want'"
done
echo "[ok] 7/7: delegation row (node$NODE -> node$NODE) = $deleg_want, self_stake exactly $SELF_BOND, both delegated buckets +$AMOUNT"

# ── Stage 3: drive to nb + E (snapshot(nb + 2E) is stored there) ─────
nb=$(( (h + E_LEN - 1) / E_LEN * E_LEN ))
target=$(( nb + E_LEN + 1 ))
reached=$(stagef_cmt_advance_to "$ref_db" "$target" 12) && arc=0 || arc=$?
[ "$arc" = 0 ] || die "could not reach height $target (advance rc=$arc, tip $reached)"
echo "[ok] reached $reached (delegation at $h, nb=$nb, snapshot($(( nb + 2 * E_LEN ))) stored at boundary $(( nb + E_LEN )))"

# the live delegated total moved by EXACTLY AMOUNT across this window
# (the guard named in HOW IT CAN LIE: no one else delegated to node 1)
tot_after=$(sqlite3 "$ref_db" "SELECT total_delegated FROM validators WHERE lower(hex(pubkey)) = '$PK';" 2>/dev/null || echo ERR)
[ "$tot_after" = "$(( td_before + AMOUNT ))" ] \
    || die "node$NODE's total_delegated is $tot_after, not $(( td_before + AMOUNT )) — something else delegated in the window"

# node 1's total_stake in snapshot(E0) as a decimal, "" when not seated
total_in() {   # total_in DB EPOCH_START
    local db="$1" e0="$2" n i vid hex
    n=$(sqlite3 "$db" "SELECT active_count FROM validator_set_snapshots WHERE epoch_start = $e0;" 2>/dev/null || true)
    case "$n" in ''|*[!0-9]*) die "snapshot($e0) is absent on $db" ;; esac
    for i in $(seq 0 $(( n - 1 ))); do
        vid=$(sqlite3 "$db" "SELECT lower(hex(substr(snapshot_blob,
                              $(( VSET_HDR + i * VSET_ENTRY + 1 )), 32)))
                              FROM validator_set_snapshots WHERE epoch_start = $e0;")
        if [ "$vid" = "$VOTER" ]; then
            hex=$(sqlite3 "$db" "SELECT hex(substr(snapshot_blob,
                                   $(( VSET_HDR + i * VSET_ENTRY + VSET_TOTAL_OFF + 1 )), 8))
                                   FROM validator_set_snapshots WHERE epoch_start = $e0;")
            echo "$(( 16#$hex ))"
            return 0
        fi
    done
    echo ""
}

stagef_sentinel ASSERT_RUN   # the terminal assertions follow

# ── Stage 4: the frozen copy(nb) splits bond and self-delegation ─────
copy_want="0|$SELF_BOND
1|$deleg_want"
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    stagef_cmt_wait_height "$db" "$target" 2 >/dev/null \
        || die "node$n never reached height $target"
    got=$(sqlite3 "$db" \
        "SELECT kind || '|' || amount FROM v2_balance_copy
          WHERE epoch_start = $nb AND validator_fp = X'$FP' AND owner_fp = X'$FP'
          ORDER BY owner_fp ASC, kind ASC;" 2>/dev/null || echo ERR)
    [ "$got" = "$copy_want" ] \
        || die "node$n: copy($nb) rows owned by node$NODE under node$NODE = '$(printf '%s' "$got" | tr '\n' ' ')', want '$(printf '%s' "$copy_want" | tr '\n' ' ')'"
done
echo "[ok] 7/7: copy($nb) holds node$NODE's bond (kind 0, $SELF_BOND) and its self-delegation (kind 1, $deleg_want) as two rows"

# ── Stage 5: the power lift ──────────────────────────────────────────
e_old=$(( nb + E_LEN ))
e_new=$(( nb + 2 * E_LEN ))
first_pair=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    t_old=$(total_in "$db" "$e_old")
    t_new=$(total_in "$db" "$e_new")
    [ -n "$t_old" ] || die "node$n: node$NODE is not seated in snapshot($e_old) — nothing to compare"
    [ -n "$t_new" ] || die "node$n: node$NODE is not seated in snapshot($e_new) — nothing to compare"
    [ "$(( t_new - t_old ))" = "$AMOUNT" ] \
        || die "node$n: node$NODE's total_stake went $t_old -> $t_new across snapshot($e_old) -> snapshot($e_new), not +$AMOUNT"
    pair="$t_old->$t_new"
    if [ -z "$first_pair" ]; then first_pair="$pair"
    elif [ "$pair" != "$first_pair" ]; then die "node$n reads $pair, node1 read $first_pair"; fi
done
echo "[ok] 7/7: node$NODE's total_stake $first_pair (+$AMOUNT) from snapshot($e_old) to snapshot($e_new) — power $(( ${first_pair##*>} / 100000000 )) units"

stagef_cmt_diff_at_floor "post-cmt-self-delegate" || exit 2

stagef_sentinel PASS
echo ""
echo "[PASS] genesis validator node$NODE delegated $AMOUNT raw to itself at height $h; all"
echo "       $STAGEF_COMMITTEE_SIZE nodes stored it as a delegation apart from the exact 10M bond,"
echo "       froze it as a separate copy row, counted it in the power, and agree on state_root."
