#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_v2_rewards.sh — the reward pool pays out at epoch boundaries
# and a payday turns the accruals into coins (tokenomics-v3 P2)
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   The P2 reward path end to end on a REAL seven-node cometbft cluster
#   (design 2026-09-23 §7 P2-6 / P2-7; decision 2026-09-22 §1
#   "Ödüller ve ücretler" and §3 "P2 tasarım soruları"):
#
#   (1) At a NON-payday boundary H, the reward pool falls by EXACTLY
#       what the accrual table gained — nothing burned, nothing minted,
#       nothing lost:  pool(H-1) - pool(H) == Σaccrual(H) - Σaccrual(H-1)
#       > 0, and the fall is at most pool(H-1) >> 16 (the per-epoch
#       payout, v2_gen.h NODUS_V2_GEN_REWARD_DIVISOR_LOG2).
#   (2) Every harness node that is a member of the set GOVERNING the
#       ended epoch — snapshot(H-E), decoded from the chain itself — holds
#       an accrual row keyed by its own fingerprint (every running node
#       signs the whole observed epoch, so each member clears the
#       participation bar), and the accrual table (and the pool) is
#       IDENTICAL on all seven nodes.
#   (3) At the PAYDAY boundary Hp ((Hp/E) % payout_interval_epochs == 0)
#       the accrual table is EMPTY afterwards and the coins written at
#       height Hp with output_index >= 400 (NODUS_V2_SETTLE_OUT_IDX_BASE)
#       sum to exactly Σaccrual(Hp-1) + pool(Hp-1) - pool(Hp) — the
#       distribution at Hp runs first, the payday then pays everything —
#       and their owners are EXACTLY {owners of an accrual row before Hp}
#       ∪ {harness nodes in snapshot(Hp-E)}: one coin each, none for
#       anyone else, identical on all seven nodes.
#   (4) state_root agrees 7/7 at the floor afterwards.
#   The property that would be false if it failed: *the reward reserve
#   moves only pool -> accrual -> coin, by the same amounts on every
#   node, and the payday fires on the interval the genesis document
#   committed.*
#
# WHAT IT REQUIRES
#   ⚠ A SHORT-EPOCH BINARY AND A SHORT PAYOUT INTERVAL, both exported
#   BEFORE stagef_up_v2.sh, or it skips (rc 99):
#     compile: -DDNAC_EPOCH_LENGTH=<E> (15 is the harness convention)
#     env:     STAGEF_EPOCH_LENGTH=<E> matching it, and
#              STAGEF_PAYOUT_INTERVAL_EPOCHS=2 — the bring-up writes it
#              into the genesis config as payout_interval_epochs (part of
#              the hashed document). The production 24 puts the payday
#              24 epochs out, beyond this harness's patience at any E.
#   An interval of 1 is refused (rc 99): every boundary would be a
#   payday and leg (1) — accrual BETWEEN paydays — would never run.
#   A cluster from stagef_up_v2.sh; the CLI-SPEND pump (nodus-cli +
#   node 3's genesis leaf, stagef_env.sh) makes it feasible — idle
#   production alone (60 s per block) is over the budget and skips.
#   STAGEF_EPOCH_BOUNDARY_BUDGET_S (default 1800) is the SKIP feasibility
#   budget shared with test_v2_epoch_boundary.sh, never a wait bound.
#
# WHAT IT LEAVES BEHIND
#   The chain several epochs further on, past at least one payday: every
#   committee validator holds one more native coin (its payday payout),
#   the accrual table is empty at the moment of the payday (it refills at
#   the next boundary). One STAGEF_PUMP_FEE_RAW fee per pump step gone
#   from node 3's coin — and, since P2, that fee is IN the reward pool,
#   not burned. Node 3's genesis leaf claimed if no earlier scenario's
#   pump did. Nothing is killed or restarted. Runs BEFORE
#   test_cmt_rule_n_retire.sh, which permanently retires node 7 (a
#   stopped member would miss the bar and legs (2)/(3) expect every
#   RUNNING member to be paid).
#
# HOW IT CAN LIE
#   - **Pre and post reads are single SQLite statements**, so each is one
#     consistent snapshot of (tip, pool, Σaccrual). The PRE read is taken
#     only after the last pump spend has LANDED; the pump is not driven
#     again until the POST reads are done. The window between them is
#     then checked to carry NO envelope (v2_blocks.tx_count) and to have
#     created NO coin other than payday (>= 400) and graduation (200)
#     rows — a fee or a claim inside the window would move the pool for a
#     reason that is not the boundary, and the scenario FAILS rather than
#     mis-attributing it.
#   - **A boundary the pump overshoots is not observed.** If the pre read
#     already shows tip >= H, that boundary is skipped and the next one
#     chosen; three misses FAIL the run (a chain that repeatedly lands a
#     spend two or more heights late is itself the anomaly).
#   - **A payday UTXO is recognised by position**, block_height = Hp and
#     output_index >= 400 (the P2 payout index base); an ordinary spend
#     with 400+ outputs landing at Hp would be counted too. The window
#     check above rules out any spend at Hp.
#   - **The committee is READ FROM THE CHAIN, never assumed to be the
#     seven genesis nodes** (first full short-epoch sweep at 0.19.69:
#     FAILED "boundary 75: node2's fingerprint has no accrual row" on a
#     correct chain). test_v2_stake.sh, earlier in the sweep, bonds an
#     EIGHTH validator (v2user) at the same stake and with no running
#     node; the set holds 7 seats, so the tie-break rotates one genesis
#     node OUT of each snapshot (measured: snapshot(60) held v2user and
#     not node2) and v2user, never signing, misses the bar until Rule N
#     retires it. Membership is decoded from validator_set_snapshots
#     (voter_id = the first 32 bytes of SHA3-512(pubkey) = the first 64
#     hex of nodus.fp; entries at 78 + i·2642, shared/dnac/vset_wire.h).
#     A running member that is NOT paid still fails the run; a node
#     rotated out is simply not expected. At least one harness node must
#     be a member of every observed snapshot, or the run FAILS (vacuity).
#   - **Epoch length E, not 720; payout interval 2, not 24.** This proves
#     the LOGIC of the distribution and of the payday cadence, nothing
#     about magnitudes at the production parameters (the pool at 200M
#     NODUS pays pool >> 16 per epoch here exactly as it would at 720).
#   - **rc=99 means the coverage did not happen.** Never a pass.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

REF=1
CONF="$BASE_DIR/v2_genesis.conf"
E_LEN="${STAGEF_EPOCH_LENGTH:-720}"
IDLE_S=$(( STAGEF_CMT_EMPTY_INTERVAL_MS / 1000 ))
PAYDAY_IDX_BASE=400          # NODUS_V2_SETTLE_OUT_IDX_BASE (v2_econ.h)
GRAD_IDX=200                 # the graduation release's own slot (v2_epoch.h)

die() { echo "[FAIL] $*" >&2; exit 1; }

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
has_acc=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_reward_accrual';" \
    2>/dev/null || echo 0)
if [ "${has_acc:-0}" = "0" ] || [ ! -f "$CONF" ]; then
    echo "[SKIP] not a tokenomics-v3 P2 Ledger V2 cluster (no v2_reward_accrual / no $CONF) — use stagef_up_v2.sh"
    exit 99
fi
INTERVAL=$(awk -F'=' '/^payout_interval_epochs[ \t]*=/{gsub(/[ \t]/,"",$2); print $2; exit}' "$CONF")
case "$INTERVAL" in
    ''|*[!0-9]*) echo "[SKIP] $CONF names no payout_interval_epochs — bring the cluster up with this tree's stagef_up_v2.sh"; exit 99 ;;
esac
if [ "$INTERVAL" -lt 2 ]; then
    echo "[SKIP] payout_interval_epochs=$INTERVAL: every boundary is a payday, so accrual BETWEEN"
    echo "       paydays (leg 1) never happens — export STAGEF_PAYOUT_INTERVAL_EPOCHS=2 before bring-up"
    exit 99
fi
stagef_sentinel SETUP_OK   # W4-H: the runner turns PASS-without-ASSERT_RUN into FAIL

# ── pace and feasibility ─────────────────────────────────────────────
pace="idle"
per_block_s="$IDLE_S"
if stagef_cmt_pump_ready "$ref_db"; then
    pace="pumped"
    per_block_s="$STAGEF_CMT_PUMP_BLOCK_S"
fi
is_payday() { [ $(( ($1 / E_LEN) % INTERVAL )) -eq 0 ]; }
head0=$(stagef_cmt_tip "$ref_db")
# H1: the first NON-payday boundary whose WHOLE epoch lies after this
# scenario started (every validator is up and signing for all of it);
# Hp: the first payday after H1.
H1=$(( (head0 / E_LEN + 2) * E_LEN ))
while is_payday "$H1"; do H1=$(( H1 + E_LEN )); done
HP=$(( H1 + E_LEN ))
while ! is_payday "$HP"; do HP=$(( HP + E_LEN )); done
need=$(( HP - head0 ))
n_obs=$(( (HP - H1) / E_LEN + 1 ))
worst_case_s=$(( need * per_block_s + n_obs * 2 * IDLE_S ))
STAGEF_EPOCH_BOUNDARY_BUDGET_S="${STAGEF_EPOCH_BOUNDARY_BUDGET_S:-1800}"
if [ "$worst_case_s" -gt "$STAGEF_EPOCH_BOUNDARY_BUDGET_S" ]; then
    echo "[SKIP] the payday at $HP is $need blocks away (epoch length $E_LEN, interval $INTERVAL);"
    echo "       the worst-case $pace wait is ${worst_case_s}s, over this harness's"
    echo "       ${STAGEF_EPOCH_BOUNDARY_BUDGET_S}s patience budget — needs -DDNAC_EPOCH_LENGTH=15 +"
    echo "       STAGEF_EPOCH_LENGTH=15 + STAGEF_PAYOUT_INTERVAL_EPOCHS=2 and the CLI-SPEND pump"
    exit 99
fi
echo "[ok] epoch length $E_LEN, payout interval $INTERVAL, head $head0: observe $H1 .. payday $HP ($need blocks, $pace, worst case ${worst_case_s}s)"

# fingerprints of the seven committee validators
declare -a FP
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    FP[$n]=$(cat "$(stagef_node_dir "$n")/identity/nodus.fp")
    [ "${#FP[$n]}" = 128 ] || die "node$n has no 128-hex fingerprint"
done

stagef_cmt_diff_at_floor "pre-v2-rewards" || exit 2

# The set that GOVERNED the epoch ending at boundary H is snapshot(H-E)
# (nodus_witness_v2_settlement_apply reads exactly that one). Prints the
# members' voter_ids (64 hex = the first 32 bytes of the fingerprint),
# one per line. Layout: shared/dnac/vset_wire.h — DNA_VSET_HDR_LEN 78,
# DNA_VSET_ENTRY_LEN 2642, voter_id first in each entry.
VSET_HDR=78
VSET_ENTRY=2642
members_of() {   # members_of EPOCH_START
    local n i
    n=$(sqlite3 "$ref_db" "SELECT active_count FROM validator_set_snapshots
                            WHERE epoch_start = $1;") \
        || die "snapshot($1) read failed"
    case "$n" in ''|*[!0-9]*) die "snapshot($1) is absent on node$REF" ;; esac
    [ "$n" -gt 0 ] || die "snapshot($1) has no member"
    for i in $(seq 0 $(( n - 1 ))); do
        sqlite3 "$ref_db" "SELECT lower(hex(substr(snapshot_blob,
                             $(( VSET_HDR + i * VSET_ENTRY + 1 )), 32)))
                             FROM validator_set_snapshots
                            WHERE epoch_start = $1;"
    done
}
# node N is a member of the listed voter_ids? PURE BASH on purpose: the
# first cut was `printf | grep -qx`, and under `pipefail` grep -q exiting
# on an early match SIGPIPEs the writer (rc 141) — MEASURED 15 false
# "not a member" in 3000 calls on a loaded machine, 0 idle — which failed
# a sweep at 0.19.69 on a correct chain. No pipe, no race.
is_member() {   # is_member N "<voter_id lines>"
    [[ $'\n'"$2"$'\n' == *$'\n'"${FP[$1]:0:64}"$'\n'* ]]
}

# One consistent snapshot: "tip pool Σaccrual n_accrual" — ONE statement,
# so SQLite answers it from one read snapshot. A failed or malformed read
# is a FAIL, never a zero.
snap() {
    local out
    out=$(sqlite3 -separator ' ' "$1" \
      "SELECT (SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks),
              (SELECT reward_pool FROM supply_tracking WHERE id = 1),
              (SELECT COALESCE(SUM(amount),0) FROM v2_reward_accrual),
              (SELECT COUNT(*) FROM v2_reward_accrual);") \
        || die "snapshot read failed on $1"
    case "$out" in
        *[!0-9\ ]*|'') die "snapshot read on $1 returned '$out'" ;;
    esac
    printf '%s\n' "$out"
}

advance() {   # advance DB TARGET — pump/idle, the pump's rc distinguished
    local out rc
    out=$(stagef_cmt_advance_to "$1" "$2" 4) && rc=0 || rc=$?
    case "$rc" in
      0) printf '%s\n' "$out" ;;
      2) die "a pump spend was approved but not included within 20 heights (tip $out) — dropped, not delayed" ;;
      3) die "the pump faulted at tip $out (see its stderr above)" ;;
      *) die "height stalled at $out ($pace), short of $2" ;;
    esac
}

# Every node's view of the post-boundary state for [H, H+E): the pool,
# then one line per accrual row (owner_fp ASC) — read only between two
# tip reads that both lie inside [H, H+E), so the rows are the state the
# boundary H wrote (accruals move only at boundaries; the pump is idle).
node_view() {   # node_view N H
    local db t1 t2 body
    db=$(stagef_node_chain_db "$1")
    stagef_cmt_wait_height "$db" "$2" 3 >/dev/null \
        || die "node$1 never reached height $2 (mesh replication stalled)"
    t1=$(stagef_cmt_tip "$db")
    body=$(sqlite3 "$db" "SELECT reward_pool FROM supply_tracking WHERE id = 1;
                          SELECT lower(hex(owner_fp)) || ':' || amount
                            FROM v2_reward_accrual ORDER BY owner_fp;")
    t2=$(stagef_cmt_tip "$db")
    [ "$t1" -ge "$2" ] && [ "$t2" -lt $(( $2 + E_LEN )) ] \
        || die "node$1 moved past the next boundary while being read ($t1..$t2)"
    printf '%s\n' "$body"
}

misses=0
H="$H1"
assert_run=0
while [ "$H" -le "$HP" ]; do
    # ── PRE: drive to H-2, then read (tip must still be below H) ─────
    advance "$ref_db" $(( H - 2 )) >/dev/null
    s=$(snap "$ref_db") || exit 1      # snap's own die() names the cause
    read -r t_pre pool_pre acc_pre nacc_pre <<< "$s"
    if [ "$t_pre" -ge "$H" ]; then
        misses=$(( misses + 1 ))
        [ "$misses" -lt 3 ] || die "three boundaries overshot by the pump before a pre-read — last at $H (tip $t_pre)"
        echo "[..] boundary $H overshot before its pre-read (tip $t_pre) — observing the next one"
        if is_payday "$H"; then HP=$(( H + E_LEN * INTERVAL )); fi
        H=$(( H + E_LEN ))
        continue
    fi
    # the accrual OWNERS before H (a payday pays exactly these plus this
    # boundary's members); rows move only at boundaries and the pump is
    # idle, so this read belongs to the same pre-boundary state — checked
    pre_owners=$(sqlite3 "$ref_db" "SELECT lower(hex(owner_fp))
                                     FROM v2_reward_accrual ORDER BY owner_fp;") \
        || die "accrual owner read failed"
    [ "$(stagef_cmt_tip "$ref_db")" -lt "$H" ] \
        || die "boundary $H landed between the pre reads — re-run"
    mem=$(members_of $(( H - E_LEN )))
    n_mem_nodes=0
    for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
        if is_member "$n" "$mem"; then n_mem_nodes=$(( n_mem_nodes + 1 )); fi
    done
    [ "$n_mem_nodes" -gt 0 ] || die "boundary $H: no harness node is a member of snapshot($(( H - E_LEN ))) — nothing to check"
    echo "[ok] pre  H=$H: tip $t_pre pool $pool_pre accrued $acc_pre ($nacc_pre rows); snapshot($(( H - E_LEN ))) holds $(printf '%s\n' "$mem" | grep -c .) member(s), $n_mem_nodes of them harness nodes"

    # ── POST: idle production only, up to H ─────────────────────────
    stagef_cmt_wait_height "$ref_db" "$H" 3 >/dev/null \
        || die "the chain stalled short of boundary $H"
    s=$(snap "$ref_db") || exit 1
    read -r t_post pool_post acc_post nacc_post <<< "$s"
    [ "$t_post" -lt $(( H + E_LEN )) ] || die "tip $t_post already past the next boundary"
    echo "[ok] post H=$H: tip $t_post pool $pool_post accrued $acc_post ($nacc_post rows)"

    # the window (t_pre, t_post] carried no fee and no claim
    win=$(sqlite3 -separator ' ' "$ref_db" \
      "SELECT (SELECT COALESCE(SUM(tx_count),0) FROM v2_blocks
                WHERE global_height > $t_pre AND global_height <= $t_post),
              (SELECT COUNT(*) FROM utxo_set
                WHERE block_height > $t_pre AND block_height <= $t_post
                  AND output_index <> $GRAD_IDX AND output_index < $PAYDAY_IDX_BASE);")
    read -r win_tx win_coins <<< "$win"
    [ "$win_tx" = 0 ] && [ "$win_coins" = 0 ] || die \
      "the window ($t_pre, $t_post] carried $win_tx envelope(s) and $win_coins non-reward coin(s) — the pool moved for a reason other than the boundary"

    d_pool=$(( pool_pre - pool_post ))
    [ "$d_pool" -gt 0 ] || die "boundary $H: the pool did not fall ($pool_pre -> $pool_post)"
    [ "$d_pool" -le $(( pool_pre >> 16 )) ] || die \
      "boundary $H: the pool fell by $d_pool, more than pool >> 16 = $(( pool_pre >> 16 ))"

    if ! is_payday "$H"; then
        # (1) pool -> accrual, exactly
        [ $(( acc_post - acc_pre )) -eq "$d_pool" ] || die \
          "boundary $H: the pool fell by $d_pool but the accrual table gained $(( acc_post - acc_pre ))"
        echo "[ok] boundary $H: pool -$d_pool == accrual +$d_pool"
    else
        # (3) accrual -> coins, everything
        [ "$nacc_post" = 0 ] || die "payday $H: $nacc_post accrual row(s) survived the payday"
        pay=$(sqlite3 -separator ' ' "$ref_db" \
          "SELECT COUNT(*), COALESCE(SUM(amount),0) FROM utxo_set
            WHERE block_height = $H AND output_index >= $PAYDAY_IDX_BASE
              AND token_id = zeroblob(64);")
        read -r n_pay sum_pay <<< "$pay"
        [ "$sum_pay" -eq $(( acc_pre + d_pool )) ] || die \
          "payday $H: coins sum to $sum_pay, expected accrual $acc_pre + this boundary's $d_pool"
        # expected owners = pre-payday accrual owners ∪ harness nodes in
        # snapshot(H-E) (paid by this boundary's distribution first)
        expect=$(
            { printf '%s\n' "$pre_owners"
              for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
                  if is_member "$n" "$mem"; then printf '%s\n' "${FP[$n]}"; fi
              done
            } | grep . | sort -u) || die "payday $H: no expected coin owner at all"
        got=$(sqlite3 "$ref_db" "SELECT owner FROM utxo_set
               WHERE block_height = $H AND output_index >= $PAYDAY_IDX_BASE
               ORDER BY owner;")
        [ "$(printf '%s\n' "$got" | grep . | sort)" = "$expect" ] || die \
          "payday $H: coin owners differ from pre-payday accrual owners ∪ members — got [$got] expected [$expect]"
        [ "$n_pay" -eq "$(printf '%s\n' "$expect" | grep -c .)" ] || die \
          "payday $H: $n_pay coin(s) for $(printf '%s\n' "$expect" | grep -c .) owner(s)"
        echo "[ok] payday $H: $n_pay coin(s) = $sum_pay (accrual $acc_pre + boundary $d_pool), table empty"
    fi

    # (2) every harness node that governed the ended epoch accrued
    # (non-payday) / the table is identical everywhere — and the pool
    # with it
    first=""
    for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
        v=$(node_view "$n" "$H")
        if ! is_payday "$H" && is_member "$n" "$mem"; then
            # pure bash, same SIGPIPE reason as is_member
            [[ $'\n'"$v" == *$'\n'"${FP[$n]}:"* ]] \
                || die "boundary $H: node$n governed epoch ($(( H - E_LEN )), $H] but its fingerprint has no accrual row on node$n"
        fi
        if [ -z "$first" ]; then first="$v"
        elif [ "$v" != "$first" ]; then
            die "boundary $H: node$n's pool/accrual table differs from node1's"
        fi
    done
    if is_payday "$H"; then
        pfirst=""
        for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
            pv=$(sqlite3 "$(stagef_node_chain_db "$n")" \
                "SELECT lower(hex(nullifier)) || ':' || owner || ':' || amount
                   FROM utxo_set WHERE block_height = $H
                    AND output_index >= $PAYDAY_IDX_BASE ORDER BY nullifier;")
            [ -n "$pv" ] || die "payday $H: node$n holds no payday coin"
            if [ -z "$pfirst" ]; then pfirst="$pv"
            elif [ "$pv" != "$pfirst" ]; then
                die "payday $H: node$n's payday coins differ from node1's"
            fi
        done
        echo "[ok] payday $H: the payday coins are identical on all $STAGEF_COMMITTEE_SIZE nodes"
    fi
    echo "[ok] boundary $H: pool and accrual table identical on all $STAGEF_COMMITTEE_SIZE nodes"
    assert_run=1
    H=$(( H + E_LEN ))
done
[ "$assert_run" = 1 ] || die "no boundary was observed"

stagef_sentinel ASSERT_RUN   # the terminal assertion is next
stagef_cmt_diff_at_floor "post-v2-rewards" || exit 2

stagef_sentinel PASS
echo ""
echo "[PASS] the reward pool fell by exactly what the accrual table gained at each boundary,"
echo "       the payday at $HP paid every accrual as a coin and emptied the table, and all"
echo "       $STAGEF_COMMITTEE_SIZE nodes agree. Epoch length $E_LEN and payout interval $INTERVAL —"
echo "       NOT the shipped 720 / 24: this proves the LOGIC, not the magnitudes."
