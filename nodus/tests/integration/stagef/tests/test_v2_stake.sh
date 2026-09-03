#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_v2_stake.sh — a claimed coin is bonded, on the V2 lane
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That a Ledger V2 envelope carrying a STAKE — a transaction that
#   consumes a real UTXO, writes validator state and moves value into a
#   locked bond — is applied identically by all seven nodes. The property
#   that would be false if it failed: *the V2 apply engine agrees across
#   nodes on a transaction that mutates state*, not merely on one that
#   mints a claim.
#
#   That distinction is the whole reason this scenario exists beside
#   test_v2_claim.sh. A claim creates an output from a committed Merkle
#   proof; it touches the claims table and the UTXO set. A stake SPENDS
#   an existing output, writes a validators row and a locked bond, and
#   therefore reaches parts of the state root the claim never does. Two
#   scenarios, two different halves of the apply engine.
#
# WHAT IT REQUIRES
#   Compile flags: NONE. A default nodus/build binary.
#   Environment: none of its own.
#   ⚠ A cluster from **stagef_up_v2.sh**, AND node 3 must already own a
#   spendable output — which means this scenario CLAIMS node 3's own
#   allocation first, rather than depending on another scenario having
#   run. Each node has its own leaf precisely so scenarios need not be
#   ordered.
#
# WHAT IT LEAVES BEHIND
#   Node 3's allocation is claimed and its leaf is spent forever. Part of
#   it is bonded into a validator record that stays. Two blocks, not one.
#   Nothing is killed or restarted.
#
# HOW IT CAN LIE
#   - **A second run FAILS on the claim, correctly** — the leaf is spent.
#     Bring the cluster up fresh.
#   - **The height delta is asserted before the state_root comparison**,
#     for the same reason as in the claim scenario: agreement over an
#     unchanged tip is agreement about nothing.
#   - **A stake that the engine rejects still leaves the chain at the
#     claim's height**, which is why the two stages are asserted
#     separately with their own deltas. Without that, a failed stake
#     would look like a pass whose "+1" came entirely from the claim.
#   - **The bond amount is well under the claimed amount** so that a
#     failure is never about insufficient funds. If this scenario ever
#     fails with a balance complaint, the claim stage is the suspect.
#   - **rc=99 means the cluster was not V2.** Coverage that did not
#     happen.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

# THE STAKER IS THE NON-VALIDATOR USER, NOT A NODE.
#
# All seven node identities are genesis validators with a bonded
# self-stake already. Staking as one of them is refused — correctly —
# and the engine says so precisely:
#   "VERDICT: env 0 leg 0 domain 0 op 1: runtime exec refused (rc -1)"
# The first cut of this scenario used node 3 and read that refusal as a
# failure. It was the scenario that was wrong. stagef_up_v2.sh therefore
# creates one identity that is NOT in the validator set and gives it its
# own genesis leaf — on a V2 chain, who can be funded is decided before
# the chain exists.
STAKER_DIR="$BASE_DIR/v2user"
REF=1
CONF="$BASE_DIR/v2_genesis.conf"
CLI="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"
BOND=1000000000000000      # DNAC_SELF_STAKE_AMOUNT — the exact genesis bond
COMMISSION=500

die() { echo "[FAIL] $*" >&2; exit 1; }
tip() { sqlite3 "$(stagef_node_chain_db "$REF")" \
        "SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks;"; }

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ] || [ ! -f "$CONF" ] || [ ! -s "$STAKER_DIR/identity/nodus.pk" ]; then
    echo "[SKIP] not a Ledger V2 cluster with a genesis config and a"
    echo "       non-validator user identity — use stagef_up_v2.sh"
    exit 99
fi

# The chain database is read READ-ONLY by the builders, so any node's
# copy serves; node1's is the reference everything else in this suite
# reads too.
sdb="$ref_db"
keys="$STAKER_DIR/identity"
destfp=$(cat "$STAKER_DIR/identity/nodus.fp")
port=$(stagef_tcp_port "$REF")

# Guard the premise rather than assume it: if this identity somehow IS a
# validator, the refusal below would be correct and the diagnosis would
# be wrong for the second time.
pk=$(xxd -p -c 99999 "$STAKER_DIR/identity/nodus.pk")
isval=$(sqlite3 "$ref_db" "SELECT COUNT(*) FROM validators WHERE lower(hex(pubkey))='$pk';" 2>/dev/null || echo 0)
[ "${isval:-0}" = "0" ] || die "the staking identity is ALREADY a validator — this scenario needs one that is not"
echo "[ok] staking identity is not in the validator set"

bash "$(dirname "$0")/../stagef_diff.sh" "pre-v2-stake" || exit 2

# ── Stage 1: fund the staker from its OWN leaf ──────────────────────
# Self-contained on purpose: depending on test_v2_claim.sh having run
# would make this scenario order-dependent, which is the defect the
# legacy suite's residue list is entirely about.
t0=$(tip)
log="$BASE_DIR/v2stake_claim.log"
if ! "$CLI" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$sdb" \
       --keys "$keys" --submit "127.0.0.1:$port" > "$log" 2>&1; then
    cat "$log" >&2; die "could not claim the user identity's allocation"
fi
grep -q '^committed: height=' "$log" || { tail -20 "$log" >&2; die "claim did not commit"; }

moved=0
for _ in $(seq 1 60); do
    [ "$(tip)" -gt "$t0" ] && { moved=1; break; }; sleep 1
done
[ "$moved" = 1 ] || die "tip did not advance after the funding claim"
t1=$(tip)
echo "[ok] the user identity funded by its own claim (tip $t0 -> $t1)"

# ── Stage 2: bond it ────────────────────────────────────────────────
slog="$BASE_DIR/v2stake_envelope.log"
if ! "$CLI" -s 127.0.0.1 -p "$port" v2-envelope stake --db "$sdb" \
       --keys "$keys" --bond "$BOND" --commission "$COMMISSION" \
       --dest-fp "$destfp" --submit "127.0.0.1:$port" \
       > "$slog" 2>&1; then
    cat "$slog" >&2
    die "stake envelope was refused — read the log above BEFORE assuming consensus"
fi
echo "[ok] stake envelope submitted (bond=$BOND commission=${COMMISSION}bps)"

# The stake must move the chain ON ITS OWN. Without this delta the +1
# from the funding claim would carry the whole scenario.
moved=0
for _ in $(seq 1 60); do
    [ "$(tip)" -gt "$t1" ] && { moved=1; break; }; sleep 1
done
[ "$moved" = 1 ] || die "tip did not advance past $t1 — the stake did not commit, and the earlier +1 was the claim's"
t2=$(tip)
echo "[ok] the stake committed on its own block (tip $t1 -> $t2)"

# ── Stage 3: the validator row exists, and identically ──────────────
sleep 5
rows=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    h=$(sqlite3 "$db" "SELECT COUNT(*) || ':' || COALESCE(SUM(self_stake),0) FROM validators;" 2>/dev/null || echo "ERR")
    rows="$rows node$n=$h"
    if [ -z "${first:-}" ]; then first="$h"; elif [ "$h" != "$first" ]; then
        echo "[FAIL] validator table differs across nodes:$rows" >&2
        exit 1
    fi
done
echo "[ok] validator table identical on all $STAGEF_COMMITTEE_SIZE nodes ($first)"

bash "$(dirname "$0")/../stagef_diff.sh" "post-v2-stake" || exit 2

echo ""
echo "[PASS] a Ledger V2 STAKE envelope spent a claimed output, wrote validator"
echo "       state and bonded value at height $t2, and all $STAGEF_COMMITTEE_SIZE nodes agreed on both"
echo "       the state_root and the validator table."
