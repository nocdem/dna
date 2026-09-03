#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_v2_claim.sh — a genesis allocation is claimed, and the chain moves
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That seven nodes apply a Ledger V2 block and produce the SAME
#   state_root. The property that would be false if it failed: *the V2
#   apply engine is deterministic across nodes* — which is the single
#   question this whole harness exists to ask, and the one V2 had never
#   been asked.
#
#   The transaction it uses is a GENESIS CLAIM, for a reason that is not
#   incidental: on a pure V2 chain it is the ONLY transaction that can
#   come first. Every coin outside the validators' locked self-bond
#   enters through the distribution, so nothing else can be submitted
#   until something has been claimed. This scenario is therefore both a
#   determinism test and the chain's bootstrap out of height 0.
#
#   Secondary, and worth stating because it is easy to lose: the claim
#   only builds if the leaf set rebuilt from the genesis CONFIG
#   reproduces the snapshot root the chain COMMITTED. A pass is also
#   evidence that the config on disk is the config this chain was born
#   from.
#
# WHAT IT REQUIRES
#   Compile flags: NONE. A default nodus/build binary.
#   Environment: none of its own.
#   ⚠ A cluster from **stagef_up_v2.sh**, which writes the genesis config
#   this scenario reads and gives each node its own allocation. On a
#   legacy cluster it exits 99 rather than pretending.
#
# WHAT IT LEAVES BEHIND
#   Node 2's allocation is CLAIMED and can never be claimed again — the
#   nullifier is committed. The chain is one block higher, and node2's
#   identity now owns a spendable UTXO, which is what makes the stake
#   scenario possible. Nothing is killed, nothing is restarted.
#
#   It uses node 2, not node 1, deliberately: node 1 is the reference
#   node for every other read in this suite and is the CLI's first
#   bootstrap entry, so leaving its balance untouched keeps unrelated
#   failures from pointing at it.
#
# HOW IT CAN LIE
#   - **A second run of this scenario on the same cluster FAILS, and that
#     is correct.** The leaf is spent. It is not a flaky test; it is a
#     scenario whose subject is single-use. Bring the cluster up fresh.
#   - **"7/7 identical" is only worth what the height delta is worth.**
#     If the claim did not commit, the comparison would be over the same
#     genesis row on every node and would pass having measured nothing —
#     the exact vacuity that made stagef_diff report `(|)` before it was
#     fixed. So the height INCREASE is asserted first and separately, and
#     the state_root comparison is read as meaningful only after it.
#   - **The dry-run is not the assertion.** It proves the claim is
#     buildable and locally admissible; only the submit proves the
#     cluster committed it. Both are run, and the failure messages say
#     which stage lost.
#   - **rc=99 means the cluster was not V2.** Coverage that did not
#     happen, never a pass.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

CLAIMANT=2
REF=1
CONF="$BASE_DIR/v2_genesis.conf"
CLI="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"

die() { echo "[FAIL] $*" >&2; exit 1; }

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"

has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ] || [ ! -f "$CONF" ]; then
    echo "[SKIP] not a Ledger V2 cluster with a genesis config — use stagef_up_v2.sh"
    exit 99
fi
echo "[ok] Ledger V2 cluster with its genesis config present"

tip_before=$(sqlite3 "$ref_db" "SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks;")
[ "$tip_before" -ge 0 ] || die "node$REF has no V2 block at all"
echo "[ok] tip before: $tip_before"

bash "$(dirname "$0")/../stagef_diff.sh" "pre-v2-claim" || exit 2

cdb=$(stagef_node_chain_db "$CLAIMANT")
keys="$(stagef_node_dir "$CLAIMANT")/identity"

# ── Stage 1: buildable and locally admissible ───────────────────────
# Separate from the submit so a failure names the stage that lost. This
# stage is also where the leaf-set equivalence check lives: the claim
# cannot be built at all unless the tree rebuilt from $CONF reproduces
# the snapshot root the chain committed.
dry="$BASE_DIR/v2claim_node${CLAIMANT}_dry.log"
if ! "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF")" \
       v2-claim --config "$CONF" --db "$cdb" --keys "$keys" --dry-run \
       > "$dry" 2>&1; then
    cat "$dry" >&2
    die "claim could not be BUILT for node$CLAIMANT"
fi
grep -q 'LOCAL ADMIT: OK' "$dry" || {
    cat "$dry" >&2
    die "claim built but the engine would not admit it"
}
amount=$(awk '/^v2-claim leaf_index/{for(i=1;i<=NF;i++) if($i ~ /^amount=/){sub(/amount=/,"",$i); print $i}}' "$dry")
echo "[ok] claim builds and admits locally (amount=$amount)"

# ── Stage 2: the cluster commits it ─────────────────────────────────
sub="$BASE_DIR/v2claim_node${CLAIMANT}_submit.log"
if ! "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF")" \
       v2-claim --config "$CONF" --db "$cdb" --keys "$keys" \
       --submit "127.0.0.1:$(stagef_tcp_port "$REF")" \
       > "$sub" 2>&1; then
    cat "$sub" >&2
    die "claim submit failed for node$CLAIMANT"
fi
grep -q '^committed: height=' "$sub" || {
    tail -20 "$sub" >&2
    die "the submit did not report a commit"
}
echo "[ok] $(grep '^committed: height=' "$sub")"

# ── Stage 3: the chain actually moved ───────────────────────────────
# Asserted BEFORE the state_root comparison and separately from it. A
# state_root check over an unchanged tip compares the same row on every
# node and passes having measured nothing.
moved=0
for _ in $(seq 1 60); do
    tip_now=$(sqlite3 "$ref_db" "SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks;")
    if [ "$tip_now" -gt "$tip_before" ]; then moved=1; break; fi
    sleep 1
done
[ "$moved" = 1 ] || die "tip did not advance past $tip_before — nothing was applied, so any state_root agreement below would be vacuous"
tip_after=$(sqlite3 "$ref_db" "SELECT MAX(global_height) FROM v2_blocks;")
echo "[ok] tip advanced: $tip_before -> $tip_after"

# ── Stage 4: and everyone agrees on what it did ─────────────────────
# Give the followers a moment to apply before reading them.
sleep 5
bash "$(dirname "$0")/../stagef_diff.sh" "post-v2-claim" || exit 2

echo ""
echo "[PASS] a Ledger V2 genesis claim committed at height $tip_after and all"
echo "       $STAGEF_COMMITTEE_SIZE nodes produced the SAME state_root for it."
echo "       This is the V2 apply engine measured across nodes — the question"
echo "       the harness exists to ask."
