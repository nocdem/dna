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
# R3 W3 (C2d) — THE SUBMIT ANSWER NO LONGER CARRIES A HEIGHT
#   On this lane `dnac_spend` answers the mempool's CheckTx result AT
#   ONCE — `status: APPROVED` means "accepted into the mempool", nothing
#   about a committed block (D-23 rev 7 item 22,
#   nodus_witness_handlers.c:2047-2063). `nodus-cli`'s
#   `committed: height=%llu index=%u` print (t6_submit) still fires on
#   this lane, but from response fields the server never sets any more —
#   they read back ZERO, always (nodus_client.c:2065-2158 never receives
#   a `bnr`/`ti` key from this lane's response, and the result struct is
#   `memset` to 0 first). So this scenario stops parsing that line for
#   anything: the CLI's own exit code already IS the APPROVED/REJECTED
#   verdict (t6_submit returns non-zero on anything but
#   NODUS_DNAC_APPROVED), and INCLUSION is learned the way this scenario
#   already learned it below — by polling the chain, never the client.
#   Claims carry no `v2_tx_index` row (that index is envelope-only,
#   `wire_id`-keyed — the Comet lane's writer is `cmt_item_index`,
#   nodus_witness_v2_apply.c:2085-2099, binding `p->wire_id`; a claim's
#   identity lives in `blk->claims[]`, a different array entirely — DELTA
#   1 citation fix, verifier UNCOVERED FINDING 7: the previous citation
#   ~:4318-4343 is the non-Comet branch), so the per-item result is read
#   through its LEDGER EFFECT instead: the claim's own UTXO row in
#   `utxo_set`, keyed by the nullifier printed at the dry-run stage but
#   found in the `tx_hash` COLUMN, not the `nullifier` column — see Stage
#   4 below for exactly why (`nodus_rt_core_claim_apply`,
#   nodus_witness_v2_claims.c:795-847).
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
#   - **APPROVED is admission, not inclusion.** The CLI's exit code 0
#     proves CheckTx accepted the claim into the mempool; it does NOT
#     prove FinalizeBlock later applied it (rc=0 is possible for a tx
#     that CheckTx admits and the ledger later refuses at apply — a
#     documented gap between the two passes on the reference this port
#     follows). The tip-advance and UTXO checks below are what close
#     that gap; a script that stopped at the CLI's rc=0 would not.
#   - **DELTA 2, MEASURED: inclusion is NOT next-block.** A stake
#     envelope on this same lane was APPROVED at tip 2 and its ledger
#     row did not appear until tip 4 — CheckTx admission promises
#     nothing about WHEN a transaction lands, only that it eventually
#     will (barring a stall or a silent drop). This scenario waits for
#     the UTXO row itself (`stagef_cmt_wait_row`), then reads its OWN
#     height, rather than assuming inclusion at `tip_before + 1`.
#   - **DELTA 3, item 2 — a chain that keeps healthily advancing but
#     never includes this claim is bounded too, separately from a
#     stall.** `stagef_cmt_wait_row` waits at most 20 heights past
#     submission (MAX_HEIGHTS, a judgment — three proposer cycles at 7
#     validators, not a measured constant) before returning rc=2
#     ("dropped, not delayed") — measured need: without this bound, the
#     same wait sat 34 minutes at a healthy, still-advancing tip until
#     killed by hand. rc=1 ("stalled") and rc=2 ("dropped") ARE
#     distinguished from each other in this scenario's die messages.
#   - **NEITHER OUTCOME IS DISTINGUISHED FROM A GENUINE SILENT DROP.**
#     Both rc=1 and rc=2 could equally mean the ledger silently refused
#     this claim after CheckTx approved it, or a real chain-side stall/
#     starvation. Either way this scenario reports FAIL; telling drop,
#     stall and starvation apart needs reading the node logs by hand.
#   - **NEVER parse `committed: height=` on this lane.** It still prints,
#     from fields the response no longer carries — see the header. A
#     script that greps it for a height is reading a number nodus-cli
#     made up out of a zeroed struct.
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

stagef_cmt_diff_at_floor "pre-v2-claim" || exit 2

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
# The nullifier is this claim's ledger identity — the dry-run computes it
# the same way the real submission will (both call dna_claim_nullifier
# over the SAME leaf), so it is safe to capture here rather than a
# second time after submit.
nullifier=$(awk '/^ *nullifier=/{sub(/^ *nullifier=/,""); print}' "$dry")
[ "${#nullifier}" = 128 ] || die "could not read a 64-byte nullifier from the dry-run output"
echo "[ok] claim builds and admits locally (amount=$amount, nullifier=${nullifier:0:16}...)"

# ── Stage 2: the cluster admits it ──────────────────────────────────
# R3 W3 (C2d) — CheckTx-immediate: rc=0 means APPROVED into the mempool,
# nothing about a committed block (see this script's header). Never grep
# the CLI's own "committed: height=" line — it still prints, from fields
# the response no longer carries.
sub="$BASE_DIR/v2claim_node${CLAIMANT}_submit.log"
if ! "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF")" \
       v2-claim --config "$CONF" --db "$cdb" --keys "$keys" \
       --submit "127.0.0.1:$(stagef_tcp_port "$REF")" \
       > "$sub" 2>&1; then
    cat "$sub" >&2
    die "claim submit was REJECTED for node$CLAIMANT (CheckTx admission failed)"
fi
echo "[ok] claim APPROVED into the mempool for node$CLAIMANT"

# ── Stage 3: the chain moved AT ALL (liveness, not inclusion) ───────
# A separate check from Stage 4 below on purpose: this only proves SOME
# block committed after submission, not that OUR claim was in it — see
# DELTA 2. A state_root check over an unchanged tip compares the same
# row on every node and passes having measured nothing, which is all
# this stage rules out. Bounded by PROGRESS, never a bare sleep.
tip_after=$(stagef_cmt_wait_height "$ref_db" "$(( tip_before + 1 ))" 2) \
    || die "tip did not advance past $tip_before within 2 empty-block intervals — the chain itself looks stalled"
echo "[ok] tip advanced: $tip_before -> $tip_after (liveness only — not proof of inclusion, see Stage 4)"

# ── Stage 4: the CheckTx admission became a REAL applied item ───────
# R3 W3 (C2d), DELTA 1 (verifier UNCOVERED FINDING 1, CONFIRMED) — the
# FIRST cut of this stage queried the WRONG COLUMN and was always RED on
# a healthy chain. `nodus_rt_core_claim_apply` (nodus_witness_v2_claims.c
# :795-847) writes the claim's own nullifier into the `tx_hash` COLUMN
# (:841, `sqlite3_bind_blob(st, 5, claim->nullifier, 64, ...)`) — the
# `nullifier` COLUMN instead holds `dna_claim_utxo_id(nullifier)`, a HASH
# of it (:809, `SHA3-512("DNA.CLUTXO.v1\0\0" || nullifier)`,
# shared/dnac/manifest_wire.c:650-657), which this scenario never
# computes and cannot reproduce without re-deriving that tag. The
# assertion is therefore keyed on `tx_hash`, not `nullifier`. Presence is
# still success for the same reason as before: this INSERT is the ONLY
# writer of a utxo_set row with this claim's nullifier in `tx_hash`
# (nodus_witness_v2_claims.c:830-841), it runs inside the claim's own
# Comet SAVEPOINT (nodus_witness_v2_apply.c:3514-3549, `claim_execute_one`
# at :3537), and a REFUSED claim's savepoint is rolled back — so a row
# here cannot exist for anything but an applied claim.
#
# R3 W3 (C2d), DELTA 2, MEASURED — "wait tip+1, then assert the row" is
# UNSOUND: a stake envelope on this same lane was APPROVED at tip 2 and
# its row did not appear until tip 4 (tx_count per height: 0,0,0,1,0,0).
# CheckTx admission does not promise next-block inclusion — a
# transaction that arrives while the next round is already in flight
# lands in a LATER one. This scenario therefore waits for the ROW ITSELF
# (`stagef_cmt_wait_row`, progress-bounded on the CHAIN'S tip, not on
# `tip_after` above), then reads the row's OWN height, rather than
# assuming it landed at `tip_after`.
# DELTA 3, item 2 — a SECOND, independent bound (MAX_HEIGHTS=20, the
# helper's default): a chain that keeps healthily producing dozens of
# blocks without ever including this claim is DROPPED, not delayed, and
# the stall bound alone (tuned for a HEALTHY chain's own cadence) could
# wait forever against that. Distinguish the two die messages: rc=1 is
# "chain stalled", rc=2 is "chain healthy, this claim never landed".
applied_at=$(stagef_cmt_wait_row "$ref_db" \
    "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$nullifier';" 4) \
    && wait_rc=0 || wait_rc=$?
if [ "$wait_rc" = 1 ]; then
    die "the claim's utxo_set row never appeared and the chain STALLED at $applied_at — CheckTx approved it but it was never applied, OR the chain stopped advancing before it could be; these are indistinguishable from outside (see this script's header)"
elif [ "$wait_rc" = 2 ]; then
    die "the claim was not included within 20 heights of submission (tip $tip_before -> $applied_at) — dropped, not delayed"
fi
claim_height=$(sqlite3 "$ref_db" \
    "SELECT block_height FROM utxo_set WHERE lower(hex(tx_hash)) = '$nullifier' LIMIT 1;" \
    2>/dev/null || true)
[ -n "$claim_height" ] || die "the row appeared between polls but its block_height could not be read"
echo "[ok] the claim's UTXO exists on-chain at height $claim_height (nullifier ${nullifier:0:16}...)"

# ── Stage 5: and everyone agrees on what it did ─────────────────────
# Every follower must reach $claim_height (the row's OWN height, NOT
# $tip_after — DELTA 2) before the comparison — a node one block behind
# would read as divergence rather than lag. Bounded per node by the same
# stall detection, never a bare sleep.
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    stagef_cmt_wait_height "$(stagef_node_chain_db "$n")" "$claim_height" 2 >/dev/null \
        || die "node$n never reached height $claim_height (mesh replication stalled)"
done
stagef_cmt_diff_at_floor "post-v2-claim" || exit 2

echo ""
echo "[PASS] a Ledger V2 genesis claim committed at height $claim_height and all"
echo "       $STAGEF_COMMITTEE_SIZE nodes produced the SAME state_root for it."
echo "       This is the V2 apply engine measured across nodes — the question"
echo "       the harness exists to ask."
