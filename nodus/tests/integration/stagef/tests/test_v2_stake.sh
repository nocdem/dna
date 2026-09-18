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
# R3 W3 (C2d) — THE SUBMIT ANSWER NO LONGER CARRIES A HEIGHT
#   `dnac_spend` answers CheckTx AT ONCE on this lane — `APPROVED` means
#   "in the mempool", nothing about a committed block (D-23 rev 7 item
#   22, nodus_witness_handlers.c:2047-2063). nodus-cli's own
#   `committed: height=%llu index=%u` print still fires, from response
#   fields that are now always ZERO (nodus_client.c:2065-2158 never
#   receives a `bnr`/`ti` key on this lane). This scenario never parses
#   that line: the CLI's exit code already is the CheckTx verdict, and
#   inclusion is read from the chain — once by tip advance (liveness
#   only) and once by the STAKE'S OWN identity row (a stake is an
#   ENVELOPE, and an envelope's identity rows ARE indexed — the Comet
#   lane's writer is `cmt_item_index`, nodus_witness_v2_apply.c
#   :2085-2099 — unlike a claim, which is not).
#
#   DELTA 3, DEFECT 1, MEASURED — **the identity row is keyed on
#   `intent_id`, NEVER `wire_id`.** The first cut captured `wire_id=`
#   from the `--dry-run` build and waited for `v2_tx_index.tx_id` to
#   equal it. The ACTUAL submit is a SECOND, independent build of the
#   same envelope, and `wire_id` (== `tx_id`) commits the FULL encoded
#   envelope INCLUDING its ML-DSA-87 signature bytes
#   (`tx_id = SHA3-512("DNA.ENVTXID.v1" || auth_context_commit ||
#   env_len || env_bytes)`, `shared/dnac/env_wire.h:104-105`) —
#   signatures are RANDOMIZED per signing, so the dry-run's `wire_id` and
#   the real submission's committed `tx_id` are DIFFERENT VALUES for the
#   SAME semantic stake. The wait could never succeed. Measured live:
#   dry-run `wire_id=c945d0cf…`, committed `v2_tx_index.tx_id=781d6534…`
#   at height 13 — the stake WAS applied the whole time. `intent_id` is
#   the fix: `shared/dnac/env_wire.h:121-131` — "the CANONICAL,
#   AUTHORIZATION-WITNESS-INDEPENDENT identity of the requested
#   execution: two envelopes whose semantic content is identical derive
#   the SAME intent_id no matter which valid signatures ... authorize
#   them. NOTHING of auth_data ... or signature randomness enters this
#   preimage" — confirmed identical in the dry-run print and the
#   committed `v2_intent_index` row in the same measurement
#   (`fd22ef4e…` both times). `nodus-cli.c:2655-2658` prints BOTH
#   `wire_id=` and `intent_id=`, 128 hex each; this scenario now captures
#   ONLY `intent_id` and keeps `wire_id` out of every assertion. The
#   Comet lane writes `v2_intent_index (intent_id, tx_id, global_height,
#   global_index)` inside `cmt_item_index`, the SAME function and the
#   SAME transaction as `v2_tx_index` (nodus_witness_v2_apply.c
#   :2040-2059) — so `global_height` is read from THAT row.
#
#   ⚠ **`test_v2_claim.sh` and `test_cmt_mempool_flood.sh` do NOT share
#   this trap — confirmed, not assumed.** A claim's identity for these
#   scenarios' purposes is its NULLIFIER
#   (`dna_claim_nullifier`, `shared/dnac/manifest_wire.c:624-648`), whose
#   preimage is `TAG_CLNUL || chain_id || manifest_hash ||
#   target_domain_id || target_asset_len || target_asset_ref ||
#   leaf_hash` — every input is chain identity, the genesis manifest, or
#   the target leaf itself; NONE of it is a signature, so the SAME
#   nullifier is produced whether it is read from a `--dry-run` build or
#   the real submission. (The claim's `tx_hash`, the SHA3-512 of the full
#   encoded claim bytes computed at `nodus-cli.c:2260`, DOES include the
#   signature and DOES vary between builds — but nothing in this suite
#   asserts on that value; `utxo_set.tx_hash` is bound from
#   `claim->nullifier` at the ledger, not the client's `tx_hash`, so it
#   was never the trap Defect 1 is.)
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
#   - **NEVER parse `committed: height=` on this lane.** See the header —
#     it prints from a zeroed struct now. rc=0 is admission, not
#     inclusion; the identity row is what proves inclusion.
#   - **DELTA 3, DEFECT 1 (fixed) — NEVER key on `wire_id` for anything
#     built twice.** The dry-run's `wire_id` and the real submission's
#     committed `tx_id` are DIFFERENT VALUES for the identical stake —
#     the signature they each commit is randomized per signing. This
#     scenario captures and asserts on `intent_id` only, which is
#     identical across both builds by construction (see the header for
#     the full citation and the measured proof). `wire_id` is not parsed
#     anywhere in this script any more.
#   - **DELTA 2, MEASURED ON THIS SCENARIO: inclusion is NOT next-block.**
#     A stake envelope here was APPROVED at tip 2 and its identity row
#     did not appear until tip 4 — the very measurement that established
#     this rule (a separate defect from DEFECT 1 above — sweep 3's
#     failure was BOTH: the wrong key AND the wrong height assumption,
#     and fixing only the timing would still never have matched).
#     Both the funding claim and the stake wait for their OWN ledger
#     effect (`stagef_cmt_wait_row`) and then read ITS height, never
#     `submission_tip + 1`. The liveness checks (tip advanced at all)
#     stay, but are read as liveness only, never as inclusion proof.
#   - **DELTA 3, DEFECT 2 (fixed) — a stall and a healthy-but-dropped
#     chain are now bounded separately.** `stagef_cmt_wait_row`'s stall
#     bound alone could wait FOREVER if the row were still mis-keyed —
#     measured: this exact scenario sat 34 minutes at a healthy,
#     advancing tip (347) until killed by hand. A second MAX_HEIGHTS
#     bound (20, a judgment) now returns a distinct rc=2 ("dropped, not
#     delayed") separately from rc=1 ("stalled").
#   - **NEITHER OUTCOME IS DISTINGUISHED FROM A GENUINE SILENT DROP.**
#     rc=1 and rc=2 are distinguished from EACH OTHER, not from "the
#     ledger silently refused this transaction after CheckTx approved
#     it" — either way this scenario reports FAIL; telling a drop, a
#     stall and starvation apart needs reading the node logs by hand.
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
stagef_sentinel SETUP_OK   # W4-H: the runner turns PASS-without-ASSERT_RUN into FAIL

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

stagef_cmt_diff_at_floor "pre-v2-stake" || exit 2

# ── Stage 1: fund the staker from its OWN leaf ──────────────────────
# Self-contained on purpose: depending on test_v2_claim.sh having run
# would make this scenario order-dependent, which is the defect the
# legacy suite's residue list is entirely about.
#
# DELTA 2, MEASURED — "wait tip+1, then trust the stake to notice" is
# UNSOUND for the same reason test_v2_claim.sh's row check was: CheckTx
# admission does not promise next-block inclusion (measured: a stake
# envelope on THIS scenario was approved at tip 2 and its row did not
# appear until tip 4). Dry-run FIRST to capture the funding claim's own
# nullifier, the same capture test_v2_claim.sh uses, so this stage can
# wait for the LEDGER EFFECT itself rather than assume it landed one
# height after submission.
t0=$(tip)
fdry="$BASE_DIR/v2stake_claim_dry.log"
if ! "$CLI" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$sdb" \
       --keys "$keys" --dry-run > "$fdry" 2>&1; then
    cat "$fdry" >&2; die "the funding claim could not be BUILT (local self-check failed)"
fi
fund_nullifier=$(awk '/^ *nullifier=/{sub(/^ *nullifier=/,""); print}' "$fdry")
[ "${#fund_nullifier}" = 128 ] || die "could not read a 64-byte nullifier from the funding claim's dry-run"

log="$BASE_DIR/v2stake_claim.log"
if ! "$CLI" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$sdb" \
       --keys "$keys" --submit "127.0.0.1:$port" > "$log" 2>&1; then
    cat "$log" >&2; die "could not claim the user identity's allocation (CheckTx REJECTED)"
fi
echo "[ok] funding claim APPROVED into the mempool"

# Liveness only (some block committed) — NOT proof this claim was in it.
t0_live=$(stagef_cmt_wait_height "$sdb" "$(( t0 + 1 ))" 2) \
    || die "tip did not advance after the funding claim was approved — the chain itself looks stalled"

# The ledger effect itself, keyed on tx_hash (nodus_witness_v2_claims.c
# :809,830-841 — the claim's own nullifier lands in tx_hash, a HASH of
# it lands in the nullifier column; see test_v2_claim.sh for the full
# citation). A claim's nullifier is signature-independent (see this
# script's header) so — unlike the stake below — this dry-run capture is
# safe to match against the real submission. stagef_cmt_wait_row returns
# the CHAIN'S current tip on success, never the row's own height — read
# that separately below. DELTA 3, DEFECT 2 — distinguish a STALL (rc=1)
# from a healthy chain that never included this claim (rc=2).
fund_stall_at=$(stagef_cmt_wait_row "$sdb" \
    "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$fund_nullifier';" 4) \
    && fund_wait_rc=0 || fund_wait_rc=$?
if [ "$fund_wait_rc" = 1 ]; then
    die "the funding claim's utxo_set row never appeared and the chain STALLED at $fund_stall_at — approved but never applied, or the chain stopped advancing; indistinguishable from outside"
elif [ "$fund_wait_rc" = 2 ]; then
    die "the funding claim was not included within 20 heights of submission (tip $t0 -> $fund_stall_at) — dropped, not delayed"
fi
t1=$(sqlite3 "$sdb" \
    "SELECT block_height FROM utxo_set WHERE lower(hex(tx_hash)) = '$fund_nullifier' LIMIT 1;" \
    2>/dev/null || true)
[ -n "$t1" ] || die "the funding row appeared between polls but its block_height could not be read"
echo "[ok] the user identity funded by its own claim (tip $t0 -> $t1, live tip was $t0_live)"

# ── Stage 2: bond it ────────────────────────────────────────────────
# Dry-run FIRST to capture the INTENT id this envelope will carry — NOT
# the wire id. DELTA 3, DEFECT 1: the submit below is a SECOND,
# independent build of the same envelope, and the wire id commits the
# ML-DSA-87 signature bytes, which are RANDOMIZED per signing — the
# dry-run's wire_id and the real submission's committed tx_id are
# DIFFERENT VALUES for the identical stake (see this script's header for
# the full citation and the live measurement). intent_id is the
# AUTHORIZATION-WITNESS-INDEPENDENT identity: it is IDENTICAL whether
# read from this dry-run or from the real submission, so it is the value
# safe to capture once and match later.
dlog="$BASE_DIR/v2stake_envelope_dry.log"
if ! "$CLI" -s 127.0.0.1 -p "$port" v2-envelope stake --db "$sdb" \
       --keys "$keys" --bond "$BOND" --commission "$COMMISSION" \
       --dest-fp "$destfp" --dry-run > "$dlog" 2>&1; then
    cat "$dlog" >&2
    die "stake envelope could not be BUILT (local self-check failed)"
fi
intent_id=$(awk '/^ *intent_id=/{sub(/^ *intent_id=/,""); print}' "$dlog")
[ "${#intent_id}" = 128 ] || die "could not read a 64-byte intent_id from the stake dry-run"
echo "[ok] stake envelope builds locally (intent_id=${intent_id:0:16}...)"

slog="$BASE_DIR/v2stake_envelope.log"
if ! "$CLI" -s 127.0.0.1 -p "$port" v2-envelope stake --db "$sdb" \
       --keys "$keys" --bond "$BOND" --commission "$COMMISSION" \
       --dest-fp "$destfp" --submit "127.0.0.1:$port" \
       > "$slog" 2>&1; then
    cat "$slog" >&2
    die "stake envelope was REJECTED (CheckTx admission failed) — read the log above BEFORE assuming consensus"
fi
echo "[ok] stake envelope APPROVED into the mempool (bond=$BOND commission=${COMMISSION}bps)"

# The chain must move AT ALL after the stake submission (liveness only —
# NOT proof the stake itself was included; without SOME delta here the
# funding claim's own +1 would carry the whole scenario undetected).
t1_live=$(stagef_cmt_wait_height "$sdb" "$(( t1 + 1 ))" 2) \
    || die "tip did not advance past $t1 — the chain itself looks stalled, not merely the stake"
echo "[ok] tip advanced past the funding height: $t1 -> $t1_live (liveness only)"

# DELTA 2, MEASURED on THIS scenario: the stake envelope this header's
# own DELTA 2 note is about was APPROVED at tip 2 and its identity row
# did not appear until tip 4 — "wait t1+1, then assert the row" is
# exactly the unsound shape that measurement disproved. Wait for the
# ROW ITSELF, then read its OWN height.
#
# DELTA 3, DEFECT 1 — keyed on `v2_intent_index.intent_id`, NEVER
# `v2_tx_index.tx_id` (wire_id): the wire_id would never match a
# dry-run capture (see the header). `cmt_item_index`
# (nodus_witness_v2_apply.c:2040-2059) writes BOTH `v2_intent_index` and
# `v2_tx_index` inside the SAME insert sequence for the same applied
# item, in the SAME transaction, so `v2_intent_index`'s `global_height`
# is exactly as authoritative as `v2_tx_index`'s would have been.
#
# DELTA 3, DEFECT 2 — distinguish a STALL (rc=1) from a healthy chain
# that never included this stake (rc=2): measured need on this exact
# call — 34 minutes at a healthy, advancing tip (347) before this was
# killed by hand, back when the query was still mis-keyed on wire_id.
stall_at=$(stagef_cmt_wait_row "$sdb" \
    "SELECT COUNT(*) FROM v2_intent_index WHERE lower(hex(intent_id)) = '$intent_id';" 4) \
    && wait_rc=0 || wait_rc=$?
if [ "$wait_rc" = 1 ]; then
    die "the stake's v2_intent_index row never appeared and the chain STALLED at $stall_at — approved but never applied, or the chain stopped advancing; indistinguishable from outside"
elif [ "$wait_rc" = 2 ]; then
    die "the stake was not included within 20 heights of submission (tip $t1 -> $stall_at) — dropped, not delayed"
fi
t2=$(sqlite3 "$sdb" \
    "SELECT global_height FROM v2_intent_index WHERE lower(hex(intent_id)) = '$intent_id' LIMIT 1;" \
    2>/dev/null || true)
[ -n "$t2" ] || die "the stake's row appeared between polls but its global_height could not be read"
# The per-item result: presence of this row IS success — a REFUSED
# envelope's identity rows are written inside that item's own SAVEPOINT
# and rolled back with it (nodus_witness_v2_apply.c comment at
# :4165-4167), so a row here cannot exist for anything CheckTx approved
# but FinalizeBlock later refused.
echo "[ok] the stake's v2_intent_index row exists at height $t2 (intent_id ${intent_id:0:16}...)"

# ── Stage 3: the validator row exists, and identically ──────────────
# Every follower must reach $t2 first — a node one block behind would
# read a validators table one write older, which is lag, not divergence.
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    stagef_cmt_wait_height "$(stagef_node_chain_db "$n")" "$t2" 2 >/dev/null \
        || die "node$n never reached height $t2 (mesh replication stalled)"
done
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

stagef_sentinel ASSERT_RUN   # the terminal assertion is next
stagef_cmt_diff_at_floor "post-v2-stake" || exit 2

stagef_sentinel PASS
echo ""
echo "[PASS] a Ledger V2 STAKE envelope spent a claimed output, wrote validator"
echo "       state and bonded value at height $t2, and all $STAGEF_COMMITTEE_SIZE nodes agreed on both"
echo "       the state_root and the validator table."
