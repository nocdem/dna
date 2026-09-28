#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_token_create.sh — a CORE TOKEN_CREATE envelope registers a
# token, mints its supply, and the token moves — 7/7 agreement
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That a version-3 CORE TOKEN_CREATE envelope (runtime_op 3, built by
#   `nodus-cli v2-envelope token-create`) is applied identically by all
#   seven nodes, and that the token it creates is SPENDABLE. The
#   properties that would be false if it failed:
#     1. the envelope the CLI builds is admitted (CheckTx) and APPLIED —
#        its two ledger effects exist: the `tokens` registry row and the
#        token genesis output (`utxo_set`, tx_hash = the envelope's
#        intent_id, token_id = the new id, output_index 0);
#     2. both effects are byte-for-byte the same on all 7 nodes, and they
#        say what was asked: name / symbol / decimals / supply as given,
#        creator_fp = the genesis output's owner (rtn_tc_exec,
#        nodus_witness_rt_native.c:1898-1918), amount = the supply;
#     3. `nodus-cli v2-envelope spend --token <id>` moves PART of that
#        supply to another identity: the genesis output is gone, exactly
#        two token outputs exist (recipient + change), they sum to the
#        supply, and all 7 nodes hold them identically;
#     4. the global root and block id agree 7/7 at a floor every node has
#        reached (stagef_cmt_diff_at_floor) after both transactions.
#   This is the first scenario that reaches the `tokens` table and a
#   non-native UTXO on the Comet lane.
#
# WHAT IT REQUIRES
#   Compile flags: NONE — a default nodus/build. nodus-server AND
#   nodus-cli from the SAME tree (the CLI takes the CORE ruleset from its
#   own compiled table; a CLI built for another ruleset is refused at
#   CheckTx, and a CLI without `v2-envelope token-create` fails the build
#   step loudly).
#   Environment: a cluster from stagef_up_v2.sh (otherwise rc 99). No
#   STAGEF_* variable of its own.
#   FUNDING: the creator is NODE 1. Its genesis leaf is ALLOC = 10^16 raw
#   (stagef_up_v2.sh: `ALLOC=10000000000000000`, one leaf per node), ten
#   times the 10^15 creation fee (NODUS_W_TOKEN_CREATE_FEE,
#   nodus/include/nodus/nodus_types.h:285). No other scenario in
#   genesis_protocol_v2.sh's list claims node 1's leaf. If node 1 does
#   not already hold enough spendable native value, this scenario CLAIMS
#   that leaf first (the test_v2_stake.sh funding pattern) and waits for
#   the claimed coin as a ledger effect.
#
# WHAT IT LEAVES BEHIND
#   - Node 1's genesis leaf claimed (if it was not already).
#   - ONE permanent `tokens` row (a fresh random id per run, name
#     "Harness Token", symbol HTK) — the registry has no delete.
#   - Token coins: 25% of the supply owned by node 2, 75% by node 1.
#   - 10^15 raw (the creation fee) plus one spend fee moved from node 1
#     into supply_tracking.reward_pool (tokenomics-v3 §1: fees go to the
#     pool). Node 1's native balance is correspondingly smaller.
#   - The chain two or more blocks further on. Nothing killed or
#     restarted.
#
# HOW IT CAN LIE
#   - **A SKIP is not a pass.** rc 99 = the cluster was not Comet (or had
#     no genesis config / node 1 identity) — coverage that did not happen.
#   - **Only the happy path.** A duplicate token id, a bad name, a fee
#     below the floor, a non-native input — every REFUSAL rule — is not
#     exercised here; the CLI refuses most of them before submitting, and
#     the chain-side refusals are unit-test territory (test_v2_native.c).
#   - **The gas-price raise is not exercised.** The harness genesis has no
#     GAS_PRICE_RAW_PER_UNIT row, so the price is 0 and the CLI pays
#     exactly the compiled creation fee in one planning pass.
#   - **The effect declaration has no unit-test pin** (unlike the SPEND
#     one, test_v2_native.c §19). An UNDER-declaration would be admitted
#     by CheckTx and refused in-block: this scenario then fails with
#     "dropped, not delayed" (wait rc 2) — a FAIL, not a false pass. An
#     OVER-declaration would still pass (it only costs block units).
#   - **The reward-pool credit is not asserted** — the pool also moves at
#     every epoch boundary and payday, so a before/after difference would
#     race the chain's own settlement.
#   - **A rerun on the same cluster skips the claim** (node 1 already
#     funded) and creates a SECOND token under a new random id — it does
#     not fail on the funding half, and the second run's rows are keyed on
#     its own id and intent_id, never on the first run's.
#   - **Exporting STAGEF_PUMP_FUNDER_NODE=1** would make the height pump
#     and this scenario claim the same leaf; whichever runs second finds
#     it already claimed (this scenario then funds from whatever node 1
#     holds, or fails loudly on insufficient funds).
#   - **Inclusion waits** are stagef_cmt_wait_row's (stall rc 1 vs
#     20-heights rc 2), distinguished from each other, NOT from a genuine
#     silent drop — the same residual every Comet scenario discloses.
#   - **NEVER parse `committed:`**: the CLI's `accepted:` line is mempool
#     CheckTx admission, not inclusion. token_id= and intent_id= are read
#     from the SUBMIT output (intent_id commits expiry_height = tip +
#     margin, so a dry run's differs whenever a block lands in between —
#     the test_v2_stake.sh P2P-PORT F6 note).
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

REF=1
CONF="$BASE_DIR/v2_genesis.conf"
CLI="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"
CREATOR_DIR="$(stagef_node_dir 1)/identity"
RECIPIENT_DIR="$(stagef_node_dir 2)/identity"
TC_FEE=1000000000000000          # NODUS_W_TOKEN_CREATE_FEE (nodus_types.h:285)
MARGIN=100000000                 # 1 NODUS for the token spend's native fee
TK_NAME="Harness Token"
TK_SYM="HTK"
TK_DEC=8
TK_SUPPLY=2100000000000000       # 21M tokens at 8 decimals
TK_SEND=$(( TK_SUPPLY / 4 ))     # the part moved to node 2
TK_KEEP=$(( TK_SUPPLY - TK_SEND ))

die() { echo "[FAIL] $*" >&2; exit 1; }

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ] || [ ! -f "$CONF" ] || \
   [ ! -s "$CREATOR_DIR/nodus.pk" ] || [ ! -s "$RECIPIENT_DIR/nodus.fp" ]; then
    echo "[SKIP] not a Comet cluster with a genesis config and node identities"
    echo "       — use stagef_up_v2.sh"
    exit 99
fi
[ -x "$CLI" ] || die "no nodus-cli at $CLI"
stagef_sentinel SETUP_OK   # W4-H: the runner turns PASS-without-ASSERT_RUN into FAIL

port=$(stagef_tcp_port "$REF")
creator_fp=$(cat "$CREATOR_DIR/nodus.fp")
recipient_fp=$(cat "$RECIPIENT_DIR/nodus.fp")
[ "${#creator_fp}" = 128 ] && [ "${#recipient_fp}" = 128 ] \
    || die "a node fingerprint is not 128 hex chars"

# The creator's spendable native value as the CLI would select it: the
# 14 largest unlocked native coins (RTN_TC_MAX_IN = 14,
# nodus_witness_rt_native.c:375; the CLI picks largest first).
spendable() {
    sqlite3 "$ref_db" \
        "SELECT COALESCE(SUM(amount),0) FROM (SELECT amount FROM utxo_set
          WHERE owner = '$creator_fp' AND token_id = zeroblob(64)
            AND unlock_block <= (SELECT COALESCE(MAX(global_height),0) FROM v2_blocks)
          ORDER BY amount DESC LIMIT 14);" 2>/dev/null || echo 0
}

stagef_cmt_diff_at_floor "pre-cmt-token-create" || exit 2

# ── Stage 0: fund the creator from node 1's OWN leaf (if needed) ─────
have=$(spendable)
need=$(( TC_FEE + MARGIN ))
if [ "$have" -lt "$need" ]; then
    grep -q "^dest_binding = ${creator_fp}\$" "$CONF" \
        || die "node1 holds $have raw spendable (< $need) and the genesis config binds no leaf to it"
    fdry="$BASE_DIR/tokencreate_claim_dry.log"
    if ! "$CLI" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$ref_db" \
           --keys "$CREATOR_DIR" --dry-run > "$fdry" 2>&1; then
        cat "$fdry" >&2; die "node1's funding claim could not be BUILT (local self-check failed)"
    fi
    fund_nullifier=$(awk '/^ *nullifier=/{sub(/^ *nullifier=/,""); print}' "$fdry")
    [ "${#fund_nullifier}" = 128 ] || die "could not read a 64-byte nullifier from the funding claim's dry-run"
    flog="$BASE_DIR/tokencreate_claim.log"
    if ! "$CLI" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$ref_db" \
           --keys "$CREATOR_DIR" --submit "127.0.0.1:$port" > "$flog" 2>&1; then
        cat "$flog" >&2; die "node1's funding claim was REJECTED (CheckTx) — was its leaf already claimed and spent?"
    fi
    # A claim's nullifier is signature-independent (test_v2_stake.sh
    # header), so the dry run's value is the one the ledger writes into
    # utxo_set.tx_hash.
    fh=$(stagef_cmt_wait_row "$ref_db" \
        "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$fund_nullifier';" 4) \
        && fwrc=0 || fwrc=$?
    [ "$fwrc" = 1 ] && die "node1's funding claim never appeared and the chain STALLED at $fh"
    [ "$fwrc" = 2 ] && die "node1's funding claim was not included within 20 heights (tip $fh) — dropped, not delayed"
    have=$(spendable)
    [ "$have" -ge "$need" ] || die "node1 still holds only $have raw spendable after claiming its leaf (need $need)"
    echo "[ok] node1 funded by its own genesis leaf ($have raw spendable, tip $fh)"
else
    echo "[ok] node1 already holds $have raw spendable (>= $need) — no claim needed"
fi

# ── Stage 1: TOKEN_CREATE ────────────────────────────────────────────
# Dry run = a build + self-check gate only (see HOW IT CAN LIE: its
# intent_id and random token id are NOT the submitted ones).
dlog="$BASE_DIR/tokencreate_dry.log"
if ! "$CLI" -s 127.0.0.1 -p "$port" v2-envelope token-create \
       --keys "$CREATOR_DIR" --name "$TK_NAME" --symbol "$TK_SYM" \
       --decimals "$TK_DEC" --supply "$TK_SUPPLY" --dry-run > "$dlog" 2>&1; then
    cat "$dlog" >&2
    die "the TOKEN_CREATE envelope could not be BUILT (self-check against node $REF failed)"
fi
grep -q 'PREFLIGHT SELF-CHECK: OK' "$dlog" \
    || { cat "$dlog" >&2; die "the token-create dry run printed no self-check verdict"; }
echo "[ok] TOKEN_CREATE envelope builds and self-checks (dry run, nothing submitted)"

t0=$(stagef_cmt_tip "$ref_db")
tlog="$BASE_DIR/tokencreate.log"
if ! "$CLI" -s 127.0.0.1 -p "$port" v2-envelope token-create \
       --keys "$CREATOR_DIR" --name "$TK_NAME" --symbol "$TK_SYM" \
       --decimals "$TK_DEC" --supply "$TK_SUPPLY" \
       --submit "127.0.0.1:$port" > "$tlog" 2>&1; then
    cat "$tlog" >&2
    die "the TOKEN_CREATE envelope was REJECTED (CheckTx admission failed) — read the log above BEFORE assuming consensus"
fi
tid=$(awk '/^  token_id=/{sub(/^  token_id=/,""); print}' "$tlog")
intent=$(awk '/^  intent_id=/{sub(/^  intent_id=/,""); print}' "$tlog")
[ "${#tid}" = 128 ] || { cat "$tlog" >&2; die "could not read a 64-byte token_id from the SUBMIT output"; }
[ "${#intent}" = 128 ] || { cat "$tlog" >&2; die "could not read a 64-byte intent_id from the SUBMIT output"; }
stagef_sentinel TARGET_REACHED
echo "[ok] TOKEN_CREATE APPROVED into the mempool (token_id=${tid:0:16}... intent_id=${intent:0:16}..., tip $t0)"

# The ledger effect itself: the registry row, keyed on the NEW id.
th=$(stagef_cmt_wait_row "$ref_db" \
    "SELECT COUNT(*) FROM tokens WHERE lower(hex(token_id)) = '$tid';" 4) \
    && twrc=0 || twrc=$?
[ "$twrc" = 1 ] && die "the tokens row never appeared and the chain STALLED at $th"
[ "$twrc" = 2 ] && die "the TOKEN_CREATE was not included within 20 heights of submission (tip $t0 -> $th) — dropped, not delayed"
# The genesis output lands in the SAME block apply (one leg, one effect
# set); waited for anyway so a reader between two writes is not a FAIL.
gh=$(stagef_cmt_wait_row "$ref_db" \
    "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$intent'
       AND lower(hex(token_id)) = '$tid';" 4) \
    && gwrc=0 || gwrc=$?
[ "$gwrc" = 0 ] || die "the tokens row exists but the token genesis output never appeared (wait rc $gwrc, tip $gh)"
h_tc=$(sqlite3 "$ref_db" \
    "SELECT block_height FROM tokens WHERE lower(hex(token_id)) = '$tid' LIMIT 1;" 2>/dev/null || true)
[ -n "$h_tc" ] || die "the tokens row appeared but its block_height could not be read"
echo "[ok] the token is registered at height $h_tc"

# ── Stage 2: both effects identical on all 7, and as requested ───────
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    stagef_cmt_wait_height "$(stagef_node_chain_db "$n")" "$h_tc" 3 >/dev/null \
        || die "node$n never reached height $h_tc (mesh replication stalled)"
done
reg_q="SELECT name || '|' || symbol || '|' || decimals || '|' || supply || '|' ||
              creator_fp || '|' || flags || '|' || block_height
         FROM tokens WHERE lower(hex(token_id)) = '$tid';"
gen_q="SELECT lower(hex(nullifier)) || '|' || owner || '|' || amount || '|' ||
              output_index || '|' || block_height
         FROM utxo_set WHERE lower(hex(tx_hash)) = '$intent'
          AND lower(hex(token_id)) = '$tid';"
reg_first=""; gen_first=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    r=$(sqlite3 "$db" "$reg_q" 2>/dev/null || echo "ERR")
    g=$(sqlite3 "$db" "$gen_q" 2>/dev/null || echo "ERR")
    if [ "$n" = 1 ]; then reg_first="$r"; gen_first="$g"
    else
        [ "$r" = "$reg_first" ] || die "tokens row differs: node1=[$reg_first] node$n=[$r]"
        [ "$g" = "$gen_first" ] || die "token genesis output differs: node1=[$gen_first] node$n=[$g]"
    fi
done
expect_reg="$TK_NAME|$TK_SYM|$TK_DEC|$TK_SUPPLY|$creator_fp|0|$h_tc"
[ "$reg_first" = "$expect_reg" ] \
    || die "tokens row is not what was asked: got [$reg_first] expected [$expect_reg]"
IFS='|' read -r gen_nul gen_owner gen_amt gen_idx gen_h <<< "$gen_first"
[ "$gen_owner" = "$creator_fp" ] && [ "$gen_amt" = "$TK_SUPPLY" ] && \
[ "$gen_idx" = 0 ] && [ "$gen_h" = "$h_tc" ] \
    || die "token genesis output is not what was asked: [$gen_first]"
echo "[ok] tokens row + genesis output identical on all $STAGEF_COMMITTEE_SIZE nodes ($TK_SYM, supply $TK_SUPPLY, output[0] at $h_tc)"

# ── Stage 3: the token moves (v2-envelope spend --token) ─────────────
slog="$BASE_DIR/tokencreate_spend.log"
t1=$(stagef_cmt_tip "$ref_db")
if ! "$CLI" -s 127.0.0.1 -p "$port" v2-envelope spend --keys "$CREATOR_DIR" \
       --to "$recipient_fp" --amount "$TK_SEND" --token "$tid" \
       --submit "127.0.0.1:$port" > "$slog" 2>&1; then
    cat "$slog" >&2
    die "the token spend was REJECTED (CheckTx admission failed) — see above"
fi
intent2=$(awk '/^  intent_id=/{sub(/^  intent_id=/,""); print}' "$slog")
[ "${#intent2}" = 128 ] || { cat "$slog" >&2; die "could not read a 64-byte intent_id from the token spend's output"; }
echo "[ok] token spend APPROVED ($TK_SEND to node2, intent_id=${intent2:0:16}..., tip $t1)"

sh=$(stagef_cmt_wait_row "$ref_db" \
    "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$intent2'
       AND lower(hex(token_id)) = '$tid';" 4) \
    && swrc=0 || swrc=$?
[ "$swrc" = 1 ] && die "the token spend's outputs never appeared and the chain STALLED at $sh"
[ "$swrc" = 2 ] && die "the token spend was not included within 20 heights of submission (tip $t1 -> $sh) — dropped, not delayed"
h_sp=$(sqlite3 "$ref_db" \
    "SELECT MAX(block_height) FROM utxo_set WHERE lower(hex(tx_hash)) = '$intent2';" 2>/dev/null || true)
[ -n "$h_sp" ] || die "the token spend's rows appeared but their block_height could not be read"

for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    stagef_cmt_wait_height "$(stagef_node_chain_db "$n")" "$h_sp" 3 >/dev/null \
        || die "node$n never reached height $h_sp (mesh replication stalled)"
done
tok_q="SELECT owner || '|' || amount || '|' || output_index || '|' || block_height
         FROM utxo_set WHERE lower(hex(tx_hash)) = '$intent2'
          AND lower(hex(token_id)) = '$tid' ORDER BY owner, amount;"
gone_q="SELECT COUNT(*) FROM utxo_set WHERE lower(hex(nullifier)) = '$gen_nul';"
tok_first=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    t=$(sqlite3 "$db" "$tok_q" 2>/dev/null || echo "ERR")
    gone=$(sqlite3 "$db" "$gone_q" 2>/dev/null || echo "ERR")
    [ "$gone" = 0 ] || die "node$n still holds the token genesis output after the spend (count [$gone])"
    if [ "$n" = 1 ]; then tok_first="$t"
    else
        [ "$t" = "$tok_first" ] || die "token outputs differ: node1=[$tok_first] node$n=[$t]"
    fi
done
n_tok=$(printf '%s\n' "$tok_first" | grep -c . || true)
[ "$n_tok" = 2 ] || die "expected exactly 2 token outputs (recipient + change), got $n_tok: [$tok_first]"
got_send=$(printf '%s\n' "$tok_first" | awk -F'|' -v o="$recipient_fp" '$1==o{print $2}')
got_keep=$(printf '%s\n' "$tok_first" | awk -F'|' -v o="$creator_fp" '$1==o{print $2}')
[ "$got_send" = "$TK_SEND" ] && [ "$got_keep" = "$TK_KEEP" ] \
    || die "token outputs are not recipient $TK_SEND + change $TK_KEEP: [$tok_first]"
echo "[ok] token outputs identical on all $STAGEF_COMMITTEE_SIZE nodes: node2 $TK_SEND + node1 $TK_KEEP = supply, genesis output spent (height $h_sp)"

stagef_sentinel ASSERT_RUN   # the terminal assertion is next
stagef_cmt_diff_at_floor "post-cmt-token-create" || exit 2

stagef_sentinel PASS
echo ""
echo "[PASS] a CORE TOKEN_CREATE registered $TK_SYM (token_id ${tid:0:16}...) at height $h_tc"
echo "       with supply $TK_SUPPLY minted to node1, a token spend moved $TK_SEND of it"
echo "       to node2 at height $h_sp, and all $STAGEF_COMMITTEE_SIZE nodes agree on the"
echo "       registry row, every token output and the global root."
