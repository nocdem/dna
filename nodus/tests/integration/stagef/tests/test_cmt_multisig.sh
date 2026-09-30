#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_multisig.sh — a 2-of-3 multisig address receives a coin by a
# transfer and spends it with two of its three signatures (general
# multisig, final pre-testnet wipe)
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   Decision docs/plans/decisions/2026-09-29-general-multisig.md (design
#   §7 rev 2: address = SHA3-512("NDS.MSIG.v1" ‖ M ‖ N ‖ keys ascending),
#   spend = auth_kind 3), end to end on a REAL seven-node cometbft
#   cluster, through the offline CLI flow (design F6.1):
#   (1) `nodus-cli msig address --m 2` over the public keys of nodes 2, 3
#       and 4 prints a 128-hex address; node 1 sends FUND raw to it with
#       an ordinary `v2-envelope spend` — the coin lands owned by the
#       multisig address, identically on all seven nodes.
#   (2) `v2-envelope spend --msig` builds the UNSIGNED kind-3 envelope
#       (inputs named explicitly, change back to the address); `msig
#       combine` with ONE signature is REFUSED locally (the export fixed
#       K = 2 — auth_len is signed) and submits nothing.
#   (3) nodes 2 and 3 each `msig sign` offline; `msig combine` assembles
#       the two signatures, runs the chain's own auth hook locally and
#       submits over node 5's session. CheckTx admits it and the chain
#       applies it: its v2_intent_index row exists.
#   (4) 7/7: the multisig coin is gone; node 5 holds SEND raw under the
#       envelope's intent_id; the change (if any) is owned by the
#       multisig address under the same intent_id.
#   (5) GENESIS-FUNDED (config_version 5): stagef_up_v2.sh wrote ONE
#       genesis output to the SAME 2-of-3 address; 7/7 hold it as a
#       height-0 coin (identity = tx_hash, output_index 0), and nodes 2
#       and 4 spend it the same way — 7/7 it is gone and node 5 holds
#       GSEND more.
#   (6) state_root agrees 7/7 at the floor before and after.
#   The property that would be false if it failed: *an M-of-N address is
#   an ordinary coin owner — anyone can pay it, and M of its keys (never
#   fewer) spend it, identically on every node.*
#
# WHAT IT REQUIRES
#   A DEFAULT build — no -D, no fault-injection environment, no STAGEF_*
#   variable of its own, no epoch length (nothing here waits for a
#   boundary). nodus-server AND nodus-cli from THIS tree: an older CLI has
#   no `msig` command (the scenario FAILS on the address step, loudly); an
#   older server refuses auth_kind 3 at CheckTx (FAILS on the submit).
#   FUNDING: node 1's own coins (FUND + a fee margin). Node 1's genesis
#   leaf is claimed here only if node 1 is not already funded —
#   test_cmt_token_create.sh / test_cmt_self_delegate.sh, earlier in the
#   sweep, ordinarily already claimed it (the same "only if not already
#   funded" rule).
#
# WHAT IT LEAVES BEHIND
#   A multisig address holding the change of FUND − SEND − fee (and the
#   genesis coin's change); SEND (+ GSEND) raw more on node 5; three fees
#   moved into the reward pool; the genesis multisig coin spent; node 1's leaf
#   claimed if it was not; the files msig_* under $BASE_DIR (descriptor,
#   export, two signature files, logs). The chain a few blocks further
#   on. Nothing killed or restarted.
#
# HOW IT CAN LIE
#   - **Happy path of the chain rules only.** M-1 signatures are refused
#     by the CLI's own count check (2), never sent to the chain; the
#     chain-side refusals (M-1 signers, a wrong or unused descriptor, the
#     parse matrix) are test_v2_native.c §MSIG — not exercised here.
#   - **The genesis-funded path (5) can be ABSENT.** stagef_up_v2.sh
#     writes the genesis output only when a nodus-cli with `msig address`
#     was available at bring-up (its "[warn] no genesis multisig output"
#     line says otherwise); then (5) does not run and the PASS line says
#     "not run" — coverage that did not happen, never a pass of (5). A
#     second run on the same cluster finds the genesis coin already spent
#     and FAILS (5) loudly.
#   - **The coin is found by (owner, amount).** A rerun on the same
#     cluster funds a SECOND coin of the same amount; the scenario picks
#     the one created by ITS OWN funding intent (tx_hash = that
#     intent_id), never "any coin of that amount".
#   - **intent_id, never wire_id.** Inclusion is the SUBMIT's intent_id
#     in v2_intent_index with stagef_cmt_wait_row's stall / 20-height
#     bounds; the export's intent_id equals combine's (signatures are
#     authorization bytes, outside the intent) and both are printed.
#   - **rc=99 means the coverage did not happen.** Never a pass.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

REF=1
FUNDER=1
SPENDER=5                               # submits + receives, signs nothing
CONF="$BASE_DIR/v2_genesis.conf"
CLI="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"
FUND=100000000000                       # 1 000 NODUS into the address
SEND=40000000000                        #   400 NODUS out of it
MARGIN=100000000000                     # 1 000 NODUS of fee headroom

die() { echo "[FAIL] $*" >&2; exit 1; }

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
if [ ! -f "$CONF" ]; then
    echo "[SKIP] not a Ledger V2 cluster from this tree (no $CONF) — use stagef_up_v2.sh"
    exit 99
fi
port=$(stagef_tcp_port "$REF")
sport=$(stagef_tcp_port "$SPENDER")
key_dir() { echo "$(stagef_node_dir "$1")/identity"; }
for n in "$FUNDER" 2 3 4 "$SPENDER"; do
    [ -s "$(key_dir "$n")/nodus.pk" ] && [ -s "$(key_dir "$n")/nodus.fp" ] \
        || die "node$n has no identity"
done
FP1=$(cat "$(key_dir "$FUNDER")/nodus.fp")
FP5=$(cat "$(key_dir "$SPENDER")/nodus.fp")
stagef_sentinel SETUP_OK   # W4-H: the runner turns PASS-without-ASSERT_RUN into FAIL

stagef_cmt_diff_at_floor "pre-cmt-multisig" || exit 2

# ── Stage 1: the 2-of-3 address over nodes 2, 3, 4 ──────────────────
DESC="$BASE_DIR/msig_2of3.desc"
alog="$BASE_DIR/msig_address.log"
if ! "$CLI" msig address --m 2 --pubkey "$(key_dir 2)/nodus.pk" \
       --pubkey "$(key_dir 3)/nodus.pk" --pubkey "$(key_dir 4)/nodus.pk" \
       --descriptor-out "$DESC" > "$alog" 2>&1; then
    cat "$alog" >&2
    die "\`nodus-cli msig address\` failed — a CLI without the msig command?"
fi
MSIG=$(awk '/address /{print $NF; exit}' "$alog")
[ "${#MSIG}" = 128 ] || { cat "$alog" >&2; die "could not read a 128-hex multisig address"; }
[ "$(stat -c %s "$DESC")" = $(( 18 + 3 * 2592 )) ] \
    || die "the descriptor is not 18 + 3 x 2592 bytes"
echo "[ok] 2-of-3 address over nodes 2/3/4: ${MSIG:0:16}..."

# ── Stage 2: fund node 1 (its own leaf, only if needed) ──────────────
spendable() {
    sqlite3 "$ref_db" \
        "SELECT COALESCE(SUM(amount),0) FROM (SELECT amount FROM utxo_set
          WHERE owner = '$FP1' AND token_id = zeroblob(64)
            AND unlock_block <= (SELECT COALESCE(MAX(global_height),0) FROM v2_blocks)
          ORDER BY amount DESC LIMIT 14);" 2>/dev/null || echo 0
}
have=$(spendable)
want=$(( FUND + MARGIN ))
if [ "$have" -lt "$want" ]; then
    grep -q "^dest_binding = ${FP1}\$" "$CONF" \
        || die "node$FUNDER holds $have raw spendable (< $want) and the genesis config binds no leaf to it"
    flog="$BASE_DIR/msig_fund_claim.log"
    fdry="$BASE_DIR/msig_fund_claim_dry.log"
    "$CLI" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$ref_db" \
        --keys "$(key_dir "$FUNDER")" --dry-run > "$fdry" 2>&1 \
        || { cat "$fdry" >&2; die "node$FUNDER's funding claim could not be BUILT"; }
    fnul=$(awk '/^ *nullifier=/{sub(/^ *nullifier=/,""); print}' "$fdry")
    [ "${#fnul}" = 128 ] || die "could not read the funding claim's nullifier"
    "$CLI" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$ref_db" \
        --keys "$(key_dir "$FUNDER")" --submit "127.0.0.1:$port" > "$flog" 2>&1 \
        || { cat "$flog" >&2; die "node$FUNDER's funding claim was REJECTED"; }
    fh=$(stagef_cmt_wait_row "$ref_db" \
        "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$fnul';" 4) \
        && fwrc=0 || fwrc=$?
    [ "$fwrc" = 0 ] || die "node$FUNDER's funding claim was not included (rc $fwrc, tip $fh)"
    have=$(spendable)
    [ "$have" -ge "$want" ] || die "node$FUNDER holds only $have raw after its claim"
fi
echo "[ok] node$FUNDER holds $have raw spendable (>= $want)"

# ── Stage 3: node 1 pays the multisig address (an ordinary transfer) ─
plog="$BASE_DIR/msig_pay.log"
"$CLI" -s 127.0.0.1 -p "$port" v2-envelope spend --keys "$(key_dir "$FUNDER")" \
    --to "$MSIG" --amount "$FUND" --submit "127.0.0.1:$port" > "$plog" 2>&1 \
    || { cat "$plog" >&2; die "the transfer TO the multisig address was REJECTED"; }
pay_intent=$(awk '/^ *intent_id=/{sub(/^ *intent_id=/,""); print; exit}' "$plog")
[ "${#pay_intent}" = 128 ] || die "could not read the transfer's intent_id"
ph=$(stagef_cmt_wait_row "$ref_db" \
    "SELECT COUNT(*) FROM v2_intent_index WHERE lower(hex(intent_id)) = '$pay_intent';" 4) \
    && prc=0 || prc=$?
[ "$prc" = 0 ] || die "the transfer to the multisig address was not included (rc $prc, tip $ph)"
coin=$(sqlite3 "$ref_db" \
    "SELECT lower(hex(nullifier)) FROM utxo_set
      WHERE owner = '$MSIG' AND amount = $FUND
        AND lower(hex(tx_hash)) = '$pay_intent';" 2>/dev/null || true)
[ "${#coin}" = 128 ] || die "no coin of $FUND raw owned by the multisig address under the transfer's intent"
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    stagef_cmt_wait_height "$db" "$ph" 2 >/dev/null || die "node$n never reached $ph"
    c=$(sqlite3 "$db" "SELECT COUNT(*) FROM utxo_set WHERE owner = '$MSIG'
                        AND lower(hex(nullifier)) = '$coin';" 2>/dev/null || echo ERR)
    [ "$c" = 1 ] || die "node$n: the multisig coin is not there ('$c')"
done
echo "[ok] 7/7: coin ${coin:0:16}... ($FUND raw) owned by the multisig address"

# ── Stage 4: the UNSIGNED kind-3 envelope, and a 1-signature refusal ─
EXP="$BASE_DIR/msig_spend.export"
blog="$BASE_DIR/msig_build.log"
"$CLI" -s 127.0.0.1 -p "$sport" v2-envelope spend --msig "$DESC" \
    --keys "$(key_dir "$SPENDER")" --in "$coin:$FUND" --to "$FP5" \
    --amount "$SEND" --export "$EXP" --submit "127.0.0.1:$sport" > "$blog" 2>&1 \
    || { cat "$blog" >&2; die "the unsigned multisig envelope could not be BUILT"; }
exp_intent=$(awk '/^ *intent_id=/{sub(/^ *intent_id=/,""); print; exit}' "$blog")
[ "${#exp_intent}" = 128 ] || die "could not read the export's intent_id"
change=$(sed -n 's/.* change=\([0-9]*\) .*/\1/p' "$blog" | head -1)
case "$change" in ''|*[!0-9]*) die "could not read the planned change" ;; esac
echo "[ok] unsigned kind-3 envelope exported (change $change back to the address)"

S2="$BASE_DIR/msig_sig_node2"
S3="$BASE_DIR/msig_sig_node3"
"$CLI" msig sign --keys "$(key_dir 2)" --in "$EXP" --out "$S2" \
    > "$BASE_DIR/msig_sign2.log" 2>&1 \
    || { cat "$BASE_DIR/msig_sign2.log" >&2; die "node 2 could not sign"; }
if "$CLI" msig combine --in "$EXP" --sig "$S2" --out "$BASE_DIR/msig_one_sig.env" \
       > "$BASE_DIR/msig_combine_one.log" 2>&1; then
    die "combine ACCEPTED one signature for a K = 2 export"
fi
grep -q "fixed 2 signers" "$BASE_DIR/msig_combine_one.log" \
    || { cat "$BASE_DIR/msig_combine_one.log" >&2; die "the one-signature refusal gave the wrong reason"; }
[ ! -e "$BASE_DIR/msig_one_sig.env" ] || die "a one-signature envelope was written"
echo "[ok] one signature (M - 1) refused by combine — nothing written or sent"

# ── Stage 5: the second signature, assembly, submission ──────────────
"$CLI" msig sign --keys "$(key_dir 3)" --in "$EXP" --out "$S3" \
    > "$BASE_DIR/msig_sign3.log" 2>&1 \
    || { cat "$BASE_DIR/msig_sign3.log" >&2; die "node 3 could not sign"; }
clog="$BASE_DIR/msig_combine.log"
t0=$(stagef_cmt_tip "$ref_db")
"$CLI" msig combine --in "$EXP" --sig "$S2" --sig "$S3" \
    --keys "$(key_dir "$SPENDER")" --submit "127.0.0.1:$sport" > "$clog" 2>&1 \
    || { cat "$clog" >&2; die "the 2-of-3 spend was REJECTED (CheckTx) — an older server without auth_kind 3?"; }
intent=$(awk '/^ *intent_id=/{sub(/^ *intent_id=/,""); print; exit}' "$clog")
[ "$intent" = "$exp_intent" ] || die "combine's intent_id differs from the export's"
sh=$(stagef_cmt_wait_row "$ref_db" \
    "SELECT COUNT(*) FROM v2_intent_index WHERE lower(hex(intent_id)) = '$intent';" 4) \
    && src=0 || src=$?
[ "$src" = 1 ] && die "the multisig spend never appeared and the chain STALLED at $sh"
[ "$src" = 2 ] && die "the multisig spend was not included within 20 heights (tip $t0 -> $sh)"
echo "[ok] the 2-of-3 spend applied (intent ${intent:0:16}...)"

stagef_sentinel ASSERT_RUN   # the terminal assertions follow

# ── Stage 6: the effects on all seven nodes ──────────────────────────
want_change=0
[ "$change" -gt 0 ] && want_change=1
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    db=$(stagef_node_chain_db "$n")
    stagef_cmt_wait_height "$db" "$sh" 2 >/dev/null || die "node$n never reached $sh"
    got=$(sqlite3 "$db" \
        "SELECT (SELECT COUNT(*) FROM utxo_set WHERE lower(hex(nullifier)) = '$coin')
             || '|' ||
                (SELECT COUNT(*) FROM utxo_set WHERE owner = '$FP5' AND amount = $SEND
                   AND lower(hex(tx_hash)) = '$intent')
             || '|' ||
                (SELECT COUNT(*) FROM utxo_set WHERE owner = '$MSIG' AND amount = $change
                   AND lower(hex(tx_hash)) = '$intent');" 2>/dev/null || echo ERR)
    [ "$got" = "0|1|$want_change" ] \
        || die "node$n: coin-left|to-node5|change = '$got', want '0|1|$want_change'"
done
echo "[ok] 7/7: the multisig coin is spent, node$SPENDER holds $SEND, change $change back to the address"

# ── Stage 7: the GENESIS-funded coin (config_version 5) ──────────────
# stagef_up_v2.sh wrote ONE genesis output to the SAME 2-of-3 address
# (nodes 2/3/4) and left the address in $BASE_DIR/msig_genesis.addr. It
# is a coin from height 0: identity = tx_hash, output_index 0,
# block_height 0 — found by those fields, never by "a coin of that
# amount". Spent here with nodes 2 and 4 (a different pair than above).
genesis_path="not run (bring-up wrote no genesis output — see stagef_up_v2.sh's [warn] line)"
if [ -s "$BASE_DIR/msig_genesis.addr" ]; then
    gaddr=$(cat "$BASE_DIR/msig_genesis.addr")
    [ "$gaddr" = "$MSIG" ] \
        || die "the bring-up's genesis multisig address differs from this scenario's (${gaddr:0:16}... vs ${MSIG:0:16}...)"
    gcoin=$(sqlite3 "$ref_db" \
        "SELECT lower(hex(nullifier)) || ':' || amount FROM utxo_set
          WHERE owner = '$MSIG' AND block_height = 0 AND output_index = 0
            AND tx_hash = nullifier LIMIT 1;" 2>/dev/null || true)
    [ -n "$gcoin" ] || die "no genesis coin owned by the 2-of-3 address (already spent by an earlier run on this cluster?)"
    gnul="${gcoin%%:*}"; gamt="${gcoin##*:}"
    for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
        db=$(stagef_node_chain_db "$n")
        c=$(sqlite3 "$db" "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(nullifier)) = '$gnul'
                            AND owner = '$MSIG' AND block_height = 0;" 2>/dev/null || echo ERR)
        [ "$c" = 1 ] || die "node$n: the genesis multisig coin is not there ('$c')"
    done
    echo "[ok] 7/7: genesis coin ${gnul:0:16}... ($gamt raw) owned by the 2-of-3 address"
    GSEND=30000000000                    # 300 NODUS
    GEXP="$BASE_DIR/msig_genesis_spend.export"
    "$CLI" -s 127.0.0.1 -p "$sport" v2-envelope spend --msig "$DESC" \
        --keys "$(key_dir "$SPENDER")" --in "$gnul:$gamt" --to "$FP5" \
        --amount "$GSEND" --export "$GEXP" --submit "127.0.0.1:$sport" \
        > "$BASE_DIR/msig_genesis_build.log" 2>&1 \
        || { cat "$BASE_DIR/msig_genesis_build.log" >&2; die "the genesis-coin envelope could not be BUILT"; }
    for n in 2 4; do
        "$CLI" msig sign --keys "$(key_dir "$n")" --in "$GEXP" \
            --out "$BASE_DIR/msig_genesis_sig_node$n" \
            > "$BASE_DIR/msig_genesis_sign$n.log" 2>&1 \
            || { cat "$BASE_DIR/msig_genesis_sign$n.log" >&2; die "node $n could not sign the genesis-coin spend"; }
    done
    "$CLI" msig combine --in "$GEXP" --sig "$BASE_DIR/msig_genesis_sig_node2" \
        --sig "$BASE_DIR/msig_genesis_sig_node4" --keys "$(key_dir "$SPENDER")" \
        --submit "127.0.0.1:$sport" > "$BASE_DIR/msig_genesis_combine.log" 2>&1 \
        || { cat "$BASE_DIR/msig_genesis_combine.log" >&2; die "the genesis-coin 2-of-3 spend was REJECTED"; }
    gintent=$(awk '/^ *intent_id=/{sub(/^ *intent_id=/,""); print; exit}' \
              "$BASE_DIR/msig_genesis_combine.log")
    [ "${#gintent}" = 128 ] || die "could not read the genesis-coin spend's intent_id"
    gh=$(stagef_cmt_wait_row "$ref_db" \
        "SELECT COUNT(*) FROM v2_intent_index WHERE lower(hex(intent_id)) = '$gintent';" 4) \
        && grc=0 || grc=$?
    [ "$grc" = 0 ] || die "the genesis-coin spend was not included (rc $grc, tip $gh)"
    for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
        db=$(stagef_node_chain_db "$n")
        stagef_cmt_wait_height "$db" "$gh" 2 >/dev/null || die "node$n never reached $gh"
        got=$(sqlite3 "$db" \
            "SELECT (SELECT COUNT(*) FROM utxo_set WHERE lower(hex(nullifier)) = '$gnul')
                 || '|' ||
                    (SELECT COUNT(*) FROM utxo_set WHERE owner = '$FP5' AND amount = $GSEND
                       AND lower(hex(tx_hash)) = '$gintent');" 2>/dev/null || echo ERR)
        [ "$got" = "0|1" ] || die "node$n: genesis-coin-left|to-node5 = '$got', want '0|1'"
    done
    genesis_path="RAN: genesis coin $gamt raw spent by nodes 2+4, $GSEND raw to node$SPENDER"
    echo "[ok] 7/7: the GENESIS multisig coin is spent (nodes 2 + 4), node$SPENDER holds $GSEND more"
fi

stagef_cmt_diff_at_floor "post-cmt-multisig" || exit 2

stagef_sentinel PASS
echo ""
echo "[PASS] a 2-of-3 address (nodes 2/3/4) received $FUND raw by a transfer and"
echo "       spent $SEND raw with two signatures; one signature was refused;"
echo "       genesis-funded path: $genesis_path;"
echo "       all $STAGEF_COMMITTEE_SIZE nodes agree on state_root."
