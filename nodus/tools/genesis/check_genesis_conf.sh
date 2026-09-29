#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════
# check_genesis_conf.sh — refuse a version-5 (cometbft + treasury + genesis
# outputs) genesis config that is not ready for the ceremony.
#
# Usage:
#   check_genesis_conf.sh <genesis.conf> --cli <path/to/nodus-cli>
#       --foundation-m <M> --foundation-pubkey <file> [--foundation-pubkey <file> ...]
#       [--derive <path/to/nodus-server>]
#
# Exit 0 = every check below passed (and, with --derive, the chain was
# derived in a throw-away directory and its chain id printed).
# Exit 1 = at least one check failed; every failure is printed.
# Exit 2 = usage error.
#
# WHAT IT CHECKS — the operator's mistakes this file can see before the
# builder does, against the decisions the numbers come from
# (docs/plans/decisions/2026-09-22-nodus-tokenomics-v3-operator.md §1 and
# docs/plans/decisions/2026-09-28-treasury-pools-and-exact-self-stake.md):
#   0. config_version = 5 (general multisig; 4 under W-A/W-C);
#   1. no REPLACE_ME_ marker remains;
#   2. Rule P.2: Σ allocations + Σ self_stake + reward_pool_initial +
#      Σ treasury balances + Σ genesis outputs == total_supply_raw (the
#      builder's own rule, gen_plan_build in
#      nodus/src/witness/nodus_witness_v2_gen.c);
#   3. total_supply_raw, reward_pool_initial, the ONE allocation (Founder,
#      source_id ordinal 1, 50M) and the nine [treasury] balances equal
#      the decision tables — exactly nine [treasury] blocks, pool_id 1..9
#      in order; since general multisig pools 5-9 hold 0 (they are
#      genesis outputs, check 10) (testnet_v3.conf.template);
#   4. exactly 7 validators, each self_stake EXACTLY 10M NODUS (10^15
#      raw — the builder's Rule P.1, gen_plan_build, and the chain's STAKE
#      rule since the final pre-testnet wipe W-B: treasury decision item 5
#      "Self-stake TAM 10M — ne az ne fazla") and commission_bps <= 5000
#      (decision §1: "üst sınır %50");
#   5. no duplicated source_id;
#   6. every dest_binding and unstake_destination_fp is 128 lowercase hex;
#   7. every pubkey is 5184 lowercase hex (DNAC_PUBKEY_SIZE = 2592 bytes;
#      nodus/tools/nodus_v2_gen_config.c) and every
#      unstake_destination_pubkey is 5184 '0' characters (general
#      multisig ONAY 2 — the derivation refuses anything else too);
#   8. gas_price_raw_per_unit = 121 and token_create_fee_raw = 10^11 are
#      written explicitly (final pre-testnet wipe W-C; decisions
#      2026-09-25-gas-price.md and 2026-09-28-token-create-fee-
#      governance.md) — the height-0 chain_config rows of params 5 / 6;
#   9. EVERY validator's unstake_destination_fp equals the FOUNDATION
#      MULTISIG ADDRESS recomputed here from the Foundation's public keys
#      and threshold (--foundation-pubkey files, --foundation-m), through
#      `nodus-cli msig address` — the SAME encoder the chain's auth_kind-3
#      parser uses (shared/dnac/msig_wire.c), never a second
#      implementation in shell. Decision 2026-09-29-general-multisig.md
#      (operator answers): the seven genesis validators' self-stake
#      returns to the Foundation multisig address, and "genesis kontrol
#      betiği Foundation adresini bilinen anahtarlardan yeniden hesaplayıp
#      karşılaştırır". The chain itself checks this field's SHAPE only
#      (nodus_witness_v2_gen.c) — no node can check its MEANING without
#      the descriptor, so this is the one place it is checked. Missing
#      Foundation arguments are a FAILURE, never a skipped check.
#  10. EXACTLY five [genesis_output] blocks — the Foundation pools 5..9 in
#      that order (the order is each coin's identity index) — each owned
#      by the Foundation multisig address of check 9 and holding the
#      decision's amount (50M, 150M, 100M, 30M, 50M NODUS).
#
# WHAT IT DOES NOT CHECK — the builder is the authority on these and
# refuses them itself (so run --derive before the ceremony):
#   - that a pubkey is a valid ML-DSA-87 key;
#   - every other genesis rule of gen_plan_build / _v3_validate.
#
# --derive runs `nodus-server --derive-v2-genesis <conf> -d <tmpdir>` in a
# fresh temporary directory, prints the chain id, and removes the
# directory. Nothing is ever written outside that temporary directory.
# ═════════════════════════════════════════════════════════════════════

set -u

usage() {
    echo "usage: $0 <genesis.conf> --cli <nodus-cli> --foundation-m <M>" >&2
    echo "          --foundation-pubkey <file> [--foundation-pubkey <file> ...]" >&2
    echo "          [--derive <nodus-server>]" >&2
    exit 2
}

[ $# -ge 1 ] || usage
CONF="$1"
shift
SERVER=""
CLI=""
FOUND_M=""
declare -a FOUND_PK=()
while [ $# -gt 0 ]; do
    case "$1" in
        --derive)            [ $# -ge 2 ] || usage; SERVER="$2"; shift 2 ;;
        --cli)               [ $# -ge 2 ] || usage; CLI="$2"; shift 2 ;;
        --foundation-m)      [ $# -ge 2 ] || usage; FOUND_M="$2"; shift 2 ;;
        --foundation-pubkey) [ $# -ge 2 ] || usage; FOUND_PK+=("$2"); shift 2 ;;
        *) usage ;;
    esac
done
[ -f "$CONF" ] || { echo "[FAIL] no such file: $CONF" >&2; exit 2; }

FAILS=0
fail() { echo "[FAIL] $*"; FAILS=$((FAILS + 1)); }

# ── decision §1, in raw units (1 NODUS = 10^8) ─────────────────────────
TOTAL_WANT=100000000000000000        # 1 000 000 000 NODUS
POOL_WANT=20000000000000000          # 200 000 000 NODUS reward reserve
N_VAL_WANT=7                         # "Genesis'te 7 Foundation validatorı"
SELF_STAKE_WANT=1000000000000000     # EXACTLY 10 000 000 NODUS (W-B)
MAX_COMMISSION=5000                  # "üst sınır %50"
INT64_MAX=9223372036854775807
# W-C — the two governed fee parameters' genesis values:
GAS_WANT=121                         # 2026-09-25-gas-price.md "121 good"
TC_FEE_WANT=100000000000             # 2026-09-28-token-create-fee-
                                     # governance.md: 1 000 NODUS

# The ONE allocation (treasury decision §Karar 3): source_id ordinal 1.
ALLOC_NAME=( "" "Founder" )
ALLOC_AMOUNT=( 0 5000000000000000 )    # 50 000 000 NODUS
N_ALLOCS=1

# The nine treasury pools (treasury decision answer 11: decision §1 table
# order; Foundation = 100M − 7 × 10M genesis stakes = 30M) → name / balance
POOL_NAME=( "" "Storage" "Compute" "VPN / Bandwidth" "Future services"
            "Security / bug bounty" "Liquidity / market making"
            "Ecosystem / developer grants"
            "Foundation (100M - 70M validator stake)" "Community airdrop" )
# General multisig (decision 2026-09-29-general-multisig.md, ONAY 2):
# pools 5-9 are the Foundation's and are GENESIS OUTPUTS to the Foundation
# multisig address — their treasury ROWS hold 0; the service pools 1-4
# stay keyless treasury rows.
POOL_AMOUNT=( 0 10000000000000000 10000000000000000 5000000000000000
              5000000000000000 0 0 0 0 0 )
N_POOLS=9
# The five genesis outputs, in DOCUMENT order (the order is each coin's
# index in its identity): pools 5, 6, 7, 8, 9 of the decision table.
GENOUT_NAME=( "Security / bug bounty (pool 5)" "Liquidity / market making (pool 6)"
              "Ecosystem / developer grants (pool 7)"
              "Foundation (pool 8, 100M - 70M validator stake)"
              "Community airdrop (pool 9)" )
GENOUT_AMOUNT=( 5000000000000000 15000000000000000 10000000000000000
                3000000000000000 5000000000000000 )
N_GENOUTS=5
VERSION_WANT=5

is_lhex() {  # $1 = value, $2 = exact length in characters
    [ "${#1}" -eq "$2" ] && [[ "$1" =~ ^[0-9a-f]+$ ]]
}
is_u64ish() {  # base-10, no sign, at most 18 digits (fits int64 sums)
    [[ "$1" =~ ^[0-9]{1,18}$ ]]
}

if grep -q $'\r' "$CONF"; then
    fail "carriage return in the file — the parser reads LF-terminated text only"
fi

# ── read the file ──────────────────────────────────────────────────────
# Same lexical rules as the parser: '#' starts a comment, blank lines are
# ignored, `key = value` with spaces around '='. Only the keys this
# script checks are collected; the parser remains the authority on the
# rest.
scope="top"
total=""; pool=""; version=""; gas=""; tcfee=""
n_val=0; n_alloc=0; n_treas=0; n_go=0
declare -a V_PK=() V_UPK=() V_FP=() V_STAKE=() V_COMM=()
declare -a A_SID=() A_DB=() A_AMT=()
declare -a T_ID=() T_BAL=()
declare -a G_OWNER=() G_AMT=()
lineno=0
while IFS= read -r raw || [ -n "$raw" ]; do
    lineno=$((lineno + 1))
    line="${raw%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [ -z "$line" ] && continue
    # ── 1. markers — on the comment-stripped line, because the template's
    # own comments mention the marker convention by name.
    if [[ "$line" =~ (REPLACE_ME_[A-Za-z0-9_]*) ]]; then
        fail "line $lineno: unfilled marker ${BASH_REMATCH[1]}"
        continue
    fi
    case "$line" in
        "[validator]")  scope="val";   n_val=$((n_val + 1));     continue ;;
        "[allocation]") scope="alloc"; n_alloc=$((n_alloc + 1)); continue ;;
        "[treasury]")   scope="treas"; n_treas=$((n_treas + 1)); continue ;;
        "[genesis_output]") scope="go"; n_go=$((n_go + 1));      continue ;;
        \[*) fail "line $lineno: unknown block header '$line'"; continue ;;
    esac
    case "$line" in
        *=*) ;;
        *) fail "line $lineno: not 'key = value'"; continue ;;
    esac
    key="${line%%=*}"; key="${key%"${key##*[![:space:]]}"}"
    val="${line#*=}";  val="${val#"${val%%[![:space:]]*}"}"
    case "$scope:$key" in
        top:config_version)              version="$val" ;;
        top:total_supply_raw)            total="$val" ;;
        top:reward_pool_initial)         pool="$val" ;;
        top:gas_price_raw_per_unit)      gas="$val" ;;
        top:token_create_fee_raw)        tcfee="$val" ;;
        val:pubkey)                     V_PK[$n_val]="$val" ;;
        val:unstake_destination_pubkey)  V_UPK[$n_val]="$val" ;;
        val:unstake_destination_fp)      V_FP[$n_val]="$val" ;;
        val:self_stake)                  V_STAKE[$n_val]="$val" ;;
        val:commission_bps)              V_COMM[$n_val]="$val" ;;
        alloc:source_id)                 A_SID[$n_alloc]="$val" ;;
        alloc:dest_binding)              A_DB[$n_alloc]="$val" ;;
        alloc:amount)                    A_AMT[$n_alloc]="$val" ;;
        treas:pool_id)                   T_ID[$n_treas]="$val" ;;
        treas:balance)                   T_BAL[$n_treas]="$val" ;;
        go:owner)                        G_OWNER[$n_go]="$val" ;;
        go:amount)                       G_AMT[$n_go]="$val" ;;
    esac
done < "$CONF"

# ── 0. the document version ────────────────────────────────────────────
[ "$version" = "$VERSION_WANT" ] || \
    fail "config_version '$version' — this build derives only $VERSION_WANT (the cometbft document with the nine [treasury] pools and the [genesis_output] blocks)"

# ── 3a. the two top-level economic numbers ─────────────────────────────
if ! is_u64ish "$total"; then
    fail "total_supply_raw '$total' is missing or not a base-10 integer of at most 18 digits"
elif [ "$total" != "$TOTAL_WANT" ]; then
    fail "total_supply_raw $total != decision §1 value $TOTAL_WANT (1 000 000 000 NODUS)"
fi
if ! is_u64ish "$pool"; then
    fail "reward_pool_initial '$pool' is missing or not a base-10 integer (write it explicitly)"
elif [ "$pool" != "$POOL_WANT" ]; then
    fail "reward_pool_initial $pool != decision §1 value $POOL_WANT (200 000 000 NODUS)"
fi

# ── 8. the governed fee parameters (W-C) ───────────────────────────────
# Optional for the parser (the builder defaults them to these same
# values), but the ceremony file writes them explicitly so the operator
# sees what the chain id binds — the reward_pool_initial rule above.
if ! is_u64ish "$gas"; then
    fail "gas_price_raw_per_unit '$gas' is missing or not a base-10 integer (write it explicitly)"
elif [ "$gas" != "$GAS_WANT" ]; then
    fail "gas_price_raw_per_unit $gas != decision value $GAS_WANT (2026-09-25-gas-price.md)"
fi
if ! is_u64ish "$tcfee"; then
    fail "token_create_fee_raw '$tcfee' is missing or not a base-10 integer (write it explicitly)"
elif [ "$tcfee" != "$TC_FEE_WANT" ]; then
    fail "token_create_fee_raw $tcfee != decision value $TC_FEE_WANT (1 000 NODUS, 2026-09-28-token-create-fee-governance.md)"
fi

# ── 4 / 7 / 6. validators ──────────────────────────────────────────────
[ "$n_val" -eq "$N_VAL_WANT" ] || \
    fail "$n_val [validator] blocks — decision §1 and the builder's Rule P.1 need exactly $N_VAL_WANT"
stake_sum=0
for ((i = 1; i <= n_val; i++)); do
    pk="${V_PK[$i]:-}"; upk="${V_UPK[$i]:-}"; fp="${V_FP[$i]:-}"
    st="${V_STAKE[$i]:-}"; cm="${V_COMM[$i]:-}"
    is_lhex "$pk" 5184  || fail "validator $i: pubkey is not 5184 lowercase hex characters"
    # general multisig ONAY 2: a genesis row's destination pubkey MUST be
    # all zero (the derivation refuses anything else too)
    [[ "$upk" =~ ^0{5184}$ ]] || fail "validator $i: unstake_destination_pubkey is not 5184 '0' characters (a genesis row's destination is the Foundation multisig address, never a single key)"
    is_lhex "$fp" 128   || fail "validator $i: unstake_destination_fp is not 128 lowercase hex characters"
    if ! is_u64ish "$st"; then
        fail "validator $i: self_stake '$st' is not a base-10 integer of at most 18 digits"
    else
        [ "$st" -eq "$SELF_STAKE_WANT" ] || \
            fail "validator $i: self_stake $st != exactly 10M NODUS ($SELF_STAKE_WANT raw) — Rule P.1, neither less nor more"
        if (( st > INT64_MAX - stake_sum )); then
            fail "validator $i: self_stake sum overflows"
        else
            stake_sum=$((stake_sum + st))
        fi
    fi
    if ! [[ "$cm" =~ ^[0-9]{1,5}$ ]]; then
        fail "validator $i: commission_bps '$cm' is not a base-10 integer"
    elif [ "$cm" -gt "$MAX_COMMISSION" ]; then
        fail "validator $i: commission_bps $cm > $MAX_COMMISSION (decision §1: at most 50 %)"
    fi
done

# ── 9. every genesis seat pays the FOUNDATION MULTISIG ADDRESS ─────────
# Recomputed from the known keys + threshold through the chain's own
# encoder (`nodus-cli msig address` → shared/dnac/msig_wire.c), never
# retyped: the operator supplies the keys, this script derives the
# address, and a transcription error in any validator block is caught
# here — the chain would accept it (shape only) and the 10M would be
# released to an address nobody controls.
FOUND_ADDR=""
if [ -z "$FOUND_M" ] || [ "${#FOUND_PK[@]}" -lt 2 ] || [ -z "$CLI" ]; then
    fail "Foundation multisig address NOT verified: pass --cli <nodus-cli> --foundation-m <M> and every --foundation-pubkey (decision 2026-09-29-general-multisig.md — the genesis seats' refund goes to that address)"
elif [ ! -x "$CLI" ]; then
    fail "--cli $CLI is not an executable"
else
    margs=()
    for f in "${FOUND_PK[@]}"; do
        [ -f "$f" ] || fail "--foundation-pubkey $f: no such file"
        margs+=(--pubkey "$f")
    done
    mout="$("$CLI" msig address --m "$FOUND_M" "${margs[@]}" 2>&1)" \
        || fail "nodus-cli msig address refused the Foundation keys: $mout"
    FOUND_ADDR="$(printf '%s\n' "$mout" | awk '/ address /{print $NF; exit}')"
    if ! is_lhex "$FOUND_ADDR" 128; then
        fail "could not read the Foundation multisig address from: $mout"
        FOUND_ADDR=""
    fi
fi
if [ -n "$FOUND_ADDR" ]; then
    for ((i = 1; i <= n_val; i++)); do
        [ "${V_FP[$i]:-}" = "$FOUND_ADDR" ] || \
            fail "validator $i: unstake_destination_fp is not the Foundation ${FOUND_M}-of-${#FOUND_PK[@]} multisig address $FOUND_ADDR"
    done
    echo "[ok] Foundation ${FOUND_M}-of-${#FOUND_PK[@]} multisig address $FOUND_ADDR (recomputed)"
fi

# ── 5 / 6 / 3b. allocations ────────────────────────────────────────────
alloc_sum=0
declare -A SEEN_SID=()
declare -a POOL_SEEN=()
for ((i = 1; i <= n_alloc; i++)); do
    sid="${A_SID[$i]:-}"; db="${A_DB[$i]:-}"; amt="${A_AMT[$i]:-}"
    if ! is_lhex "$sid" 128; then
        fail "allocation $i: source_id is not 128 lowercase hex characters"
        continue
    fi
    if [ -n "${SEEN_SID[$sid]:-}" ]; then
        fail "allocation $i: source_id duplicates allocation ${SEEN_SID[$sid]}"
    else
        SEEN_SID[$sid]=$i
    fi
    is_lhex "$db" 128 || fail "allocation $i: dest_binding is not 128 lowercase hex characters"
    if ! is_u64ish "$amt"; then
        fail "allocation $i: amount '$amt' is not a base-10 integer of at most 18 digits"
        continue
    fi
    if (( amt > INT64_MAX - alloc_sum )); then
        fail "allocation $i: amount sum overflows"
    else
        alloc_sum=$((alloc_sum + amt))
    fi
    # The allocation band: a source_id of 124 zeros followed by a 4-digit
    # decimal ordinal 0001..000N.
    ord=""
    if [[ "$sid" =~ ^0{124}([0-9]{4})$ ]]; then
        ord=$((10#${BASH_REMATCH[1]}))
    fi
    if [ -z "$ord" ] || [ "$ord" -lt 1 ] || [ "$ord" -gt "$N_ALLOCS" ]; then
        fail "allocation $i: source_id is not one of the allocation ids 1..$N_ALLOCS documented in testnet_v3.conf.template"
        continue
    fi
    POOL_SEEN[$ord]=$i
    if [ "$amt" != "${ALLOC_AMOUNT[$ord]}" ]; then
        fail "allocation $i ($ord, ${ALLOC_NAME[$ord]}): amount $amt != decision value ${ALLOC_AMOUNT[$ord]}"
    fi
done
for ((p = 1; p <= N_ALLOCS; p++)); do
    [ -n "${POOL_SEEN[$p]:-}" ] || fail "allocation $p (${ALLOC_NAME[$p]}) has no [allocation] block"
done

# ── 3c. the nine [treasury] pools ──────────────────────────────────────
treas_sum=0
[ "$n_treas" -eq "$N_POOLS" ] || \
    fail "$n_treas [treasury] blocks — the treasury decision (and the parser) need exactly $N_POOLS, pools 1..$N_POOLS in order"
for ((i = 1; i <= n_treas; i++)); do
    tid="${T_ID[$i]:-}"; bal="${T_BAL[$i]:-}"
    if [ "$tid" != "$i" ]; then
        fail "[treasury] block $i: pool_id '$tid' — block $i must be pool $i (pools 1..$N_POOLS in order)"
    fi
    if ! is_u64ish "$bal"; then
        fail "[treasury] block $i: balance '$bal' is not a base-10 integer of at most 18 digits"
        continue
    fi
    if (( bal > INT64_MAX - treas_sum )); then
        fail "[treasury] block $i: balance sum overflows"
    else
        treas_sum=$((treas_sum + bal))
    fi
    if [ "$i" -le "$N_POOLS" ] && [ "$bal" != "${POOL_AMOUNT[$i]}" ]; then
        fail "[treasury] pool $i (${POOL_NAME[$i]}): balance $bal != decision value ${POOL_AMOUNT[$i]}"
    fi
done

# ── 10. the genesis outputs (general multisig, config_version 5) ───────
# EXACTLY the five Foundation pools, in pool order 5..9 (the document
# order is each coin's identity index), each owned by the Foundation
# multisig address recomputed in check 9 and holding the decision's
# amount.
go_sum=0
[ "$n_go" -eq "$N_GENOUTS" ] || \
    fail "$n_go [genesis_output] blocks — the decision moves exactly $N_GENOUTS Foundation pools (5..9, in that order) to the Foundation multisig address"
for ((i = 1; i <= n_go; i++)); do
    ow="${G_OWNER[$i]:-}"; ga="${G_AMT[$i]:-}"
    is_lhex "$ow" 128 || fail "[genesis_output] $i: owner is not 128 lowercase hex characters"
    if [ -n "$FOUND_ADDR" ] && [ "$ow" != "$FOUND_ADDR" ]; then
        fail "[genesis_output] $i: owner is not the Foundation multisig address $FOUND_ADDR"
    fi
    if ! is_u64ish "$ga"; then
        fail "[genesis_output] $i: amount '$ga' is not a base-10 integer of at most 18 digits"
        continue
    fi
    if (( ga > INT64_MAX - go_sum )); then
        fail "[genesis_output] $i: amount sum overflows"
    else
        go_sum=$((go_sum + ga))
    fi
    if [ "$i" -le "$N_GENOUTS" ] && [ "$ga" != "${GENOUT_AMOUNT[$((i - 1))]}" ]; then
        fail "[genesis_output] $i (${GENOUT_NAME[$((i - 1))]}): amount $ga != decision value ${GENOUT_AMOUNT[$((i - 1))]}"
    fi
done

# ── 2. Rule P.2 ────────────────────────────────────────────────────────
if is_u64ish "$total" && is_u64ish "$pool"; then
    if (( alloc_sum > INT64_MAX - stake_sum )) || \
       (( alloc_sum + stake_sum > INT64_MAX - pool )) || \
       (( alloc_sum + stake_sum + pool > INT64_MAX - treas_sum )); then
        fail "Rule P.2: the sum overflows"
    else
        p2=$((alloc_sum + stake_sum + pool + treas_sum))
        if (( p2 > INT64_MAX - go_sum )); then
            fail "Rule P.2: the sum overflows"
        else
            p2=$((p2 + go_sum))
            if [ "$p2" != "$total" ]; then
                fail "Rule P.2: Σ allocations $alloc_sum + Σ self_stake $stake_sum + reward_pool_initial $pool + Σ treasury $treas_sum + Σ genesis outputs $go_sum = $p2 != total_supply_raw $total"
            fi
        fi
    fi
fi

if [ "$FAILS" -gt 0 ]; then
    echo "REFUSED: $FAILS check(s) failed — $CONF is not ready for the ceremony."
    exit 1
fi
echo "[ok] $CONF: version, markers, Rule P.2, decision amounts (Founder allocation + nine treasury pools + five Foundation genesis outputs), validators (every one paying the Foundation multisig address, destination pubkey all zero), source_ids and hex shapes all pass"

# ── optional: derive in a throw-away directory ─────────────────────────
[ -n "$SERVER" ] || exit 0
[ -x "$SERVER" ] || { echo "[FAIL] --derive: $SERVER is not an executable" >&2; exit 2; }
TMPD="$(mktemp -d "${TMPDIR:-/tmp}/check_genesis_conf.XXXXXX")" || {
    echo "[FAIL] --derive: could not create a temporary directory" >&2; exit 1; }
trap 'rm -rf -- "$TMPD"' EXIT
# The data directory is a SUBDIRECTORY, so the captured stderr never sits
# beside the chain database the derivation creates.
mkdir "$TMPD/data" || { echo "[FAIL] --derive: mkdir failed" >&2; exit 1; }
OUT="$("$SERVER" --derive-v2-genesis "$CONF" -d "$TMPD/data" 2>"$TMPD/derive.err")"
RC=$?
if [ "$RC" -ne 0 ]; then
    echo "[FAIL] --derive: nodus-server refused the config (rc=$RC):"
    cat "$TMPD/derive.err"
    exit 1
fi
CHAIN_ID="$(printf '%s\n' "$OUT" | awk '$1 == "chain-id" { print $2 }')"
if ! is_lhex "$CHAIN_ID" 64; then
    echo "[FAIL] --derive: no chain-id line in the derivation's output:"
    printf '%s\n' "$OUT"
    exit 1
fi
echo "[ok] derived in a temporary directory (now removed)"
echo "chain-id $CHAIN_ID"
exit 0
