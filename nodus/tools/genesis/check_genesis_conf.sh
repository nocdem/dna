#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════
# check_genesis_conf.sh — refuse a version-3 genesis config that is not
# ready for the ceremony.
#
# Usage:
#   check_genesis_conf.sh <genesis.conf>
#   check_genesis_conf.sh <genesis.conf> --derive <path/to/nodus-server>
#
# Exit 0 = every check below passed (and, with --derive, the chain was
# derived in a throw-away directory and its chain id printed).
# Exit 1 = at least one check failed; every failure is printed.
# Exit 2 = usage error.
#
# WHAT IT CHECKS — the operator's mistakes this file can see before the
# builder does, against the decision the numbers come from
# (docs/plans/decisions/2026-09-22-nodus-tokenomics-v3-operator.md §1):
#   1. no REPLACE_ME_ marker remains;
#   2. Rule P.2: Σ allocations + Σ self_stake + reward_pool_initial ==
#      total_supply_raw (the builder's own rule, gen_plan_build in
#      nodus/src/witness/nodus_witness_v2_gen.c);
#   3. total_supply_raw, reward_pool_initial and every pool amount equal
#      the decision table (pools identified by the source_id band 1..10
#      documented in testnet_v3.conf.template);
#   4. exactly 7 validators, each self_stake >= 10M NODUS (10^15 raw) and
#      commission_bps <= 5000 (decision §1: "üst sınır %50");
#   5. no duplicated source_id;
#   6. every dest_binding and unstake_destination_fp is 128 lowercase hex;
#   7. every pubkey and unstake_destination_pubkey is 5184 lowercase hex
#      (DNAC_PUBKEY_SIZE = 2592 bytes; nodus/tools/nodus_v2_gen_config.c).
#
# WHAT IT DOES NOT CHECK — the builder is the authority on these and
# refuses them itself (so run --derive before the ceremony):
#   - that unstake_destination_fp IS SHA3-512(unstake_destination_pubkey);
#   - that a pubkey is a valid ML-DSA-87 key;
#   - every other genesis rule of gen_plan_build / _v3_validate.
#
# --derive runs `nodus-server --derive-v2-genesis <conf> -d <tmpdir>` in a
# fresh temporary directory, prints the chain id, and removes the
# directory. Nothing is ever written outside that temporary directory.
# ═════════════════════════════════════════════════════════════════════

set -u

usage() {
    echo "usage: $0 <genesis.conf> [--derive <nodus-server>]" >&2
    exit 2
}

[ $# -ge 1 ] || usage
CONF="$1"
shift
SERVER=""
if [ $# -gt 0 ]; then
    [ "$1" = "--derive" ] && [ $# -eq 2 ] || usage
    SERVER="$2"
fi
[ -f "$CONF" ] || { echo "[FAIL] no such file: $CONF" >&2; exit 2; }

FAILS=0
fail() { echo "[FAIL] $*"; FAILS=$((FAILS + 1)); }

# ── decision §1, in raw units (1 NODUS = 10^8) ─────────────────────────
TOTAL_WANT=100000000000000000        # 1 000 000 000 NODUS
POOL_WANT=20000000000000000          # 200 000 000 NODUS reward reserve
N_VAL_WANT=7                         # "Genesis'te 7 Foundation validatorı"
MIN_SELF_STAKE=1000000000000000      # 10 000 000 NODUS
MAX_COMMISSION=5000                  # "üst sınır %50"
INT64_MAX=9223372036854775807

# source_id ordinal (1..10, decision §1 table order) → pool name / amount
POOL_NAME=( "" "Storage" "Compute" "VPN / Bandwidth" "Future services"
            "Security / bug bounty" "Liquidity / market making" "Founder"
            "Ecosystem / developer grants"
            "Foundation (100M - 70M validator stake)" "Community airdrop" )
POOL_AMOUNT=( 0 10000000000000000 10000000000000000 5000000000000000
              5000000000000000 5000000000000000 15000000000000000
              5000000000000000 10000000000000000 3000000000000000
              5000000000000000 )
N_POOLS=10

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
total=""; pool=""
n_val=0; n_alloc=0
declare -a V_PK=() V_UPK=() V_FP=() V_STAKE=() V_COMM=()
declare -a A_SID=() A_DB=() A_AMT=()
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
        \[*) fail "line $lineno: unknown block header '$line'"; continue ;;
    esac
    case "$line" in
        *=*) ;;
        *) fail "line $lineno: not 'key = value'"; continue ;;
    esac
    key="${line%%=*}"; key="${key%"${key##*[![:space:]]}"}"
    val="${line#*=}";  val="${val#"${val%%[![:space:]]*}"}"
    case "$scope:$key" in
        top:total_supply_raw)            total="$val" ;;
        top:reward_pool_initial)         pool="$val" ;;
        val:pubkey)                      V_PK[$n_val]="$val" ;;
        val:unstake_destination_pubkey)  V_UPK[$n_val]="$val" ;;
        val:unstake_destination_fp)      V_FP[$n_val]="$val" ;;
        val:self_stake)                  V_STAKE[$n_val]="$val" ;;
        val:commission_bps)              V_COMM[$n_val]="$val" ;;
        alloc:source_id)                 A_SID[$n_alloc]="$val" ;;
        alloc:dest_binding)              A_DB[$n_alloc]="$val" ;;
        alloc:amount)                    A_AMT[$n_alloc]="$val" ;;
    esac
done < "$CONF"

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

# ── 4 / 7 / 6. validators ──────────────────────────────────────────────
[ "$n_val" -eq "$N_VAL_WANT" ] || \
    fail "$n_val [validator] blocks — decision §1 and the builder's Rule P.1 need exactly $N_VAL_WANT"
stake_sum=0
for ((i = 1; i <= n_val; i++)); do
    pk="${V_PK[$i]:-}"; upk="${V_UPK[$i]:-}"; fp="${V_FP[$i]:-}"
    st="${V_STAKE[$i]:-}"; cm="${V_COMM[$i]:-}"
    is_lhex "$pk" 5184  || fail "validator $i: pubkey is not 5184 lowercase hex characters"
    is_lhex "$upk" 5184 || fail "validator $i: unstake_destination_pubkey is not 5184 lowercase hex characters"
    is_lhex "$fp" 128   || fail "validator $i: unstake_destination_fp is not 128 lowercase hex characters"
    if ! is_u64ish "$st"; then
        fail "validator $i: self_stake '$st' is not a base-10 integer of at most 18 digits"
    else
        [ "$st" -ge "$MIN_SELF_STAKE" ] || \
            fail "validator $i: self_stake $st is below 10M NODUS ($MIN_SELF_STAKE raw)"
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
    # The pool band: a source_id of 124 zeros followed by a 4-digit
    # decimal ordinal 0001..0010.
    ord=""
    if [[ "$sid" =~ ^0{124}([0-9]{4})$ ]]; then
        ord=$((10#${BASH_REMATCH[1]}))
    fi
    if [ -z "$ord" ] || [ "$ord" -lt 1 ] || [ "$ord" -gt "$N_POOLS" ]; then
        fail "allocation $i: source_id is not one of the pool ids 1..$N_POOLS documented in testnet_v3.conf.template"
        continue
    fi
    POOL_SEEN[$ord]=$i
    if [ "$amt" != "${POOL_AMOUNT[$ord]}" ]; then
        fail "allocation $i (pool $ord, ${POOL_NAME[$ord]}): amount $amt != decision §1 value ${POOL_AMOUNT[$ord]}"
    fi
done
for ((p = 1; p <= N_POOLS; p++)); do
    [ -n "${POOL_SEEN[$p]:-}" ] || fail "pool $p (${POOL_NAME[$p]}) has no [allocation] block"
done

# ── 2. Rule P.2 ────────────────────────────────────────────────────────
if is_u64ish "$total" && is_u64ish "$pool"; then
    if (( alloc_sum > INT64_MAX - stake_sum )) || \
       (( alloc_sum + stake_sum > INT64_MAX - pool )); then
        fail "Rule P.2: the sum overflows"
    else
        p2=$((alloc_sum + stake_sum + pool))
        if [ "$p2" != "$total" ]; then
            fail "Rule P.2: Σ allocations $alloc_sum + Σ self_stake $stake_sum + reward_pool_initial $pool = $p2 != total_supply_raw $total"
        fi
    fi
fi

if [ "$FAILS" -gt 0 ]; then
    echo "REFUSED: $FAILS check(s) failed — $CONF is not ready for the ceremony."
    exit 1
fi
echo "[ok] $CONF: markers, Rule P.2, decision §1 amounts, validators, source_ids and hex shapes all pass"

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
