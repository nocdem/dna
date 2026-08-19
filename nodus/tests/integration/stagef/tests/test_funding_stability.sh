#!/usr/bin/env bash
#
# Stage F — funding stability proof (O15C-D.1 §5).
#
# The OPEN harness-instability record's symptom is
# `stagef_mk_funded_user` failing with "Operation timed out" /
# "fund failed after 3 attempts", with a failure set that varied run to
# run. This scenario funds SEVEN distinct recipients on a fresh cluster
# and verifies the outcome from COMMITTED CHAIN STATE only.
#
# It is deliberately NOT a pass/fail on the CLI's opinion. The harness's
# standing rule is that a CLI exit code is not a commit in either
# direction, so every client result — success, failure or timeout — is
# reconciled against the chain, and the reconciliation is REPORTED so a
# green run cannot hide a client-side failure that the chain silently
# fixed up.
#
# §5 requires, per run:
#   * all seven intended funding outputs appear
#   * each output belongs to the intended recipient
#   * NO DUPLICATE funding output is created
#   * no accepted transaction silently disappears
#   * all validators agree on height and state root
#   * no blind client retry conceals a failure
#   * every indeterminate/failed client result is reconciled
#
# The duplicate check is the load-bearing one and the reason this does
# not simply reuse stagef_mk_funded_user: that helper's own success
# predicate is `COUNT(*) >= 1`, and it retries `dna send` up to three
# times, so a send that commits AFTER its chain poll but BEFORE the
# resend produces two funding outputs that the helper would report as
# success. Here the assertion is EQUALITY.

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

fail() { echo "[FAIL] $*" >&2; exit 1; }
ok()   { echo "[ok] $*"; }
info() { echo "[info] $*"; }

[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || \
    fail "no active Stage F harness. Run stagef_up.sh first."
command -v sqlite3 >/dev/null || fail "sqlite3 CLI required"

N=7
RECIPIENTS=7
FUND_RAW=1200000000000000

node_db() { stagef_node_chain_db "$1"; }
head_height() {
    sqlite3 -readonly "$(node_db 1)" "SELECT COALESCE(MAX(height),0) FROM blocks;"
}

# Count funding outputs owned by fp, on a given node's committed chain.
owned_count() {
    local node="$1" fp="$2" db
    db=$(node_db "$node")
    sqlite3 -readonly "$db" \
        "SELECT COUNT(*) FROM utxo_set WHERE owner = '$fp';" 2>/dev/null || echo "ERR"
}

# ── 1. create the recipients (identity only — no funding yet) ─────────
declare -a FPS=()
for i in $(seq 1 $RECIPIENTS); do
    th="$BASE_DIR/stab/user_$i"
    mkdir -p "$th/.dna"
    cp "$(stagef_user_home)/.dna/config" "$th/.dna/config"
    HOME="$th" DNA_NO_FALLBACK=1 "$STAGEF_DNACLI_BIN" \
        -q identity create "stab_$i" "stagefpw" > "$th/create.log" 2>&1 || true
    fp=$(HOME="$th" DNA_NO_FALLBACK=1 "$STAGEF_DNACLI_BIN" \
        -q identity whoami 2>&1 | awk '/^Current identity:/ {print $3; exit}')
    [ -n "$fp" ] && [ ${#fp} -ge 64 ] || fail "could not create recipient $i"
    FPS+=("$fp")
done
ok "created $RECIPIENTS distinct recipients"

# Every recipient must start with ZERO outputs, or the duplicate check
# below would be measuring pre-existing state.
for i in $(seq 0 $((RECIPIENTS-1))); do
    c=$(owned_count 1 "${FPS[$i]}")
    [ "$c" = "0" ] || fail "recipient $((i+1)) already owns $c output(s) before funding"
done
ok "all recipients start with zero committed outputs"

H_START=$(head_height)
info "head before funding: $H_START"

# ── 2. fund each recipient EXACTLY ONCE ───────────────────────────────
# One send per recipient. No retry loop: a retry is precisely what
# manufactures duplicates, and §5 forbids concealing a failure with one.
declare -a CLI_RC=()
for i in $(seq 0 $((RECIPIENTS-1))); do
    set +e
    stagef_dna -q dna send "${FPS[$i]}" "$FUND_RAW" "stab_fund_$((i+1))" \
        > "$BASE_DIR/stab/send_$((i+1)).log" 2>&1
    rc=$?
    set -e
    CLI_RC+=("$rc")
done
info "client exit codes: ${CLI_RC[*]} (recorded, not authoritative)"

# ── 3. wait for the chain to settle ───────────────────────────────────
deadline=$(( SECONDS + 240 ))
while [ $SECONDS -lt $deadline ]; do
    all=1
    for i in $(seq 0 $((RECIPIENTS-1))); do
        c=$(owned_count 1 "${FPS[$i]}")
        [ "$c" = "ERR" ] && { all=0; break; }
        [ "${c:-0}" -ge 1 ] || { all=0; break; }
    done
    [ "$all" -eq 1 ] && break
    sleep 3
done

# ── 4. §5 assertions, from committed chain state ──────────────────────
missing=0; dup=0
for i in $(seq 0 $((RECIPIENTS-1))); do
    c=$(owned_count 1 "${FPS[$i]}")
    case "$c" in
        0)  echo "[FAIL] recipient $((i+1)) has NO funding output (client rc=${CLI_RC[$i]})" >&2
            missing=$((missing+1)) ;;
        1)  ;;                       # exactly right
        ERR) fail "could not read utxo_set for recipient $((i+1))" ;;
        *)  echo "[FAIL] recipient $((i+1)) has $c funding outputs — DUPLICATE" >&2
            dup=$((dup+1)) ;;
    esac
done
[ "$missing" -eq 0 ] || fail "$missing recipient(s) never received their funding"
ok "all $RECIPIENTS intended funding outputs appear on chain"
[ "$dup" -eq 0 ] || fail "$dup recipient(s) received DUPLICATE funding outputs"
ok "no duplicate funding output was created"

# Ownership: each output must belong to the recipient it was sent to.
# (owned_count already keys on owner, so a cross-credit would show as a
# missing output on one recipient and a duplicate on another; this is the
# explicit statement of the property.)
for i in $(seq 0 $((RECIPIENTS-1))); do
    amt=$(sqlite3 -readonly "$(node_db 1)" \
        "SELECT amount FROM utxo_set WHERE owner = '${FPS[$i]}';" 2>/dev/null)
    [ "$amt" = "$FUND_RAW" ] || \
        fail "recipient $((i+1)) output amount $amt != intended $FUND_RAW"
done
ok "every output belongs to its intended recipient at the intended amount"

# ── 5. reconcile every client result against the chain ────────────────
# A non-zero CLI result that nonetheless committed is the known false
# negative; it must be REPORTED, never silently absorbed.
recon=0
for i in $(seq 0 $((RECIPIENTS-1))); do
    if [ "${CLI_RC[$i]}" != "0" ]; then
        recon=$((recon+1))
        info "recipient $((i+1)): client reported rc=${CLI_RC[$i]} but the chain committed the funding (reconciled false negative)"
    fi
done
if [ "$recon" -eq 0 ]; then
    ok "every client result agreed with the chain (no indeterminate results)"
else
    ok "$recon indeterminate client result(s) reconciled against committed state"
fi

# ── 6. all validators agree ───────────────────────────────────────────
H_END=$(head_height)
[ "${H_END:-0}" -gt "$H_START" ] || fail "chain did not advance during funding"

ref=""
for n in $(seq 1 $N); do
    row=$(sqlite3 -readonly "$(node_db "$n")" \
        "SELECT MAX(height) || '|' || hex(state_root) FROM blocks \
          WHERE height = (SELECT MAX(height) FROM blocks);" 2>/dev/null || true)
    [ -n "$row" ] || fail "node$n has no committed blocks"
    if [ -z "$ref" ]; then ref="$row"
    elif [ "$row" != "$ref" ]; then
        fail "node$n DIVERGED: $row != $ref"
    fi
done
ok "all $N validators agree on height and state_root ($ref)"

# Every recipient must be visible on every node, not just node1.
for n in $(seq 1 $N); do
    for i in $(seq 0 $((RECIPIENTS-1))); do
        c=$(owned_count "$n" "${FPS[$i]}")
        [ "$c" = "1" ] || fail "node$n sees $c output(s) for recipient $((i+1)), expected 1"
    done
done
ok "all $RECIPIENTS outputs visible with count==1 on all $N nodes"

echo
echo "=== FUNDING STABILITY RUN PASSED (head $H_START → $H_END) ==="
