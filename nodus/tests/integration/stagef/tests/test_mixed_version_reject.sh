#!/usr/bin/env bash
#
# Stage F — O15C-D.4 — a stale-protocol validator must not participate.
#
# ── What is being proven ──────────────────────────────────────────────
#
# O15C-D.3 added three proof-bearing NEW_VIEW keys. CBOR skips unknown
# keys and nothing read `hdr->version`, so a legacy binary silently
# processed those messages under the pre-D.3 local-subset semantics.
# Reproduced on real binaries (bc0ff148 vs c65c8cd1): the legacy node
# committed byte-identical blocks AND its vote counted toward quorum.
#
# The repair bumps NODUS_T3_BFT_PROTOCOL_VER 2 -> 3 and gates the
# consensus-affecting message set on an exact version match, after wsig
# verification and before any BFT state changes.
#
# ── Why the cluster is built THIS way ─────────────────────────────────
#
# A mixed cluster started from scratch never reaches steady state: the
# PRE-EXISTING H-9 bootstrap guard (nodus_witness_bootstrap.c,
# "MIXED VERSION CLUSTER DETECTED", exit 3) fires during DISCOVER and
# kills every current node. H-9 only runs while a FRESH node bootstraps —
# a node that already has a chain goes INIT -> HAVE_CHAIN -> DONE and
# never re-enters DISCOVER, which is exactly why H-9 did NOT prevent the
# pre-fix silent participation (it fired zero times in that run).
#
# So: bring up a HOMOGENEOUS current cluster, let genesis commit, THEN
# swap one node's binary and restart it against its existing data
# directory. Bootstrap is bypassed and the D.4 gate is what is under test.
#
# ── The proof is quorum arithmetic, not log-grepping ──────────────────
#
# With node7 legacy and two current nodes stopped, the live set is
# 4 current + 1 legacy = 5 = quorum. If the legacy vote still counted the
# chain would advance — it did exactly that before the fix. Post-fix it
# must STALL, and must RESUME the moment a current node returns. That is
# behavioural, and immune to "the logs said so".
#
# Env: STAGEF_LEGACY_NODUS_BIN must point at the historical build.

set -uo pipefail

. "$(dirname "$0")/../stagef_env.sh"

fail() { echo "[FAIL] $*" >&2; exit 1; }
ok()   { echo "[ok] $*"; }
info() { echo "[info] $*"; }

[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || \
    fail "no active Stage F harness. Run stagef_up.sh first."
LEGACY="${STAGEF_LEGACY_NODUS_BIN:-}"
[ -x "$LEGACY" ] || fail "STAGEF_LEGACY_NODUS_BIN not set/executable"
command -v sqlite3 >/dev/null || fail "sqlite3 CLI required"

N=7
STALE=7
head_of() {
    local db; db=$(ls "$BASE_DIR/node$1/data"/witness_*.db 2>/dev/null | head -1)
    [ -n "$db" ] || { echo ""; return; }
    sqlite3 -readonly "$db" "SELECT COALESCE(MAX(height),0) FROM blocks;" 2>/dev/null
}
send_tx() {
    local dest="$1" memo="$2"
    HOME="$BASE_DIR/user" DNA_NO_FALLBACK=1 "$STAGEF_DNACLI_BIN" \
        -q dna send "$dest" 50000000 "$memo" > "$BASE_DIR/${memo}.log" 2>&1
    echo $?
}

mapfile -t PIDS < "$BASE_DIR/pids.txt"

# ── 0. homogeneous baseline: the chain must exist first ───────────────
H_GEN=$(head_of 1)
[ -n "$H_GEN" ] && [ "${H_GEN:-0}" -ge 1 ] || \
    fail "no committed chain — the homogeneous bring-up did not complete"
ok "homogeneous current cluster committed genesis (head=$H_GEN)"

# ── 1. swap node7 to the LEGACY binary, same data directory ───────────
STALE_PID="${PIDS[$((STALE-1))]}"
CMDLINE=$(tr '\0' '\n' < "/proc/$STALE_PID/cmdline" 2>/dev/null | tail -n +2)
[ -n "$CMDLINE" ] || fail "could not read node$STALE cmdline (pid $STALE_PID)"
kill -TERM "$STALE_PID" 2>/dev/null
for _ in $(seq 1 20); do kill -0 "$STALE_PID" 2>/dev/null || break; sleep 1; done
kill -KILL "$STALE_PID" 2>/dev/null
ok "node$STALE (current) stopped"

# shellcheck disable=SC2086
"$LEGACY" $CMDLINE >> "$BASE_DIR/node$STALE/nodus.log" 2>&1 &
STALE_NEW=$!
# Record the new pid so stagef_down.sh tears it down too. Without this
# the respawned node outlives teardown, keeps its ports bound, and the
# NEXT bring-up fails with "port already in use".
echo "$STALE_NEW" >> "$BASE_DIR/pids.txt"
ok "node$STALE restarted on the LEGACY binary (pid $STALE_NEW, registered for teardown)"
sleep 25

grep -q "MIXED VERSION CLUSTER DETECTED" "$BASE_DIR/node$STALE/nodus.log" && \
    info "node$STALE logged the H-9 bootstrap guard (expected only if it re-entered DISCOVER)"

# ── 2. the gate must actually be firing on current nodes ──────────────
H0=$(head_of 1)
DEST=$(cat "$BASE_DIR/node2/identity/nodus.fp")
info "head before probe: $H0"
rc=$(send_tx "$DEST" "d4_mix_probe1"); info "probe1 client rc=$rc"
sleep 30

rej=0
for n in $(seq 1 6); do
    c=$(grep -c "INCOMPATIBLE PEER" "$BASE_DIR/node$n/nodus.log" 2>/dev/null || echo 0)
    [ "${c:-0}" -gt 0 ] && rej=$((rej+1))
done
[ "$rej" -ge 1 ] || fail "no current node reported an INCOMPATIBLE PEER — the gate never fired, so nothing is being proven"
ok "version gate fired on $rej/6 current nodes (diagnostic, not a silent stall)"

# ── 3. QUORUM ARITHMETIC — the decisive test ──────────────────────────
# Stop two CURRENT nodes: live set = 4 current + 1 legacy = 5 = quorum.
kill -STOP "${PIDS[4]}" "${PIDS[5]}" 2>/dev/null
ok "stopped node5 and node6 (current) — live set is 4 current + 1 legacy = 5 = quorum"

H1=$(head_of 1)
rc=$(send_tx "$DEST" "d4_mix_probe2"); info "probe2 client rc=$rc"
sleep 70
H2=$(head_of 1)
info "head $H1 -> $H2 with the legacy node making up the fifth vote"

if [ "${H2:-0}" -gt "${H1:-0}" ]; then
    kill -CONT "${PIDS[4]}" "${PIDS[5]}" 2>/dev/null
    fail "chain ADVANCED with 4 current + 1 legacy — the stale validator was COUNTED toward quorum (this is the pre-fix behaviour)"
fi
ok "chain did NOT advance — the stale validator is NOT counted toward quorum"

# ── 4. ...and it resumes as soon as a CURRENT node returns ────────────
# Proves the stall is the version gate, not an unrelated wedge.
kill -CONT "${PIDS[4]}" 2>/dev/null
ok "resumed node5 (current) — live set is 5 current"
rc=$(send_tx "$DEST" "d4_mix_probe3"); info "probe3 client rc=$rc"
deadline=$(( SECONDS + 120 ))
H3=$H2
while [ $SECONDS -lt $deadline ]; do
    H3=$(head_of 1)
    [ "${H3:-0}" -gt "${H2:-0}" ] && break
    sleep 3
done
kill -CONT "${PIDS[5]}" 2>/dev/null
[ "${H3:-0}" -gt "${H2:-0}" ] || \
    fail "chain did not resume with 5 CURRENT validators — the stall was not the version gate"
ok "chain RESUMED $H2 -> $H3 once a fifth CURRENT validator returned"

# ── 5. no block was committed under mixed semantics ───────────────────
ref=""
for n in $(seq 1 6); do
    row=$(sqlite3 -readonly "$(ls "$BASE_DIR/node$n/data"/witness_*.db | head -1)" \
        "SELECT MAX(height) || '|' || hex(state_root) FROM blocks \
           WHERE height = (SELECT MAX(height) FROM blocks);" 2>/dev/null || true)
    [ -n "$row" ] || fail "node$n has no committed blocks"
    if [ -z "$ref" ]; then ref="$row"
    elif [ "$row" != "$ref" ]; then fail "current node$n DIVERGED: $row != $ref"; fi
done
ok "all 6 current validators agree on height and state_root ($ref)"

echo
echo "=== MIXED-VERSION REJECTION PROVEN ==="
echo "    A stale-protocol validator cannot contribute to quorum, and the"
echo "    failure is diagnostic rather than a silent stall."
