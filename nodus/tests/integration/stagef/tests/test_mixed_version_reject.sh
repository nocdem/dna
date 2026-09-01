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
#
# ── HOW THIS CAN LIE, and how it did ──────────────────────────────────
#
# WHICH SIDE REFUSES DEPENDS ON WHICH LEGACY BINARY YOU BUILD, and §2's
# anti-vacuity check used to assume the wrong one.
#
# The gate was ADDED by the 2 -> 3 bump this scenario was written for, so
# the v2 binary it was written against had none: it kept talking and the
# CURRENT nodes refused it. Any legacy binary from v3 onward carries the
# gate itself — it drops every current-version frame on arrival, never
# advances, and therefore never sends a consensus vote, so the current
# nodes log NOTHING. §2 demanded a CURRENT-side refusal and therefore
# could not pass at all with a modern legacy binary; on 2026-09-01 with
# a v4 binary against v6 it failed there, with 33 refusals sitting in the
# legacy node's own log. §2 now accepts EITHER side and says which.
#
# A post-gate legacy binary also cannot DECODE new verbs at all — the
# same run shows `T3 decode failed ... w_viewok` on the legacy node — so
# an unknown verb is dropped below the gate rather than by it.
#
# ⚠ THE REGIMES ARE NOT EQUIVALENT, and §3 is what makes the result mean
# something either way: with 4 current + 1 legacy = quorum, the chain
# must STALL. Under a pre-gate legacy binary that proves the current
# nodes refuse a stale vote; under a post-gate one it proves an isolated
# stale node cannot make up a quorum. Only the FIRST exercises the
# CURRENT node's gate — that path's coverage otherwise lives in
# `ctest test_witness_protocol_version_gate` §2/§3.
#
# ⚠ `grep -c` prints "0" AND exits non-zero when it matches nothing.
# `$(grep -c ... || echo 0)` therefore yields TWO lines and every
# numeric test on it dies with "integer expression expected". Use
# `|| true`.

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

# ⚠ COUNT BOTH SIDES. This check is ANTI-VACUITY — it establishes that the
# version mismatch is real and is being ENFORCED somewhere, so §3's
# arithmetic is measuring the gate and not an unrelated wedge. Which side
# refuses depends on WHICH legacy binary is used, and both outcomes are
# correct:
#
#   * A legacy binary from BEFORE the gate existed (v2, the version this
#     scenario was originally written against) has no gate. It keeps
#     talking, and the CURRENT nodes are what refuse it.
#   * A legacy binary from v3 ONWARD carries the gate itself. It drops
#     every current-version frame on arrival, never advances, and
#     therefore never sends a consensus vote — so the current nodes have
#     nothing to refuse and log NOTHING. Measured 2026-09-01 with a v4
#     legacy binary against v6: 33 refusals on the legacy node, ZERO on
#     the six current ones, legacy stuck at head 1 while the cluster
#     reached 2.
#
# Requiring the CURRENT side specifically — which this check did until
# 2026-09-01 — makes the scenario UNPASSABLE with any post-v2 legacy
# binary, and it failed for that reason rather than for anything about
# the code.
#
# ⚠ `grep -c` prints "0" AND exits 1 when it matches nothing, so the old
# `|| echo 0` appended a SECOND line and `[ -gt ]` died with "integer
# expression expected". `|| true` keeps the count and swallows the status.
rej_cur=0
for n in $(seq 1 6); do
    c=$(grep -c "INCOMPATIBLE PEER" "$BASE_DIR/node$n/nodus.log" 2>/dev/null || true)
    [ "${c:-0}" -gt 0 ] && rej_cur=$((rej_cur+1))
done
rej_stale=$(grep -c "INCOMPATIBLE PEER" "$BASE_DIR/node$STALE/nodus.log" 2>/dev/null || true)
rej_stale=${rej_stale:-0}
info "version-gate refusals: current nodes $rej_cur/6, legacy node$STALE $rej_stale"
[ "$rej_cur" -ge 1 ] || [ "$rej_stale" -ge 1 ] || \
    fail "NEITHER side reported an INCOMPATIBLE PEER — the version gate never fired on any node, so the cluster is not actually mixed and nothing below is being proven"
if [ "$rej_cur" -ge 1 ]; then
    ok "version gate fired on $rej_cur/6 CURRENT nodes — the legacy node is speaking and is being refused"
else
    ok "version gate fired on the LEGACY node ($rej_stale refusals) — it carries the gate itself and self-isolates, so it never reaches the point of voting"
fi

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
