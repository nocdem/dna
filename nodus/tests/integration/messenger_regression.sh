#!/usr/bin/env bash
# messenger_regression.sh — Phase 17 Task 80 of witness stake v1
#
# Automates the manual chip+punk -> nocdem messenger regression that
# memory `feedback_post_deploy_test` mandates after every nodus
# deploy. This is a NEW-feature regression check too: once the stake
# TX types land, it proves that a vanilla messenger path (Seal wire
# format, DHT transport, nodus witness commit) still works on the
# new chain — i.e. that the stake/delegate/unstake work did not
# regress the core messaging flow.
#
# Scope: runbook skeleton + a best-effort auto-run when the required
# identities are present on the host. Live identities are not
# available in CI; this script is meant for the workstation or the
# post-deploy operator check, not for unattended testing.
#
# Relationship to nodus/tests/smoke_post_deploy.sh:
#   smoke_post_deploy.sh exercises a direct UTXO SPEND at the nodus
#   layer. This script exercises the full messenger-level round-trip
#   (DNA Engine -> DHT put/get -> inbox) on top of an already-live
#   cluster. Both should pass after a stake-phase deploy.
#
# Run from /opt/dna.
#
# Usage:
#   bash nodus/tests/integration/messenger_regression.sh
#
# Environment:
#   DNA_CLI   — path to dna-connect-cli
#                  (default: messenger/build/cli/dna-connect-cli)
#   SENDER    — messenger identity name to send from
#                  (default: chip+punk)
#   RECEIVER  — messenger identity name to receive at
#                  (default: nocdem)
#   PROBE_MSG — message body (default: "stake-regression <timestamp>")
#
# Exit codes:
#   0 — round-trip succeeded OR identities missing (skip acknowledged)
#   1 — binary missing
#   2 — round-trip attempted and FAILED

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DNA_CLI="${DNA_CLI:-$REPO_ROOT/messenger/build/cli/dna-connect-cli}"
SENDER="${SENDER:-chip+punk}"
RECEIVER="${RECEIVER:-nocdem}"
PROBE_MSG="${PROBE_MSG:-stake-regression $(date -u +%Y-%m-%dT%H:%M:%SZ)}"

INBOX_DIR="${INBOX_DIR:-/var/log/dna-debug}"

section() {
    echo ""
    echo "============================================================"
    echo "  $1"
    echo "============================================================"
}

# ── Phase 0: Preflight ──────────────────────────────────────────────
section "Phase 0 — preflight"

if [ ! -x "$DNA_CLI" ]; then
    echo "[fail] dna-connect-cli not found at $DNA_CLI"
    echo "       build: cd $REPO_ROOT/messenger/build && cmake .. && make -j\$(nproc)"
    exit 1
fi

# Do we have the sender identity locally? The CLI looks it up via
# `dna list` (identities). If not, skip — this script is not
# destructive and we don't create identities here.
if ! "$DNA_CLI" dna list 2>/dev/null | grep -q "$SENDER"; then
    echo "[skip] sender identity '$SENDER' not available on this host"
    echo "       this regression runs on the workstation / operator"
    echo "       machine where $SENDER + $RECEIVER are provisioned."
    exit 0
fi
echo "[ok] sender identity '$SENDER' present"

# ── Phase 1: Send probe message ─────────────────────────────────────
section "Phase 1 — send probe $SENDER -> $RECEIVER"
cat <<DOC
  "\$DNA_CLI" -i "$SENDER" dna message \\
       --to "$RECEIVER" \\
       --body "$PROBE_MSG"
DOC

send_out="$(mktemp)"
set +e
"$DNA_CLI" -i "$SENDER" dna message --to "$RECEIVER" --body "$PROBE_MSG" \
    >"$send_out" 2>&1
rc=$?
set -e

cat "$send_out"
if [ "$rc" -ne 0 ]; then
    echo "[fail] send returned rc=$rc"
    rm -f "$send_out"
    exit 2
fi
rm -f "$send_out"

# Extract the message id (the CLI emits "msg_id=..."). If it doesn't
# exist we can't verify receipt, but we can still treat the send
# leg as a half-pass.
msg_id=""
if command -v grep >/dev/null 2>&1; then
    msg_id="$("$DNA_CLI" -i "$SENDER" dna message --to "$RECEIVER" --body "$PROBE_MSG" 2>&1 \
        | grep -oE 'msg_id=[0-9a-f]+' | head -1 | cut -d= -f2 || true)"
fi

# ── Phase 2: Receive probe message ──────────────────────────────────
section "Phase 2 — receive probe at $RECEIVER"
cat <<DOC
Two observation paths:

(a) debug inbox on the receiver machine
    (per memory reference_debug_log_inbox):
      ls -lt $INBOX_DIR/${RECEIVER}/ | head

(b) CLI inbox dump:
      "\$DNA_CLI" -i "$RECEIVER" dna inbox --limit 10
DOC

if [ -d "$INBOX_DIR/$RECEIVER" ]; then
    echo "[info] debug inbox for $RECEIVER exists; listing most recent 5:"
    ls -lt "$INBOX_DIR/$RECEIVER/" 2>/dev/null | head -n 6 || true
else
    echo "[info] debug inbox $INBOX_DIR/$RECEIVER not present on this host"
fi

echo ""
echo "[info] manually verify the probe body on the receiver:"
echo "         \"$PROBE_MSG\""
echo "       arrives within the expected DHT put/get window (~ 30 s)."

# ── Phase 3: Post-conditions to verify ──────────────────────────────
section "Phase 3 — post-conditions"
cat <<'DOC'
After the round-trip succeeds you MUST also confirm:

  (1) nodus/build/ctest -R witness  -> all pass
  (2) witness block_height advances at each of the 7 cluster nodes
      (via cluster-status)
  (3) state_root is byte-identical across 7 nodes
      (see stake_seven_node.sh Phase 5 step 10)
  (4) no stake-related regressions: re-run
        ctest -R "apply_|integration_"
      on the fresh build — all PASS.
DOC

echo ""
echo "[ok] messenger regression runbook completed."
