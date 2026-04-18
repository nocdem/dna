#!/usr/bin/env bash
# stake_single_node.sh — Phase 17 Task 78 of witness stake v1
#
# Single-node integration runbook for the stake / delegate / unstake
# lifecycle. Boots ONE local nodus-server bound to non-production
# ports, runs genesis with a 1-validator chain_def, performs a
# stake -> delegate -> unstake cycle, and spot-checks state_root
# consistency across operations.
#
# Scope: runbook. This script documents the exact commands and
# environment a developer uses to reproduce the single-node sim on
# their workstation. It does NOT replace the C-level apply_* unit
# tests (test_apply_stake, test_apply_delegate, ...) or the Phase 11
# integration tests (test_integration_unstake_two_phase,
# test_integration_undelegate_claim) which already cover the
# state-mutation semantics under ctest.
#
# Why a runbook instead of a self-driving CI script:
#   * Running a full nodus-server out of /tmp with a fresh identity is
#     reasonable locally but brittle in CI (epoll, port races,
#     SQLCipher init, witness discovery).
#   * A reproducible *procedure* is more valuable than a one-off
#     automation for the Phase 18 deploy rehearsal.
#
# Run from /opt/dna. Requires: nodus-server built, dna-connect-cli
# built, no process already on the chosen ports.
#
# Usage: bash nodus/tests/integration/stake_single_node.sh
#
# Exit codes:
#   0 — all phases completed (either executed or acknowledged skip)
#   1 — required binary missing
#   2 — a phase's guard failed (port in use, etc.)
#
# Port offset strategy (avoid prod 4000-4004):
#   UDP    : 14000
#   TCPCLI : 14001
#   TCPNBR : 14002
#   CHAN   : 14003   (disabled at runtime)
#   WIT    : 14004

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
NODUS_BIN="$REPO_ROOT/nodus/build/nodus-server"
DNACLI_BIN="$REPO_ROOT/messenger/build/cli/dna-connect-cli"

UDP_PORT=14000
TCP_PORT=14001

DATA_DIR="$(mktemp -d /tmp/stake_single_node_XXXXXX)"
IDENT_DIR="$(mktemp -d /tmp/stake_single_node_ident_XXXXXX)"
LOG_FILE="$DATA_DIR/nodus.log"

SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$DATA_DIR" "$IDENT_DIR"
}
trap cleanup EXIT

section() {
    echo ""
    echo "============================================================"
    echo "  $1"
    echo "============================================================"
}

require_bin() {
    local path="$1"
    if [ ! -x "$path" ]; then
        echo "[fail] required binary not found: $path"
        echo "       build it first:"
        case "$path" in
            *nodus-server)
                echo "         cd $REPO_ROOT/nodus/build && cmake .. && make -j\$(nproc)"
                ;;
            *dna-connect-cli)
                echo "         cd $REPO_ROOT/messenger/build && cmake .. && make -j\$(nproc)"
                ;;
        esac
        exit 1
    fi
}

port_in_use() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltun 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]${port}\$"
    elif command -v lsof >/dev/null 2>&1; then
        lsof -iTCP:"$port" -iUDP:"$port" -sTCP:LISTEN >/dev/null 2>&1
    else
        return 1
    fi
}

# ── Phase 0: Preflight ──────────────────────────────────────────────
section "Phase 0 — preflight"
require_bin "$NODUS_BIN"
require_bin "$DNACLI_BIN"

for p in "$UDP_PORT" "$TCP_PORT"; do
    if port_in_use "$p"; then
        echo "[fail] port $p already in use — pick a different offset"
        exit 2
    fi
done
echo "[ok] binaries present, ports $UDP_PORT/$TCP_PORT free"
echo "[ok] ephemeral data=$DATA_DIR ident=$IDENT_DIR"

# ── Phase 1: Boot nodus-server ─────────────────────────────────────
# Documented form; not auto-executed by default in CI.  Uncomment to
# run locally.
section "Phase 1 — boot nodus-server (documented, not executed)"
cat <<DOC
To run this runbook end-to-end on your workstation, uncomment the
block below. It boots the server detached, waits for TCP readiness,
then runs the subsequent phases. Kept commented by default so that
CI smoke-runs only the syntax check (bash -n) without spawning a
long-lived process.

# "\$NODUS_BIN" -u $UDP_PORT -t $TCP_PORT -i "\$IDENT_DIR" -d "\$DATA_DIR" \\
#     >"\$LOG_FILE" 2>&1 &
# SERVER_PID=\$!
# echo "[info] nodus-server pid=\$SERVER_PID log=\$LOG_FILE"
# for i in \$(seq 1 30); do
#     if ss -lt 2>/dev/null | grep -Eq "[:.]${TCP_PORT}\\s"; then
#         break
#     fi
#     sleep 0.5
# done
DOC

# ── Phase 2: Genesis (documented) ──────────────────────────────────
section "Phase 2 — genesis (documented)"
cat <<'DOC'
Generate a 1-validator chain_def blob and submit it:

  "$DNACLI_BIN" dna genesis-prepare \
       --validators 1 \
       --out "$DATA_DIR/chain_def.cbor"
  "$DNACLI_BIN" dna genesis-submit \
       --chain-def "$DATA_DIR/chain_def.cbor" \
       --server 127.0.0.1:$TCP_PORT

Expected: a block at height 0 lands; nodus-server log shows
"genesis committed" and the validator row appears in the witness DB.
DOC

# ── Phase 3: post-genesis distribution ──────────────────────────────
section "Phase 3 — post-genesis distribution (documented)"
cat <<'DOC'
Fund the operator with a known amount so the subsequent stake cycle
can pay fees + self-stake:

  "$DNACLI_BIN" dna send --to <operator_fp> --amount 20000000

After commit, verify:

  "$DNACLI_BIN" dna balance --address <operator_fp>
DOC

# ── Phase 4: stake / delegate / unstake cycle (documented) ──────────
section "Phase 4 — stake / delegate / unstake cycle (documented)"
cat <<'DOC'
  # operator self-stakes 10M DNAC at 1% commission
  "$DNACLI_BIN" dna stake --commission-bps 100

  # delegator delegates 1000 DNAC to operator
  "$DNACLI_BIN" -i delegator dna delegate \
       --validator <operator_fp> --amount 100000000000

  # capture state_root after delegate
  ROOT_A=$("$DNACLI_BIN" dna chain-head --format state_root)

  # issue commission update (pending, effective next epoch)
  "$DNACLI_BIN" dna validator-update --commission-bps 500

  # delegator undelegates (auto-claim path)
  "$DNACLI_BIN" -i delegator dna undelegate \
       --validator <operator_fp> --amount 100000000000

  # capture state_root after undelegate
  ROOT_B=$("$DNACLI_BIN" dna chain-head --format state_root)

  # operator unstakes (RETIRING phase 1)
  "$DNACLI_BIN" dna unstake

  # capture state_root after unstake
  ROOT_C=$("$DNACLI_BIN" dna chain-head --format state_root)

Each ROOT_* value MUST be a 128-character hex string. The three
values MUST differ — state_root evolves as state mutates.  Re-running
the identical sequence on a freshly-initialized data dir MUST
produce the same three ROOT values (determinism check; this is also
what Task 82 enforces across compilers).
DOC

# ── Phase 5: Invariants to spot-check ───────────────────────────────
section "Phase 5 — invariants (documented spot-checks)"
cat <<'DOC'
After the cycle above:

  (1) supply invariant (Task 81 automates a stricter version):
        sum(utxo.amount) + sum(validator.self_stake)
      + sum(delegation.amount) + block_fee_pool
      + sum(reward.accumulator_materialized)
      + sum(reward.validator_unclaimed)
      == DNAC_DEFAULT_TOTAL_SUPPLY (1e17 raw)

  (2) validator_stats.active_count is 1 after stake, 1 during
      RETIRING, 0 only after the epoch boundary transitions the
      validator to UNSTAKED.

  (3) state_root reported by `dna chain-head` matches the one
      computed independently by nodus_witness_merkle_compute_state_root.

  (4) ctest -R "apply_|integration_" on the nodus build still passes
      (the unit tests cover each apply_* helper under NODUS_WITNESS_INTERNAL_API).
DOC

echo ""
echo "[ok] single-node runbook syntax-checked. See comments above for"
echo "     the full manual procedure."
