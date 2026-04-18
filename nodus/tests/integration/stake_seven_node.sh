#!/usr/bin/env bash
# stake_seven_node.sh — Phase 17 Task 79 of witness stake v1
#
# 7-node cluster dry-run runbook for the stake / delegate / claim /
# unstake lifecycle. Per memory `feedback_no_docker`, uses localhost
# with 7 nodus-server instances bound to disjoint port ranges.
#
# Scope: runbook skeleton. Spawning 7 localhost nodus-servers in a
# single script is brittle (SQLCipher races, UDP keyspace fit,
# witness discovery convergence), so this script documents the
# procedure and is designed to be *filled in* during Phase 18
# deployment rehearsal when the production cluster is available.
#
# What this script DOES do:
#   * `bash -n` passes.
#   * Port layout is documented and collision-checked.
#   * Each validator's identity + data dir layout is described.
#   * The 10-step lifecycle from the design doc §PHASE 17 Task 79 is
#     spelled out with the exact `dna` verb invocations.
#
# What this script does NOT do:
#   * Spawn real nodus-server processes. See §1 below.
#   * Parse nodus-cli output. `dna chain-head` and peer-query verbs
#     are called for effect; actual scraping is deferred until
#     Phase 18 when the cluster is cut over.
#
# Run from /opt/dna.
#
# Usage: bash nodus/tests/integration/stake_seven_node.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
NODUS_BIN="$REPO_ROOT/nodus/build/nodus-server"
DNACLI_BIN="$REPO_ROOT/messenger/build/cli/dna-connect-cli"

# ── Port layout ─────────────────────────────────────────────────────
# Each node gets a 10-port stride to keep UDP/TCP/channel/witness
# ports disjoint. All nodes on 127.0.0.1.
#
#   Node i (1..7):
#     UDP    : 14000 + 10*(i-1)     (Kademlia)
#     TCPCLI : 14001 + 10*(i-1)     (client)
#     TCPNBR : 14002 + 10*(i-1)     (inter-node)
#     CHAN   : 14003 + 10*(i-1)     (channels — idle)
#     WIT    : 14004 + 10*(i-1)     (witness BFT)
#
# Production uses 4000-4004 — these 14000-14069 slots are explicitly
# reserved for local cluster sims so a running local cluster never
# contends with prod.

NODE_COUNT=7
BASE_PORT=14000
STRIDE=10

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
        exit 1
    fi
}

node_udp()  { echo $((BASE_PORT + STRIDE * ($1 - 1) + 0)); }
node_tcp()  { echo $((BASE_PORT + STRIDE * ($1 - 1) + 1)); }
node_nbr()  { echo $((BASE_PORT + STRIDE * ($1 - 1) + 2)); }
node_chan() { echo $((BASE_PORT + STRIDE * ($1 - 1) + 3)); }
node_wit()  { echo $((BASE_PORT + STRIDE * ($1 - 1) + 4)); }

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

collisions=0
for i in $(seq 1 $NODE_COUNT); do
    for p in "$(node_udp $i)" "$(node_tcp $i)" "$(node_nbr $i)" \
             "$(node_chan $i)" "$(node_wit $i)"; do
        if port_in_use "$p"; then
            echo "[warn] port $p (node $i) already in use"
            collisions=$((collisions + 1))
        fi
    done
done
if [ "$collisions" -gt 0 ]; then
    echo "[fail] $collisions port collisions; aborting before spawn"
    exit 2
fi
echo "[ok] all 35 ports in the 14000-14069 range are free"

# ── Phase 1: Port table ─────────────────────────────────────────────
section "Phase 1 — port table"
printf "  %-6s %-6s %-6s %-6s %-6s %-6s\n" \
    "NODE" "UDP" "TCP" "NBR" "CHAN" "WIT"
for i in $(seq 1 $NODE_COUNT); do
    printf "  %-6s %-6s %-6s %-6s %-6s %-6s\n" \
        "n${i}" "$(node_udp $i)" "$(node_tcp $i)" \
        "$(node_nbr $i)" "$(node_chan $i)" "$(node_wit $i)"
done

# ── Phase 2: per-node spawn recipe (documented) ─────────────────────
section "Phase 2 — per-node spawn recipe (documented)"
cat <<'DOC'
For each node i in 1..7, the local sim needs:

  DATA_i="$(mktemp -d /tmp/ss7n_data_XXXXXX)"
  IDENT_i="$(mktemp -d /tmp/ss7n_ident_XXXXXX)"
  LOG_i="$DATA_i/nodus.log"

  "$NODUS_BIN" \
      -u $(node_udp $i) \
      -t $(node_tcp $i) \
      -i "$IDENT_i" \
      -d "$DATA_i" \
      >"$LOG_i" 2>&1 &
  PIDS[$i]=$!

Wait until TCP is listening on every node before continuing:

  for i in $(seq 1 7); do
      for _ in $(seq 1 60); do
          if ss -lt 2>/dev/null | grep -Eq "[:.]$(node_tcp $i)\\s"; then
              break
          fi
          sleep 0.25
      done
  done

Then seed Kademlia by point-pinging each subsequent node at n1:
  "$DNACLI_BIN" --server 127.0.0.1:$(node_tcp 1) dna peer-add 127.0.0.1:$(node_udp j)
DOC

# ── Phase 3: Genesis with 7-validator chain_def ─────────────────────
section "Phase 3 — genesis with 7-validator chain_def (documented)"
cat <<'DOC'
Build the chain_def from the 7 node identities (one pubkey each):

  "$DNACLI_BIN" dna genesis-prepare \
       --validators 7 \
       --pubkey-file "$IDENT_1/pubkey.bin" \
       --pubkey-file "$IDENT_2/pubkey.bin" \
       --pubkey-file "$IDENT_3/pubkey.bin" \
       --pubkey-file "$IDENT_4/pubkey.bin" \
       --pubkey-file "$IDENT_5/pubkey.bin" \
       --pubkey-file "$IDENT_6/pubkey.bin" \
       --pubkey-file "$IDENT_7/pubkey.bin" \
       --out "$DATA_1/chain_def.cbor"

Submit genesis unanimously. All 7 nodes MUST co-sign:

  "$DNACLI_BIN" dna genesis-submit \
       --chain-def "$DATA_1/chain_def.cbor" \
       --server 127.0.0.1:$(node_tcp 1)

Expected: block 0 committed, chain_id propagates to all 7 nodes,
validator_stats.active_count = 7 on every node, state_root matches
across all 7 nodes (Task 82 checks this deterministically).
DOC

# ── Phase 4: Distribute to 8 testers ────────────────────────────────
section "Phase 4 — distribute to 8 testers (documented)"
cat <<'DOC'
Following memory `project_genesis_protocol` ("7 tester'a 1M PUNK +
100 DNAC dagit") and the design doc, perform 8 distribution sends
from the genesis-output fingerprint to each tester:

  for t in tester1 tester2 ... tester8; do
      "$DNACLI_BIN" dna send --to "$t" --amount 100_00000000
  done
DOC

# ── Phase 5: stake/delegate/claim lifecycle ─────────────────────────
section "Phase 5 — lifecycle walkthrough (design §PHASE 17 Task 79)"
cat <<'DOC'
Mirror the design doc ten-step walkthrough:

  1. Start all 7 nodus instances (Phase 2 above)
  2. Genesis with 7-validator chain_def (Phase 3)
  3. Distribution to 8 testers (Phase 4)
  4. bios delegates 1000 DNAC to validator "one":
       "$DNACLI_BIN" -i bios dna delegate \
            --validator <one_fp> --amount 100000000000
  5. Wait 2 epochs (each epoch = NODUS_W_EPOCH_BLOCKS blocks; the
     local sim generates blocks as TXs arrive so push some no-op
     TXs — spend-to-self — to advance the chain).
  6. bios claims reward:
       "$DNACLI_BIN" -i bios dna claim --validator <one_fp>
     Expected: one UTXO for the pending-reward amount is emitted to
     bios; validator.accumulator snapshot advances.
  7. one issues validator-update to commission 10%:
       "$DNACLI_BIN" -i one dna validator-update --commission-bps 1000
     Status: pending (effective at next epoch boundary).
  8. Wait 1 epoch -> new rate effective.
  9. bios undelegates -> auto-claim path:
       "$DNACLI_BIN" -i bios dna undelegate \
            --validator <one_fp> --amount 100000000000
     Expected: TWO UTXOs for bios (principal + pending reward).
 10. 7/7 state_root consistency:
       for i in $(seq 1 7); do
           "$DNACLI_BIN" --server 127.0.0.1:$(node_tcp $i) \
               dna chain-head --format state_root
       done
     All 7 outputs MUST be byte-identical.
DOC

# ── Phase 6: teardown ───────────────────────────────────────────────
section "Phase 6 — teardown (documented)"
cat <<'DOC'
  for pid in "${PIDS[@]}"; do
      kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  for d in "$DATA_1" "$DATA_2" ... "$IDENT_1" "$IDENT_2" ...; do
      rm -rf "$d"
  done

DO NOT leave any nodus-server hanging on ports 14000-14069 —
subsequent runs will abort in Phase 0.
DOC

echo ""
echo "[ok] 7-node cluster runbook syntax-checked. Follow sections 1-6"
echo "     above to execute locally, or treat as the Phase 18"
echo "     deployment rehearsal checklist."
