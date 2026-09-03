#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_v2_epoch_boundary.sh — a V2 chain crosses an epoch boundary
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That a Ledger V2 fleet driven ACROSS an epoch boundary freezes the
#   next epoch's validator-set snapshot identically on every node, and
#   still agrees on state_root afterwards. The property that would be
#   false if it failed: *the V2 epoch machinery is deterministic across
#   nodes* — the boundary is where a chain writes state nobody asked it
#   to write, from a rule rather than from a transaction, and it is the
#   classic place for two nodes to disagree.
#
# WHAT IT REQUIRES
#   ⚠ **A SHORT-EPOCH BINARY. Both halves, or it skips.**
#     compile: -DDNAC_EPOCH_LENGTH=<E> with E small (15 is the harness
#              convention)
#     env:     STAGEF_EPOCH_LENGTH=<E> matching it, exported BEFORE
#              stagef_up_v2.sh — the bring-up writes E into the genesis
#              config, and the builder REFUSES a config that disagrees
#              with the binary.
#   At the shipped 720 this scenario skips: reaching height 720 needs 720
#   transactions, and see the note on where transactions come from.
#   A cluster from stagef_up_v2.sh, with pump leaves unclaimed.
#
# WHERE THE BLOCKS COME FROM, because it is not obvious
#   A V2 chain produces a block only when a transaction arrives, and on a
#   fresh one the only thing an identity can submit is a genesis claim.
#   So block production is bounded by unclaimed leaves. stagef_up_v2.sh
#   mints a batch of small "pump" leaves owned by one identity for
#   exactly this; a single v2-claim call over them submits one claim per
#   leaf, and each lands in its own block (measured: 40 leaves -> 40
#   blocks, height 0 -> 40).
#
# WHAT IT LEAVES BEHIND
#   The pump leaves are SPENT and the chain is tens of blocks further on,
#   past at least one epoch boundary. Nothing is killed or restarted. Any
#   scenario that needs pump leaves must run BEFORE this one — which is
#   why this is the only V2 scenario with an order constraint, and it is
#   stated rather than discovered.
#
# HOW IT CAN LIE
#   - **Advancing is not crossing.** A height delta proves the chain
#     moved; it says nothing about a boundary. The assertion is that the
#     height crossed a multiple of E, computed from the before/after
#     heights, and that a snapshot row for the NEW epoch appeared.
#   - **A snapshot that was already there proves nothing.** The bring-up
#     seeds epochs 0 and E at genesis, so the row for the FIRST boundary
#     exists before this scenario runs. The assertion is on a row that
#     was ABSENT before and PRESENT after, and the before-set is captured
#     first.
#   - **Identical-across-nodes is the point, not existence.** One node
#     writing a snapshot proves nothing about agreement; the row's hash
#     is compared across all seven.
#   - **rc=99 means the epoch length made this unreachable**, i.e. the
#     coverage did not happen. Never a pass.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

REF=1
CONF="$BASE_DIR/v2_genesis.conf"
PUMP="$BASE_DIR/v2pump/identity"
CLI="${STAGEF_NODUSCLI_BIN:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"
E_LEN="${STAGEF_EPOCH_LENGTH:-720}"

die() { echo "[FAIL] $*" >&2; exit 1; }
tip() { sqlite3 "$(stagef_node_chain_db "$REF")" \
        "SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks;"; }
snapshots() { sqlite3 "$(stagef_node_chain_db "$1")" \
        "SELECT group_concat(epoch_start,',') FROM \
         (SELECT epoch_start FROM validator_set_snapshots ORDER BY epoch_start);"; }

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ] || [ ! -f "$CONF" ] || [ ! -s "$PUMP/nodus.pk" ]; then
    echo "[SKIP] not a Ledger V2 cluster with a pump identity — use stagef_up_v2.sh"
    exit 99
fi

# A boundary must be reachable with the leaves on hand. At the shipped
# 720 it is not, and saying so is the honest outcome.
head0=$(tip)
next_boundary=$(( (head0 / E_LEN + 1) * E_LEN ))
need=$(( next_boundary - head0 ))
avail=$(grep -c '^\[allocation\]' "$CONF" || true)
if [ "$need" -gt "$avail" ]; then
    echo "[SKIP] the next boundary is $need blocks away (epoch length $E_LEN) and"
    echo "       only $avail leaves exist — a V2 chain makes one block per"
    echo "       transaction, so this needs a SHORT-EPOCH build:"
    echo "         -DDNAC_EPOCH_LENGTH=15 + STAGEF_EPOCH_LENGTH=15"
    exit 99
fi
echo "[ok] epoch length $E_LEN, head $head0, next boundary at $next_boundary ($need blocks)"

before_set=$(snapshots "$REF")
echo "[ok] snapshots before: $before_set"

bash "$(dirname "$0")/../stagef_diff.sh" "pre-v2-epoch" || exit 2

# ── Drive the chain across ──────────────────────────────────────────
log="$BASE_DIR/v2epoch_pump.log"
"$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$REF")" v2-claim --config "$CONF" \
    --db "$ref_db" --keys "$PUMP" \
    --submit "127.0.0.1:$(stagef_tcp_port "$REF")" > "$log" 2>&1 || true
submitted=$(grep -c '^committed:' "$log" || true)
[ "${submitted:-0}" -ge "$need" ] || die \
  "only $submitted claims committed, $need were needed to reach the boundary — read $log"
echo "[ok] $submitted claims committed"

crossed=0
for _ in $(seq 1 120); do
    [ "$(tip)" -ge "$next_boundary" ] && { crossed=1; break; }
    sleep 1
done
head1=$(tip)
[ "$crossed" = 1 ] || die "height reached $head1, short of the boundary at $next_boundary"
echo "[ok] the chain CROSSED the boundary: $head0 -> $head1 (boundary $next_boundary)"

# ── A snapshot for a NEW epoch must have appeared ────────────────────
sleep 8
after_set=$(snapshots "$REF")
[ "$after_set" != "$before_set" ] || die \
  "the snapshot set is unchanged ($after_set) — the chain crossed a boundary and froze nothing, which is the defect this scenario exists to catch"
echo "[ok] snapshots after: $after_set"

# ── And every node must have frozen the SAME one ────────────────────
first=""; rows=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    h=$(sqlite3 "$(stagef_node_chain_db "$n")" \
        "SELECT COUNT(*) || ':' || COALESCE(hex(snapshot_hash),'-') \
         FROM validator_set_snapshots WHERE epoch_start = $next_boundary;" 2>/dev/null || echo ERR)
    rows="$rows node$n=$h"
    if [ -z "$first" ]; then first="$h"
    elif [ "$h" != "$first" ]; then
        echo "[FAIL] the epoch-$next_boundary snapshot DIFFERS across nodes:$rows" >&2
        exit 1
    fi
done
case "$first" in 0:*|ERR) die "no epoch-$next_boundary snapshot row on any node";; esac
echo "[ok] the epoch-$next_boundary snapshot is byte-identical on all $STAGEF_COMMITTEE_SIZE nodes"

bash "$(dirname "$0")/../stagef_diff.sh" "post-v2-epoch" || exit 2

echo ""
echo "[PASS] a Ledger V2 chain crossed the epoch boundary at $next_boundary, froze the"
echo "       next validator-set snapshot byte-identically on all $STAGEF_COMMITTEE_SIZE nodes, and every"
echo "       node still agrees on state_root. Epoch length $E_LEN — NOT the shipped 720,"
echo "       so this proves the LOGIC of the boundary and nothing about its magnitude."
