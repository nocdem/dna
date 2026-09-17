#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_v2_join.sh — a node loses its chain and rejoins by its pin
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   That a node whose data directory has been wiped can rejoin a live
#   Ledger V2 fleet using ONLY an operator-supplied genesis BlockID, and
#   converge to the same state_root as the six that never stopped. The
#   property that would be false if it failed: *a V2 fleet has a recovery
#   path for a node that lost everything, and that path needs no
#   database copied between machines.*
#
#   This is the V2 answer to a question the legacy lane answers
#   differently, and the difference is the reason this scenario had to be
#   written instead of pointing test_bootstrap_partial_wipe.sh at a V2
#   cluster. A legacy node with no chain asks its peers for the genesis
#   and adopts whatever a quorum agrees on. A V2 node does not: it adopts
#   a peer's genesis bundle ONLY if the bundle re-derives to the pin it
#   was given locally. The pin is a local trust anchor, so recovery is
#   deliberately impossible without it — and that is a property worth
#   pinning down, not a gap.
#
# WHAT IT REQUIRES
#   Compile flags: NONE. A default nodus/build binary.
#   Environment: none of its own.
#   ⚠ A cluster from **stagef_up_v2.sh**, which writes $BASE_DIR/v2_genesis_pin.
#   The pin is READ from that file rather than re-derived: re-deriving it
#   here would be a second opinion about the chain's identity, and a
#   scenario is supposed to check the fleet's, not form its own.
#
# R3 W3 (C2d) — THE PIN IS 32 BYTES, NOT 64 (D-24 rev 4 item 1,
#   atlas-dec-8a88ea40d4ac8cd6d8c361dca9b7b2c7, APPROVED)
#   "the pin is 32 BYTES everywhere: --v2-genesis-pin takes 64 hex
#   characters = the chain id." nodus-server.c's parse_v2_pin refuses
#   anything but exactly 64 hex characters (:93-104); this scenario's own
#   length check is rewritten to match. And a version-3 chain never
#   writes a global_height=0 row to v2_blocks (genesis is a stored
#   DOCUMENT, not a block — nodus_v2_gen_config.c's required-key
#   message: "0 and 1 both start the chain at height 1 but are DIFFERENT
#   chain ids"), so "adopted" is read from the witness DB's FILENAME
#   instead — it embeds the derived chain id's first 16 bytes in the
#   SAME hex `join_adopt` itself writes (nodus_witness_v2_join.c
#   `witness_%s.db` over `chain32[0..15]`), so comparing filenames IS
#   comparing the derived identity, without a second read of the row
#   that no longer exists.
#
# WHAT IT LEAVES BEHIND
#   Node 6 has a brand-new data directory: its identity is preserved (the
#   validator set is genesis-fixed and a new key would not be in it), but
#   its databases are gone and rebuilt by adoption. It runs under a NEW
#   pid appended to pids.txt. Its nodus.log is TRUNCATED, not appended —
#   the scenario needs to distinguish this boot's lines from the original
#   one's, and a delta over a wiped-and-readopted node is not meaningful.
#
# HOW IT CAN LIE
#   - **"It came back up" is not "it rejoined".** A node that failed to
#     adopt would still listen and still serve DHT traffic, because nodus
#     keeps the DHT role when the witness module has no chain. So the
#     assertions are: a V2 chain database EXISTS again, its genesis block
#     id equals the fleet's, and the state_root matches. Not the port.
#   - **A stale database would pass a weaker check.** The wipe is
#     verified before the restart — if the old witness_*.db were still
#     there, "it has a chain" would be true without anything having been
#     adopted. That check is what makes the rest mean something.
#   - **The identity is deliberately NOT regenerated.** A fresh key would
#     not be in the genesis validator set, so the node would come back as
#     a non-validator and the scenario would be measuring something else
#     entirely while still going green.
#   - **A pin mismatch cannot produce a false pass**, only a hang: the
#     joiner refuses every bundle that does not re-derive to its pin, so
#     a wrong pin leaves the node chainless until the timeout fails it.
#   - **DELTA 1 (verifier CLAIM 20 note) — the adoption wait (120 x 1 s)
#     and the role+LIVE wait (30 x 1 s) are ATTEMPT-bounded, not a single
#     fixed timer deciding the verdict.** Each polls for a LOG LINE or a
#     DB row to appear and dies if it never does within the bound — the
#     same shape bring-up's own anti-vacuity loop uses, not the
#     `test_v2_partial_wipe.sh` `sleep 8` shape (fixed in that script,
#     DELTA 1 item 5) where one fixed sleep decided the whole outcome.
#   - **rc=99 means the cluster was not V2.** Coverage that did not
#     happen.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

VICTIM=6
REF=1
PINFILE="$BASE_DIR/v2_genesis_pin"

die() { echo "[FAIL] $*" >&2; exit 1; }

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ] || [ ! -s "$PINFILE" ]; then
    echo "[SKIP] not a Ledger V2 cluster with a recorded genesis pin — use stagef_up_v2.sh"
    exit 99
fi

PIN=$(cat "$PINFILE")
[ "${#PIN}" = 64 ] || die "recorded pin is not 64 hex chars (32-byte chain id, D-24 rev 4)"

fleet_gid=$(basename "$ref_db")
fleet_tip=$(sqlite3 "$ref_db" "SELECT MAX(global_height) FROM v2_blocks;")
echo "[ok] fleet chain_db=$fleet_gid tip=$fleet_tip"

stagef_cmt_diff_at_floor "pre-v2-join" || exit 2

# ── Wipe ────────────────────────────────────────────────────────────
nd=$(stagef_node_dir "$VICTIM")
vpid=$(pgrep -f "node$VICTIM/data" | head -1 || true)
[ -n "$vpid" ] || die "node$VICTIM is not running"
kill -9 "$vpid"
sleep 3

# Everything except the identity. A fresh key would not be in the
# genesis validator set and the node would rejoin as a non-validator —
# green, and measuring something else.
rm -f "$nd/data/"*.db "$nd/data/"*.db-wal "$nd/data/"*.db-shm \
      "$nd/data/.witness_db_seen" "$nd/data/.bootstrap_in_progress" \
      "$nd/data/.recovery_in_progress"
rm -rf "$nd/data/archive"
: > "$nd/nodus.log"

# Verified, not assumed: without this, "it has a chain" afterwards could
# just be the old file nobody removed.
ls "$nd/data/"witness_*.db >/dev/null 2>&1 && die "wipe did not remove the chain DB"
echo "[ok] node$VICTIM wiped (identity kept, databases gone)"

# ── Rejoin, with nothing but the pin ────────────────────────────────
SEEDS=""
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    SEEDS="$SEEDS -s 127.0.0.1:$(stagef_udp_port "$n")"
done
# shellcheck disable=SC2086
"$STAGEF_NODUS_BIN" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
    -u "$(stagef_udp_port "$VICTIM")" -t "$(stagef_tcp_port "$VICTIM")" \
    -p "$(stagef_peer_port "$VICTIM")" -C "$(stagef_chan_port "$VICTIM")" \
    -W "$(stagef_witness_port "$VICTIM")" \
    --v2-genesis-pin "$PIN" \
    -i "$nd/identity" -d "$nd/data" $SEEDS \
    >> "$nd/nodus.log" 2>&1 &
newpid=$!
echo "$newpid" >> "$BASE_DIR/pids.txt"
echo "[ok] node$VICTIM restarted with ONLY the genesis pin (pid $newpid)"

# ── It must ADOPT, not merely start ─────────────────────────────────
adopted=0
for _ in $(seq 1 120); do
    if ls "$nd/data/"witness_*.db >/dev/null 2>&1; then
        gid=$(basename "$(stagef_node_chain_db "$VICTIM")" 2>/dev/null || true)
        [ -n "$gid" ] && { adopted=1; break; }
    fi
    sleep 1
done
[ "$adopted" = 1 ] || {
    echo "--- node$VICTIM log tail ---" >&2
    tail -30 "$nd/nodus.log" >&2
    die "node$VICTIM never adopted a chain — it is up and serving DHT with no witness role, which is exactly what 'it started' would have hidden"
}
[ "$gid" = "$fleet_gid" ] || die \
  "node$VICTIM adopted a DIFFERENT chain: $gid vs the fleet's $fleet_gid"
echo "[ok] node$VICTIM adopted the fleet's chain ($gid)"

# ANTI-VACUITY: the role line AND lane-live, not just an open handle —
# a chain DB existing again is not the same as this node actually
# resuming consensus on it (nodus_witness.c's own bring-up gate applies
# with no less force to a joiner than to a fresh derivation).
role_ok=0 live_ok=0
for _ in $(seq 1 30); do
    if grep -q 'chain role: COMETBFT' "$nd/nodus.log"; then role_ok=1; fi
    if grep -q 'cometbft lane LIVE' "$nd/nodus.log"; then live_ok=1; fi
    if [ "$role_ok" = 1 ] && [ "$live_ok" = 1 ]; then break; fi
    sleep 1
done
[ "$role_ok" = 1 ] && [ "$live_ok" = 1 ] || die \
  "node$VICTIM has the chain but never reported COMETBFT role + lane LIVE (role=$role_ok live=$live_ok)"
echo "[ok] node$VICTIM reports the COMETBFT role and is LIVE"

# ── And catches up through the reactor's stored-part gossip ─────────
# R3 W3 (C2d) — there is no separate blocksync reactor on this lane:
# wait_sync is ALWAYS false (D-23 rev 7 item 18,
# nodus_witness.c:1564-1572), so a node behind its peers catches up
# through the CONSENSUS reactor's own stored-part gossip
# (reactor.go:575-590, ported) — the same channel that carries live
# votes and proposals, not a bulk block-fetch protocol. Bounded by
# progress (stall detection), never a bare sleep.
vt=$(stagef_cmt_wait_height "$(stagef_node_chain_db "$VICTIM")" "$fleet_tip" 3) \
    || die "node$VICTIM adopted but did not catch up (stuck at $vt, fleet was $fleet_tip)"
echo "[ok] node$VICTIM caught up to tip $vt"

for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    stagef_cmt_wait_height "$(stagef_node_chain_db "$n")" "$vt" 2 >/dev/null \
        || die "node$n never reached height $vt (mesh replication stalled)"
done
stagef_cmt_diff_at_floor "post-v2-join" || exit 2

echo ""
echo "[PASS] a wiped node rejoined a live Ledger V2 fleet with nothing but its"
echo "       identity and the genesis pin, adopted the fleet's chain, took its"
echo "       witness role, caught up to tip $vt, and all $STAGEF_COMMITTEE_SIZE nodes agree."
