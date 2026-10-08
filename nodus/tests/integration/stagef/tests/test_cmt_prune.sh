#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_prune.sh — block pruning at MIXED retention (not in the sweep)
# ════════════════════════════════════════════════════════════════════
#
# Decision: docs/plans/decisions/2026-10-03-block-pruning-7-paydays.md.
# Item 4: "No hard fork: no consensus byte, block, app_hash or state root
# changes — proven by the harness at mixed retention." This is that proof.
#
# WHAT IT PROVES
#   That two pruning validators (nodes 4 and 5, nodus.json
#   `retain_blocks` R) and five archive validators (1-3, 6, 7) run ONE
#   chain: every node agrees 7/7 on block id and global root while the
#   pruned nodes drop their old blocks, a pruned node survives kill -9 +
#   restart, and a WIPED archive node rejoins by its pin and block-syncs
#   the whole chain from height 1 while the pruned nodes cannot serve the
#   bottom of it. Also, read from each node's chain database (cometbft
#   block / state store, nodus_witness_cmt_store.c):
#   - the start floor: retain_blocks = the chain's evidence window
#     `max_age_num_blocks` M is REFUSED (nodus_witness_cmt_node.c
#     nodus_cmt_node_check_retain_blocks — N must be 0 or > M) before the
#     handshake — the node's witness does not run and its block store is
#     left as it was;
#   - a pruned node keeps exactly the last R blocks: with T its block
#     store's tip (the highest `P:` height), its base (lowest `P:`
#     height) is T−R+1, or T−R in the window between saving block T and
#     block T's prune (cmt_cs.c finalize-commit saves block T at :3047-
#     3063 before applying it at :3111; nodus_witness_cmt_host.c runs
#     pruneBlocks after store.Save, :1762-1773); every height in
#     [base, T] has its `P:` rows, `H:`, `BH:` (whose value is the height,
#     nodus_witness_cmt_store.c:1180-1182), and nothing below base does —
#     except block 1's meta `H:1`, which is NEVER pruned (decision item 5,
#     fix f8ecb5ac): `H:` is exactly [base, T] ∪ {1}, `H:1` checked
#     present and non-empty (the proto is not decoded), `BH:` of height 1
#     absent; `C:` covers [base, T−1] (block
#     h's save writes C:h−1, :1195), with `C:0` exempt (see HOW IT CAN
#     LIE); `abciResponsesKey:` starts at base, or base−1 between the
#     block-store prune and the state-store prune (two batches,
#     nodus_cmt_blockexec_prune_blocks host.c:1545 then :1551);
#   - an archive node keeps every height 1..T of each of those rows;
#   - SeenCommit: EVERY node (archive too) holds exactly ONE `SC:` row,
#     at its block-store tip T (save_block_to_batch deletes SC:(h−1−W) in
#     the batch that writes SC:h, W = double_sign_check_height = 0,
#     shared/dnac/cmt_config.h:146 — never overridden in this tree).
#   - a pruned node RESTARTED after height 1 is pruned (base > 1, its
#     parts / BH: / C: gone, H:1 kept) still activates Ledger V2 at that
#     start (no "Ledger V2 NOT ACTIVATED" line, nodus_witness.c:913-938)
#     and ADMITS a spend submitted to its own client port, which lands
#     (ledger effect).
#   The property that would be false if it failed: *retention is
#   node-local — a node may drop history without changing a byte any other
#   node computes, keeps serving clients across a restart, and the chain
#   stays joinable while archive nodes exist.*
#
# EXPECTED RESULT: PASS on f8ecb5ac and later (decision item 5 keeps
#   H:1); on 605b748b FAIL — first at step d (H:1 absent on a pruned
#   node), and at step f if that check is bypassed. The Ledger V2
#   preflight run at every open loads block 1's META (check 5,
#   nodus_witness_v2_preflight.c:334-349); on 605b748b a pruned node has
#   lost it, the preflight reports an inspection fault, the ingress stays
#   disarmed (nodus_witness.c:913-938) and every CheckTx on that node is
#   refused "successor chain not armed (activation gate closed)"
#   (nodus_witness_verify.c:673-676) while the node keeps producing —
#   MEASURED by the ORCHESTRATOR on 605b748b: "Ledger V2 NOT ACTIVATED …
#   INSPECTION_FAULT", spend refused (CLI rc=7). Step f's two admission
#   assertions are NOT to be weakened to make this scenario pass.
#
# WHAT IT REQUIRES
#   Compile flags: NONE beyond a default build of a tree carrying the
#   pruning commit (605b748b: `retain_blocks`, the floor, the SeenCommit
#   cleanup) AND its fix f8ecb5ac (H:1 kept, decision item 5) and the
#   block sync port. Every mode (`STAGEF_MODE` combined /
#   splitw / mixedw / splits / mixeds / split / mixed) — every stop and
#   start goes through stagef_stop_node / stagef_spawn_* (stagef_env.sh).
#   Environment, exported BEFORE `stagef_up_v2.sh` (both are in the hashed
#   genesis document — a different chain id):
#     STAGEF_EVIDENCE_MAX_AGE_BLOCKS=M        e.g. 10 → R = M + 2 = 12
#     STAGEF_EVIDENCE_MAX_AGE_DURATION_NS=D   e.g. 1000000 (1 ms)
#   The DURATION half is load-bearing: PruneBlocks deletes a height's
#   `H:` / `C:` only when nodus_cmt_is_evidence_expired holds, which needs
#   age in blocks > M AND age in time > D (nodus_witness_cmt_store.c
#   :414-426); the default D is 48 h (shared/dnac/cmt_params.c:69), so on
#   a harness chain that lives minutes those rows would stay. The scenario
#   SKIPs unless D < R × 10^6 ns: a vote's time is at least its block's
#   time + 1 ms (cmt_cs.c cmt_cs_vote_time :4100-4103,
#   CMT_CS_TIME_IOTA_NS cmt_cs.h:425) and a block's time is the weighted
#   median of the previous height's votes, so every pruned height h
#   (H − h ≥ R at a commit of H) is at least R ms older than H — expired
#   by block-time arithmetic alone, with no wall-clock assumption.
#   A cluster from stagef_up_v2.sh (`$BASE_DIR/v2_genesis.conf`,
#   `$BASE_DIR/v2_genesis_pin`), fresh: no node may carry a per-node
#   config yet. A nodus-cli (STAGEF_NODUSCLI_BIN) — step f submits a spend
#   with it, so it is REQUIRED (SKIP 99 without one); with it the CLI-SPEND
#   pump drives the blocks (STAGEF_PUMP_FUNDER_NODE 3 /
#   STAGEF_PUMP_SUBMIT_NODE 1 — both must differ from nodes 4, 5, 6, or it
#   FAILS at once). Should the pump be unready anyway, the ≈ 3R + 2 blocks
#   are idle production at 60 s per block (≈ 40 min at R = 12).
#   SKIP (99): not a version-3 cluster, no pin, no nodus-cli, the evidence
#   window not lowered (no evidence_max_age_num_blocks in
#   v2_genesis.conf), or the duration absent / not below R ms.
#   Run standalone, on its own bring-up:
#     export STAGEF_EVIDENCE_MAX_AGE_BLOCKS=10 STAGEF_EVIDENCE_MAX_AGE_DURATION_NS=1000000
#     bash stagef_up_v2.sh && bash tests/test_cmt_prune.sh
#
# WHAT IT LEAVES BEHIND
#   $BASE_DIR/node4/nodus.json and node5/nodus.json (the shared config +
#   "retain_blocks": R) — every later spawn of nodes 4 and 5 by ANY
#   scenario prunes (stagef_node_config); nodes 4 and 5 restarted under
#   new pids (node 5 twice — once refused, once correct; node 4 twice —
#   enabling, then kill -9), every pid appended to pids.txt, their logs
#   appended; node 6 wiped (identity kept) and rejoined under a new pid,
#   its nodus.log (and witness.log when split) TRUNCATED; the chain ≥ 3R +
#   2 blocks further on (plus whatever the join takes); node 3's genesis
#   leaf claimed (unless an earlier pump did) and one fee per pump step
#   spent, plus one more for step f's spend through node 4. On a
#   FAIL after the refusal step node 5 may be left degraded (combined: the
#   server up without its witness) or without its nodus-witness — tear
#   down. Rule N: nodes 4, 5 and 6 are each down for a few blocks; at a
#   short epoch (E = 15) that can cost one of them one epoch below the
#   attendance bar, never two in a row.
#
# HOW IT CAN LIE
#   - **Small numbers.** M = 10, R = 12, D = 1 ms prove the LOGIC (the
#     base moves, the rows go, the nodes agree); nothing about the
#     production window (M = 100 000, R = 120 960, D = 48 h), nor the
#     first prune of a long-lived node (one pass over ~10^5+ heights,
#     flushed every 1 000 — never more than a few hundred here), nor the
#     database file size (SQLite keeps freed pages; no VACUUM is run).
#   - **The 48 h duration half is not exercised at its real value**: the
#     duration knob is what lets the `H:` / `C:` deletion happen here at
#     all. At D = 48 h and a block interval below ≈ 1.73 s production
#     would keep those rows below the base (the commit's own "not done":
#     the duration is not checked at start) — not measured here.
#   - **`C:0` stays on a pruned node.** Block 1's save writes its
#     LastCommit as C:0 (nodus_witness_cmt_store.c:1195, height − 1) and
#     PruneBlocks walks from base = 1 (:377), so height 0 is never
#     visited — the reference's own shape (store.go:377), one row. The
#     `C:` checks exclude height 0.
#   - **Snapshot windows are tolerated, not hidden**: base ∈ {T−R,
#     T−R+1}, abciResponses minimum ∈ {base−1, base}, the abciResponses
#     maximum ∈ {T−1, T} (block T saved before it is applied). Each read
#     of a node is ONE SELECT — one read transaction — so the counts
#     within it are mutually consistent.
#   - **"Which peer served the joiner" is not logged.** The joiner's
#     block store holding `P:` for every height from 1 while nodes 4 and
#     5 hold none below their base shows the bottom of the chain came
#     from a node that still had it: block sync skips a peer whose base is
#     above the wanted height (shared/dnac/cmt_bsync_pool.c:491, pool.go
#     :490-492; also left out of maxPeerHeight, :307, :471-476) and a
#     pruned node cannot load what it deleted. The bad-peer / banning
#     paths are not exercised.
#   - **The 7/7 comparison is stagef_diff.sh's** (block id + global root
#     in `v2_blocks`, the application's table, which pruning does not
#     touch); the block store's own block hashes are compared at ONE
#     retained height (pruned node 4 vs archive node 1, the `BH:` key).
#   - **The refusal step's split branch** proves nodus-witness exited and
#     printed its exit line; the exit CODE is not read (the process is
#     not this shell's child).
#   - **Admission after restart is asserted on ONE node (4) with ONE
#     spend** (the pump funder's self-send, submitted to node 4's client
#     port, its created coin waited for on node 4). Node 5 is never
#     restarted after its height 1 is pruned; a combined-only or
#     split-only difference in that path shows up only in the mode run.
#   - **Admission before the restart is not asserted separately**; the
#     pump (step c) submits to node 1, an archive node.
#   - rc 99 is coverage that did not happen.
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

REF=1
PRUNED="4 5"
ARCHIVE="1 2 3 6 7"
REFUSE=5          # the floor-refusal victim (then pruned)
RESTART=4         # the kill -9 victim (pruned)
JOINER=6          # wiped + rejoined (archive)
CONF="$BASE_DIR/v2_genesis.conf"
PINFILE="$BASE_DIR/v2_genesis_pin"

die() { echo "[FAIL] $*" >&2; exit 1; }
db_of() { stagef_node_chain_db "$1"; }

# conf_key KEY — the value of a top-level `KEY = value` line of the genesis
# config ("" when absent).
conf_key() {
    awk -v k="$1" '$1 == k && $2 == "=" { print $3; exit }' "$CONF" 2>/dev/null || true
}

# ── 0. gates (SKIP 99 before SETUP_OK) ──────────────────────────────
ref_db=$(db_of "$REF")
has_v2=0
if [ -n "$ref_db" ] && [ -s "$ref_db" ]; then
    has_v2=$(sqlite3 "$ref_db" \
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
fi
if [ "${has_v2:-0}" = "0" ] || [ ! -f "$CONF" ] || [ ! -s "$PINFILE" ]; then
    echo "[SKIP] not a version-3 cluster from stagef_up_v2.sh (v2_blocks, v2_genesis.conf, v2_genesis_pin)"
    exit 99
fi
M=$(conf_key evidence_max_age_num_blocks)
D=$(conf_key evidence_max_age_duration_ns)
case "$M" in
    ''|*[!0-9]*)
        echo "[SKIP] the genesis evidence window was not lowered (no evidence_max_age_num_blocks in $CONF) — bring up with STAGEF_EVIDENCE_MAX_AGE_BLOCKS / STAGEF_EVIDENCE_MAX_AGE_DURATION_NS"
        exit 99 ;;
esac
R=$(( M + 2 ))
case "$D" in
    ''|*[!0-9]*)
        echo "[SKIP] the evidence DURATION was not lowered (no evidence_max_age_duration_ns in $CONF): at the 48 h default H:/C: rows below the base are not deleted on a harness chain — set STAGEF_EVIDENCE_MAX_AGE_DURATION_NS below $(( R * 1000000 ))"
        exit 99 ;;
esac
if [ "$D" -ge $(( R * 1000000 )) ]; then
    echo "[SKIP] evidence_max_age_duration_ns $D is not below R x 1 ms = $(( R * 1000000 )) ns — the H:/C: expiry would depend on wall time, not on block-time arithmetic"
    exit 99
fi
if [ ! -x "$STAGEF_NODUSCLI_BIN" ]; then
    echo "[SKIP] no nodus-cli at $STAGEF_NODUSCLI_BIN — step f submits a spend to the restarted pruned node's own client port"
    exit 99
fi
for v in 4 5 6; do
    [ "$v" != "$STAGEF_PUMP_FUNDER_NODE" ] && [ "$v" != "$STAGEF_PUMP_SUBMIT_NODE" ] \
        || die "node $v is a victim here and the pump's funder or submit node — change STAGEF_PUMP_*"
done
stagef_sentinel SETUP_OK

PIN=$(cat "$PINFILE")
[ "${#PIN}" = 64 ] || die "recorded pin is not 64 hex chars"
echo "[ok] evidence window M=$M blocks, D=$D ns; pruned nodes ($PRUNED) keep R=$R blocks; archive nodes ($ARCHIVE)"
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    [ "$(stagef_node_config "$n")" = "$BASE_DIR/nodus.json" ] \
        || die "node$n already has its own config $(stagef_node_config "$n") — this scenario needs a fresh bring-up"
done

# ── helpers ─────────────────────────────────────────────────────────

# log_size FILE — current byte size (0 when absent).
log_size() { stat -c %s "$1" 2>/dev/null || echo 0; }

# log_new_has FILE OFFSET TEXT — 0 if TEXT (fixed string) is in the bytes
# FILE gained after OFFSET. No pipe into grep -q (pipefail + SIGPIPE).
log_new_has() {
    grep -F -q -- "$3" < <(tail -c +"$(( $2 + 1 ))" "$1" 2>/dev/null)
}

# wait_log NODE_LABEL FILE OFFSET TEXT ATTEMPTS [PID] — attempt-bounded
# (ATTEMPTS x 1 s) wait for TEXT in FILE's new bytes; broken early when PID
# (if given) has exited and the text is still absent.
wait_log() {
    local lbl="$1" f="$2" off="$3" txt="$4" att="$5" pid="${6:-}"
    for _ in $(seq 1 "$att"); do
        log_new_has "$f" "$off" "$txt" && return 0
        if [ -n "$pid" ] && _stagef_pid_gone "$pid"; then
            log_new_has "$f" "$off" "$txt" && return 0
            break
        fi
        sleep 1
    done
    echo "[FAIL] $lbl: '$txt' never appeared in $f (new bytes)" >&2
    tail -20 "$f" >&2
    return 1
}

# snap N — ONE read of node N's chain database: a single SELECT (one read
# transaction, so every value below comes from the same committed state
# while the chain keeps writing). Keys are BLOBs (nodus_witness_v2_schema.c
# cmt_blockstore / cmt_state, bound with sqlite3_bind_blob) — read through
# CAST(key AS TEXT). Sets:
#   S_T     block-store tip (max P: height)    S_PMIN/S_PCNT  P: heights
#   S_HMIN/S_HCNT  H: rows                     S_CMIN/S_CCNT/S_CMAX  C: (h>0)
#   S_SCCNT/S_SCMAX  SC: rows                  S_BHCNT/S_BHMIN  BH: values
#   S_ARCNT/S_ARMIN/S_ARMAX  abciResponsesKey: rows (state store)
#   S_C0    C:0 present (0/1)
#   S_HMINX/S_HCNTX  H: rows above height 1    S_H1/S_H1LEN  H:1 rows / its
#   value's byte length                        S_BH1  BH: rows whose height is 1
snap() {
    local db out
    db=$(db_of "$1")
    [ -n "$db" ] || { echo "[FAIL] node$1 has no chain DB" >&2; return 1; }
    out=$(sqlite3 -cmd '.timeout 10000' "$db" "
WITH k  AS (SELECT CAST(key AS TEXT) AS t, value AS v FROM cmt_blockstore),
     p  AS (SELECT DISTINCT CAST(substr(t, 3) AS INTEGER) AS h FROM k WHERE substr(t, 1, 2) = 'P:'),
     hm AS (SELECT CAST(substr(t, 3) AS INTEGER) AS h, v FROM k WHERE substr(t, 1, 2) = 'H:'),
     c  AS (SELECT CAST(substr(t, 3) AS INTEGER) AS h FROM k WHERE substr(t, 1, 2) = 'C:'),
     sc AS (SELECT CAST(substr(t, 4) AS INTEGER) AS h FROM k WHERE substr(t, 1, 3) = 'SC:'),
     bh AS (SELECT CAST(CAST(v AS TEXT) AS INTEGER) AS h FROM k WHERE substr(t, 1, 3) = 'BH:'),
     ar AS (SELECT CAST(substr(CAST(key AS TEXT), 18) AS INTEGER) AS h FROM cmt_state
             WHERE substr(CAST(key AS TEXT), 1, 17) = 'abciResponsesKey:')
SELECT (SELECT COALESCE(MAX(h), -1) FROM p), (SELECT COALESCE(MIN(h), -1) FROM p),
       (SELECT COUNT(*) FROM p),
       (SELECT COALESCE(MIN(h), -1) FROM hm), (SELECT COUNT(*) FROM hm),
       (SELECT COALESCE(MIN(h), -1) FROM c WHERE h > 0), (SELECT COUNT(*) FROM c WHERE h > 0),
       (SELECT COALESCE(MAX(h), -1) FROM c WHERE h > 0),
       (SELECT COUNT(*) FROM sc), (SELECT COALESCE(MAX(h), -1) FROM sc),
       (SELECT COUNT(*) FROM bh), (SELECT COALESCE(MIN(h), -1) FROM bh),
       (SELECT COUNT(*) FROM ar), (SELECT COALESCE(MIN(h), -1) FROM ar),
       (SELECT COALESCE(MAX(h), -1) FROM ar),
       (SELECT COUNT(*) FROM c WHERE h = 0),
       (SELECT COALESCE(MIN(h), -1) FROM hm WHERE h > 1), (SELECT COUNT(*) FROM hm WHERE h > 1),
       (SELECT COUNT(*) FROM hm WHERE h = 1),
       (SELECT COALESCE(MAX(length(v)), 0) FROM hm WHERE h = 1),
       (SELECT COUNT(*) FROM bh WHERE h = 1);") \
        || { echo "[FAIL] node$1: the block-store read failed ($db)" >&2; return 1; }
    IFS='|' read -r S_T S_PMIN S_PCNT S_HMIN S_HCNT S_CMIN S_CCNT S_CMAX \
        S_SCCNT S_SCMAX S_BHCNT S_BHMIN S_ARCNT S_ARMIN S_ARMAX S_C0 \
        S_HMINX S_HCNTX S_H1 S_H1LEN S_BH1 <<< "$out"
    case "$S_BH1" in ''|*[!0-9]*) echo "[FAIL] node$1: unparsable block-store read '$out'" >&2; return 1 ;; esac
    return 0
}

snap_line() {
    echo "tip=$S_T P:[$S_PMIN..] x$S_PCNT H:[$S_HMIN..] x$S_HCNT (H:1 x$S_H1, ${S_H1LEN}B; H>1 from $S_HMINX x$S_HCNTX) C:[$S_CMIN..$S_CMAX] x$S_CCNT (C:0 $S_C0) SC x$S_SCCNT @$S_SCMAX BH:[$S_BHMIN..] x$S_BHCNT abciResponses:[$S_ARMIN..$S_ARMAX] x$S_ARCNT"
}

# check_sc LABEL — exactly one SeenCommit, at the block-store tip.
check_sc() {
    [ "$S_SCCNT" = 1 ] && [ "$S_SCMAX" = "$S_T" ] \
        || die "$1: SeenCommit rows x$S_SCCNT (max $S_SCMAX), want exactly SC:$S_T — $(snap_line)"
}

# check_archive N LABEL — every height 1..T kept.
check_archive() {
    local n="$1" lbl="$2" t
    snap "$n" || die "$lbl: node$n unreadable"
    t="$S_T"
    [ "$t" -ge 2 ] || die "$lbl: node$n block-store tip $t"
    [ "$S_PMIN" = 1 ] && [ "$S_PCNT" = "$t" ] \
        || die "$lbl: archive node$n is missing block parts — $(snap_line)"
    [ "$S_HMIN" = 1 ] && [ "$S_HCNT" = "$t" ] \
        || die "$lbl: archive node$n is missing block metas — $(snap_line)"
    [ "$S_CMIN" = 1 ] && [ "$S_CMAX" = $(( t - 1 )) ] && [ "$S_CCNT" = $(( t - 1 )) ] \
        || die "$lbl: archive node$n commits are not C:1..C:$(( t - 1 )) — $(snap_line)"
    [ "$S_BHMIN" = 1 ] && [ "$S_BHCNT" = "$t" ] \
        || die "$lbl: archive node$n block-hash index is not 1..$t — $(snap_line)"
    { [ "$S_ARMAX" = "$t" ] || [ "$S_ARMAX" = $(( t - 1 )) ]; } && [ "$S_ARMIN" = 1 ] \
        && [ "$S_ARCNT" = "$S_ARMAX" ] \
        || die "$lbl: archive node$n FinalizeBlock responses are not 1..$t (or ..$(( t - 1 ))) — $(snap_line)"
    check_sc "$lbl: node$n"
    echo "[ok] $lbl: archive node$n keeps every height — $(snap_line)"
}

# check_pruned N LABEL — exactly the last R heights kept (window above).
check_pruned() {
    local n="$1" lbl="$2" t b
    snap "$n" || die "$lbl: node$n unreadable"
    t="$S_T"; b="$S_PMIN"
    [ "$t" -gt $(( R + 1 )) ] || die "$lbl: node$n block-store tip $t is not above R + 1 = $(( R + 1 ))"
    { [ "$b" = $(( t - R + 1 )) ] || [ "$b" = $(( t - R )) ]; } \
        || die "$lbl: pruned node$n base $b, want $(( t - R + 1 )) (or $(( t - R )) before block $t's prune) — $(snap_line)"
    [ "$S_PCNT" = $(( t - b + 1 )) ] \
        || die "$lbl: pruned node$n block parts are not contiguous over [$b, $t] — $(snap_line)"
    # Decision item 5 (fix f8ecb5ac): block 1's meta H:1 is NEVER pruned —
    # the Ledger V2 preflight reads it at every open
    # (nodus_witness_v2_preflight.c:334-349); every other H: row below the
    # base is. So H: = [base, T] ∪ {1}, exactly.
    [ "$b" -gt 1 ] || die "$lbl: node$n pruned nothing"
    [ "$S_HMINX" = "$b" ] && [ "$S_HCNTX" = "$S_PCNT" ] \
        || die "$lbl: pruned node$n block metas above height 1 are not exactly [$b, $t] (H: kept below the base = the evidence-window leak) — $(snap_line)"
    [ "$S_H1" = 1 ] && [ "$S_H1LEN" -gt 0 ] && [ "$S_HMIN" = 1 ] && [ "$S_HCNT" = $(( S_PCNT + 1 )) ] \
        || die "$lbl: pruned node$n does not keep block 1's meta H:1 (decision item 5) beside [$b, $t] — $(snap_line)"
    echo "[ok] $lbl: pruned node$n keeps H:1 ($S_H1LEN bytes) and no other H: row below base $b"
    [ "$S_BH1" = 0 ] \
        || die "$lbl: pruned node$n still holds block 1's BH: row (only H:1 is kept) — $(snap_line)"
    [ "$S_CMIN" = "$b" ] && [ "$S_CMAX" = $(( t - 1 )) ] && [ "$S_CCNT" = $(( t - b )) ] \
        || die "$lbl: pruned node$n commits are not exactly C:$b..C:$(( t - 1 )) — $(snap_line)"
    [ "$S_BHMIN" = "$b" ] && [ "$S_BHCNT" = "$S_PCNT" ] \
        || die "$lbl: pruned node$n block-hash index is not exactly [$b, $t] — $(snap_line)"
    { [ "$S_ARMIN" = "$b" ] || [ "$S_ARMIN" = $(( b - 1 )) ]; } && [ "$S_ARMIN" -ge $(( t - R )) ] \
        && { [ "$S_ARMAX" = "$t" ] || [ "$S_ARMAX" = $(( t - 1 )) ]; } \
        && [ "$S_ARCNT" = $(( S_ARMAX - S_ARMIN + 1 )) ] \
        || die "$lbl: pruned node$n FinalizeBlock responses are not [$b (or $(( b - 1 ))), $t] — $(snap_line)"
    check_sc "$lbl: node$n"
    echo "[ok] $lbl: pruned node$n keeps the last $R heights (+ H:1) — $(snap_line)"
}

# fleet_tip — node REF's v2 tip.
fleet_tip() { stagef_cmt_tip "$(db_of "$REF")"; }

# catch_up N TARGET LABEL — progress-bounded wait for node N's v2 tip.
catch_up() {
    local h
    h=$(stagef_cmt_wait_height "$(db_of "$1")" "$2" 3) \
        || die "$3: node$1 did not reach height $2 (stuck at $h)"
}

# start_pruned N — node N with "retain_blocks": R, from a stopped state:
# writes its config, starts every process (stagef_spawn_node), and waits
# for the retention line and for node N to reach the fleet tip.
start_pruned() {
    local n="$1" lg off ft
    lg=$(stagef_node_log "$n")
    stagef_write_node_config "$n" "$R" || die "could not write node$n's config"
    off=$(log_size "$lg")
    stagef_spawn_node "$n" \
        || die "node$n did not come up with retain_blocks $R (the [FAIL] line above names the process)"
    wait_log "node$n" "$lg" "$off" "block retention: the last $R blocks are kept (evidence window $M blocks)" 90 \
        || die "node$n never logged its retention line"
    ft=$(fleet_tip)
    catch_up "$n" "$ft" "start_pruned"
    echo "[ok] node$n runs with retain_blocks $R (pids $STAGEF_NODE_PIDS), caught up to $ft"
}

stagef_cmt_diff_at_floor "pre-prune" || exit 2

pace="idle production (CreateEmptyBlocksInterval)"
if stagef_cmt_pump_ready "$ref_db"; then
    pace="CLI-SPEND pump (node$STAGEF_PUMP_FUNDER_NODE funds, node$STAGEF_PUMP_SUBMIT_NODE submits)"
fi
echo "[ok] block driving: $pace"

# Baseline: before anyone prunes, every node is an archive node and every
# node already holds ONE SeenCommit (the cleanup runs on every node of
# this build, from block 1). Height 3 first, so every row class has
# something to show (a fresh bring-up stops waiting at height 1).
reached=$(stagef_cmt_advance_to "$ref_db" 3 3) && arc=0 || arc=$?
[ "$arc" = 0 ] || die "the fleet did not reach height 3 (rc=$arc, tip $reached)"
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    catch_up "$n" 3 "baseline"
    check_archive "$n" "baseline"
done

# ── a. the floor: retain_blocks = M is refused ──────────────────────
src=0; stagef_stop_node "$REFUSE" TERM || src=$?
[ "$src" = 0 ] || die "stopping node$REFUSE failed (stagef_stop_node rc=$src)"
echo "[ok] node$REFUSE stopped (pids $STAGEF_STOPPED_PIDS)"
stagef_write_node_config "$REFUSE" "$M" || die "could not write node$REFUSE's config"
nd5=$(stagef_node_dir "$REFUSE")
vlog5=$(stagef_node_log "$REFUSE")
clog5="$nd5/nodus.log"
voff=$(log_size "$vlog5"); coff=$(log_size "$clog5")
# Started process by process — NOT stagef_spawn_node, which waits for a
# split witness's running line: a refused nodus-witness exits before it
# (tools/nodus-witness.c: nodus_witness_init fails at :299, exit 1 at
# :322; the running line is :338).
cp5=$(stagef_spawn_core "$REFUSE"); echo "$cp5" >> "$BASE_DIR/pids.txt"
wp5=""
if stagef_node_is_split "$REFUSE"; then
    wp5=$(stagef_spawn_witness "$REFUSE"); echo "$wp5" >> "$BASE_DIR/pids.txt"
fi
if stagef_node_is_storage_split "$REFUSE"; then
    sp5=$(stagef_spawn_storage "$REFUSE"); echo "$sp5" >> "$BASE_DIR/pids.txt"
fi
# The exact refusal (nodus_witness_cmt_node.c nodus_cmt_node_init): the
# window it names is the chain's STORED one — the lowered M.
wait_log "node$REFUSE" "$vlog5" "$voff" \
    "retain_blocks $M refused: it must be 0 (keep every block) or greater than this chain's evidence window max_age_num_blocks $M" \
    90 "$wp5" || die "node$REFUSE did not refuse retain_blocks $M"
echo "[ok] node$REFUSE refused retain_blocks $M (= the evidence window)"
if [ -n "$wp5" ]; then
    # Split witness: nodus-witness exits (tools/nodus-witness.c :299-322).
    gone=0
    for _ in $(seq 1 60); do
        if _stagef_pid_gone "$wp5"; then gone=1; break; fi
        sleep 0.5
    done
    [ "$gone" = 1 ] || die "node$REFUSE's nodus-witness (pid $wp5) is still running after refusing"
    log_new_has "$vlog5" "$voff" "WITNESS MODULE INIT FAILED — nodus-witness EXITS (code 1)" \
        || die "node$REFUSE's nodus-witness exited without its exit line"
    echo "[ok] node$REFUSE's nodus-witness exited (split)"
else
    # Witness in the core: the server stays up DEGRADED (nodus_server.c,
    # the O15L Faz 2 block).
    wait_log "node$REFUSE" "$clog5" "$coff" "WITNESS MODULE INIT FAILED — THIS NODE IS RUNNING DEGRADED" 30 \
        || die "node$REFUSE's server did not report the degraded witness"
    ! _stagef_pid_gone "$cp5" || die "node$REFUSE's server (pid $cp5) exited — the refusal must leave it up, degraded"
    echo "[ok] node$REFUSE's server stays up degraded (witness in-process)"
fi
! log_new_has "$vlog5" "$voff" "cometbft lane LIVE" \
    || die "node$REFUSE went LIVE with retain_blocks $M"
! log_new_has "$vlog5" "$voff" "block retention:" \
    || die "node$REFUSE logged a retention line although it refused"
# Refused before the handshake (whose replay prunes): nothing was pruned.
check_archive "$REFUSE" "after-refusal"
src=0; stagef_stop_node "$REFUSE" TERM || src=$?
if stagef_node_is_split "$REFUSE"; then
    # Its nodus-witness is already gone, so the node is not whole: rc 3.
    [ "$src" = 3 ] || die "stopping the refused node$REFUSE: rc=$src, want 3 (core/storage stopped, the witness already gone)"
else
    [ "$src" = 0 ] || die "stopping the refused node$REFUSE failed (rc=$src)"
fi
echo "[ok] refused node$REFUSE stopped"

# ── b. nodes 5 and 4 prune (R), one at a time; 1-3, 6, 7 archive ────
# Log offsets taken BEFORE each start: the first prune runs at the first
# commit after it (a "failed to prune blocks" line is looked for below).
log_off5=$(log_size "$(stagef_node_log 5)")
start_pruned "$REFUSE"
src=0; stagef_stop_node 4 TERM || src=$?
[ "$src" = 0 ] || die "stopping node4 failed (stagef_stop_node rc=$src)"
log_off4=$(log_size "$(stagef_node_log 4)")
start_pruned 4

# ── c. drive the chain ≥ 3R blocks ──────────────────────────────────
t0=$(fleet_tip)
target=$(( t0 + 3 * R ))
reached=$(stagef_cmt_advance_to "$ref_db" "$target" 3) && arc=0 || arc=$?
[ "$arc" = 0 ] || die "the fleet did not reach height $target (rc=$arc, tip $reached)"
echo "[ok] the chain moved $t0 -> $reached"
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    catch_up "$n" "$target" "drive"
done

# ── d. the stores ───────────────────────────────────────────────────
for n in $PRUNED; do check_pruned "$n" "after-drive"; done
for n in $ARCHIVE; do check_archive "$n" "after-drive"; done
! log_new_has "$(stagef_node_log 4)" "$log_off4" "failed to prune blocks" \
    || die "node4 logged a prune failure"
! log_new_has "$(stagef_node_log 5)" "$log_off5" "failed to prune blocks" \
    || die "node5 logged a prune failure"
echo "[ok] no prune failure logged on nodes 4 / 5"

# ── e. 7/7 after pruning demonstrably happened ──────────────────────
stagef_cmt_diff_at_floor "post-prune-drive" || exit 2
# The block store's own block hash at one retained height: the BH: key
# (BH:<hex hash>, value = the height) on pruned node 4 and archive node 1.
snap 4 || die "node4 unreadable"
hcmp=$(( S_T - 1 ))
bh_of() {
    sqlite3 -cmd '.timeout 10000' "$(db_of "$1")" \
        "SELECT CAST(key AS TEXT) FROM cmt_blockstore WHERE substr(CAST(key AS TEXT), 1, 3) = 'BH:'
           AND CAST(CAST(value AS TEXT) AS INTEGER) = $2;"
}
bh4=$(bh_of 4 "$hcmp"); bh1=$(bh_of 1 "$hcmp")
[ -n "$bh4" ] && [ "$bh4" = "$bh1" ] \
    || die "block hash at height $hcmp: node4 '$bh4' vs node1 '$bh1'"
echo "[ok] block $hcmp has the same hash on pruned node4 and archive node1 (${bh4:0:19}…)"

# ── f. a pruned node survives kill -9 ───────────────────────────────
snap "$RESTART" || die "node$RESTART unreadable"
base_before="$S_PMIN"
# Height 1 is pruned (base > 1: its parts, BH:, C: are gone) while its meta
# H:1 is kept (decision item 5) — the state the restart's Ledger V2
# preflight reads (check 5, nodus_witness_v2_preflight.c:334-349).
[ "$S_PMIN" -gt 1 ] && [ "$S_BH1" = 0 ] \
    || die "node$RESTART has not pruned height 1 yet (base $S_PMIN, BH:1 x$S_BH1) — the restart would not exercise a pruned height 1"
[ "$S_H1" = 1 ] && [ "$S_H1LEN" -gt 0 ] \
    || die "node$RESTART lost block 1's meta H:1 (x$S_H1, ${S_H1LEN} bytes) — decision item 5 keeps it"
echo "[ok] node$RESTART: height 1 pruned (base $S_PMIN, no BH:1) and H:1 kept ($S_H1LEN bytes)"
lg4=$(stagef_node_log "$RESTART")
src=0; stagef_stop_node "$RESTART" KILL || src=$?
[ "$src" = 0 ] || die "killing node$RESTART failed (stagef_stop_node rc=$src)"
echo "[ok] node$RESTART killed (pids $STAGEF_STOPPED_PIDS), base was $base_before"
off4=$(log_size "$lg4")
stagef_spawn_node "$RESTART" \
    || die "node$RESTART did not come back after kill -9 (the [FAIL] line above names the process)"
wait_log "node$RESTART" "$lg4" "$off4" "block retention: the last $R blocks are kept (evidence window $M blocks)" 90 \
    || die "node$RESTART lost its retention setting across the restart"
wait_log "node$RESTART" "$lg4" "$off4" "completed ABCI handshake" 90 \
    || die "node$RESTART never completed its handshake"
ft=$(fleet_tip)
vt=$(stagef_cmt_wait_height "$(db_of "$RESTART")" "$(( ft + 2 ))" 3) \
    || die "node$RESTART did not produce past the fleet tip $ft after its restart (stuck at $vt)"
check_pruned "$RESTART" "after-restart"
[ "$S_PMIN" -gt "$base_before" ] \
    || die "node$RESTART's base did not advance after the restart ($base_before -> $S_PMIN)"
! log_new_has "$lg4" "$off4" "failed to prune blocks" || die "node$RESTART logged a prune failure after the restart"
echo "[ok] node$RESTART restarted, produced to $vt, base $base_before -> $S_PMIN"

# The restarted pruned node must still ADMIT transactions. Producing
# blocks (above) is consensus; admission is the Ledger V2 ingress gate,
# armed at open only when the preflight is ready (nodus_witness.c:913-
# 938) — and preflight check 5 loads block 1's META
# (nodus_witness_v2_preflight.c:334-349). A disarmed gate refuses every
# CheckTx with "successor chain not armed (activation gate closed)"
# (nodus_witness_verify.c:673-676).
# Expected: PASS on f8ecb5ac+ (decision item 5 keeps H:1); FAIL on
# 605b748b, which pruned H:1 — MEASURED by the ORCHESTRATOR: "Ledger V2
# NOT ACTIVATED … INSPECTION_FAULT" and the spend refused (CLI rc=7).
# These two assertions are not to be weakened. Both are evaluated
# before the verdict, so the output says
# which half failed.
f_bad=""
if log_new_has "$lg4" "$off4" "Ledger V2 NOT ACTIVATED"; then
    grep -F -- "Ledger V2 NOT ACTIVATED" < <(tail -c +"$(( off4 + 1 ))" "$lg4") >&2 || true
    f_bad="$f_bad [node$RESTART logged 'Ledger V2 NOT ACTIVATED' at this start]"
fi
# A self-send of the pump funder's largest coin, submitted to node
# RESTART's OWN client port (the CLI lists the coins there too, so the
# amount is read from node RESTART's database), confirmed by its ledger
# effect (the created utxo_set row, tx_hash = the intent id) — the same
# shape as stagef_cmt_pump_to.
db4=$(db_of "$RESTART")
amt=$(stagef_pump_largest "$db4")
if [ "$amt" -le "$STAGEF_PUMP_FEE_RAW" ]; then
    h=$(stagef_pump_claim "$ref_db") && crc=0 || crc=$?
    [ "$crc" = 0 ] || die "node$STAGEF_PUMP_FUNDER_NODE's leaf claim failed (rc=$crc, tip $h) — no coin for the post-restart spend"
    catch_up "$RESTART" "$h" "claim"
    amt=$(stagef_pump_largest "$db4")
fi
[ "$amt" -gt "$STAGEF_PUMP_FEE_RAW" ] || die "node$STAGEF_PUMP_FUNDER_NODE holds no coin above the fee on node$RESTART"
fkeys=$(stagef_pump_keys)
ffp=$(cat "$fkeys/nodus.fp")
port4=$(stagef_tcp_port "$RESTART")
srcl=0
sout=$("$STAGEF_NODUSCLI_BIN" -s 127.0.0.1 -p "$port4" \
          v2-envelope spend --keys "$fkeys" --to "$ffp" \
          --amount "$(( amt - STAGEF_PUMP_FEE_RAW ))" --fee "$STAGEF_PUMP_FEE_RAW" --no-dust-sweep \
          --submit "127.0.0.1:$port4" 2>&1) || srcl=$?
if [ "$srcl" != 0 ]; then
    printf '%s\n' "$sout" >&2
    f_bad="$f_bad [a spend submitted to node$RESTART's client port $port4 was refused (CLI rc=$srcl)]"
else
    intent=$(printf '%s\n' "$sout" | awk -F= '/^  intent_id=/{print $2; exit}')
    if [ "${#intent}" != 128 ]; then
        printf '%s\n' "$sout" >&2
        f_bad="$f_bad [the spend to node$RESTART printed no intent_id]"
    else
        h=$(stagef_cmt_wait_row "$db4" \
            "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$intent';" 3) \
            && wrc=0 || wrc=$?
        if [ "$wrc" != 0 ]; then
            f_bad="$f_bad [the spend ${intent:0:16}... admitted by node$RESTART never landed (wait rc=$wrc, tip $h)]"
        else
            echo "[ok] node$RESTART admitted a spend on its own client port after the restart; it landed (tip $h)"
        fi
    fi
fi
[ -z "$f_bad" ] || die "the restarted pruned node$RESTART does not admit transactions:$f_bad"
echo "[ok] node$RESTART: Ledger V2 activated at this start and admits transactions"
stagef_cmt_diff_at_floor "post-prune-restart" || exit 2

# ── g. a wiped archive node rejoins while 4 and 5 are pruned ────────
for n in $PRUNED; do
    snap "$n" || die "node$n unreadable"
    [ "$S_PMIN" -gt 1 ] || die "node$n's base is $S_PMIN — nothing to prove the joiner against"
    echo "[ok] pruned node$n's base is $S_PMIN: it cannot serve heights 1..$(( S_PMIN - 1 ))"
done
[ ! -e "$BASE_DIR/node$JOINER/nodus.json" ] || die "node$JOINER has a per-node config — it must rejoin as an archive node"
fleet_gid=$(basename "$ref_db")
ndj=$(stagef_node_dir "$JOINER")
vlogj=$(stagef_node_log "$JOINER")
src=0; stagef_stop_node "$JOINER" KILL || src=$?
[ "$src" = 0 ] || die "stopping node$JOINER failed (stagef_stop_node rc=$src)"
echo "[ok] node$JOINER stopped (pids $STAGEF_STOPPED_PIDS)"
# test_v2_join.sh's wipe, exactly: everything but the identity.
rm -f "$ndj/data/"*.db "$ndj/data/"*.db-wal "$ndj/data/"*.db-shm \
      "$ndj/data/.witness_db_seen" "$ndj/data/.bootstrap_in_progress" \
      "$ndj/data/.recovery_in_progress"
rm -rf "$ndj/data/archive"
: > "$ndj/nodus.log"
[ "$vlogj" = "$ndj/nodus.log" ] || : > "$vlogj"
ls "$ndj/data/"witness_*.db >/dev/null 2>&1 && die "wipe did not remove node$JOINER's chain DB"
echo "[ok] node$JOINER wiped (identity kept)"
stagef_spawn_node "$JOINER" --v2-genesis-pin "$PIN" \
    || die "node$JOINER did not come up with its pin (the [FAIL] line above names the process)"
adopted=0
for _ in $(seq 1 120); do
    gid=$(basename "$(db_of "$JOINER")" 2>/dev/null || true)
    if [ -n "$gid" ] && [ "$gid" != "." ]; then adopted=1; break; fi
    sleep 1
done
[ "$adopted" = 1 ] || { tail -30 "$vlogj" >&2; die "node$JOINER never adopted a chain"; }
[ "$gid" = "$fleet_gid" ] || die "node$JOINER adopted a DIFFERENT chain: $gid vs $fleet_gid"
echo "[ok] node$JOINER adopted the fleet's chain ($gid)"
# Block sync (progress-bounded like test_cmt_blocksync.sh: 3 empty-block
# intervals with neither the done line nor tip movement fail it).
last_tip=-1 since=0 poll_s=5
stall_polls=$(( (3 * (STAGEF_CMT_EMPTY_INTERVAL_MS / 1000) + poll_s - 1) / poll_s ))
while ! grep -q 'block sync done at height' "$vlogj"; do
    t=$(stagef_cmt_tip "$(db_of "$JOINER")")
    [ -n "$t" ] || t=-1
    if [ "$t" -gt "$last_tip" ]; then last_tip="$t"; since=0
    else since=$(( since + 1 )); fi
    [ "$since" -lt "$stall_polls" ] || die "node$JOINER made no block-sync progress (tip $t) across 3 empty-block intervals"
    sleep "$poll_s"
done
line=$(grep 'block sync done at height' "$vlogj" | tail -1)
synced_n=$(printf '%s\n' "$line" | sed -n 's/.*block sync done at height \([0-9]*\) (\([0-9]*\) block.*/\2/p')
case "$synced_n" in ''|*[!0-9]*) die "could not parse the block-sync line: $line" ;; esac
[ "$synced_n" -ge 1 ] || die "node$JOINER switched to consensus with 0 blocks synced"
echo "[ok] node$JOINER: $line"
! grep -q 'block retention:' "$vlogj" || die "node$JOINER logged a retention line — it must be an archive node"
ft=$(fleet_tip)
catch_up "$JOINER" "$ft" "join"
check_archive "$JOINER" "after-join"
echo "[ok] node$JOINER holds every block from height 1 — below nodes 4 / 5's base it can only have come from an archive peer"
for n in $PRUNED; do check_pruned "$n" "after-join"; done

# ── h. final ────────────────────────────────────────────────────────
ft=$(fleet_tip)
for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    catch_up "$n" "$ft" "final"
done
for n in $PRUNED; do check_pruned "$n" "final"; done
for n in $ARCHIVE; do check_archive "$n" "final"; done
stagef_sentinel ASSERT_RUN
stagef_cmt_diff_at_floor "post-prune-final" || exit 2

stagef_sentinel PASS
echo ""
echo "[PASS] mixed retention: nodes 4 and 5 keep the last $R blocks (evidence window"
echo "       $M blocks, $D ns), nodes 1-3, 6, 7 keep everything; retain_blocks $M was"
echo "       refused; a pruned node survived kill -9; a wiped archive node rejoined by"
echo "       its pin and block-synced from height 1; one SeenCommit per node; all"
echo "       $STAGEF_COMMITTEE_SIZE nodes agree."
