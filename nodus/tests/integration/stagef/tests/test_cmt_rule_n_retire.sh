#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_rule_n_retire.sh — a validator that signs nothing for two
# consecutive epochs is AUTO_RETIRED, and the retirement reaches
# cometbft (tokenomics-v3 P1, D-3, D-11, §A)
# ════════════════════════════════════════════════════════════════════
#
# WHAT IT PROVES
#   Rule N's liveness rule end to end, over a REAL SIGSTOPped validator
#   — not a hand-set database row (that half is already proven by
#   test_v2_epoch.c's own unit tests; this harness proves the SAME rule
#   fires from REAL signature attendance on a REAL cometbft cluster):
#
#   (1) a validator that cannot sign for two consecutive epochs is
#       AUTO_RETIRED at the SECOND boundary (`validators.status`,
#       `consecutive_missed_epochs == 2`, `active_count` decremented by
#       exactly one) — D-3/D-11.
#   (2) that retirement reaches cometbft's OWN validator set, but ONE
#       EPOCH LATER than the DB flip, not at the same boundary — the
#       property that would be false if this harness's own author had
#       assumed (as the ORIGINAL dispatch text for this scenario did)
#       that the removal is announced at the SAME boundary Rule N
#       decides it. It is not: `nodus_cmt_app_finalize_block`'s §A diff
#       at boundary H compares `snapshot(H)` (frozen at boundary H-E,
#       BEFORE this retirement was decided) against `snapshot(H-E)`
#       (frozen even earlier) — neither side has ever seen the
#       retirement yet. The retirement only becomes visible in
#       `snapshot(H+E)`, written by THIS SAME boundary's own
#       `nodus_witness_vset_commit_next(H)` call, AFTER Rule N flipped
#       the row. So the §A ValidatorUpdates line reporting "1 removal"
#       for this validator appears at boundary H+E — the THIRD boundary
#       after the stop, not the second. This script waits for that
#       third boundary and asserts the INFO line there; asserting it one
#       epoch early would either never fire (a script that reports PASS
#       without exercising its subject) or be quietly wrong about what
#       it measured.
#   (3) the stopped validator's own `v2_attendance.last_signed_height`
#       is frozen for the ENTIRE window (it cannot sign — it is not
#       running), while every other validator's keeps moving, and the
#       chain never stalls (6 of 7 exceeds `dna_bft_quorum(7) = 5`).
#   (4) resuming the validator lets it catch up and re-converge with the
#       fleet — the retirement does not orphan it permanently on this
#       lane (P1 does not touch rejoin; that is a later package).
#
# WHY NODE 7, WHY THE ALIGNMENT WAIT
#   Node 7 (arbitrary, fixed — no derivation needed on this lane, the
#   same reasoning `test_cmt_dead_proposer.sh`'s header gives for its
#   own fixed victim). The script does NOT stop node 7 immediately: if
#   the current height is already mid-epoch, node 7 would have signed
#   part of that epoch before the stop, and the FIRST epoch's outcome
#   would depend on how much of it was already elapsed — sometimes a
#   miss, sometimes not, at this harness's mercy. Instead it waits
#   (with node 7 healthy) until the chain reaches the START of a fresh
#   epoch, stops node 7 there, and only then does the two-epoch clock
#   start — so both watched epochs are unambiguously 0 % attended by
#   design, not by luck.
#
# WHAT IT REQUIRES
#   Compile flags: a SHORT-EPOCH build — `-DDNAC_EPOCH_LENGTH=<E>` (the
#   short-epoch sweep's E=15 build). A default nodus/build binary
#   (E=720) only reaches the SKIP below.
#   Environment: `STAGEF_EPOCH_LENGTH=<E>` exported to the SAME E before
#   bring-up, from stagef_up_v2.sh. This scenario needs to observe
#   THREE consecutive epoch boundaries plus a short settle window; at
#   the shipped epoch length (720) that is many hours of idle-only wall
#   time and this script SKIPS (rc 99) rather than wait for it — see the
#   wall-clock budget below, computed the same way
#   `test_v2_epoch_boundary.sh` computes its own (a blocks-away figure
#   times the interval, never a bare timeout raised until green).
#   ⚠ A cluster from **stagef_up_v2.sh**. On a legacy cluster it exits 99.
#
# ROUND 5 RE-CHECK (R5-8, tokenomics-v3 P1): re-verified against R5-1
# (duty-set evaluation), R5-2 (the floor) and R5-3 (graduation deferral)
# — arithmetic UNCHANGED. Node 7 is a continuous 7-of-7 committee member
# with a real duty at both e1 and e2 (R5-1 does not reset anything for
# it); retiring it alone at e2 leaves bonded_after = 6, nowhere near
# round 5's DNAC_RULE_N_MIN_BONDED = 4 (R5-2's floor does not engage);
# ROUND 6 RE-CHECK (the floor is now voting power, decision file §3
# 2026-09-23 "Rule N TABANI WEIGHT ÜZERİNDEN"; the count constant is
# deleted): the next epoch's seatable set is the 6 other genesis
# validators — plus, if test_v2_stake.sh ran earlier, a staker bonded
# with the SAME DNAC_SELF_STAKE_AMOUNT (its own BOND) — all at equal
# power (stagef_up_v2.sh SELF_STAKE), so the largest member holds at
# most 1/6 of the set's power and (P - max) > P*2/3 holds: the
# retirement is ALLOWED exactly as before, no step below changes; node 7 only
# BECOMES AUTO_RETIRED partway through e2's own Rule N step (step 4),
# AFTER e2's own graduation phase (step 2) already ran, so it was never
# a graduation candidate at e2 with or without R5-3's snapshot check; by
# e3, `commit_next(e2)` has already excluded it from snapshot(e3), so
# R5-3's deferral condition does not hold and it graduates at e3 exactly
# as this header already described. No step below needed adjustment.
#
# WHAT IT LEAVES BEHIND
#   Node 7 SIGSTOPped and then SIGCONTed — an EXIT trap resumes it on
#   any early exit, or a failed run leaves the fleet a validator short
#   for everything after it. Node 7 permanently AUTO_RETIRED on this
#   chain (UNSTAKED after its own next graduation boundary, per D-11) —
#   this is NOT reversible within this bring-up; a scenario run AFTER
#   this one that assumes 7 ACTIVE validators will not find them. The
#   runner places it immediately before `test_cmt_arena_runway.sh`
#   (which only reads receive-arena latches) and after everything else.
#
# HOW IT CAN LIE
#   - Idle production (CreateEmptyBlocks) means "height advanced" alone
#     proves nothing about Rule N specifically — every assertion here
#     reads `v2_attendance` / `validators` / the CMT-APP log line
#     directly, never infers retirement from height movement alone.
#   - The two-epoch clock starts at the FIRST boundary reached AFTER the
#     stop lands; if `kill -STOP` itself races a boundary block (stop
#     delivered a moment after the boundary height was already decided),
#     the alignment wait's own re-check below re-derives the epoch
#     bounds from the height ACTUALLY observed after the stop, so this
#     is self-correcting rather than assumed.
#   - rc=99 means the cluster was not Comet, or the wall-clock budget for
#     three boundaries at this build's epoch length was not available —
#     coverage that did not happen, never a pass.
#   - The victim's frozen attendance is read 3 heights AFTER the stop,
#     not at it: block H credits the precommits for H-1, so a precommit
#     sent just before the stop lands one block later (measured on the
#     first short-epoch sweep at 0.19.67: 29 -> 30). See the SETTLE block.
#   - Only the 50 % BAR is exercised, never the 120-block RECENCY window
#     (DNAC_SETTLEMENT_ATTENDANCE_WINDOW_BLOCKS): at E=15 the window is
#     longer than the two watched epochs, so the victim's frozen
#     `last_signed_height` still sits inside it at e2 and the retirement
#     is decided by the bar alone. The recency rule and the Rule N
#     voting-power floor are covered only by test_v2_epoch.c (§11a; the
#     floor §12c, §12e-§12i) at E=720 — this scenario's one retirement is
#     always allowed, so a REFUSED retirement is never exercised here.
#   - A green here is at E=15, not 720: it proves the retire → §A →
#     graduation ordering and 7/7 agreement, nothing about how long a
#     real epoch takes to reach it.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

REF=1
VICTIM=7   # FIXED — no derivation needed or possible on this lane.

die() { echo "[FAIL] $*" >&2; exit 1; }

VPID=""
resume() { [ -n "$VPID" ] && kill -CONT "$VPID" 2>/dev/null || true; }
trap resume EXIT

ref_db=$(stagef_node_chain_db "$REF")
[ -n "$ref_db" ] && [ -s "$ref_db" ] || die "no chain DB for node$REF"
has_v2=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ]; then
    echo "[SKIP] not a Comet cluster — use stagef_up_v2.sh"
    exit 99
fi

E_LEN="${STAGEF_EPOCH_LENGTH:-720}"
tip() { stagef_cmt_tip "$ref_db"; }

# ── Wall-clock budget for THREE boundaries + settle, computed from the
# CURRENT tip, exactly the reasoning test_v2_epoch_boundary.sh's own
# header states: worst case is purely idle production, one
# CreateEmptyBlocksInterval per block, no leaf count involved. ────────
STAGEF_RULE_N_RETIRE_BUDGET_S="${STAGEF_RULE_N_RETIRE_BUDGET_S:-5400}"
head0=$(tip)
epoch_start0=$(( (head0 / E_LEN) * E_LEN ))
align_to=$(( epoch_start0 == head0 ? head0 : epoch_start0 + E_LEN ))
e1=$(( align_to + E_LEN ))
e2=$(( e1 + E_LEN ))
e3=$(( e2 + E_LEN ))
settle_to=$(( e3 + 7 ))
need=$(( settle_to - head0 ))
worst_case_s=$(( need * (STAGEF_CMT_EMPTY_INTERVAL_MS / 1000) ))
if [ "$worst_case_s" -gt "$STAGEF_RULE_N_RETIRE_BUDGET_S" ]; then
    echo "[SKIP] epoch length $E_LEN needs $need blocks to observe three"
    echo "       boundaries plus settle from height $head0; worst-case"
    echo "       idle-only wait is ${worst_case_s}s, over this harness's"
    echo "       ${STAGEF_RULE_N_RETIRE_BUDGET_S}s patience budget —"
    echo "       needs a SHORT-EPOCH build: -DDNAC_EPOCH_LENGTH=15 +"
    echo "       STAGEF_EPOCH_LENGTH=15"
    exit 99
fi
echo "[ok] epoch length $E_LEN, head $head0, boundaries at $align_to/$e1/$e2/$e3, settle to $settle_to (worst case ${worst_case_s}s)"
stagef_sentinel SETUP_OK   # W4-H: the runner turns PASS-without-ASSERT_RUN into FAIL

stagef_cmt_diff_at_floor "pre-cmt-rule-n-retire" || exit 2

voter_id=$(stagef_voter_id "$(stagef_node_dir "$VICTIM")/identity/nodus.pk")
[ "${#voter_id}" = 64 ] || die "could not derive node$VICTIM's voter_id"

# ── ALIGNMENT: wait for a fresh epoch start with node 7 still HEALTHY,
# so both watched epochs are unambiguously 0 % attended by design. ────
if [ "$align_to" -gt "$head0" ]; then
    aligned=$(stagef_cmt_wait_height "$ref_db" "$align_to" 3) \
        || die "tip did not reach the alignment boundary $align_to (stuck at $aligned)"
fi
# Self-correcting re-derivation (HOW IT CAN LIE): read the height
# ACTUALLY reached, not assumed, before deriving the two-epoch window.
aligned_h=$(tip)
e1=$(( ((aligned_h / E_LEN) * E_LEN) + E_LEN ))
e2=$(( e1 + E_LEN ))
e3=$(( e2 + E_LEN ))
echo "[ok] aligned at height $aligned_h; boundaries at $e1/$e2/$e3"

VPID=$(pgrep -f "node$VICTIM/data" | head -1 || true)
[ -n "$VPID" ] || die "node$VICTIM is not running"
kill -STOP "$VPID"
echo "[ok] node$VICTIM (pid $VPID) STOPPED (voter_id ${voter_id:0:16}...) at height $aligned_h"

# SETTLE before freezing (MEASURED, first short-epoch sweep at 0.19.67,
# /tmp/stagef-20260923T165138Z: stop at 30, read 29, later 30). Block H
# credits the precommits FOR H-1 (nodus_witness_v2_attendance_credit), so
# a precommit node 7 sent just BEFORE the stop is credited one block AFTER
# it. Same rule and same stated assumption as test_cmt_dead_proposer.sh's
# SETTLE block: at most one committed block of lead over node 1, so every
# pre-stop precommit is credited by aligned_h+3; a larger lead shows as a
# visible RED below, never a false GREEN. Side effect worth knowing: that
# late credit gives node 7 ONE signed block inside the first watched epoch
# (≈ 1/15 at E=15) — still far below the 50 % bar, so the miss at e1 is
# unaffected, but "0 % attended" is 0-1 blocks, not exactly 0.
# Its own name: `settle_to` is the FINAL "e3 + 7" target set above and
# reused at the end — overwriting it (as the first cut of this block did)
# made the final settle return at once.
stop_settle_to=$(( aligned_h + 3 ))
settled_h=$(stagef_cmt_wait_height "$ref_db" "$stop_settle_to" 12) \
    || die "tip did not reach the settle height $stop_settle_to with node$VICTIM stopped (stuck at $settled_h)"
last_signed_frozen=$(sqlite3 "$ref_db" \
    "SELECT COALESCE(last_signed_height,-1) FROM v2_attendance WHERE lower(hex(voter_id))='$voter_id';" \
    2>/dev/null || echo -1)
echo "[ok] node$VICTIM's last_signed_height settled at tip $settled_h (stop at $aligned_h): $last_signed_frozen"

# v2_attendance's key (voter_id, SHA3-512(pubkey)[0..31]) is NOT
# `validators`' own key (pubkey) — resolve node 7's raw pubkey bytes
# directly so its OWN row can be read by the table's real key.
v7pk_hex=$(xxd -p -c 999999 "$(stagef_node_dir "$VICTIM")/identity/nodus.pk" 2>/dev/null || true)
[ -n "$v7pk_hex" ] || die "could not read node$VICTIM's pubkey file"

# ── First epoch, fully missed, but below AUTO_RETIRE_EPOCHS ─────────
h1=$(stagef_cmt_wait_height "$ref_db" "$e1" 12) \
    || die "tip did not reach the first boundary $e1 with node$VICTIM stopped (stuck at $h1)"
row1=$(sqlite3 "$ref_db" \
    "SELECT status||'|'||consecutive_missed_epochs FROM validators WHERE lower(hex(pubkey))='$v7pk_hex';")
[ -n "$row1" ] || die "no validators row for node$VICTIM's pubkey"
st1="${row1%%|*}"; miss1="${row1##*|}"
[ "$st1" = "0" ] || die "node$VICTIM's status changed after ONE missed epoch (status=$st1) — Rule N must not AUTO_RETIRE before DNAC_AUTO_RETIRE_EPOCHS misses"
[ "$miss1" = "1" ] || die "node$VICTIM's consecutive_missed_epochs after one fully-missed epoch is $miss1, expected 1"
echo "[ok] boundary $e1 (height $h1): node$VICTIM ACTIVE, consecutive_missed_epochs=1 (one miss, not yet AUTO_RETIRE)"

# ── Second epoch, fully missed: AUTO_RETIRE fires ────────────────────
h2=$(stagef_cmt_wait_height "$ref_db" "$e2" 12) \
    || die "tip did not reach the second boundary $e2 with node$VICTIM stopped (stuck at $h2)"
row2=$(sqlite3 "$ref_db" \
    "SELECT status||'|'||consecutive_missed_epochs FROM validators WHERE lower(hex(pubkey))='$v7pk_hex';")
st2="${row2%%|*}"; miss2="${row2##*|}"
[ "$st2" = "3" ] || die "node$VICTIM's status at the second missed boundary is $st2, expected 3 (DNAC_VALIDATOR_AUTO_RETIRED)"
[ "$miss2" = "2" ] || die "node$VICTIM's consecutive_missed_epochs at AUTO_RETIRE is $miss2, expected 2 (DNAC_AUTO_RETIRE_EPOCHS)"
echo "[ok] boundary $e2 (height $h2): node$VICTIM AUTO_RETIRED (status=3), consecutive_missed_epochs=2"

# ── Third epoch: cometbft's OWN validator set catches up (§A, one
# epoch behind the DB flip — see this script's own header). ─────────
h3=$(stagef_cmt_wait_height "$ref_db" "$e3" 12) \
    || die "tip did not reach the third boundary $e3 with node$VICTIM stopped (stuck at $h3)"
log="$(stagef_node_dir "$REF")/nodus.log"
[ -f "$log" ] || die "no nodus.log for node$REF"
if ! grep -q "boundary height $e3 .*n_removed=1" "$log"; then
    echo "[FAIL] node$REF's log has no 'boundary height $e3 ... n_removed=1' CMT-APP line" >&2
    grep "boundary height $e3" "$log" >&2 || true
    exit 1
fi
echo "[ok] boundary $e3 (height $h3): the CMT-APP ValidatorUpdates line reports n_removed=1"

# ── The victim signed nothing in the ENTIRE window; others kept going ─
last_signed_now=$(sqlite3 "$ref_db" \
    "SELECT COALESCE(last_signed_height,-1) FROM v2_attendance WHERE lower(hex(voter_id))='$voter_id';" \
    2>/dev/null || echo -1)
[ "$last_signed_now" = "$last_signed_frozen" ] || die \
  "node$VICTIM's v2_attendance last_signed_height MOVED while it was STOPPED ($last_signed_frozen -> $last_signed_now)"
others=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM v2_attendance WHERE lower(hex(voter_id)) <> '$voter_id' AND last_signed_height > $aligned_h;")
[ "${others:-0}" -ge 1 ] || die "no OTHER validator's attendance moved past $aligned_h"
echo "[ok] node$VICTIM signed nothing across the whole window; $others other validator(s) kept signing"

# ── Settle: 7 further heights with node 7 absent from every commit,
# then resume and re-converge. ───────────────────────────────────────
settled=$(stagef_cmt_wait_height "$ref_db" "$settle_to" 6) \
    || die "tip did not reach the settle height $settle_to (stuck at $settled)"
echo "[ok] tip advanced to $settled with node$VICTIM still stopped (needed >= $settle_to)"

kill -CONT "$VPID"
resumed="$VPID"
VPID=""     # disarms the EXIT trap; already resumed
echo "[ok] node$VICTIM (pid $resumed) RESUMED"

fleet_tip=$(stagef_cmt_tip "$ref_db")
vt=$(stagef_cmt_wait_height "$(stagef_node_chain_db "$VICTIM")" "$fleet_tip" 4) \
    || die "node$VICTIM did not catch up after resuming (stuck at $vt, fleet was $fleet_tip)"
echo "[ok] node$VICTIM caught up (tip $vt)"

for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
    stagef_cmt_wait_height "$(stagef_node_chain_db "$n")" "$vt" 2 >/dev/null \
        || die "node$n never reached height $vt (mesh replication stalled)"
done
stagef_sentinel ASSERT_RUN   # the terminal assertion is next
stagef_cmt_diff_at_floor "post-cmt-rule-n-retire" || exit 2

stagef_sentinel PASS
echo ""
echo "[PASS] node$VICTIM missed two consecutive epochs while stopped, was"
echo "       AUTO_RETIRED at boundary $e2, cometbft's own set caught up at"
echo "       boundary $e3, and the fleet re-converged after resuming"
echo "       (tip $head0 -> $vt)."
