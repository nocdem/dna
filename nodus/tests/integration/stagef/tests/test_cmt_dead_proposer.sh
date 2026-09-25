#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_dead_proposer.sh — one validator stops, the chain keeps going
# ════════════════════════════════════════════════════════════════════
#
# R3 W3 (C2d) — REPLACES test_v2_view_change.sh, NOT A RENAME IN PLACE.
#   That scenario derived a specific "epoch leader" positionally out of
#   `validator_set_snapshots` (`stagef_leader_entry`, a stagef_env.sh helper
#   deleted with the legacy lane in R3 W4),
#   read `pbft_state.current_view` and grepped for "view change quorum" /
#   "P3 committed tip frozen" — all legacy PBFT machinery. NONE of it
#   exists on this lane: a version-3 chain never reaches the legacy tick
#   body at all (nodus_witness.c:2545-2549, `if (witness->v2_successor) {
#   ...; return; }` short-circuits straight past `pbft_state`), and
#   cometbft's proposer is a WEIGHTED ROUND-ROBIN over accumulated
#   priority carried inside the `cmt_state` protobuf blob — not a SQL
#   column this harness can read positionally the way the legacy
#   snapshot blob could be sliced. There is also no derivation NEEDED:
#   demand is not required to observe a rotation (CreateEmptyBlocks means
#   idle production continues on its own), so this scenario needs neither
#   a leaf, nor a leader index, nor a view counter.
#
# WHAT IT PROVES
#   That a version-3 fleet whose CommitteeSize-many-height window
#   necessarily includes at least one height the stopped validator was
#   due to propose still commits, without that validator, and that the
#   stopped validator resumes proposing once resumed. The property that
#   would be false if it failed: *a cometbft chain survives a proposer
#   that stops responding at its own turn — round timeout and reproposal
#   at the next priority in line, exactly as the reference does it.*
#
# WHY THE VICTIM IS FIXED, NOT DERIVED, AND WHY A HEIGHT-DELTA BOUND
# STANDS IN FOR A LEADER DERIVATION (grounded inference, not measured
# this session — see the report's QUESTIONS)
#   cometbft's proposer selection (accumulated priority += voting power
#   each height; the max is chosen and has the total subtracted) is a
#   textbook weighted round-robin that, under EQUAL voting power — which
#   this build's genesis gives every one of the 7 validators (identical
#   self_stake, stagef_up_v2.sh's SELF_STAKE constant) — degenerates to
#   exact round-robin: across any CommitteeSize (7) consecutive heights,
#   each validator is due to propose exactly once. So stopping ANY ONE
#   validator and observing the height advance by >= 7 while it is down
#   is a PIGEONHOLE guarantee that at least one of those heights hit the
#   stopped validator's turn, timed out at round 0, and rotated to the
#   next validator in priority order — without this harness needing to
#   compute which height that was. This is read from the ported
#   selection code's STRUCTURE (shared/dnac/cmt_validator_set.c
#   :849-977, accumulate-then-subtract-total), not measured empirically
#   in this session; flagged as a QUESTION for the ORCHESTRATOR to
#   confirm or route to a red-teamer before this scenario is trusted at
#   face value.
#
# WHAT IT REQUIRES
#   Compile flags: NONE. A default nodus/build binary.
#   Environment: none of its own. No leaf, no fault-injection build.
#   ⚠ A cluster from **stagef_up_v2.sh**. On a legacy cluster it exits 99.
#   ⏱ Needs AT LEAST 7 CreateEmptyBlocksInterval-lengths of wall time
#   with the victim down (>= 420 s at the default 60 000 ms interval) —
#   this is the pigeonhole window, not padding, and it can take
#   noticeably longer than that if round-0 timeouts against the down
#   validator repeatedly cost extra time before rotating.
#
# WHAT IT LEAVES BEHIND
#   One committee node (node 2, FIXED) SIGSTOPped and then SIGCONTed. An
#   EXIT trap resumes it on any early exit, or a failed run would leave
#   the fleet a validator short for everything after it. No leaf is
#   spent; no leader-derivation state to leave behind, because there is
#   none on this lane.
#
# HOW IT CAN LIE
#   - **"Height advanced" alone would be exactly the liveness test that
#     cannot observe the thing it is named for** — CreateEmptyBlocks
#     means the chain could in principle keep committing on time-driven
#     production alone even if something were subtly wrong about how a
#     dead validator's turn is actually handled. The load-bearing
#     assertion is therefore NOT the height delta by itself: it is that
#     the VICTIM'S OWN attendance row did NOT move while stopped (it
#     could not SIGN anything, being frozen — a fact this harness reads
#     directly from `v2_attendance`, not inferred from silence) AND that
#     OTHER validators' attendance DID move past the point of the stop
#     (a quorum kept signing without it). Both together are what "rotated
#     past it and kept going" means; either alone is weaker.
#   - **tokenomics-v3 P1 (D-2, D-4) changed WHAT is read, not WHAT is
#     proved.** Before this package attendance credited the committed
#     header PROPOSER into `validators.last_signed_block` (a merkle-leaf
#     field); this package relocated it out-of-root into `v2_attendance`,
#     credited on every COMMIT-flagged vote of `decided_last_commit` —
#     i.e. on every validator that SIGNED, not on whoever proposed. A
#     SIGSTOPped process can do neither (it cannot propose AND it cannot
#     sign a precommit), so the property this scenario pins — "the
#     stopped validator's attendance is frozen; everyone else's is not"
#     — still holds under the new source, and is if anything a MORE
#     direct reading of "did this validator do anything while stopped":
#     signing is the mechanism cometbft itself requires for liveness,
#     where proposing was only this chain's OWN credit rule.
#   - **DELTA 1 (verifier UNCOVERED FINDING 6, fixed).** The baseline
#     reads (`last_signed_before`, `tip_before`) are taken AFTER
#     `kill -STOP` lands, never before — reading them first left a
#     window in which the chain could commit between the read and the
#     signal, racing in BOTH directions: a block the victim proposed in
#     that window would misread as "moved while stopped" (false RED);
#     an OTHER validator's block in that window would shrink the observed
#     window to 6 of the 7-cycle, missing the victim's turn with
#     probability 1/7 and passing without the timeout ever firing (false
#     GREEN).
#   - **The one-block credit lag (tokenomics-v3 P1 landing, measured).**
#     Block H credits the precommits FOR H-1, so a precommit the victim
#     sent just before the stop lands in the row one block AFTER the stop.
#     The frozen baseline is therefore read 3 heights past the stop (see
#     the SETTLE block), never immediately after it; the first production
#     sweep at 0.19.67 failed on exactly that race (10 -> 11).
#   - **No log line proves a round advanced past 0.** Read for this
#     package: `cmt_cs.c` carries ZERO `QGP_LOG_INFO` calls —
#     `cmt_cs_enter_new_round` (:1772) and every neighbouring transition
#     function log ONLY on a FAULT path. There is no positive "entered
#     round N" or "proposer timed out" line to grep on this build. The
#     pigeonhole argument above is what stands in for that log line;
#     this is disclosed rather than papered over with a log line that
#     does not exist.
#   - **A validator that never held a genesis SELF_STAKE tie would break
#     the equal-power assumption.** stagef_up_v2.sh's genesis gives
#     every one of the 7 an identical SELF_STAKE (D-4's own bond amount);
#     if a later stage of the sweep changed one validator's stake before
#     this scenario ran, the round-robin degeneracy the pigeonhole
#     argument depends on would no longer hold exactly. Not the case in
#     this scenario's position in genesis_protocol_v2.sh's explicit
#     order (test_v2_stake.sh stakes the NON-VALIDATOR user, never a
#     node), but a scenario run standalone after something that changes
#     a node's stake should not trust this argument blindly.
#   - **rc=99 means the cluster was not Comet.** Coverage that did not
#     happen, never a pass.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

REF=1
VICTIM=2   # FIXED — no derivation needed or possible on this lane; see header.

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
stagef_sentinel SETUP_OK   # W4-H: the runner turns PASS-without-ASSERT_RUN into FAIL

stagef_cmt_diff_at_floor "pre-cmt-dead-proposer" || exit 2

# DELTA 1 (verifier UNCOVERED FINDING 6, CONFIRMED) — STOP FIRST, THEN
# READ THE BASELINE. Reading last_signed_before/tip_before and THEN
# stopping the victim leaves a window in which the chain keeps
# committing between the read and the signal landing — a race in BOTH
# directions: (false RED) the victim proposes a block in that window,
# last_signed_during then differs from the stale last_signed_before and
# the scenario wrongly claims it "moved while stopped"; (false GREEN) an
# OTHER validator commits tip_before+1 in that window, shrinking the
# observed window to 6 of the 7-cycle, which misses the victim's turn
# with probability 1/7 and passes without the round timeout ever firing.
# The signal is delivered FIRST, synchronously, before either DB read.
voter_id=$(stagef_voter_id "$(stagef_node_dir "$VICTIM")/identity/nodus.pk")
[ "${#voter_id}" = 64 ] || die "could not derive node$VICTIM's voter_id"
VPID=$(pgrep -f "node$VICTIM/data" | head -1 || true)
[ -n "$VPID" ] || die "node$VICTIM is not running"
kill -STOP "$VPID"
echo "[ok] node$VICTIM (pid $VPID) STOPPED (voter_id ${voter_id:0:16}...)"

last_signed_before=$(sqlite3 "$ref_db" \
    "SELECT COALESCE(last_signed_height,-1) FROM v2_attendance WHERE lower(hex(voter_id))='$voter_id';" \
    2>/dev/null || echo -1)
[ "${last_signed_before:-ERR}" != "ERR" ] || die "could not read node$VICTIM's v2_attendance row"
tip_before=$(stagef_cmt_tip "$ref_db")
echo "[ok] baseline (read AFTER the stop): node$VICTIM last_signed_height=$last_signed_before tip=$tip_before"

# ── SETTLE before freezing the baseline (tokenomics-v3 P1 landing,
# MEASURED at production constants 2026-09-23: /tmp/stagef-20260923T162434Z).
# Attendance is credited from `decided_last_commit`: block H carries the
# precommits FOR H-1 (nodus_witness_v2_attendance_credit writes
# last_signed_height = H-1). A precommit the victim SENT BEFORE the stop
# is therefore credited one block LATER — after the stop — by whichever
# proposer assembles that LastCommit. Measured: stop at tip 11, baseline
# 10, then 11 appeared with node2 frozen; node2's own WAL holds its signed
# messages and EndHeight for height 11, written before the stop. Reading
# the baseline immediately after the stop made the verdict depend on
# whether that in-flight precommit had been folded in yet — a timing race,
# forbidden by the NO FLAKY rule. The baseline is now read once the tip is
# 3 heights past the stop. Arithmetic: a validator precommits at most the
# height after the one it last committed, so if the victim had committed
# L blocks more than node1's tip_before when it stopped, its last
# precommit is for tip_before+L+1, credited by block tip_before+L+2.
# Settling at +3 covers L <= 1. L is NOT bounded by anything this script
# can read — it is an assumption (node1 lagging the victim by two whole
# committed blocks at the instant of the stop). If it is ever violated the
# failure is a visible RED below ("MOVED ... after the settle point"),
# never a false GREEN. From the settle point on the row must not move.
settle_to=$(( tip_before + 3 ))
settled_tip=$(stagef_cmt_wait_height "$ref_db" "$settle_to" 12) \
    || die "tip did not reach $settle_to with node$VICTIM stopped (stuck at $settled_tip) — the fleet may have stalled rather than rotated"
last_signed_settled=$(sqlite3 "$ref_db" \
    "SELECT COALESCE(last_signed_height,-1) FROM v2_attendance WHERE lower(hex(voter_id))='$voter_id';" \
    2>/dev/null || echo -1)
echo "[ok] settled baseline at tip $settled_tip: node$VICTIM last_signed_height=$last_signed_settled (was $last_signed_before right after the stop — the difference, if any, is precommits sent BEFORE the stop and credited one block later)"

# ── The pigeonhole window: >= 7 heights, bounded by progress ────────
target=$(( tip_before + STAGEF_COMMITTEE_SIZE ))
# Generous stall budget: a round timing out against the down validator
# costs real extra time beyond the ordinary interval, on top of however
# many heights land on OTHER validators' turns inside the window.
after=$(stagef_cmt_wait_height "$ref_db" "$target" 12) \
    || die "tip did not reach $target with node$VICTIM stopped (stuck at $after) — the fleet may have stalled rather than rotated"
echo "[ok] tip advanced to $after with node$VICTIM stopped (needed >= $target)"

# ── The victim SIGNED NOTHING while stopped ─────────────────────────
last_signed_during=$(sqlite3 "$ref_db" \
    "SELECT COALESCE(last_signed_height,-1) FROM v2_attendance WHERE lower(hex(voter_id))='$voter_id';" \
    2>/dev/null || echo -1)
[ "$last_signed_during" = "$last_signed_settled" ] || die \
  "node$VICTIM's v2_attendance last_signed_height MOVED while it was STOPPED, after the settle point ($last_signed_settled -> $last_signed_during) — a SIGSTOPped process should not have been able to sign a precommit at all"
echo "[ok] node$VICTIM signed nothing while stopped (last_signed_height frozen at $last_signed_settled from tip $settled_tip to $after)"

# ── SOMEONE ELSE kept signing ────────────────────────────────────────
others=$(sqlite3 "$ref_db" \
    "SELECT COUNT(*) FROM v2_attendance WHERE lower(hex(voter_id)) <> '$voter_id' AND last_signed_height > $tip_before;")
[ "${others:-0}" -ge 1 ] || die \
  "no OTHER validator's v2_attendance last_signed_height moved past $tip_before — the chain advanced by height but nobody's attendance row shows it"
echo "[ok] $others other validator(s) signed at least one COMMIT-flagged vote in the window"

# ── Resume, and it must catch up ────────────────────────────────────
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
stagef_cmt_diff_at_floor "post-cmt-dead-proposer" || exit 2

stagef_sentinel PASS
echo ""
echo "[PASS] node$VICTIM was stopped for >= $STAGEF_COMMITTEE_SIZE heights, signed"
echo "       nothing in that window while other validators kept committing,"
echo "       and re-converged to the SAME chain after resuming. Tip $tip_before -> $vt."
