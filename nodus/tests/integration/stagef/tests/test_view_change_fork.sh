#!/usr/bin/env bash
#
# Stage F test — C5 view-change safety against a DERIVED epoch leader.
#
# ── WHAT IT PROVES ───────────────────────────────────────────────────
#   That pausing the validator this cluster has PROVEN is its current
#   epoch leader does not fork the chain: the survivors rotate the view
#   away from it, commit new work without it, and the leader re-converges
#   to the same state_root when it comes back.
#
#   The property that would be false if this failed: "a BFT chain can
#   make progress while its designated leader is unresponsive, and the
#   leader can rejoin without divergence."
#
#   Four phases:
#     A — C5 prepared-cert capture fires on all 7 nodes after genesis
#         commit (Phase 3 regression guard).
#     B — DERIVE the leader for the epoch the next block belongs to,
#         SIGSTOP exactly that node, then require BOTH that a view-change
#         quorum completed while it was down AND that the surviving 6
#         committed a new funding TX.
#     C — resume it, verify it syncs back to the same state_root.
#     D — final assertion: all 7 nodes at identical state_root.
#
#   Full Byzantine view-change-fork triggering (leader isolated mid-
#   proposal so 3+ nodes carry conflicting prepared certs) still requires
#   network partition tooling (tc/iptables) or Byzantine injection —
#   future work. This catches regressions in the C5 capture / rotation /
#   sync / convergence paths using process-level signals only.
#
#   ⚠ WHAT IT NO LONGER DOES: pass while exercising nothing. Until
#   2026-09-02 it stopped a HARDCODED node 1 and then only checked that
#   state_root converged. The leader is `(epoch + view) % n`
#   (nodus_witness_bft_leader_index, nodus_witness_bft.c:1195-1198) over a
#   committee ordered by stake DESC and then by a state_seed-derived
#   tiebreak, over identities generated FRESH ON EVERY RUN — so whether
#   node 1 held that slot was a coin flip. When it did not, the chain
#   never lost its proposer, no view change was required, and the run
#   printed `view-change activity on 0 nodes` immediately before `[PASS]`.
#   The script even said so out loud ("proceeding anyway — the original
#   leader may still be node 1's slot"), which read as tolerance but was
#   the scenario conceding it did not control its own subject. The victim
#   is now DERIVED, by the SAME code test_vset_grow_shrink.sh section G
#   uses (stagef_leader_entry in stagef_env.sh).
#
# ── WHAT IT REQUIRES ─────────────────────────────────────────────────
#   Compile flags (the binary): NONE of its own. A default `nodus/build`
#     binary is enough. No fault-injection build; -DQGP_FAULT_INJECT is
#     NOT required, and no NODUS_FAULT_* variable is read.
#   Environment (the scripts): STAGEF_EPOCH_LENGTH must MATCH the binary's
#     DNAC_EPOCH_LENGTH, and must be exported BEFORE stagef_up.sh. At the
#     defaults (both 720) that is automatic and this scenario stays
#     "plain". On a short-epoch campaign the -D and the env var must agree
#     — the leader rank is derived from the epoch ordinal, so a mismatch
#     derives the WRONG validator. That mismatch cannot produce a false
#     green: pausing an innocent follower leaves the real leader alive,
#     the chain keeps producing, no view change forms, and Phase B FAILS
#     with the epoch, the view and the victim printed.
#   State: an active harness (stagef_up.sh) with a committed genesis and
#     a validator-set snapshot for the epoch the head sits in. Genesis
#     seeds epochs 0 and E; every boundary since has committed its own.
#
# ── WHAT IT LEAVES BEHIND ────────────────────────────────────────────
#   One committee node SIGSTOPped and then SIGCONTed — a DIFFERENT one on
#   every run, because it is derived, so it is printed. It keeps its
#   original pid (no restart, unlike section G's kill -9). An EXIT trap
#   resumes it on every early exit, so a failure does not leave the
#   cluster with a frozen node.
#   The cluster is left at a HIGHER current_view than it started at
#   (current_view never resets and is persisted per chain DB), and with
#   one extra funded test user under $BASE_DIR/tusers/. Every scenario
#   that sorts after this one inherits both — in particular
#   test_vset_grow_shrink.sh, whose section G is written for exactly that
#   (it counts view-change log lines as BEFORE/AFTER deltas, never as
#   presence).
#
# ── HOW IT CAN LIE ───────────────────────────────────────────────────
#   1. THE IDLE WINDOW PROVES NOTHING, AND IT IS NOT ASSERTED.
#      The 90 s wait between the SIGSTOP and the funding send cannot
#      observe a rotation, and that is a property of the chain, not of the
#      wait. The P3 demand-armed deadman only arms when there is pending
#      work — `if (w->mempool.count > 0 || w->pending_forward_count > 0)`,
#      nodus_witness_bft.c:11986 — and the branch immediately below it
#      says so in the node's own words: "an IDLE node arms no timeout, so
#      it can never initiate a view change" (:12084-12089).
#      ⚠ The matching log line, "IDLE — no timeout armed, no view change
#      possible" (:12111), sits inside `#ifdef O15H_DIAG_ENABLED` (:12099)
#      and does NOT print in a default build — do not go hunting for it in
#      nodus.log. The GATE at :11986 is ordinary unconditional code and is
#      what actually decides. Block production is TX-driven, so with an empty
#      mempool a dead leader produces NO round, NO timeout and NO
#      VIEW_CHANGE, for as long as you care to wait. A measurement of
#      "0 of 6 nodes reached view-change quorum in 90 s" taken in THIS
#      window is the predicted behaviour and is not evidence of a defect.
#      The window is therefore kept, and REPORTED, but the assertion is
#      taken after the first demand arrives.
#      ⚠ DO NOT "FIX" THIS BY RAISING THE 90 s. A bigger idle window is
#      still an idle window. And do NOT add a transaction pump here to
#      make the window productive — that changes what the scenario tests
#      and is a decision for whoever owns the scenario, not for whoever is
#      making it green.
#   2. STALE LOG LINES. Every line this scenario looks for already exists
#      when it starts: test_med28_reproposal.sh and
#      test_newview_convergence.sh both force view changes and both sort
#      BEFORE this file alphabetically, which is the order
#      genesis_protocol.sh uses. `grep -q "view change quorum"` is
#      therefore VACUOUSLY TRUE in a full sweep — it was, in the version
#      this replaced. Every count here is a BEFORE/AFTER delta and only an
#      INCREASE is evidence. Simplify any of them back to a presence test
#      and the scenario silently stops testing.
#   3. A PASS MEANS THE REAL LEADER WAS PAUSED — not merely that node 1
#      was. The whole value of this scenario now rests on the derivation:
#      the snapshot row for the epoch is read POSITIONALLY at rank
#      (epoch + view) % active_count, and the entry's voter_id is
#      cross-checked against the node's own fingerprint prefix before
#      anything is signalled. If that cross-check is ever removed, a
#      wrong-bytes read would send SIGSTOP to an innocent node and the
#      scenario would be back to proving nothing.
#   4. VIEW OR EPOCH DRIFT REDIRECTS LEADERSHIP — residual, diagnosable.
#      The rank is only as good as the (epoch, view) pair it was computed
#      from. The window BEFORE the pause is CLOSED: the head and the view
#      are re-read and the whole derivation re-run, twice, and a survivor
#      already holding a higher view than the node the derivation read is
#      a FAILURE. The window AFTER cannot drift on an idle chain — no
#      blocks means no epoch change — but once the funding TX arrives, a
#      round timeout can rotate the view and hand leadership to a
#      DIFFERENT node. The scenario then fails on a healthy chain. That
#      residual is NOT closed here; it is made visible instead, by
#      printing the pre-pause and post-pause views and heights in every
#      failure message.
#   5. A DEAD REFERENCE NODE. Every single-node read goes through
#      $REF_NODE, which is re-pointed OFF the victim before the pause.
#      Reintroduce a raw node1 read and it can read a frozen replica and
#      report a stall on a chain that is advancing fine — or worse,
#      compare the victim's height against itself.
#   6. rc=99 IS BANNED HERE. genesis_protocol.sh treats 99 as SKIP and
#      exits 0 with SKIPs allowed, and a SKIP needs no ASSERT_RUN
#      sentinel. Encoding "no snapshot row" or "the view moved twice" as a
#      skip would make this coverage silently absent under a green suite.
#      A skip is not a pass; every precondition here FAILS.
#   7. A KNOWN FALSE-*FAIL* RESIDUAL — SIGSTOP IS NOT kill -9, AND THE
#      CLIENT NOTICES. It cannot produce a green, only a misattributed
#      red. The pump/fund goes through dna-connect-cli, and
#      nodus_client_connect tries the bootstrap list IN CONFIG ORDER
#      (nodus_client.c:663-679), which stagef_up.sh writes as node1 first.
#      A SIGSTOPped process still holds its listening socket, so the
#      kernel COMPLETES the TCP handshake into the backlog and the connect
#      SUCCEEDS — then the HELLO times out after connect_timeout_ms
#      (default 5000, nodus_client.c:621-622, :768). Section G does not
#      have this: kill -9 closes the socket, so its connect is refused at
#      once and the client moves on. So when the derived victim IS node1,
#      the funding TX can be delayed or lost on the client side and the
#      cluster never sees demand at all.
#      This is NOT hypothetical-only, and it is also NOT new: the version
#      this replaced paused node1 on EVERY run and its funding step was
#      observed to succeed, so the client does recover in practice. The
#      residual is kept visible rather than assumed away — Phase B's
#      failure branch splits on the P3 delta precisely to tell "the
#      cluster never saw demand" (suspect this) from "the cluster saw
#      demand and did not rotate" (the consensus finding).
#   8. KNOWN GAPS, recorded rather than hidden:
#      - this scenario records NO reachability sentinels, so the runner
#        classifies it UNINSTRUMENTED and cannot convert a vacuous PASS
#        into a failure for it. Every path to the final [PASS] below now
#        runs through the Phase B truth table, so a PASS that skipped its
#        assertion is not reachable — but the runner does not know that;
#      - Phase C waits with a blind `sleep 30` for the resumed node to
#        catch up, instead of waiting on the condition. It is a timing
#        guess, and it is the pre-existing behaviour;
#      - Phase D's convergence check (stagef_diff.sh) compares each node's
#        LATEST block, so a node one block behind reads as divergence
#        rather than lag.
#
# ── EXIT CODES ───────────────────────────────────────────────────────
#   0 PASS · 1 no harness · 2 Phase A capture missing ·
#   3 victim pid not found · 4 the dead-leader assertion FAILED ·
#   5 the leader could not be derived (precondition fault)

set -euo pipefail

. "$(dirname "$0")/../stagef_env.sh"

if [ -z "${BASE_DIR:-}" ] || [ ! -d "$BASE_DIR" ]; then
    echo "[FAIL] no active Stage F harness. Run stagef_up.sh first." >&2
    exit 1
fi

# The epoch length the BINARY was built with. It is only a script-side
# mirror of DNAC_EPOCH_LENGTH; see WHAT IT REQUIRES above for what a
# mismatch costs and why it cannot produce a false green.
#
# Validated before anything divides by it: an empty or zero value would
# otherwise abort mid-derivation with a bare "division by 0" from bash and
# no indication of which knob was wrong.
E_LEN="$STAGEF_EPOCH_LENGTH"
case "$E_LEN" in ''|*[!0-9]*)
    echo "[FAIL] STAGEF_EPOCH_LENGTH='$E_LEN' is not a number — the epoch \
leader cannot be derived" >&2
    exit 5;;
esac
if [ "$E_LEN" -lt 1 ]; then
    echo "[FAIL] STAGEF_EPOCH_LENGTH=$E_LEN — the epoch leader cannot be \
derived from a zero-length epoch" >&2
    exit 5
fi

# THE REFERENCE NODE — the node every single-node read goes through.
#
# It is 1 for the whole derivation, during which nothing is paused, and
# Phase B re-points it to a node it has proven is NOT the victim before
# sending the first signal. See lie-path 5.
REF_NODE=1

# The committed head, through $REF_NODE. A failed query is NOT a height:
# it returns 1 and prints nothing, so no caller can read an error as 0 and
# then derive a rank from it.
chain_head() {
    local db out
    db=$(ref_db)
    [ -n "$db" ] || return 1
    out=$(sqlite3 "$db" "SELECT COALESCE(MAX(height),0) FROM blocks;" \
        2>/dev/null) || return 1
    [ -n "$out" ] || return 1
    echo "$out"
}

# ── Phase A — C5 prepared-cert capture on all nodes ─────────────────
# Genesis BFT round fires shortly after stagef_up returns. On slow
# machines or when peer-mesh establishment lags into the warn-window
# ("[warn] not all nodes reached full roster within 30 s"), a node
# may still be wiring up its committee at the moment we sample the
# log. Poll for up to 30 s with 1 s granularity instead of one-shot —
# if all 7 captures never arrive within that window the node really
# did miss the round.
echo "== Phase A — C5 prepared-cert capture post-genesis =="
deadline=$(( SECONDS + 60 ))
captured=0
while [ $SECONDS -lt $deadline ]; do
    captured=0
    for n in $(seq 1 "$STAGEF_COMMITTEE_SIZE"); do
        log="$BASE_DIR/node$n/nodus.log"
        if [ -f "$log" ] && grep -q "C5 prepared cert captured" "$log"; then
            captured=$((captured + 1))
        fi
    done
    [ "$captured" -ge "$STAGEF_COMMITTEE_SIZE" ] && break
    sleep 1
done
if [ "$captured" -lt "$STAGEF_COMMITTEE_SIZE" ]; then
    echo "[FAIL] only $captured of $STAGEF_COMMITTEE_SIZE nodes logged C5 prepared-cert capture (after 60s wait)" >&2
    exit 2
fi
echo "[info] all $captured nodes logged C5 prepared-cert capture"

bash "$(dirname "$0")/../stagef_diff.sh" "baseline"

# ── Phase B — derive the epoch leader, pause it, require a rotation ──
echo ""
echo "== Phase B — pause the DERIVED epoch leader =="

# ── B.1 derive the victim ────────────────────────────────────────────
#
# The leader for the NEXT block, which is the one the survivors will have
# to produce. nodus_witness_bft_is_leader computes its epoch from
# `next_bh = tip + 1` (nodus_witness_bft.c:1229) and then
# `epoch = next_bh / DNAC_EPOCH_LENGTH` (:1284) — so the epoch of the
# committed head is the WRONG one whenever the head sits on a boundary.
#
# The whole derivation is re-run if the head's epoch or the view moved
# between reading them and pausing the node: either would silently hand
# leadership to somebody else and make the signal land on an innocent
# follower.
derive_view=""
victim=""
EPOCH_START=""
H_DERIVE=""
DERIVED_OK=0
# The node the (head, view) pair is READ from. It is $REF_NODE while the
# derivation runs — nothing is paused yet — but $REF_NODE is re-pointed
# off the victim on success, so it is captured separately to keep the
# failure messages below able to name it.
DERIVE_NODE="$REF_NODE"
for attempt in 1 2; do
    DERIVE_NODE="$REF_NODE"
    H_DERIVE=$(chain_head) || H_DERIVE=""
    case "$H_DERIVE" in ''|*[!0-9]*)
        echo "[FAIL] cannot read the committed head from node$REF_NODE — the \
leader rank is derived from the epoch of head+1 and is underivable without it" >&2
        exit 5;;
    esac
    EPOCH_ORD=$(( (H_DERIVE + 1) / E_LEN ))
    EPOCH_START=$(( EPOCH_ORD * E_LEN ))

    # The set for this epoch was frozen at the previous boundary
    # (nodus_witness_vset_commit_next) or seeded by genesis, so it is
    # already committed and this scenario must NOT produce it. A bounded
    # re-read covers a read racing the writer on one node; an absent row
    # after that is a real fault and FAILS — guessing a leader would make
    # the whole phase meaningless.
    snap_have=0
    for _ in $(seq 1 10); do
        snap_have=$(sqlite3 "$(ref_db)" "SELECT COUNT(*) FROM \
            validator_set_snapshots WHERE epoch_start = $EPOCH_START;" \
            2>/dev/null) || snap_have=0
        if [ "${snap_have:-0}" = "1" ]; then break; fi
        sleep 2
    done
    if [ "${snap_have:-0}" != "1" ]; then
        echo "[FAIL] no committed validator-set snapshot for epoch \
$EPOCH_START (head=$H_DERIVE, E_LEN=$E_LEN) — the leader for the next block \
cannot be derived. If E_LEN does not match the binary's DNAC_EPOCH_LENGTH, \
that is the first thing to check." >&2
        exit 5
    fi

    derive_view=$(node_view "$REF_NODE") || {
        echo "[FAIL] cannot read current_view from node$REF_NODE's pbft_state \
— the leader rank is (epoch + view) % n and is underivable without it" >&2
        exit 5
    }

    # stagef_leader_entry prints its own precise [FAIL] for every fault it
    # can see (missing/garbled active_count, a blob whose length disagrees
    # with it, a slice of the wrong width), so this adds no message of its
    # own — a second line would only bury the diagnosis.
    LEADER_LINE=$(stagef_leader_entry "$(ref_db)" "$EPOCH_START" "$E_LEN" \
        "$derive_view") || exit 5
    read -r LEADER_IDX ACTIVE_COUNT LEADER_PK LEADER_WID <<< "$LEADER_LINE"

    # Which of our nodes is that? Matched on the RAW PUBKEY, the same
    # byte string node_pubkey_hex reads out of the node's own identity.
    victim=""
    for n in $(running_nodes); do
        if [ "$(node_pubkey_hex "$n")" = "$LEADER_PK" ]; then
            victim="$n"; break
        fi
    done
    if [ -z "$victim" ]; then
        echo "[FAIL] the epoch-$EPOCH_START leader (rank $LEADER_IDX of \
$ACTIVE_COUNT, view $derive_view) is not any of this harness's nodes — the \
snapshot names a validator this scenario did not create" >&2
        exit 5
    fi

    # The reference node for everything after the pause: alive, and not
    # the victim. Lowest running index that is not the victim, so it is
    # deterministic rather than whichever one the shell listed first.
    NEXT_REF=""
    for n in $(running_nodes); do
        if [ "$n" != "$victim" ]; then NEXT_REF="$n"; break; fi
    done
    if [ -z "$NEXT_REF" ]; then
        echo "[FAIL] no running node other than the victim" >&2
        exit 5
    fi

    # RE-READ IMMEDIATELY BEFORE COMMITTING TO THE VICTIM. A view rotation
    # or an epoch crossing in the window between deriving and signalling
    # hands leadership to somebody else.
    view_now=$(node_view "$REF_NODE") || {
        echo "[FAIL] cannot re-read current_view before the pause" >&2
        exit 5
    }
    h_now=$(chain_head) || h_now=""
    case "$h_now" in ''|*[!0-9]*)
        echo "[FAIL] cannot re-read the committed head before the pause" >&2
        exit 5;;
    esac
    if [ "$view_now" = "$derive_view" ] && \
       [ $(( (h_now + 1) / E_LEN )) -eq "$EPOCH_ORD" ]; then
        REF_NODE="$NEXT_REF"
        DERIVED_OK=1
        break
    fi
    echo "[info] the chain moved during derivation (attempt $attempt, read \
from node$DERIVE_NODE): view $derive_view -> $view_now, head $H_DERIVE -> \
$h_now — re-deriving the leader"
done
if [ "$DERIVED_OK" -ne 1 ]; then
    echo "[FAIL] the (epoch, view) pair moved on both derivation attempts, \
read from node$DERIVE_NODE (view $derive_view -> ${view_now:-?}, head \
$H_DERIVE -> ${h_now:-?}) — the epoch leader cannot be pinned down long \
enough to pause it. This is a FAILURE, never a skip: a skipped scenario is \
coverage that did not happen." >&2
    exit 5
fi

echo "[info] epoch $EPOCH_START leader = rank $LEADER_IDX of $ACTIVE_COUNT at \
view $derive_view -> node$victim (witness id ${LEADER_WID:0:16}…)"
echo "[info] head=$H_DERIVE, E_LEN=$E_LEN, next block $(( H_DERIVE + 1 )) is \
in epoch ordinal $EPOCH_ORD"
echo "[info] reference node for every single-node read is now node$REF_NODE"

# Cross-check the two independent derivations of the same 32 bytes: the
# snapshot's voter_id field (sliced positionally out of the blob) and the
# first half of the node's own fingerprint file. Both are
# SHA3-512(pubkey)[0..31] — nodus_chain_config_derive_witness_id vs
# nodus_fingerprint — and it is also exactly what the node writes into
# blocks.proposer_id. If these disagree, the byte offsets are wrong and
# every conclusion drawn from them is worthless. See lie-path 3.
# The `|| VICTIM_FP_WID=""` matters under `set -euo pipefail`: an
# unreadable fingerprint file would otherwise kill the script with a bare
# redirection error instead of reaching the cross-check that explains it.
VICTIM_FP_WID=$(cut -c1-$(( VSET_VOTER_ID_LEN * 2 )) \
    < "$BASE_DIR/node$victim/identity/nodus.fp" \
    | tr '[:lower:]' '[:upper:]') || VICTIM_FP_WID=""
if [ "$VICTIM_FP_WID" != "$LEADER_WID" ]; then
    echo "[FAIL] snapshot entry $LEADER_IDX voter_id ($LEADER_WID) does not \
match node$victim's own fingerprint prefix ($VICTIM_FP_WID) — the positional \
read of the snapshot blob is addressing the wrong bytes" >&2
    exit 5
fi

# ── B.2 baselines, then pause the leader ─────────────────────────────
#
# Counted BEFORE the pause because all of these lines already exist in a
# full run: test_med28_reproposal.sh and test_newview_convergence.sh force
# view changes and both sort earlier. Only a DELTA is evidence — lie-path 2.
VCQ_BEFORE=$(log_count "view change quorum! new view:")
VCI_BEFORE=$(log_count "initiated view change to view")
P3_BEFORE=$(log_count "P3 committed tip frozen")
VIEW_BEFORE=$(cluster_view_max "$victim") || {
    echo "[FAIL] cannot read current_view from any surviving node" >&2
    exit 5
}

# THE DERIVATION NODE MUST NOT DISAGREE WITH THE CLUSTER. The loop above
# pinned the view on node$DERIVE_NODE; this baseline reads the MAX across
# every node EXCEPT the victim. A survivor holding a HIGHER view means a
# rotation has completed that node$DERIVE_NODE has not adopted, so the rank
# is stale and the pause would land on a follower. EQUALITY is required
# rather than "not higher", because a disagreement in either direction
# means the view the rank was computed from is not the one the cluster is
# operating at. Closable before the signal, therefore closed — the same
# class as "the view moved twice": a FAILURE, never a skip.
if [ "$VIEW_BEFORE" -ne "$derive_view" ]; then
    echo "[FAIL] the leader was derived from node$DERIVE_NODE at view \
$derive_view but the surviving nodes' max view is $VIEW_BEFORE — the two \
disagree, so rank $LEADER_IDX no longer identifies the epoch-$EPOCH_START \
leader and pausing node$victim would prove nothing" >&2
    exit 5
fi

TARGET_NODE="$victim"
TARGET_PID=$(pgrep -f "$BASE_DIR/node${TARGET_NODE}/" | head -1 || true)
if [ -z "$TARGET_PID" ]; then
    echo "[FAIL] could not find pid for node$TARGET_NODE" >&2
    exit 3
fi
echo "[info] stopping the epoch-$EPOCH_START leader node$TARGET_NODE \
(pid=$TARGET_PID, view=$VIEW_BEFORE, VC quorums so far=$VCQ_BEFORE)"

# Set trap to resume the node even on early exit (so we don't leave
# the harness in a stopped state for the next test).
kill -STOP "$TARGET_PID"
trap "kill -CONT $TARGET_PID 2>/dev/null || true" EXIT

# ── B.3 the idle observation window — NOT an assertion ───────────────
#
# READ LIE-PATH 1 BEFORE TOUCHING THIS. With the leader paused and the
# mempool empty, no round opens, nothing times out, and the P3 deadman
# does not even arm (nodus_witness_bft.c:11986 gates the whole window on
# `mempool.count > 0 || pending_forward_count > 0`). So a silent 90 s here
# is the chain behaving exactly as designed, and it is REPORTED rather
# than asserted. The 90 s is kept because it is the settle window the
# scenario has always had; raising it would buy nothing, and lowering it
# would prove nothing either.
echo "[info] idle observation window (90s): with an empty mempool a paused"
echo "[info] leader arms no deadman, so silence here is EXPECTED and is not"
echo "[info] evidence of a defect — see this file's lie-path 1"
deadline=$(( SECONDS + 90 ))
vcq_idle="$VCQ_BEFORE"
while [ $SECONDS -lt $deadline ]; do
    vcq_idle=$(log_count "view change quorum! new view:")
    if [ "$vcq_idle" -gt "$VCQ_BEFORE" ]; then break; fi
    sleep 2
done
if [ "$vcq_idle" -gt "$VCQ_BEFORE" ]; then
    echo "[info] a view-change quorum completed during the IDLE window \
($VCQ_BEFORE -> $vcq_idle) — some demand was already pending when the leader \
was paused"
else
    echo "[info] no view-change quorum during the idle window (still \
$VCQ_BEFORE) — as predicted; the assertion is taken after demand arrives"
fi

# ── B.4 the first demand, and the assertion ──────────────────────────
#
# Creating a funded user is what puts a transaction into the cluster, and
# therefore what arms the deadman on the followers. The CLI's own exit
# code is not the truth — stagef_mk_funded_user confirms the spendable
# UTXO on chain in both directions — but its result IS one half of the
# truth table below, so it is captured instead of exiting on the spot.
echo "[info] submitting the first demand (funding a test user) with the epoch"
echo "[info] leader node$TARGET_NODE paused — this is what can arm P3"
FUND_OK=0
TEST_HOME=""
if TEST_HOME=$(stagef_mk_funded_user "vcfork" 120000000000000); then
    FUND_OK=1
fi

# Captured while the victim is STILL paused, so they can only describe the
# window in which the leader was actually down.
VIEW_AFTER=$(cluster_view_max "$victim") || {
    echo "[FAIL] cannot read current_view from any surviving node after the \
funding attempt" >&2
    exit 4
}
VCQ_AFTER=$(log_count "view change quorum! new view:")
VCI_AFTER=$(log_count "initiated view change to view")
P3_AFTER=$(log_count "P3 committed tip frozen")
H_AFTER=$(chain_head) || H_AFTER="?"

echo "[info] with node$TARGET_NODE paused: view $VIEW_BEFORE -> $VIEW_AFTER, \
head $H_DERIVE -> $H_AFTER, P3 fires +$(( P3_AFTER - P3_BEFORE )), \
initiations +$(( VCI_AFTER - VCI_BEFORE )), quorums \
+$(( VCQ_AFTER - VCQ_BEFORE )), fund committed=$FUND_OK"

# THE TRUTH TABLE. Four outcomes, and only one of them is a pass. The
# rotation and the commit are asserted SEPARATELY because they fail for
# different reasons and the diagnosis differs.
ROTATED=0
if [ "$VCQ_AFTER" -gt "$VCQ_BEFORE" ]; then ROTATED=1; fi

if [ "$ROTATED" -eq 1 ] && [ "$FUND_OK" -eq 1 ]; then
    echo "[ok] the cluster rotated the view past its paused leader \
node$TARGET_NODE ($VIEW_BEFORE -> $VIEW_AFTER) and committed new work \
without it"
elif [ "$ROTATED" -eq 0 ] && [ "$FUND_OK" -eq 0 ]; then
    # TWO VERY DIFFERENT CAUSES, AND THE P3 DELTA SEPARATES THEM.
    #
    # Nothing rotates until some follower SEES pending demand, so "no
    # rotation" means either the demand never arrived or it arrived and
    # the cluster failed to act on it. Reporting both as one failure is
    # how a harness artefact gets filed as a consensus defect.
    if [ "$P3_AFTER" -eq "$P3_BEFORE" ]; then
        echo "[FAIL] the epoch-$EPOCH_START leader node$TARGET_NODE (rank \
$LEADER_IDX of $ACTIVE_COUNT at view $derive_view) was paused, and NO \
follower ever observed pending demand (P3 'committed tip frozen' fires did \
not increase: $P3_BEFORE -> $P3_AFTER). The transaction most likely never \
reached a live node's mempool, so the deadman could not arm and no rotation \
was possible — that is a DELIVERY failure, not the consensus halt this \
scenario looks for. ⚠ SUSPECT THE CLIENT FIRST: nodus_client_connect tries \
the bootstrap list IN ORDER (nodus_client.c:663-679) and node1 is first, \
and a SIGSTOPped node still has an open listening socket, so the TCP \
connect SUCCEEDS and the HELLO then times out — unlike section G's \
kill -9, which is refused immediately. Read \
\$BASE_DIR/tusers/vcfork_*/fund.log for which node it talked to. Views \
$VIEW_BEFORE -> $VIEW_AFTER, head $H_DERIVE -> $H_AFTER." >&2
    else
        echo "[FAIL] the epoch-$EPOCH_START leader node$TARGET_NODE (rank \
$LEADER_IDX of $ACTIVE_COUNT at view $derive_view) was paused, followers DID \
observe pending demand and fired the P3 deadman (+$(( P3_AFTER - P3_BEFORE )) \
across the node logs, initiations +$(( VCI_AFTER - VCI_BEFORE ))), but the \
surviving $(( STAGEF_COMMITTEE_SIZE - 1 )) nodes never completed a \
view-change QUORUM, so no transaction could commit. THIS IS THE CONSENSUS \
FINDING this scenario exists to catch — demand was seen, the rotation was \
initiated, and it did not converge. Views $VIEW_BEFORE -> $VIEW_AFTER, head \
$H_DERIVE -> $H_AFTER. Read the surviving nodes' nodus.log around \
'initiated view change to view'." >&2
    fi
    exit 4
elif [ "$ROTATED" -eq 0 ] && [ "$FUND_OK" -eq 1 ]; then
    echo "[FAIL] a transaction committed while node$TARGET_NODE was paused \
but NO view-change quorum was logged ($VCQ_BEFORE -> $VCQ_AFTER). Somebody \
other than node$TARGET_NODE was leading, which means the derivation was \
stale: rank $LEADER_IDX of $ACTIVE_COUNT, epoch $EPOCH_START, view \
$derive_view -> $VIEW_AFTER, head $H_DERIVE -> $H_AFTER. Check that \
STAGEF_EPOCH_LENGTH=$E_LEN matches the binary's DNAC_EPOCH_LENGTH, then see \
lie-path 4." >&2
    exit 4
else
    echo "[FAIL] the cluster rotated the view past node$TARGET_NODE \
($VIEW_BEFORE -> $VIEW_AFTER, quorums +$(( VCQ_AFTER - VCQ_BEFORE ))) but the \
funding transaction never committed on any node. A rotation that does not \
restore block production is not a recovery. Head $H_DERIVE -> $H_AFTER." >&2
    exit 4
fi
echo "[info] funded user created with node$TARGET_NODE paused ($TEST_HOME)"

# ── Phase C — resume node, verify sync catch-up ─────────────────────
echo ""
echo "== Phase C — resume + sync =="
kill -CONT "$TARGET_PID"
trap - EXIT
echo "[info] node$TARGET_NODE resumed"

# Give sync 30s to catch node$TARGET_NODE up. Sync interval is typically
# fast but Dilithium verify on replayed blocks is slow.
#
# ⚠ This is a blind sleep, not a condition — lie-path 7. It is the
# pre-existing behaviour and is left alone deliberately; Phase D's
# convergence check is what actually decides the outcome.
sleep 30

# ── Phase D — final state_root convergence ──────────────────────────
echo ""
echo "== Phase D — final state_root convergence =="
bash "$(dirname "$0")/../stagef_diff.sh" "post-vcfork"

echo ""
echo "[PASS] C5 view-change fork safety: $captured/$STAGEF_COMMITTEE_SIZE \
nodes captured a prepared cert; the DERIVED epoch-$EPOCH_START leader \
node$TARGET_NODE (rank $LEADER_IDX of $ACTIVE_COUNT) was paused, the \
survivors completed +$(( VCQ_AFTER - VCQ_BEFORE )) view-change quorum(s) \
(view $VIEW_BEFORE -> $VIEW_AFTER) and committed new work without it, and \
state_root converged across all $STAGEF_COMMITTEE_SIZE nodes after it \
resumed. Epoch length $E_LEN."
