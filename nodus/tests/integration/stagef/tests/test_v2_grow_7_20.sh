#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_v2_grow_7_20.sh — a Comet committee grows 7 → 10 → 20 by
# governance, and keeps (and loses) liveness exactly at 2/3 of power
# ════════════════════════════════════════════════════════════════════
#
# CONVERTED TO THE VERSION-3 (cometbft) LANE (package GROW-7-20-COMET,
# 2026-09-26). The previous version was written for the deleted legacy
# lane: it grepped the retired `committed: height=` CLI print, read
# v2_blocks.qc (the Comet insert names ten columns and drops `header`,
# `qc` and `commit_cert` — nodus_witness_v2_apply.c:4075-4084), assumed
# one block per transaction, and spoke of view changes. None of that
# exists here. The claim-by-claim disposition is at the end of this
# header.
#
# P2P-PORT F6 (2026-09-26) — ADAPTED TO THE NEW 4004 STACK, NOT RUN YET.
# Copied from the GROW-7-20-COMET worktree and changed in four places:
# (a) the stake builder takes no --db (decision K3); (b) every node —
# genesis, candidates, the STEP 9 joiner — finds its 4004 peers through
# the network file named in $BASE_DIR/nodus.json (stagef_env.sh "THE 4004
# MESH"), with the harness-only allow_duplicate_ip / addr_book_strict=false
# that 20 nodes on 127.0.0.1 need; (c) the joining text no longer
# describes the deleted ident gate / DHT roster; (d) NEW STEP 4f: at N = 20
# node 1 and cand1 must answer EVERY client ping while the chain commits
# (the defect nodus/BUGS.md "P1 LIVENESS AT N≥20" recorded on the old
# transport; the p2p port is its fix). The bring-up must be on a
# p2p-aware server (stagef_up_v2.sh writes the network file only then).
#
# WHAT IT PROVES
#   The property that would be false if it failed: *a running version-3
#   chain can enlarge its own validator set by governance, the change
#   reaches cometbft's OWN voting set, and at N = 20 with equal stake the
#   chain commits with exactly 14 validators alive and stops with 13* —
#   the difference between a fleet you can grow and one frozen at its
#   genesis seven, and between a quorum rule that is cometbft's and one
#   that only looks like it.
#
#   Claims, each asserted separately (STEP numbers below):
#     1. 13 funded non-validators bond on a live chain and become
#        validator rows — and bonding alone is not membership (the live
#        epoch's committee is still 7).
#     2. the committee size is decided by a governance vote: at the first
#        epoch where all 20 are eligible (tenure + frozen copy, read from
#        the chain) the default target (32) would seat 20; the vote says
#        10 and exactly 10 are seated.
#     3. a target above the ceiling (33 > NODUS_V2_ACTIVE_SET_MAX 32) is
#        refused by EVERY genesis node's CheckTx (the apply engine's own
#        exec hook in a dry run), and no node's chain holds it — while a
#        LEGAL vote over the SAME client path is admitted and lands.
#     4. growth happens AT the boundary: the snapshot counts (10, then 20)
#        and hashes agree on all 20 nodes; cometbft's own ValidatorUpdates
#        line at each boundary reports the change (n_added / n_removed)
#        identically on all 20 nodes; and the committed Comet header's
#        NEXT-validators hash (v2_blocks.vset_hash = FinalizeBlock's
#        next_validators_hash, nodus_witness_cmt_app.c:2356-2364 →
#        nodus_witness_v2_apply.c:4043/:4097) is the same at H−1 and H
#        and CHANGES at H+1 (block H+1 commits to the set validating H+2)
#        — cometbft's two-height lag (recorded at nodus_witness_peer.c:
#        707-709 before P2P-PORT F5 deleted that file: "it still
#        validates heights H and H+1 with the PREVIOUS set").
#     5. tenure + the frozen copy gate selection: the epoch before the
#        first eligible one is still the genesis 7.
#     6. LIVENESS AT N = 20, the operator's key property:
#        6a. 6 of 20 stopped (six GENESIS nodes 2..7): the chain keeps
#            committing across a pigeonhole window, every one of the 14
#            running validators signs, none of the 6 stopped does;
#        6b. a 7th stopped (13 of 20 running): NO new height across 3
#            consecutive CreateEmptyBlocks intervals, with a transaction
#            pending — the EXPECTED safety stall;
#        6c. all 7 resumed: the pending transaction lands, the chain goes
#            on committing, all 20 nodes agree.
#     7. the 20-seat set survives a full stop/start of every node.
#     8. a node that misses an epoch boundary catches up and agrees on the
#        snapshot that boundary wrote.
#     9. a node with no chain and no seat adopts the chain from its pin
#        and replays genesis → head, both growth boundaries included.
#
# THE QUORUM ARITHMETIC — COMETBFT'S RULE, IN VOTING POWER
#   A vote set has a majority when its power `sum > total * 2 / 3`
#   (integer division — shared/dnac/cmt_vote_set.c:967; the commit
#   verifier's `needed = total * 2 / 3`, cmt_validation.c:298, the same
#   rule). Power per validator = total_stake / DNAC_DECIMAL_UNIT
#   (nodus_witness_cmt_app.c:2570, the §A diff). Every validator here
#   bonds exactly DNAC_SELF_STAKE_AMOUNT = 10^15 raw (stagef_up_v2.sh
#   SELF_STAKE / this file's BOND; dnac.h:137) and nobody delegates, so
#   every power is 10^15 / 10^8 = 10^7. This script READS that premise
#   from the chain (validators.self_stake all equal, delegations 0, the
#   frozen copy's per-validator totals all equal) and computes the numbers
#   below from what it read — it does not assume them.
#     N = 20: total = 2.0e8, total*2/3 = 133 333 333 → need power
#             > 133 333 333 → 14 signers (1.4e8). 13 signers = 1.3e8.
#             → 6 stopped (14 run) MUST commit; 7 stopped (13 run) MUST stall.
#     N = 10: total = 1.0e8, total*2/3 = 66 666 666 → 7 signers.
#             → 3 stopped would commit; 4 would stall. (Arithmetic only —
#             this script does not run a liveness matrix at N = 10.)
#   dna_bft_quorum(n) = 2n/3+1 is the GOVERNANCE approval count (the
#   chain-config CLI's), not cometbft's vote rule; it happens to agree
#   at equal stake and is not used for any liveness number here.
#
# WHY THE 6 STOPPED ARE GENESIS NODES
#   With nodes 2..7 stopped the running set is node 1 + the 13 candidates.
#   If cometbft's voting set were still the genesis 7 (or the 10-set), 6
#   of its members would be stopped and the chain could NOT commit. So
#   6a committing is itself proof that the candidates are real voters in
#   cometbft's set, not just rows in a table. Node 1 is never stopped
#   during the matrix: it is the reference DB and the pump's submit node.
#
# WHY 15 HEIGHTS IN 6a (pigeonhole), AND WHY IT IS ALIGNED
#   Under equal voting power cometbft's weighted round-robin degenerates
#   to exact round-robin (test_cmt_dead_proposer.sh's header, read from
#   shared/dnac/cmt_validator_set.c:849-977 — GROUNDED INFERENCE from the
#   ported code's structure, not measured here). 15 consecutive heights
#   have 15 distinct round-0 proposers out of 20; only 14 are running, so
#   at least one of those heights had a STOPPED round-0 proposer and had
#   to time out and move on. Window = (running) + 1 = 15.
#   RULE N: a validator whose epoch attendance is below 50 %
#   (DNAC_LIVENESS_THRESHOLD_BPS 5000, nodus_witness_v2_epoch.c
#   nodus_witness_v2_attendance_meets_bar) for DNAC_AUTO_RETIRE_EPOCHS = 2
#   consecutive epochs is AUTO_RETIRED — which would shrink the committee
#   under this scenario's feet. So the six are stopped RIGHT AT a fresh
#   epoch start b (the test_cmt_rule_n_retire.sh alignment shape) and the
#   window is 15 ≤ E: they miss the epoch [b, b+E) and at most a few
#   heights of the next one (6b adds no height — nothing commits; the
#   resume lag is a few blocks), so at most ONE epoch is missed and Rule N
#   never retires them. The same alignment is used for STEP 8's victim.
#   This is why E must be at least 15 (see the SKIP gate). The script
#   ASSERTS at the end that no validator is AUTO_RETIRED and that the
#   latest snapshot still seats 20, so a wrong premise here is a visible
#   RED, never a silent change of subject.
#
# THE GROWTH ARITHMETIC — DERIVED FROM WHAT LANDED, NOT ASSUMED
#   A validator is seated for epoch e only if (a) Rule R tenure:
#   active_since_block + 2E <= e, or it is genesis-seeded (active_since
#   <= 1) — nodus_witness_validator.c:384, DNAC_MIN_TENURE_BLOCKS = 2E
#   (dnac.h:224); AND (b) its bond is in the FROZEN copy the selection
#   ranks by, copy(e − 2E) (tokenomics-v3 P3-1 "okuma B",
#   nodus_witness_committee.c:285 lookback_block = e − E − 1 → :390
#   copy_epoch = e − 2E); the target is the chain_config value effective
#   at e (nodus_witness_vset.c:485-507, read by commit_next at boundary
#   e − E, :700-704).
#   On this lane the 13 claims and 13 bonds land in a few blocks, not one
#   per block, so every candidate's active_since is about the same height.
#   After the bonds land the script reads a_min / a_max (the candidates'
#   active_since_block) and derives
#     B      = the first boundary strictly above a_max
#     E_MID  = B + 2E   — the FIRST epoch all 13 are eligible (at E=15
#                         with bonds below 15: 45)
#     E_TEN  = E_MID − E — tenure/copy still closed: the genesis 7 (30)
#     E_GROW = E_MID + E — the second vote's epoch (60)
#   and requires every candidate to be first-eligible at the SAME epoch
#   (ceil((a_min+2E)/E)·E == E_MID), which holds whenever no bond landed
#   on a boundary height; otherwise it FAILS with that reason (a bond on a
#   boundary height makes "is it in copy(B)" depend on intra-block
#   ordering this script does not read).
#   Two votes, both committed long before the boundary that reads them:
#     vote A: TARGET_ACTIVE_COUNT = 10 effective E_MID — committed before
#             E_TEN (commit_next(E_TEN) builds snapshot(E_MID)). At E_MID
#             20 are eligible (checked from the chain); the default would
#             seat all 20; exactly 10 proves the vote decided it.
#     vote B: TARGET_ACTIVE_COUNT = 20 effective E_GROW — committed before
#             E_MID. It equals what the default would seat, so E_GROW
#             proves GROWTH, not governance, and is labelled that way.
#   Which 10 are seated at E_MID is a draw: equal frozen totals rank by
#   the SHA3 tie-break (nodus_witness_committee.c
#   cmp_frozen_desc_tiebreak_asc), so genesis nodes may be rotated out.
#   Nothing here assumes which 10; the Comet ValidatorUpdates line must
#   show n_added − n_removed = 3.
#   Cometbft applies a set announced at boundary H from H+2 (its two-
#   height lag, nodus_witness_cmt_app.c §A comment and
#   test_cmt_rule_n_retire.sh's header), so the liveness matrix starts
#   only past E_GROW + 2.
#
# WHAT IT REQUIRES
#   ⚠ A SHORT-EPOCH + SHORT-GRACE BINARY, A CANDIDATE-BEARING BRING-UP,
#   AND ITS OWN FRESH CLUSTER.
#     compile (README.md "Quick start" short-epoch line, all four):
#              -DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
#              -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#              -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#              (nodus-server AND nodus-cli from the SAME build — the CLI
#              enforces the grace floor with its own compiled constant)
#     env, ALL exported BEFORE stagef_up_v2.sh:
#              STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN → that build
#              STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#              STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#              STAGEF_V2_CANDIDATES=13   — mints the 13 funded identities
#                                          (0, the default → SKIP)
#     Not needed any more: STAGEF_V2_PUMP_LEAVES (height is driven by the
#     CLI-SPEND pump — node 3's genesis leaf, stagef_env.sh
#     stagef_cmt_pump_to — not by pump leaves).
#     Kept at their defaults: STAGEF_PUMP_FUNDER_NODE=3 (keys only — the
#     node may be stopped) and STAGEF_PUMP_SUBMIT_NODE=1 (REQUIRED: nodes
#     2..7 are stopped in STEP 6; any other value SKIPs).
#   SKIPS (rc 99) — coverage that did not happen, never a pass — when:
#     not a version-3 cluster / no genesis config; a candidate identity is
#     missing; STAGEF_EPOCH_LENGTH is outside [15, 20] (15 = the 6a
#     pigeonhole window, below it Rule N can retire the stopped six; above
#     20 the ≈ 9 epochs this walks are out of a reasonable wall clock);
#     STAGEF_CC_GRACE_SAFETY > E (the votes could not land in time); the
#     CLI-SPEND pump is unavailable; the pump submit node is not node 1.
#   ⏱ ≈ 45-75 min on one 4-CPU machine (JUDGMENT, not measured on this
#   lane): ≈ 130 pumped blocks, candidate and joiner catch-up over the
#   4004 p2p port, one 3-interval (180 s) expected stall, a full
#   20-node restart.
#
# WHAT IT LEAVES BEHIND
#   ⚠ THE HEAVIEST RESIDUE IN THE SUITE. Run it STANDALONE, on its own
#   fresh bring-up, and tear down after (stagef_down.sh reaps every pid
#   this script appends to pids.txt).
#     - 13 candidate nodes running under $BASE_DIR/cand1..13 (derived
#       locally from v2_genesis.conf, ports C+3+i — stagef_up_v2.sh:260),
#       plus a 21st, non-validator replay node under $BASE_DIR/grow_replay
#     - a PERMANENT 20-seat committee; two chain_config_history rows
#       (param 4: 10 at E_MID, 20 at E_GROW)
#     - every candidate's genesis leaf claimed and bonded
#     - node 3's genesis leaf claimed by the pump and one fee per pump step
#       gone from it (into the reward pool since tokenomics-v3 P2)
#     - every node restarted once (STEP 7), cand12 twice (STEP 8); nodes
#       2..7 and cand13 SIGSTOPped and resumed (STEP 6)
#     - the chain ≈ 9 epochs on
#   An EXIT trap SIGCONTs every node this script stopped. It does NOT
#   restart a node it killed: a failure inside STEP 7 or STEP 8 leaves
#   that node down — tear down rather than diagnose further.
#
# HOW IT CAN LIE
#   - **CheckTx APPROVED is admission, not inclusion.** Every transaction
#     here (claims, bonds, votes, pump spends) is followed to its LEDGER
#     EFFECT — the utxo_set row, the validators row, the
#     chain_config_history row, the spend's created coin — through
#     stagef_cmt_wait_row (progress- AND height-bounded). The CLI's stdout
#     is read only for its verdict line, never for a height.
#   - **"20 validator rows" is not "a committee of 20".** A bond writes
#     the row at once; seats come only from a boundary's snapshot. Counts
#     are read from validator_set_snapshots and from cometbft's own
#     ValidatorUpdates line, on all 20 nodes.
#   - **A stall is only a stall if the chain was asked to move.** Idle
#     production (CreateEmptyBlocks, 60 s) asks every interval anyway;
#     6b additionally submits one pump spend (CheckTx-approved on node 1)
#     and requires it NOT to land. Positive control before (6a commits
#     with 14), recovery after (6c: the SAME pending spend lands): that is
#     what tells a quorum stall from 20 processes starving on 4 CPUs.
#   - **An in-flight height may commit just after the 7th stop** (its
#     precommit could already be out). 6b allows the tip to move by at
#     most 2 before freezing (JUDGMENT, the same shape as
#     test_cmt_dead_proposer.sh's settle allowance); a larger move is RED.
#   - **The 33 refusal must be a REFUSAL.** It is built by `v2-envelope
#     chain-config` (the offline path — `chain-config propose` refuses 33
#     in the CLI itself, nodus-cli.c:1393, before any node sees it), and
#     each of the 7 answers must be the node's own CheckTx refusal
#     (`dnac_spend RPC failed (rc=7 status=0)` — NODUS_ERR_PROTOCOL_ERROR,
#     nodus_types.h:475, the handler's "CheckTx code N" reply,
#     nodus_witness_handlers.c ~:1888) after a locally-built envelope
#     ("envelope built:"). rc=7 is also the answer to other mempool
#     refusals ("CheckTx admission refused"), so the CONTROL matters: vote
#     B uses the SAME offline path and must be admitted and land. If vote
#     B fails, the refusal proves nothing and the run is RED.
#   - **Vote A and vote B use different client paths** (networked
#     `chain-config propose`, the verbs 40-41 flow test_cmt_chain_config.sh
#     proves; and the offline `v2-envelope chain-config`). Both write
#     expiry tip+90 (nodus-cli.c:89-90, :952), inside the tip+100 CheckTx
#     rule (decision 2026-09-25-mempool-policy.md); this script builds no
#     envelope itself.
#   - **Joining on the 4004 p2p port (P2P-PORT F6).** The ident gate and
#     the DHT "nodus:pk" roster this bullet used to describe are DELETED
#     with the old transport. A candidate (and STEP 9's joiner) starts with
#     -c nodus.json, whose network file lists the SEVEN genesis nodes as
#     persistent peers ("id@127.0.0.1:<witness port>"): it DIALS them, and
#     they admit it as an ordinary inbound peer (reference admission,
#     max_num_inbound_peers 40; decision K2 exempts BONDED identities from
#     the cap once their stake lands) — the reference model, in which a
#     non-validator receives consensus gossip before it has a seat. PEX
#     (on by default) then spreads the candidates' addresses. NOT
#     MEASURED YET on this stack: the time a from-genesis catch-up of 13
#     nodes takes over it. The candidate catch-up wait (STEP 1c) is
#     therefore progress-bounded with a wide 8-interval stall (480 s — the
#     legacy lane measured 12 of 13 joiners adopting by ~180 s and the
#     13th by ~360 s); if a candidate cannot sync before its seat it FAILS
#     there, with that reason, instead of stalling the chain at E_MID+2.
#     The joiner's adoption (STEP 9) is attempt-bounded at 600 × 1 s for
#     the same reason. Do NOT tune either down.
#   - **STEP 4f samples, it does not prove "never".** Two nodes, pinged
#     back-to-back across >= 3 commits; a stall shorter than the gap
#     between two probes, or on a node not probed, is not seen. The bound
#     is the CLI's own 5 s per step (connect, AUTH, PING); the slowest
#     probe is printed, never asserted against a number of ours. Raw
#     results: $BASE_DIR/grow_ping/node<N>.txt ("<rc> <ms>" per probe).
#   - **The pigeonhole in 6a is an INFERENCE** from the ported proposer
#     selection (see above), not an observed timeout: cmt_cs.c logs no
#     "round advanced" line (test_cmt_dead_proposer.sh's header). The
#     load-bearing 6a assertions are the attendance rows: 6 frozen, all 14
#     others moving while the chain commits.
#   - **One machine.** 20-21 processes on one host: no partition, no
#     latency, SIGSTOP is not a crash, and a green here is green at E=15 /
#     grace 15. It proves the LOGIC — governance lands on a boundary,
#     tenure and the frozen copy gate selection, cometbft's set follows
#     the snapshot, the 2/3 power line holds at N=20 — and NOTHING about
#     production magnitudes (E=720, grace 17280).
#   - **6a runs at EXACT majority.** 14 running, 14 needed: every running
#     validator's precommit is required for every block, so one node
#     lagging a round costs that round a timeout. A RED at 6a needs the
#     node logs read (round timeouts, missing prevotes) before it is
#     called a defect; the positive-control framing is what separates it
#     from CPU starvation.
#   - **Long-gap catch-up is new ground here.** STEP 1c (13 nodes from
#     genesis) and STEP 9 (~130 blocks) are longer catch-ups than any the
#     sweep has exercised on this lane (README "What a green COMET run
#     does not prove", item 4: there is no blocksync, only the consensus
#     reactor's stored-part gossip). They are the likeliest first-run
#     stall.
#   - **Rule N safety is inferred, then checked.** It rests on each
#     resumed validator signing >= 50 % of the epoch after its missed one
#     — provided by 6c's all-20 catch-up wait before anything else runs —
#     and on `signed_count` being per-epoch, which this script did NOT
#     read in the source (indirectly grounded: test_cmt_rule_n_retire.sh
#     measures a retirement after exactly two missed epochs). A RED at
#     the terminal "no validator AUTO_RETIRED" check points at resume or
#     catch-up lag first.
#   - **NOT RUN YET on this lane.** This conversion (GROW-7-20-COMET) was
#     written against the source; no line of it has been exercised on a
#     cluster. The first run is its first measurement.
#   - **rc=99 is not a pass.**
#
# CLAIM DISPOSITION (legacy → Comet lane)
#   1  bond by strangers ........ KEPT (effect-keyed waits, batched blocks)
#   1b bonding ≠ membership ..... KEPT
#   2  size decided by vote ..... REWRITTEN (epochs derived from the bonds
#                                  that landed; eligibility read from the
#                                  chain; the legacy "14 eligible" is gone)
#   3  33 refused ............... REWRITTEN (offline path; each of the 7
#                                  CheckTx refusals + same-path control)
#   4a/4b count + hash on all ... KEPT (both growth epochs, all 20 nodes)
#   4c header vset digest ....... REWRITTEN → v2_blocks.vset_hash is the
#                                  Comet header's NEXT-validators hash
#                                  here: equal at H−1/H, different at H+1,
#                                  equal again at H+2, identical on all 20;
#                                  PLUS cometbft's ValidatorUpdates line
#                                  (n_added/n_removed) on all 20
#   4d boundary block has a QC .. DROPPED — the Comet insert does not
#                                  write `qc` (apply.c:4075-4084; the
#                                  commit lives in the Comet block
#                                  store); block_id (covers the header)
#                                  agreement across all 20 replaces it
#   4e agreement after growth ... KEPT (global_root + block_id, 20 nodes)
#   5  tenure gates ............. KEPT (tenure AND the frozen copy, both
#                                  closed at E_TEN; not separated)
#   6a quorum alive commits ..... REWRITTEN (6 genesis stopped, 15-height
#                                  pigeonhole window, attendance rows)
#   6b one fewer stalls ......... REWRITTEN (7 stopped, 3 intervals, a
#                                  pending spend that must not land)
#   6c restore resumes .......... REWRITTEN (the pending spend lands)
#   6d genesis 7 alone stall .... DROPPED — subsumed: "the 7 alone" is 13
#                                  stopped / 7 running, strictly below
#                                  6b's 13 running, which already stalls
#                                  by the same power arithmetic; and 6a
#                                  commits with only ONE genesis node
#                                  running, so the genesis 7 are neither
#                                  needed nor sufficient
#   7  full stop/start .......... KEPT
#   8  missed boundary catch-up . KEPT (aligned for Rule N; the missed
#                                  boundary's snapshot compared)
#   9  cold replay by a joiner .. KEPT (pin adoption, both growth
#                                  boundaries compared)
#   legacy pump_once / chain_moves / pump budget ... DROPPED — the Comet
#   lane makes idle blocks and the CLI-SPEND pump drives height; the
#   "empty pump is not a stalled chain" distinction survives as the
#   pump helper's rc 3 (fault) vs rc 1 (stall) vs rc 2 (dropped).
#
# EXIT: 0 pass (every step asserted), 99 skip, anything else fail.
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"
# Split S3/S6: spawns candidates and SIGSTOPs/starts genesis nodes as one
# nodus-server process each — SKIP (99) in every split mode (splitw,
# mixedw, splits, mixeds, split, mixed). Not an OLD/NEW upgrade pair: its
# own reason, printed as given.
stagef_split_skip_if --reason "candidate spawns / SIGSTOP of genesis nodes not adapted to split nodes" \
    $(seq 1 "$STAGEF_COMMITTEE_SIZE")

die()  { echo "[FAIL] $*" >&2; exit 1; }
ok()   { echo "[ok] $*"; }
info() { echo "[info] $*"; }
skip() { echo "[SKIP] $*"; exit 99; }

# ── every node this script SIGSTOPs is SIGCONTed on ANY exit ─────────
STOPPED_PIDS=()
resume_stopped() {
    local p
    for p in "${STOPPED_PIDS[@]+"${STOPPED_PIDS[@]}"}"; do
        kill -CONT "$p" 2>/dev/null || true
    done
    STOPPED_PIDS=()
}
trap resume_stopped EXIT

[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || die "no active harness — run stagef_up_v2.sh first"
command -v sqlite3 >/dev/null || die "sqlite3 required"
command -v openssl >/dev/null || die "openssl required (stagef_voter_id)"

CLI="$STAGEF_NODUSCLI_BIN"
NODUS="$STAGEF_NODUS_BIN"
[ -x "$CLI" ]   || die "nodus-cli not found at $CLI"
[ -x "$NODUS" ] || die "nodus-server not found at $NODUS"

C="$STAGEF_COMMITTEE_SIZE"          # 7 genesis validators (stagef_env.sh:49)
NCAND=13
TOTAL=$(( C + NCAND ))              # 20
E="${STAGEF_EPOCH_LENGTH:-720}"
G="${STAGEF_CC_GRACE_SAFETY:-17280}"
CONF="$BASE_DIR/v2_genesis.conf"
BOND=1000000000000000               # DNAC_SELF_STAKE_AMOUNT (dnac.h:137)
COMMISSION=500
V2_SET_MAX=32                       # NODUS_V2_ACTIVE_SET_MAX (nodus_witness.h:166)
ILLEGAL=$(( V2_SET_MAX + 1 ))       # 33 — refused by rt_native.c:4116-4118
MID_TARGET=10                       # vote A: below the 20 eligible at E_MID
PUMP_IDS="${STAGEF_V2_PUMP_IDENTITIES:-1}"

# ── requirements, checked not assumed ───────────────────────────────
SDB=$(stagef_node_chain_db 1)
[ -n "$SDB" ] && [ -s "$SDB" ] || skip "no chain DB for node1 — not a stagef_up_v2.sh cluster"
has_v2=$(sqlite3 "$SDB" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
[ "${has_v2:-0}" != "0" ] && [ -f "$CONF" ] || skip "not a version-3 cluster with a genesis config — use stagef_up_v2.sh"
[ -s "$BASE_DIR/v2_genesis_pin" ] && [ -s "$BASE_DIR/v2_chain_id" ] || skip "bring-up recorded no genesis pin / chain id"
# P2P-PORT F6: the candidates and the joiner find their 4004 peers only
# through the network file a p2p-aware bring-up writes.
[ -s "$(stagef_network_file)" ] || skip "no network file at $(stagef_network_file) — bring up on a nodus-server with the 4004 p2p port (its -h lists --network-file)"
for i in $(seq 1 "$NCAND"); do
    [ -s "$BASE_DIR/cand$i/identity/nodus.pk" ] && [ -s "$BASE_DIR/cand$i/identity/nodus.fp" ] || \
        skip "candidate $i missing — export STAGEF_V2_CANDIDATES=$NCAND before stagef_up_v2.sh"
done
if [ "$E" -lt 15 ] || [ "$E" -gt 20 ]; then
    skip "epoch length $E: needs a short-epoch build with 15 <= E <= 20
       (-DDNAC_EPOCH_LENGTH=15 + STAGEF_EPOCH_LENGTH=15). Below 15 the
       STEP 6a pigeonhole window (15 heights) no longer fits one epoch and
       Rule N could retire the stopped validators; above 20 the ~9 epochs
       this scenario walks are out of a reasonable wall clock."
fi
if [ "$G" -gt "$E" ]; then
    skip "STAGEF_CC_GRACE_SAFETY=$G > E=$E — the committee-size votes could not
       land before the boundary that reads them. Needs a short-grace build
       (-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 + ..._ERGONOMIC_BLOCKS=15)
       with STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15."
fi
[ "$STAGEF_PUMP_SUBMIT_NODE" = 1 ] || \
    skip "STAGEF_PUMP_SUBMIT_NODE=$STAGEF_PUMP_SUBMIT_NODE — this scenario stops nodes 2..7 in STEP 6; the pump must submit to node 1"
if ! stagef_cmt_pump_ready "$SDB"; then
    skip "the CLI-SPEND pump is unavailable (see [pump] above) — ~130 blocks of
       idle production at 60 s each is out of reach"
fi
DU=$(awk -F'= *' '/^decimal_unit/{print $2; exit}' "$CONF")
case "$DU" in ''|*[!0-9]*|0) die "cannot read decimal_unit from $CONF" ;; esac

pre_vals=$(sqlite3 "$SDB" "SELECT COUNT(*) FROM validators;")
[ "$pre_vals" = "$C" ] || die "expected $C validators before growth, found $pre_vals — this cluster is not fresh (run standalone)"
for i in $(seq 1 "$NCAND"); do
    if ls "$BASE_DIR/cand$i/data/"witness_*.db >/dev/null 2>&1; then
        die "cand$i already has a chain database — this bring-up already ran this scenario; bring up fresh"
    fi
done
[ ! -e "$BASE_DIR/grow_replay" ] || die "$BASE_DIR/grow_replay exists — this bring-up already ran this scenario"
stagef_sentinel SETUP_OK
ok "requirements met (E=$E, grace $G, $NCAND candidates, pump ready, decimal_unit $DU)"

# ── node addressing: 1..C genesis, C+1..TOTAL candidates ─────────────
PORT1=$(stagef_tcp_port 1)
node_dir()  { if [ "$1" -le "$C" ]; then echo "$BASE_DIR/node$1"; else echo "$BASE_DIR/cand$(( $1 - C ))"; fi; }
# Candidate i uses port block C+3+i — the one stagef_up_v2.sh:260 gave its
# identity spawn, past the v2user (C+1), pump (C+2) and probe (C+3) blocks.
node_pidx() { if [ "$1" -le "$C" ]; then echo "$1"; else echo $(( C + 3 + $1 - C )); fi; }
# largest_db DIR — the largest non-empty witness_*.db in DIR (the rule of
# stagef_env.sh stagef_node_chain_db), without a `ls | head` pipe: under
# pipefail an early-exiting reader can SIGPIPE the writer (README,
# test_v2_rewards.sh row: measured rc 141 false negatives).
largest_db() {
    local f best="" bs=-1 s
    for f in "$1/"witness_*.db; do
        [ -s "$f" ] || continue
        s=$(stat -c%s "$f")
        if [ "$s" -gt "$bs" ]; then best="$f"; bs="$s"; fi
    done
    if [ -n "$best" ]; then echo "$best"; fi
    return 0
}
node_db()  { largest_db "$(node_dir "$1")/data"; }
node_log() { echo "$(node_dir "$1")/nodus.log"; }
node_pk()  { echo "$(node_dir "$1")/identity/nodus.pk"; }
node_fp()  { cat "$(node_dir "$1")/identity/nodus.fp"; }
node_pkhex() { xxd -p -c 999999 "$(node_pk "$1")"; }
# The node's own process: its data dir as the -d argument (one per dir).
node_pid() { pgrep -o -f -- "-d $(node_dir "$1")/data( |\$)" || true; }
tip() { stagef_cmt_tip "$SDB"; }

SEEDS=()
for s in $(seq 1 "$C"); do SEEDS+=(-s "127.0.0.1:$(stagef_udp_port "$s")"); done

# start_node N [extra server args...] — the bring-up's spawn line
# (stagef_up_v2.sh:622-627), log APPENDED, pid appended to pids.txt.
start_node() {
    local n="$1"; shift
    local dir pidx
    dir=$(node_dir "$n"); pidx=$(node_pidx "$n")
    "$NODUS" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$pidx")" -t "$(stagef_tcp_port "$pidx")" \
        -p "$(stagef_peer_port "$pidx")" -C "$(stagef_chan_port "$pidx")" \
        -W "$(stagef_witness_port "$pidx")" \
        "$@" -i "$dir/identity" -d "$dir/data" "${SEEDS[@]}" \
        >> "$dir/nodus.log" 2>&1 &
    echo "$!" >> "$BASE_DIR/pids.txt"
}

# wait_listening N — attempt-bounded, the bring-up's own check (:632-640).
wait_listening() {
    local tcp ok_=0 lst
    tcp=$(stagef_tcp_port "$(node_pidx "$1")")
    for _ in $(seq 1 60); do
        lst=$(ss -lt 2>/dev/null || true)
        if grep -Eq "[:.]${tcp}\\b" <<< "$lst"; then ok_=1; break; fi
        sleep 0.5
    done
    [ "$ok_" = 1 ] || die "node $1 never listened on $tcp"
}

# wait_role_live N FROM_LINE — role + startup table + LIVE in the log
# lines written AFTER FROM_LINE (this boot only). Attempt-bounded, the
# bring-up's anti-vacuity shape (stagef_up_v2.sh:678-697). Valid for ANY
# start of a node that holds a version-3 chain, seat or no seat: witness
# init runs nodus_witness_cmt_live_init whenever the post-open gate
# accepted a version-3 chain (nodus_witness.c:2067-2073), which prints the
# startup-table line (:1708) and later the LIVE line (:1820); the role
# line is the gate's own (:938). One awk pass over the file — no
# early-exit pipe reader (see largest_db).
wait_role_live() {
    local log flags=000
    log=$(node_log "$1")
    for _ in $(seq 1 90); do
        flags=$(awk -v o="$2" 'NR > o && /chain role: COMETBFT/        {r=1}
                               NR > o && /cometbft startup table built/ {s=1}
                               NR > o && /cometbft lane LIVE/          {l=1}
                               END { printf "%d%d%d", r, s, l }' "$log" 2>/dev/null || echo 000)
        [ "$flags" = 111 ] && return 0
        sleep 1
    done
    die "node $1 incomplete after start: role/startup-table/lane-live = $flags (see $log)"
}

log_lines() { local f; f=$(node_log "$1"); if [ -f "$f" ]; then wc -l < "$f"; else echo 0; fi; }

# sigstop_node N — SIGSTOP, recorded for the EXIT trap.
sigstop_node() {
    local pid; pid=$(node_pid "$1")
    [ -n "$pid" ] || die "node $1 is not running"
    kill -STOP "$pid"
    STOPPED_PIDS+=("$pid")
}

# kill_node N — SIGTERM and wait until the process is gone (attempt-
# bounded). A child of THIS shell becomes a zombie until reaped, and
# `kill -0` succeeds on a zombie, so the state is read, not the signal.
kill_node() {
    local pid st
    pid=$(node_pid "$1")
    [ -n "$pid" ] || die "node $1 is not running"
    kill "$pid"
    for _ in $(seq 1 60); do
        st=$(ps -o stat= -p "$pid" 2>/dev/null || true)
        case "$st" in
            ''|Z*) wait "$pid" 2>/dev/null || true; return 0 ;;
        esac
        sleep 1
    done
    die "node $1 (pid $pid) did not exit within 60 s of SIGTERM"
}

# wait_all_reach H STALL [N...] — every listed node's own tip reaches H,
# progress-bounded (stagef_cmt_wait_height). Default: all TOTAL nodes.
wait_all_reach() {
    local h="$1" stall="$2" n db; shift 2
    local nodes=("$@")
    [ "${#nodes[@]}" -gt 0 ] || nodes=($(seq 1 "$TOTAL"))
    for n in "${nodes[@]}"; do
        db=$(node_db "$n")
        [ -n "$db" ] || die "node $n has no chain database"
        stagef_cmt_wait_height "$db" "$h" "$stall" >/dev/null \
            || die "node $n never reached height $h (stuck at $(stagef_cmt_tip "$db"))"
    done
}

# assert_same LABEL SQL N... — the value is identical and NON-EMPTY on
# every listed node (an empty read is a failure, never agreement).
assert_same() {
    local label="$1" sql="$2"; shift 2
    local first="" n db v
    for n in "$@"; do
        db=$(node_db "$n")
        [ -n "$db" ] || die "$label: node $n has no chain DB"
        v=$(sqlite3 "$db" "$sql" 2>/dev/null || true)
        [ -n "$v" ] || die "$label: node $n returned EMPTY — an empty read is a failure, not agreement"
        if [ -z "$first" ]; then first="$v"
        elif [ "$v" != "$first" ]; then die "$label: node $n disagrees ($v != $first)"; fi
    done
    echo "$first"
}

# agree_at_floor LABEL [EXTRA_DB...] — stagef_cmt_diff_at_floor's shape
# over ALL 20 nodes (that helper and stagef_diff.sh loop 1..7 only,
# stagef_env.sh:897): the floor is the minimum tip, a height every node
# has provably reached; global_root AND block_id (block_id covers the
# Comet header, stagef_diff.sh's own reasoning) must be identical there.
agree_at_floor() {
    local label="$1"; shift
    local dbs=() db n h floor="" ref="" row
    for n in $(seq 1 "$TOTAL"); do
        db=$(node_db "$n"); [ -n "$db" ] || die "$label: node $n has no chain DB"
        dbs+=("$db")
    done
    dbs+=("$@")
    for db in "${dbs[@]}"; do
        h=$(stagef_cmt_tip "$db"); [ -n "$h" ] || h=-1
        if [ -z "$floor" ] || [ "$h" -lt "$floor" ]; then floor="$h"; fi
    done
    [ "$floor" -ge 1 ] || die "$label: some node has no block (floor $floor)"
    for db in "${dbs[@]}"; do
        row=$(sqlite3 "$db" "SELECT hex(global_root)||'|'||hex(block_id) FROM v2_blocks WHERE global_height=$floor;" 2>/dev/null || true)
        [ -n "$row" ] || die "$label: $(dirname "$(dirname "$db")") has no row at the floor $floor"
        if [ -z "$ref" ]; then ref="$row"
        elif [ "$row" != "$ref" ]; then
            die "$label: DIVERGENCE at height $floor — $(dirname "$(dirname "$db")") has ${row:0:32}..., the first node ${ref:0:32}..."
        fi
    done
    ok "$label: ${#dbs[@]} nodes identical at height $floor (root|block_id ${ref:0:16}...)"
}

# need_signers N P — the smallest k with k·P > (N·P)·2/3 (integer), i.e.
# cometbft's majority rule (cmt_vote_set.c:967) at N equal powers P.
need_signers() {
    local n="$1" p="$2" k=0 thr
    thr=$(( n * p * 2 / 3 ))
    while [ $(( k * p )) -le "$thr" ]; do k=$(( k + 1 )); done
    echo "$k"
}

# vu_line N H — "n_added n_power_changed n_removed" from node N's
# cometbft ValidatorUpdates INFO line for boundary H
# (nodus_witness_cmt_app.c:2654-2658), empty when absent.
vu_line() {
    local line
    line=$(grep -m1 "epoch boundary height $2 .*validator_updates n_added=" "$(node_log "$1")" 2>/dev/null || true)
    if [[ $line =~ n_added=([0-9]+)\ n_power_changed=([0-9]+)\ n_removed=([0-9]+) ]]; then
        echo "${BASH_REMATCH[1]} ${BASH_REMATCH[2]} ${BASH_REMATCH[3]}"
    fi
}

# vset_switch H — v2_blocks.vset_hash is the Comet header's NEXT-
# validators hash (nodus_witness_cmt_app.c:2356-2364: FinalizeBlock
# carries only next_validators_hash), i.e. block h commits to the set that
# validates h+1. With the two-height lag (heights H and H+1 are still
# validated by the previous set — the deleted nodus_witness_peer.c:707-709
# recorded it) that gives:
# vset(H−1) = set(H) = old, vset(H) = set(H+1) = old, vset(H+1) =
# set(H+2) = NEW, vset(H+2) = set(H+3) = new. Asserted exactly, and the
# H+1 value identical on all TOTAL nodes. Callers have waited for every
# node to reach H+2.
vset_at() { sqlite3 "$SDB" "SELECT hex(vset_hash) FROM v2_blocks WHERE global_height=$1;"; }
vset_switch() {
    local h="$1" vm v0 v1 v2
    vm=$(vset_at $(( h - 1 ))); v0=$(vset_at "$h")
    v1=$(vset_at $(( h + 1 ))); v2=$(vset_at $(( h + 2 )))
    [ -n "$vm" ] && [ -n "$v0" ] && [ -n "$v1" ] && [ -n "$v2" ] || die "vset_hash missing around boundary $h"
    [ "$vm" = "$v0" ] || die "the header next-validators hash changed already at $h — cometbft's two-height lag says H+1 is still validated by the previous set"
    [ "$v0" != "$v1" ] || die "the header next-validators hash is UNCHANGED at $(( h + 1 )) — the snapshot moved but cometbft's voting set for $(( h + 2 )) did not"
    [ "$v1" = "$v2" ] || die "the header next-validators hash moved again at $(( h + 2 )) — expected one change per boundary"
    assert_same "header next-validators hash at $(( h + 1 ))" \
        "SELECT hex(vset_hash) FROM v2_blocks WHERE global_height=$(( h + 1 ));" $(seq 1 "$TOTAL") >/dev/null
}

# frozen_copy_check EPOCH — per-validator totals in copy(EPOCH)
# (v2_balance_copy, nodus_witness_v2_econ.c:415; validator_fp =
# SHA3-512(pubkey) = nodus.fp, :311) as "count|distinct|min".
frozen_copy_check() {
    sqlite3 "$SDB" "SELECT COUNT(*)||'|'||COUNT(DISTINCT s)||'|'||COALESCE(MIN(s),0) FROM
        (SELECT validator_fp, SUM(amount) AS s FROM v2_balance_copy WHERE epoch_start=$1 GROUP BY validator_fp);"
}
in_copy() {   # N EPOCH → the node's frozen total in copy(EPOCH), 0 absent
    sqlite3 "$SDB" "SELECT COALESCE(SUM(amount),0) FROM v2_balance_copy WHERE epoch_start=$2
        AND lower(hex(validator_fp))=lower('$(node_fp "$1")');"
}

echo "══ Comet committee growth $C → $MID_TARGET → $TOTAL, and liveness at N=$TOTAL ══"
stagef_cmt_diff_at_floor "pre-v2-grow" || exit 2

# ════════════════════════════════════════════════════════════════════
# STEP 1 — 13 funded strangers claim their leaves and bond
# ════════════════════════════════════════════════════════════════════
t0=$(tip)
for i in $(seq 1 "$NCAND"); do
    n=$(( C + i ))
    isval=$(sqlite3 "$SDB" "SELECT COUNT(*) FROM validators WHERE lower(hex(pubkey))='$(node_pkhex "$n")';")
    [ "$isval" = 0 ] || die "cand$i is ALREADY a validator — it cannot demonstrate becoming one"
    crc=0
    "$CLI" -s 127.0.0.1 -p "$PORT1" v2-claim --config "$CONF" --db "$SDB" \
        --keys "$(node_dir "$n")/identity" --submit "127.0.0.1:$PORT1" \
        > "$BASE_DIR/grow_claim_$i.log" 2>&1 || crc=$?
    [ "$crc" = 0 ] || { cat "$BASE_DIR/grow_claim_$i.log" >&2; die "cand$i's claim was not admitted (v2-claim rc=$crc)"; }
done
ok "13 candidate claims CheckTx-approved (admission only — inclusion next)"
for i in $(seq 1 "$NCAND"); do
    n=$(( C + i )); fp=$(node_fp "$n")
    h=$(stagef_cmt_wait_row "$SDB" \
        "SELECT COUNT(*) FROM utxo_set WHERE owner='$fp' AND token_id=zeroblob(64) AND amount > 0;" 3) \
        && wrc=0 || wrc=$?
    case "$wrc" in
        0) ;;
        1) die "cand$i's claimed coin never appeared and the chain STALLED at $h" ;;
        *) die "cand$i's claim was not included within 20 heights (tip $h) — dropped, not delayed" ;;
    esac
done
ok "all 13 claimed coins are on the chain (tip $t0 -> $(tip))"

for i in $(seq 1 "$NCAND"); do
    n=$(( C + i )); k="$(node_dir "$n")/identity"
    src=0
    # P2P-PORT F6 (K3): no --db — the stake builder reads chain id, coins,
    # tip and gas price from node 1 over the candidate's own session.
    "$CLI" -s 127.0.0.1 -p "$PORT1" v2-envelope stake --keys "$k" \
        --bond "$BOND" --commission "$COMMISSION" --dest-fp "$(node_fp "$n")" \
        --submit "127.0.0.1:$PORT1" > "$BASE_DIR/grow_stake_$i.log" 2>&1 || src=$?
    [ "$src" = 0 ] || { cat "$BASE_DIR/grow_stake_$i.log" >&2; die "cand$i's stake was not admitted (rc=$src)"; }
done
ok "13 stake envelopes CheckTx-approved (admission only — inclusion next)"
for i in $(seq 1 "$NCAND"); do
    n=$(( C + i ))
    h=$(stagef_cmt_wait_row "$SDB" \
        "SELECT COUNT(*) FROM validators WHERE lower(hex(pubkey))='$(node_pkhex "$n")';" 3) \
        && wrc=0 || wrc=$?
    case "$wrc" in
        0) ;;
        1) die "cand$i's validator row never appeared and the chain STALLED at $h" ;;
        *) die "cand$i's bond was not included within 20 heights (tip $h) — dropped, not delayed" ;;
    esac
done
vrow=$(sqlite3 "$SDB" "SELECT COUNT(*)||'|'||COUNT(DISTINCT self_stake)||'|'||MIN(self_stake)||'|'||
        (SUM(total_delegated)+SUM(external_delegated)) FROM validators;")
[ "$vrow" = "$TOTAL|1|$BOND|0" ] || die "validators table is not $TOTAL equal bonds with no delegation: count|distinct|min|delegated = $vrow"
POWER=$(( BOND / DU ))
ok "STEP 1 — $NCAND strangers bonded: $TOTAL validator rows, every self_stake $BOND, no delegation (power $POWER each)"

# 1b — bonding is not membership.
e_now=$(( $(tip) / E * E ))
c_now=$(sqlite3 "$SDB" "SELECT active_count FROM validator_set_snapshots WHERE epoch_start=$e_now;")
[ "$c_now" = "$C" ] || die "the live epoch's committee changed on bonding alone (epoch $e_now count=$c_now)"
ok "STEP 1b — the live committee (epoch $e_now) is still $C: bonding is not membership"

# ── the growth epochs, from what actually landed ────────────────────
A_MIN=""; A_MAX=""
for i in $(seq 1 "$NCAND"); do
    as=$(sqlite3 "$SDB" "SELECT active_since_block FROM validators WHERE lower(hex(pubkey))='$(node_pkhex $(( C + i )))';")
    case "$as" in ''|*[!0-9]*) die "cannot read cand$i's active_since_block ('$as')" ;; esac
    if [ -z "$A_MIN" ] || [ "$as" -lt "$A_MIN" ]; then A_MIN="$as"; fi
    if [ -z "$A_MAX" ] || [ "$as" -gt "$A_MAX" ]; then A_MAX="$as"; fi
done
B=$(( (A_MAX / E + 1) * E ))
E_MID=$(( B + 2 * E ))
E_TEN=$(( E_MID - E ))
E_GROW=$(( E_MID + E ))
e_lo=$(( ((A_MIN + 2 * E + E - 1) / E) * E ))
[ "$e_lo" = "$E_MID" ] || die "the candidates' bonds straddle a boundary (active_since $A_MIN..$A_MAX, first-eligible $e_lo vs $E_MID) — the one-epoch 7 → 10 step this scenario asserts cannot be predicted; harness arithmetic, not a chain defect"
ok "bonds landed at heights $A_MIN..$A_MAX → copy boundary $B, tenure-closed epoch $E_TEN, first-eligible epoch $E_MID, growth epoch $E_GROW"

N_NEED=$(need_signers "$TOTAL" "$POWER")
N_NEED10=$(need_signers "$MID_TARGET" "$POWER")
STOP_A=$(( TOTAL - N_NEED ))
WINDOW=$(( N_NEED + 1 ))
[ "$STOP_A" = $(( C - 1 )) ] || die "at N=$TOTAL power $POWER cometbft needs $N_NEED signers, so $STOP_A may stop — this scenario's matrix stops exactly the $(( C - 1 )) genesis nodes 2..$C"
[ "$WINDOW" -le "$E" ] || die "pigeonhole window $WINDOW > E=$E (see the Rule N note in the header)"
info "quorum: N=$TOTAL needs $N_NEED signers ($STOP_A may stop, $(( STOP_A + 1 )) stall); N=$MID_TARGET needs $N_NEED10"

# ════════════════════════════════════════════════════════════════════
# STEP 3 — a target above the ceiling is refused by every genesis node
# ════════════════════════════════════════════════════════════════════
KEYS=""
for n in $(seq 1 $(( C * 2 / 3 + 1 ))); do KEYS="${KEYS:+$KEYS,}$(node_dir "$n")/identity"; done
for n in $(seq 1 "$C"); do
    lg="$BASE_DIR/grow_cc_illegal_node$n.log"
    irc=0
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" -i "$(node_dir 1)/identity" \
        v2-envelope chain-config --db "$SDB" --keys "$KEYS" --param 4 \
        --value "$ILLEGAL" --effective "$E_MID" --nonce $(( 77000 + n )) > "$lg" 2>&1 || irc=$?
    [ "$irc" != 0 ] || { cat "$lg" >&2; die "node $n ADMITTED a TARGET_ACTIVE_COUNT of $ILLEGAL (ceiling $V2_SET_MAX)"; }
    grep -q '^envelope built:' "$lg" || { cat "$lg" >&2; die "the $ILLEGAL envelope was not built locally — a client-side failure is not a node's refusal"; }
    grep -q 'dnac_spend RPC failed (rc=7 status=0)' "$lg" || { cat "$lg" >&2; die "node $n's answer to $ILLEGAL is not a CheckTx refusal (expected rc=7 status=0)"; }
done
ok "STEP 3 — TARGET_ACTIVE_COUNT=$ILLEGAL built locally and REFUSED by the CheckTx of all $C genesis nodes"

# ════════════════════════════════════════════════════════════════════
# STEP 2 — the two legal votes
# ════════════════════════════════════════════════════════════════════
# Approvals bind epoch(tip) and the committee resolved there (nodus-cli.c
# :1358 / :1905); do not vote in the last blocks of an epoch, where the
# envelope could land in the next one.
if [ $(( $(tip) % E )) -ge $(( E - 3 )) ]; then
    nb=$(( ($(tip) / E + 1) * E + 1 ))
    h=$(stagef_cmt_advance_to "$SDB" "$nb" 4) || die "could not step past the epoch edge to $nb (stuck at $h)"
fi
t_vote=$(tip)
floor_h=$(( t_vote + 1 + G ))
[ "$E_MID" -ge "$floor_h" ] || die "vote A (effective $E_MID) is below the grace floor $floor_h at tip $t_vote — harness arithmetic, not a chain defect"

# cc_wait VALUE EFFECTIVE DEADLINE LABEL — the row is the ledger effect;
# it must be committed before DEADLINE (the boundary that reads it).
cc_wait() {
    local v="$1" eff="$2" deadline="$3" label="$4" h wrc cb
    h=$(stagef_cmt_wait_row "$SDB" \
        "SELECT COUNT(*) FROM chain_config_history WHERE param_id=4 AND effective_block=$eff AND new_value=$v;" 3) \
        && wrc=0 || wrc=$?
    case "$wrc" in
        0) ;;
        1) die "$label: the chain_config_history row never appeared and the chain STALLED at $h" ;;
        *) die "$label: admitted but not included within 20 heights (tip $h) — dropped, not delayed" ;;
    esac
    cb=$(sqlite3 "$SDB" "SELECT commit_block FROM chain_config_history WHERE param_id=4 AND effective_block=$eff;")
    [ "$cb" -lt "$deadline" ] || die "$label committed at $cb, not before the boundary $deadline that reads it — harness timing, the vote cannot act"
    echo "$cb"
}

lgA="$BASE_DIR/grow_cc_voteA.log"; arc=0
"$CLI" -s 127.0.0.1 -p "$PORT1" -i "$(node_dir 1)/identity" chain-config propose \
    --param TARGET_ACTIVE_COUNT --value "$MID_TARGET" --effective "$E_MID" \
    --nonce 77101 > "$lgA" 2>&1 || arc=$?
[ "$arc" = 0 ] && grep -q 'proposal accepted' "$lgA" || { cat "$lgA" >&2; die "vote A (target $MID_TARGET at $E_MID, chain-config propose) was not admitted (rc=$arc)"; }
cbA=$(cc_wait "$MID_TARGET" "$E_MID" "$E_TEN" "vote A") || exit 1
ok "STEP 2 — vote A: target $MID_TARGET effective $E_MID committed at $cbA (networked approvals, verbs 40-41)"

lgB="$BASE_DIR/grow_cc_voteB.log"; brc=0
"$CLI" -s 127.0.0.1 -p "$PORT1" -i "$(node_dir 1)/identity" v2-envelope chain-config \
    --db "$SDB" --keys "$KEYS" --param 4 --value "$TOTAL" --effective "$E_GROW" \
    --nonce 77102 > "$lgB" 2>&1 || brc=$?
[ "$brc" = 0 ] && grep -q 'accepted: mempool CheckTx approved' "$lgB" || { cat "$lgB" >&2; die "vote B (target $TOTAL at $E_GROW) was not admitted over the SAME offline path the $ILLEGAL refusal used — so that refusal proves nothing about governance"; }
cbB=$(cc_wait "$TOTAL" "$E_GROW" "$E_MID" "vote B") || exit 1
ok "STEP 2b — vote B: target $TOTAL effective $E_GROW committed at $cbB (offline approvals — the control for STEP 3)"

wait_all_reach "$cbB" 3 $(seq 1 "$C")
# vote_rows_agree N... — each vote row identical, and no row for the
# illegal target, on every listed node.
vote_rows_agree() {
    local eff bad
    for eff in "$E_MID" "$E_GROW"; do
        assert_same "vote row effective $eff" \
            "SELECT new_value||':'||commit_block||':'||hex(tx_hash) FROM chain_config_history WHERE param_id=4 AND effective_block=$eff;" \
            "$@" >/dev/null
    done
    bad=$(assert_same "rows for $ILLEGAL" \
        "SELECT COUNT(*) FROM chain_config_history WHERE param_id=4 AND new_value=$ILLEGAL;" "$@")
    [ "$bad" = 0 ] || die "a chain_config row for the illegal target $ILLEGAL exists"
}
vote_rows_agree $(seq 1 "$C")
ok "STEP 2c — both vote rows byte-identical on all $C genesis nodes; no node holds $ILLEGAL"

# ════════════════════════════════════════════════════════════════════
# STEP 1c — the candidates come up as nodes and catch up BEFORE any
# boundary that could seat them (a seated node that cannot vote is a
# missing vote: at E_MID+2 the 10-set needs 7 of 10).
# ════════════════════════════════════════════════════════════════════
CHAIN_ID=$(cat "$BASE_DIR/v2_chain_id")
for i in $(seq 1 "$NCAND"); do
    n=$(( C + i )); d=$(node_dir "$n")
    # The genesis is a pure function of the config (stagef_up_v2.sh step 3):
    # derive it locally, exactly as the seven did, and CHECK it is the fleet's.
    if ! "$NODUS" --derive-v2-genesis "$CONF" -d "$d/data" > "$d/derive.log" 2> "$d/derive.err"; then
        cat "$d/derive.log" "$d/derive.err" >&2; die "cand$i's genesis derivation was refused"
    fi
    cid=$(awk '/^chain-id/{print $2}' "$d/derive.log")
    [ "$cid" = "$CHAIN_ID" ] || die "cand$i derived chain $cid, the fleet is $CHAIN_ID"
    start_node "$n"
done
for i in $(seq 1 "$NCAND"); do wait_listening $(( C + i )); wait_role_live $(( C + i )) 0; done
ok "STEP 1c — $NCAND candidates derived the fleet's chain ($CHAIN_ID) and are LIVE"
fleet=$(tip)
wait_all_reach "$fleet" 8 $(seq $(( C + 1 )) "$TOTAL")
ok "STEP 1c — all $NCAND candidates caught up to the fleet tip $fleet"

# ════════════════════════════════════════════════════════════════════
# STEP 5 — tenure + the frozen copy: E_TEN is still the genesis 7; and
# the premise of STEP 2: at E_MID all 20 are eligible, at equal power
# ════════════════════════════════════════════════════════════════════
h=$(stagef_cmt_advance_to "$SDB" $(( E_TEN + 1 )) 4) || die "could not reach $(( E_TEN + 1 )) (stuck at $h)"
wait_all_reach $(( E_TEN + 1 )) 4
for i in $(seq 1 "$NCAND"); do
    [ "$(in_copy $(( C + i )) "$B")" = "$BOND" ] || die "cand$i's bond is not in the frozen copy($B) — the arithmetic above is wrong"
done
cp=$(frozen_copy_check "$B")
[ "$cp" = "$TOTAL|1|$BOND" ] || die "copy($B) is not $TOTAL equal totals of $BOND: count|distinct|min = $cp"
eligible=0
for n in $(seq 1 "$TOTAL"); do
    r=$(sqlite3 "$SDB" "SELECT status||'|'||active_since_block FROM validators WHERE lower(hex(pubkey))='$(node_pkhex "$n")';")
    st=${r%%|*}; as=${r##*|}
    if { [ "$st" = 0 ] || [ "$st" = 4 ]; } && { [ $(( as + 2 * E )) -le "$E_MID" ] || [ "$as" -le 1 ]; } \
       && [ "$(in_copy "$n" "$B")" -gt 0 ]; then
        eligible=$(( eligible + 1 ))
    fi
done
[ "$eligible" = "$TOTAL" ] || die "only $eligible of $TOTAL are eligible for epoch $E_MID — claim 2's premise does not hold"
[ "$eligible" -gt "$MID_TARGET" ] || die "eligible $eligible is not above the vote $MID_TARGET — claim 2 would be vacuous"
ten=$(assert_same "epoch $E_TEN snapshot count" \
    "SELECT active_count FROM validator_set_snapshots WHERE epoch_start=$E_TEN;" $(seq 1 "$TOTAL"))
[ "$ten" = "$C" ] || die "epoch $E_TEN already has $ten seats — tenure/copy did not gate the candidates"
ok "STEP 5 — epoch $E_TEN is still $C seats on all $TOTAL nodes (tenure closed, copy($(( B - E ))) holds no candidate); $eligible eligible at $E_MID, all at frozen total $BOND"

# ════════════════════════════════════════════════════════════════════
# STEP 4 — the growth lands AT the boundaries, in the snapshot AND in
# cometbft's own voting set
# ════════════════════════════════════════════════════════════════════
# 4a — E_MID: the vote, not the default, sized it.
h=$(stagef_cmt_advance_to "$SDB" $(( E_MID + 2 )) 6) || die "the chain did not reach $(( E_MID + 2 )) after the 10-set took over (stuck at $h)"
wait_all_reach $(( E_MID + 2 )) 4
mid=$(assert_same "epoch $E_MID snapshot count" \
    "SELECT active_count FROM validator_set_snapshots WHERE epoch_start=$E_MID;" $(seq 1 "$TOTAL"))
[ "$mid" = "$MID_TARGET" ] || die "epoch $E_MID has $mid seats, not the voted $MID_TARGET ($eligible eligible; the default would seat $eligible)"
assert_same "epoch $E_MID snapshot hash" \
    "SELECT hex(snapshot_hash) FROM validator_set_snapshots WHERE epoch_start=$E_MID;" $(seq 1 "$TOTAL") >/dev/null
vuA=$(vu_line 1 "$E_MID")
[ -n "$vuA" ] || die "node1 logged no cometbft ValidatorUpdates line for boundary $E_MID"
for n in $(seq 2 "$TOTAL"); do
    [ "$(vu_line "$n" "$E_MID")" = "$vuA" ] || die "node $n's ValidatorUpdates line at $E_MID ($(vu_line "$n" "$E_MID")) differs from node1's ($vuA)"
done
read -r addA pcA remA <<< "$vuA"
[ $(( addA - remA )) = $(( MID_TARGET - C )) ] && [ "$addA" -gt 0 ] || \
    die "cometbft's update at $E_MID (added $addA, removed $remA) does not take $C to $MID_TARGET"
vset_switch "$E_MID"
ok "STEP 4a — epoch $E_MID: $mid seats (the vote; the default would seat $eligible), identical on $TOTAL nodes; cometbft added $addA, removed $remA (power changes $pcA)"

# 4b — E_GROW: growth to the full set.
h=$(stagef_cmt_advance_to "$SDB" $(( E_GROW + 2 )) 6) || die "the chain did not reach $(( E_GROW + 2 )) after the 20-set took over (stuck at $h)"
wait_all_reach $(( E_GROW + 2 )) 4
grown=$(assert_same "epoch $E_GROW snapshot count" \
    "SELECT active_count FROM validator_set_snapshots WHERE epoch_start=$E_GROW;" $(seq 1 "$TOTAL"))
[ "$grown" = "$TOTAL" ] || die "epoch $E_GROW has $grown seats, expected $TOTAL"
assert_same "epoch $E_GROW snapshot hash" \
    "SELECT hex(snapshot_hash) FROM validator_set_snapshots WHERE epoch_start=$E_GROW;" $(seq 1 "$TOTAL") >/dev/null
cp=$(frozen_copy_check "$E_TEN")
[ "$cp" = "$TOTAL|1|$BOND" ] || die "copy($E_TEN), the one epoch $E_GROW is ranked by, is not $TOTAL equal totals: $cp"
vuB=$(vu_line 1 "$E_GROW")
[ -n "$vuB" ] || die "node1 logged no cometbft ValidatorUpdates line for boundary $E_GROW"
for n in $(seq 2 "$TOTAL"); do
    [ "$(vu_line "$n" "$E_GROW")" = "$vuB" ] || die "node $n's ValidatorUpdates line at $E_GROW differs from node1's ($vuB)"
done
read -r addB pcB remB <<< "$vuB"
[ "$addB" = $(( TOTAL - MID_TARGET )) ] && [ "$remB" = 0 ] || \
    die "cometbft's update at $E_GROW (added $addB, removed $remB) does not take $MID_TARGET to $TOTAL"
vset_switch "$E_GROW"
vote_rows_agree $(seq 1 "$TOTAL")
stagef_sentinel TARGET_REACHED
ok "STEP 4b — epoch $E_GROW: $TOTAL seats identical on $TOTAL nodes; cometbft added $addB, removed 0 (power changes $pcB); both vote rows identical and no $ILLEGAL row on all $TOTAL"
agree_at_floor "STEP 4e — after growth"

# ════════════════════════════════════════════════════════════════════
# STEP 4f (P2P-PORT F6) — at N = 20 a node still answers its CLIENTS
# while it commits. The defect this guards (nodus/BUGS.md "P1 LIVENESS AT
# N≥20", measured by this scenario's first run at 0.19.79): the old 4004
# transport signed every message per peer with ML-DSA-87 on the event
# loop, and a node answered NO client for 5-15 s around every commit. The
# p2p port authenticates the connection once and AEAD-frames messages
# (p2p-port design §2), so the loop is free. Probed on node 1 (genesis)
# and cand1 (grown in) with `nodus-cli ping` (a fresh session each time:
# connect, HELLO/AUTH, PING) in a loop while the pump drives >= 3 commits;
# every probe must succeed. The bound is the CLI's OWN fixed 5 s per step
# (nodus-cli.c wait_response(5000)) — not a number of this script, never
# to be raised (timeout-tuning ban; the BUGS entry says the same).
# ════════════════════════════════════════════════════════════════════
PING_DIR="$BASE_DIR/grow_ping"
rm -rf "$PING_DIR"; mkdir -p "$PING_DIR"
ping_probe() {   # N OUTFILE — until $PING_DIR/stop exists
    local port s e r
    port=$(stagef_tcp_port "$(node_pidx "$1")")
    while [ ! -e "$PING_DIR/stop" ]; do
        s=$(date +%s%N)
        if "$CLI" -s 127.0.0.1 -p "$port" ping > /dev/null 2>&1; then r=0; else r=$?; fi
        e=$(date +%s%N)
        echo "$r $(( (e - s) / 1000000 ))" >> "$2"
    done
}
PING_NODES="1 $(( C + 1 ))"
ping_pids=()
for n in $PING_NODES; do
    ping_probe "$n" "$PING_DIR/node$n.txt" &
    ping_pids+=("$!")
done
p_h0=$(tip)
h=$(stagef_cmt_advance_to "$SDB" $(( p_h0 + 3 )) 4) || {
    touch "$PING_DIR/stop"; wait "${ping_pids[@]}" 2>/dev/null || true
    die "STEP 4f — the chain did not advance 3 heights at N=$TOTAL (stuck at $h)"
}
touch "$PING_DIR/stop"
wait "${ping_pids[@]}" 2>/dev/null || true
for n in $PING_NODES; do
    f="$PING_DIR/node$n.txt"
    [ -s "$f" ] || die "STEP 4f — no ping probe of node $n completed while the chain went $p_h0 -> $h"
    tot=$(awk 'END { print NR }' "$f")
    bad_p=$(awk '$1 != 0 { k++ } END { print k + 0 }' "$f")
    mx=$(awk 'BEGIN { m = 0 } $2 > m { m = $2 } END { print m }' "$f")
    if [ "$bad_p" != 0 ]; then
        die "STEP 4f — node $n failed $bad_p of $tot client pings while committing $p_h0 -> $h at N=$TOTAL (slowest ${mx} ms; raw: $f) — the node stopped serving clients around a commit"
    fi
    ok "STEP 4f — node $n answered all $tot client pings across commits $p_h0 -> $h at N=$TOTAL (slowest ${mx} ms, printed only)"
done

# ════════════════════════════════════════════════════════════════════
# STEP 6 — liveness at N = 20, equal power: 14 commit, 13 stall
# ════════════════════════════════════════════════════════════════════
declare -A VID
for n in $(seq 1 "$TOTAL"); do
    VID[$n]=$(stagef_voter_id "$(node_pk "$n")")
    [ "${#VID[$n]}" = 64 ] || die "could not derive node $n's voter_id"
done
last_signed() {
    sqlite3 "$SDB" "SELECT COALESCE(MAX(last_signed_height),-1) FROM v2_attendance WHERE lower(hex(voter_id))='${VID[$1]}';"
}

# Align to a fresh epoch start (Rule N — see the header), then stop the six.
b=$(( ($(tip) / E + 1) * E ))
h=$(stagef_cmt_advance_to "$SDB" "$b" 4) || die "could not reach the aligned boundary $b (stuck at $h)"
for n in $(seq 2 "$C"); do sigstop_node "$n"; done
tip_stop=$(tip)
ok "STEP 6a — nodes 2..$C SIGSTOPped at tip $tip_stop (boundary $b): $(( TOTAL - STOP_A )) of $TOTAL running, cometbft needs $N_NEED"

settle=$(( tip_stop + 3 ))   # one-block credit lag (test_cmt_dead_proposer.sh SETTLE)
h=$(stagef_cmt_advance_to "$SDB" "$settle" 6) || die "STEP 6a — with $STOP_A of $TOTAL stopped the chain did NOT reach $settle (stuck at $h) — $(( TOTAL - STOP_A )) is exactly cometbft's majority and it must commit"
declare -A FROZEN
for n in $(seq 2 "$C"); do FROZEN[$n]=$(last_signed "$n"); done
target=$(( tip_stop + WINDOW ))
h=$(stagef_cmt_advance_to "$SDB" "$target" 6) || die "STEP 6a — the chain did not reach $target with $STOP_A stopped (stuck at $h)"
for n in $(seq 2 "$C"); do
    [ "$(last_signed "$n")" = "${FROZEN[$n]}" ] || die "stopped node $n's attendance MOVED after the settle point (${FROZEN[$n]} -> $(last_signed "$n"))"
done
for n in 1 $(seq $(( C + 1 )) "$TOTAL"); do
    ls_n=$(last_signed "$n")
    [ "$ls_n" -gt "$settle" ] || die "running node $n's attendance did not move past $settle ($ls_n) — at exact majority every running validator's precommit is required, so its absence means the voting set is not what this scenario thinks"
done
ok "STEP 6a — $STOP_A of $TOTAL stopped: tip $tip_stop -> $h (>= $WINDOW heights, a stopped round-0 proposer by pigeonhole); the $STOP_A signed nothing, all $(( TOTAL - STOP_A )) running signed"

# 6b — one more stopped: 13 of 20, below the majority.
V7=$TOTAL                      # cand13
sigstop_node "$V7"
tip_b=$(tip)
keys=$(stagef_pump_keys); pfp=$(cat "$keys/nodus.fp")
amt=$(stagef_pump_largest "$SDB")
[ "$amt" -gt "$STAGEF_PUMP_FEE_RAW" ] || die "STEP 6b — the pump funder holds no coin above the fee; nothing could be submitted, a stall would be untested"
# One pump step's spend (the same CLI line as stagef_env.sh stagef_cmt_pump_to,
# :807-823), submitted WITHOUT waiting — its inclusion is the subject.
out=$("$CLI" -s 127.0.0.1 -p "$PORT1" v2-envelope spend --keys "$keys" --to "$pfp" \
        --amount "$(( amt - STAGEF_PUMP_FEE_RAW ))" --fee "$STAGEF_PUMP_FEE_RAW" --no-dust-sweep \
        --submit "127.0.0.1:$PORT1" 2>&1) || { printf '%s\n' "$out" >&2; die "STEP 6b — the probe spend was not admitted; a stall would be untested"; }
intent=$(awk -F= '/^  intent_id=/ && !d {print $2; d=1}' <<< "$out")
[ "${#intent}" = 128 ] || { printf '%s\n' "$out" >&2; die "STEP 6b — the probe spend printed no intent_id"; }
stall_at=$(stagef_cmt_wait_row "$SDB" "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash))='$intent';" 3) \
    && src=0 || src=$?
case "$src" in
    1) ;;
    0) die "STEP 6b — with $(( STOP_A + 1 )) of $TOTAL stopped the chain COMMITTED the probe spend (tip $stall_at) — $(( TOTAL - STOP_A - 1 )) signers are below cometbft's majority $N_NEED" ;;
    *) die "STEP 6b — the chain kept committing (tip $tip_b -> $stall_at) with $(( STOP_A + 1 )) of $TOTAL stopped" ;;
esac
[ "$stall_at" -le $(( tip_b + 2 )) ] || die "STEP 6b — the tip moved $tip_b -> $stall_at after the 7th stop: more than the 2-height in-flight allowance"
ok "STEP 6b — $(( STOP_A + 1 )) of $TOTAL stopped: NO height for 3 consecutive intervals with a spend pending (tip $tip_b -> $stall_at) — the expected safety stall"

# 6c — resume: the pending spend lands, the chain goes on, everyone agrees.
resume_stopped
h=$(stagef_cmt_wait_row "$SDB" "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash))='$intent';" 6) \
    && rrc=0 || rrc=$?
[ "$rrc" = 0 ] || die "STEP 6c — after resuming, the pending spend did not land (wait rc=$rrc, tip $h) — the chain did not recover"
rec_h=$(sqlite3 "$SDB" "SELECT block_height FROM utxo_set WHERE lower(hex(tx_hash))='$intent' LIMIT 1;")
h=$(stagef_cmt_advance_to "$SDB" $(( $(tip) + 3 )) 4) || die "STEP 6c — the chain did not keep committing after recovery (stuck at $h)"
wait_all_reach "$h" 4
stagef_cmt_diff_at_floor "post-liveness-matrix (genesis 7)" || exit 2
agree_at_floor "STEP 6c — after the liveness matrix"
ok "STEP 6c — all resumed: the pending spend landed at $rec_h, tip $h, all $TOTAL nodes agree"

# ════════════════════════════════════════════════════════════════════
# STEP 7 — the 20-seat set survives a full stop/start of every node
# ════════════════════════════════════════════════════════════════════
before=$(tip)
for n in $(seq 1 "$TOTAL"); do kill_node "$n"; done
declare -A OFF
for n in $(seq 1 "$TOTAL"); do OFF[$n]=$(log_lines "$n"); start_node "$n"; done
for n in $(seq 1 "$TOTAL"); do wait_listening "$n"; wait_role_live "$n" "${OFF[$n]}"; done
h=$(stagef_cmt_advance_to "$SDB" $(( before + 2 )) 4) || die "STEP 7 — the chain did not resume after a full restart at committee $TOTAL (stuck at $h, was $before)"
wait_all_reach "$h" 4
c=$(assert_same "post-restart committee" \
    "SELECT active_count FROM validator_set_snapshots ORDER BY epoch_start DESC LIMIT 1;" $(seq 1 "$TOTAL"))
[ "$c" = "$TOTAL" ] || die "STEP 7 — the latest snapshot seats $c after the restart, expected $TOTAL"
ok "STEP 7 — all $TOTAL stopped and restarted: the chain resumed ($before -> $h) and the latest snapshot still seats $TOTAL"

# ════════════════════════════════════════════════════════════════════
# STEP 8 — a node misses an epoch boundary and catches up
# ════════════════════════════════════════════════════════════════════
V8=$(( C + 12 ))               # cand12: not stopped in STEP 6
b2=$(( ($(tip) / E + 1) * E ))
h=$(stagef_cmt_advance_to "$SDB" "$b2" 4) || die "could not reach the aligned boundary $b2 (stuck at $h)"
kill_node "$V8"
missed=$(( b2 + E ))
h=$(stagef_cmt_advance_to "$SDB" $(( missed + 1 )) 4) || die "STEP 8 — the chain did not reach $(( missed + 1 )) with cand12 down (stuck at $h)"
vt=$(stagef_cmt_tip "$(node_db "$V8")")
[ "$vt" -lt "$missed" ] || die "STEP 8 — cand12's tip $vt is not below the boundary $missed it was supposed to miss"
off=$(log_lines "$V8"); start_node "$V8"; wait_listening "$V8"; wait_role_live "$V8" "$off"
fleet=$(tip)
vt=$(stagef_cmt_wait_height "$(node_db "$V8")" "$fleet" 4) || die "STEP 8 — cand12 did not catch up (stuck at $vt, fleet $fleet)"
wait_all_reach "$fleet" 4
assert_same "snapshot written at the missed boundary $missed" \
    "SELECT active_count||':'||hex(snapshot_hash) FROM validator_set_snapshots WHERE epoch_start=$(( missed + E ));" \
    $(seq 1 "$TOTAL") >/dev/null
agree_at_floor "STEP 8 — after catch-up"
ok "STEP 8 — cand12 was down across boundary $missed, caught up to $vt and agrees on the snapshot that boundary wrote"

# ════════════════════════════════════════════════════════════════════
# STEP 9 — a node that was never there replays genesis → head
# ════════════════════════════════════════════════════════════════════
FRESH="$BASE_DIR/grow_replay"
FIDX=$(( C + 3 + NCAND + PUMP_IDS ))   # past every port block the bring-up used
mkdir -p "$FRESH/identity" "$FRESH/data"
PIN=$(cat "$BASE_DIR/v2_genesis_pin")
[ "${#PIN}" = 64 ] || die "recorded pin is not 64 hex characters"
"$NODUS" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
    -u "$(stagef_udp_port "$FIDX")" -t "$(stagef_tcp_port "$FIDX")" \
    -p "$(stagef_peer_port "$FIDX")" -C "$(stagef_chan_port "$FIDX")" \
    -W "$(stagef_witness_port "$FIDX")" \
    --v2-genesis-pin "$PIN" -i "$FRESH/identity" -d "$FRESH/data" "${SEEDS[@]}" \
    >> "$FRESH/nodus.log" 2>&1 &
echo "$!" >> "$BASE_DIR/pids.txt"
fdb=""
for _ in $(seq 1 600); do
    fdb=$(largest_db "$FRESH/data")
    [ -n "$fdb" ] && break
    sleep 1
done
[ -n "$fdb" ] || { tail -30 "$FRESH/nodus.log" >&2; die "STEP 9 — the joiner never adopted a chain in 600 s"; }
[ "$(basename "$fdb")" = "$(basename "$SDB")" ] || die "STEP 9 — the joiner adopted $(basename "$fdb"), the fleet is $(basename "$SDB")"
r=0; l=0
for _ in $(seq 1 90); do
    grep -q 'chain role: COMETBFT' "$FRESH/nodus.log" && r=1
    grep -q 'cometbft lane LIVE' "$FRESH/nodus.log" && l=1
    [ "$r$l" = 11 ] && break
    sleep 1
done
[ "$r$l" = 11 ] || die "STEP 9 — the joiner has the chain but no COMETBFT role + lane LIVE (role=$r live=$l)"
head_h=$(tip)
fh=$(stagef_cmt_wait_height "$fdb" "$head_h" 4) || die "STEP 9 — the joiner did not replay to head $head_h (stuck at $fh)"
for hh in "$E_MID" "$E_GROW" $(( E_GROW + 1 )) "$head_h"; do
    a=$(sqlite3 "$SDB" "SELECT hex(global_root)||'|'||hex(block_id) FROM v2_blocks WHERE global_height=$hh;")
    bb=$(sqlite3 "$fdb" "SELECT hex(global_root)||'|'||hex(block_id) FROM v2_blocks WHERE global_height=$hh;")
    [ -n "$a" ] && [ -n "$bb" ] || die "STEP 9 — block $hh missing on one side"
    [ "$a" = "$bb" ] || die "STEP 9 — replayed block $hh differs from the fleet's"
done
for ee in "$E_MID" "$E_GROW"; do
    a=$(sqlite3 "$SDB" "SELECT active_count||':'||hex(snapshot_hash) FROM validator_set_snapshots WHERE epoch_start=$ee;")
    bb=$(sqlite3 "$fdb" "SELECT active_count||':'||hex(snapshot_hash) FROM validator_set_snapshots WHERE epoch_start=$ee;")
    [ -n "$a" ] && [ "$a" = "$bb" ] || die "STEP 9 — the joiner's snapshot for epoch $ee differs ($bb vs $a)"
done
ok "STEP 9 — a node that was never there adopted by pin and replayed genesis → $fh, both growth boundaries ($E_MID, $E_GROW) identical"

# ════════════════════════════════════════════════════════════════════
# TERMINAL — the set is still the 20, nobody was retired, all agree
# ════════════════════════════════════════════════════════════════════
retired=$(sqlite3 "$SDB" "SELECT COUNT(*) FROM validators WHERE status=3;")
[ "$retired" = 0 ] || die "$retired validator(s) AUTO_RETIRED — the Rule N alignment premise of STEP 6/8 failed"
last_c=$(sqlite3 "$SDB" "SELECT active_count FROM validator_set_snapshots ORDER BY epoch_start DESC LIMIT 1;")
[ "$last_c" = "$TOTAL" ] || die "the latest snapshot seats $last_c, not $TOTAL"
h=$(tip)
wait_all_reach "$h" 4
stagef_cmt_wait_height "$fdb" "$h" 4 >/dev/null || die "the joiner fell behind $h"
stagef_sentinel ASSERT_RUN
stagef_cmt_diff_at_floor "post-v2-grow (genesis 7)" || exit 2
agree_at_floor "post-v2-grow (all $TOTAL + joiner)" "$fdb"

stagef_sentinel PASS
echo
echo "[PASS] a Comet committee grew $C → $mid → $TOTAL by governance (votes at $E_MID / $E_GROW),"
echo "       cometbft's own set followed both boundaries, and at N=$TOTAL with equal power the"
echo "       chain committed with $(( TOTAL - STOP_A )) running and stalled with $(( TOTAL - STOP_A - 1 )), then recovered;"
echo "       the set survived a full restart, a missed boundary and a cold replay."
# Report the parameters the BINARY carries, not what the shell holds: the
# ceremony refuses a config whose epoch length disagrees with the binary
# (stagef_up_v2.sh:333-340), so E is the binary's; the grace is read from
# the build's own CMakeCache when it is there.
_grace="unknown (compiled in; not readable from this script)"
_cache="$(dirname "$STAGEF_NODUS_BIN")/CMakeCache.txt"
if [ -f "$_cache" ]; then
    _g=$(grep -m1 -o 'DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=[0-9]*' "$_cache" || true)
    _g=${_g%%$'\n'*}; _g=${_g##*=}
    if [ -n "$_g" ]; then _grace="$_g (from the binary's CMakeCache)"; fi
fi
echo "       Parameters: DNAC_EPOCH_LENGTH=$E, SAFETY grace $_grace. This proves the LOGIC"
echo "       at those constants and nothing about production magnitudes (720 / 17280)."
exit 0
