#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_hf7.sh — HF-7 P1e: the generation-5 (roots) edge on a 7-node
# chain — param 22 RULESET_GEN_ROOTS = D5 voted on a generation-4 chain,
# the registry switch 4 -> 5 and the one-time last_upd_hash seed at the
# end of A−1, then the v2_replay relation as the only replay guard from A:
# rows written for applied envelopes, a pre-A envelope dead at A, a
# replayed intent refused, rows pruned at their expiry — 7/7 identical
# (standalone — NOT in the sweep).
# ════════════════════════════════════════════════════════════════════
#
# Governing records: snapshot design docs/plans/2026-09-11-nodus-ledger-
# snapshot-design.md §10.2 (items 1-8), §10.3 (the transition matrix),
# §10.5 P1e, §10.9 (rev 1), §10.11 (khan decisions A-D: no row cap,
# param 22 ERGONOMIC, D5 binds 720 only, expiry_height INTEGER), §10.12;
# decision docs/plans/decisions/2026-10-20-kurultay-27-hf7-p1-summary.md
# items 1 (pre-A envelopes are dead at A), 2 (edge at the end of A−1, A−1's
# replay set EMPTY), 3 (rows inside the item's savepoint, prune
# expiry <= H), 4 (the D2 predicate), 5 (every guard caller on v2_replay),
# 9 (the test list). TEMPLATE: test_hf6_edge.sh — its vote helpers
# (cc_guard / propose / wait_cc_row / ruleset_info / require_gen /
# cross_edge / same_on_all) and its generation 2 -> 3 -> 4 path are copied
# WITHOUT its HF-6 slice-5d delegation; the pump is stagef_env.sh's
# stagef_cmt_pump_to; the multisig flow is test_cmt_multisig.sh's; every
# new part is marked "hf7:".
#
# WHY SIX VOTES: the generation-5 edge is triggered by the param-22 row
# with DNAC_CFG_RULESET_GEN_ROOTS_D (D5) (nodus_witness_v2_apply.c
# phase_6b_gen5_edge). Param 22 is votable only while generation EXACTLY 4
# judges the vote, with HF-2 on, once ever, A−1 and A off an epoch boundary
# (nodus_witness_chain_config.c CC_PARAM_RULESET_GEN_ROOTS rules (a)-(e));
# generation 4 needs param 18 (RULESET_GEN_ROLES = D4) under generation 3,
# which needs EVM_ACTIVE (14), RULESET_GEN2 (9), HF3_ACTIVE (8) and
# HF2_ACTIVE (7) — so 7, 8, 9, 14, 18 and 22 are voted, in that order.
#
# WHY H % E == 8 AND A % E == 8: rules (d) and (e) of params 18 and 22
# forbid the edge block and the first block after it on a boundary. With
# A % E == 8 the last boundary before A is A − 8 and the first after it is
# A + 7, so the edge reads (tip in [A − 1, A + 6]) sit in a window no
# boundary writes into (a boundary touches SYSTEM and would move a head —
# nodus_witness_v2_apply.c phase 6e's touched declaration).
#
# WHAT IT PROVES — each item would be false if it failed
#   0. Capability gate (FAIL): the server and the CLI print one version
#      banner; the CLI's chain-config usage names "EVM_ACTIVE exactly
#      <D>", "RULESET_GEN_ROLES exactly <D4>" and "RULESET_GEN_ROOTS
#      exactly <D5>" (compiled literals, never a script literal); node 1's
#      database is schema S19 (v2_replay exists, v2_domain_heads has
#      last_upd_hash); every node's NEWEST start logged "HF-6 rule-set
#      generation 4 vote D4 0x<D4> (param 18 …)" and "HF-7 rule-set
#      generation 5 vote D5 0x<D5> (param 22 RULESET_GEN_ROOTS, switch spec
#      v1)" (nodus_witness.c) with the CLI's D4 / D5 — the runbook's 7/7
#      pre-vote comparison, so the D5 voted is every server's compiled D5.
#   1. Preconditions: a fresh chain (no param 7 / 8 / 9 / 14 / 16 / 18 /
#      22 row, no roles row, an empty v2_replay), the bring-up's genesis
#      2-of-3 coin present.
#   2. HF2_ACTIVE, HF3_ACTIVE, RULESET_GEN2, EVM_ACTIVE, RULESET_GEN_ROLES
#      voted and crossed, each row identical 7/7 and committed below its
#      effective height; generation 4 on 7/7 (ruleset-info), the HF-6 edge
#      line on 7/7, blocks AT H−1 / H / H+1 identical 7/7.
#   3. RULESET_GEN_ROOTS = D5 voted at A (A % E == 8): round 1 7/7, row
#      identical 7/7, committed < A; generation 4 still on 7/7.
#   4. hf7 (summary item 1, the CORE half): a 2-of-3 envelope over the
#      genesis multisig coin is BUILT and SIGNED while generation 4 is in
#      force (its CORE leg names v9), with an expiry beyond A.
#   5. THE A−1 CELL, read at tip in [A − 1, A + 6] with NO envelope above
#      the tip the pump returned at (≤ A − 2; Σ v2_blocks.tx_count = 0),
#      ONE SQL statement per node:
#      v2_replay EMPTY on 7/7 (A−1 inserts nothing — §10.3); every
#      v2_domain_heads row's last_upd_hash a 64-byte BLOB (the seed ran);
#      no head disagrees with its v2_root_history mirror row at the head's
#      own domain_height (the mirror the seed and phase 9 check); the
#      (domain_id, last_upd_hash) list identical on 7/7.
#   6. THE PUMP-PATH SPEND P (stagef_env.sh's CLI-SPEND step: node 3's
#      largest coin back to itself, 1-in/1-out, --no-dust-sweep), submitted
#      at tip A−1 (built under generation 5): CheckTx admits it, it is
#      applied at h_P >= A (printed; "AT A" only when h_P == A), its
#      v2_replay row (tx_id = the submit's wire_id, intent_id, expiry) is
#      IDENTICAL on 7/7 and its expiry e_P satisfies D2 at its own block
#      (h_P <= e_P <= h_P + 720) and the CLI's CheckTx window
#      (tip_b + 1 <= e_P <= tip_b + NODUS_CMT_APP_MAX_EXPIRY_AHEAD).
#   7. The edge itself: blocks AT A−1 / A / A+1 identical 7/7; every node
#      logged "HF-7: rule-set generation 4 -> 5 and the head last_upd_hash
#      seed at the end of height A−1 (param 22 RULESET_GEN_ROOTS, D5
#      0x<D5>); height A is judged under generation 5"; the SYSTEM and CORE
#      v2_root_history rows AT global_height A−1 are identical 7/7 and name
#      SYSTEM v11 / CORE v10 (generation 5 — read from
#      nodus_ruleset_pins.h G5), the rows below A−1 name v10 / v9
#      (generation 4); ruleset-info 7/7 = generation 5, SYSTEM / CORE
#      versions and hashes = the A−1 rows.
#   8. hf7 (summary item 1): step 4's generation-4 envelope, submitted
#      after A with an expiry still ahead, is REFUSED by the node (CLI
#      "refused: rc=… node=…", never "failed:") and never included.
#   9. hf7 (summary item 9, "same-intent / different-wire"): a 2-of-3
#      envelope M over the SAME genesis coin, built under generation 5 and
#      signed by nodes 2, 3 AND 4 before anything is submitted, combined
#      with nodes 2 + 3 and applied — its v2_replay row identical 7/7, D2
#      at its block; then
#        9a. the SAME bytes re-submitted (combine 2 + 3 again; the printed
#            wire_id is the first one) — refused by the node;
#        9b. the SAME intent under a DIFFERENT authorization (combine
#            2 + 4: another wire_id, the same intent_id) — refused by the
#            node with "intent or wire id already committed on this chain"
#            (nodus_witness_verify.c, the v2_replay guard, which CheckTx
#            runs BEFORE the dry run that would find the input spent).
#  10. Prune: pumped to e_P − 1, every node's ONE-statement read of P's row
#      satisfies "present ⇔ tip < e_P" (never pruned early); pumped to
#      max(e_P, e_M), P's and M's rows are gone on 7/7; and on every node
#      no v2_replay row has expiry_height <= the same statement's tip
#      (the prune `expiry <= H` held at every committed tip).
#  11. The end: on 7/7 v2_tx_index holds M's first wire_id once and
#      neither the step-4 envelope's nor the 9b wire_id; v2_intent_index
#      holds M's intent once and not the step-4 envelope's; 7/7 identical
#      global_root + block_id at the final floor.
#
# WHAT IT REQUIRES
#   Compile flags — ONE short-epoch + short-grace build of THIS tree (an
#   HF-7 branch carrying P1a-P1d: schema S19, the gen-5 wiring, the edge,
#   param 22, the D5 literal), nodus-server AND nodus-cli from the SAME
#   build, with NODUS_EVM_ENABLED (the default of the standalone
#   non-Windows nodus build — the generation-4 AND generation-5 edges FAULT
#   without it):
#     -DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#   (params 7, 8, 9, 18, 22 are ERGONOMIC — 22 by khan decision B; param
#   14 is SAFETY.)
#   THE FOUNDATION OWNER: the default build compiles the K8 owner and its
#   D4 / D5 literals. This scenario reads no owner. A build that overrides
#   the owner with -DDNAC_HF6_FOUNDATION_OWNER='{…}' MUST also carry
#   -DDNAC_CFG_RULESET_GEN_ROLES_D=<that owner's D4> AND
#   -DDNAC_CFG_RULESET_GEN_ROOTS_D=<that owner's D5> (stagef_hf6_owner.sh
#   prints all three) — otherwise every node REFUSES TO START (the runtime
#   selfcheck re-derives both literals), the bring-up fails visibly.
#   Environment, ALL exported BEFORE stagef_up_v2.sh unless noted:
#     STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN    that build
#     STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15  (read by this
#         script only)
#   Leave STAGEF_PAYOUT_INTERVAL_EPOCHS unset (24) and STAGEF_MODE unset
#   (combined). No variable of its own.
#   The bring-up's genesis 2-of-3 coin ($BASE_DIR/msig_genesis_2of3.desc,
#   msig_genesis.addr — written by stagef_up_v2.sh when its nodus-cli has
#   `msig address`, i.e. a CLI of this tree): absent -> SKIP.
#   Tools: sqlite3, ss.
#   Exact command sequence (ORCHESTRATOR):
#     F='-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
#     cmake -S <TREE>/nodus -B <TREE>/nodus/build-shortepoch -DCMAKE_C_FLAGS="$F"
#     make -C <TREE>/nodus/build-shortepoch -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN=<TREE>/nodus/build-shortepoch/nodus-server
#     export STAGEF_NODUSCLI_BIN=<TREE>/nodus/build-shortepoch/nodus-cli
#     export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     S=<TREE>/nodus/tests/integration/stagef
#     bash $S/stagef_up_v2.sh
#     bash $S/tests/test_cmt_hf7.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   SKIP (rc 99): a binary missing / not executable, STAGEF_EPOCH_LENGTH
#   or the genesis epoch_length != 15, a grace variable != 15, not a Comet
#   cluster, no $BASE_DIR/v2_genesis.conf, no genesis multisig coin files,
#   a tool missing, any split STAGEF_MODE (ruleset-info, the vote path and
#   the msig flow were not checked through a split core). A skip is not a
#   pass.
#   FAIL (rc 1) on the capability gate, on a chain that already holds a
#   param 7 / 8 / 9 / 14 / 16 / 18 / 22 row, a roles row or a v2_replay row,
#   or whose genesis multisig coin is already spent (single-use — needs a
#   fresh bring-up).
#
# WHAT IT LEAVES BEHIND
#   HF-2 ACTIVE, HF-3 ACTIVE, rule-set generations 2, 3 (+ the EVM domain),
#   4 (HF-6) and 5 (HF-7) — all one-way; six chain_config_history rows
#   (params 7, 8, 9, 14, 18, 22). The HF-6 migration's rows (validators
#   re-keyed to validator_id, 2M bonds + 8M Foundation-owned
#   self-delegations, seven v2_validator_roles / v2_consensus_keys rows).
#   Every head's last_upd_hash seeded. Node 3's genesis leaf claimed by the
#   pump; every pump fee and the multisig fee in the reward pool; the
#   genesis 2-of-3 coin spent (GSEND raw to node 5, the change back to the
#   address); v2_replay holding only the rows of the last ≤ 100 blocks'
#   envelopes. $BASE_DIR/hf7/ (CLI logs, two exports, five signature
#   files). Nothing killed or restarted. Tear down with stagef_down.sh
#   before re-running (every vote and the genesis multisig coin are
#   single-use).
#
# HOW IT CAN LIE
#   - **ONE build, no rolling upgrade.** Every node runs the HF-7 binary
#     from bring-up on. The live order — an OLD (pre-S19) fleet rolled one
#     node at a time onto the new binary, the S19 migration at start, then
#     the vote (DEPLOY_RUNBOOK §2.2 HF-7 row) — is NOT exercised; an old
#     binary refusing (or accepting) the param-22 proposal, a node that
#     missed the S19 migration, a mixed fleet at A: none of it is here.
#     The snapshot design's P1e line asked for an OLD/NEW pair; this
#     dispatch is the one-build form.
#   - **E = 15, grace 15/15, BPY 20 prove the LOGIC**, nothing about the
#     production 720 / 720 / 6 307 200 (README "WHAT A GREEN HARNESS RUN
#     DOES NOT PROVE"). The expiry window D2 (720) is NOT shortened: every
#     envelope this CLI builds expires tip + 90, far inside it.
#   - **Every node runs the same binary**: a generation-5 reader forgotten
#     UNIFORMLY (a root leg composed wrongly, SYSTEM v6 / GLOBAL v2 built
#     from the wrong bytes) computes the same wrong value on all seven, and
#     7/7 identity cannot see it. The root compositions (S1-S8) are the
#     KAT's (hf7_root_coverage_kat.json, test_* unit tests), never decoded
#     here: this scenario sees global_root + block_id identity and the
#     node's own version rows, not the bytes inside the roots.
#   - **The A−1 cell is read from the logs and the DB, not from a root
#     decode.** "SYSTEM v6 (12 legs)", "segment leaves v2", "DomainHead v2",
#     "GLOBAL v2 with the EMPTY replay root" are NOT observed directly: what
#     is read is the edge's own log line, the v2_root_history rows at A−1
#     (ruleset_version), the empty v2_replay, the seeded head column and
#     7/7 identity of the block AT A−1.
#   - **No segment exists**: no storage node is registered and the first
#     archive segment (P = 360 at E = 15) is not published on this
#     cluster, so the segment re-tag at A−1 (§10.3 "segment leaves v2")
#     moves nothing here — ABSENT coverage.
#   - **An envelope with expiry outside D2 is NOT built — ABSENT
#     coverage.** Every nodus-cli builder takes its expiry from
#     cli_env_expiry (tip + NODUS_CMT_APP_MAX_EXPIRY_AHEAD − 10); the one
#     --expiry flag (`validator consent` / `storage consent`) is a consent
#     expiry, not an envelope's. CheckTx would refuse an out-of-window
#     expiry anyway, so only a Byzantine PROPOSER could place one in a
#     block — the ProcessProposal whole-block refusal and the FinalizeBlock
#     FAULT (§10.9, summary item 4) are the unit tests', not this
#     scenario's.
#   - **The EVM half of summary item 1 is ABSENT.** A generation-4 EVM
#     envelope cannot be held across A with this CLI: `evm send` builds,
#     submits and waits for its receipt in one call and writes no envelope
#     file. The CORE half (step 8) is exercised; the EVM pair rule is the
#     pinned unit test's.
#   - **9a is refused by the MEMPOOL CACHE, not by v2_replay.** cometbft
#     keeps committed txs in its LRU cache (shared/dnac/cmt_mem.c Update,
#     the `mem.cache.Push(tx)` of a code-OK result; cache size 10 000), so
#     identical bytes are ordinarily answered "duplicate transaction"
#     (nodus_witness_handlers.c, CMT_MEM_ERR_TX_IN_CACHE) before the
#     application's CheckTx runs; only an evicted entry would reach the
#     guard. The script asserts a node refusal, not which layer gave it. The v2_replay guard is reached by 9b
#     (other bytes, same intent), whose node text is asserted. The
#     wire_id half of the guard ("intent OR wire id") is not separable
#     here: a different wire with the same intent hits the intent half.
#   - **The block-path guard is NOT reached**: an honest proposer never
#     selects a replayed envelope (CheckTx refuses it first), so the item
#     loop's / dry run's / proposal seam's v2_replay lookups are the unit
#     tests' (summary item 5) — this scenario proves admission refuses and
#     nothing is included.
#   - **"AT A" is best effort.** P is submitted at tip A−1; whether it is
#     in block A or a later one is the mempool's timing (README "What
#     flips", DELTA 2). The PASS line says which; the A column with an
#     applied item is exercised only when it says "AT A".
#   - **Same-block in-batch duplicates, failed-item rollback, restart
#     around the edge, block sync across A, the S19 migration of an old
#     database** (summary item 9) are NOT exercised — unit tests and
#     restart scenarios.
#   - **The step-8 refusal reason is printed, not asserted**: the node may
#     refuse at entry identity (the preflight's version pin) or at the
#     verification lane's preflight; either way the CORE v9 leg is what
#     differs, but which exact check fired is not pinned by this script.
#   - **The A−1 window is wall-clock-adjacent** (idle production ≈ 60 s
#     per block): a read outside [A − 1, A + 6], or any envelope inside it
#     before P, FAILs as "layout broke" — a false RED, never a false PASS.
#     Every proposal is kept away from an epoch boundary (cc_guard).
#   - The log lines are asserted, but they are the node's own words —
#     the table checks are the proof.
#   - Every wait is progress- and height-bounded (stagef_cmt_wait_height /
#     _wait_row / stagef_cmt_pump_to), never a bare sleep. rc 99 = SKIP,
#     coverage that did not happen.
#   - Duration: ≈ 450 blocks (JUDGMENT, not measured): the generation-4
#     path of test_hf6_edge.sh without its delegation and boundaries
#     (≈ 300), the param-22 grace and the idle crossing (≈ 35), and ≈ 100
#     pumped blocks to the prune height — on the order of 1.5-2 h.
#   - Run results: none — written against the source, NOT run by its
#     author.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"
# hf7: ruleset-info, the vote path and the msig flow were not checked
# through a split core — SKIP (99) in every split mode (the HF-6 rule).
stagef_split_skip_if --reason "HF-7 scenario not checked through a split core" \
    $(seq 1 "$STAGEF_COMMITTEE_SIZE")

die() { echo "[FAIL] $*" >&2; exit 1; }

S_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRV="$STAGEF_NODUS_BIN"
CLI="$STAGEF_NODUSCLI_BIN"
PARAM_HF2=7                # DNAC_CFG_HF2_ACTIVE (dnac.h), value exactly 1
PARAM_HF3=8                # DNAC_CFG_HF3_ACTIVE (dnac.h), value exactly 1
PARAM_GEN2=9               # DNAC_CFG_RULESET_GEN2 (dnac.h), value exactly D2
PARAM_EVM=14               # DNAC_CFG_EVM_ACTIVE (dnac.h), value exactly D
PARAM_RET16=16             # DNAC_CFG_RULESET_GEN_STORAGE — RETIRED
PARAM_HF6=18               # DNAC_CFG_RULESET_GEN_ROLES (dnac.h), value exactly D4
PARAM_HF7=22               # hf7: DNAC_CFG_RULESET_GEN_ROOTS (dnac.h), value exactly D5
GEN_2=2                    # NODUS_RT_GEN_2
GEN_EVM=3                  # NODUS_RT_GEN_EVM
GEN_4=4                    # NODUS_RT_GEN_STORAGE (= NODUS_RT_GEN_ROOTS_BASE)
GEN_5=5                    # hf7: NODUS_RT_GEN_ROOTS (nodus_witness_runtime.h)
DOM_SYSTEM=0               # DNA_DOMAIN_SYSTEM (shared/dnac/ledger_ids.h)
DOM_CORE=1                 # DNA_DOMAIN_CORE
GRACE_MARGIN=5             # the HF-2/HF-3/HF-4 template's +5
WINDOW_MARGIN=5            # the EVM template's F5 window margin
CC_GUARD_GAP=4             # the EVM template's epoch-boundary guard
PUMP_STOP_GAP=7            # the HF-4 template's idle window before an edge
EDGE_MOD=8                 # H % E and A % E (header, "WHY ... == 8")
E_REQ=15
E="$E_REQ"
SPENDER=5                  # hf7: submits the multisig envelopes, receives GSEND
GSEND=30000000000          # hf7: 300 NODUS out of the genesis 2-of-3 coin
CONF="$BASE_DIR/v2_genesis.conf"
LOGD="$BASE_DIR/hf7"
MSIG_DESC="$BASE_DIR/msig_genesis_2of3.desc"
MSIG_ADDR_FILE="$BASE_DIR/msig_genesis.addr"
N="$STAGEF_COMMITTEE_SIZE"
PINS_H="$STAGEF_REPO_ROOT/nodus/include/nodus/nodus_ruleset_pins.h"
TYPES_H="$STAGEF_REPO_ROOT/nodus/include/nodus/nodus_types.h"
APPLY_H="$STAGEF_REPO_ROOT/nodus/src/witness/nodus_witness_v2_apply.h"

# ── SKIP gates (rc 99 — a skip is not a pass) ───────────────────────
for pair in "STAGEF_NODUS_BIN=$SRV" "STAGEF_NODUSCLI_BIN=$CLI"; do
    name="${pair%%=*}"; bin="${pair#*=}"
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        echo "[SKIP] $name is unset or not executable ('$bin') — this scenario needs the short-epoch"
        echo "       build of an HF-7 tree; see the header"
        exit 99
    fi
done
if [ "${STAGEF_EPOCH_LENGTH:-720}" != "$E_REQ" ]; then
    echo "[SKIP] STAGEF_EPOCH_LENGTH=${STAGEF_EPOCH_LENGTH:-720} — this scenario is laid out for"
    echo "       E=$E_REQ (-DDNAC_EPOCH_LENGTH=$E_REQ + STAGEF_EPOCH_LENGTH=$E_REQ before bring-up)"
    exit 99
fi
if [ "${STAGEF_CC_GRACE_ERGONOMIC:-720}" != 15 ] || [ "${STAGEF_CC_GRACE_SAFETY:-17280}" != 15 ]; then
    echo "[SKIP] STAGEF_CC_GRACE_ERGONOMIC=${STAGEF_CC_GRACE_ERGONOMIC:-720}" \
         "STAGEF_CC_GRACE_SAFETY=${STAGEF_CC_GRACE_SAFETY:-17280} — needs the short-grace"
    echo "       build (-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15"
    echo "       -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15) and both variables = 15"
    exit 99
fi
for t in sqlite3 ss; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "[SKIP] '$t' is not installed — the HF-7 checks need it"
        exit 99
    fi
done
[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || die "no active Stage F run (bring one up with stagef_up_v2.sh)"
ref_db0=$(stagef_node_chain_db 1)
[ -n "$ref_db0" ] && [ -s "$ref_db0" ] || die "no chain DB for node1"
has_v2=$(sqlite3 "$ref_db0" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ]; then
    echo "[SKIP] not a Comet cluster — bring it up with stagef_up_v2.sh"
    exit 99
fi
if [ ! -f "$CONF" ]; then
    echo "[SKIP] no $CONF — this scenario needs a stagef_up_v2.sh bring-up"
    exit 99
fi
if [ ! -s "$MSIG_DESC" ] || [ ! -s "$MSIG_ADDR_FILE" ]; then
    echo "[SKIP] no genesis 2-of-3 coin files ($MSIG_DESC, $MSIG_ADDR_FILE) — the bring-up"
    echo "       writes them only with a nodus-cli that has \`msig address\` (stagef_up_v2.sh [warn])"
    exit 99
fi
CONF_E=$(sed -n 's/^epoch_length *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
if [ "$CONF_E" != "$E_REQ" ]; then
    echo "[SKIP] the genesis document says epoch_length=${CONF_E:-?}, this scenario needs $E_REQ"
    exit 99
fi
mkdir -p "$LOGD"

# ── CAPABILITY GATE (FAIL, not skip) ────────────────────────────────
bin_version() {            # BIN KIND ("Server" | "CLI") -> X.Y.Z, "" if no banner
    local out re="Nodus $2 v([0-9]+\.[0-9]+\.[0-9]+)"
    out=$("$1" -h 2>&1 || true)
    if [[ "$out" =~ $re ]]; then echo "${BASH_REMATCH[1]}"; fi
}
SRV_VER=$(bin_version "$SRV" Server); CLI_VER=$(bin_version "$CLI" CLI)
[ -n "$SRV_VER" ] && [ -n "$CLI_VER" ] || die "a binary printed no version banner on -h (server '$SRV_VER', cli '$CLI_VER')"
[ "$SRV_VER" = "$CLI_VER" ] || die "the server ($SRV_VER) and the CLI ($CLI_VER) are not one build"
listening() {
    local out
    out=$(ss -ltnH "sport = :$1" 2>/dev/null || true)
    [ -n "$out" ]
}
PROBE_PORT=""
for p in 14991 14992 14993 14994 14995 14996 14997 14998 14999; do
    if ! listening "$p"; then PROBE_PORT="$p"; break; fi
done
[ -n "$PROBE_PORT" ] || die "no free port in 14991..14999 for the usage probe"
# the compiled vote literals, from the CLI's own usage text (nodus-cli.c
# cmd_chain_config_propose, printed before any connect)
usage_out=$(timeout 60 "$CLI" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose 2>&1 || true)
D_DEC=$(sed -n 's/^  EVM_ACTIVE  *exactly \([0-9][0-9]*\) .*/\1/p' <<< "$usage_out")
D_DEC="${D_DEC%%$'\n'*}"
D4_DEC=$(sed -n 's/^  RULESET_GEN_ROLES  *exactly \([0-9][0-9]*\) .*/\1/p' <<< "$usage_out")
D4_DEC="${D4_DEC%%$'\n'*}"
D5_DEC=$(sed -n 's/^  RULESET_GEN_ROOTS  *exactly \([0-9][0-9]*\) .*/\1/p' <<< "$usage_out")
D5_DEC="${D5_DEC%%$'\n'*}"
[ -n "$D_DEC" ] && [ -n "$D4_DEC" ] && [ -n "$D5_DEC" ] || {
    printf '%s\n' "$usage_out" >&2
    die "the CLI's chain-config usage does not name 'EVM_ACTIVE exactly <D>', 'RULESET_GEN_ROLES exactly <D4>' and 'RULESET_GEN_ROOTS exactly <D5>'"; }
[ "$D_DEC" -gt 0 ] 2>/dev/null && [ "$D4_DEC" -gt 0 ] 2>/dev/null && [ "$D5_DEC" -gt 0 ] 2>/dev/null \
    || die "a vote literal is not a positive int64 (D '$D_DEC', D4 '$D4_DEC', D5 '$D5_DEC')"
D_HEX=$(printf '%016x' "$D_DEC"); D4_HEX=$(printf '%016x' "$D4_DEC"); D5_HEX=$(printf '%016x' "$D5_DEC")
# hf7: schema S19 — v2_replay and v2_domain_heads.last_upd_hash exist only
# in an HF-7 build's database (nodus_witness_v2_schema.c)
s19=$(sqlite3 -separator '|' "$ref_db0" \
    "SELECT (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_replay'),
            (SELECT COUNT(*) FROM pragma_table_info('v2_domain_heads') WHERE name='last_upd_hash'),
            (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_validator_roles');" \
    2>/dev/null || echo ERR)
[ "$s19" = "1|1|1" ] || die "node1's database is not schema S19 (v2_replay|last_upd_hash|v2_validator_roles = '$s19') — not an HF-7 build"
# hf7: the generation-4 / generation-5 SYSTEM and CORE ruleset versions,
# from THIS tree's pins header (the gen-5 table P1d regenerated); the
# ruleset-info check at step 7 proves the running binary carries them.
pin_val() {
    sed -n "s/^#define $1  *\([0-9][0-9]*\)u *$/\1/p" "$PINS_H"
}
G4_SYS_V=$(pin_val NODUS_PIN_G4_SYS_RULESET_VERSION)
G4_CORE_V=$(pin_val NODUS_PIN_G4_CORE_RULESET_VERSION)
G5_SYS_V=$(pin_val NODUS_PIN_G5_SYS_RULESET_VERSION)
G5_CORE_V=$(pin_val NODUS_PIN_G5_CORE_RULESET_VERSION)
for v in "$G4_SYS_V" "$G4_CORE_V" "$G5_SYS_V" "$G5_CORE_V"; do
    case "$v" in ''|*[!0-9]*) die "could not read the G4 / G5 SYSTEM / CORE ruleset versions from $PINS_H" ;; esac
done
[ "$G5_SYS_V" -gt "$G4_SYS_V" ] && [ "$G5_CORE_V" -gt "$G4_CORE_V" ] \
    || die "generation 5 does not bump SYSTEM ($G4_SYS_V -> $G5_SYS_V) and CORE ($G4_CORE_V -> $G5_CORE_V) — summary item 1 half (a)"
# hf7: the two windows the expiry checks use, read from their defines
MEM_AHEAD=$(sed -n 's/^#define NODUS_CMT_APP_MAX_EXPIRY_AHEAD  *\([0-9][0-9]*\)u.*/\1/p' "$TYPES_H")
D2_WIN=$(sed -n 's/^#define NODUS_V2_EXPIRY_WINDOW_BLOCKS  *((uint64_t)\([0-9][0-9]*\)).*/\1/p' "$APPLY_H")
case "$MEM_AHEAD" in ''|*[!0-9]*) die "could not read NODUS_CMT_APP_MAX_EXPIRY_AHEAD from $TYPES_H" ;; esac
case "$D2_WIN" in ''|*[!0-9]*) die "could not read NODUS_V2_EXPIRY_WINDOW_BLOCKS from $APPLY_H" ;; esac
echo "[ok] capability gate: one build v$SRV_VER; D = 0x$D_HEX, D4 = 0x$D4_HEX, D5 = $D5_DEC (0x$D5_HEX); schema S19"
echo "     G4 SYSTEM v$G4_SYS_V / CORE v$G4_CORE_V -> G5 SYSTEM v$G5_SYS_V / CORE v$G5_CORE_V; CheckTx window $MEM_AHEAD, D2 $D2_WIN"

# ── script-local helpers (test_hf6_edge.sh's, unless "hf7:") ────────
db_of()  { stagef_node_chain_db "$1"; }
tip_of() { stagef_cmt_tip "$(db_of "$1")"; }
node_keys() { echo "$(stagef_node_dir "$1")/identity"; }
node_log()  { stagef_node_log "$1"; }
pin_of()    { cat "$(node_keys "$1")/nodus.fp"; }

node_runs_srv() {
    local pat pid
    pat="-d $(stagef_node_dir "$1")/data"
    for pid in $(pgrep -f -- "$pat" || true); do
        [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" = "$(readlink -f "$SRV")" ] && return 0
    done
    return 1
}

pump_to() {
    local target="$1" h prc
    h=$(stagef_cmt_pump_to "$(db_of 1)" "$target") && prc=0 || prc=$?
    case "$prc" in
        0) echo "[ok] node1 tip $h >= $target (pumped)" ;;
        1) die "chain STALLED while pumping to $target (tip $h)" ;;
        2) die "a pump spend was not included within 20 heights while pumping to $target (tip $h) — dropped, not delayed" ;;
        *) die "the pump faulted (rc $prc) while pumping to $target (tip $h) — its output is above" ;;
    esac
}

wait_all() {
    local n
    for n in $(seq 1 "$N"); do
        stagef_cmt_wait_height "$(db_of "$n")" "$1" 3 >/dev/null \
            || die "node$n never reached height $1"
    done
}

diff_at() {
    bash "$S_DIR/stagef_diff.sh" --at-height "$1" "$2" || exit 2
}

cc_row() {
    sqlite3 "$(db_of "$1")" \
        "SELECT new_value || '|' || commit_block || '|' || hex(tx_hash) FROM chain_config_history
          WHERE param_id = $2 AND effective_block = $3;" 2>/dev/null || echo ERR
}

wait_cc_row() {
    local param="$1" eff="$2" val="$3" maxh="$4"
    local h wrc first="" r n rows=""
    h=$(stagef_cmt_wait_row "$(db_of 1)" \
        "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $param
           AND effective_block = $eff AND new_value = $val;" 3 "$maxh") && wrc=0 || wrc=$?
    case "$wrc" in
        0) ;;
        1) die "chain STALLED waiting for the param-$param row (effective $eff) on node1 (tip $h)" ;;
        *) die "the param-$param row (effective $eff) did not land on node1 within $maxh heights (tip $h)" ;;
    esac
    for n in $(seq 1 "$N"); do
        stagef_cmt_wait_height "$(db_of "$n")" "$h" 3 >/dev/null \
            || die "node$n never reached height $h (the param-$param row's detection height)"
        r=$(cc_row "$n" "$param" "$eff")
        rows="$rows node$n=$r"
        if [ -z "$first" ]; then first="$r"
        elif [ "$r" != "$first" ]; then die "the param-$param row (effective $eff) DIFFERS across nodes:$rows"; fi
    done
    case "$first" in ""|ERR) die "no param-$param row (effective $eff) readable";; esac
    [ "${first%%|*}" = "$val" ] || die "the param-$param row carries value ${first%%|*}, expected $val"
    CC_CB="${first#*|}"; CC_CB="${CC_CB%%|*}"
    echo "[ok] param-$param row (value $val, effective $eff, commit_block $CC_CB) identical on 7/7"
}

# cc_guard NODE — the EVM template's epoch-boundary guard (the CLI takes
# the committee of tip + 1 but the epoch of tip — BUGS.md). Sets CCG_TIP /
# CCG_NB.
cc_guard() {
    local n="$1" t nb try
    for try in 1 2; do
        t=$(tip_of "$n")
        nb=$(( (t / E + 1) * E ))
        if [ $(( t % E )) != 0 ] && [ $(( nb - t )) -ge "$CC_GUARD_GAP" ]; then
            CCG_TIP="$t"; CCG_NB="$nb"
            return 0
        fi
        echo "[info] node$n's tip $t is on or within $CC_GUARD_GAP heights of the epoch boundary $nb — pumping to $(( nb + 1 )) before the proposal (attempt $try)"
        pump_to $(( nb + 1 ))
        wait_all $(( nb + 1 ))
    done
    die "node$n's tip $(tip_of "$n") is still next to an epoch boundary after two guard pumps"
}

cc_guard_after() {
    local t
    t=$(tip_of "$1")
    [ $(( t + 1 )) -lt "$CCG_NB" ] || die \
        "the proposal from node$1 crossed into the epoch boundary $CCG_NB (tip $CCG_TIP -> $t): its approvals may straddle two epochs (the CLI committee/epoch edge, BUGS.md) — the layout broke, not the chain"
}

# propose NAME VALUE EFFECTIVE LOG — node 1's seat; FAIL unless round 1
# is 7/7 and the CLI reports acceptance.
propose() {
    local name="$1" val="$2" eff="$3" log="$4" prc=0
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" -i "$(node_keys 1)" \
        chain-config propose --param "$name" --value "$val" --effective "$eff" > "$log" 2>&1 || prc=$?
    cat "$log"
    cc_guard_after 1
    [ "$prc" = 0 ] || die "chain-config propose $name exited $prc (see $log)"
    grep -q "Round 1: $N/$N approved" "$log" || die "propose $name: round 1 was not $N/$N (see $log)"
    grep -q "proposal accepted" "$log" || die "propose $name did not report acceptance (see $log)"
}

# ruleset_info NODE — nodus-cli.c cmd_ruleset_info's lines (hf7: + the
# SYSTEM / CORE version and hash lines)
ruleset_info() {
    local n="$1" log rrc=0
    log="$LOGD/ruleset_info_node${n}_$(tip_of "$n").log"
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" ruleset-info > "$log" 2>&1 || rrc=$?
    RI_RC="$rrc"
    RI_OUT=$(cat "$log")
    RI_TIP=$(sed -n 's/^tip=\([0-9]*\) generation=.*/\1/p' "$log")
    RI_GEN=$(sed -n 's/^tip=[0-9]* generation=\([0-9]*\) .*/\1/p' "$log")
    RI_H=$(sed -n 's/^  RULESET_GEN2 height H=\([0-9]*\).*/\1/p' "$log")
    RI_D2=$(sed -n 's/^  node D2=0x\([0-9a-f]*\) .*/\1/p' "$log")
    RI_CLI_D2=$(sed -n 's/^  node D2=0x[0-9a-f]*  this CLI D2=0x\([0-9a-f]*\).*/\1/p' "$log")
    RI_SYS_V=$(sed -n 's/^  SYSTEM v\([0-9]*\) hash=[0-9a-f]*$/\1/p' "$log")
    RI_SYS_H=$(sed -n 's/^  SYSTEM v[0-9]* hash=\([0-9a-f]*\)$/\1/p' "$log")
    RI_CORE_V=$(sed -n 's/^  CORE   v\([0-9]*\) hash=[0-9a-f]*$/\1/p' "$log")
    RI_CORE_H=$(sed -n 's/^  CORE   v[0-9]* hash=\([0-9a-f]*\)$/\1/p' "$log")
}

# require_gen NODE GEN H — generation + the param-9 H + carried by this
# CLI as that compiled generation.
require_gen() {
    local n="$1" g="$2" hh="$3"
    ruleset_info "$n"
    [ "$RI_RC" = 0 ] || { printf '%s\n' "$RI_OUT" >&2; die "ruleset-info on node$n exited $RI_RC"; }
    [ "$RI_GEN" = "$g" ] || { printf '%s\n' "$RI_OUT" >&2; die "node$n reports generation '$RI_GEN' at tip $RI_TIP, expected $g"; }
    [ "$RI_H" = "$hh" ] || { printf '%s\n' "$RI_OUT" >&2; die "node$n reports RULESET_GEN2 H=$RI_H, expected $hh"; }
    [[ "$RI_OUT" != *MISMATCH* ]] || { printf '%s\n' "$RI_OUT" >&2; die "node$n's D2 differs from the CLI's"; }
    [[ "$RI_OUT" == *"this CLI carries it as compiled generation $g"* ]] || {
        printf '%s\n' "$RI_OUT" >&2; die "the CLI does not carry node$n's tuple as compiled generation $g"; }
}

# cross_edge LABEL H — pumped to H - PUMP_STOP_GAP, then idle across
# H - 1 / H / H + 1, compared 7/7 AT each.
cross_edge() {
    local label="$1" hh="$2" x
    pump_to $(( hh - PUMP_STOP_GAP ))
    wait_all $(( hh + 1 ))
    for x in $(( hh - 1 )) "$hh" $(( hh + 1 )); do diff_at "$x" "$label-at-height-$x"; done
}

# same_on_all WHAT FN — FN's output on node 1 equals every node's;
# prints node 1's.
same_on_all() {
    local what="$1" fn="$2" ref d n
    ref=$("$fn" 1)
    [ "$ref" != ERR ] && [ -n "$ref" ] || die "$what: node1's read failed or is empty"
    for n in $(seq 2 "$N"); do
        d=$("$fn" "$n")
        [ "$d" = "$ref" ] || { printf 'node1:\n%s\nnode%s:\n%s\n' "$ref" "$n" "$d" >&2
            die "$what: node$n differs from node1"; }
    done
    printf '%s\n' "$ref"
}

# ── hf7: helpers ─────────────────────────────────────────────────────
# rh_row NODE DOMAIN GLOBAL_HEIGHT / rh_below — test_cmt_evm.sh's
# v2_root_history reads (version | ruleset hash | state root)
rh_row() {
    sqlite3 "$(db_of "$1")" \
        "SELECT ruleset_version || '|' || lower(hex(ruleset_hash)) || '|' || lower(hex(state_root))
           FROM v2_root_history WHERE domain_id = $2 AND global_height = $3;" 2>/dev/null || echo ERR
}
rh_below() {
    sqlite3 "$(db_of "$1")" \
        "SELECT ruleset_version || '|' || lower(hex(ruleset_hash)) FROM v2_root_history
          WHERE domain_id = $2 AND global_height < $3
          ORDER BY global_height DESC LIMIT 1;" 2>/dev/null || echo ERR
}

# hf7: cell_snap NODE FROM — ONE statement: "tip Σtx_count[FROM..tip]
# n_replay n_heads n_heads_bad n_mirror n_mirror_bad heads_list"
# (heads_bad = last_upd_hash not a 64-byte BLOB; mirror = a v2_root_history
# row at the head's own (domain_id, domain_height) — the row
# head_history_mirror reads; mirror_bad = its upd_hash differs from the
# head's column; heads_list = domain_id:last_upd_hash,… in domain order).
cell_snap() {
    local out
    out=$(sqlite3 -separator ' ' "$(db_of "$1")" \
      "SELECT (SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks),
              (SELECT COALESCE(SUM(tx_count),0) FROM v2_blocks WHERE global_height >= $2),
              (SELECT COUNT(*) FROM v2_replay),
              (SELECT COUNT(*) FROM v2_domain_heads),
              (SELECT COUNT(*) FROM v2_domain_heads
                WHERE typeof(last_upd_hash) != 'blob' OR length(last_upd_hash) != 64),
              (SELECT COUNT(*) FROM v2_domain_heads h JOIN v2_root_history r
                 ON r.domain_id = h.domain_id AND r.domain_height = h.domain_height),
              (SELECT COUNT(*) FROM v2_domain_heads h JOIN v2_root_history r
                 ON r.domain_id = h.domain_id AND r.domain_height = h.domain_height
                WHERE typeof(h.last_upd_hash) != 'blob' OR r.upd_hash != h.last_upd_hash),
              (SELECT COALESCE(group_concat(x, ','), '-') FROM
                 (SELECT domain_id || ':' || lower(hex(last_upd_hash)) AS x FROM v2_domain_heads
                   ORDER BY domain_id));" 2>&1) || { printf '%s\n' "$out"; return 1; }
    [[ "$out" =~ ^-?[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [-0-9a-f:,]+$ ]] \
        || { printf '%s\n' "$out"; return 1; }
    printf '%s\n' "$out"
}

# hf7: replay_of NODE WIRE — ONE statement: "tip|count|intent|expiry" of
# the v2_replay row keyed by tx_id = WIRE ('-|-' when absent)
replay_of() {
    sqlite3 "$(db_of "$1")" \
        "SELECT (SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks) || '|' ||
                (SELECT COUNT(*) FROM v2_replay WHERE lower(hex(tx_id)) = '$2') || '|' ||
                COALESCE((SELECT lower(hex(intent_id)) || '|' || expiry_height FROM v2_replay
                           WHERE lower(hex(tx_id)) = '$2'), '-|-');" 2>/dev/null || echo ERR
}

# hf7: row_7of7 LABEL WIRE INTENT — the v2_replay row of WIRE on every
# node: present, intent = INTENT, one expiry identical 7/7 (each read in
# [the row's block, its expiry) — a row past its expiry would be pruned).
# Sets ROW_E.
row_7of7() {
    local label="$1" wire="$2" intent="$3" n r t c ri re first=""
    for n in $(seq 1 "$N"); do
        r=$(replay_of "$n" "$wire")
        IFS='|' read -r t c ri re <<< "$r"
        [ "$c" = 1 ] && [ "$ri" = "$intent" ] || die \
            "$label: node$n's v2_replay row for wire ${wire:0:16}... is '$r' at tip $t — expected one row with intent ${intent:0:16}..."
        if [ -z "$first" ]; then first="$re"
        elif [ "$re" != "$first" ]; then die "$label: the v2_replay expiry differs across nodes (node1 $first, node$n $re)"; fi
        [ "$t" -lt "$re" ] || die "$label: node$n holds the row at tip $t >= its expiry $re (prune expiry <= H missed it)"
    done
    case "$first" in ''|*[!0-9]*) die "$label: unreadable v2_replay expiry '$first'" ;; esac
    ROW_E="$first"
    echo "[ok] $label: v2_replay (tx_id ${wire:0:16}..., intent ${intent:0:16}..., expiry $ROW_E) identical on 7/7"
}

# hf7: row_state_ok LABEL WIRE E — every node's ONE-statement read obeys
# "present ⇔ tip < E" (never pruned early, never kept past its expiry).
row_state_ok() {
    local label="$1" wire="$2" e="$3" n r t c rest
    for n in $(seq 1 "$N"); do
        r=$(replay_of "$n" "$wire")
        IFS='|' read -r t c rest <<< "$r"
        case "$t" in ''|*[!0-9-]*) die "$label: node$n's read failed: '$r'" ;; esac
        if [ "$t" -lt "$e" ]; then
            [ "$c" = 1 ] || die "$label: node$n PRUNED the row of ${wire:0:16}... at tip $t < its expiry $e"
        else
            [ "$c" = 0 ] || die "$label: node$n still holds the row of ${wire:0:16}... at tip $t >= its expiry $e"
        fi
        echo "[info] $label: node$n tip $t, row ${c}x (expiry $e)"
    done
}

# hf7: prune_inv NODE — ONE statement: "tip n_rows n_rows_at_or_below_tip"
prune_inv() {
    sqlite3 -separator ' ' "$(db_of "$1")" \
        "SELECT t, (SELECT COUNT(*) FROM v2_replay),
                (SELECT COUNT(*) FROM v2_replay WHERE expiry_height <= t)
           FROM (SELECT COALESCE(MAX(global_height),-1) AS t FROM v2_blocks);" 2>/dev/null || echo ERR
}

# hf7: msig_build LABEL EXPORT — `v2-envelope spend --msig` over the
# genesis 2-of-3 coin (test_cmt_multisig.sh stage 7), session on node 5.
# Sets MB_INTENT / MB_EXPIRY.
msig_build() {
    local label="$1" exp="$2" log="$LOGD/msig_build_$1.log"
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$SPENDER")" v2-envelope spend --msig "$MSIG_DESC" \
        --keys "$(node_keys "$SPENDER")" --in "$GNUL:$GAMT" --to "$FP_SPENDER" \
        --amount "$GSEND" --export "$exp" --submit "127.0.0.1:$(stagef_tcp_port "$SPENDER")" \
        > "$log" 2>&1 || { cat "$log" >&2; die "$label: the unsigned 2-of-3 envelope could not be BUILT"; }
    cat "$log"
    MB_INTENT=$(awk '/^ *intent_id=/{sub(/^ *intent_id=/,""); print; exit}' "$log")
    MB_EXPIRY=$(sed -n 's/^v2-envelope spend --msig: .* expiry=\([0-9][0-9]*\)$/\1/p' "$log")
    [ "${#MB_INTENT}" = 128 ] || die "$label: could not read the export's intent_id"
    case "$MB_EXPIRY" in ''|*[!0-9]*) die "$label: could not read the export's expiry" ;; esac
}

# hf7: msig_sign LABEL EXPORT NODE — `msig sign` over the node's OWN port,
# pinned to its fingerprint (test_cmt_multisig.sh stage 5)
msig_sign() {
    local label="$1" exp="$2" n="$3" log="$LOGD/msig_sign_$1_node$3.log"
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" msig sign --pin "$(pin_of "$n")" \
        --keys "$(node_keys "$n")" --in "$exp" --out "$LOGD/sig_$1_node$n" > "$log" 2>&1 \
        || { cat "$log" >&2; die "$label: node $n could not sign"; }
    [ -s "$LOGD/sig_$1_node$n" ] || die "$label: node $n wrote no signature file"
}

# hf7: msig_combine LOG EXPORT SUBMIT_NODE SIG... — combine + submit;
# sets MC_RC / MC_WIRE / MC_INTENT (printed by combine before it submits)
msig_combine() {
    local log="$1" exp="$2" sn="$3" s args=()
    shift 3
    for s in "$@"; do args+=(--sig "$s"); done
    MC_RC=0
    "$CLI" msig combine --in "$exp" "${args[@]}" --keys "$(node_keys "$SPENDER")" \
        --submit "127.0.0.1:$(stagef_tcp_port "$sn")" > "$log" 2>&1 || MC_RC=$?
    cat "$log"
    MC_WIRE=$(awk '/^ *wire_id=/{sub(/^ *wire_id=/,""); print; exit}' "$log")
    MC_INTENT=$(awk '/^ *intent_id=/{sub(/^ *intent_id=/,""); print; exit}' "$log")
    [ "${#MC_WIRE}" = 128 ] && [ "${#MC_INTENT}" = 128 ] \
        || die "combine printed no wire_id / intent_id (see $log) — it refused locally, before any submission"
}

# hf7: node_refused LOG — the CLI's machine-greppable line for an error
# frame FROM THE NODE (nodus-cli.c cli_print_spend_refusal): "refused:"
# means the node answered; "failed:" means it may have taken the tx.
node_refused() {
    grep -q 'dnac_spend RPC failed (rc=[-0-9]*) refused: rc=' "$1"
}

# hf7: count_on_all WHAT SQL WANT — SQL's single value equals WANT on 7/7
count_on_all() {
    local what="$1" sql="$2" want="$3" n v
    for n in $(seq 1 "$N"); do
        v=$(sqlite3 "$(db_of "$n")" "$sql" 2>/dev/null || echo ERR)
        [ "$v" = "$want" ] || die "$what: node$n reads '$v', expected $want"
    done
    echo "[ok] $what: $want on 7/7"
}

# ── 0/1. preconditions: a fresh cluster on this build ───────────────
for n in $(seq 1 "$N"); do
    node_runs_srv "$n" || die "node$n is not running STAGEF_NODUS_BIN ($(readlink -f "$SRV")) — bring the cluster up with it"
done
# the runbook's 7/7 pre-vote comparison: every node's newest start printed
# the CLI's D4 (HF-6) and D5 (hf7) (nodus_witness.c)
for n in $(seq 1 "$N"); do
    bl=$(grep -o 'HF-6 rule-set generation 4 vote D4 0x[0-9a-f]* (param 18 RULESET_GEN_ROLES, switch spec v[0-9]*)' \
            "$(node_log "$n")" | tail -1 || true)
    [ "$bl" = "HF-6 rule-set generation 4 vote D4 0x$D4_HEX (param 18 RULESET_GEN_ROLES, switch spec v1)" ] || die \
        "node$n's startup banner D4 line is '${bl:-none}', not the CLI's D4 0x$D4_HEX (param 18, switch spec v1)"
    bl=$(grep -o 'HF-7 rule-set generation 5 vote D5 0x[0-9a-f]* (param 22 RULESET_GEN_ROOTS, switch spec v[0-9]*)' \
            "$(node_log "$n")" | tail -1 || true)
    [ "$bl" = "HF-7 rule-set generation 5 vote D5 0x$D5_HEX (param 22 RULESET_GEN_ROOTS, switch spec v1)" ] || die \
        "node$n's startup banner D5 line is '${bl:-none}', not the CLI's D5 0x$D5_HEX (param 22, switch spec v1)"
done
echo "[ok] 7/7 startup banners name the CLI's D4 0x$D4_HEX (param 18) and D5 0x$D5_HEX (param 22)"
for p in "$PARAM_HF2" "$PARAM_HF3" "$PARAM_GEN2" "$PARAM_EVM" "$PARAM_RET16" "$PARAM_HF6" "$PARAM_HF7"; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $p;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1 already holds a param-$p row — this scenario needs a fresh bring-up"
done
for tb in v2_validator_roles v2_replay; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM $tb;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1's $tb is not empty — this scenario needs a fresh bring-up"
done
INIT_H=$(sed -n 's/^initial_height *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
[ -n "$INIT_H" ] || die "no initial_height in $CONF"
[ "$INIT_H" = 0 ] && INIT_H=1
# hf7: the genesis 2-of-3 coin (stagef_up_v2.sh; test_cmt_multisig.sh
# stage 7's identity: height 0, output_index 0, tx_hash = nullifier)
MSIG_ADDR=$(cat "$MSIG_ADDR_FILE")
[ "${#MSIG_ADDR}" = 128 ] || die "$MSIG_ADDR_FILE does not hold a 128-hex address"
gcoin=$(sqlite3 "$ref_db0" \
    "SELECT lower(hex(nullifier)) || ':' || amount FROM utxo_set
      WHERE owner = '$MSIG_ADDR' AND block_height = 0 AND output_index = 0
        AND tx_hash = nullifier LIMIT 1;" 2>/dev/null || true)
[ -n "$gcoin" ] || die "no genesis coin owned by the 2-of-3 address (already spent? — needs a fresh bring-up)"
GNUL="${gcoin%%:*}"; GAMT="${gcoin##*:}"
[ "${#GNUL}" = 128 ] && [ "$GAMT" -gt "$GSEND" ] 2>/dev/null || die "the genesis 2-of-3 coin '$gcoin' is malformed or below $GSEND"
FP_SPENDER=$(cat "$(node_keys "$SPENDER")/nodus.fp")
for n in 2 3 4 "$SPENDER"; do
    [ -s "$(node_keys "$n")/nodus.pk" ] && [ -s "$(node_keys "$n")/nodus.fp" ] || die "node$n has no identity"
done
stagef_cmt_pump_ready "$(db_of 1)" || die "the CLI-SPEND pump is not usable on this bring-up (reason above)"
stagef_sentinel SETUP_OK
echo "[ok] 7/7 nodes run $(readlink -f "$SRV"); genesis 2-of-3 coin ${GNUL:0:16}... ($GAMT raw)"

# ── 1. the chain commits ────────────────────────────────────────────
stagef_cmt_diff_at_floor "pre-hf7" || exit 2

# ── 2. the prerequisites: HF-2, HF-3, generation 2, 3 (EVM), 4 (HF-6) ─
cc_guard 1
H2=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $CCG_TIP — node1 proposes HF2_ACTIVE=1 effective H2=$H2"
propose HF2_ACTIVE 1 "$H2" "$LOGD/propose_hf2.log"
wait_cc_row "$PARAM_HF2" "$H2" 1 20
[ "$CC_CB" -lt "$H2" ] || die "the HF2 row committed at $CC_CB, not before its effective height $H2"
pump_to $(( H2 + 1 ))
wait_all $(( H2 + 1 ))
stagef_cmt_diff_at_floor "past-HF2" || exit 2

cc_guard 1
H3=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $CCG_TIP — node1 proposes HF3_ACTIVE=1 effective H3=$H3"
propose HF3_ACTIVE 1 "$H3" "$LOGD/propose_hf3.log"
wait_cc_row "$PARAM_HF3" "$H3" 1 20
[ "$CC_CB" -lt "$H3" ] || die "the HF3 row committed at $CC_CB, not before its effective height $H3"
pump_to $(( H3 + 1 ))
wait_all $(( H3 + 1 ))
stagef_cmt_diff_at_floor "past-HF3" || exit 2

require_gen 1 1 0
D2_HEX="$RI_D2"
[ "${#D2_HEX}" = 16 ] && [ "$D2_HEX" = "$RI_CLI_D2" ] || die "the node's D2 '$D2_HEX' and the CLI's '$RI_CLI_D2' are not one 16-hex literal"
D2_DEC=$(( 16#$D2_HEX ))
cc_guard 1
H4=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
while [ $(( (H4 - 1) % E )) = 0 ]; do H4=$(( H4 + 1 )); done   # param 9 rule (c)
echo "[ok] tip $CCG_TIP — node1 proposes RULESET_GEN2=$D2_DEC effective H4=$H4"
propose RULESET_GEN2 "$D2_DEC" "$H4" "$LOGD/propose_gen2.log"
wait_cc_row "$PARAM_GEN2" "$H4" "$D2_DEC" 20
[ "$CC_CB" -lt "$H4" ] || die "the RULESET_GEN2 row committed at $CC_CB, not before its effective height $H4"
cross_edge gen2 "$H4"
for n in $(seq 1 "$N"); do
    grep -q "rule-set generation 1 -> 2 at the end of height $(( H4 - 1 )) " "$(node_log "$n")" \
        || die "node$n logged no 'rule-set generation 1 -> 2 at the end of height $(( H4 - 1 ))' line"
    require_gen "$n" "$GEN_2" "$H4"
done
echo "[ok] rule-set generation 2 on 7/7 from H4=$H4"

cc_guard 1
HE=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_SAFETY + GRACE_MARGIN ))    # param 14: SAFETY grace
H_WIN=$(( INIT_H + 256 + WINDOW_MARGIN ))                        # EVM rule (g), red-team F5
[ "$HE" -ge "$H_WIN" ] || HE="$H_WIN"
while [ $(( (HE - 1) % E )) = 0 ]; do HE=$(( HE + 1 )); done     # EVM rule (f)
echo "[ok] tip $CCG_TIP — node1 proposes EVM_ACTIVE=$D_DEC effective HE=$HE (window floor $H_WIN)"
propose EVM_ACTIVE "$D_DEC" "$HE" "$LOGD/propose_evm.log"
wait_cc_row "$PARAM_EVM" "$HE" "$D_DEC" 20
[ "$CC_CB" -lt "$HE" ] || die "the EVM_ACTIVE row committed at $CC_CB, not before its effective height $HE"
cross_edge evm "$HE"
EVM_LINE="Nodus EVM: rule-set generation $GEN_2 -> $GEN_EVM and the EVM domain registered ACTIVE at the end of height $(( HE - 1 )) (D 0x$D_HEX)"
for n in $(seq 1 "$N"); do
    grep -qF "$EVM_LINE" "$(node_log "$n")" || die "node$n logged no '$EVM_LINE' line"
    require_gen "$n" "$GEN_EVM" "$H4"
done
echo "[ok] the EVM generation $GEN_EVM on 7/7 from HE=$HE"

cc_guard 1
H=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
while [ $(( H % E )) != "$EDGE_MOD" ]; do H=$(( H + 1 )); done   # rules (d), (e)
echo "[ok] tip $CCG_TIP — node1 proposes RULESET_GEN_ROLES=$D4_DEC effective H=$H"
propose RULESET_GEN_ROLES "$D4_DEC" "$H" "$LOGD/propose_hf6.log"
wait_cc_row "$PARAM_HF6" "$H" "$D4_DEC" 20
[ "$CC_CB" -lt "$H" ] || die "the RULESET_GEN_ROLES row committed at $CC_CB, not before its effective height $H"
cross_edge hf6 "$H"
HF6_LINE="HF-6: rule-set generation $GEN_EVM -> $GEN_4 and the validator migration at the end of height $(( H - 1 )) (param $PARAM_HF6 RULESET_GEN_ROLES, D4 0x$D4_HEX); height $H is judged under generation $GEN_4"
for n in $(seq 1 "$N"); do
    grep -qF "$HF6_LINE" "$(node_log "$n")" || die "node$n logged no '$HF6_LINE' line"
    require_gen "$n" "$GEN_4" "$H4"
done
echo "[ok] generation $GEN_4 on 7/7 from H=$H (HF-6)"

# ── 3. hf7: the generation-5 vote (param 22 = D5), A % E == 8 ───────
cc_guard 1
A=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))  # param 22: ERGONOMIC (khan B)
while [ $(( A % E )) != "$EDGE_MOD" ]; do A=$(( A + 1 )); done   # rules (d), (e)
[ $(( (A - 1) % E )) != 0 ] && [ $(( A % E )) != 0 ] || die "internal: A=$A or A-1 is a boundary"
echo "[ok] tip $CCG_TIP — node1 proposes RULESET_GEN_ROOTS=$D5_DEC effective A=$A (last boundary $(( A - EDGE_MOD )), next $(( A - EDGE_MOD + E )))"
propose RULESET_GEN_ROOTS "$D5_DEC" "$A" "$LOGD/propose_hf7.log"
wait_cc_row "$PARAM_HF7" "$A" "$D5_DEC" 20
[ "$CC_CB" -lt "$A" ] || die "the RULESET_GEN_ROOTS row committed at $CC_CB, not before its effective height $A"
for n in $(seq 1 "$N"); do require_gen "$n" "$GEN_4" "$H4"; done
echo "[ok] generation $GEN_4 on 7/7 before the generation-5 edge"

# ── 4. hf7: a generation-4 envelope, built and signed before the edge ─
EXP4="$LOGD/msig_gen4.export"
msig_build gen4 "$EXP4"
INTENT4="$MB_INTENT"; E4="$MB_EXPIRY"
[ "$E4" -gt $(( A + PUMP_STOP_GAP + 10 )) ] || die \
    "the generation-4 export expires at $E4, not beyond A + $(( PUMP_STOP_GAP + 10 )) = $(( A + PUMP_STOP_GAP + 10 )) — step 8 would test the expiry, not the version (layout broke)"
msig_sign gen4 "$EXP4" 2
msig_sign gen4 "$EXP4" 3
echo "[ok] a generation-4 2-of-3 envelope (intent ${INTENT4:0:16}..., expiry $E4 > A=$A) built and signed by nodes 2 + 3 — NOT submitted"

# ── 5. hf7: the A−1 cell, before any envelope of the new generation ──
pump_to $(( A - PUMP_STOP_GAP ))
# the pump's last spend is applied at or below the tip it returned at
# (each step waits for its own row), so nothing of ours lands above it
T_PUMP=$(tip_of 1)
[ "$T_PUMP" -le $(( A - 2 )) ] || die "the pump overshot to $T_PUMP >= A−1=$(( A - 1 )) — layout broke (false RED)"
echo "[info] idle production from tip $T_PUMP — no pump spend in flight across A−1"
wait_all $(( A - 1 ))
CELL_FROM=$(( T_PUMP + 1 ))
CELL_REF=""
for n in $(seq 1 "$N"); do
    s=$(cell_snap "$n" "$CELL_FROM") || die "node$n's A−1 cell read failed: '$s'"
    read -r t ntx nrep nh nhbad nmir nmirbad hlist <<< "$s"
    [ "$t" -ge $(( A - 1 )) ] && [ "$t" -le $(( A + EDGE_MOD - 2 )) ] || die \
        "node$n's A−1 cell read is at tip $t, outside [$(( A - 1 )), $(( A + EDGE_MOD - 2 ))] — the layout broke (false RED)"
    [ "$ntx" = 0 ] || die "node$n: $ntx envelope(s) in [$CELL_FROM, $t] before P — attribution impossible (false RED)"
    [ "$nrep" = 0 ] || die "node$n: v2_replay holds $nrep row(s) at tip $t with no envelope since $CELL_FROM — A−1 must insert none (§10.3)"
    [ "$nh" -gt 0 ] || die "node$n: v2_domain_heads is empty"
    [ "$nhbad" = 0 ] || die "node$n: $nhbad of $nh heads carry no 64-byte last_upd_hash after the edge (the seed did not run)"
    [ "$nmirbad" = 0 ] || die "node$n: $nmirbad head(s) disagree with their v2_root_history mirror row"
    [ "$nmir" -gt 0 ] || die "node$n: no head has a v2_root_history mirror row — the mirror check would be vacuous"
    rest="$nh $nmir $hlist"
    if [ -z "$CELL_REF" ]; then CELL_REF="$rest"
    elif [ "$rest" != "$CELL_REF" ]; then die "node$n's heads '$rest' differ from node1's '$CELL_REF'"; fi
done
read -r cell_nh cell_nmir cell_list <<< "$CELL_REF"
echo "[ok] A−1 cell 7/7: v2_replay empty; $cell_nh heads, every last_upd_hash a 64-byte BLOB, identical 7/7; $cell_nmir mirror row(s) agree"

# ── 6. hf7: the pump-path spend P, submitted at tip A−1 ──────────────
P_KEYS=$(stagef_pump_keys)
P_FP=$(cat "$P_KEYS/nodus.fp")
P_AMT=$(stagef_pump_largest "$(db_of 1)")
[ "$P_AMT" -gt "$STAGEF_PUMP_FEE_RAW" ] || die "the pump funder holds no coin above the fee for P"
p_log="$LOGD/spend_P.log"
"$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$STAGEF_PUMP_SUBMIT_NODE")" \
    v2-envelope spend --keys "$P_KEYS" --to "$P_FP" \
    --amount "$(( P_AMT - STAGEF_PUMP_FEE_RAW ))" --fee "$STAGEF_PUMP_FEE_RAW" --no-dust-sweep \
    --submit "127.0.0.1:$(stagef_tcp_port "$STAGEF_PUMP_SUBMIT_NODE")" > "$p_log" 2>&1 \
    || { cat "$p_log" >&2; die "P (the pump-path spend at tip A−1) was REFUSED"; }
cat "$p_log"
P_WIRE=$(awk '/^  wire_id=/{sub(/^  wire_id=/,""); print; exit}' "$p_log")
P_INTENT=$(awk '/^  intent_id=/{sub(/^  intent_id=/,""); print; exit}' "$p_log")
P_TIPB=$(sed -n 's/^v2-envelope spend 1\/1: .* tip=\([0-9][0-9]*\)$/\1/p' "$p_log")
[ "${#P_WIRE}" = 128 ] && [ "${#P_INTENT}" = 128 ] || die "P's submit output carried no wire_id / intent_id"
case "$P_TIPB" in ''|*[!0-9]*) die "could not read P's build tip from '$p_log'" ;; esac
[ "$P_TIPB" -ge $(( A - 1 )) ] || die "P was built at tip $P_TIPB < A−1 — under generation 4 (internal)"
ph=$(stagef_cmt_wait_row "$(db_of 1)" \
    "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$P_INTENT';" 3) && pwrc=0 || pwrc=$?
[ "$pwrc" = 1 ] && die "P never appeared and the chain STALLED at $ph"
[ "$pwrc" = 2 ] && die "P was not included within 20 heights (tip $ph) — dropped, not delayed"
H_P=$(sqlite3 "$(db_of 1)" \
    "SELECT global_height FROM v2_intent_index WHERE lower(hex(intent_id)) = '$P_INTENT' LIMIT 1;" 2>/dev/null || true)
case "$H_P" in ''|*[!0-9]*) die "P landed but its height could not be read ('$H_P')" ;; esac
[ "$H_P" -ge "$A" ] || die "P applied at $H_P < A=$A (internal)"
P_AT="AT A"; [ "$H_P" = "$A" ] || P_AT="at $H_P = A+$(( H_P - A )) (NOT at A — the block-A column with an applied item is not exercised)"
wait_all $(( H_P > A + 1 ? H_P : A + 1 ))
row_7of7 "P" "$P_WIRE" "$P_INTENT"
E_P="$ROW_E"
[ "$E_P" -ge "$H_P" ] && [ $(( E_P - H_P )) -le "$D2_WIN" ] || die \
    "P's expiry $E_P is outside D2 at its block $H_P ([$H_P, $(( H_P + D2_WIN ))])"
[ "$E_P" -ge $(( P_TIPB + 1 )) ] && [ "$E_P" -le $(( P_TIPB + MEM_AHEAD )) ] || die \
    "P's expiry $E_P is outside the CheckTx window of its build tip $P_TIPB ([$(( P_TIPB + 1 )), $(( P_TIPB + MEM_AHEAD ))])"
echo "[ok] P applied $P_AT (built at tip $P_TIPB), expiry $E_P inside D2 and the CheckTx window"

# ── 7. hf7: the edge — blocks, log line, root history, ruleset-info ──
for x in $(( A - 1 )) "$A" $(( A + 1 )); do diff_at "$x" "hf7-at-height-$x"; done
HF7_LINE="HF-7: rule-set generation $GEN_4 -> $GEN_5 and the head last_upd_hash seed at the end of height $(( A - 1 )) (param $PARAM_HF7 RULESET_GEN_ROOTS, D5 0x$D5_HEX); height $A is judged under generation $GEN_5"
RH_SYS=""; RH_CORE=""
for n in $(seq 1 "$N"); do
    grep -qF "$HF7_LINE" "$(node_log "$n")" || die "node$n logged no '$HF7_LINE' line"
    s=$(rh_row "$n" "$DOM_SYSTEM" $(( A - 1 ))); c=$(rh_row "$n" "$DOM_CORE" $(( A - 1 )))
    [ -n "$s" ] && [ "$s" != ERR ] || die "node$n has no SYSTEM v2_root_history row at A−1=$(( A - 1 ))"
    [ -n "$c" ] && [ "$c" != ERR ] || die "node$n has no CORE v2_root_history row at A−1=$(( A - 1 ))"
    if [ -z "$RH_SYS" ]; then RH_SYS="$s"; RH_CORE="$c"
    else
        [ "$s" = "$RH_SYS" ] || die "node$n's SYSTEM root-history row at A−1 differs: $s vs $RH_SYS"
        [ "$c" = "$RH_CORE" ] || die "node$n's CORE root-history row at A−1 differs: $c vs $RH_CORE"
    fi
    sb=$(rh_below "$n" "$DOM_SYSTEM" $(( A - 1 ))); cb=$(rh_below "$n" "$DOM_CORE" $(( A - 1 )))
    [ "${sb%%|*}" = "$G4_SYS_V" ] || die "node$n's last SYSTEM row below A−1 names v${sb%%|*}, expected generation 4's v$G4_SYS_V"
    [ "${cb%%|*}" = "$G4_CORE_V" ] || die "node$n's last CORE row below A−1 names v${cb%%|*}, expected generation 4's v$G4_CORE_V"
done
[ "${RH_SYS%%|*}" = "$G5_SYS_V" ] || die "the SYSTEM row at A−1 names v${RH_SYS%%|*}, expected generation 5's v$G5_SYS_V"
[ "${RH_CORE%%|*}" = "$G5_CORE_V" ] || die "the CORE row at A−1 names v${RH_CORE%%|*}, expected generation 5's v$G5_CORE_V"
for n in $(seq 1 "$N"); do
    require_gen "$n" "$GEN_5" "$H4"
    s="${RH_SYS#*|}"; c="${RH_CORE#*|}"
    [ "$RI_SYS_V|$RI_SYS_H" = "${RH_SYS%%|*}|${s%%|*}" ] || die "node$n's ruleset-info SYSTEM v$RI_SYS_V differs from the A−1 root-history row"
    [ "$RI_CORE_V|$RI_CORE_H" = "${RH_CORE%%|*}|${c%%|*}" ] || die "node$n's ruleset-info CORE v$RI_CORE_V differs from the A−1 root-history row"
done
stagef_sentinel TARGET_REACHED
echo "[ok] the generation-5 edge on 7/7 at the end of A−1=$(( A - 1 )): blocks A−1 / A / A+1 identical, the HF-7 line,"
echo "     SYSTEM v$G5_SYS_V / CORE v$G5_CORE_V at A−1 (v$G4_SYS_V / v$G4_CORE_V below), ruleset-info generation $GEN_5"

# ── 8. hf7: the generation-4 envelope is dead at A ──────────────────
t8=$(tip_of "$SPENDER")
[ "$E4" -gt $(( t8 + 1 )) ] || die "the generation-4 export expired before its submission (tip $t8, expiry $E4) — layout broke"
c4log="$LOGD/msig_combine_gen4.log"
msig_combine "$c4log" "$EXP4" "$SPENDER" "$LOGD/sig_gen4_node2" "$LOGD/sig_gen4_node3"
WIRE4="$MC_WIRE"
[ "$MC_INTENT" = "$INTENT4" ] || die "combine's intent for the generation-4 export differs from the export's"
[ "$MC_RC" != 0 ] || die "the generation-4 envelope was ACCEPTED at tip $t8 >= A−1 — a pre-A CORE leg is not dead at A (summary item 1)"
node_refused "$c4log" || die "the generation-4 envelope's refusal did not come from the node (no 'refused: rc=' line — see $c4log)"
echo "[ok] the generation-4 envelope (CORE v$G4_CORE_V leg) submitted at tip $t8 was REFUSED by node$SPENDER: $(grep -o 'node="[^"]*"' "$c4log" | head -1)"

# ── 9. hf7: M — applied once; same bytes and same intent refused ─────
EXP5="$LOGD/msig_gen5.export"
msig_build gen5 "$EXP5"
INTENT5="$MB_INTENT"; E5X="$MB_EXPIRY"
[ "$INTENT5" != "$INTENT4" ] || die "the generation-5 export has the generation-4 export's intent (internal)"
for n in 2 3 4; do msig_sign gen5 "$EXP5" "$n"; done     # all three BEFORE anything spends the coin
c5log="$LOGD/msig_combine_gen5_23.log"
msig_combine "$c5log" "$EXP5" "$SPENDER" "$LOGD/sig_gen5_node2" "$LOGD/sig_gen5_node3"
[ "$MC_RC" = 0 ] || die "M (the generation-5 2-of-3 envelope, nodes 2 + 3) was REFUSED — see $c5log"
WIRE5="$MC_WIRE"
[ "$MC_INTENT" = "$INTENT5" ] || die "combine's intent for M differs from the export's"
mh=$(stagef_cmt_wait_row "$(db_of 1)" \
    "SELECT COUNT(*) FROM v2_intent_index WHERE lower(hex(intent_id)) = '$INTENT5';" 3) && mwrc=0 || mwrc=$?
[ "$mwrc" = 1 ] && die "M never appeared and the chain STALLED at $mh"
[ "$mwrc" = 2 ] && die "M was not included within 20 heights (tip $mh) — dropped, not delayed"
H_M=$(sqlite3 "$(db_of 1)" \
    "SELECT global_height FROM v2_intent_index WHERE lower(hex(intent_id)) = '$INTENT5' LIMIT 1;" 2>/dev/null || true)
case "$H_M" in ''|*[!0-9]*) die "M landed but its height could not be read ('$H_M')" ;; esac
wait_all "$H_M"
row_7of7 "M" "$WIRE5" "$INTENT5"
E_M="$ROW_E"
[ "$E_M" = "$E5X" ] || die "M's v2_replay expiry $E_M is not the export's expiry $E5X"
[ "$E_M" -ge "$H_M" ] && [ $(( E_M - H_M )) -le "$D2_WIN" ] || die "M's expiry $E_M is outside D2 at its block $H_M"
count_on_all "the genesis 2-of-3 coin after M" \
    "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(nullifier)) = '$GNUL';" 0
count_on_all "M's $GSEND raw to node$SPENDER" \
    "SELECT COUNT(*) FROM utxo_set WHERE owner = '$FP_SPENDER' AND amount = $GSEND AND lower(hex(tx_hash)) = '$INTENT5';" 1
# 9a — the SAME bytes again (combine 2 + 3 is offline and deterministic)
c5alog="$LOGD/msig_combine_gen5_23_again.log"
msig_combine "$c5alog" "$EXP5" "$SPENDER" "$LOGD/sig_gen5_node2" "$LOGD/sig_gen5_node3"
[ "$MC_WIRE" = "$WIRE5" ] || die "9a: combine 2 + 3 printed another wire_id (${MC_WIRE:0:16}... vs ${WIRE5:0:16}...) — not the same bytes"
[ "$MC_RC" != 0 ] || die "9a: the SAME envelope bytes were ACCEPTED a second time"
node_refused "$c5alog" || die "9a: the refusal did not come from the node (see $c5alog)"
echo "[ok] 9a: the same bytes re-submitted were refused by node$SPENDER: $(grep -o 'node="[^"]*"' "$c5alog" | head -1)"
# 9b — the SAME intent, another authorization (nodes 2 + 4), to node 6
c5blog="$LOGD/msig_combine_gen5_24.log"
msig_combine "$c5blog" "$EXP5" 6 "$LOGD/sig_gen5_node2" "$LOGD/sig_gen5_node4"
WIRE5B="$MC_WIRE"
[ "$MC_INTENT" = "$INTENT5" ] || die "9b: combine 2 + 4 printed another intent_id — the same-intent case is not built"
[ "$WIRE5B" != "$WIRE5" ] || die "9b: combine 2 + 4 printed M's wire_id — the different-wire case is not built"
[ "$MC_RC" != 0 ] || die "9b: an envelope with M's intent under another authorization was ACCEPTED — the v2_replay guard did not fire"
node_refused "$c5blog" || die "9b: the refusal did not come from the node (see $c5blog)"
grep -q 'intent or wire id already committed on this chain' "$c5blog" || {
    cat "$c5blog" >&2
    die "9b: node6 refused, but not with the v2_replay guard's 'intent or wire id already committed on this chain'"; }
echo "[ok] 9b: M's intent under another wire (${WIRE5B:0:16}...) was refused by node6's v2_replay guard"

# ── 10. hf7: the prune ───────────────────────────────────────────────
t10=$(tip_of 1)
if [ $(( E_P - 1 )) -gt "$t10" ]; then pump_to $(( E_P - 1 )); fi
row_state_ok "P before its expiry" "$P_WIRE" "$E_P"
E_MAX="$E_P"; [ "$E_M" -le "$E_MAX" ] || E_MAX="$E_M"
pump_to "$E_MAX"
wait_all "$E_MAX"
row_state_ok "P after its expiry" "$P_WIRE" "$E_P"
row_state_ok "M after its expiry" "$WIRE5" "$E_M"
stagef_sentinel ASSERT_RUN
for n in $(seq 1 "$N"); do
    r=$(prune_inv "$n")
    read -r t nr nbad <<< "$r"
    [ "$nbad" = 0 ] || die "node$n holds $nbad v2_replay row(s) with expiry <= its tip $t (prune expiry <= H)"
    echo "[info] node$n tip $t: $nr v2_replay row(s), none at or below the tip"
done
echo "[ok] the prune: P's and M's rows gone on 7/7 at their expiry, never before; no row at or below any tip"

# ── 11. hf7: nothing refused was ever included ──────────────────────
count_on_all "M's wire_id in v2_tx_index" \
    "SELECT COUNT(*) FROM v2_tx_index WHERE lower(hex(tx_id)) = '$WIRE5';" 1
count_on_all "the 9b wire_id in v2_tx_index" \
    "SELECT COUNT(*) FROM v2_tx_index WHERE lower(hex(tx_id)) = '$WIRE5B';" 0
count_on_all "the generation-4 wire_id in v2_tx_index" \
    "SELECT COUNT(*) FROM v2_tx_index WHERE lower(hex(tx_id)) = '$WIRE4';" 0
count_on_all "M's intent in v2_intent_index" \
    "SELECT COUNT(*) FROM v2_intent_index WHERE lower(hex(intent_id)) = '$INTENT5';" 1
count_on_all "the generation-4 intent in v2_intent_index" \
    "SELECT COUNT(*) FROM v2_intent_index WHERE lower(hex(intent_id)) = '$INTENT4';" 0
stagef_cmt_diff_at_floor "post-hf7" || exit 2
stagef_sentinel PASS
echo ""
echo "[info] HEIGHTS: HF2 $H2 | HF3 $H3 | GEN2 $H4 | EVM $HE | HF-6 H $H | HF-7 A $A | P $H_P (expiry $E_P) | M $H_M (expiry $E_M)"
echo "[PASS] HF-7 generation-5 edge: param 22 = D5 0x$D5_HEX switched the registry 4 -> 5 at the end of A−1"
echo "       (SYSTEM v$G5_SYS_V / CORE v$G5_CORE_V, every head's last_upd_hash seeded, v2_replay empty), 7/7 identical;"
echo "       P applied $P_AT with its v2_replay row 7/7; the generation-4 envelope refused at A;"
echo "       M's same bytes and its same intent under another wire refused; rows pruned at their expiry."
echo "       ONE build, E=15 / grace 15 / BPY 20 — the LOGIC only; expiry outside D2, the EVM half of"
echo "       summary item 1 and the segment re-tag are NOT exercised (header)."
