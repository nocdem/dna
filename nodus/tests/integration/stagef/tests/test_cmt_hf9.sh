#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_hf9.sh — HF-9 (plan docs/plans/approved/2026-11-04-hf9.md §12
# T-13, with the harness part of T-16): the generation-6 edge on the 7-node
# harness — populated legs, the param-24 vote, the edge at the end of block
# A−1, the eight keyed tries and the rendezvous storage assignment on 7/7,
# one node restarted across A, a fresh node replaying from genesis
# (standalone — NOT in the sweep)
# ════════════════════════════════════════════════════════════════════
#
# Governing records: the approved plan (operator 2026-11-04: "1 eveg 2
# duzelt 3 evet"; this package's brief: "Kodu Sonnet yazacak.") §4.2 (the
# eight legs), §5.1-5.3 (state, capture, flush), §6 (compositions), §7.1-7.3
# (param 24 / D6, the edge, the boundary table), §8.3-8.6 (the selector, the
# retained assignment, the boundary procedure, the transition at B1), §12
# (T-13, T-14, T-16 and the run list under the table), §13 (WP7), §16 (what
# is deferred). TEMPLATES (their helpers are copied, nothing is shared):
# test_cmt_hf8_gen5.sh (the capability gate, the six votes to generation 5,
# the vote helpers), test_storage_archive.sh (the storage CLI, the segment
# layout), test_cmt_blocksync.sh and test_v2_join.sh (stop / restart / wipe
# and rejoin a node), test_cmt_token_create.sh (the token). Every part that
# is new for HF-9 is marked "hf9:".
#
# TWO RUNS (plan §12, the paragraph under the table) — how each is started
#   SHORT EPOCH — "7/7 state_root at epoch length 15" (CLAUDE.md TESTS):
#     the whole scenario, storage included. Build, environment and command
#     sequence are below ("WHAT IT REQUIRES"). Expected length ≈ 560 blocks.
#   PRODUCTION-CONSTANT EDGE RUN — the same script on a build WITHOUT the
#     short-epoch flags (E = 720, STAGEF_EPOCH_LENGTH unset or 720). The
#     script then runs `WITH_STORAGE=0`: everything up to and through the
#     edge (the votes, the populated legs that exist without a segment, the
#     param-24 vote, A−2 / A / A+1, the restart across A, the fresh replay),
#     and LEAVES OUT every storage step (registration, segment 1, B1, join,
#     exit, param 25) because a segment is P = 24 × E = 17 280 blocks at
#     E = 720 and the first one is published at P + 2E = 18 720 — out of
#     reach (plan §12: "P = 17280 is out of reach"). Legs 5 (registry) and
#     6 (segments) are then EMPTY on every node and the scenario asserts
#     exactly that (their roots must equal the empty-leg root). The PASS
#     line says "WITHOUT storage". Which grace the production run uses is
#     NOT chosen here (the plan is silent): the effective heights come from
#     STAGEF_CC_GRACE_SAFETY / _ERGONOMIC as the other scenarios read them,
#     so at the shipped 17 280 / 720 the votes of params 14 and 24 wait that
#     many blocks — the run is as long as those waits say.
#
# WHAT IT PROVES — each item would be false if it failed
#   0. Capability gate (FAIL): one version banner for the server and the CLI;
#      the CLI's chain-config usage names EVM_ACTIVE / RULESET_GEN_ROLES /
#      RULESET_GEN_ROOTS / RULESET_GEN_TRIE "exactly <D…>" and STORAGE_COPIES
#      "[4, 16]"; the usage's "vote wait N blocks" of RULESET_GEN_TRIE and
#      "one epoch, N blocks" of STORAGE_COPIES equal STAGEF_CC_GRACE_SAFETY
#      and STAGEF_EPOCH_LENGTH (the binary's constants, read from the binary
#      — an env var that does not match the build FAILs here); node 1's
#      database is schema S20 (the keyed-trie tables, the 24 triggers
#      "v2_trie_l<leg>_<ins|del|upd>", v2_trie_state.capture = 0); every
#      node's newest start logged the CLI's D4, D5 and D6.
#   1. Fresh chain: no row of params 7, 8, 9, 14, 16, 18, 22, 24, 25; no
#      v2_trie_roots row; no storage registration. Leaves are claimed by
#      nodes 1, 2, 4, 5, 6, 7 (node 3 = the pump's funder); node 1 creates a
#      token, node 2 registers a name (hf9: the populated legs 2 and 4; the
#      claims fill leg 3, the genesis outputs leg 1; validator_set_snapshots
#      and v2_attendance_epoch, legs 7 and 8, fill at the first boundaries).
#   2. The six votes of test_cmt_hf8_gen5.sh to generation 5 (HF2, HF3,
#      GEN2, EVM, ROLES, ROOTS), each row 7/7 and committed below its
#      effective height, the blocks AT each edge's H−1 / H / H+1 identical
#      7/7 in the FULL 64-byte mode, ruleset-info generation 5.
#   3. hf9 (short epoch only): nodes 4, 5, 6, 7 register as storage nodes
#      under their own keys; segment 1 is published at exactly 26 E (= P +
#      2E, the first storage boundary ≥ P + 2E), identical 7/7.
#   4. hf9: every one of the eight source tables is populated before the
#      edge (legs 5 and 6 only with storage), and at the cell read BEFORE the
#      edge (tip ≤ A−2: v2_trie_state.capture = 0, no v2_trie_roots row, no
#      v2_trie_dirty row, no v2_storage_assign_state row) and at the cells
#      read AFTER it (tip ≥ A−1: capture = 1, eight v2_trie_roots rows,
#      v2_trie_dirty empty) the same eight snapshot reads on every live node
#      are BYTE-IDENTICAL: the tip, the full 64-byte global_root and block_id
#      of the listed heights, capture, dirty, the eight leg roots (each
#      root equals the empty-leg root SHA3-512(0x80) EXACTLY when its source
#      table — with the leg's row selection: leg 3 = target_domain_id 1 —
#      has no row, plan §4.1), and the storage relations below.
#   5. param 24 = D6 voted at A with A−1 and A not epoch boundaries (the
#      rule), the SAFETY wait; the edge line "HF-9: rule-set generation 5 -> 6
#      … at the end of height A−1 (param 24 RULESET_GEN_TRIE, D6 0x…)" on
#      every node; ruleset-info generation 6 with "this CLI carries it as
#      compiled generation 6"; tip A−2 is still generation 5.
#   6. Restart across A (hf9, T-13 "restart of one node across A"): node 3
#      is stopped at tip A−3 and restarted when the fleet is at A+2 — the
#      gap A−2 … A+2 is 5 blocks, test_cmt_blocksync.sh's Rule-N cap at E =
#      15 (E/2 − 2). It catches up THROUGH the edge block and then agrees
#      7/7: the full 64-byte global_root and block_id AT A−1, A and A+1, and
#      the leg roots and every relation of the snapshot read.
#   7. Short epoch only — the storage assignment (plan §8.4-8.6), read at the
#      first generation-6 boundary B1 = the first boundary ≥ A and at each
#      boundary of the events below, each as ONE snapshot per node:
#        a. at the edge (before B1): v2_storage_assign_state = (R 4,
#           boundary H2, xfer 1) with H2 the last boundary < A; the basis =
#           exactly the four members; segment 1 has four current rows, all
#           from_h = B1 (E-s2); v2_storage_member_epoch holds rows for H2−E
#           and H2 (E-s1); the frozen sets of H2−E and H2 name four members.
#        b. B1 (no event, previous relation XOR): R 4; segment 1 four current
#           rows; exactly ONE member has n_new = 1 (the one rendezvous adds
#           to the three XOR holders of four) and held_union = 1 for all
#           four; that member's grace_until = B1 + E, the others 0 (K9).
#        c. join (node 2 registers after B1) — boundary B1 + E: five
#           eligible, R 4 → four current rows for segment 1;
#           Σ n_new = the rows inserted at it; rows ended = rows inserted.
#        d. param 25 = 5 (STORAGE_COPIES, the one-epoch wait) voted after
#           B1 + E, effective between B1 + 2E and B1 + 3E: at B1 + 2E copies
#           is still 4, at B1 + 3E it is 5, segment 1 has FIVE current rows
#           and exactly one new row and one member with n_new = 1 and a
#           grace_until ≥ boundary + E.
#        e. exit (node 5, by its owner = its own key): its row EXITING then
#           RELEASED at the first boundary ≥ x; at that boundary node 5 is
#           out of the basis, its segment rows are ended (to_h = boundary),
#           the other four keep theirs, no n_new.
#      At every one of those boundaries: v2_storage_assign_state.boundary =
#      the boundary and copies = R(boundary); the basis = the registry's
#      ACTIVE members with fail_streak < 3; every published segment has
#      exactly min(R, |basis|) current rows, each on a basis member;
#      v2_storage_held = the per-member count of current rows;
#      v2_storage_member_epoch has one row per ACTIVE member at the
#      boundary and, for every row with n_new > 0, grace_until ≥ boundary +
#      n_new × E — and the whole relation (every row and column of all seven
#      storage tables) is identical on every live node (plan §8.4-8.5).
#   8. Short epoch only — T-16, harness half (plan §12 T-16: "the holder
#      runtime fetches the newly assigned segments and stops holding dropped
#      ones only after the overlap epoch"): every node that is a current
#      holder of segment 1 at B1, B1 + E and B1 + 3E has the completeness
#      marker segments/seg-1.ok before the next boundary; node 5, taken out
#      by its exit, still has it at B_rel and at B_rel + E − 1 (the overlap
#      epoch) and has deleted it by B_rel + E + 3.
#   9. A fresh node replaying from genesis (T-13): node 3 is stopped, its
#      databases are wiped (its identity kept), it is restarted with the
#      genesis pin only; its log (truncated first, so every line is of THIS
#      replay) carries the HF-7 edge line, the HF-9 edge line and a
#      generation-6 boundary; it reaches the fleet tip and agrees 7/7 in the
#      full 64-byte mode, leg roots and storage relations included.
#  10. No node logged "HF9-SHADOW FAULT" or "CMT_FAULT" (plan §11) during the
#      run; stagef_diff.sh is called ONLY with --full (T-14).
#
# WHAT IT REQUIRES
#   Compile flags — SHORT EPOCH: ONE short-epoch + short-grace build of THIS
#   tree (nodus-server AND nodus-cli from the SAME build dir, with
#   NODUS_EVM_ENABLED — the standalone non-Windows default: the generation-4,
#   -5 and -6 edges FAULT without it):
#     -DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#   (params 7, 8, 9, 18, 22, 25 are ERGONOMIC; params 14 and 24 are SAFETY.)
#   Optional TEST-OWNER build: PLUS the four flags stagef_hf6_owner.sh prints
#   (-DDNAC_HF6_FOUNDATION_OWNER, its D4, D5 and — HF-9 WP7 — D6; all or
#   none). With STAGEF_HF6_OWNER_KEYS set the scenario applies
#   test_cmt_hf8_gen5.sh's TEST-OWNER gate (keys, fp, not a node's) and,
#   after generation 4, checks that every validator is owned by that owner;
#   without it the K8 default is expected. Nothing else here needs the owner:
#   the storage members register under their OWN keys.
#   Compile flags — PRODUCTION-CONSTANT EDGE RUN: a default build (no
#   -DDNAC_* constants); with a TEST-OWNER the same four owner flags only.
#   Environment, ALL exported BEFORE stagef_up_v2.sh unless noted:
#     STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN    that build
#     short epoch:   STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     read by THIS script only: STAGEF_CC_GRACE_SAFETY=15
#       STAGEF_CC_GRACE_ERGONOMIC=15 (short epoch: both MUST be 15, else
#       SKIP; production run: the values of the build)
#     optional: STAGEF_HF6_OWNER_FP_HEX / STAGEF_HF6_OWNER_KEYS (test owner)
#   Leave STAGEF_MODE (combined), STAGEF_V2_CANDIDATES and
#   STAGEF_PAYOUT_INTERVAL_EPOCHS unset. No treasury pool 1 is needed: no
#   settlement AMOUNT is asserted (see HOW IT CAN LIE).
#   Tools: sqlite3, xxd, ss, openssl (SHA3-512).
#   Exact command sequence (ORCHESTRATOR), short epoch, test-owner build:
#     S=<TREE>/nodus/tests/integration/stagef
#     bash $S/stagef_hf6_owner.sh /tmp/hf9-owner <TREE>/nodus/build/nodus-server
#       (prints the owner fp and the four flags O / D / D5F / D6F)
#     F='-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
#     cmake -S <TREE>/nodus -B <TREE>/nodus/build-hf9 -DCMAKE_C_FLAGS="$F $O $D $D5F $D6F"
#     make -C <TREE>/nodus/build-hf9 -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN=<TREE>/nodus/build-hf9/nodus-server
#     export STAGEF_NODUSCLI_BIN=<TREE>/nodus/build-hf9/nodus-cli
#     export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     export STAGEF_HF6_OWNER_FP_HEX=<fp> STAGEF_HF6_OWNER_KEYS=/tmp/hf9-owner/identity
#     bash $S/stagef_up_v2.sh
#     bash $S/tests/test_cmt_hf9.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   (without the owner: drop the first command, $O $D $D5F $D6F and the two
#   STAGEF_HF6_OWNER_* exports.) Production-constant edge run: the same with
#   a build made without $F, STAGEF_EPOCH_LENGTH / _BLOCKS_PER_YEAR /
#   _CC_GRACE_* unset (or the build's own values).
#   SKIP (rc 99): a binary missing, STAGEF_EPOCH_LENGTH or the genesis
#   epoch_length differing, short epoch with a grace variable ≠ 15, a tool
#   missing, STAGEF_HF6_OWNER_KEYS set but unusable is a FAIL (not a skip),
#   not a Comet cluster, no $BASE_DIR/v2_genesis.conf, no pump, any split
#   STAGEF_MODE. A skip is not a pass.
#   FAIL (rc 1) on the capability gate (above), on a chain that already holds
#   any of the rows of item 1, on a leaf already claimed.
#
# WHAT IT LEAVES BEHIND
#   HF-2, HF-3, rule-set generations 2, 3 (+ the EVM domain), 4, 5 and 6 —
#   all one-way; chain_config_history rows for params 7, 8, 9, 14, 18, 22,
#   24 (and 25 in the short run). The HF-6 migration's rows, the HF-7 seed,
#   the eight keyed tries (v2_trie_nodes / v2_trie_roots) with capture = 1.
#   One v2_names row, one tokens row, the leaves of nodes 1, 2, 3 (the
#   pump), 4, 5, 6, 7 claimed. Short run: four storage nodes registered at
#   generation 5 (nodes 4, 5, 6, 7), node 2 registered after B1, node 5
#   RELEASED (its bond back as one locked coin, output_index 201), segment 1
#   published, segment files under node<N>/data/segments, one STORAGE_COPIES
#   row (5). Node 3 restarted once and then wiped and rejoined (its
#   nodus.log truncated, a new pid in pids.txt, its databases rebuilt).
#   $BASE_DIR/hf9/ (every CLI log, consent files). Tear down with
#   stagef_down.sh before re-running (every switch is one-way, every leaf and
#   param row single-use).
#
# HOW IT CAN LIE
#   - E = 15, grace 15 / 15, BPY 20 prove the LOGIC, not the production 720 /
#     17 280 / 720. The production-constant run proves the edge at E = 720
#     and says in its PASS line what it leaves out.
#   - **Leg roots are read at a tip, not at a height.** v2_trie_roots keeps
#     the LATEST root of each leg only; there is no per-height leg-root
#     history (plan §16 DF-3: proofs at historical heights are not built).
#     "Leg roots at A−1, A, A+1, B1, B1+E, B1+2E" is therefore carried as:
#     (1) the FULL global_root and block_id at each of those heights, 7/7
#     (stagef_diff.sh --full — historical rows exist), and (2) the leg roots
#     of one snapshot per node at a common tip T ≥ that height, with the
#     facts that make T stand for the height: for A−1 / A the read is at
#     T ≥ A and the scenario asserts v2_blocks tx_count summed over A … T is
#     0 and T is before the next boundary, so no row of a leg changed since
#     the end of A−1 (the edge block); at A−1 itself the window is, by
#     inference from README "DELTA 1" (a block whose global root differs
#     from its predecessor's is followed by a proof block at the 4 s
#     timeout_commit pace; NOT measured), one such interval — too short to
#     read reliably, so it is not read there. A leg root that changed
#     and changed back between the height and T would not be seen.
#   - The "cell" read is BOUNDED re-reading of an expected asynchronous
#     condition (all live nodes report the same tip): up to 10 reads, 1 s
#     apart; nodes at one tip with different content die at once (that is a
#     divergence, never retried). A chain that never lets the nodes agree
#     on a tip FAILs after the 10 reads.
#   - The independent facts here are the empty-leg root (SHA3-512(0x80),
#     plan §4.1, computed by openssl), the source-table row counts, the
#     registry, the node identities and the n_new / row identities above;
#     the leg roots themselves are NOT recomputed (the oracle's KAT and the
#     unit tests do that, T-4 / T-5): equality of 8 stored roots on 7 nodes
#     proves agreement, not correctness. The HRW SCORES / ORDER are not
#     recomputed either (the selector against its oracle is T-4 / T-7); the
#     set of holders of segment 1 is read from the chain.
#   - **Not driven (the plan names them, the tree has no mechanism):** the
#     FAIL-STREAK CROSSING of T-13 (three NOT OK epochs → ineligible → a
#     departure at the next freeze). A member answers probes or not: the
#     tree has no fault knob for the 0x72 serving side (no getenv in
#     nodus_witness_storage_*.c — test_storage_archive.sh, HOW IT CAN LIE),
#     and freezing a validator (SIGSTOP) for the three settled epochs breaks
#     the Rule-N cap test_cmt_blocksync.sh keeps. The eligibility CROSSING
#     therefore appears only through R, the join and the exit. Also not
#     asserted: any settlement AMOUNT (no pool 1), the probe-report bits of
#     the new holders (T-16's "probe reports carry bits for the new holders":
#     the plan does not say what a member in grace must carry), K9 grace
#     beyond "n_new > 0 ⇒ grace_until ≥ boundary + n_new × E", R decreasing,
#     a second segment (the second is due at 2P + 2E = 750), a kind-3 owner.
#   - The join's new holder and the displaced holder depend on the node
#     identities of the run (the rendezvous scores): the scenario asserts
#     only what is true for every identity set (sums, equalities,
#     "at least" bounds) and READS the holders from the chain; it does not
#     know in advance which member node 2 displaces. Only the R change and
#     the exit are deterministic in who changes, and they are asserted so.
#   - Node 3 is the pump's funder: the pump reads node 1's database and
#     submits to node 1, using only node 3's identity FILES, never its
#     process (stagef_cmt_pump_to) — test_cmt_blocksync.sh keeps its victim
#     off the funder out of caution; here node 3 is the only node that is
#     neither a storage member, the proposer (node 1) nor the joiner
#     (node 2).
#   - The restart victim is down for 5 blocks; a longer gap risks Rule N
#     (README). Its leg roots are compared only after it is back; while it is
#     down the cells compare the six live nodes (the 7/7 full-mode diff at
#     A−1 / A / A+1 is made after it caught up).
#   - Duration ≈ 560 blocks short epoch (JUDGMENT, not measured: the six
#     votes ≈ 330, segment 1 at 390, A ≈ 428, B1 + 3E + the exit ≈ 520,
#     the replay). rc 99 = coverage that did not happen.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"
# hf9: ruleset-info, the vote path and the storage RPCs were not checked
# through a split core — SKIP (99) in every split mode (the HF-6 rule).
stagef_split_skip_if --reason "HF-9 generation-6 scenario not checked through a split core" \
    $(seq 1 "$STAGEF_COMMITTEE_SIZE")

die() { echo "[FAIL] $*" >&2; exit 1; }

S_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRV="$STAGEF_NODUS_BIN"
CLI="$STAGEF_NODUSCLI_BIN"
PARAM_HF2=7                # DNAC_CFG_HF2_ACTIVE, value exactly 1
PARAM_HF3=8                # DNAC_CFG_HF3_ACTIVE, value exactly 1
PARAM_GEN2=9               # DNAC_CFG_RULESET_GEN2, value exactly D2
PARAM_EVM=14               # DNAC_CFG_EVM_ACTIVE, value exactly D
PARAM_RET16=16             # DNAC_CFG_RULESET_GEN_STORAGE — RETIRED
PARAM_HF6=18               # DNAC_CFG_RULESET_GEN_ROLES, value exactly D4
PARAM_HF7=22               # DNAC_CFG_RULESET_GEN_ROOTS, value exactly D5
PARAM_TRIE=24              # hf9: DNAC_CFG_RULESET_GEN_TRIE, value exactly D6
PARAM_COPIES=25            # hf9: DNAC_CFG_STORAGE_COPIES, [4, 16]
GEN_2=2                    # NODUS_RT_GEN_2
GEN_EVM=3                  # NODUS_RT_GEN_EVM
GEN_4=4                    # NODUS_RT_GEN_STORAGE
GEN_5=5                    # NODUS_RT_GEN_ROOTS
GEN_6=6                    # hf9: NODUS_RT_GEN_TRIE (nodus_witness_runtime.h)
GRACE_MARGIN=5             # the HF-2/HF-3/HF-4 template's +5
WINDOW_MARGIN=5            # the EVM template's F5 window margin
CC_GUARD_GAP=4             # the EVM template's epoch-boundary guard
PUMP_STOP_GAP=7            # the HF-4 template's idle window before an edge
A_MARGIN=20                # hf9: room between the param-24 vote and A (layout, not a timeout)
E_SHORT=15                 # the one epoch length whose segment (P = 24 E) is reachable
BOND=100000000000000       # DNAC_HF6_STORAGE_BOND_DEFAULT (test_storage_archive.sh)
CONSENT_AHEAD=150          # consent expiry = tip + this (test_storage_archive.sh)
K8_OWNER=8eff7f418ab7a4432118ff99e21f2c3d1baf186200c148a3bba7d274499386ac970e267a9c9b3bbc05bfff1c62a72d63f72a555db780feeaaad4fb49ba9f7b89
OWNER=$(printf '%s' "${STAGEF_HF6_OWNER_FP_HEX:-$K8_OWNER}" | tr 'A-F' 'a-f')
OWN_KEYS="${STAGEF_HF6_OWNER_KEYS:-}"
CONF="$BASE_DIR/v2_genesis.conf"
LOGD="$BASE_DIR/hf9"
N="$STAGEF_COMMITTEE_SIZE"
E="$STAGEF_EPOCH_LENGTH"
GRACE_ERG="$STAGEF_CC_GRACE_ERGONOMIC"
GRACE_SAF="$STAGEF_CC_GRACE_SAFETY"
VICTIM=3                   # hf9: restart across A and fresh replay (header, HOW IT CAN LIE)
JOINER=2                   # hf9: registers as a storage node after B1
EXITER=5                   # hf9: the storage node its owner takes out
MEMBERS_PRE="4 5 6 7"      # hf9: registered at generation 5, before A
NAME_B=hf9nameone          # hf9: node 2's name (9 characters)
TK_NAME="Harness HF9 Token"
TK_SYM="HF9"
TK_DEC=8
TK_SUPPLY=2100000000000000
EMPTY_ROOT=""              # hf9: SHA3-512(0x80), set by the gate
MSG_LAYOUT="the layout broke (a false RED, never a false PASS)"

# hf9: the short run covers storage, the production-constant run does not
WITH_STORAGE=0
if [ "$E" = "$E_SHORT" ]; then WITH_STORAGE=1; fi

# ── SKIP gates (rc 99 — a skip is not a pass) ───────────────────────
for pair in "STAGEF_NODUS_BIN=$SRV" "STAGEF_NODUSCLI_BIN=$CLI"; do
    name="${pair%%=*}"; bin="${pair#*=}"
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        echo "[SKIP] $name is unset or not executable ('$bin') — this scenario needs a build of"
        echo "       this tree; see the header"
        exit 99
    fi
done
case "$E" in ''|*[!0-9]*) echo "[SKIP] STAGEF_EPOCH_LENGTH='$E' is not an integer"; exit 99 ;; esac
if [ "$WITH_STORAGE" = 1 ] && { [ "$GRACE_ERG" != 15 ] || [ "$GRACE_SAF" != 15 ]; }; then
    echo "[SKIP] STAGEF_CC_GRACE_ERGONOMIC=$GRACE_ERG STAGEF_CC_GRACE_SAFETY=$GRACE_SAF — the short run needs the"
    echo "       short-grace build (-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15"
    echo "       -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15) and both variables = 15"
    exit 99
fi
for t in sqlite3 xxd ss openssl; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "[SKIP] '$t' is not installed — the HF-9 checks need it"
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
CONF_E=$(sed -n 's/^epoch_length *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
if [ "$CONF_E" != "$E" ]; then
    echo "[SKIP] the genesis document says epoch_length=${CONF_E:-?}, STAGEF_EPOCH_LENGTH is $E"
    exit 99
fi
mkdir -p "$LOGD"

# ── CAPABILITY GATE (FAIL, not skip) — test_cmt_hf8_gen5.sh's, plus HF-9 ─
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
usage_out=$(timeout 60 "$CLI" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose 2>&1 || true)
usage_dec() {              # NAME -> the decimal after "NAME  exactly"
    local v
    v=$(sed -n "s/^  $1  *exactly \\([0-9][0-9]*\\) .*/\\1/p" <<< "$usage_out")
    printf '%s' "${v%%$'\n'*}"
}
D_DEC=$(usage_dec EVM_ACTIVE); D4_DEC=$(usage_dec RULESET_GEN_ROLES)
D5_DEC=$(usage_dec RULESET_GEN_ROOTS); D6_DEC=$(usage_dec RULESET_GEN_TRIE)
[ -n "$D_DEC" ] && [ -n "$D4_DEC" ] && [ -n "$D5_DEC" ] && [ -n "$D6_DEC" ] || {
    printf '%s\n' "$usage_out" >&2
    die "the CLI's chain-config usage does not name 'EVM_ACTIVE', 'RULESET_GEN_ROLES', 'RULESET_GEN_ROOTS' and 'RULESET_GEN_TRIE' with 'exactly <D>' — not an HF-9 build"; }
for v in "$D_DEC" "$D4_DEC" "$D5_DEC" "$D6_DEC"; do
    [ "$v" -gt 0 ] 2>/dev/null || die "a vote literal is not a positive int64 (D '$D_DEC', D4 '$D4_DEC', D5 '$D5_DEC', D6 '$D6_DEC')"
done
D_HEX=$(printf '%016x' "$D_DEC"); D4_HEX=$(printf '%016x' "$D4_DEC")
D5_HEX=$(printf '%016x' "$D5_DEC"); D6_HEX=$(printf '%016x' "$D6_DEC")
# hf9: the binary's own constants, read from its usage — the build must be what the env says
trie_line=$(grep '^  RULESET_GEN_TRIE ' <<< "$usage_out" || true)
copies_line=$(grep '^  STORAGE_COPIES ' <<< "$usage_out" || true)
BIN_SAF=$(sed -n 's/.*vote wait \([0-9][0-9]*\) blocks).*/\1/p' <<< "$trie_line")
BIN_ERG=$(sed -n 's/.*vote wait one epoch, \([0-9][0-9]*\) blocks).*/\1/p' <<< "$copies_line")
BIN_CMIN=$(sed -n 's/^  STORAGE_COPIES  *\[\([0-9][0-9]*\), \([0-9][0-9]*\)\].*/\1/p' <<< "$copies_line")
BIN_CMAX=$(sed -n 's/^  STORAGE_COPIES  *\[\([0-9][0-9]*\), \([0-9][0-9]*\)\].*/\2/p' <<< "$copies_line")
[ -n "$BIN_SAF" ] && [ -n "$BIN_ERG" ] && [ -n "$BIN_CMIN" ] && [ -n "$BIN_CMAX" ] || {
    printf '%s\n' "$usage_out" >&2
    die "the CLI's usage names no 'vote wait N blocks' for RULESET_GEN_TRIE, no 'one epoch, N blocks' or no [min, max] for STORAGE_COPIES — not an HF-9 build"; }
[ "$BIN_SAF" = "$GRACE_SAF" ] || die "the CLI's RULESET_GEN_TRIE vote wait is $BIN_SAF blocks, STAGEF_CC_GRACE_SAFETY is $GRACE_SAF — the build and the environment disagree"
[ "$BIN_ERG" = "$E" ] || die "the CLI's STORAGE_COPIES vote wait is one epoch = $BIN_ERG blocks, STAGEF_EPOCH_LENGTH is $E — the build and the environment disagree"
[ "$BIN_CMIN" = 4 ] && [ "$BIN_CMAX" = 16 ] || die "the CLI's STORAGE_COPIES range is [$BIN_CMIN, $BIN_CMAX], plan D4 says [4, 16]"
for nmv in "RULESET_GEN_TRIE:$D6_DEC" "STORAGE_COPIES:4"; do
    nm="${nmv%%:*}"
    probe=$(timeout 60 "$CLI" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose \
                --param "$nm" --value "${nmv##*:}" --effective 1 2>&1 || true)
    [[ "$probe" != *"Unknown param name"* && "$probe" == *"client_connect failed"* ]] || {
        printf '%s\n' "$probe" >&2
        die "the CLI did not pass $nm through its name table to the connect step — not an HF-9 build"; }
done
# hf9: schema S20 on node 1 — the keyed-trie tables, the 24 triggers (names
# v2_trie_l<leg>_<ins|del|upd>, nodus_witness_v2_schema.c), capture = 0
s20=$(sqlite3 -separator '|' "$ref_db0" \
    "SELECT (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN
               ('v2_trie_nodes','v2_trie_roots','v2_trie_dirty','v2_trie_state')),
            (SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'v2_trie_l%'),
            COALESCE((SELECT capture FROM v2_trie_state WHERE id = 1), -1),
            (SELECT COUNT(*) FROM v2_trie_roots);" 2>/dev/null || echo ERR)
[ "$s20" = "4|24|0|0" ] || die "node1's database is not a fresh schema S20 (tables|triggers|capture|leg roots = '$s20', expected 4|24|0|0) — not an HF-9 build, or a chain past the edge"
echo "[ok] capability gate: one build v$SRV_VER; D = 0x$D_HEX, D4 = 0x$D4_HEX, D5 = 0x$D5_HEX, D6 = 0x$D6_HEX; SAFETY wait $BIN_SAF, one epoch $BIN_ERG; schema S20 with the 24 triggers"

# ── script-local helpers (test_cmt_hf8_gen5.sh's, unless "hf9:") ────
db_of()  { stagef_node_chain_db "$1"; }
tip_of() { stagef_cmt_tip "$(db_of "$1")"; }
node_keys() { echo "$(stagef_node_dir "$1")/identity"; }
node_log()  { stagef_node_log "$1"; }
fp_of()  { tr 'A-F' 'a-f' < "$1/nodus.fp" | tr -d '[:space:]'; }   # $1 = identity dir
# dial_for NODE KEYS_DIR — a node refuses a client holding its own key (4001 plan 4.4): the next node
dial_for() {
    if [ "$2" = "$(node_keys "$1")" ]; then echo $(( $1 % N + 1 )); else echo "$1"; fi
}
declare -A FP
for n in $(seq 1 "$N"); do FP[$n]=$(fp_of "$(node_keys "$n")"); done
ALIVE=()                   # hf9: the nodes the cells and the waits compare
for n in $(seq 1 "$N"); do ALIVE+=("$n"); done

# ── TEST-OWNER gate (FAIL — the operator asked for it by setting the keys) ─
if [ -n "$OWN_KEYS" ]; then
    [[ "$OWNER" =~ ^[0-9a-f]{128}$ ]] || die "STAGEF_HF6_OWNER_FP_HEX is not 128 hex characters ('$OWNER')"
    [ -s "$OWN_KEYS/nodus.pk" ] && [ -s "$OWN_KEYS/nodus.sk" ] || die \
        "STAGEF_HF6_OWNER_KEYS=$OWN_KEYS holds no nodus.pk / nodus.sk — make it with stagef_hf6_owner.sh BEFORE the build"
    [ "$(stat -c %s "$OWN_KEYS/nodus.pk")" = 2592 ] || die "$OWN_KEYS/nodus.pk is not 2592 bytes"
    [ "$OWNER" != "$K8_OWNER" ] || die \
        "STAGEF_HF6_OWNER_KEYS is set but STAGEF_HF6_OWNER_FP_HEX is the K8 default — the build must compile the test owner (stagef_hf6_owner.sh prints the flags)"
    own_kfp=$(stagef_sha3_512_hex "$OWN_KEYS/nodus.pk")
    [ "$own_kfp" = "$OWNER" ] || die \
        "SHA3-512($OWN_KEYS/nodus.pk) = ${own_kfp:0:16}… is not STAGEF_HF6_OWNER_FP_HEX ${OWNER:0:16}… — the owner key and the compiled owner must be one identity"
    for n in $(seq 1 "$N"); do
        [ "${FP[$n]}" != "$OWNER" ] || die "the test owner is node$n's own key — it must be a separate identity"
    done
    echo "[ok] TEST-OWNER gate: owner keys $OWN_KEYS, SHA3-512 = ${OWNER:0:16}…"
fi

# hf9: the empty-leg root, plan §4.1 substitution 4: SHA3-512 of the single byte 0x80,
# upper case (sqlite hex())
EMPTY_ROOT=$(printf '\x80' | openssl dgst -sha3-512 -binary | xxd -p -c 256 | tr 'a-f' 'A-F' | tr -d '\n')
[[ "$EMPTY_ROOT" =~ ^[0-9A-F]{128}$ ]] || die "could not compute SHA3-512(0x80) with openssl ('$EMPTY_ROOT')"

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

wait_all() {               # every ALIVE node reaches height $1 (progress-bounded)
    local n
    for n in "${ALIVE[@]}"; do
        stagef_cmt_wait_height "$(db_of "$n")" "$1" 3 >/dev/null \
            || die "node$n never reached height $1"
    done
}

# hf9 (T-14): the ONLY way this scenario compares blocks — the 64-byte mode.
# stagef_diff.sh reads all $N nodes, so no node may be down.
diff_full_at() {
    [ "${#ALIVE[@]}" = "$N" ] || die "internal: diff_full_at called while a node is down"
    bash "$S_DIR/stagef_diff.sh" --full --at-height "$1" "$2" || exit 2
}
floor_diff() {             # the race-free floor read, 64-byte mode
    local floor="" h n
    for n in "${ALIVE[@]}"; do
        h=$(tip_of "$n"); [ -n "$h" ] || h=-1
        if [ -z "$floor" ] || [ "$h" -lt "$floor" ]; then floor="$h"; fi
    done
    [ "$floor" -ge 0 ] || die "floor_diff: no node has a block yet"
    diff_full_at "$floor" "$1"
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
    for n in "${ALIVE[@]}"; do
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
    echo "[ok] param-$param row (value $val, effective $eff, commit_block $CC_CB) identical on ${#ALIVE[@]}/$N"
}

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
}

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

# an edge crossed on IDLE production (nothing in flight), the full-mode diff AT H-1 / H / H+1
cross_edge() {
    local label="$1" hh="$2" x
    pump_to $(( hh - PUMP_STOP_GAP ))
    wait_all $(( hh + 1 ))
    for x in $(( hh - 1 )) "$hh" $(( hh + 1 )); do diff_full_at "$x" "$label-at-height-$x"; done
}

# hf9: the next height >= $1 that is neither an epoch boundary nor the block after one
# (params 9 / 14 / 18 / 22 / 24 rules: H-1 and, for 18 / 22 / 24, H not a boundary)
clear_of_boundary() {
    local x="$1"
    while [ $(( x % E )) = 0 ] || [ $(( (x - 1) % E )) = 0 ]; do x=$(( x + 1 )); done
    echo "$x"
}

spend_intent() { awk -F= '/^  intent_id=/{print $2; exit}' "$1"; }

claim_leaf() {
    local keys="$1" node="$2" port db fp log h wrc
    port=$(stagef_tcp_port "$(dial_for "$node" "$keys")"); db=$(db_of "$node"); fp=$(fp_of "$keys")
    log="$LOGD/claim_node$node.log"
    "$CLI" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$db" \
        --keys "$keys" --submit "127.0.0.1:$port" > "$log" 2>&1 \
        || { cat "$log" >&2; die "v2-claim for $keys was refused (see $log)"; }
    h=$(stagef_cmt_wait_row "$db" \
        "SELECT COUNT(*) FROM utxo_set WHERE owner = '$fp'
           AND token_id = zeroblob(64) AND amount > $STAGEF_PUMP_FEE_RAW;") && wrc=0 || wrc=$?
    [ "$wrc" = 0 ] || die "the claimed coin for $keys never appeared (wait rc=$wrc, tip $h)"
    echo "[ok] claimed the genesis leaf of node$node (tip $h)"
}

# ── hf9: the cell — ONE read snapshot per node, compared across the live nodes ─
# cell_dump NODE "H…" A — BEGIN … COMMIT in one sqlite3 call: a read transaction,
# so every line of the dump is of ONE committed state. Tags:
#   tip|T                         the node's tip
#   gr|H|global_root|block_id|tx  the FULL columns of height H ('-' if absent)
#   txsum|S                       Σ tx_count over heights >= A
#   capture|0/1  dirty|N  leg|i|root   v2_trie_state, v2_trie_dirty, v2_trie_roots
#   src|i|COUNT                   the source table of leg i (leg 3: target CORE = 1, ledger_ids.h)
#   (short run) astate|R|boundary|xfer  basis|fp  assign|k|fp|score|from|to  held|fp|n
#               mepoch|epoch|fp|held_union|n_new  reg|fp|status|exit|fail|grace|reg_h
#               seg|k|published  sets|epoch|count
cell_dump() {
    local n="$1" hl="$2" a="$3" sql h
    sql="BEGIN; SELECT 'tip|' || COALESCE(MAX(global_height), -1) FROM v2_blocks;"
    for h in $hl; do
        sql="$sql SELECT 'gr|$h|' || COALESCE((SELECT hex(global_root) || '|' || hex(block_id) || '|' || tx_count FROM v2_blocks WHERE global_height = $h), '-');"
    done
    sql="$sql SELECT 'txsum|' || COALESCE(SUM(tx_count), 0) FROM v2_blocks WHERE global_height >= $a;"
    sql="$sql SELECT 'capture|' || COALESCE((SELECT capture FROM v2_trie_state WHERE id = 1), '-');"
    sql="$sql SELECT 'dirty|' || COUNT(*) FROM v2_trie_dirty;"
    sql="$sql SELECT 'leg|' || leg || '|' || hex(root) FROM v2_trie_roots ORDER BY leg;"
    sql="$sql SELECT 'src|1|' || COUNT(*) FROM utxo_set;"
    sql="$sql SELECT 'src|2|' || COUNT(*) FROM tokens;"
    sql="$sql SELECT 'src|3|' || COUNT(*) FROM v2_claims_spent WHERE target_domain_id = 1;"
    sql="$sql SELECT 'src|4|' || COUNT(*) FROM v2_names;"
    sql="$sql SELECT 'src|5|' || COUNT(*) FROM v2_storage_nodes;"
    sql="$sql SELECT 'src|6|' || COUNT(*) FROM v2_storage_segments;"
    sql="$sql SELECT 'src|7|' || COUNT(*) FROM validator_set_snapshots;"
    sql="$sql SELECT 'src|8|' || COUNT(*) FROM v2_attendance_epoch;"
    if [ "$WITH_STORAGE" = 1 ]; then
        sql="$sql SELECT 'astate|' || copies || '|' || boundary || '|' || xfer FROM v2_storage_assign_state;"
        sql="$sql SELECT 'basis|' || lower(hex(node_fp)) FROM v2_storage_assign_basis ORDER BY node_fp;"
        sql="$sql SELECT 'assign|' || k || '|' || lower(hex(node_fp)) || '|' || lower(hex(score)) || '|' || from_h || '|' || COALESCE(to_h, '-') FROM v2_storage_assign ORDER BY k, from_h, node_fp;"
        sql="$sql SELECT 'held|' || lower(hex(node_fp)) || '|' || held FROM v2_storage_held ORDER BY node_fp;"
        sql="$sql SELECT 'mepoch|' || epoch_start || '|' || lower(hex(node_fp)) || '|' || held_union || '|' || n_new FROM v2_storage_member_epoch ORDER BY epoch_start, node_fp;"
        sql="$sql SELECT 'reg|' || lower(hex(node_fp)) || '|' || status || '|' || exit_height || '|' || fail_streak || '|' || grace_until || '|' || registered_height FROM v2_storage_nodes ORDER BY node_fp;"
        sql="$sql SELECT 'seg|' || k || '|' || published_height FROM v2_storage_segments ORDER BY k;"
        sql="$sql SELECT 'sets|' || epoch_start || '|' || member_count FROM v2_storage_sets ORDER BY epoch_start;"
    fi
    sql="$sql COMMIT;"
    sqlite3 -cmd '.timeout 5000' "$(db_of "$n")" "$sql" 2>&1
}

CELL=""; CELL_TIP=-1
cell_lines() { sed -n "s/^$1|//p" <<< "$CELL"; }
cell_one()   { cell_lines "$1" | sed -n '1p'; }

# cell_read LABEL "H…" A MIN_TIP — wait until every live node is at MIN_TIP, then read
# every live node's snapshot; the live nodes must agree on the tip (bounded re-read of
# an expected asynchronous condition) and, at one tip, on EVERY byte of the dump.
cell_read() {
    local label="$1" hl="$2" a="$3" min="$4" try n d ref="" ref_n="" tips agree
    wait_all "$min"
    for try in 1 2 3 4 5 6 7 8 9 10; do
        ref=""; agree=1; tips=""
        for n in "${ALIVE[@]}"; do
            if ! d=$(cell_dump "$n" "$hl" "$a"); then die "$label: node$n's snapshot read failed: $d"; fi
            case "$d" in tip\|*) ;; *) die "$label: node$n's snapshot read failed: $d" ;; esac
            tips="$tips node$n=$(sed -n '1p' <<< "$d" | sed 's/^tip|//')"
            if [ -z "$ref" ]; then ref="$d"; ref_n="$n"
            elif [ "$(sed -n '1p' <<< "$d")" != "$(sed -n '1p' <<< "$ref")" ]; then agree=0
            elif [ "$d" != "$ref" ]; then
                diff <(printf '%s\n' "$ref") <(printf '%s\n' "$d") >&2 || true
                die "$label: node$n's snapshot DIFFERS from node$ref_n's at the SAME tip (diff above) — consensus state diverged"
            fi
        done
        if [ "$agree" = 1 ]; then
            CELL="$ref"
            CELL_TIP=$(sed -n '1p' <<< "$ref" | sed 's/^tip|//')
            echo "[ok] $label: ${#ALIVE[@]} live nodes agree on every byte of the snapshot at tip $CELL_TIP"
            return 0
        fi
        sleep 1
    done
    die "$label: the live nodes never reported one tip in 10 reads (last:$tips)"
}

# hf9: the leg facts of a snapshot. $1 = pre | post
check_legs() {
    local when="$1" label="$2" i root cnt cap dirty nleg
    cap=$(cell_one capture); dirty=$(cell_one dirty)
    nleg=$(cell_lines leg | wc -l)
    for i in 1 2 3 4 5 6 7 8; do
        cnt=$(cell_one "src|$i")
        [[ "$cnt" =~ ^[0-9]+$ ]] || die "$label: the source count of leg $i is '$cnt'"
    done
    if [ "$when" = pre ]; then
        [ "$cap" = 0 ] || die "$label: v2_trie_state.capture reads '$cap' before the edge, expected 0 (plan §5.1: written only by the edge)"
        [ "$dirty" = 0 ] || die "$label: v2_trie_dirty holds $dirty row(s) before the edge, expected 0 (capture = 0: the triggers write nothing)"
        [ "$nleg" = 0 ] || die "$label: v2_trie_roots holds $nleg row(s) before the edge, expected 0"
        return 0
    fi
    [ "$cap" = 1 ] || die "$label: v2_trie_state.capture reads '$cap' after the edge, expected 1"
    [ "$dirty" = 0 ] || die "$label: v2_trie_dirty holds $dirty row(s) at a block's end, expected 0 (plan §5.3 end-of-block assertion)"
    [ "$nleg" = 8 ] || die "$label: v2_trie_roots holds $nleg row(s), expected 8"
    for i in 1 2 3 4 5 6 7 8; do
        root=$(cell_one "leg|$i"); cnt=$(cell_one "src|$i")
        [[ "$root" =~ ^[0-9A-F]+$ ]] || die "$label: leg $i has no root ('$root')"
        if [ "$cnt" = 0 ]; then
            [ "$root" = "$EMPTY_ROOT" ] || die "$label: leg $i has no source row but its root is ${root:0:16}…, expected the empty-leg root SHA3-512(0x80) = ${EMPTY_ROOT:0:16}… (plan §4.1)"
        else
            [ "$root" != "$EMPTY_ROOT" ] || die "$label: leg $i has $cnt source row(s) but its root is the empty-leg root (the trie holds nothing)"
        fi
    done
    echo "[ok] $label: capture 1, dirty 0, eight leg roots; empty-leg root exactly for the empty source tables ($(for i in 1 2 3 4 5 6 7 8; do printf '%s ' "$(cell_one "src|$i")"; done)rows)"
}

# hf9: populated legs (plan T-13 "populated legs before the edge")
require_populated() {
    local label="$1" i cnt need
    for i in 1 2 3 4 7 8; do
        cnt=$(cell_one "src|$i")
        [ "$cnt" -gt 0 ] || die "$label: leg $i's source table is EMPTY — it must be populated before the edge (the leg would prove nothing)"
    done
    if [ "$WITH_STORAGE" = 1 ]; then
        for i in 5 6; do
            cnt=$(cell_one "src|$i")
            [ "$cnt" -gt 0 ] || die "$label: leg $i's source table is EMPTY — the registry and a published segment are required in the short run"
        done
    fi
}

# ── hf9: the storage relations (plan §8.4-8.5), every one asserted at a boundary read ──
FPS_SORTED=""              # the fps of the current members, set by members_set
members_set() {            # NODE… -> FPS_SORTED (lower hex, ascending, space-separated)
    local n
    FPS_SORTED=$(for n in "$@"; do printf '%s\n' "${FP[$n]}"; done | LC_ALL=C sort | tr '\n' ' ' | sed 's/ *$//')
}
reg_status() {             # FP -> the registry's status of that fp in the dump ('' if absent)
    cell_lines reg | awk -F'|' -v f="$1" '$1 == f { print $2 }'
}
reg_grace() { cell_lines reg | awk -F'|' -v f="$1" '$1 == f { print $5 }'; }

# check_storage_state B WANT_R LABEL — the invariants at boundary B read at the tip of the dump
check_storage_state() {
    local b="$1" want_r="$2" label="$3" st copies bnd basis elig nb want k cur bad held_calc held_have
    local nact nme
    st=$(cell_one astate)
    [ -n "$st" ] || die "$label: v2_storage_assign_state holds no row"
    IFS='|' read -r copies bnd _ <<< "$st"
    [ "$bnd" = "$b" ] || die "$label: the assignment state is at boundary $bnd, expected $b (the read is past the next boundary, or the state is stale)"
    [ "$copies" = "$want_r" ] || die "$label: v2_storage_assign_state.copies = $copies, expected R = $want_r"
    basis=$(cell_lines basis | tr '\n' ' ' | sed 's/ *$//')
    elig=$(cell_lines reg | awk -F'|' '$2 == 1 && $4 < 3 { printf "%s ", $1 }' | sed 's/ *$//')
    [ "$basis" = "$elig" ] || die "$label: the basis [$basis] is not the registry's ACTIVE members with fail_streak < 3 [$elig] (plan §8.5 steps 1-2)"
    nb=$(cell_lines basis | wc -l)
    [ "$nb" -ge 1 ] || die "$label: the basis is empty"
    want=$(( want_r < nb ? want_r : nb ))
    for k in $(cell_lines seg | awk -F'|' '{ print $1 }'); do
        cur=$(cell_lines assign | awk -F'|' -v k="$k" '$1 == k && $5 == "-"' | wc -l)
        [ "$cur" = "$want" ] || die "$label: segment $k has $cur current assignment row(s), expected min(R=$want_r, eligible=$nb) = $want (plan §8.4 completeness)"
    done
    bad=$(cell_lines assign | awk -F'|' -v basis=" $basis " '$5 == "-" && index(basis, " " $2 " ") == 0 { print $2 }')
    [ -z "$bad" ] || die "$label: a current assignment row names a node outside the basis: $bad"
    held_calc=$(cell_lines assign | awk -F'|' '$5 == "-" { c[$2]++ } END { for (f in c) print f "|" c[f] }' | LC_ALL=C sort)
    held_have=$(cell_lines held | LC_ALL=C sort)
    [ "$held_calc" = "$held_have" ] || die "$label: v2_storage_held [$held_have] is not the per-member count of current rows [$held_calc] (plan §8.4)"
    nact=$(cell_lines reg | awk -F'|' '$2 == 1' | wc -l)
    nme=$(cell_lines mepoch | awk -F'|' -v b="$b" '$1 == b' | wc -l)
    [ "$nme" = "$nact" ] || die "$label: v2_storage_member_epoch has $nme row(s) at $b, expected one per ACTIVE member = $nact"
    # K9: n_new > 0 raises grace_until to at least B + n_new × E
    while IFS='|' read -r _ fp _ nn; do
        [ "$nn" -gt 0 ] || continue
        [ "$(reg_grace "$fp")" -ge $(( b + nn * E )) ] || die "$label: ${fp:0:16}… has n_new $nn at $b but grace_until $(reg_grace "$fp") < $(( b + nn * E )) (K9)"
    done < <(cell_lines mepoch | awk -F'|' -v b="$b" '$1 == b')
    echo "[ok] $label: boundary $b, R = $want_r, |basis| = $nb, every segment has $want current rows, held = rows, member_epoch rows = $nact, grace >= boundary + n_new x E"
}
n_new_sum()  { cell_lines mepoch | awk -F'|' -v b="$1" '$1 == b { s += $4 } END { print s + 0 }'; }
rows_from()  { cell_lines assign | awk -F'|' -v b="$1" '$4 == b && $5 == "-"' | wc -l; }
rows_ended() { cell_lines assign | awk -F'|' -v b="$1" '$5 == b' | wc -l; }
cur_holders_of() {         # K -> the nodes (indexes) holding segment K now
    local f n
    for f in $(cell_lines assign | awk -F'|' -v k="$1" '$1 == k && $5 == "-" { print $2 }'); do
        for n in $(seq 1 "$N"); do [ "${FP[$n]}" = "$f" ] && echo "$n"; done
    done
}

# hf9 (T-16): segment files of the holder runtime (nodus_witness_storage_segment.h:
# seg-<k>.ok is the completeness marker; the segment directory is data/segments)
seg_file() { echo "$(stagef_node_dir "$1")/data/segments/seg-$2.ok"; }
wait_seg_file() {          # NODE K UNTIL_TIP — present, or FAIL once node1's tip reaches UNTIL_TIP
    local f t
    f=$(seg_file "$1" "$2")
    while :; do
        [ -f "$f" ] && return 0
        t=$(tip_of 1)
        [ "$t" -lt "$3" ] || return 1
        sleep 2
    done
}
wait_seg_gone() {
    local f t
    f=$(seg_file "$1" "$2")
    while :; do
        [ ! -e "$f" ] && return 0
        t=$(tip_of 1)
        [ "$t" -lt "$3" ] || return 1
        sleep 2
    done
}
require_holder_files() {   # LABEL BOUNDARY — every current holder of segment 1 has seg-1.ok before the next boundary
    local label="$1" b="$2" n
    for n in $(cur_holders_of 1); do
        wait_seg_file "$n" 1 $(( b + E - 1 )) || die "$label: node$n is a current holder of segment 1 at $b but $(seg_file "$n" 1) did not appear before the next boundary (the holder runtime did not export / fetch it)"
    done
    echo "[ok] $label: every current holder of segment 1 ($(cur_holders_of 1 | tr '\n' ' ')) has seg-1.ok"
}

# ── hf9: storage CLI (test_storage_archive.sh's) ────────────────────
consent_make() {           # NODE OWNER OUT LOG
    local n="$1" own="$2" out="$3" log="$4" crc=0 exp
    exp=$(( $(tip_of "$n") + CONSENT_AHEAD ))
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" -i "$(node_keys "$n")" \
        storage consent --owner "$own" --expiry "$exp" --out "$out" > "$log" 2>&1 || crc=$?
    cat "$log"
    [ "$crc" = 0 ] && [ -s "$out" ] || die "node$n's storage consent (owner ${own:0:16}...) was refused (rc $crc, see $log)"
}
register_member() {       # NODE — consent to itself as owner, register, wait for the ACTIVE row
    local n="$1" keys cf log port h wrc fp
    keys=$(node_keys "$n"); fp="${FP[$n]}"
    cf="$LOGD/consent_node$n.txt"; log="$LOGD/register_node$n.log"
    consent_make "$n" "$fp" "$cf" "$LOGD/consent_node$n.log"
    port=$(stagef_tcp_port "$(dial_for "$n" "$keys")")
    "$CLI" -s 127.0.0.1 -p "$port" storage register --keys "$keys" --consent "$cf" \
        --submit "127.0.0.1:$port" > "$log" 2>&1 || { cat "$log" >&2; die "storage register for node$n failed (see $log)"; }
    cat "$log"
    grep -q '^accepted: mempool CheckTx approved' "$log" || die "storage register for node$n: no CheckTx approval line (see $log)"
    h=$(stagef_cmt_wait_row "$(db_of "$n")" \
        "SELECT COUNT(*) FROM v2_storage_nodes WHERE lower(hex(node_fp)) = '$fp' AND status = 1;") && wrc=0 || wrc=$?
    case "$wrc" in
        0) ;;
        1) die "chain STALLED waiting for node$n's registry row (tip $h)" ;;
        *) die "node$n's registration did not land within 20 heights (tip $h) — dropped, not delayed" ;;
    esac
    echo "[ok] node$n registered as a storage node (row visible at tip $h)"
}

# ── 0/1. preconditions: a fresh cluster on this build ───────────────
for n in $(seq 1 "$N"); do
    node_runs_srv "$n" || die "node$n is not running STAGEF_NODUS_BIN ($(readlink -f "$SRV")) — bring the cluster up with it"
done
for n in $(seq 1 "$N"); do
    bl=$(grep -o 'HF-6 rule-set generation 4 vote D4 0x[0-9a-f]* (param 18 RULESET_GEN_ROLES, switch spec v[0-9]*)' \
            "$(node_log "$n")" | tail -1 || true)
    [ "$bl" = "HF-6 rule-set generation 4 vote D4 0x$D4_HEX (param 18 RULESET_GEN_ROLES, switch spec v1)" ] || die \
        "node$n's startup banner D4 line is '${bl:-none}', not the CLI's D4 0x$D4_HEX (param 18, switch spec v1)"
    bl=$(grep -o 'HF-7 rule-set generation 5 vote D5 0x[0-9a-f]* (param 22 RULESET_GEN_ROOTS, switch spec v[0-9]*)' \
            "$(node_log "$n")" | tail -1 || true)
    [ "$bl" = "HF-7 rule-set generation 5 vote D5 0x$D5_HEX (param 22 RULESET_GEN_ROOTS, switch spec v1)" ] || die \
        "node$n's startup banner D5 line is '${bl:-none}', not the CLI's D5 0x$D5_HEX (param 22, switch spec v1)"
    bl=$(grep -o 'HF-9 rule-set generation 6 vote D6 0x[0-9a-f]* (param 24 RULESET_GEN_TRIE, switch spec v[0-9]*)' \
            "$(node_log "$n")" | tail -1 || true)
    [ "$bl" = "HF-9 rule-set generation 6 vote D6 0x$D6_HEX (param 24 RULESET_GEN_TRIE, switch spec v1)" ] || die \
        "node$n's startup banner D6 line is '${bl:-none}', not the CLI's D6 0x$D6_HEX (param 24, switch spec v1)"
done
for p in "$PARAM_HF2" "$PARAM_HF3" "$PARAM_GEN2" "$PARAM_EVM" "$PARAM_RET16" "$PARAM_HF6" "$PARAM_HF7" "$PARAM_TRIE" "$PARAM_COPIES"; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $p;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1 already holds a param-$p row — this scenario needs a fresh bring-up"
done
for tb in v2_validator_roles delegations v2_storage_nodes tokens v2_names; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM $tb;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1's $tb is not empty — this scenario needs a fresh bring-up"
done
INIT_H=$(sed -n 's/^initial_height *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
[ -n "$INIT_H" ] || die "no initial_height in $CONF"
[ "$INIT_H" = 0 ] && INIT_H=1
PIN_FILE="$BASE_DIR/v2_genesis_pin"
[ -s "$PIN_FILE" ] || die "no $PIN_FILE — needed by the fresh-replay step (stagef_up_v2.sh writes it)"
PIN=$(cat "$PIN_FILE")
[ "${#PIN}" = 64 ] || die "the recorded pin is not 64 hex characters"
stagef_cmt_pump_ready "$(db_of 1)" || die "the CLI-SPEND pump is not usable on this bring-up (reason above)"
[ "$VICTIM" != "$STAGEF_PUMP_SUBMIT_NODE" ] || die "the restart victim (node $VICTIM) is the pump's submit node — change STAGEF_PUMP_SUBMIT_NODE"
stagef_sentinel SETUP_OK
floor_diff "pre-hf9"
echo "[info] mode: $([ "$WITH_STORAGE" = 1 ] && echo "SHORT EPOCH (E=$E), storage included" || echo "PRODUCTION-CONSTANT edge run (E=$E), WITHOUT storage segments — registration, segment 1, B1, join, exit and param 25 are not run (header)")"

# ── 1. leaves, a token and a name — the populated legs (hf9) ────────
CLAIM_NODES="1 2"
if [ "$WITH_STORAGE" = 1 ]; then CLAIM_NODES="1 2 $MEMBERS_PRE"; fi
for k in $CLAIM_NODES; do claim_leaf "$(node_keys "$k")" "$k"; done
# the token: node 1 creates it (test_cmt_token_create.sh's call), dialled through node 2
tport=$(stagef_tcp_port "$(dial_for 1 "$(node_keys 1)")")
tlog="$LOGD/token_create.log"
"$CLI" -s 127.0.0.1 -p "$tport" v2-envelope token-create --keys "$(node_keys 1)" \
    --name "$TK_NAME" --symbol "$TK_SYM" --decimals "$TK_DEC" --supply "$TK_SUPPLY" \
    --submit "127.0.0.1:$tport" > "$tlog" 2>&1 || { cat "$tlog" >&2; die "token-create from node1 was refused (see $tlog)"; }
tid=$(awk '/^  token_id=/{sub(/^  token_id=/,""); print}' "$tlog")
[ "${#tid}" = 128 ] || { cat "$tlog" >&2; die "token-create printed no 64-byte token_id"; }
th=$(stagef_cmt_wait_row "$(db_of 1)" "SELECT COUNT(*) FROM tokens WHERE lower(hex(token_id)) = '$tid';") && wrc=0 || wrc=$?
[ "$wrc" = 0 ] || die "the tokens row did not appear (wait rc=$wrc, tip $th)"
echo "[ok] token ${tid:0:16}… created by node1 (tip $th)"
# the name: node 2 registers it (test_cmt_hf8_gen5.sh's call)
nlog="$LOGD/register_${NAME_B}.log"; port1=$(stagef_tcp_port 1)
"$CLI" -s 127.0.0.1 -p "$port1" name register "$NAME_B" --keys "$(node_keys 2)" \
    --submit "127.0.0.1:$port1" > "$nlog" 2>&1 || { cat "$nlog" >&2; die "name register $NAME_B from node2 failed (see $nlog)"; }
hn=$(stagef_cmt_wait_row "$(db_of 1)" \
    "SELECT COUNT(*) FROM v2_names WHERE name = CAST('$NAME_B' AS BLOB) AND lower(hex(owner)) = '${FP[2]}';") && wrc=0 || wrc=$?
[ "$wrc" = 0 ] || die "the v2_names row '$NAME_B' -> node2 did not land (wait rc=$wrc, tip $hn)"
echo "[ok] '$NAME_B' registered to node2 (tip $hn)"

# ── 2. the six votes to generation 5 (test_cmt_hf8_gen5.sh) ─────────
cc_guard 1
H2=$(clear_of_boundary $(( CCG_TIP + 1 + GRACE_ERG + GRACE_MARGIN )))
echo "[ok] tip $CCG_TIP — node1 proposes HF2_ACTIVE=1 effective H2=$H2"
propose HF2_ACTIVE 1 "$H2" "$LOGD/propose_hf2.log"
wait_cc_row "$PARAM_HF2" "$H2" 1 20
[ "$CC_CB" -lt "$H2" ] || die "the HF2 row committed at $CC_CB, not before its effective height $H2"
pump_to $(( H2 + 1 ))
wait_all $(( H2 + 1 ))

cc_guard 1
H3=$(clear_of_boundary $(( CCG_TIP + 1 + GRACE_ERG + GRACE_MARGIN )))
echo "[ok] tip $CCG_TIP — node1 proposes HF3_ACTIVE=1 effective H3=$H3"
propose HF3_ACTIVE 1 "$H3" "$LOGD/propose_hf3.log"
wait_cc_row "$PARAM_HF3" "$H3" 1 20
[ "$CC_CB" -lt "$H3" ] || die "the HF3 row committed at $CC_CB, not before its effective height $H3"
pump_to $(( H3 + 1 ))
wait_all $(( H3 + 1 ))

require_gen 1 1 0
D2_HEX="$RI_D2"
[ "${#D2_HEX}" = 16 ] && [ "$D2_HEX" = "$RI_CLI_D2" ] || die "the node's D2 '$D2_HEX' and the CLI's '$RI_CLI_D2' are not one 16-hex literal"
D2_DEC=$(( 16#$D2_HEX ))
cc_guard 1
H4=$(clear_of_boundary $(( CCG_TIP + 1 + GRACE_ERG + GRACE_MARGIN )))
echo "[ok] tip $CCG_TIP — node1 proposes RULESET_GEN2=$D2_DEC effective H4=$H4"
propose RULESET_GEN2 "$D2_DEC" "$H4" "$LOGD/propose_gen2.log"
wait_cc_row "$PARAM_GEN2" "$H4" "$D2_DEC" 20
[ "$CC_CB" -lt "$H4" ] || die "the RULESET_GEN2 row committed at $CC_CB, not before its effective height $H4"
cross_edge gen2 "$H4"
for n in $(seq 1 "$N"); do require_gen "$n" "$GEN_2" "$H4"; done
echo "[ok] rule-set generation 2 on 7/7 from H4=$H4"

cc_guard 1
HE=$(( CCG_TIP + 1 + GRACE_SAF + GRACE_MARGIN ))                 # param 14: SAFETY grace
H_WIN=$(( INIT_H + 256 + WINDOW_MARGIN ))                        # EVM rule (g)
[ "$HE" -ge "$H_WIN" ] || HE="$H_WIN"
HE=$(clear_of_boundary "$HE")
echo "[ok] tip $CCG_TIP — node1 proposes EVM_ACTIVE=$D_DEC effective HE=$HE (window floor $H_WIN)"
propose EVM_ACTIVE "$D_DEC" "$HE" "$LOGD/propose_evm.log"
wait_cc_row "$PARAM_EVM" "$HE" "$D_DEC" 20
[ "$CC_CB" -lt "$HE" ] || die "the EVM_ACTIVE row committed at $CC_CB, not before its effective height $HE"
cross_edge evm "$HE"
for n in $(seq 1 "$N"); do require_gen "$n" "$GEN_EVM" "$H4"; done
echo "[ok] the EVM generation $GEN_EVM on 7/7 from HE=$HE"

cc_guard 1
H6=$(clear_of_boundary $(( CCG_TIP + 1 + GRACE_ERG + GRACE_MARGIN )))
echo "[ok] tip $CCG_TIP — node1 proposes RULESET_GEN_ROLES=$D4_DEC effective H6=$H6"
propose RULESET_GEN_ROLES "$D4_DEC" "$H6" "$LOGD/propose_hf6.log"
wait_cc_row "$PARAM_HF6" "$H6" "$D4_DEC" 20
[ "$CC_CB" -lt "$H6" ] || die "the RULESET_GEN_ROLES row committed at $CC_CB, not before its effective height $H6"
cross_edge hf6 "$H6"
HF6_LINE="HF-6: rule-set generation $GEN_EVM -> $GEN_4 and the validator migration at the end of height $(( H6 - 1 )) (param $PARAM_HF6 RULESET_GEN_ROLES, D4 0x$D4_HEX); height $H6 is judged under generation $GEN_4"
for n in $(seq 1 "$N"); do
    grep -qF "$HF6_LINE" "$(node_log "$n")" || die "node$n logged no '$HF6_LINE' line"
    require_gen "$n" "$GEN_4" "$H4"
done
echo "[ok] generation $GEN_4 on 7/7 from H6=$H6 (HF-6)"
vown=$(sqlite3 -separator '|' "$(db_of 1)" \
    "SELECT COUNT(*), COUNT(DISTINCT owner_fp), COALESCE(MIN(lower(hex(owner_fp))), '-') FROM v2_validator_roles;" 2>/dev/null || echo ERR)
[ "$vown" = "$N|1|$OWNER" ] || die \
    "the validator owners after the generation-4 edge are '$vown', expected '$N|1|${OWNER:0:16}...' — the build's DNAC_HF6_FOUNDATION_OWNER is not $([ -n "$OWN_KEYS" ] && echo 'STAGEF_HF6_OWNER_FP_HEX' || echo 'the K8 default')"

cc_guard 1
A5=$(clear_of_boundary $(( CCG_TIP + 1 + GRACE_ERG + GRACE_MARGIN )))
echo "[ok] tip $CCG_TIP — node1 proposes RULESET_GEN_ROOTS=$D5_DEC effective A5=$A5"
propose RULESET_GEN_ROOTS "$D5_DEC" "$A5" "$LOGD/propose_hf7.log"
wait_cc_row "$PARAM_HF7" "$A5" "$D5_DEC" 20
[ "$CC_CB" -lt "$A5" ] || die "the RULESET_GEN_ROOTS row committed at $CC_CB, not before its effective height $A5"
cross_edge hf7 "$A5"
HF7_LINE="HF-7: rule-set generation $GEN_4 -> $GEN_5 and the head last_upd_hash seed at the end of height $(( A5 - 1 )) (param $PARAM_HF7 RULESET_GEN_ROOTS, D5 0x$D5_HEX); height $A5 is judged under generation $GEN_5"
for n in $(seq 1 "$N"); do
    grep -qF "$HF7_LINE" "$(node_log "$n")" || die "node$n logged no '$HF7_LINE' line"
    require_gen "$n" "$GEN_5" "$H4"
done
floor_diff "gen5"
echo "[ok] generation $GEN_5 on 7/7 from A5=$A5 (HF-7)"

# ── 3. hf9: four storage nodes, and segment 1 (short epoch only) ────
if [ "$WITH_STORAGE" = 1 ]; then
    P=$(( 24 * E ))                     # DNA_V2_SEGMENT_BLOCKS
    H_PUB=$(( P + 2 * E ))              # the first storage boundary >= P + 2E
    [ $(( H_PUB % E )) = 0 ] || die "the expected publication height $H_PUB is not a boundary"
    for k in $MEMBERS_PRE; do register_member "$k"; done
    members_set $MEMBERS_PRE
    wait_all "$(tip_of 1)"
    [ "$(tip_of 1)" -lt $(( H_PUB - E )) ] || die "the members registered after $(( H_PUB - E )) — $MSG_LAYOUT (K9a would give them grace)"
    pump_to $(( H_PUB + 1 ))
    wait_all $(( H_PUB + 1 ))
    h=$(stagef_cmt_wait_row "$(db_of 1)" "SELECT COUNT(*) FROM v2_storage_segments WHERE k = 1;" 3 5) && wrc=0 || wrc=$?
    [ "$wrc" = 0 ] || die "segment 1 was not published on node1 by tip $h (expected at $H_PUB; wait rc $wrc)"
    stagef_sentinel TARGET_REACHED
    cell_read "segment-1" "$H_PUB" "$A5" $(( H_PUB + 1 ))
    [ "$(cell_lines seg)" = "1|$H_PUB" ] || die "the published segments are [$(cell_lines seg | tr '\n' ' ')], expected exactly segment 1 published at $H_PUB (the first storage boundary >= P + 2E)"
    reg_ok=$(cell_lines reg | awk -F'|' '$2 == 1 && $3 == 0 && $4 == 0 && $5 == 0' | wc -l)
    [ "$reg_ok" = 4 ] || die "the registry is [$(cell_lines reg | tr '\n' ' ')], expected the four members ACTIVE with exit 0, fail_streak 0, grace_until 0"
    echo "[ok] segment 1 published at $H_PUB on 7/7; four storage members ACTIVE (fail_streak 0, grace_until 0)"
    diff_full_at "$H_PUB" "segment-published-at-$H_PUB"
fi

# ── 4. hf9: populated before the edge; the param-24 vote ────────────
if [ "$WITH_STORAGE" = 1 ]; then
    pump_to $(( H_PUB + 2 ))
    wait_all $(( H_PUB + 2 ))
fi
cell_read "pre-vote" "" 0 "$(tip_of 1)"
require_populated "pre-vote"
check_legs pre "pre-vote"
echo "[ok] every leg's source table is populated before the vote ($(for i in 1 2 3 4 5 6 7 8; do printf 'L%s=%s ' "$i" "$(cell_one "src|$i")"; done))"

cc_guard 1
T_V24="$CCG_TIP"
A=$(clear_of_boundary $(( T_V24 + 1 + GRACE_SAF + A_MARGIN )))
H2_LAST=$(( A / E * E ))               # the last boundary < A (A % E >= 2 by clear_of_boundary)
B1=$(( H2_LAST + E ))                  # the first boundary >= A
[ $(( A - H2_LAST )) -ge 2 ] || die "internal: A=$A is within 1 of the boundary $H2_LAST"
echo "[ok] tip $T_V24 — node1 proposes RULESET_GEN_TRIE=$D6_DEC (D6 0x$D6_HEX) effective A=$A (A-1 and A not boundaries; H2=$H2_LAST, B1=$B1)"
propose RULESET_GEN_TRIE "$D6_DEC" "$A" "$LOGD/propose_trie.log"
wait_cc_row "$PARAM_TRIE" "$A" "$D6_DEC" 20
[ "$CC_CB" -lt "$A" ] || die "the RULESET_GEN_TRIE row committed at $CC_CB, not before its effective height $A"
floor_diff "post-d6-vote"
for n in $(seq 1 "$N"); do require_gen "$n" "$GEN_5" "$H4"; done
echo "[ok] the param-24 row is on 7/7, still generation $GEN_5 before A"

# ── 5. hf9: cross the edge idle; node 3 is down across A (restart) ───
pump_to $(( A - PUMP_STOP_GAP ))
wait_all $(( A - PUMP_STOP_GAP ))
echo "[info] idle production from tip $(tip_of 1) — nothing in flight across the edge"
wait_all $(( A - 3 ))
src=0; stagef_stop_node "$VICTIM" TERM || src=$?
[ "$src" != 1 ] || die "node$VICTIM is not running"
[ "$src" = 0 ] || die "stopping node$VICTIM failed (stagef_stop_node rc=$src)"
echo "[ok] node$VICTIM stopped at tip $(tip_of 1) (A-3 = $(( A - 3 ))) — it misses A-2 .. A+2"
ALIVE=()
for n in $(seq 1 "$N"); do [ "$n" = "$VICTIM" ] || ALIVE+=("$n"); done
# the control: still generation 5, capture 0, no trie roots, no assignment state
cell_read "pre-edge" "" "$A" "$(tip_of 1)"
[ "$CELL_TIP" -le $(( A - 2 )) ] || die "the pre-edge cell was read at tip $CELL_TIP, past A-2 = $(( A - 2 )) — $MSG_LAYOUT"
check_legs pre "pre-edge (tip $CELL_TIP <= A-2)"
if [ "$WITH_STORAGE" = 1 ]; then
    [ -z "$(cell_one astate)" ] || die "pre-edge: v2_storage_assign_state already has a row ('$(cell_one astate)') — the edge writes it (plan §8.6 E-s2)"
    [ -z "$(cell_lines basis)" ] || die "pre-edge: v2_storage_assign_basis is not empty"
fi
ruleset_info 1
[ "$RI_GEN" = "$GEN_5" ] || { printf '%s\n' "$RI_OUT" >&2; die "node1 reports generation '$RI_GEN' at tip $RI_TIP before the edge, expected $GEN_5"; }
echo "[ok] before the edge (tip $CELL_TIP): generation $GEN_5, capture 0, no leg roots, no assignment state"

wait_all "$A"
cell_read "edge-A" "$(( A - 1 )) $A" "$A" "$A"
[ "$CELL_TIP" -ge "$A" ] || die "internal: the edge cell tip $CELL_TIP < A"
[ "$(cell_one txsum)" = 0 ] || die "edge-A: $(cell_one txsum) transaction(s) in heights $A .. $CELL_TIP — the leg roots read at $CELL_TIP would no longer be those of the end of A-1"
[ "$CELL_TIP" -lt "$B1" ] || die "edge-A: the cell was read at tip $CELL_TIP, past the first boundary $B1 — $MSG_LAYOUT"
check_legs post "edge-A (tip $CELL_TIP, no transaction since A-1)"
CELL_EDGE="$CELL"
HF9_LINE="HF-9: rule-set generation $GEN_5 -> $GEN_6, the eight keyed tries built and the dirty capture on at the end of height $(( A - 1 )) (param $PARAM_TRIE RULESET_GEN_TRIE, D6 0x$D6_HEX); height $A is judged under generation $GEN_6"
for n in "${ALIVE[@]}"; do
    grep -qF "$HF9_LINE" "$(node_log "$n")" || die "node$n logged no '$HF9_LINE' line"
done
require_gen 1 "$GEN_6" "$H4"
echo "[ok] the generation-6 edge ran at the end of A-1=$(( A - 1 )) on every live node; ruleset-info generation $GEN_6"
stagef_sentinel TARGET_REACHED
if [ "$WITH_STORAGE" = 1 ]; then
    st=$(cell_one astate)
    [ "$st" = "4|$H2_LAST|1" ] || die "edge-A: v2_storage_assign_state = '$st', expected '4|$H2_LAST|1' (R 4, boundary H2, xfer 1 — plan §8.6 E-s2)"
    members_set $MEMBERS_PRE
    [ "$(cell_lines basis | tr '\n' ' ' | sed 's/ *$//')" = "$FPS_SORTED" ] || die "edge-A: the basis is not exactly the four members"
    [ "$(cell_lines assign | awk -F'|' -v b1="$B1" '$1 == 1 && $4 == b1 && $5 == "-"' | wc -l)" = 4 ] \
        || die "edge-A: segment 1 does not have four current rows from_h = B1 = $B1 (plan §8.6 E-s2: rows from_h = B1)"
    [ "$(cell_lines assign | wc -l)" = 4 ] || die "edge-A: the assignment relation has $(cell_lines assign | wc -l) rows, expected exactly four"
    for hh in $(( H2_LAST - E )) "$H2_LAST"; do
        [ "$(cell_lines sets | awk -F'|' -v h="$hh" '$1 == h && $2 == 4' | wc -l)" = 1 ] \
            || die "edge-A: the frozen storage set of $hh does not name four members — $MSG_LAYOUT"
        [ "$(cell_lines mepoch | awk -F'|' -v h="$hh" '$1 == h' | wc -l)" -ge 1 ] \
            || die "edge-A: v2_storage_member_epoch has no row for $hh (plan §8.6 E-s1)"
    done
    echo "[ok] the storage transition ran at the edge: state (4, $H2_LAST, xfer 1), four rows from_h = B1 = $B1, member_epoch rows for $(( H2_LAST - E )) and $H2_LAST"
fi

wait_all $(( A + 1 ))
cell_read "edge-A+1" "$A $(( A + 1 ))" "$A" $(( A + 1 ))
[ "$CELL_TIP" -lt "$B1" ] || die "edge-A+1: the cell was read at tip $CELL_TIP, past the first boundary $B1"
if [ "$(cell_one txsum)" = 0 ]; then
    [ "$(cell_lines leg)" = "$(sed -n 's/^leg|//p' <<< "$CELL_EDGE")" ] \
        || die "edge-A+1: the leg roots changed between the edge cell and tip $CELL_TIP although no transaction was applied and no boundary crossed"
    echo "[ok] edge-A+1: no transaction and no boundary since A-1 — the eight leg roots are unchanged"
fi
check_legs post "edge-A+1 (tip $CELL_TIP)"

wait_all $(( A + 2 ))
stagef_spawn_node "$VICTIM" \
    || die "node$VICTIM did not come back after the restart (the [FAIL] line above names the process)"
echo "[ok] node$VICTIM restarted at fleet tip $(tip_of 1) (pids $STAGEF_NODE_PIDS)"
for lg in "$(stagef_node_dir "$VICTIM")/nodus.log" "$(node_log "$VICTIM")"; do
    if grep -q 'REFUSING START' "$lg"; then tail -20 "$lg" >&2; die "node$VICTIM logged REFUSING START ($lg)"; fi
done
vt=$(stagef_cmt_wait_height "$(db_of "$VICTIM")" "$(( $(tip_of 1) ))" 3) \
    || die "node$VICTIM did not catch up (stuck at $vt)"
echo "[ok] node$VICTIM caught up THROUGH the edge to tip $vt"
ALIVE=()
for n in $(seq 1 "$N"); do ALIVE+=("$n"); done
wait_all "$(( A + 2 ))"
for x in $(( A - 1 )) "$A" $(( A + 1 )); do diff_full_at "$x" "edge-after-restart-at-height-$x"; done
stagef_cmt_wait_height "$(db_of 1)" "$(( A + 2 ))" 3 >/dev/null || die "node1 stalled"
cell_read "post-restart" "$(( A - 1 )) $A $(( A + 1 ))" "$A" $(( A + 2 ))
check_legs post "post-restart (tip $CELL_TIP, 7/7)"
echo "[ok] 7/7 after the restart across A: the full 64-byte global_root and block_id at A-1, A, A+1; the eight leg roots at tip $CELL_TIP"

# ── 6. hf9: the storage assignment at B1 and its events (short epoch only) ─
if [ "$WITH_STORAGE" = 1 ]; then
    pump_to $(( B1 + 1 ))
    cell_read "B1" "$B1" "$A" $(( B1 + 1 ))
    check_legs post "B1"
    check_storage_state "$B1" 4 "B1 (previous relation XOR)"
    # (b) the transition at B1: Σ n_new = 1, held_union 1 for all, grace B1 + E for that member
    [ "$(n_new_sum "$B1")" = 1 ] || die "B1: Σ n_new = $(n_new_sum "$B1"), expected exactly 1 (rendezvous adds one member to the three XOR holders of four, plan §8.6)"
    [ "$(cell_lines mepoch | awk -F'|' -v b="$B1" '$1 == b && $3 != 1' | wc -l)" = 0 ] || die "B1: a member has held_union != 1"
    while IFS='|' read -r _ fp _ nn; do
        want_g=0; [ "$nn" = 1 ] && want_g=$(( B1 + E ))
        [ "$(reg_grace "$fp")" = "$want_g" ] || die "B1: ${fp:0:16}… has n_new $nn and grace_until $(reg_grace "$fp"), expected $want_g (K9: B + n x E for n > 0, else 0)"
    done < <(cell_lines mepoch | awk -F'|' -v b="$B1" '$1 == b')
    [ "$(cell_lines assign | awk -F'|' '$5 == "-"' | wc -l)" = 4 ] || die "B1: the current assignment rows are not exactly four"
    echo "[ok] B1=$B1: R 4 over four members, Σ n_new = 1 (XOR -> rendezvous), grace_until B1 + E for exactly that member"
    diff_full_at "$B1" "B1-at-height-$B1"
    require_holder_files "B1" "$B1"

    # (c) the join: node 2 registers after B1; boundary B1 + E
    register_member "$JOINER"
    members_set $MEMBERS_PRE "$JOINER"
    [ "$(tip_of 1)" -lt $(( B1 + E - 3 )) ] || die "the join landed at tip $(tip_of 1), too close to the boundary $(( B1 + E )) — $MSG_LAYOUT"
    pump_to $(( B1 + E + 1 ))
    cell_read "B1+E" "$(( B1 + E ))" "$A" $(( B1 + E + 1 ))
    check_legs post "B1+E"
    check_storage_state $(( B1 + E )) 4 "B1+E (join of node $JOINER)"
    [ "$(cell_lines basis | tr '\n' ' ' | sed 's/ *$//')" = "$FPS_SORTED" ] || die "B1+E: the basis is not the five members"
    [ "$(n_new_sum $(( B1 + E )))" = "$(rows_from $(( B1 + E )))" ] || die "B1+E: Σ n_new ($(n_new_sum $(( B1 + E )))) != the rows inserted at it ($(rows_from $(( B1 + E ))))"
    [ "$(rows_ended $(( B1 + E )))" = "$(rows_from $(( B1 + E )))" ] || die "B1+E: rows ended ($(rows_ended $(( B1 + E )))) != rows inserted ($(rows_from $(( B1 + E )))) — four holders of five before and after"
    echo "[ok] B1+E=$(( B1 + E )): five eligible, R 4 — $(rows_from $(( B1 + E ))) row(s) inserted, as many ended, four current rows; node $JOINER is $([ "$(rows_from $(( B1 + E )))" = 1 ] && echo 'a holder' || echo 'not among the four')"
    diff_full_at $(( B1 + E )) "B1+E-at-height-$(( B1 + E ))"
    require_holder_files "B1+E" $(( B1 + E ))

    # (d) param 25 = 5, voted at generation 6, effective after B1 + 2E, before B1 + 3E
    pump_to $(( B1 + E + 2 ))
    cc_guard 1
    E25=$(( CCG_TIP + 1 + GRACE_ERG + GRACE_MARGIN ))
    [ "$E25" -gt $(( B1 + 2 * E )) ] && [ "$E25" -le $(( B1 + 3 * E )) ] || die "internal: the param-25 effective height $E25 is outside ($(( B1 + 2 * E )), $(( B1 + 3 * E ))] — $MSG_LAYOUT"
    echo "[ok] tip $CCG_TIP — node1 proposes STORAGE_COPIES=5 effective E25=$E25 (one epoch + $GRACE_MARGIN)"
    propose STORAGE_COPIES 5 "$E25" "$LOGD/propose_copies.log"
    wait_cc_row "$PARAM_COPIES" "$E25" 5 20
    [ "$CC_CB" -lt "$E25" ] || die "the STORAGE_COPIES row committed at $CC_CB, not before its effective height $E25"
    pump_to $(( B1 + 2 * E + 1 ))
    cell_read "B1+2E" "$(( B1 + 2 * E ))" "$A" $(( B1 + 2 * E + 1 ))
    check_legs post "B1+2E"
    check_storage_state $(( B1 + 2 * E )) 4 "B1+2E (R still 4)"
    diff_full_at $(( B1 + 2 * E )) "B1+2E-at-height-$(( B1 + 2 * E ))"
    pump_to $(( B1 + 3 * E + 1 ))
    cell_read "B1+3E" "$(( B1 + 3 * E ))" "$A" $(( B1 + 3 * E + 1 ))
    check_legs post "B1+3E"
    check_storage_state $(( B1 + 3 * E )) 5 "B1+3E (R = 5)"
    [ "$(rows_from $(( B1 + 3 * E )))" = 1 ] || die "B1+3E: $(rows_from $(( B1 + 3 * E ))) row(s) inserted, expected exactly 1 (the one eligible member that was not a holder)"
    [ "$(rows_ended $(( B1 + 3 * E )))" = 0 ] || die "B1+3E: rows ended at it, expected none (R grows)"
    [ "$(n_new_sum $(( B1 + 3 * E )))" = 1 ] || die "B1+3E: Σ n_new = $(n_new_sum $(( B1 + 3 * E ))), expected 1"
    [ "$(cell_lines assign | awk -F'|' '$1 == 1 && $5 == "-"' | wc -l)" = 5 ] || die "B1+3E: segment 1 does not have five current rows"
    echo "[ok] B1+3E=$(( B1 + 3 * E )): STORAGE_COPIES 5 took effect at the freeze — five current rows for segment 1, exactly one new holder (n_new 1)"
    diff_full_at $(( B1 + 3 * E )) "B1+3E-at-height-$(( B1 + 3 * E ))"
    require_holder_files "B1+3E" $(( B1 + 3 * E ))

    # (e) the exit of node $EXITER by its owner (its own key), at B_rel
    xlog="$LOGD/exit_node$EXITER.log"; xrc=0
    xport=$(stagef_tcp_port "$(dial_for "$EXITER" "$(node_keys "$EXITER")")")
    "$CLI" -s 127.0.0.1 -p "$xport" storage exit --keys "$(node_keys "$EXITER")" \
        --node-fp "${FP[$EXITER]}" --submit "127.0.0.1:$xport" > "$xlog" 2>&1 || xrc=$?
    cat "$xlog"
    [ "$xrc" = 0 ] || die "storage exit of node$EXITER by its owner exited $xrc (see $xlog)"
    grep -q '^accepted: mempool CheckTx approved' "$xlog" || die "storage exit: no CheckTx approval line (see $xlog)"
    h=$(stagef_cmt_wait_row "$(db_of "$EXITER")" \
        "SELECT COUNT(*) FROM v2_storage_nodes WHERE lower(hex(node_fp)) = '${FP[$EXITER]}' AND status IN (2, 3) AND exit_height > 0;") && wrc=0 || wrc=$?
    [ "$wrc" = 0 ] || die "node$EXITER's exit did not land (wait rc $wrc, tip $h)"
    XH=$(sqlite3 "$(db_of "$EXITER")" "SELECT exit_height FROM v2_storage_nodes WHERE lower(hex(node_fp)) = '${FP[$EXITER]}';" 2>/dev/null || echo ERR)
    [[ "$XH" =~ ^[0-9]+$ ]] && [ "$XH" -gt 0 ] || die "node$EXITER's exit_height is '$XH'"
    B_REL=$(( (XH + E - 1) / E * E ))
    [ "$B_REL" = $(( B1 + 4 * E )) ] || die "the exit landed at x=$XH, its release boundary $B_REL is not B1 + 4E = $(( B1 + 4 * E )) — $MSG_LAYOUT"
    echo "[ok] node$EXITER EXITING at x=$XH — release boundary B_rel=$B_REL"
    pump_to $(( B_REL + 1 ))
    cell_read "B_rel" "$B_REL" "$A" $(( B_REL + 1 ))
    check_legs post "B_rel"
    check_storage_state "$B_REL" 5 "B_rel (node $EXITER out)"
    [ "$(reg_status "${FP[$EXITER]}")" = 3 ] || die "B_rel: node$EXITER's registry status is '$(reg_status "${FP[$EXITER]}")', expected 3 (RELEASED)"
    [ "$(cell_lines assign | awk -F'|' -v f="${FP[$EXITER]}" '$2 == f && $5 == "-"' | wc -l)" = 0 ] || die "B_rel: node$EXITER still has current assignment rows"
    [ "$(cell_lines assign | awk -F'|' -v f="${FP[$EXITER]}" -v b="$B_REL" '$2 == f && $5 == b' | wc -l)" = 1 ] || die "B_rel: node$EXITER's row of segment 1 was not ended at $B_REL"
    [ "$(cell_lines assign | awk -F'|' '$1 == 1 && $5 == "-"' | wc -l)" = 4 ] || die "B_rel: segment 1 does not have four current rows (five members minus the exiter, R = 5)"
    [ "$(n_new_sum "$B_REL")" = 0 ] || die "B_rel: Σ n_new = $(n_new_sum "$B_REL"), expected 0 (nobody gains a segment)"
    echo "[ok] B_rel=$B_REL: node$EXITER RELEASED, out of the basis, its row ended at $B_REL, four holders keep theirs, no n_new"
    diff_full_at "$B_REL" "B_rel-at-height-$B_REL"
    # T-16: the displaced holder keeps its file through the overlap epoch, then deletes it
    [ -f "$(seg_file "$EXITER" 1)" ] || die "B_rel: node$EXITER's seg-1.ok is already gone at tip $(tip_of 1) — it must be kept through the overlap epoch"
    require_holder_files "B_rel" "$B_REL"
    pump_to $(( B_REL + E - 1 ))
    [ -f "$(seg_file "$EXITER" 1)" ] || die "node$EXITER's seg-1.ok was deleted at tip $(tip_of 1) < B_rel + E = $(( B_REL + E )) — before the overlap epoch ended"
    echo "[ok] T-16: node$EXITER still has seg-1.ok at tip $(tip_of 1) (B_rel + E - 1) — the overlap epoch"
    pump_to $(( B_REL + E + 1 ))
    wait_seg_gone "$EXITER" 1 $(( B_REL + E + 4 )) || die "node$EXITER's seg-1.ok was not deleted by tip $(( B_REL + E + 4 )) although it is no holder in either epoch any more"
    echo "[ok] T-16: node$EXITER deleted seg-1.ok once the overlap epoch had passed (tip $(tip_of 1))"
fi

# ── 7. hf9: a fresh node replaying from genesis ─────────────────────
vnd=$(stagef_node_dir "$VICTIM")
vlog=$(stagef_node_log "$VICTIM")
src=0; stagef_stop_node "$VICTIM" KILL || src=$?
[ "$src" = 0 ] || die "stopping node$VICTIM for the wipe failed (stagef_stop_node rc=$src)"
ALIVE=()
for n in $(seq 1 "$N"); do [ "$n" = "$VICTIM" ] || ALIVE+=("$n"); done
sleep 3
rm -f "$vnd/data/"*.db "$vnd/data/"*.db-wal "$vnd/data/"*.db-shm \
      "$vnd/data/.witness_db_seen" "$vnd/data/.bootstrap_in_progress" \
      "$vnd/data/.recovery_in_progress"
rm -rf "$vnd/data/archive" "$vnd/data/segments"
: > "$vnd/nodus.log"
[ "$vlog" = "$vnd/nodus.log" ] || : > "$vlog"
ls "$vnd/data/"witness_*.db >/dev/null 2>&1 && die "the wipe did not remove node$VICTIM's chain DB"
echo "[ok] node$VICTIM wiped (identity kept, databases and logs gone)"
fleet_chain=$(basename "$(db_of 1)")
stagef_spawn_node "$VICTIM" --v2-genesis-pin "$PIN" \
    || die "node$VICTIM did not come up after the wipe (the [FAIL] line above names the process)"
adopted=0
for _ in $(seq 1 120); do
    if ls "$vnd/data/"witness_*.db >/dev/null 2>&1 && [ -n "$(db_of "$VICTIM")" ]; then adopted=1; break; fi
    sleep 1
done
[ "$adopted" = 1 ] || { tail -30 "$vlog" >&2; die "node$VICTIM never adopted a chain"; }
[ "$(basename "$(db_of "$VICTIM")")" = "$fleet_chain" ] || die "node$VICTIM adopted a DIFFERENT chain than the fleet's"
fleet_tip=$(tip_of 1)
vt=$(stagef_cmt_wait_height "$(db_of "$VICTIM")" "$fleet_tip" 3) \
    || die "node$VICTIM adopted the chain but did not replay to the fleet tip $fleet_tip (stuck at $vt)"
echo "[ok] node$VICTIM replayed from genesis to tip $vt (fleet tip was $fleet_tip)"
ALIVE=()
for n in $(seq 1 "$N"); do ALIVE+=("$n"); done
# the replay crossed the edges: its log was truncated, so these lines are of THIS replay
grep -qF "$HF7_LINE" "$vlog" || die "the replaying node$VICTIM logged no '$HF7_LINE' line — it did not replay the generation-5 edge"
grep -qF "$HF9_LINE" "$vlog" || die "the replaying node$VICTIM logged no '$HF9_LINE' line — it did not replay the generation-6 edge"
echo "[ok] node$VICTIM's replay logged the generation-5 and the generation-6 edge lines"
wait_all "$vt"
for x in $(( A - 1 )) "$A" $(( A + 1 )) "$vt"; do diff_full_at "$x" "replay-at-height-$x"; done
cell_read "post-replay" "$(( A - 1 )) $A $(( A + 1 ))" "$A" "$vt"
check_legs post "post-replay (tip $CELL_TIP, 7/7)"
if [ "$WITH_STORAGE" = 1 ]; then
    members_set $MEMBERS_PRE "$JOINER"
    st=$(cell_one astate)
    [ "${st%%|*}" = 5 ] || die "post-replay: v2_storage_assign_state.copies = '${st%%|*}', expected 5"
    [ "$(cell_lines assign | awk -F'|' '$1 == 1 && $5 == "-"' | wc -l)" = 4 ] || die "post-replay: segment 1 does not have four current rows"
    echo "[ok] post-replay: the replayed node holds the same storage relations (R 5, four current rows, every table byte-identical to the six others)"
fi
stagef_sentinel ASSERT_RUN
floor_diff "post-hf9"

# ── 8. no fault line anywhere ───────────────────────────────────────
for n in $(seq 1 "$N"); do
    if grep -q 'HF9-SHADOW FAULT' "$(node_log "$n")"; then
        grep 'HF9-SHADOW FAULT' "$(node_log "$n")" | tail -3 >&2
        die "node$n logged an HF9-SHADOW FAULT (plan §11)"
    fi
    if grep -q 'CMT_FAULT' "$(node_log "$n")"; then
        grep 'CMT_FAULT' "$(node_log "$n")" | tail -3 >&2
        die "node$n logged a CMT_FAULT"
    fi
done
echo "[ok] no node logged an HF9-SHADOW FAULT or a CMT_FAULT"

stagef_sentinel PASS
echo ""
echo "[info] HEIGHTS: HF2 $H2 | HF3 $H3 | GEN2 $H4 | EVM $HE | ROLES $H6 | ROOTS $A5 | TRIE (A) $A | H2 $H2_LAST | B1 $B1"
if [ "$WITH_STORAGE" = 1 ]; then
    echo "       | segment 1 at $H_PUB | join B1+E $(( B1 + E )) | STORAGE_COPIES effective $E25 | R=5 at $(( B1 + 3 * E )) | exit x=$XH released $B_REL"
    echo "[PASS] HF-9 generation 6 at E=$E (7/7 at epoch length $E): populated legs (utxo, token, claims, name,"
    echo "       registry, segment, snapshots, attendance), D6 voted at A=$A, the edge at the end of A-1, eight leg"
    echo "       roots and the storage assignment byte-identical on 7/7 at A, B1, B1+E, B1+2E, B1+3E and the exit's"
    echo "       boundary, node $VICTIM restarted across A and then replayed from genesis, segment files held and"
    echo "       dropped as the overlap rule says. NOT driven: the fail-streak crossing, any settlement amount."
else
    echo "[PASS] HF-9 generation 6 at E=$E WITHOUT storage segments (production-constant edge run): populated"
    echo "       legs 1, 2, 3, 4, 7, 8 and EMPTY legs 5 and 6 (their roots equal the empty-leg root), D6 voted at A=$A,"
    echo "       the edge at the end of A-1, eight leg roots byte-identical on 7/7, node $VICTIM restarted across A and"
    echo "       then replayed from genesis. LEFT OUT: storage registration, segment 1 (P = 24 x E is out of reach),"
    echo "       B1, join, exit, param 25 (header)."
fi
