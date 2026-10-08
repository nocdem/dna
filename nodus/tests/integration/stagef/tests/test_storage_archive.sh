#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_storage_archive.sh — the archive storage reward on a 7-node chain:
# the storage rule-set generation voted in (param 16, generation 3 -> 4
# on top of the Nodus EVM generation), two storage nodes registered, the
# first archive segment published, probed over channel 0x72, reported
# and SETTLED from treasury pool 1 (standalone — NOT in the sweep)
# ════════════════════════════════════════════════════════════════════
#
# Governing records: docs/plans/decisions/2026-10-05-storage-reward-is-
# for-archive.md (K1 block count, K2/K5/K5a fail_streak, K3 samples, K4
# R = 3, K6 channel 0x72, K7 report window, K9/K9a grace, K10 generation
# 4 on GEN_EVM, param 16); 2026-10-05-archive-reward-bytes-approved.md
# (segment root bytes item 1); 2026-10-04-storage-reward-approved.md (S(H),
# register / report / exit); design docs/plans/2026-10-05-archive-reward-
# design.md rev 4; nodus/docs/DEPLOY_RUNBOOK.md §2.2 (height-activated
# votes) and §2.6 (the storage node). TEMPLATE: test_cmt_evm.sh — its
# helpers are copied (one build here: no OLD/NEW pair, no rolling
# upgrade), every new part is marked "storage:".
#
# WHY THE SEGMENT IS REACHABLE AT ALL: a segment is one payday period of
# 24 epochs (DNA_V2_SEGMENT_BLOCKS = 24 × DNAC_EPOCH_LENGTH,
# shared/dnac/ledger_roots_v2.h) — 17 280 blocks at the shipped E = 720
# (unchanged, asserted in ledger_roots_v2.c), 360 at the short-epoch
# build's E = 15. Segment 1 = heights 1..P, due at the first storage
# boundary >= P + 2E (nodus_witness_v2_storage.c st_publish:
# DNAC_STORAGE_SEGMENT_DELAY_EPOCHS = 2).
#
# WHAT IT PROVES — each item would be false if it failed
#   0. Capability gate (FAIL): the server and the CLI print one version
#      banner; the CLI's chain-config usage names "EVM_ACTIVE exactly <D>"
#      and "RULESET_GEN_STORAGE exactly <DS>" (its compiled literals —
#      never a script literal) and it has the `storage` command.
#   1. The chain commits; node 3 (the pump) and the two storage nodes 4
#      and 5 claim their genesis leaves (100M NODUS each — the bond is
#      exactly 10^14 raw, DNAC_STORAGE_STAKE_MIN).
#   2. The storage generation's prerequisites, in order, each row
#      identical 7/7 and committed below its effective height: HF2_ACTIVE,
#      HF3_ACTIVE, RULESET_GEN2 (generation 1 -> 2), EVM_ACTIVE
#      (generation 2 -> 3 + the EVM domain; H >= initial_height + 256 + 5,
#      red-team F5 rule (g)). A fresh chain is generation 1, and param 16
#      is votable only while the EVM generation judges the vote
#      (nodus_witness_chain_config.c, CC_PARAM_RULESET_GEN_STORAGE rule
#      (d)), whose own vote needs HF-2, HF-3 and generation 2 (rules
#      (b)/(c)/(e)) — so all five votes are needed, not two.
#   3. Before the storage vote: `storage register --dry-run` is refused by
#      the CLI's generation gate ("storage registration exists only from
#      generation 4"), and `storage status` says "not registered".
#   4. RULESET_GEN_STORAGE = DS voted at H_s (H_s % E == 2: H_s - 1 is off
#      a boundary — rule (c) — and the first storage boundary is E - 2
#      blocks after it); round 1 7/7; the row identical 7/7, committed
#      < H_s. Crossing H_s (pumped to H_s - 7, then idle): 7/7 identical
#      blocks AT H_s - 1, H_s, H_s + 1; every node logged "storage reward:
#      rule-set generation 3 -> 4 at the end of height H_s - 1 (storage
#      vote literal 0x<DS>)"; `ruleset-info` 7/7 = generation 4.
#   5. Nodes 4 and 5 `storage register --submit` with their NODE keys:
#      each v2_storage_nodes row lands (ACTIVE, bond 10^14, payee = the
#      node's own fingerprint, fail_streak 0, grace_until 0) and the
#      registry is identical on 7/7; both are members of the first frozen
#      set that contains them (B_in), and B_in <= the publication boundary
#      (else the layout broke — FAIL, see HOW IT CAN LIE).
#   6. Segment 1 is published at exactly H_pub = the first storage
#      boundary >= 26E: one v2_storage_segments row (k 1, root,
#      published_height) identical on 7/7, no k = 2; its root equals
#      SHA3-512("NDS.STSEG.v1" (16 B) ‖ k (8 BE) ‖ count = P (4 BE) ‖
#      block_id[1] ‖ … ‖ block_id[P]) recomputed by this script from
#      node 1's v2_blocks (bytes item 1 at P = 24E).
#   7. `storage status` during the epoch after H_pub, on each storage
#      node's own port with its own key: "registry: ACTIVE, bond
#      100000000000000 raw, fail_streak 0", "grace_until: 0 (never in
#      grace)" — K9a: no set(H − E) at the first storage boundary, and a
#      segment published at a boundary is not counted at it
#      (nodus_witness_v2_storage.c nodus_storage_grace_counts,
#      st_grace_update) — no "IN GRACE" note, "2 member(s), this node IS a
#      member", "eligible segments this epoch: 1 (P blocks): 1". Node 1
#      (not registered) reads "not registered" / "is NOT a member".
#   8. Validators report: for the probing epoch Hx (H_pub, or the next
#      epoch when H_pub + 2E is a payday), the committed
#      v2_storage_reports rows (read after the window (Hx+E, Hx+E+⌊E/2⌋]
#      closed and before Hx + 2E prunes them) are identical on 7/7, carry
#      set_hash = the frozen S(Hx), and come from MORE than half the seats
#      (F1, equal genesis power).
#   9. The settlement at B = Hx + 2E (not a payday) pays the storage
#      payees: from ONE-statement snapshots before and after B,
#        pool1_pre − pool1_post == 2 × ⌊(pool1_pre >> 16) / 2⌋
#      (both members OK with equal weight P — v2_storage.c st_settle:
#      budget = pool1 >> NODUS_V2_GEN_REWARD_DIVISOR_LOG2, share =
#      ⌊budget × w / W⌋),
#        Σaccrual_post − Σaccrual_pre == (reward_pool_pre − reward_pool_post)
#                                        + (pool1_pre − pool1_post)
#      (the storage pay lands in the same v2_reward_accrual table as the
#      validator reward of the same boundary), and each storage payee's
#      accrual rose by at least ⌊(pool1_pre >> 16) / 2⌋.
#  10. fail_streak stays 0 and grace_until 0 for both honest storage
#      nodes on 7/7 after the settlement (an OK epoch with eligible blocks
#      resets to 0 — K5a; a NOT OK one would have written 1), and 7/7
#      identical global_root + block_id at the final floor.
#
# WHAT IT REQUIRES
#   Compile flags — ONE short-epoch + short-grace build, nodus-server AND
#   nodus-cli from the SAME tree, with NODUS_EVM_ENABLED (the default of
#   the standalone non-Windows nodus build, nodus/CMakeLists.txt; the
#   storage generation is compiled only there — K10 (a)):
#     -DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#   (params 7, 8, 9, 16 are ERGONOMIC; param 14 is SAFETY.)
#   Environment, ALL exported BEFORE stagef_up_v2.sh (hashed into the
#   genesis document) unless noted:
#     STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN    that build
#     STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     STAGEF_TREASURY_POOL1_RAW=1000000000000000   (suggested 10^15 raw =
#         10M NODUS; pool 1 is 0 on a harness chain without it, and a
#         settlement then pays nothing — SKIP below 2^17)
#     STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15  (read by
#         this script only)
#   Leave STAGEF_PAYOUT_INTERVAL_EPOCHS unset (24): the script steps off a
#   payday by itself; 1 (every boundary a payday) is a SKIP.
#   Tools: sqlite3, xxd, openssl with SHA3-512, ss.
#   Exact command sequence (ORCHESTRATOR):
#     F='-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
#     cmake -S <TREE>/nodus -B <TREE>/nodus/build-shortepoch -DCMAKE_C_FLAGS="$F"
#     make -C <TREE>/nodus/build-shortepoch -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN=<TREE>/nodus/build-shortepoch/nodus-server
#     export STAGEF_NODUSCLI_BIN=<TREE>/nodus/build-shortepoch/nodus-cli
#     export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     export STAGEF_TREASURY_POOL1_RAW=1000000000000000
#     S=<TREE>/nodus/tests/integration/stagef
#     bash $S/stagef_up_v2.sh
#     bash $S/tests/test_storage_archive.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   SKIP (rc 99): a binary missing / not executable, STAGEF_EPOCH_LENGTH
#   or the genesis epoch_length != 15, a grace variable != 15, not a
#   Comet cluster, no $BASE_DIR/v2_genesis.conf, pool 1 below 2^17,
#   payout_interval_epochs = 1, a tool missing, any split STAGEF_MODE
#   (the storage RPCs were not checked through a split core). A skip is
#   not a pass.
#
# WHAT IT LEAVES BEHIND
#   HF-2 ACTIVE, HF-3 ACTIVE, rule-set generation 2, the EVM generation 3
#   + EVM domain and the storage generation 4 — all one-way; five
#   chain_config_history rows (params 7, 8, 9, 14, 16). Nodes 4 and 5
#   registered storage nodes (ACTIVE, bond 10^14 each locked), segment 1
#   published, their segment files under node<4,5>/data/segments (if the
#   holder finished exporting), pool 1 debited by one settlement, the
#   payees' accrual raised. The leaves of nodes 3, 4, 5 claimed. Every
#   pump fee in the reward pool. $BASE_DIR/storage/ (every CLI log).
#   Nothing restarted. Tear down with stagef_down.sh before re-running
#   (leaves and params 9 / 14 / 16 are single-use).
#
# HOW IT CAN LIE
#   - **E = 15, grace 15/15, BPY 20 prove the LOGIC, not 720 / 17 280.**
#     A segment is 360 blocks here and 17 280 in production; the segment
#     file, the 0x72 samples and the 0x73 fetch run over 360 heights. The
#     production segment length is held only by the compile-time assert
#     (ledger_roots_v2.c) and the unit tests run at the default E = 720
#     (test_storage_*; their own headers say most of them run at any
#     E >= 8 — test_storage_b2.c:144-147 — and test_storage_probe.c loops
#     E = 720 and 15; whether every one passes at E = 15 is NOT verified).
#   - **Both storage nodes are also validators** (the runbook §2.6
#     "both-roles node"). A storage node that is NOT a validator (serving
#     0x72 to validators over a persistent peer, earning only the storage
#     reward) is NOT exercised; F2 (a seat's own bit is not counted for
#     itself) is exercised only in that each storage node's own seat is
#     one of the reporters.
#   - **Only the honest path.** No NOT OK verdict, no fail_streak + 1, no
#     skip at 3, no K5 return, no grace > 0, no handoff of a segment to
#     another holder, no exit / release, no 0x73 fetch (every holder has
#     the blocks in its own store). No fault knob for the 0x72 serving
#     side exists in the tree (no getenv in nodus_witness_storage_*.c);
#     SIGSTOP of a storage node here would also freeze a validator for
#     >= 7 blocks, beyond the 5-block cap test_cmt_blocksync.sh keeps to
#     stay clear of Rule N — so the NOT OK path is not driven. Unit tests
#     (test_storage_b2, test_storage_probe) are its proof.
#   - **The settlement checks are arithmetic on committed tables:** each
#     payee's own storage share is not separable from its validator
#     reward of the same boundary — only the conservation sum, the exact
#     pool 1 debit and a lower bound per payee are asserted. The per-seat
#     report bitmaps are PRINTED, not judged; the > 2/3 verdict per member
#     is proved by the exact debit (a member NOT OK is paid nothing).
#   - **F1 is asserted as "more than half the seats reported"**, which is
#     "more than half the power" only because the genesis validators bond
#     equal stakes; nothing here self-delegates.
#   - **No payday is observed:** the settlement boundary is stepped off a
#     payday on purpose (a payday empties the accrual table in the same
#     block); the accrual -> coin step is test_v2_rewards.sh's subject.
#   - **The segment root is re-derived HERE** from the formula as the C
#     implements it (ledger_roots_v2.c dna_v2_segment_root) — a
#     self-consistency check at P = 360, not an independent KAT.
#   - **The registration layout:** both nodes must be in a frozen set no
#     later than the publication boundary, so that K9a gives grace 0. If a
#     slow machine lands a registration after it, the scenario FAILS with
#     "layout broke" (a false RED, never a false PASS); the grace > 0 path
#     is not exercised.
#   - **A report that misses its 7-block window** (⌊E/2⌋) loses that
#     seat's report; if more than half miss, nothing settles and the pay
#     assertions FAIL — a false RED. The probing epoch, the window and the
#     settlement are crossed on IDLE production (no pump spend in flight)
#     for that reason. Probes are localhost and the probe deadline is wall
#     clock (10 s) — NTP is trivially in sync here.
#   - **Segment files** (`seg-1.ok`) and the per-node "probe of … OK" /
#     "report for H=… committed" lines are REPORTED, not asserted.
#   - Every wait is progress- and height-bounded (stagef_cmt_wait_height /
#     _wait_row), never a bare sleep (the 0.5 s / 1 s attempt-bounded
#     polls are the template's). rc 99 = SKIP, coverage that did not
#     happen.
#   - Duration: ≈ 430 blocks (JUDGMENT, not measured): pumped to the EVM
#     edge's window floor (≈ 262) and on to the publication boundary
#     (≈ 390), idle across the GEN2, EVM and storage edges (≈ 8 blocks
#     each) and across the last ≈ 30 blocks (probing epoch, report
#     window, settlement) — on the order of 1.5-2 h.
#   - Run results: PASS on 2026-10-06 at bf1c4c1f (104 [ok]) and at
#     49c7218f (103 [ok]), both E=15 / BPY 20 / grace 15/15, P=360,
#     pool 1 = 10^15 (orchestration ledger, the two HARNESS BİTTİ lines).
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"
# storage: the storage RPCs (dnac_storage_status, ruleset-info) were not
# checked through a split core — SKIP (99) in every split mode.
stagef_split_skip_if --reason "storage RPCs not checked through a split core" \
    $(seq 1 "$STAGEF_COMMITTEE_SIZE")

die() { echo "[FAIL] $*" >&2; exit 1; }

S_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRV="$STAGEF_NODUS_BIN"
CLI="$STAGEF_NODUSCLI_BIN"
PARAM_HF2=7                # DNAC_CFG_HF2_ACTIVE (dnac.h), value exactly 1
PARAM_HF3=8                # DNAC_CFG_HF3_ACTIVE (dnac.h), value exactly 1
PARAM_GEN2=9               # DNAC_CFG_RULESET_GEN2 (dnac.h), value exactly D2
PARAM_EVM=14               # DNAC_CFG_EVM_ACTIVE (dnac.h), value exactly D
PARAM_STOR=16              # storage: DNAC_CFG_RULESET_GEN_STORAGE, value exactly DS
GEN_2=2                    # NODUS_RT_GEN_2
GEN_EVM=3                  # NODUS_RT_GEN_EVM (= NODUS_RT_GEN_STORAGE_BASE)
GEN_STOR=4                 # storage: NODUS_RT_GEN_STORAGE (nodus_witness_runtime.c)
GRACE_MARGIN=5             # the HF-2/HF-3/HF-4 template's +5
WINDOW_MARGIN=5            # the EVM template's F5 window margin
CC_GUARD_GAP=4             # the EVM template's epoch-boundary guard
PUMP_STOP_GAP=7            # the HF-4 template's idle window before an edge
E_REQ=15
E="$E_REQ"
P=$(( 24 * E ))            # storage: DNA_V2_SEGMENT_BLOCKS = 24 x DNAC_EPOCH_LENGTH
DELAY=$(( 2 * E ))         # storage: DNAC_STORAGE_SEGMENT_DELAY_EPOCHS x E
REPORT_CLOSE=$(( E / 2 ))  # storage: the report window (H+E, H+E+⌊E/2⌋]
DIV_LOG2=16                # storage: NODUS_V2_GEN_REWARD_DIVISOR_LOG2 (v2_gen.h)
BOND=100000000000000       # storage: DNAC_STORAGE_STAKE_MIN = 10^6 x 10^8
ST_A=4                     # storage: the two storage nodes (both validators)
ST_B=5
CONF="$BASE_DIR/v2_genesis.conf"
LOGD="$BASE_DIR/storage"
N="$STAGEF_COMMITTEE_SIZE"

# ── SKIP gates (rc 99 — a skip is not a pass) ───────────────────────
for pair in "STAGEF_NODUS_BIN=$SRV" "STAGEF_NODUSCLI_BIN=$CLI"; do
    name="${pair%%=*}"; bin="${pair#*=}"
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        echo "[SKIP] $name is unset or not executable ('$bin') — this scenario needs the short-epoch"
        echo "       build of a tree with the storage generation; see the header"
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
for t in sqlite3 xxd openssl ss; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "[SKIP] '$t' is not installed — the storage checks need it"
        exit 99
    fi
done
if [ "$(printf 'abc' | openssl dgst -sha3-512 2>/dev/null | awk '{print $NF}')" != \
     "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" ]; then
    # SHA3-512("abc") — the known-answer probe test_cmt_evm.sh uses
    echo "[SKIP] this openssl has no working SHA3-512 (the segment root re-derivation needs it)"
    exit 99
fi
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
if [ "$CONF_E" != "$E_REQ" ]; then
    echo "[SKIP] the genesis document says epoch_length=${CONF_E:-?}, this scenario needs $E_REQ"
    exit 99
fi
INTERVAL=$(sed -n 's/^payout_interval_epochs *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
case "$INTERVAL" in ''|*[!0-9]*) die "no payout_interval_epochs in $CONF" ;; esac
if [ "$INTERVAL" -le 1 ]; then
    echo "[SKIP] payout_interval_epochs=$INTERVAL: every boundary is a payday, so the settlement"
    echo "       boundary can never be read without a payday emptying the accrual table — leave"
    echo "       STAGEF_PAYOUT_INTERVAL_EPOCHS unset (24)"
    exit 99
fi
POOL1_0=$(sqlite3 "$ref_db0" "SELECT balance FROM v2_treasury WHERE pool_id = 1;" 2>/dev/null || echo ERR)
case "$POOL1_0" in ''|*[!0-9]*) die "treasury pool 1 unreadable on node1 ('$POOL1_0')" ;; esac
if [ "$POOL1_0" -lt 131072 ]; then
    echo "[SKIP] treasury pool 1 holds $POOL1_0 raw — below 2^17 the budget (pool1 >> $DIV_LOG2) cannot"
    echo "       pay two members a non-zero share; export STAGEF_TREASURY_POOL1_RAW (suggested"
    echo "       1000000000000000) BEFORE stagef_up_v2.sh"
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
# cmd_chain_config_propose: "  EVM_ACTIVE             exactly %llu",
# "  RULESET_GEN_STORAGE    exactly %llu", printed before any connect)
usage_out=$(timeout 60 "$CLI" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose 2>&1 || true)
D_DEC=$(sed -n 's/^  EVM_ACTIVE  *exactly \([0-9][0-9]*\) .*/\1/p' <<< "$usage_out")
D_DEC="${D_DEC%%$'\n'*}"
DS_DEC=$(sed -n 's/^  RULESET_GEN_STORAGE  *exactly \([0-9][0-9]*\) .*/\1/p' <<< "$usage_out")
DS_DEC="${DS_DEC%%$'\n'*}"
[ -n "$D_DEC" ] && [ -n "$DS_DEC" ] || {
    printf '%s\n' "$usage_out" >&2
    die "the CLI's chain-config usage does not name both 'EVM_ACTIVE exactly <D>' and 'RULESET_GEN_STORAGE exactly <DS>'"; }
[ "$D_DEC" -gt 0 ] 2>/dev/null && [ "$DS_DEC" -gt 0 ] 2>/dev/null || die "a vote literal is not a positive int64 (D '$D_DEC', DS '$DS_DEC')"
D_HEX=$(printf '%016x' "$D_DEC"); DS_HEX=$(printf '%016x' "$DS_DEC")
st_usage=$(timeout 60 "$CLI" -s 127.0.0.1 -p "$PROBE_PORT" storage 2>&1 || true)
[[ "$st_usage" == *"storage status [--fp <hex128>]"* ]] || {
    printf '%s\n' "$st_usage" >&2; die "the CLI has no 'storage' command (B2b-CLI)"; }
echo "[ok] capability gate: one build v$SRV_VER; EVM D = $D_DEC (0x$D_HEX), storage DS = $DS_DEC (0x$DS_HEX); 'storage' present"

# ── script-local helpers (test_cmt_evm.sh's, unless "storage:") ─────
db_of()  { stagef_node_chain_db "$1"; }
tip_of() { stagef_cmt_tip "$(db_of "$1")"; }
fp_of()  { cat "$1/nodus.fp"; }                 # $1 = identity dir
fp_lc()  { tr 'A-F' 'a-f' < "$1/nodus.fp"; }
node_keys() { echo "$(stagef_node_dir "$1")/identity"; }
node_log()  { stagef_node_log "$1"; }

node_runs_srv() {          # storage: the one build (no OLD/NEW pair)
    local pat pid
    pat="-d $(stagef_node_dir "$1")/data"
    for pid in $(pgrep -f -- "$pat" || true); do
        [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" = "$(readlink -f "$SRV")" ] && return 0
    done
    return 1
}

spend_intent() { awk -F= '/^  intent_id=/{print $2; exit}' "$1"; }

claim_leaf() {
    local keys="$1" node="$2" port db fp log h wrc
    port=$(stagef_tcp_port "$node"); db=$(db_of "$node"); fp=$(fp_of "$keys")
    log="$LOGD/claim_$(basename "$(dirname "$keys")").log"
    "$CLI" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$db" \
        --keys "$keys" --submit "127.0.0.1:$port" > "$log" 2>&1 \
        || { cat "$log" >&2; die "v2-claim for $keys was refused (see $log)"; }
    h=$(stagef_cmt_wait_row "$db" \
        "SELECT COUNT(*) FROM utxo_set WHERE owner = '$fp'
           AND token_id = zeroblob(64) AND amount > $STAGEF_PUMP_FEE_RAW;") && wrc=0 || wrc=$?
    [ "$wrc" = 0 ] || die "the claimed coin for $keys never appeared (wait rc=$wrc, tip $h)"
    echo "[ok] claimed the genesis leaf of $keys (tip $h)"
}

wait_applied() {
    local h wrc
    h=$(stagef_cmt_wait_row "$(db_of "$1")" \
        "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$2';") && wrc=0 || wrc=$?
    case "$wrc" in
        0) printf '%s\n' "$h" ;;
        1) die "chain STALLED waiting for spend ${2:0:16}... on node$1 (tip $h)" ;;
        *) die "spend ${2:0:16}... not included within 20 heights on node$1 (tip $h) — dropped, not delayed" ;;
    esac
}

PUMP_KEYS=$(node_keys 3)
PUMP_SEQ=0
pump_to() {
    local node="$1" target="$2" log intent port
    port=$(stagef_tcp_port "$node")
    while [ "$(tip_of "$node")" -lt "$target" ]; do
        PUMP_SEQ=$(( PUMP_SEQ + 1 ))
        log="$LOGD/pump_$PUMP_SEQ.log"
        "$CLI" -s 127.0.0.1 -p "$port" v2-envelope spend --keys "$PUMP_KEYS" \
            --to "$(fp_of "$PUMP_KEYS")" --amount all --count 1 \
            --submit "127.0.0.1:$port" > "$log" 2>&1 \
            || { cat "$log" >&2; die "pump spend $PUMP_SEQ was refused/failed on node$node (see $log)"; }
        intent=$(spend_intent "$log")
        [ "${#intent}" = 128 ] || { cat "$log" >&2; die "pump spend $PUMP_SEQ printed no intent_id"; }
        wait_applied "$node" "$intent" >/dev/null
    done
    echo "[ok] node$node tip $(tip_of "$node") >= $target (pumped)"
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
# the committee of tip + 1 but the epoch of tip — nodus/BUGS.md): the
# proposer's tip t must be off a boundary and >= CC_GUARD_GAP before the
# next one, else pump to the next boundary + 1. Sets CCG_TIP / CCG_NB.
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
        pump_to 1 $(( nb + 1 ))
        wait_all $(( nb + 1 ))
    done
    die "node$n's tip $(tip_of "$n") is still next to an epoch boundary after two guard pumps"
}

cc_guard_after() {
    local t
    t=$(tip_of "$1")
    [ $(( t + 1 )) -lt "$CCG_NB" ] || die \
        "the proposal from node$1 crossed into the epoch boundary $CCG_NB (tip $CCG_TIP -> $t): its approvals may straddle two epochs (the CLI committee/epoch edge, nodus/BUGS.md) — the layout broke, not the chain"
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

# ruleset_info NODE — nodus-cli.c cmd_ruleset_info's lines (the EVM
# template's parser).
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

# cross_edge LABEL H — pumped to H - PUMP_STOP_GAP (a generation-N
# envelope still pending past the switch would read as "dropped": false
# RED only), then idle across H - 1 / H / H + 1, compared 7/7 AT each.
cross_edge() {
    local label="$1" hh="$2" x
    pump_to 1 $(( hh - PUMP_STOP_GAP ))
    wait_all $(( hh + 1 ))
    for x in $(( hh - 1 )) "$hh" $(( hh + 1 )); do diff_at "$x" "$label-at-height-$x"; done
}

# ── storage: helpers ────────────────────────────────────────────────
is_payday() { [ $(( ($1 / E) % INTERVAL )) -eq 0 ]; }

# registry_dump NODE — the whole storage registry, canonical
registry_dump() {
    sqlite3 "$(db_of "$1")" \
        "SELECT lower(hex(node_fp)) || '|' || lower(hex(payee_fp)) || '|' || bond || '|' || status || '|' ||
                registered_height || '|' || exit_height || '|' || fail_streak || '|' || grace_until
           FROM v2_storage_nodes ORDER BY node_fp;" 2>/dev/null || echo ERR
}

# require_registry WHAT — the registry identical on 7/7, exactly the two
# storage nodes, each ACTIVE (1), bond 10^14, payee = its own fp,
# exit_height 0, fail_streak 0, grace_until 0
require_registry() {
    local what="$1" n ref d line fp payee bond status rh xh fs gu nrow=0
    ref=$(registry_dump 1)
    [ "$ref" != ERR ] && [ -n "$ref" ] || die "$what: node1's storage registry is unreadable or empty"
    for n in $(seq 2 "$N"); do
        d=$(registry_dump "$n")
        [ "$d" = "$ref" ] || { printf 'node1:\n%s\nnode%s:\n%s\n' "$ref" "$n" "$d" >&2
            die "$what: node$n's storage registry differs from node1's"; }
    done
    while IFS='|' read -r fp payee bond status rh xh fs gu; do
        nrow=$(( nrow + 1 ))
        [ "$fp" = "$FP_A" ] || [ "$fp" = "$FP_B" ] || die "$what: a registry row for an unexpected node ${fp:0:16}..."
        [ "$payee" = "$fp" ] || die "$what: ${fp:0:16}...'s payee is not its own fingerprint"
        [ "$bond" = "$BOND" ] || die "$what: ${fp:0:16}...'s bond is $bond, expected $BOND"
        [ "$status" = 1 ] || die "$what: ${fp:0:16}... is status $status, expected 1 (ACTIVE)"
        [ "$xh" = 0 ] || die "$what: ${fp:0:16}... has exit_height $xh"
        [ "$fs" = 0 ] || die "$what: ${fp:0:16}...'s fail_streak is $fs, expected 0 (honest)"
        [ "$gu" = 0 ] || die "$what: ${fp:0:16}...'s grace_until is $gu, expected 0 (K9a: no take-over)"
    done <<< "$ref"
    [ "$nrow" = 2 ] || die "$what: the registry holds $nrow rows, expected 2"
    echo "[ok] $what: the storage registry is identical on 7/7 — nodes $ST_A and $ST_B ACTIVE, bond $BOND, own payee, fail_streak 0, grace_until 0"
}

# status_of NODE KEYS_NODE [--fp FP] — `storage status` on NODE's own port
status_of() {
    local n="$1" kn="$2" log src=0
    shift 2
    log="$LOGD/status_node${kn}_on_node${n}_$(tip_of "$n").log"
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" -i "$(node_keys "$kn")" \
        storage status "$@" > "$log" 2>&1 || src=$?
    ST_RC="$src"
    ST_OUT=$(cat "$log")
}

# ── 0. preconditions: fresh cluster on this build ───────────────────
for n in $(seq 1 "$N"); do
    node_runs_srv "$n" || die "node$n is not running STAGEF_NODUS_BIN ($(readlink -f "$SRV")) — bring the cluster up with it"
done
for p in "$PARAM_HF2" "$PARAM_HF3" "$PARAM_GEN2" "$PARAM_EVM" "$PARAM_STOR"; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $p;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1 already holds a param-$p row — this scenario needs a fresh bring-up"
done
[ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM v2_storage_nodes;" 2>/dev/null || echo ERR)" = 0 ] \
    || die "node1's storage registry is not empty — this scenario needs a fresh bring-up"
INIT_H=$(sed -n 's/^initial_height *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
[ -n "$INIT_H" ] || die "no initial_height in $CONF"
[ "$INIT_H" = 0 ] && INIT_H=1
FP_A=$(fp_lc "$(node_keys "$ST_A")"); FP_B=$(fp_lc "$(node_keys "$ST_B")")
FP_1=$(fp_lc "$(node_keys 1)")
for f in "$FP_A" "$FP_B" "$FP_1"; do [ "${#f}" = 128 ] || die "a node fingerprint is not 128 hex"; done
stagef_sentinel SETUP_OK
echo "[ok] 7/7 nodes run $(readlink -f "$SRV"); pool 1 = $POOL1_0 raw; payday every $INTERVAL epochs; P = $P"

# ── 1. the chain commits; fund the pump + the storage nodes ─────────
stagef_cmt_diff_at_floor "pre-storage" || exit 2
claim_leaf "$PUMP_KEYS" 1
claim_leaf "$(node_keys "$ST_A")" "$ST_A"
claim_leaf "$(node_keys "$ST_B")" "$ST_B"
t=$(tip_of 1)
pump_to 1 $(( t + 2 ))
stagef_cmt_diff_at_floor "storage-chain-committing" || exit 2

# ── 2. the prerequisites: HF-2, HF-3, generation 2, the EVM generation ─
cc_guard 1
H2=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $CCG_TIP — node1 proposes HF2_ACTIVE=1 effective H2=$H2"
propose HF2_ACTIVE 1 "$H2" "$LOGD/propose_hf2.log"
wait_cc_row "$PARAM_HF2" "$H2" 1 20
[ "$CC_CB" -lt "$H2" ] || die "the HF2 row committed at $CC_CB, not before its effective height $H2"
pump_to 1 $(( H2 + 1 ))
wait_all $(( H2 + 1 ))
stagef_cmt_diff_at_floor "past-HF2" || exit 2

cc_guard 1
H3=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $CCG_TIP — node1 proposes HF3_ACTIVE=1 effective H3=$H3"
propose HF3_ACTIVE 1 "$H3" "$LOGD/propose_hf3.log"
wait_cc_row "$PARAM_HF3" "$H3" 1 20
[ "$CC_CB" -lt "$H3" ] || die "the HF3 row committed at $CC_CB, not before its effective height $H3"
pump_to 1 $(( H3 + 1 ))
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

# ── 3. storage: before the vote — the CLI refuses, the node knows nothing ─
st_log="$LOGD/register_pre_vote.log"; prc=0
"$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$ST_A")" -i "$(node_keys "$ST_A")" \
    storage register --dry-run > "$st_log" 2>&1 || prc=$?
cat "$st_log"
[ "$prc" != 0 ] && grep -q "storage registration exists only from generation $GEN_STOR" "$st_log" \
    || die "storage register before the vote was not refused by the CLI's generation gate (rc $prc, see $st_log)"
[ -z "$(spend_intent "$st_log")" ] || die "storage register before the vote built an envelope"
status_of "$ST_A" "$ST_A"
[ "$ST_RC" = 0 ] && [[ "$ST_OUT" == *"registry: not registered"* ]] || {
    printf '%s\n' "$ST_OUT" >&2; die "storage status before the vote did not say 'not registered' (rc $ST_RC)"; }
echo "[ok] before the storage vote: register REFUSED by the generation gate; status 'not registered'"

# ── 4. storage: the RULESET_GEN_STORAGE vote, H_s % E == 2 ──────────
cc_guard 1
HS=$(( CCG_TIP + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
while [ $(( HS % E )) != 2 ]; do HS=$(( HS + 1 )); done          # rule (c) + E-2 blocks to the boundary
echo "[ok] tip $CCG_TIP — node1 proposes RULESET_GEN_STORAGE=$DS_DEC effective H_s=$HS (first storage boundary $(( HS - 2 + E )))"
propose RULESET_GEN_STORAGE "$DS_DEC" "$HS" "$LOGD/propose_storage.log"
wait_cc_row "$PARAM_STOR" "$HS" "$DS_DEC" 20
[ "$CC_CB" -lt "$HS" ] || die "the RULESET_GEN_STORAGE row committed at $CC_CB, not before its effective height $HS"
for n in $(seq 1 "$N"); do require_gen "$n" "$GEN_EVM" "$H4"; done
cross_edge storage "$HS"
STOR_LINE="storage reward: rule-set generation $GEN_EVM -> $GEN_STOR at the end of height $(( HS - 1 )) (storage vote literal 0x$DS_HEX)"
for n in $(seq 1 "$N"); do
    grep -qF "$STOR_LINE" "$(node_log "$n")" || die "node$n logged no '$STOR_LINE' line"
    require_gen "$n" "$GEN_STOR" "$H4"
done
stagef_cmt_diff_at_floor "past-storage-edge" || exit 2
echo "[ok] the storage generation $GEN_STOR on 7/7 from H_s=$HS (DS 0x$DS_HEX)"

# ── 5. storage: register nodes 4 and 5 with their NODE keys ─────────
for k in "$ST_A" "$ST_B"; do
    log="$LOGD/register_node$k.log"; prc=0
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$k")" -i "$(node_keys "$k")" \
        storage register --submit "127.0.0.1:$(stagef_tcp_port "$k")" > "$log" 2>&1 || prc=$?
    cat "$log"
    [ "$prc" = 0 ] || die "storage register on node$k exited $prc (see $log)"
    grep -q '^accepted: mempool CheckTx approved' "$log" || die "storage register on node$k: no CheckTx approval line (see $log)"
    intent=$(spend_intent "$log")
    [ "${#intent}" = 128 ] || die "storage register on node$k printed no intent_id (see $log)"
done
REG_H=0
for k in "$ST_A" "$ST_B"; do
    if [ "$k" = "$ST_A" ]; then fp="$FP_A"; else fp="$FP_B"; fi
    h=$(stagef_cmt_wait_row "$(db_of "$k")" \
        "SELECT COUNT(*) FROM v2_storage_nodes WHERE lower(hex(node_fp)) = '$fp' AND status = 1;") && wrc=0 || wrc=$?
    case "$wrc" in
        0) ;;
        1) die "chain STALLED waiting for node$k's registry row (tip $h)" ;;
        *) die "node$k's registration did not land within 20 heights (tip $h) — dropped, not delayed" ;;
    esac
    echo "[ok] node$k registered (row visible at tip $h)"
    [ "$h" -le "$REG_H" ] || REG_H="$h"
done
wait_all "$REG_H"          # every node holds both rows at or below this tip
require_registry "post-register"

# both in a frozen set: the first set that holds both is B_in. Pumped to
# the next boundary + 1 (twice at most); its set must name them both.
B_IN=""
for try in 1 2; do
    t=$(tip_of 1)
    nb=$(( (t / E + 1) * E ))
    pump_to 1 $(( nb + 1 ))
    wait_all $(( nb + 1 ))
    B_IN=$(sqlite3 "$(db_of 1)" \
        "SELECT COALESCE(MIN(epoch_start), '') FROM (SELECT epoch_start FROM v2_storage_set_members
           WHERE lower(hex(node_fp)) IN ('$FP_A', '$FP_B') GROUP BY epoch_start HAVING COUNT(*) = 2);" 2>/dev/null || echo ERR)
    [ "$B_IN" != ERR ] || die "v2_storage_set_members unreadable on node1"
    [ -n "$B_IN" ] && break
done
[ -n "$B_IN" ] || die "nodes $ST_A and $ST_B are not both in any frozen storage set after two boundaries"
B_FIRST=$(sqlite3 "$(db_of 1)" "SELECT MIN(epoch_start) FROM v2_storage_sets;" 2>/dev/null || echo ERR)
case "$B_FIRST" in ''|*[!0-9]*) die "v2_storage_sets unreadable on node1 ('$B_FIRST')" ;; esac
for n in $(seq 1 "$N"); do
    m=$(sqlite3 "$(db_of "$n")" \
        "SELECT group_concat(lower(hex(node_fp)) || ':' || fail_streak || ':' || grace_until, ',')
           FROM (SELECT node_fp, fail_streak, grace_until FROM v2_storage_set_members
                  WHERE epoch_start = $B_IN ORDER BY node_fp);" 2>/dev/null || echo ERR)
    case "$m" in
        *"$FP_A:0:0"*"$FP_B:0:0"*|*"$FP_B:0:0"*"$FP_A:0:0"*) ;;
        *) die "node$n's frozen set S($B_IN) is not {node$ST_A, node$ST_B} with fail_streak 0 / grace_until 0: '$m'" ;;
    esac
    c=$(sqlite3 "$(db_of "$n")" "SELECT member_count FROM v2_storage_sets WHERE epoch_start = $B_IN;" 2>/dev/null || echo ERR)
    [ "$c" = 2 ] || die "node$n's v2_storage_sets row at $B_IN counts '$c' members, expected 2"
done
echo "[ok] both storage nodes are members of S($B_IN) on 7/7 (first storage boundary $B_FIRST)"

# ── 6. storage: segment 1 published at the first boundary >= P + 2E ──
H_PUB_X=$(( P + DELAY ))
[ "$B_FIRST" -le "$H_PUB_X" ] || H_PUB_X="$B_FIRST"
[ $(( H_PUB_X % E )) = 0 ] || die "the expected publication height $H_PUB_X is not a boundary (P + 2E, E = $E)"
[ "$B_IN" -le "$H_PUB_X" ] || die \
    "the layout broke: the storage nodes joined at $B_IN, after the publication boundary $H_PUB_X — K9a would give them grace (not this scenario's path)"
pump_to 1 $(( H_PUB_X - 2 ))
echo "[info] idle production from tip $(tip_of 1) — no pump spend in flight across the probing epoch, the report window and the settlement"
wait_all "$H_PUB_X"
h=$(stagef_cmt_wait_row "$(db_of 1)" "SELECT COUNT(*) FROM v2_storage_segments WHERE k = 1;" 3 5) && wrc=0 || wrc=$?
[ "$wrc" = 0 ] || die "segment 1 was not published on node1 by tip $h (expected at $H_PUB_X; wait rc $wrc)"
stagef_sentinel TARGET_REACHED
SEG_REF=""
for n in $(seq 1 "$N"); do
    s=$(sqlite3 "$(db_of "$n")" \
        "SELECT group_concat(k || '|' || lower(hex(root)) || '|' || published_height, ',')
           FROM (SELECT k, root, published_height FROM v2_storage_segments ORDER BY k);" 2>/dev/null || echo ERR)
    if [ -z "$SEG_REF" ]; then SEG_REF="$s"
    elif [ "$s" != "$SEG_REF" ]; then die "node$n's published segment list differs: '$s' vs node1 '$SEG_REF'"; fi
done
IFS='|' read -r seg_k SEG_ROOT H_PUB <<< "$SEG_REF"
[ "$seg_k" = 1 ] && [ "${#SEG_ROOT}" = 128 ] || die "the segment list is not exactly segment 1: '$SEG_REF'"
[[ "$H_PUB" =~ ^[0-9]+$ ]] || die "the segment list is not exactly segment 1: '$SEG_REF'"
[ "$H_PUB" = "$H_PUB_X" ] || die "segment 1 was published at $H_PUB, expected the first storage boundary >= P + 2E = $H_PUB_X"
# bytes item 1 at P = 24E: re-derived from node 1's v2_blocks
nblk=$(sqlite3 "$(db_of 1)" "SELECT COUNT(*) FROM v2_blocks WHERE global_height BETWEEN 1 AND $P AND length(block_id) = 64;")
[ "$nblk" = "$P" ] || die "node1 holds $nblk 64-byte block ids in 1..$P, expected $P"
seg_re=$( { printf 'NDS.STSEG.v1\0\0\0\0'
            printf '%016x%08x' 1 "$P" | xxd -r -p
            sqlite3 "$(db_of 1)" "SELECT hex(block_id) FROM v2_blocks WHERE global_height BETWEEN 1 AND $P
                                    ORDER BY global_height;" | tr -d '\n' | xxd -r -p
          } | openssl dgst -sha3-512 | awk '{print $NF}')
[ "$seg_re" = "$SEG_ROOT" ] || die "segment 1's root ${SEG_ROOT:0:16}... is not SHA3-512(NDS.STSEG.v1 ‖ k ‖ count=$P ‖ block_id[1..$P]) = ${seg_re:0:16}..."
diff_at "$H_PUB" "segment-published-at-$H_PUB"
echo "[ok] segment 1 (heights 1..$P) published at $H_PUB on 7/7; root ${SEG_ROOT:0:16}... = bytes item 1 recomputed at count $P"

# ── 7. storage: `storage status` in the epoch after the publication ──
for k in "$ST_A" "$ST_B"; do
    if [ "$k" = "$ST_A" ]; then fp="$FP_A"; else fp="$FP_B"; fi
    status_of "$k" "$k"
    printf '%s\n' "$ST_OUT"
    [ "$ST_RC" = 0 ] || die "storage status on node$k exited $ST_RC"
    [[ "$ST_OUT" == *"storage node $fp"* ]] || die "node$k's status names another node"
    [[ "$ST_OUT" == *"registry: ACTIVE, bond $BOND raw, fail_streak 0, registered at "* ]] \
        || die "node$k's status is not 'ACTIVE, bond $BOND raw, fail_streak 0'"
    [[ "$ST_OUT" == *"grace_until: 0 (never in grace)"* ]] || die "node$k's status is not 'grace_until: 0' (K9a)"
    [[ "$ST_OUT" != *"IN GRACE"* ]] || die "node$k's status says it is IN GRACE"
    re='frozen storage set for epoch [(]([0-9]+), [0-9]+[]]: 2 member[(]s[)], this node IS a member'
    [[ "$ST_OUT" =~ $re ]] || die "node$k's status does not show a 2-member set it is a member of"
    [ "${BASH_REMATCH[1]}" -ge "$H_PUB" ] || die "node$k's status is for epoch ${BASH_REMATCH[1]}, before the publication $H_PUB"
    [[ "$ST_OUT" == *"eligible segments this epoch: 1 ($P blocks): 1"* ]] \
        || die "node$k's status does not list segment 1 ($P blocks) as eligible"
done
status_of 1 1
[ "$ST_RC" = 0 ] && [[ "$ST_OUT" == *"registry: not registered"* && "$ST_OUT" == *"this node is NOT a member"* ]] || {
    printf '%s\n' "$ST_OUT" >&2; die "node1's status (not registered) did not read 'not registered' / 'NOT a member'"; }
echo "[ok] storage status: nodes $ST_A/$ST_B ACTIVE members, grace_until 0, segment 1 eligible ($P blocks); node1 not registered"

# ── 8. storage: the reports of the probing epoch Hx ─────────────────
HX="$H_PUB"
while is_payday $(( HX + DELAY )); do HX=$(( HX + E )); done
B_SET=$(( HX + DELAY ))
[ "$HX" = "$H_PUB" ] || echo "[info] $(( H_PUB + DELAY )) is a payday — the settled epoch is $HX instead (segment 1 stays eligible)"
W_CLOSED=$(( HX + E + REPORT_CLOSE ))
wait_all "$W_CLOSED"
SET_HASH=$(sqlite3 "$(db_of 1)" "SELECT lower(hex(set_hash)) FROM v2_storage_sets WHERE epoch_start = $HX;" 2>/dev/null || echo ERR)
[ "${#SET_HASH}" = 128 ] || die "no frozen S($HX) on node1 ('$SET_HASH')"
REP_REF=""
for n in $(seq 1 "$N"); do
    out=$(sqlite3 -separator ' ' "$(db_of "$n")" \
        "SELECT (SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks),
                (SELECT COUNT(*) FROM v2_storage_reports WHERE epoch_start = $HX),
                (SELECT COUNT(*) FROM v2_storage_reports WHERE epoch_start = $HX AND lower(hex(set_hash)) <> '$SET_HASH'),
                (SELECT COALESCE(group_concat(r, ','), '-') FROM
                   (SELECT seat || ':' || hex(bitmap) AS r FROM v2_storage_reports
                     WHERE epoch_start = $HX ORDER BY seat));" 2>/dev/null || echo ERR)
    read -r rt rc rbad rlist <<< "$out"
    [[ "$rt" =~ ^[0-9]+$ ]] && [[ "$rc" =~ ^[0-9]+$ ]] || die "node$n's report read failed: '$out'"
    [ "$rt" -lt "$B_SET" ] || die "node$n reached the settlement boundary $B_SET while its reports were read (tip $rt) — they are pruned there"
    [ "$rbad" = 0 ] || die "node$n holds $rbad report(s) for H=$HX against another set hash"
    if [ -z "$REP_REF" ]; then REP_REF="$rc $rlist"
    elif [ "$rc $rlist" != "$REP_REF" ]; then die "node$n's committed reports for H=$HX differ: '$rc $rlist' vs node1 '$REP_REF'"; fi
done
N_REP="${REP_REF%% *}"
[ $(( N_REP * 2 )) -gt "$N" ] || die "only $N_REP of $N seats committed a report for H=$HX — F1 (more than half the power) cannot hold"
echo "[ok] $N_REP/$N seats committed a STORAGE_REPORT for H=$HX against S($HX), identical on 7/7 (seat:bitmap ${REP_REF#* })"
n_logged=0
for n in $(seq 1 "$N"); do
    if grep -q "report for H=$HX committed" "$(node_log "$n")"; then n_logged=$(( n_logged + 1 )); fi
done
echo "[info] REPORTED: $n_logged/$N node logs say 'report for H=$HX committed'"
# the reporter's "probe of <peer id, 16 hex>.. OK" line (W_STPROBE; the
# peer id is hex(fp[0..31]), nodus_witness_storage_reporter.c take_answer)
for k in "$ST_A" "$ST_B"; do
    if [ "$k" = "$ST_A" ]; then fp="$FP_A"; else fp="$FP_B"; fi
    n_ok=0
    for n in $(seq 1 "$N"); do
        if grep -q "probe of ${fp:0:16}\.\. OK" "$(node_log "$n")"; then n_ok=$(( n_ok + 1 )); fi
    done
    if [ -f "$(stagef_node_dir "$k")/data/segments/seg-1.ok" ]; then f=present; else f=absent; fi
    echo "[info] REPORTED: node$k — $n_ok/$N node logs hold a 'probe of ${fp:0:16}.. OK' line; segment file marker seg-1.ok $f"
done

# ── 9. storage: the settlement at B = Hx + 2E pays the storage payees ─
# snap — ONE statement (the test_v2_rewards.sh lesson: every value from
# one read snapshot): "tip reward_pool pool1 Σaccrual acc(A) acc(B)".
# Prints the line and returns 0, or prints the raw answer and returns 1
# (the caller dies — a die inside $(...) would only end the subshell).
snap() {
    local out
    out=$(sqlite3 -separator ' ' "$(db_of 1)" \
      "SELECT (SELECT COALESCE(MAX(global_height),-1) FROM v2_blocks),
              (SELECT reward_pool FROM supply_tracking WHERE id = 1),
              (SELECT balance FROM v2_treasury WHERE pool_id = 1),
              (SELECT COALESCE(SUM(amount),0) FROM v2_reward_accrual),
              (SELECT COALESCE(SUM(amount),0) FROM v2_reward_accrual WHERE lower(hex(owner_fp)) = '$FP_A'),
              (SELECT COALESCE(SUM(amount),0) FROM v2_reward_accrual WHERE lower(hex(owner_fp)) = '$FP_B');" \
          2>&1) || { printf '%s\n' "$out"; return 1; }
    [[ "$out" =~ ^[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+$ ]] || { printf '%s\n' "$out"; return 1; }
    printf '%s\n' "$out"
}
s=$(snap) || die "the pre-settlement snapshot on node1 failed: '$s'"
read -r t_pre rp_pre p1_pre acc_pre a_pre b_pre <<< "$s"
[ "$t_pre" -lt "$B_SET" ] || die "node1 passed the settlement boundary $B_SET before the pre read (tip $t_pre)"
[ "$t_pre" -ge "$W_CLOSED" ] || die "pre read at tip $t_pre, before the report window closed ($W_CLOSED)"
[ "$p1_pre" = "$POOL1_0" ] || die "pool 1 moved before the first paying settlement: $POOL1_0 -> $p1_pre"
echo "[ok] pre  B=$B_SET: tip $t_pre reward_pool $rp_pre pool1 $p1_pre Σaccrual $acc_pre node$ST_A $a_pre node$ST_B $b_pre"
stagef_cmt_wait_height "$(db_of 1)" "$B_SET" 3 >/dev/null || die "the chain stalled short of the settlement boundary $B_SET"
s=$(snap) || die "the post-settlement snapshot on node1 failed: '$s'"
read -r t_post rp_post p1_post acc_post a_post b_post <<< "$s"
[ "$t_post" -ge "$B_SET" ] && [ "$t_post" -lt $(( B_SET + E )) ] \
    || die "post read at tip $t_post, outside [$B_SET, $(( B_SET + E )))"
echo "[ok] post B=$B_SET: tip $t_post reward_pool $rp_post pool1 $p1_post Σaccrual $acc_post node$ST_A $a_post node$ST_B $b_post"
BUDGET=$(( p1_pre >> DIV_LOG2 ))
SHARE=$(( BUDGET / 2 ))
[ "$SHARE" -gt 0 ] || die "the budget $BUDGET cannot pay two shares (pool 1 $p1_pre)"
DEBIT=$(( p1_pre - p1_post ))
[ "$DEBIT" = $(( 2 * SHARE )) ] || die \
    "pool 1 fell by $DEBIT, expected 2 x floor(($p1_pre >> $DIV_LOG2) / 2) = $(( 2 * SHARE )) (both members OK, equal weight $P) — $([ "$DEBIT" = "$SHARE" ] && echo 'ONE member was paid' || echo 'not a two-member settlement')"
d_acc=$(( acc_post - acc_pre )); d_rp=$(( rp_pre - rp_post ))
[ "$d_acc" = $(( d_rp + DEBIT )) ] || die \
    "Σaccrual rose by $d_acc, expected reward-pool debit $d_rp + pool 1 debit $DEBIT = $(( d_rp + DEBIT ))"
[ $(( a_post - a_pre )) -ge "$SHARE" ] || die "node$ST_A's accrual rose by $(( a_post - a_pre )), below its storage share $SHARE"
[ $(( b_post - b_pre )) -ge "$SHARE" ] || die "node$ST_B's accrual rose by $(( b_post - b_pre )), below its storage share $SHARE"
echo "[ok] settlement at $B_SET paid the storage payees: pool 1 -$DEBIT (2 x $SHARE), Σaccrual +$d_acc = reward pool -$d_rp + pool 1 -$DEBIT"

# ── 10. storage: honest nodes keep fail_streak 0; 7/7 ───────────────
wait_all "$B_SET"
require_registry "post-settlement"
for n in $(seq 1 "$N"); do
    p1=$(sqlite3 "$(db_of "$n")" "SELECT balance FROM v2_treasury WHERE pool_id = 1;" 2>/dev/null || echo ERR)
    [ "$p1" = "$p1_post" ] || die "node$n's pool 1 reads '$p1', node1's $p1_post"
done
diff_at "$B_SET" "storage-settlement-at-$B_SET"

stagef_sentinel ASSERT_RUN
stagef_cmt_diff_at_floor "post-storage" || exit 2
stagef_sentinel PASS
echo ""
echo "[info] HEIGHTS: HF2 $H2 | HF3 $H3 | GEN2 $H4 | EVM $HE | storage H_s $HS | first storage set $B_FIRST"
echo "       | both members from $B_IN | segment 1 published $H_PUB | probed epoch $HX | settled $B_SET"
echo "[PASS] archive storage reward: generation $GEN_STOR voted on top of the EVM generation, nodes $ST_A/$ST_B"
echo "       registered, segment 1 (P = $P) published and re-derived, $N_REP/$N reports, the settlement paid"
echo "       2 x $SHARE from pool 1 with fail_streak 0 and grace_until 0 — 7/7 identical."
echo "       E=15 / grace 15 / P=360 — the LOGIC only; the NOT OK / grace / handoff paths are NOT exercised (header)."
