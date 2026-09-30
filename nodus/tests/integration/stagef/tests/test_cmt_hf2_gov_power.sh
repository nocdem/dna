#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_hf2_gov_power.sh — HF-2, the second height-activated hard
# fork: a WIPELESS rolling upgrade 0.23.1 -> HF-2, then a vote that
# switches chain-config approval from SEATS to VOTING POWER
# (standalone — NOT in the sweep)
# ════════════════════════════════════════════════════════════════════
#
# Governing records: docs/plans/2026-09-30-gov-weight-netzero-design.md
# rev 2 + §4a (one activation parameter, HF-1 pattern; Fable F1/F2/F4);
# docs/plans/decisions/2026-09-30-governance-stake-weight-and-power-cap.md
# item 1 ("oylama zaten stake ağırlıklı olmalıydı, kaçırmışız" — approvals
# must carry > 2/3 of the governing committee's voting power, the block-
# commit unit and integer form); docs/plans/decisions/2026-09-23-height-
# activated-upgrades-before-testnet.md (a rule-widening change is a
# height-activated planned hard fork); nodus/docs/ARCHITECTURE.md "HF-2";
# nodus/docs/DEPLOY_RUNBOOK.md §2.2 "HF-2" (the order this scenario
# rehearses: roll 7 nodes one at a time -> verify 7/7 -> vote param 7
# under TODAY's seat rule -> power rule from H).
#
# ⚠ ONE DELIBERATE DEVIATION FROM THE DISPATCH — READ BEFORE TRUSTING 6b.
#   The dispatch asked for "the same shape (5 small seats) built OFFLINE
#   after H is REFUSED". With a LIVE database that envelope is never sent:
#   the offline builder reads param 7 at tip + 1 itself and, under HF-2,
#   refuses locally when the given keys hold <= 2/3 of the power
#   (nodus-cli.c cmd_v2_envelope, the `if (hf2_on)` block: "HF-2 is
#   active: the N approver keys given hold voting power …", goto done —
#   nothing submitted). So a chain-side refusal needs a builder whose view
#   is BEHIND H. This script makes one without touching any C: it points
#   the SAME offline builder at a consistent copy of node 1's database
#   taken at a tip T0 with T0 + 1 < H (`sqlite3 <live> ".backup <copy>"`),
#   so the builder picks the seat rule and signs the 5 small seats. What
#   that stands for on a real network: any builder whose view is behind
#   H — above all the online `chain-config propose`, which keeps the seat
#   rule for its own early abort because no RPC reports param 7
#   (nodus-cli.c cmd_chain_config_propose, the "⚠ HF-2" comment at its
#   committee-query step). The envelope stays valid for the live chain:
#   the preflight height enters only the expiry check (shared/dnac/
#   env_preflight.c, `expiry_height < proposed_global_height`), expiry is
#   T0 + 90 (CLI_ENV_EXPIRY_AHEAD), and the approvals bind epoch(T0) and
#   the set hash of the committee at T0 (nodus_rt_cc_approval_digest in
#   the builder; the engine's committee_snapshot_for_height binds
#   epoch(X−1) and the committee at X−1) — so T0 and every submission tip
#   are ASSERTED to lie in the SAME epoch, and a CONTROL (6c) sends the
#   big seat + 4 small, built from the SAME stale copy, in the SAME epoch,
#   and it LANDS. The local refusal on the live database is asserted too
#   (6a) — that is the CLI's check, not the chain's.
#
# WHAT IT PROVES — each item would be false if it failed
#   0. R3-F4-style gate: OLD and NEW are the builds they claim to be (see
#      "VERSION GATE" below) — a FAIL (rc 1), not a skip, when not.
#   1. A chain started on OLD (0.23.1, pre-HF-2) commits and 7/7 agree.
#   2. Rolling upgrade (runbook §2.2 HF-2 step 1): nodes 1..7 stopped ONE
#      AT A TIME (SIGTERM) and restarted on NEW with the SAME data dir,
#      identity and ports; after EVERY step the node is back in its
#      COMETBFT role, ran and completed the ABCI handshake on the SAME
#      chain file, reached the fleet tip, the chain advanced >= 2 heights
#      with REAL spends carried by the mixed fleet, and 7/7 agree on
#      global_root + block_id at a floor past the step's baseline. With no
#      param-7 row an OLD and a NEW binary must compute identical blocks
#      (ARCHITECTURE.md "HF-2", "Byte-identical while off").
#   3. Powers made UNEQUAL: node 1 delegates DELEG_RAW (10M NODUS) to
#      ITSELF (allowed since W-B, test_cmt_self_delegate.sh). The first
#      snapshot built from the copy that holds it is snapshot(P), P = nb +
#      2E, nb = ceil(h/E)·E (nodus_witness_v2_epoch.h
#      nodus_v2_power_exit_boundary, "okuma B"; the pattern
#      test_cmt_self_delegate.sh asserts). Blocks X with X−1 >= P are
#      governed by it (committee_snapshot_for_height reads the committee
#      at X−1; nodus_committee_get_for_block's e_start = ⌊h/E⌋·E). The
#      snapshot is DECODED on all 7 nodes from validator_set_snapshots
#      (shared/dnac/vset_wire.h layout: header 78, entry 2642, total_stake
#      u64 BE at entry offset 2624), power = total_stake / 10^8 (the
#      derivation committee_snapshot_for_height copies into view->powers),
#      and ASSERTED, not planned: 7 seats; the 5 small seats (nodes 2..6)
#      sum <= ⌊2T/3⌋ while being a seat quorum (dna_bft_quorum(7) = 5);
#      the big seat + 4 small (nodes 1..5) sum > ⌊2T/3⌋.
#   4. The HF2_ACTIVE vote (param 7, value 1) cast with the NEW CLI's
#      online `chain-config propose` under TODAY's seat rule (all 7
#      approve in round 1) at effective H lands a chain_config_history
#      row byte-identical on 7/7. H is placed at epoch offset HOFF (8 of
#      15) and at least one full epoch after P (why: 5 and 6b).
#   5. BEFORE H, with the row already committed and the committee's power
#      unequal: an OFFLINE `v2-envelope chain-config` approved by EXACTLY
#      the 5 small seats (seat quorum met, power <= 2/3 — asserted from the
#      governing snapshot of the block it landed in) is APPLIED — its
#      (param 5, EFF_A) row on 7/7, commit_block < H. Param 5 = GAS_PRICE_
#      RAW_PER_UNIT at its CURRENT value, effective ~1000 blocks past H:
#      a no-op the test never reaches (harmless — see "leaves behind").
#   6. AFTER H (every node's tip >= H, CheckTx judges at >= H + 1):
#      (a) the live-DB offline builder REFUSES the 5 small seats locally
#          (its HF-2 line with the power numbers; nothing built, nothing
#          sent);
#      (b) the 5-small envelope built from the pre-H copy (seat rule) is
#          REFUSED by the CheckTx of EACH of the 7 nodes ("dnac_spend RPC
#          failed (rc=7 status=0)" after "envelope built:"), and its
#          (param 5, EFF_B) row is ABSENT on 7/7 three heights later;
#      (c) CONTROL: the big seat + 4 small built from the SAME copy, SAME
#          epoch, SAME seat count (5), is ADMITTED and LANDS on 7/7 — so
#          6b's refusal is the power rule, not a stale-build artefact;
#      (d) the live-DB builder with the big seat + 4 small prints its HF-2
#          line (5 approvers, power > ⌊2T/3⌋) and its row LANDS on 7/7.
#   7. 7/7 agreement at the end; every height used is printed.
#
# WHAT IT REQUIRES
#   Compile flags — TWO short-epoch + short-grace builds, nodus-server AND
#   nodus-cli from the SAME tree each:
#     -DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#   (the epoch is needed because a power change reaches the committee two
#   boundaries after the delegation; param 7 is ERGONOMIC.) OLD = a82a2544
#   (nodus 0.23.1, main before HF-2); NEW = the HF-2 tree WITH its
#   merge-time version bump (see VERSION GATE). Both builds must carry the
#   SAME constants or the NEW open of OLD's chain fails for an unrelated
#   reason.
#   Environment:
#     exported BEFORE stagef_up_v2.sh (the ceremony writes them into the
#     hashed genesis document):
#       STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     read by THIS script only:
#       STAGEF_NODUS_BIN_OLD / STAGEF_NODUSCLI_BIN_OLD   the OLD pair
#       STAGEF_NODUS_BIN_NEW / STAGEF_NODUSCLI_BIN_NEW   the NEW pair
#       STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     and the bring-up must run the OLD server + OLD CLI as
#     STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN (checked: every node's
#     /proc/<pid>/exe must be the OLD server, else FAIL).
#   Exact command sequence (ORCHESTRATOR):
#     F='-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
#     git -C /opt/dna worktree add <OLD_TREE> a82a2544
#     cmake -S <OLD_TREE>/nodus -B <OLD_TREE>/nodus/build-hf2 -DCMAKE_C_FLAGS="$F"
#     make -C <OLD_TREE>/nodus/build-hf2 -j"$(nproc)" nodus-server nodus-cli
#     # NEW_TREE = the HF-2 tree after the merge-time NODUS_VERSION bump
#     cmake -S <NEW_TREE>/nodus -B <NEW_TREE>/nodus/build-hf2 -DCMAKE_C_FLAGS="$F"
#     make -C <NEW_TREE>/nodus/build-hf2 -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN_OLD=<OLD_TREE>/nodus/build-hf2/nodus-server
#     export STAGEF_NODUSCLI_BIN_OLD=<OLD_TREE>/nodus/build-hf2/nodus-cli
#     export STAGEF_NODUS_BIN_NEW=<NEW_TREE>/nodus/build-hf2/nodus-server
#     export STAGEF_NODUSCLI_BIN_NEW=<NEW_TREE>/nodus/build-hf2/nodus-cli
#     export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     S=/opt/dna/nodus/tests/integration/stagef
#     STAGEF_NODUS_BIN=$STAGEF_NODUS_BIN_OLD STAGEF_NODUSCLI_BIN=$STAGEF_NODUSCLI_BIN_OLD \
#         bash $S/stagef_up_v2.sh
#     bash $S/tests/test_cmt_hf2_gov_power.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   SKIP (rc 99): a binary missing / not executable, OLD and NEW servers
#   byte-identical, STAGEF_EPOCH_LENGTH != 15, a grace variable != 15, not
#   a Comet cluster. A skip is not a pass.
#
#   VERSION GATE — why "NEW != OLD + a feature probe", not a pinned number.
#   HF-1 pinned NEW to exactly its version; HF-2 is versioned only when it
#   is merged (commit e05048e2 and its successors up to a9d55a4a still say
#   NODUS_VERSION_STRING "0.23.1", the same as OLD — nodus_types.h:30), so
#   a pinned number would be wrong the day it is bumped. The gate is:
#   (i) each pair's server and CLI banners agree ("Nodus Server v…" /
#   "Nodus CLI v…" from `-h`, tools/nodus-server.c / tools/nodus-cli.c
#   usage()); (ii) NEW's banner != OLD's — a NEW built from a tree
#   WITHOUT the bump FAILS here by construction (build NEW from the bumped
#   tree); (iii) the HF-2 FEATURE: `nodus-cli chain-config propose --param
#   HF2_ACTIVE --value 1 --effective 1` against a port nothing listens on
#   — OLD's name table has no HF2_ACTIVE (cc_param_name_to_id; zero "HF2"
#   in a82a2544's nodus-cli.c) and prints "Unknown param name:
#   HF2_ACTIVE" before any connect; NEW's table has it and gets as far as
#   "client_connect failed". Both exit 1, so the TEXTS are asserted, not
#   the codes. (iv) Every node's log shows "Nodus v<OLD> running" at the
#   start and a NEW "Nodus v<NEW> running" after its upgrade. The script
#   RUNS each binary once with `-h`, and each CLI once for the probe
#   (random in-memory identity, no disk writes, no server reached).
#
# WHAT IT LEAVES BEHIND
#   All 7 nodes on NEW under new pids (appended to pids.txt; every
#   nodus.log appended, holding both runs). HF-2 ACTIVE from H on this
#   chain (one-way — no vote can turn it off). Node 1's power doubled
#   permanently (10M NODUS self-delegated from its claimed leaf). Four
#   chain_config_history rows: param 7 = 1 at H; param 5 = the CURRENT
#   gas price at EFF_A, EFF_C, EFF_D (H + 1000..1003 — never reached by
#   this run; the value equals the price in force, so reaching them later
#   changes nothing). Node 1's and node 3's genesis leaves claimed (node
#   3's coin shrinks by one fee per pump step, into the reward pool).
#   $BASE_DIR/hf2/ (every CLI log and node1_preH.db, the pre-H copy).
#   The chain several epochs further on. Nothing wiped. Tear down with
#   stagef_down.sh before re-running (the leaves are single-use).
#
# HOW IT CAN LIE
#   - **GW-2 (a net-zero block applies instead of halting every node) is
#     NOT exercised here.** An honest mempool cannot produce that block
#     (DELEGATE-create + full UNDELEGATE of the same pair in ONE block);
#     the only proof is the unit test test_v2_native
#     test_hf2_netzero_block (VERDICT at height 1, applied at height 2,
#     twin fixture identical roots). A green here says nothing about GW-2.
#   - **6b uses a STALE copy — the deviation above.** It proves the CHAIN
#     refuses a 5-small-seat set from H on; it does not prove any shipped
#     client would send one (the offline builder would not, from a live
#     DB — 6a). The copy is made with SQLite's backup API (a consistent
#     snapshot; a plain `cp` of a WAL-mode file would miss the WAL). A
#     backup that fails against the live writer (SQLITE_BUSY) is NOT
#     retried: the copy's tip is range-checked and a bad copy FAILs.
#   - **Every CC submission is kept >= 3 heights before an epoch
#     boundary** (approvals bind the epoch they were signed in); a tip too
#     close is pumped into the next epoch's start (5, 6d) or FAILs (6b,
#     6c) — a false RED, never a false PASS.
#   - **"rc=7 status=0" is any CheckTx refusal**, not specifically the
#     power rule: the dry run's reason is a node DEBUG line
#     (nodus_witness_v2_env_dry_run -> exec_one_env -> nodus_rt_system_exec).
#     What narrows it: 5 (the same 5 seats APPLIED before H, under the
#     same unequal committee), 6c (the same stale path, same epoch, same
#     seat count, only the power differs, LANDS), and the epoch assertions
#     (a wrong epoch would fail the approvals' signatures instead).
#   - **The offline builder's own quorum logic** decides 6a and 6d's
#     approver count (it adds keys in the given order until power > 2/3);
#     6d's HF-2 line is checked against the numbers decoded from the
#     snapshot, so a builder that summed differently FAILS — but the
#     builder and the engine share the derivation (total_stake / 10^8),
#     so a wrong derivation in BOTH would pass (self-consistent, not
#     independent).
#   - **Committee power vs commit power** are taken to be the same frozen
#     value (ARCHITECTURE.md "HF-2" honest labels — not re-verified by
#     that package, and not measured here: this reads the snapshot the
#     engine reads, never cometbft's validator set).
#   - **The online `propose` is exercised only under the seat rule** (the
#     param-7 vote, all 7 in round 1). Its behaviour after H with unequal
#     power (seat-rule early abort, chain refusal) is represented by 6b,
#     not run.
#   - **The one-block offset after a boundary (Fable F2)** is NOT
#     exercised: every CC submission here is placed away from a boundary
#     and asserted to be governed by an epoch whose snapshot was decoded.
#   - **The rule-off window (5) proves the seat rule at ONE height** — the
#     one the 5-small envelope landed at (printed), in [P+1, H). Its wait
#     is height-bounded to H − 1 (stagef_cmt_wait_row MAX_HEIGHTS); if it
#     does not land before H the run FAILs, never skips.
#   - **The version gate trusts NODUS_VERSION_STRING + the name table.**
#     A HF-2 tree with the bump reverted FAILS (ii); a pre-HF-2 tree
#     bumped by hand FAILS (iii). The byte-difference SKIP and the
#     /proc/<pid>/exe check are path/byte based.
#   - **D3 (identical blocks across the mixed fleet)** is proven only for
#     what the mixed fleet carried: idle blocks, 1-in/1-out CORE SPENDs
#     and claims. No stake, delegation or governance envelope crosses a
#     mixed fleet here; the delegation and every vote run on 7/7 NEW.
#   - Heights are driven by REAL spends (node 3's leaf, NEW CLI, its own
#     priced default fee — dnac_fee_info; at the harness's 121 raw/unit a
#     1-in/1-out spend pays the 10^6 floor), one in flight, each confirmed
#     by its created utxo_set row; every wait is progress- and
#     height-bounded (stagef_cmt_wait_height / stagef_cmt_wait_row).
#   - rc 99 = SKIP, coverage that did not happen.
#   - E = 15, grace 15/15, BPY 20: this proves the LOGIC of the cutover
#     and of the power rule at those constants — NOTHING about the
#     production epoch 720 / grace 720 / 17 280.
#   - Wall time is NOT measured (JUDGMENT: the rolling upgrade plus ≈ 4-5
#     epochs of pumped blocks, tens of minutes on a 4-CPU machine).
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

die() { echo "[FAIL] $*" >&2; exit 1; }

OLD_SRV="${STAGEF_NODUS_BIN_OLD:-}"
OLD_CLI="${STAGEF_NODUSCLI_BIN_OLD:-}"
NEW_SRV="${STAGEF_NODUS_BIN_NEW:-}"
NEW_CLI="${STAGEF_NODUSCLI_BIN_NEW:-}"
PARAM_GAS=5                # DNAC_CFG_GAS_PRICE_RAW_PER_UNIT (the harmless param)
PARAM_HF2=7                # DNAC_CFG_HF2_ACTIVE (dnac.h), value exactly 1
DELEG_RAW=1000000000000000 # 10M NODUS — node 1's power 10^7 -> 2*10^7
DECIMAL_UNIT=100000000     # DNAC_DECIMAL_UNIT: power = total_stake / this
GRACE_MARGIN=5             # same +5 margin test_cmt_hf1_gas_upgrade.sh uses
E_REQ=15                   # the epoch length this scenario is laid out for
HOFF=8                     # H's offset inside its epoch (see step 4)
VSET_HDR=78                # shared/dnac/vset_wire.h DNA_VSET_HDR_LEN
VSET_ENTRY=2642            # DNA_VSET_ENTRY_LEN
VSET_TOTAL_OFF=2624        # voter_id 32 + pubkey 2592 -> total_stake u64 BE
CONF="$BASE_DIR/v2_genesis.conf"
LOGD="$BASE_DIR/hf2"
N="$STAGEF_COMMITTEE_SIZE"

# ── SKIP gates (rc 99 — a skip is not a pass) ───────────────────────
for pair in "STAGEF_NODUS_BIN_OLD=$OLD_SRV" "STAGEF_NODUSCLI_BIN_OLD=$OLD_CLI" \
            "STAGEF_NODUS_BIN_NEW=$NEW_SRV" "STAGEF_NODUSCLI_BIN_NEW=$NEW_CLI"; do
    name="${pair%%=*}"; bin="${pair#*=}"
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        echo "[SKIP] $name is unset or not executable ('$bin') — this scenario needs"
        echo "       an OLD (0.23.1, a82a2544) and a NEW (HF-2) short-epoch build; see the header"
        exit 99
    fi
done
if cmp -s "$OLD_SRV" "$NEW_SRV"; then
    echo "[SKIP] STAGEF_NODUS_BIN_OLD and STAGEF_NODUS_BIN_NEW are byte-identical —"
    echo "       an upgrade to the same binary proves nothing"
    exit 99
fi
if [ "${STAGEF_EPOCH_LENGTH:-720}" != "$E_REQ" ]; then
    echo "[SKIP] STAGEF_EPOCH_LENGTH=${STAGEF_EPOCH_LENGTH:-720} — this scenario is laid out for"
    echo "       E=$E_REQ (-DDNAC_EPOCH_LENGTH=$E_REQ + STAGEF_EPOCH_LENGTH=$E_REQ before bring-up)"
    exit 99
fi
if [ "${STAGEF_CC_GRACE_ERGONOMIC:-720}" != 15 ] || [ "${STAGEF_CC_GRACE_SAFETY:-17280}" != 15 ]; then
    echo "[SKIP] STAGEF_CC_GRACE_ERGONOMIC=${STAGEF_CC_GRACE_ERGONOMIC:-720}" \
         "STAGEF_CC_GRACE_SAFETY=${STAGEF_CC_GRACE_SAFETY:-17280} — needs the short-grace"
    echo "       builds (-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15"
    echo "       -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15) and both variables = 15"
    exit 99
fi
E_LEN="$E_REQ"

# ── VERSION GATE (FAIL, not skip — see the header) ──────────────────
bin_version() {            # BIN KIND ("Server" | "CLI") -> X.Y.Z, "" if no banner
    local out re="Nodus $2 v([0-9]+\.[0-9]+\.[0-9]+)"
    out=$("$1" -h 2>&1 || true)
    if [[ "$out" =~ $re ]]; then echo "${BASH_REMATCH[1]}"; fi
}
OLD_VER=$(bin_version "$OLD_SRV" Server); NEW_VER=$(bin_version "$NEW_SRV" Server)
OLD_CLI_VER=$(bin_version "$OLD_CLI" CLI); NEW_CLI_VER=$(bin_version "$NEW_CLI" CLI)
echo "[info] versions: OLD server ${OLD_VER:-?} / cli ${OLD_CLI_VER:-?}; NEW server ${NEW_VER:-?} / cli ${NEW_CLI_VER:-?}"
for pair in "OLD server=$OLD_VER" "OLD cli=$OLD_CLI_VER" "NEW server=$NEW_VER" "NEW cli=$NEW_CLI_VER"; do
    [ -n "${pair#*=}" ] || die "the ${pair%%=*} binary printed no version banner on -h"
done
[ "$OLD_VER" = "$OLD_CLI_VER" ] || die "the OLD server ($OLD_VER) and OLD CLI ($OLD_CLI_VER) are not one build"
[ "$NEW_VER" = "$NEW_CLI_VER" ] || die "the NEW server ($NEW_VER) and NEW CLI ($NEW_CLI_VER) are not one build"
[ "$NEW_VER" != "$OLD_VER" ] || die \
    "NEW reports the SAME version as OLD ($NEW_VER) — build NEW from the HF-2 tree WITH its merge-time NODUS_VERSION bump (header, VERSION GATE (ii))"

# (iii) the HF-2 name-table probe, against a port nothing listens on
listening() {
    local out
    out=$(ss -ltnH "sport = :$1" 2>/dev/null || true)
    [ -n "$out" ]
}
PROBE_PORT=""
for p in 14991 14992 14993 14994 14995 14996 14997 14998 14999; do
    if ! listening "$p"; then PROBE_PORT="$p"; break; fi
done
[ -n "$PROBE_PORT" ] || die "no free port in 14991..14999 for the HF2_ACTIVE name-table probe"
probe() {                  # CLI -> the CLI's combined output (rc ignored: 1 either way)
    timeout 60 "$1" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose \
        --param HF2_ACTIVE --value 1 --effective 1 2>&1 || true
}
old_probe=$(probe "$OLD_CLI"); new_probe=$(probe "$NEW_CLI")
[[ "$old_probe" == *"Unknown param name: HF2_ACTIVE"* ]] || {
    printf '%s\n' "$old_probe" >&2
    die "the OLD CLI's name table ACCEPTED HF2_ACTIVE — OLD is not a pre-HF-2 build"; }
[[ "$new_probe" != *"Unknown param name"* && "$new_probe" == *"client_connect failed"* ]] || {
    printf '%s\n' "$new_probe" >&2
    die "the NEW CLI did not pass HF2_ACTIVE through its name table to the connect step — NEW is not an HF-2 build"; }
echo "[ok] version gate: OLD $OLD_VER refuses HF2_ACTIVE by name, NEW $NEW_VER knows it (probe port $PROBE_PORT, nothing reached)"

# ── cluster preconditions ───────────────────────────────────────────
[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || die "no active Stage F run (bring one up with stagef_up_v2.sh)"
ref_db0=$(stagef_node_chain_db 1)
[ -n "$ref_db0" ] && [ -s "$ref_db0" ] || die "no chain DB for node1"
has_v2=$(sqlite3 "$ref_db0" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>/dev/null || echo 0)
if [ "${has_v2:-0}" = "0" ]; then
    echo "[SKIP] not a Comet cluster — bring it up with stagef_up_v2.sh"
    exit 99
fi
[ -f "$CONF" ] || die "no $CONF — this scenario needs a stagef_up_v2.sh bring-up"
mkdir -p "$LOGD"

# ── script-local helpers ────────────────────────────────────────────
db_of()  { stagef_node_chain_db "$1"; }
tip_of() { stagef_cmt_tip "$(db_of "$1")"; }
fp_of()  { cat "$1/nodus.fp"; }                 # $1 = identity dir
node_keys() { echo "$(stagef_node_dir "$1")/identity"; }
epoch_start_of() { echo $(( $1 / E_LEN * E_LEN )); }

# The server pid of node $1: the one process whose command line carries
# that node's data dir as its -d argument (stagef_up_v2.sh's spawn line
# and start_node below).
node_pid() {
    local pat pid
    pat="-d $(stagef_node_dir "$1")/data"
    for pid in $(pgrep -f -- "$pat" || true); do
        case "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" in
            "$(readlink -f "$OLD_SRV")"|"$(readlink -f "$NEW_SRV")") echo "$pid"; return 0 ;;
        esac
    done
    return 0
}

# node_runs NODE BIN — 0 when node NODE's server process IS binary BIN.
node_runs() {
    local pid
    pid=$(node_pid "$1")
    [ -n "$pid" ] || return 1
    [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" = "$(readlink -f "$2")" ]
}

floor_of() {               # NODE... -> the minimum tip
    local floor=-1 first=1 n h
    for n in "$@"; do
        h=$(tip_of "$n"); [ -n "$h" ] || h=-1
        if [ "$first" = 1 ]; then floor="$h"; first=0
        elif [ "$h" -lt "$floor" ]; then floor="$h"; fi
    done
    echo "$floor"
}

# spend_intent LOG — the "  intent_id=<128 hex>" line of a CLI spend.
spend_intent() { awk -F= '/^  intent_id=/{print $2; exit}' "$1"; }

# claim_leaf CLI IDENTITY_DIR SUBMIT_NODE — claim the identity's genesis
# leaf and wait for the coin as a LEDGER EFFECT (test_cmt_hf1_gas_
# upgrade.sh's claim_leaf, unchanged).
claim_leaf() {
    local cli="$1" keys="$2" node="$3" port db fp log h wrc
    port=$(stagef_tcp_port "$node"); db=$(db_of "$node"); fp=$(fp_of "$keys")
    log="$LOGD/claim_$(basename "$(dirname "$keys")").log"
    "$cli" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$db" \
        --keys "$keys" --submit "127.0.0.1:$port" > "$log" 2>&1 \
        || { cat "$log" >&2; die "v2-claim for $keys was refused (see $log)"; }
    h=$(stagef_cmt_wait_row "$db" \
        "SELECT COUNT(*) FROM utxo_set WHERE owner = '$fp'
           AND token_id = zeroblob(64) AND amount > $STAGEF_PUMP_FEE_RAW;") && wrc=0 || wrc=$?
    [ "$wrc" = 0 ] || die "the claimed coin for $keys never appeared (wait rc=$wrc, tip $h)"
    echo "[ok] claimed the genesis leaf of $keys (tip $h)"
}

# wait_applied NODE INTENT — the spend's created utxo_set row (tx_hash =
# the envelope's intent_id, nodus_witness_rt_native.c rtn_utxo_create_eff)
# on NODE, progress- and height-bounded (stagef_cmt_wait_row).
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

PUMP_KEYS=$(node_keys 3)          # node 3's leaf drives height (stagef_env.sh's funder)
PUMP_SEQ=0
# pump_to NODE TARGET — self-send SPENDs by node 3's identity with the
# NEW CLI (its own priced default fee), submitted to and confirmed on
# NODE, one in flight, until NODE's tip >= TARGET.
pump_to() {
    local node="$1" target="$2" log intent port
    port=$(stagef_tcp_port "$node")
    while [ "$(tip_of "$node")" -lt "$target" ]; do
        PUMP_SEQ=$(( PUMP_SEQ + 1 ))
        log="$LOGD/pump_$PUMP_SEQ.log"
        "$NEW_CLI" -s 127.0.0.1 -p "$port" v2-envelope spend --keys "$PUMP_KEYS" \
            --to "$(fp_of "$PUMP_KEYS")" --amount all --count 1 \
            --submit "127.0.0.1:$port" > "$log" 2>&1 \
            || { cat "$log" >&2; die "pump spend $PUMP_SEQ was refused/failed on node$node (see $log)"; }
        intent=$(spend_intent "$log")
        [ "${#intent}" = 128 ] || { cat "$log" >&2; die "pump spend $PUMP_SEQ printed no intent_id"; }
        wait_applied "$node" "$intent" >/dev/null
    done
    echo "[ok] node$node tip $(tip_of "$node") >= $target (pumped)"
}

# wait_all NODE_TARGET — every node's tip reaches TARGET (progress-bounded).
wait_all() {
    local n
    for n in $(seq 1 "$N"); do
        stagef_cmt_wait_height "$(db_of "$n")" "$1" 3 >/dev/null \
            || die "node$n never reached height $1"
    done
}

# stop_node K — SIGTERM (nodus-server.c installs a SIGTERM handler), then
# an attempt-bounded wait for the process AND its client port to go.
stop_node() {
    local k="$1" pid tcp i
    pid=$(node_pid "$k"); tcp=$(stagef_tcp_port "$k")
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid"
        for i in $(seq 1 120); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
        ! kill -0 "$pid" 2>/dev/null || die "node$k (pid $pid) did not exit within 60 s of SIGTERM"
        echo "[ok] node$k stopped (SIGTERM, pid $pid)"
    else
        echo "[info] node$k had no running server process to stop"
    fi
    for i in $(seq 1 60); do listening "$tcp" || break; sleep 0.5; done
    ! listening "$tcp" || die "node$k's client port $tcp is still bound after the stop"
}

# start_node K BIN — stagef_up_v2.sh's spawn line, same identity, data
# dir, ports and config (-c nodus.json carries the network file). The log
# is APPENDED.
start_node() {
    local k="$1" bin="$2" nd seeds="" n tcp i ok=0 pid
    nd=$(stagef_node_dir "$k"); tcp=$(stagef_tcp_port "$k")
    for n in $(seq 1 "$N"); do seeds="$seeds -s 127.0.0.1:$(stagef_udp_port "$n")"; done
    # shellcheck disable=SC2086
    "$bin" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$k")" -t "$tcp" \
        -p "$(stagef_peer_port "$k")" -C "$(stagef_chan_port "$k")" \
        -W "$(stagef_witness_port "$k")" \
        -i "$nd/identity" -d "$nd/data" $seeds \
        >> "$nd/nodus.log" 2>&1 &
    pid=$!
    echo "$pid" >> "$BASE_DIR/pids.txt"
    for i in $(seq 1 60); do if listening "$tcp"; then ok=1; break; fi; sleep 0.5; done
    [ "$ok" = 1 ] || die "node$k never listened again on $tcp after the restart"
    echo "[ok] node$k restarted on $(readlink -f "$bin") (pid $pid)"
}

# upgrade_node K — one rolling step (test_cmt_hf1_gas_upgrade.sh's
# upgrade_node): stop node K, restart it on NEW, prove it rejoined, the
# chain advanced >= 2 heights with real spends, and 7/7 agree at a floor
# past the step's baseline.
upgrade_node() {
    local k="$1" ref vlog nd chain_before role0 hs0 hsdone0 refuse0 newver0 base fleet target i ok
    ref=$(( k == 1 ? 2 : 1 ))
    nd=$(stagef_node_dir "$k"); vlog="$nd/nodus.log"
    node_runs "$k" "$OLD_SRV" || die "node$k is not running the OLD binary before its upgrade step"
    stagef_cmt_diff_at_floor "pre-upgrade-node$k" || exit 2
    base=$(floor_of $(seq 1 "$N"))
    chain_before=$(basename "$(db_of "$k")")
    role0=$(grep -c 'chain role: COMETBFT' "$vlog" || true)
    hs0=$(grep -c 'ABCI replay blocks:' "$vlog" || true)
    hsdone0=$(grep -c 'completed ABCI handshake' "$vlog" || true)
    refuse0=$(grep -c 'REFUSING START' "$vlog" || true)
    newver0=$(grep -c "Nodus v$NEW_VER running" "$vlog" || true)

    stop_node "$k"
    start_node "$k" "$NEW_SRV"
    node_runs "$k" "$NEW_SRV" || die "node$k's process is not the NEW binary after the restart"

    ok=0
    for i in $(seq 1 30); do
        [ "$(grep -c 'chain role: COMETBFT' "$vlog" || true)" -gt "$role0" ] && { ok=1; break; }
        sleep 1
    done
    [ "$ok" = 1 ] || die "node$k did not re-establish the COMETBFT role on the NEW binary"
    ok=0
    for i in $(seq 1 30); do
        [ "$(grep -c "Nodus v$NEW_VER running" "$vlog" || true)" -gt "$newver0" ] && { ok=1; break; }
        sleep 1
    done
    [ "$ok" = 1 ] || die "node$k's log has no NEW 'Nodus v$NEW_VER running' line after the restart"
    ok=0
    for i in $(seq 1 30); do
        [ "$(grep -c 'completed ABCI handshake' "$vlog" || true)" -gt "$hsdone0" ] && { ok=1; break; }
        sleep 1
    done
    [ "$ok" = 1 ] || die "node$k did not complete a NEW ABCI handshake on the NEW binary"
    [ "$(grep -c 'ABCI replay blocks:' "$vlog" || true)" -gt "$hs0" ] \
        || die "node$k shows no NEW 'ABCI replay blocks:' line after the restart"
    [ "$(grep -c 'REFUSING START' "$vlog" || true)" = "$refuse0" ] \
        || die "node$k logged REFUSING START on the NEW binary"
    [ "$(basename "$(db_of "$k")")" = "$chain_before" ] \
        || die "node$k came back on a DIFFERENT chain file ($chain_before -> $(basename "$(db_of "$k")"))"
    echo "[ok] node$k on NEW: COMETBFT role, handshake completed, same chain file ($chain_before)"

    fleet=$(tip_of "$ref")
    stagef_cmt_wait_height "$(db_of "$k")" "$fleet" 3 >/dev/null \
        || die "node$k did not catch up to the fleet tip $fleet after its upgrade"
    target=$(( fleet + 2 ))
    pump_to "$ref" "$target"
    wait_all "$target"
    [ "$(floor_of $(seq 1 "$N"))" -gt "$base" ] || die "the floor did not move past $base in node$k's step"
    stagef_cmt_diff_at_floor "post-upgrade-node$k" || exit 2
    echo "[ok] rolling step node$k: OLD -> NEW, chain advanced $base -> >= $target, 7/7 agree"
}

# cc_row NODE PARAM EFFECTIVE -> new_value|commit_block|tx_hash, "" when absent
cc_row() {
    sqlite3 "$(db_of "$1")" \
        "SELECT new_value || '|' || commit_block || '|' || hex(tx_hash) FROM chain_config_history
          WHERE param_id = $2 AND effective_block = $3;" 2>/dev/null || echo ERR
}

# wait_cc_row PARAM EFFECTIVE VALUE MAX_HEIGHTS — the row lands on node 1
# (progress-bounded, height-bounded by MAX_HEIGHTS), then every node
# reaches that height and holds the SAME row. Sets CC_ROW and CC_CB (its
# commit_block).
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
    CC_ROW="$first"
    CC_CB="${first#*|}"; CC_CB="${CC_CB%%|*}"
    echo "[ok] param-$param row (value $val, effective $eff, commit_block $CC_CB) identical on 7/7"
}

# snap_entries DB EPOCH_START -> "count" then one "voter_hex total_stake"
# line per entry, decoded from validator_set_snapshots.snapshot_blob
# (shared/dnac/vset_wire.h layout; test_cmt_self_delegate.sh's total_in).
snap_entries() {
    local db="$1" e0="$2" n i vid hex
    n=$(sqlite3 "$db" "SELECT active_count FROM validator_set_snapshots WHERE epoch_start = $e0;" 2>/dev/null || true)
    case "$n" in ''|*[!0-9]*) die "snapshot($e0) is absent on $db" ;; esac
    echo "$n"
    for i in $(seq 0 $(( n - 1 ))); do
        vid=$(sqlite3 "$db" "SELECT lower(hex(substr(snapshot_blob,
                              $(( VSET_HDR + i * VSET_ENTRY + 1 )), 32)))
                              FROM validator_set_snapshots WHERE epoch_start = $e0;")
        hex=$(sqlite3 "$db" "SELECT hex(substr(snapshot_blob,
                               $(( VSET_HDR + i * VSET_ENTRY + VSET_TOTAL_OFF + 1 )), 8))
                               FROM validator_set_snapshots WHERE epoch_start = $e0;")
        echo "$vid $(( 16#$hex ))"
    done
}

# power_of_node SNAP_TEXT NODE -> that node's power (total_stake / 10^8),
# "" when it holds no seat. SNAP_TEXT is snap_entries' output.
power_of_node() {
    local vid line
    vid=$(fp_of "$(node_keys "$2")"); vid="${vid:0:64}"
    while read -r line; do
        case "$line" in
            "$vid "*) echo $(( ${line#* } / DECIMAL_UNIT )); return 0 ;;
        esac
    done <<< "$1"
    echo ""
}

# check_unequal EPOCH_START — decode snapshot(EPOCH_START) on all 7
# nodes, require it identical, 7 seats, and the power split this
# scenario needs. Sets T_POW, NEED (= floor(2T/3), the engine's
# twice / 3), SMALL_POW (nodes 2..6), BIG_POW (nodes 1..5).
check_unequal() {
    local e0="$1" n txt first="" k p s=0 b=0 t=0 line
    for n in $(seq 1 "$N"); do
        txt=$(snap_entries "$(db_of "$n")" "$e0")
        if [ -z "$first" ]; then first="$txt"
        elif [ "$txt" != "$first" ]; then die "snapshot($e0) decodes DIFFERENTLY on node$n than on node1"; fi
    done
    [ "$(head -1 <<< "$first")" = "$N" ] || die "snapshot($e0) seats $(head -1 <<< "$first"), not $N"
    while read -r line; do t=$(( t + ${line#* } / DECIMAL_UNIT )); done <<< "$(tail -n +2 <<< "$first")"
    for k in 1 2 3 4 5 6 7; do
        p=$(power_of_node "$first" "$k")
        [ -n "$p" ] || die "node$k holds no seat in snapshot($e0)"
        case "$k" in 2|3|4|5|6) s=$(( s + p )) ;; esac
        case "$k" in 1|2|3|4|5) b=$(( b + p )) ;; esac
        [ "$k" = 1 ] || [ "$p" -lt "$(power_of_node "$first" 1)" ] \
            || die "snapshot($e0): node$k's power $p is not below node1's $(power_of_node "$first" 1) — powers are not unequal"
    done
    T_POW="$t"; NEED=$(( 2 * t / 3 )); SMALL_POW="$s"; BIG_POW="$b"
    [ "$SMALL_POW" -le "$NEED" ] || die "snapshot($e0): the 5 small seats hold $SMALL_POW of $T_POW (> $NEED) — the power split this scenario needs is absent"
    [ "$BIG_POW" -gt "$NEED" ] || die "snapshot($e0): the big seat + 4 small hold $BIG_POW of $T_POW (<= $NEED)"
    echo "[ok] 7/7 snapshot($e0): 7 seats, total power $T_POW, need > $NEED; 5 small = $SMALL_POW (a seat quorum, power <= 2/3), big + 4 = $BIG_POW (> 2/3)"
}

# cc_build DB KEYS_CSV EFFECTIVE NONCE SUBMIT_NODE LOG — the OFFLINE
# `v2-envelope chain-config` (param 5 at the current value), submitted to
# SUBMIT_NODE. Returns the CLI's rc.
cc_build() {
    local db="$1" keys="$2" eff="$3" nonce="$4" node="$5" log="$6"
    "$NEW_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$node")" -i "$(node_keys 1)" \
        v2-envelope chain-config --db "$db" --keys "$keys" --param "$PARAM_GAS" \
        --value "$GAS_NOW" --effective "$eff" --nonce "$nonce" > "$log" 2>&1
}

keys_csv() {               # NODE... -> "dir1,dir2,..."
    local out="" n
    for n in "$@"; do out="${out:+$out,}$(node_keys "$n")"; done
    echo "$out"
}
SMALL5=$(keys_csv 2 3 4 5 6)
BIG4=$(keys_csv 1 2 3 4 5)

# ── 0. preconditions: fresh cluster, every node on the OLD binary ───
for n in $(seq 1 "$N"); do
    node_runs "$n" "$OLD_SRV" || die \
        "node$n is not running STAGEF_NODUS_BIN_OLD ($(readlink -f "$OLD_SRV")) — bring the cluster up with STAGEF_NODUS_BIN=\$STAGEF_NODUS_BIN_OLD (header)"
    grep -q "Nodus v$OLD_VER running" "$(stagef_node_dir "$n")/nodus.log" \
        || die "node$n's log has no 'Nodus v$OLD_VER running' line — it was not started from the OLD build"
done
[ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $PARAM_HF2;" 2>/dev/null || echo ERR)" = 0 ] \
    || die "node1 already holds a param-$PARAM_HF2 row — this scenario needs a fresh bring-up"
stagef_sentinel SETUP_OK
echo "[ok] 7/7 nodes run the OLD binary $(readlink -f "$OLD_SRV")"
echo "     NEW binary: $(readlink -f "$NEW_SRV")"

# ── 1. the OLD chain commits and agrees; fund the actors ────────────
stagef_cmt_diff_at_floor "on-OLD" || exit 2
claim_leaf "$OLD_CLI" "$PUMP_KEYS" 1
claim_leaf "$OLD_CLI" "$(node_keys 1)" 1
t=$(tip_of 1)
pump_to 1 $(( t + 2 ))
stagef_cmt_diff_at_floor "OLD-chain-committing" || exit 2

# ── 2. rolling upgrade, 7/7 after every step ────────────────────────
for k in $(seq 1 "$N"); do upgrade_node "$k"; done
for n in $(seq 1 "$N"); do node_runs "$n" "$NEW_SRV" || die "node$n is not on NEW after the rolling upgrade"; done
H_UPGRADED=$(tip_of 1)
echo "[ok] all 7 nodes upgraded one at a time with no wipe; 7/7 agreed after every step (tip $H_UPGRADED)"

# ── 3. unequal power: node 1 delegates DELEG_RAW to itself ──────────
PK1=$(xxd -p -c 99999 "$(node_keys 1)/nodus.pk")
[ "${#PK1}" = 5184 ] || die "node1's public key file has the wrong length"
dlog="$LOGD/self_delegate.log"
"$NEW_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" v2-envelope delegate \
    --keys "$(node_keys 1)" --validator "$PK1" --amount "$DELEG_RAW" \
    --submit "127.0.0.1:$(stagef_tcp_port 1)" > "$dlog" 2>&1 \
    || { cat "$dlog" >&2; die "node1's self-DELEGATE was refused (see $dlog)"; }
d_intent=$(awk '/^ *intent_id=/{sub(/^ *intent_id=/,""); print; exit}' "$dlog")
[ "${#d_intent}" = 128 ] || { cat "$dlog" >&2; die "the self-DELEGATE printed no intent_id"; }
h=$(stagef_cmt_wait_row "$(db_of 1)" \
    "SELECT COUNT(*) FROM v2_intent_index WHERE lower(hex(intent_id)) = '$d_intent';" 3) && wrc=0 || wrc=$?
[ "$wrc" = 0 ] || die "the self-delegation never landed (wait rc=$wrc, tip $h)"
H_DELEG=$(sqlite3 "$(db_of 1)" \
    "SELECT global_height FROM v2_intent_index WHERE lower(hex(intent_id)) = '$d_intent' LIMIT 1;")
case "$H_DELEG" in ''|*[!0-9]*) die "unreadable height for the self-delegation";; esac
NB=$(( (H_DELEG + E_LEN - 1) / E_LEN * E_LEN ))
P=$(( NB + 2 * E_LEN ))
echo "[ok] node1 self-delegated $DELEG_RAW raw at height $H_DELEG — copy($NB) holds it, snapshot($P) is the first set built from it"

# ── 4. the HF2_ACTIVE vote under today's seat rule ──────────────────
T_VOTE=$(tip_of 1)
H0=$(( T_VOTE + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
[ "$H0" -ge $(( P + E_LEN + HOFF )) ] || H0=$(( P + E_LEN + HOFF ))
H=$(( (H0 - HOFF + E_LEN - 1) / E_LEN * E_LEN + HOFF ))
E_H=$(epoch_start_of "$H")
[ $(( H % E_LEN )) = "$HOFF" ] && [ "$H" -ge "$H0" ] || die "arithmetic: H=$H is not the first height >= $H0 at epoch offset $HOFF"
echo "[ok] tip $T_VOTE — node1 proposes HF2_ACTIVE=1 effective H=$H (epoch $E_H, offset $HOFF; >= P + E = $(( P + E_LEN )))"
vlog="$LOGD/propose_hf2.log"
prc=0
"$NEW_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" -i "$(node_keys 1)" \
    chain-config propose --param HF2_ACTIVE --value 1 --effective "$H" > "$vlog" 2>&1 || prc=$?
cat "$vlog"
[ "$prc" = 0 ] || die "chain-config propose HF2_ACTIVE exited $prc (see $vlog)"
grep -q "proposal accepted" "$vlog" || die "propose did not report acceptance (see $vlog)"
wait_cc_row "$PARAM_HF2" "$H" 1 20
HF2_ROW="$CC_ROW"
R_VOTE="$CC_CB"
[ "$R_VOTE" -lt "$H" ] || die "the HF2 row committed at $R_VOTE, not before its effective height $H"
stagef_cmt_diff_at_floor "post-hf2-vote" || exit 2

# the harmless value: the gas price in force now (genesis row, W-C)
GAS_NOW=$(sqlite3 "$(db_of 1)" \
    "SELECT new_value FROM chain_config_history WHERE param_id = $PARAM_GAS
       AND effective_block <= $(tip_of 1) ORDER BY effective_block DESC LIMIT 1;" 2>/dev/null || true)
case "$GAS_NOW" in ''|*[!0-9]*) die "no param-$PARAM_GAS row in force on node1 (a pre-W-C bring-up?)";; esac
EFF_A=$(( H + 1000 )); EFF_B=$(( H + 1001 )); EFF_C=$(( H + 1002 )); EFF_D=$(( H + 1003 ))
echo "[ok] harmless proposal: param $PARAM_GAS = $GAS_NOW (the price in force) at effective $EFF_A..$EFF_D"

# ── 5. BEFORE H: the 5 small seats are enough (seat rule) ───────────
pump_to 1 "$P"
S5=$(tip_of 1)
if [ $(( S5 - $(epoch_start_of "$S5") )) -gt $(( E_LEN - 4 )) ]; then
    pump_to 1 $(( $(epoch_start_of "$S5") + E_LEN ))     # next epoch's start
    S5=$(tip_of 1)
fi
check_unequal "$(epoch_start_of "$S5")"
[ $(( H - S5 )) -ge 4 ] || die "step 5 window too short: tip $S5, H $H"
# the approvals bind epoch(S5); landing across the next boundary would
# fail their signatures, not the rule under test
[ $(( S5 - $(epoch_start_of "$S5") )) -le $(( E_LEN - 4 )) ] \
    || die "step 5: tip $S5 is within 3 heights of the next epoch boundary — pump_to $P overshot"
[ "$(cc_row 1 "$PARAM_HF2" "$H")" = "$HF2_ROW" ] || die "the HF2 row is not in node1's DB at step 5"
a_log="$LOGD/cc_small5_preH.log"
cc_build "$(db_of 1)" "$SMALL5" "$EFF_A" 72001 1 "$a_log" \
    || { cat "$a_log" >&2; die "5: the 5-small-seat envelope was not admitted BEFORE H (tip $S5 < $H) — the seat rule is not in force"; }
cat "$a_log"
! grep -q 'HF-2 \(is \)\?active' "$a_log" || die "5: the builder applied the HF-2 rule at tip $S5 + 1 < $H"
grep -q 'accepted: mempool CheckTx approved' "$a_log" || die "5: no CheckTx acceptance line (see $a_log)"
wait_cc_row "$PARAM_GAS" "$EFF_A" "$GAS_NOW" $(( H - 1 - S5 ))
CB_A="$CC_CB"
[ "$CB_A" -lt "$H" ] || die "5: the 5-small row committed at $CB_A >= H $H"
GOV_A=$(epoch_start_of $(( CB_A - 1 )))
[ "$GOV_A" -ge "$P" ] || die "5: the row's block $CB_A is governed by epoch $GOV_A, before the unequal set $P"
check_unequal "$GOV_A"
echo "[ok] 5: BEFORE H, 5 small seats ($SMALL_POW of $T_POW power, <= $NEED) APPLIED at $CB_A < $H (governing snapshot($GOV_A))"

# ── the pre-H copy: a builder view behind H (the header's DEVIATION) ─
pump_to 1 "$E_H"
STALE_DB="$LOGD/node1_preH.db"
rm -f "$STALE_DB"
sqlite3 "$(db_of 1)" ".backup '$STALE_DB'" || die "could not back up node1's DB to $STALE_DB"
T0=$(stagef_cmt_tip "$STALE_DB")
[ "$T0" -ge "$E_H" ] && [ "$T0" -le $(( H - 2 )) ] \
    || die "the pre-H copy's tip $T0 is outside [$E_H, $(( H - 2 ))] — its approvals would bind a different epoch or it would read HF-2 on"
[ "$(sqlite3 "$STALE_DB" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $PARAM_HF2 AND effective_block = $H;")" = 1 ] \
    || die "the pre-H copy does not hold the HF2 row"
echo "[ok] pre-H copy of node1's DB at tip T0=$T0 (epoch $E_H; T0 + 1 < H=$H — the builder will pick the seat rule)"

# ── 6. AFTER H ──────────────────────────────────────────────────────
pump_to 1 "$H"
wait_all "$H"
echo "[ok] every node's tip >= H=$H — CheckTx now judges at >= $(( H + 1 ))"
stagef_sentinel TARGET_REACHED
check_unequal "$E_H"

# 6a. the live-DB builder refuses the 5 small seats itself
l_log="$LOGD/cc_small5_live_postH.log"
lrc=0
cc_build "$(db_of 1)" "$SMALL5" "$EFF_B" 72002 1 "$l_log" || lrc=$?
cat "$l_log"
[ "$lrc" != 0 ] || die "6a: the live-DB builder SUBMITTED a 5-small-seat set after H"
grep -q "HF-2 is active: the 5 approver keys given hold voting power $SMALL_POW of $T_POW, need > $NEED" "$l_log" \
    || die "6a: the builder's refusal is not the HF-2 power line with $SMALL_POW / $T_POW / $NEED (see $l_log)"
! grep -q '^envelope built:' "$l_log" || die "6a: the builder built an envelope it should have refused"
echo "[ok] 6a: the live-DB offline builder refused the 5 small seats locally ($SMALL_POW of $T_POW, need > $NEED)"

# 6b. the stale 5-small envelope is refused by the CheckTx of every node
REF_TIPS=""
for n in $(seq 1 "$N"); do
    tn=$(tip_of "$n")
    [ "$tn" -ge "$H" ] && [ "$(epoch_start_of "$tn")" = "$E_H" ] \
        || die "6b: node$n's tip $tn is not in [$H, $(( E_H + E_LEN - 1 ))] — the stale approvals would fail for the wrong reason"
    b_log="$LOGD/cc_small5_stale_node$n.log"
    brc=0
    cc_build "$STALE_DB" "$SMALL5" "$EFF_B" 72002 "$n" "$b_log" || brc=$?
    tn2=$(tip_of "$n")
    [ "$(epoch_start_of "$tn2")" = "$E_H" ] || die "6b: node$n crossed into the next epoch during its submission (tip $tn2)"
    ! grep -q 'HF-2 \(is \)\?active' "$b_log" || { cat "$b_log" >&2; die "6b: the stale-copy builder applied the HF-2 rule — the copy is not pre-H"; }
    grep -q '^envelope built:' "$b_log" || { cat "$b_log" >&2; die "6b: the stale 5-small envelope was not built locally — a client-side failure is not a node's refusal"; }
    [ "$brc" != 0 ] || { cat "$b_log" >&2; die "6b: node$n ADMITTED a 5-small-seat approval set ($SMALL_POW of $T_POW) after H — GW-1 broken"; }
    grep -q 'dnac_spend RPC failed (rc=7 status=0)' "$b_log" \
        || { cat "$b_log" >&2; die "6b: node$n's answer is not a CheckTx refusal (expected rc=7 status=0)"; }
    REF_TIPS="$REF_TIPS node$n@$tn"
done
echo "[ok] 6b: the 5-small envelope (seat rule, from T0=$T0) REFUSED by the CheckTx of all 7 nodes:$REF_TIPS"

# 6c. CONTROL — the SAME stale path, same epoch, same count, big + 4
tc=$(tip_of 1)
[ "$(epoch_start_of "$tc")" = "$E_H" ] && [ "$tc" -le $(( E_H + E_LEN - 4 )) ] \
    || die "6c: node1's tip $tc leaves no room inside epoch $E_H for the control to land"
c_log="$LOGD/cc_big4_stale_node1.log"
cc_build "$STALE_DB" "$BIG4" "$EFF_C" 72003 1 "$c_log" \
    || { cat "$c_log" >&2; die "6c: the big + 4 envelope from the SAME stale copy was refused — 6b's refusal cannot be attributed to power"; }
cat "$c_log"
! grep -q 'HF-2 \(is \)\?active' "$c_log" || die "6c: the stale-copy builder applied the HF-2 rule"
wait_cc_row "$PARAM_GAS" "$EFF_C" "$GAS_NOW" $(( E_H + E_LEN - 1 - tc ))
CB_C="$CC_CB"
[ "$CB_C" -ge "$H" ] && [ "$(epoch_start_of $(( CB_C - 1 )))" = "$E_H" ] \
    || die "6c: the control landed at $CB_C, not in [$H, epoch $E_H]"
echo "[ok] 6c: CONTROL — big + 4 ($BIG_POW of $T_POW) from the SAME copy LANDED at $CB_C >= H on 7/7"

# 6d. the live-DB builder under HF-2 with the big seat + 4 small
d2_log="$LOGD/cc_big4_live_postH.log"
# keep 3 heights of room before the next boundary (the approvals bind
# epoch(td)); if too close, pump into the next epoch's start first
td=$(tip_of 1)
if [ $(( td - $(epoch_start_of "$td") )) -gt $(( E_LEN - 4 )) ]; then
    pump_to 1 $(( $(epoch_start_of "$td") + E_LEN ))
    td=$(tip_of 1)
fi
[ $(( td - $(epoch_start_of "$td") )) -le $(( E_LEN - 4 )) ] \
    || die "6d: tip $td is within 3 heights of a boundary after the pump"
check_unequal "$(epoch_start_of "$td")"
cc_build "$(db_of 1)" "$BIG4" "$EFF_D" 72004 1 "$d2_log" \
    || { cat "$d2_log" >&2; die "6d: the big + 4 set was refused after H"; }
cat "$d2_log"
grep -q "HF-2 active at height [0-9]*: 5 approver(s) hold voting power $BIG_POW of $T_POW (> $NEED)" "$d2_log" \
    || die "6d: the builder's HF-2 line does not say 5 approvers, $BIG_POW of $T_POW (> $NEED) (see $d2_log)"
wait_cc_row "$PARAM_GAS" "$EFF_D" "$GAS_NOW" 20
CB_D="$CC_CB"
[ "$CB_D" -ge "$H" ] || die "6d: landed at $CB_D < H"
echo "[ok] 6d: live builder under HF-2 — big + 4 ($BIG_POW > $NEED) LANDED at $CB_D on 7/7 (submitted at tip $td)"

# 6b, the ledger half: three heights later the refused row is absent 7/7
t=$(tip_of 1)
pump_to 1 $(( t + 3 ))
wait_all $(( t + 3 ))
for n in $(seq 1 "$N"); do
    [ "$(cc_row "$n" "$PARAM_GAS" "$EFF_B")" = "" ] \
        || die "6b: node$n holds a param-$PARAM_GAS row at effective $EFF_B — the refused 5-small set LANDED"
done
echo "[ok] 6b (ledger): no param-$PARAM_GAS row at effective $EFF_B on 7/7 at tip >= $(( t + 3 ))"

stagef_sentinel ASSERT_RUN
stagef_cmt_diff_at_floor "post-hf2-power" || exit 2
stagef_sentinel PASS
echo ""
echo "[info] HEIGHTS: upgraded-by $H_UPGRADED | delegation $H_DELEG (copy $NB, unequal snapshot P=$P)"
echo "       | vote tip $T_VOTE, HF2 row commit $R_VOTE, H=$H (epoch $E_H) | step5 submit $S5 -> commit $CB_A"
echo "       (governing $GOV_A) | pre-H copy T0=$T0 | 6b tips$REF_TIPS | 6c commit $CB_C | 6d commit $CB_D"
echo "       | effective heights A=$EFF_A B=$EFF_B (refused) C=$EFF_C D=$EFF_D"
echo "[PASS] HF-2: 7 nodes rolled 0.23.1 -> NEW one at a time with 7/7 agreement after every"
echo "       step; HF2_ACTIVE voted by seats at H=$H; with node1 at 2x power, 5 small seats"
echo "       ($SMALL_POW of $T_POW) were ENOUGH before H and REFUSED on 7/7 CheckTx after it,"
echo "       while big + 4 ($BIG_POW) landed after it. E=15 / grace 15 — the LOGIC only."
echo "       GW-2 (net-zero block) NOT exercised here (test_v2_native test_hf2_netzero_block)."
