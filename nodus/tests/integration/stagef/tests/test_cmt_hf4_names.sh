#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_hf4_names.sh — HF-4, the rule-set generation switch at a
# height + on-chain names: a WIPELESS rolling upgrade from the live
# binary to HF-4, the RULESET_GEN2 vote (param 9), the switch at the end
# of block H-1, a NAME_REGISTER after H, and restart / wipe + pin replay
# across H (standalone — NOT in the sweep)
# ════════════════════════════════════════════════════════════════════
#
# Governing records: docs/plans/2026-10-02-onchain-names-design.md rev 4
# (§1.2 the vote names its target, §1.3 the switch in phase 6b', §1.4
# registry fields, §1.5 rollout, §2 the name operation, §3 test plan);
# docs/plans/decisions/2026-10-02-onchain-names.md (APPROVED 2026-10-02,
# items 1-18 — item 17: param 9 grace class ERGONOMIC);
# docs/plans/decisions/2026-09-26-hard-fork-lagging-node.md (every node
# on the new binary BEFORE the vote); the HF-3 precedent
# test_cmt_hf3_block_bounds.sh (this script's helpers are copied from it,
# changed only where noted "HF-4:").
#
# WHAT IT PROVES — each item would be false if it failed
#   0. Version gate (FAIL, not skip): OLD knows HF2_ACTIVE and HF3_ACTIVE
#      and does NOT know RULESET_GEN2; NEW knows RULESET_GEN2; each pair's
#      server and CLI banners agree; NEW's banner != OLD's.
#   1. A chain started on OLD commits and 7/7 agree; the pump (node 3)
#      and the two name identities (nodes 1 and 2) claim their leaves on
#      the OLD fleet.
#   2. HF-2 and then HF-3 are made ACTIVE on the OLD fleet, BEFORE the
#      rolling upgrade — the live testnet's state (DEPLOY_RUNBOOK.md §2.2
#      "Live hard forks": param 7 effective 1500, param 8 effective 2926):
#      param 7 = 1 (vote rule (b) of param 9 needs it, design §1.2), then
#      param 8 = 1, each voted with the OLD CLI's online `chain-config
#      propose` exactly as test_cmt_hf3_block_bounds.sh does, each row
#      identical on 7/7 and committed below its effective height, and
#      every node past each effective height before the next step. So
#      the HF-4 crossing below runs with HF-3's block bounds in force.
#   3. Rolling upgrade (runbook §2.2 order): nodes 1..7 stopped ONE AT A
#      TIME (SIGTERM) and restarted on NEW with the SAME data dir,
#      identity and ports; after EVERY step the node is back in its
#      COMETBFT role with a NEW completed ABCI handshake on the SAME chain
#      file, real spends carried by the mixed fleet, the chain advanced
#      >= 2 heights and 7/7 agree on global_root + block_id. After the
#      roll every node's log names the SAME generation-2 vote literal D2
#      and the SAME git commit (design §1.5, the procedure check).
#   4. Before the vote: `ruleset-info` on 7/7 reports generation 1 and
#      H = 0 with one identical (SYSTEM, CORE) tuple; `name register` with
#      the NEW CLI is REFUSED ("still runs rule-set generation 1 … (no
#      vote committed yet)"), and v2_names is empty on 7/7.
#   5. The RULESET_GEN2 vote (param 9, value = the decimal of the D2 the
#      node reports, checked equal to the NEW CLI's own) at effective H =
#      vote tip + 1 + grace + H_MARGIN, moved up until H-1 is not an
#      epoch boundary (rule (c)); the chain_config_history row for
#      (param 9, effective H) is byte-identical on 7/7 and committed < H.
#      A SECOND param-9 proposal (its own valid effective, from node 2's
#      seat) is REFUSED by all 6 other seats with "stateful rules
#      rejected" (rule (a), single use; round 1 ends 1/7, "Quorum not
#      reached"), and param 9 still has exactly ONE row on 7/7 three
#      heights later.
#   6. Between the vote and H (tip + 1 < H, checked before and after):
#      `ruleset-info` reports generation 1 and H = <H>; `name register`
#      is still REFUSED (generation 1, a vote IS committed).
#   7. The chain crosses H (pumped to H-7, then idle production — see
#      HOW IT CAN LIE for why): on 7/7 the v2_root_history rows at
#      global_height H-1 name SYSTEM v7 / CORE v5 with the generation-2
#      hashes `ruleset-info` prints, identical (version, hash, state_root)
#      on 7/7; the last rows BELOW H-1 still name generation 1 (control);
#      `ruleset-info` on 7/7: generation 2, SYSTEM v7, CORE v5, "this CLI
#      carries it as compiled generation 2"; every node logged the
#      "rule-set generation 1 -> 2 at the end of height H-1" line; and
#      7/7 identical global_root + block_id AT H-1, AT H and AT H+1.
#   8. After H: `name register punk` from node 1's identity is applied —
#      the v2_names row exists, and on EVERY node `name lookup punk`
#      returns node 1's fingerprint at the SAME registered_height R,
#      `name of <node 1 fp>` returns punk, and the sqlite row
#      (name, lower(hex(owner)), registered_height) is identical; the
#      CORE state_root in v2_root_history at global_height R is identical
#      on 7/7. Then `name register punk` from node 2's identity is
#      REFUSED ("already registered") and `name register punk2` from
#      node 1's is REFUSED ("already holds the name punk"); two heights
#      later v2_names still holds exactly ONE row on 7/7 and node 2 holds
#      no name.
#   9. Restart convergence across H: node 4 kill -9'd after H, restarted
#      on NEW on its own data dir (role + NEW completed handshake, same
#      chain file), catches up, and 7/7 agree at a later floor.
#  10. Pinned rejoin across H: node 6's chain data wiped exactly as
#      test_v2_join.sh does (identity kept), restarted on NEW with
#      --v2-genesis-pin; it adopts the fleet's chain file, re-executes the
#      chain from genesis through the switch (its TRUNCATED log carries
#      the "generation 1 -> 2 at the end of height H-1" line again), and
#      its root-history rows at H-1, its v2_names row, its `ruleset-info`
#      and its blocks AT H-1 / H / H+1 equal the fleet's; 7/7 at the end.
#
# WHAT IT REQUIRES
#   Compile flags — TWO short-epoch + short-grace builds, nodus-server AND
#   nodus-cli from the SAME tree each (the HF-2/HF-3 scenarios' flag set;
#   the epoch flag matters here: rule (c) reads DNAC_EPOCH_LENGTH, and the
#   two builds must agree or NEW's open of OLD's chain fails for an
#   unrelated reason):
#     -DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#   (params 7, 8 and 9 are all ERGONOMIC — param 9 by decision item 17.) OLD = the live
#   binary pair (2026-10-02: nodus 0.23.9, main 547fa773 / 30010235 —
#   RE-CHECK on build day); NEW = the HF-4 tree WITH its merge-time
#   NODUS_VERSION bump (see VERSION GATE).
#   Environment:
#     exported BEFORE stagef_up_v2.sh (hashed into the genesis document):
#       STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     read by THIS script only:
#       STAGEF_NODUS_BIN_OLD / STAGEF_NODUSCLI_BIN_OLD   the OLD pair
#       STAGEF_NODUS_BIN_NEW / STAGEF_NODUSCLI_BIN_NEW   the NEW pair
#       STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     and the bring-up must run the OLD server + OLD CLI as
#     STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN (checked: every node's
#     /proc/<pid>/exe must be the OLD server, else FAIL). Leave
#     STAGEF_PAYOUT_INTERVAL_EPOCHS and STAGEF_ADDR_HISTORY_INDEX at their
#     defaults (not read; not required).
#   Exact command sequence (ORCHESTRATOR):
#     F='-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
#     git -C /opt/dna worktree add <OLD_TREE> <the live commit, 547fa773 or 30010235>
#     cmake -S <OLD_TREE>/nodus -B <OLD_TREE>/nodus/build-hf4 -DCMAKE_C_FLAGS="$F"
#     make -C <OLD_TREE>/nodus/build-hf4 -j"$(nproc)" nodus-server nodus-cli
#     # NEW_TREE = the HF-4 tree after the merge-time NODUS_VERSION bump
#     cmake -S <NEW_TREE>/nodus -B <NEW_TREE>/nodus/build-hf4 -DCMAKE_C_FLAGS="$F"
#     make -C <NEW_TREE>/nodus/build-hf4 -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN_OLD=<OLD_TREE>/nodus/build-hf4/nodus-server
#     export STAGEF_NODUSCLI_BIN_OLD=<OLD_TREE>/nodus/build-hf4/nodus-cli
#     export STAGEF_NODUS_BIN_NEW=<NEW_TREE>/nodus/build-hf4/nodus-server
#     export STAGEF_NODUSCLI_BIN_NEW=<NEW_TREE>/nodus/build-hf4/nodus-cli
#     export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     S=/opt/dna/nodus/tests/integration/stagef
#     STAGEF_NODUS_BIN=$STAGEF_NODUS_BIN_OLD STAGEF_NODUSCLI_BIN=$STAGEF_NODUSCLI_BIN_OLD \
#         bash $S/stagef_up_v2.sh
#     bash $S/tests/test_cmt_hf4_names.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   SKIP (rc 99): a binary missing / not executable, OLD and NEW servers
#   byte-identical, STAGEF_EPOCH_LENGTH != 15, a grace variable != 15, not
#   a Comet cluster, no $BASE_DIR/v2_genesis_pin (step 10 needs it). A
#   skip is not a pass.
#
#   VERSION GATE — the HF-3 scenario's gate, re-aimed at HF-4:
#   (i) each pair's server and CLI banners agree ("Nodus Server v…" /
#   "Nodus CLI v…" from `-h`); (ii) NEW's banner != OLD's — a NEW built
#   from a tree WITHOUT the merge-time bump FAILS here by construction;
#   (iii) name-table probes against a port nothing listens on: OLD's CLI
#   must reach "client_connect failed" with --param HF2_ACTIVE (step 2
#   needs it) and with --param HF3_ACTIVE (OLD is post-HF-3, the live
#   binary), and must print "Unknown param name: RULESET_GEN2" (OLD is
#   pre-HF-4); NEW's CLI must reach "client_connect failed" with --param
#   RULESET_GEN2. All exit 1, so the TEXTS are asserted, not the codes.
#   (iv) every node's log shows "Nodus v<OLD> running" at the start and
#   "Nodus v<NEW> running" after its upgrade. The script RUNS each binary
#   once with `-h` and each CLI for the probes (random in-memory identity,
#   no disk writes, no server reached).
#
# WHAT IT LEAVES BEHIND
#   All 7 nodes on NEW under new pids (appended to pids.txt). Every
#   nodus.log appended (holding both runs) EXCEPT node 6's, which is
#   TRUNCATED by the wipe + pin rejoin (step 10); node 4 restarted twice
#   (upgrade + kill -9). HF-2 ACTIVE from H2, HF-3 ACTIVE from H3 and
#   rule-set generation 2 from H on this chain (all one-way — no vote
#   turns any off). Three chain_config_history rows: param 7 = 1 at H2,
#   param 8 = 1 at H3, param 9 = D2 at H. ONE
#   v2_names row ("punk" -> node 1, permanent) and its price + fee moved
#   from node 1's coins into the reward pool. The genesis leaves of nodes
#   1, 2 and 3 claimed (node 3's coin shrinks by one fee per pump step).
#   Node 6's data dir rebuilt by adoption (identity kept). $BASE_DIR/hf4/
#   (every CLI log). The chain several epochs further on. Tear down with
#   stagef_down.sh before re-running (the leaves are single-use and
#   param 9 is single-use).
#
# HOW IT CAN LIE
#   - **Every `name register` refusal here is the CLI's OWN pre-check,
#     never the chain's.** `cmd_name_register` (nodus-cli.c) refuses
#     before building anything: at generation 1 ("still runs rule-set
#     generation 1"), on a taken name (its `dnac_name_lookup`) and on an
#     ID that already holds a name (its `dnac_name_of`). The CLI has no
#     flag to skip those checks, so the chain-side first-wins /
#     one-per-ID refusal (the exec's NAME/OWNER reads + PRE_ABSENT
#     CREATE), the mempool's synthetic OWNER conflict key, and the
#     node's generation-1 refusal of an op-8 leg (preflight
#     ERR_CTX_VERSION) are NOT exercised here — their proofs are the unit
#     tests. What this scenario adds on top of the CLI texts is the chain
#     state after each refusal (one v2_names row on 7/7; node 2 holds no
#     name).
#   - **A refused param-9 leg COMMITTED BY THE OLD BINARY is NOT replayed
#     here.** The design's old-block replay (§1.2 "Replay of old blocks",
#     §3 test plan) needs an OLD-era block carrying a refused param-9
#     CHAIN_CONFIG leg; an honest OLD CLI cannot even name param 9 (the
#     version gate proves it prints "Unknown param name"), so no such
#     block exists on this chain. The stand-in is the unit test
#     test_hf4_switch case E — itself a PROXY: a param-14 leg refused by
#     the range gate (the path a param-9 leg took on the pre-HF-4 build)
#     shows the same gas_wanted / gas_used as the HF-4 refusals, on ONE
#     binary; no real OLD-built block is replayed anywhere. Step 10's
#     replay covers only what this
#     chain holds: idle blocks, 1-in/1-out CORE SPENDs, claims, the
#     param-7 and param-9 votes, the switch and one NAME_REGISTER.
#   - **The second param-9 proposal is refused by the SEATS (round 1)**,
#     so nothing reaches CheckTx or the SYSTEM exec: rule (a) is proven
#     at the approval responder only. Its effective is chosen valid on the
#     grace floor and on rule (c), it is proposed from node 2's seat (no
#     per-proposer cooldown record — node 1's first vote left one at every
#     seat, and the responder answers "rate-limited" BEFORE the rules),
#     and the asserted text is the responder's own reason on 6 of 6 other
#     seats. "stateful rules rejected" is the SAME text for rules (a), (b)
#     and (c); (b) and (c) hold here by construction (HF-2 is active, H'-1
#     is off a boundary), which is what ties the text to (a).
#     Rules (b) (vote with HF-2 inactive) and (c) (H-1 on a boundary) are
#     NOT exercised as refusals — this script only CHOOSES H to satisfy
#     (c); their proofs are the unit tests.
#   - **HF-2 and HF-3 are activated by the OLD CLI on the OLD fleet**
#     (step 2). If OLD is not the live binary (re-check on build day),
#     step 2 proves their activation for THAT build, not the live one.
#     HF-3's capacity lift is not exercised (one spend in flight — the
#     HF-3 scenario's own caveat); only that HF-4 switches with it on.
#   - **H-1, H and H+1 are crossed on IDLE production** (pumped only to
#     H-7). Why: the NEW CLI caps an envelope's expiry at H-1 while tip+1
#     < H (`cli_env_expiry`, design §1.6), so a pump spend built at tip t
#     has only H-1-t heights to land; pumping right up to H would turn an
#     ordinary 2-height inclusion delay into an expired, "dropped" spend
#     (a false RED). The idle crossing is the design §3 "idle block at H-1
#     and at H" shape; `v2_blocks.tx_count` at H-1/H/H+1 is REPORTED, not
#     asserted. The expiry cap itself is not asserted here.
#   - **The registry is read through `ruleset-info` (the node's own
#     answer) and v2_root_history** (ruleset_version + ruleset_hash of the
#     H-1 rows). The domain_registry blobs are not decoded by this bash
#     harness; the root-history rows at H-1 are outside the app hash
#     (design §1.3), so their 7/7 identity is checked explicitly, and the
#     app-hash side is the 7/7 global_root + block_id at H-1 / H / H+1.
#   - **"Same D2 and git commit on 7/7" is the procedure check of design
#     §1.5, read from log lines** — it proves the seven processes report
#     one build, not that the bytes are identical (the build is not
#     reproducible; /proc/<pid>/exe is checked against NEW's path).
#   - **The name price is not asserted** (no balance or reward-pool
#     arithmetic) — only that the registration applied; the CLI pays the
#     price `dnac_fee_info` reports. Price votes (params 10-13) are not
#     exercised.
#   - **The version gate trusts NODUS_VERSION_STRING + the CLI name
#     table.** An HF-4 tree with the bump reverted FAILS (ii); a pre-HF-4
#     tree bumped by hand FAILS (iii).
#   - The between-vote-and-H checks (step 6) need tip + 1 < H while they
#     run; the vote's H carries H_MARGIN extra heights for them and the
#     second proposal, and a fleet that got there first FAILS loudly
#     (never passes on the wrong side of H).
#   - Heights before H-7 and after H+1 are driven by REAL spends (node 3's
#     leaf), one in flight, each confirmed by its created utxo_set row;
#     every wait is progress- and height-bounded, and the CLI for each
#     spend is the one whose binary the TARGET node runs (a NEW CLI asks
#     the node `dnac_ruleset_info`, which an OLD node does not know).
#   - rc 99 = SKIP, coverage that did not happen.
#   - E = 15, grace 15/15, BPY 20: this proves the LOGIC of the switch at
#     those constants — NOTHING about the production epoch 720 / grace
#     720 / 17 280 (param 9's live grace is 720 blocks, decision item 17).
#   - Wall time is NOT measured (JUDGMENT: two rolling waves of pumped
#     blocks, ~8 idle 60 s blocks across H, a from-genesis rejoin — tens
#     of minutes on a 4-CPU machine).
#   - Written against the source; NOT yet run (written by the HF-4
#     harness builder, 2026-10-02 — the first run is the ORCHESTRATOR's).
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

die() { echo "[FAIL] $*" >&2; exit 1; }

S_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OLD_SRV="${STAGEF_NODUS_BIN_OLD:-}"
OLD_CLI="${STAGEF_NODUSCLI_BIN_OLD:-}"
NEW_SRV="${STAGEF_NODUS_BIN_NEW:-}"
NEW_CLI="${STAGEF_NODUSCLI_BIN_NEW:-}"
PARAM_HF2=7                # DNAC_CFG_HF2_ACTIVE (dnac.h), value exactly 1
PARAM_HF3=8                # DNAC_CFG_HF3_ACTIVE (dnac.h), value exactly 1
PARAM_GEN2=9               # DNAC_CFG_RULESET_GEN2 (dnac.h), value exactly D2
GEN2_SYS_V=7               # design §1.1: gen 2 = SYSTEM v7 / CORE v5
GEN2_CORE_V=5
DOM_SYSTEM=0               # DNA_DOMAIN_SYSTEM (shared/dnac/ledger_ids.h)
DOM_CORE=1                 # DNA_DOMAIN_CORE
GRACE_MARGIN=5             # the HF-2 vote: test_cmt_hf3_block_bounds.sh's +5
# HF-4: the param-9 vote carries a LARGER margin — a layout choice, not a
# timeout: between the vote and H this script lands the row, makes a
# second (refused) proposal, pumps 3 heights for its "no second row"
# check, runs the step-6 checks at tip + 1 < H, and stops pumping at
# H - PUMP_STOP_GAP. 20 heights cover that sequence with room to spare;
# a fleet that still gets there first FAILS with that reason (header).
H_MARGIN=20
# HF-4: pumping stops at H - PUMP_STOP_GAP; see "HOW IT CAN LIE" — the
# NEW CLI caps an envelope's expiry at H-1 before H, so the last pumped
# spend (built at tip <= H-8) keeps >= 7 heights to land.
PUMP_STOP_GAP=7
NAME_A=punk                # the dispatched name (4 characters)
NAME_A2=punk2              # node 1's would-be second name (refused)
E_REQ=15                   # the epoch length the builds carry
CONF="$BASE_DIR/v2_genesis.conf"
PINFILE="$BASE_DIR/v2_genesis_pin"
LOGD="$BASE_DIR/hf4"
N="$STAGEF_COMMITTEE_SIZE"
RESTART_VICTIM=4           # step 9 (test_v2_restart_convergence.sh's node)
JOIN_VICTIM=6              # step 10 (test_v2_join.sh's node)

# ── SKIP gates (rc 99 — a skip is not a pass) ───────────────────────
for pair in "STAGEF_NODUS_BIN_OLD=$OLD_SRV" "STAGEF_NODUSCLI_BIN_OLD=$OLD_CLI" \
            "STAGEF_NODUS_BIN_NEW=$NEW_SRV" "STAGEF_NODUSCLI_BIN_NEW=$NEW_CLI"; do
    name="${pair%%=*}"; bin="${pair#*=}"
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        echo "[SKIP] $name is unset or not executable ('$bin') — this scenario needs"
        echo "       an OLD (the live binary) and a NEW (HF-4) short-epoch build; see the header"
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
    "NEW reports the SAME version as OLD ($NEW_VER) — build NEW from the HF-4 tree WITH its merge-time NODUS_VERSION bump (header, VERSION GATE (ii))"

# (iii) the name-table probes, against a port nothing listens on
listening() {
    local out
    out=$(ss -ltnH "sport = :$1" 2>/dev/null || true)
    [ -n "$out" ]
}
PROBE_PORT=""
for p in 14991 14992 14993 14994 14995 14996 14997 14998 14999; do
    if ! listening "$p"; then PROBE_PORT="$p"; break; fi
done
[ -n "$PROBE_PORT" ] || die "no free port in 14991..14999 for the name-table probes"
probe() {                  # CLI PARAM VALUE -> the CLI's combined output (rc ignored: 1 either way)
    timeout 60 "$1" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose \
        --param "$2" --value "$3" --effective 1 2>&1 || true
}
old_hf2=$(probe "$OLD_CLI" HF2_ACTIVE 1)
old_hf3=$(probe "$OLD_CLI" HF3_ACTIVE 1)
old_gen2=$(probe "$OLD_CLI" RULESET_GEN2 1)
new_gen2=$(probe "$NEW_CLI" RULESET_GEN2 1)
[[ "$old_hf2" != *"Unknown param name"* && "$old_hf2" == *"client_connect failed"* ]] || {
    printf '%s\n' "$old_hf2" >&2
    die "the OLD CLI does not know HF2_ACTIVE — OLD is not a post-HF-2 build (step 2 needs one)"; }
[[ "$old_hf3" != *"Unknown param name"* && "$old_hf3" == *"client_connect failed"* ]] || {
    printf '%s\n' "$old_hf3" >&2
    die "the OLD CLI does not know HF3_ACTIVE — OLD is not the post-HF-3 live build"; }
[[ "$old_gen2" == *"Unknown param name: RULESET_GEN2"* ]] || {
    printf '%s\n' "$old_gen2" >&2
    die "the OLD CLI's name table ACCEPTED RULESET_GEN2 — OLD is not a pre-HF-4 build"; }
[[ "$new_gen2" != *"Unknown param name"* && "$new_gen2" == *"client_connect failed"* ]] || {
    printf '%s\n' "$new_gen2" >&2
    die "the NEW CLI did not pass RULESET_GEN2 through its name table to the connect step — NEW is not an HF-4 build"; }
echo "[ok] version gate: OLD $OLD_VER knows HF2_ACTIVE/HF3_ACTIVE and refuses RULESET_GEN2 by name, NEW $NEW_VER knows RULESET_GEN2 (probe port $PROBE_PORT, nothing reached)"

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
if [ ! -s "$PINFILE" ]; then
    echo "[SKIP] no $PINFILE — step 10's pinned rejoin needs a stagef_up_v2.sh bring-up that recorded the pin"
    exit 99
fi
PIN=$(cat "$PINFILE")
[ "${#PIN}" = 64 ] || die "recorded pin is not 64 hex chars (32-byte chain id, D-24 rev 4)"
[ -f "$CONF" ] || die "no $CONF — this scenario needs a stagef_up_v2.sh bring-up"
mkdir -p "$LOGD"

# ── script-local helpers (test_cmt_hf3_block_bounds.sh's, unless "HF-4:") ─
db_of()  { stagef_node_chain_db "$1"; }
tip_of() { stagef_cmt_tip "$(db_of "$1")"; }
fp_of()  { cat "$1/nodus.fp"; }                 # $1 = identity dir
# HF-4: the same fingerprint, lowercased — the form `name lookup` prints
# and lower(hex(v2_names.owner)) yields.
fp_lc()  { tr 'A-F' 'a-f' < "$1/nodus.fp"; }
node_keys() { echo "$(stagef_node_dir "$1")/identity"; }

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

node_runs() {
    local pid
    pid=$(node_pid "$1")
    [ -n "$pid" ] || return 1
    [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" = "$(readlink -f "$2")" ]
}

# HF-4: the CLI that may talk to node $1 — the NEW CLI asks every node
# `dnac_ruleset_info` before building (cli_select_runtimes), which an OLD
# node does not know; the OLD CLI builds generation 1 without asking,
# which a NEW node accepts while generation 1 is in force.
cli_for() {
    if node_runs "$1" "$NEW_SRV"; then echo "$NEW_CLI"; else echo "$OLD_CLI"; fi
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

spend_intent() { awk -F= '/^  intent_id=/{print $2; exit}' "$1"; }

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
pump_to() {
    local node="$1" target="$2" log intent port cli
    port=$(stagef_tcp_port "$node")
    while [ "$(tip_of "$node")" -lt "$target" ]; do
        PUMP_SEQ=$(( PUMP_SEQ + 1 ))
        log="$LOGD/pump_$PUMP_SEQ.log"
        cli=$(cli_for "$node")                  # HF-4: per target node
        "$cli" -s 127.0.0.1 -p "$port" v2-envelope spend --keys "$PUMP_KEYS" \
            --to "$(fp_of "$PUMP_KEYS")" --amount all --count 1 \
            --submit "127.0.0.1:$port" > "$log" 2>&1 \
            || { cat "$log" >&2; die "pump spend $PUMP_SEQ ($cli) was refused/failed on node$node (see $log)"; }
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

# HF-4: 7/7 identical global_root + block_id AT a fixed height, which
# every node must already hold (caller waits first).
diff_at() {
    bash "$S_DIR/stagef_diff.sh" --at-height "$1" "$2" || exit 2
}

stop_node() {
    local k="$1" sig="${2:-TERM}" pid tcp i
    pid=$(node_pid "$k"); tcp=$(stagef_tcp_port "$k")
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "-$sig" "$pid"
        for i in $(seq 1 120); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
        ! kill -0 "$pid" 2>/dev/null || die "node$k (pid $pid) did not exit within 60 s of SIG$sig"
        echo "[ok] node$k stopped (SIG$sig, pid $pid)"
    else
        echo "[info] node$k had no running server process to stop"
    fi
    for i in $(seq 1 60); do listening "$tcp" || break; sleep 0.5; done
    ! listening "$tcp" || die "node$k's client port $tcp is still bound after the stop"
}

# start_node NODE BIN [EXTRA_ARG...] — HF-4: extra args (the pin, step 10)
start_node() {
    local k="$1" bin="$2" nd seeds="" n tcp i ok=0 pid
    shift 2
    nd=$(stagef_node_dir "$k"); tcp=$(stagef_tcp_port "$k")
    for n in $(seq 1 "$N"); do seeds="$seeds -s 127.0.0.1:$(stagef_udp_port "$n")"; done
    # shellcheck disable=SC2086
    "$bin" -c "$BASE_DIR/nodus.json" -b 127.0.0.1 \
        -u "$(stagef_udp_port "$k")" -t "$tcp" \
        -p "$(stagef_peer_port "$k")" -C "$(stagef_chan_port "$k")" \
        -W "$(stagef_witness_port "$k")" \
        "$@" \
        -i "$nd/identity" -d "$nd/data" $seeds \
        >> "$nd/nodus.log" 2>&1 &
    pid=$!
    echo "$pid" >> "$BASE_DIR/pids.txt"
    for i in $(seq 1 60); do if listening "$tcp"; then ok=1; break; fi; sleep 0.5; done
    [ "$ok" = 1 ] || die "node$k never listened again on $tcp after the restart"
    echo "[ok] node$k restarted on $(readlink -f "$bin") (pid $pid)"
}

# wait_log_delta LOG PATTERN BEFORE WHAT — attempt-bounded (30 x 1 s) poll
# for one MORE line matching PATTERN than BEFORE (the template's shape).
wait_log_delta() {
    local log="$1" pat="$2" before="$3" what="$4" i
    for i in $(seq 1 30); do
        [ "$(grep -c -- "$pat" "$log" || true)" -gt "$before" ] && return 0
        sleep 1
    done
    die "$what"
}

# HF-4: the D2 / git-commit line this node's NEWEST start logged (design
# §1.5 — "startup prints D2 and the git commit it was built from").
d2_line_of() {
    grep -o 'generation-2 vote D2 0x[0-9a-f]* (switch spec v[0-9]*), built from git commit [^ ]*' \
        "$(stagef_node_dir "$1")/nodus.log" | tail -1 || true
}

upgrade_node() {
    local k="$1" ref vlog nd chain_before role0 hs0 hsdone0 refuse0 newver0 d2c0 base fleet target
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
    d2c0=$(grep -c 'generation-2 vote D2 0x' "$vlog" || true)

    stop_node "$k"
    start_node "$k" "$NEW_SRV"
    node_runs "$k" "$NEW_SRV" || die "node$k's process is not the NEW binary after the restart"

    wait_log_delta "$vlog" 'chain role: COMETBFT' "$role0" \
        "node$k did not re-establish the COMETBFT role on the NEW binary"
    wait_log_delta "$vlog" "Nodus v$NEW_VER running" "$newver0" \
        "node$k's log has no NEW 'Nodus v$NEW_VER running' line after the restart"
    wait_log_delta "$vlog" 'completed ABCI handshake' "$hsdone0" \
        "node$k did not complete a NEW ABCI handshake on the NEW binary"
    wait_log_delta "$vlog" 'generation-2 vote D2 0x' "$d2c0" \
        "node$k's NEW start logged no 'generation-2 vote D2 …, built from git commit …' line (design §1.5)"
    [ "$(grep -c 'ABCI replay blocks:' "$vlog" || true)" -gt "$hs0" ] \
        || die "node$k shows no NEW 'ABCI replay blocks:' line after the restart"
    [ "$(grep -c 'REFUSING START' "$vlog" || true)" = "$refuse0" ] \
        || die "node$k logged REFUSING START on the NEW binary"
    [ "$(basename "$(db_of "$k")")" = "$chain_before" ] \
        || die "node$k came back on a DIFFERENT chain file ($chain_before -> $(basename "$(db_of "$k")"))"
    echo "[ok] node$k on NEW: COMETBFT role, handshake completed, same chain file ($chain_before)"
    echo "     $(d2_line_of "$k")"

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
    CC_ROW="$first"
    CC_CB="${first#*|}"; CC_CB="${CC_CB%%|*}"
    echo "[ok] param-$param row (value $val, effective $eff, commit_block $CC_CB) identical on 7/7"
}

# propose CLI NAME VALUE EFFECTIVE LOG — the online `chain-config propose`
# from node 1's identity; FAIL unless it reports acceptance. (HF-4: the
# value is an argument — param 9's is D2, not 1.)
propose() {
    local cli="$1" name="$2" val="$3" eff="$4" log="$5" prc=0
    "$cli" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" -i "$(node_keys 1)" \
        chain-config propose --param "$name" --value "$val" --effective "$eff" > "$log" 2>&1 || prc=$?
    cat "$log"
    [ "$prc" = 0 ] || die "chain-config propose $name exited $prc (see $log)"
    grep -q "proposal accepted" "$log" || die "propose $name did not report acceptance (see $log)"
}

# HF-4: `ruleset-info` against node $1 with the NEW CLI; the parsed
# fields land in RI_* (call directly, never inside $(...)).
ruleset_info() {
    local n="$1" log rrc=0
    log="$LOGD/ruleset_info_node${n}_$(tip_of "$n").log"
    "$NEW_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" ruleset-info > "$log" 2>&1 || rrc=$?
    RI_RC="$rrc"
    RI_OUT=$(cat "$log")
    RI_TIP=$(sed -n 's/^tip=\([0-9]*\) generation=.*/\1/p' "$log")
    RI_GEN=$(sed -n 's/^tip=[0-9]* generation=\([0-9]*\) .*/\1/p' "$log")
    RI_SYS_V=$(awk '$1 == "SYSTEM" { print substr($2, 2); exit }' "$log")
    RI_SYS_H=$(awk '$1 == "SYSTEM" { print substr($3, 6); exit }' "$log")
    RI_CORE_V=$(awk '$1 == "CORE" { print substr($2, 2); exit }' "$log")
    RI_CORE_H=$(awk '$1 == "CORE" { print substr($3, 6); exit }' "$log")
    RI_H=$(sed -n 's/^  RULESET_GEN2 height H=\([0-9]*\).*/\1/p' "$log")
    RI_D2=$(sed -n 's/^  node D2=0x\([0-9a-f]*\) .*/\1/p' "$log")
    RI_CLI_D2=$(sed -n 's/^  node D2=0x[0-9a-f]*  this CLI D2=0x\([0-9a-f]*\).*/\1/p' "$log")
}

# require_ruleset NODE GEN SYS_V CORE_V H — `ruleset-info` on NODE must
# report exactly this generation / tuple versions / H, carried by the
# NEW CLI as that compiled generation, with no D2 MISMATCH.
require_ruleset() {
    local n="$1" g="$2" sv="$3" cv="$4" hh="$5"
    ruleset_info "$n"
    [ "$RI_RC" = 0 ] || { printf '%s\n' "$RI_OUT" >&2; die "ruleset-info on node$n exited $RI_RC (an older node, or a generation this CLI does not carry)"; }
    [ "$RI_GEN" = "$g" ] || { printf '%s\n' "$RI_OUT" >&2; die "node$n reports generation '$RI_GEN' at tip $RI_TIP, expected $g"; }
    [ "$RI_SYS_V" = "$sv" ] && [ "$RI_CORE_V" = "$cv" ] || {
        printf '%s\n' "$RI_OUT" >&2; die "node$n reports SYSTEM v$RI_SYS_V / CORE v$RI_CORE_V, expected v$sv / v$cv"; }
    [ "${#RI_SYS_H}" = 128 ] && [ "${#RI_CORE_H}" = 128 ] || {
        printf '%s\n' "$RI_OUT" >&2; die "node$n's ruleset-info hashes did not parse"; }
    [ "$RI_H" = "$hh" ] || { printf '%s\n' "$RI_OUT" >&2; die "node$n reports RULESET_GEN2 H=$RI_H, expected $hh"; }
    [[ "$RI_OUT" != *MISMATCH* ]] || { printf '%s\n' "$RI_OUT" >&2; die "node$n's D2 differs from the NEW CLI's"; }
    [[ "$RI_OUT" == *"this CLI carries it as compiled generation $g"* ]] || {
        printf '%s\n' "$RI_OUT" >&2; die "the NEW CLI does not carry node$n's tuple as compiled generation $g"; }
}

# name_register NODE_KEYS_OF NAME LOG — the NEW CLI, submitted to node 1.
# Sets NR_RC (exit code); output in LOG.
name_register() {
    local kn="$1" nm="$2" log="$3" port
    port=$(stagef_tcp_port 1)
    NR_RC=0
    "$NEW_CLI" -s 127.0.0.1 -p "$port" name register "$nm" --keys "$(node_keys "$kn")" \
        --submit "127.0.0.1:$port" > "$log" 2>&1 || NR_RC=$?
    cat "$log"
}

# names_rows NODE — every v2_names row, BINARY order, one line each.
names_rows() {
    sqlite3 "$(db_of "$1")" \
        "SELECT CAST(name AS TEXT) || '|' || lower(hex(owner)) || '|' || registered_height
           FROM v2_names ORDER BY name;" 2>/dev/null || echo ERR
}

names_count() {
    sqlite3 "$(db_of "$1")" "SELECT COUNT(*) FROM v2_names;" 2>/dev/null || echo ERR
}

# rh_row NODE DOMAIN GLOBAL_HEIGHT — the v2_root_history row of DOMAIN
# written AT that block: version|ruleset_hash|state_root ("" if none).
rh_row() {
    sqlite3 "$(db_of "$1")" \
        "SELECT ruleset_version || '|' || lower(hex(ruleset_hash)) || '|' || lower(hex(state_root))
           FROM v2_root_history WHERE domain_id = $2 AND global_height = $3;" 2>/dev/null || echo ERR
}

# rh_below NODE DOMAIN GLOBAL_HEIGHT — the version|hash of DOMAIN's last
# row strictly BELOW that height (the generation-1 control).
rh_below() {
    sqlite3 "$(db_of "$1")" \
        "SELECT ruleset_version || '|' || lower(hex(ruleset_hash)) FROM v2_root_history
          WHERE domain_id = $2 AND global_height < $3
          ORDER BY global_height DESC LIMIT 1;" 2>/dev/null || echo ERR
}

# lookup NODE NAME -> sets LK_RC and LK_OUT (`name lookup`, NEW CLI)
lookup() {
    LK_RC=0
    LK_OUT=$("$NEW_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$1")" name lookup "$2" 2>&1) || LK_RC=$?
}

# name_of NODE FP -> sets NO_RC and NO_OUT (`name of`, NEW CLI)
name_of() {
    NO_RC=0
    NO_OUT=$("$NEW_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$1")" name of "$2" 2>&1) || NO_RC=$?
}

# ── 0. preconditions: fresh cluster, every node on the OLD binary ───
for n in $(seq 1 "$N"); do
    node_runs "$n" "$OLD_SRV" || die \
        "node$n is not running STAGEF_NODUS_BIN_OLD ($(readlink -f "$OLD_SRV")) — bring the cluster up with STAGEF_NODUS_BIN=\$STAGEF_NODUS_BIN_OLD (header)"
    grep -q "Nodus v$OLD_VER running" "$(stagef_node_dir "$n")/nodus.log" \
        || die "node$n's log has no 'Nodus v$OLD_VER running' line — it was not started from the OLD build"
done
for p in "$PARAM_HF2" "$PARAM_HF3" "$PARAM_GEN2"; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $p;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1 already holds a param-$p row — this scenario needs a fresh bring-up"
done
stagef_sentinel SETUP_OK
echo "[ok] 7/7 nodes run the OLD binary $(readlink -f "$OLD_SRV")"
echo "     NEW binary: $(readlink -f "$NEW_SRV")"

# ── 1. the OLD chain commits and agrees; fund the pump + the name IDs ─
stagef_cmt_diff_at_floor "on-OLD" || exit 2
claim_leaf "$OLD_CLI" "$PUMP_KEYS" 1
claim_leaf "$OLD_CLI" "$(node_keys 1)" 1        # NAME_A's owner
claim_leaf "$OLD_CLI" "$(node_keys 2)" 1        # the refused second claimant
t=$(tip_of 1)
pump_to 1 $(( t + 2 ))
stagef_cmt_diff_at_floor "OLD-chain-committing" || exit 2

# ── 2. HF-2 ACTIVE on the OLD fleet (param-9 vote rule (b)) ─────────
T_V2=$(tip_of 1)
H2=$(( T_V2 + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $T_V2 — node1 proposes HF2_ACTIVE=1 effective H2=$H2 with the OLD CLI"
propose "$OLD_CLI" HF2_ACTIVE 1 "$H2" "$LOGD/propose_hf2.log"
wait_cc_row "$PARAM_HF2" "$H2" 1 20
R_V2="$CC_CB"
[ "$R_V2" -lt "$H2" ] || die "the HF2 row committed at $R_V2, not before its effective height $H2"
pump_to 1 $(( H2 + 1 ))
wait_all $(( H2 + 1 ))
stagef_cmt_diff_at_floor "OLD-past-HF2" || exit 2
echo "[ok] HF-2 is ACTIVE on the OLD fleet from H2=$H2 (row committed at $R_V2), 7/7 agree past it"

# HF-4: HF-3 ACTIVE on the OLD fleet too, BEFORE the roll — the live
# testnet's state (runbook §2.2: param 8 effective 2926). Same shape as
# test_cmt_hf3_block_bounds.sh's param-8 vote, cast with the OLD CLI.
T_V3=$(tip_of 1)
H3=$(( T_V3 + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $T_V3 — node1 proposes HF3_ACTIVE=1 effective H3=$H3 with the OLD CLI"
propose "$OLD_CLI" HF3_ACTIVE 1 "$H3" "$LOGD/propose_hf3.log"
wait_cc_row "$PARAM_HF3" "$H3" 1 20
R_V3="$CC_CB"
[ "$R_V3" -lt "$H3" ] || die "the HF3 row committed at $R_V3, not before its effective height $H3"
pump_to 1 $(( H3 + 1 ))
wait_all $(( H3 + 1 ))
stagef_cmt_diff_at_floor "OLD-past-HF3" || exit 2
echo "[ok] HF-3 is ACTIVE on the OLD fleet from H3=$H3 (row committed at $R_V3), 7/7 agree past it"

# ── 3. rolling upgrade, 7/7 after every step ────────────────────────
for k in $(seq 1 "$N"); do upgrade_node "$k"; done
for n in $(seq 1 "$N"); do node_runs "$n" "$NEW_SRV" || die "node$n is not on NEW after the rolling upgrade"; done
D2_LINE=$(d2_line_of 1)
[ -n "$D2_LINE" ] || die "node1 logged no D2 / git-commit line"
for n in $(seq 2 "$N"); do
    [ "$(d2_line_of "$n")" = "$D2_LINE" ] || die \
        "node$n's D2 / git-commit line differs from node1's: '$(d2_line_of "$n")' vs '$D2_LINE' (design §1.5: no vote unless 7/7 match)"
done
H_UPGRADED=$(tip_of 1)
echo "[ok] all 7 nodes upgraded one at a time with no wipe; 7/7 agreed after every step (tip $H_UPGRADED)"
echo "[ok] 7/7 logged: $D2_LINE"

# ── 4. before the vote: generation 1, H = 0, names closed ───────────
ruleset_info 1
[ "$RI_RC" = 0 ] || { printf '%s\n' "$RI_OUT" >&2; die "ruleset-info on node1 exited $RI_RC before the vote"; }
GEN1_SYS_V="$RI_SYS_V"; GEN1_CORE_V="$RI_CORE_V"
GEN1_SYS_H="$RI_SYS_H"; GEN1_CORE_H="$RI_CORE_H"
for n in $(seq 1 "$N"); do
    require_ruleset "$n" 1 "$GEN1_SYS_V" "$GEN1_CORE_V" 0
    [ "$RI_SYS_H" = "$GEN1_SYS_H" ] && [ "$RI_CORE_H" = "$GEN1_CORE_H" ] \
        || die "node$n's generation-1 hashes differ from node1's"
done
[ "$GEN1_SYS_V" -lt "$GEN2_SYS_V" ] && [ "$GEN1_CORE_V" -lt "$GEN2_CORE_V" ] \
    || die "generation 1 reads SYSTEM v$GEN1_SYS_V / CORE v$GEN1_CORE_V — not below generation 2's v$GEN2_SYS_V / v$GEN2_CORE_V"
D2_HEX="$RI_D2"
[ "${#D2_HEX}" = 16 ] && [ "$D2_HEX" = "$RI_CLI_D2" ] || die "the node's D2 '$D2_HEX' and the NEW CLI's '$RI_CLI_D2' are not one 16-hex literal"
[[ "$D2_LINE" == *"D2 0x$D2_HEX "* ]] || die "the startup D2 line ('$D2_LINE') does not name the D2 ruleset-info reports (0x$D2_HEX)"
D2_DEC=$(( 16#$D2_HEX ))
[ "$D2_DEC" -gt 0 ] || die "D2 0x$D2_HEX is not a positive int64 (top bit must be clear, design §1.2)"
echo "[ok] 7/7 before the vote: generation 1 (SYSTEM v$GEN1_SYS_V / CORE v$GEN1_CORE_V), H=0; D2 = 0x$D2_HEX = $D2_DEC"

for n in $(seq 1 "$N"); do
    [ "$(names_count "$n")" = 0 ] || die "node$n holds v2_names rows before any vote"
done
lookup 1 "$NAME_A"
[ "$LK_RC" = 2 ] || { printf '%s\n' "$LK_OUT" >&2; die "name lookup $NAME_A before the vote exited $LK_RC, expected 2 (not registered)"; }
name_register 1 "$NAME_A" "$LOGD/register_pre_vote.log"
[ "$NR_RC" != 0 ] || die "name register $NAME_A was ACCEPTED by the CLI before any vote"
grep -q "still runs rule-set generation 1" "$LOGD/register_pre_vote.log" \
    && grep -q "no vote committed yet" "$LOGD/register_pre_vote.log" \
    || die "name register before the vote failed for ANOTHER reason (see $LOGD/register_pre_vote.log)"
echo "[ok] REFUSED before the vote (CLI pre-check): $(grep 'still runs rule-set generation 1' "$LOGD/register_pre_vote.log")"
stagef_cmt_diff_at_floor "pre-gen2-vote" || exit 2

# ── 5. the RULESET_GEN2 vote on 7/7 NEW ─────────────────────────────
T_VOTE=$(tip_of 1)
H=$(( T_VOTE + 1 + STAGEF_CC_GRACE_ERGONOMIC + H_MARGIN ))
while [ $(( (H - 1) % E_REQ )) = 0 ]; do H=$(( H + 1 )); done   # rule (c)
echo "[ok] tip $T_VOTE — node1 proposes RULESET_GEN2=$D2_DEC effective H=$H (H-1=$(( H - 1 )), $(( (H - 1) % E_REQ )) past a boundary of E=$E_REQ)"
propose "$NEW_CLI" RULESET_GEN2 "$D2_DEC" "$H" "$LOGD/propose_gen2.log"
wait_cc_row "$PARAM_GEN2" "$H" "$D2_DEC" 20
R_VOTE="$CC_CB"
[ "$R_VOTE" -lt "$H" ] || die "the RULESET_GEN2 row committed at $R_VOTE, not before its effective height $H"
stagef_cmt_diff_at_floor "post-gen2-vote" || exit 2

# the SECOND param-9 proposal — its own effective, valid on the grace
# floor and on rule (c), so only rule (a) (single use) can refuse it
T_2ND=$(tip_of 1)
H_2ND=$(( H + 2 ))
while [ $(( (H_2ND - 1) % E_REQ )) = 0 ]; do H_2ND=$(( H_2ND + 1 )); done
[ "$H_2ND" -ge $(( T_2ND + 1 + STAGEF_CC_GRACE_ERGONOMIC )) ] \
    || die "the second proposal's effective $H_2ND is below its grace floor at tip $T_2ND — the layout broke (widen H_MARGIN)"
# Proposed from NODE 2's seat against its own node: every seat recorded
# node 1's identity in its per-proposer cooldown when the first vote's
# round arrived (the responder checks that BEFORE the rules and answers
# "rate-limited"), so a second proposal from node 1 inside that window
# would be refused for the wrong reason. Node 2's identity has no such
# record. Every OTHER seat must answer the rule's own text.
P2LOG="$LOGD/propose_gen2_second.log"
prc2=0
"$NEW_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 2)" -i "$(node_keys 2)" \
    chain-config propose --param RULESET_GEN2 --value "$D2_DEC" --effective "$H_2ND" \
    > "$P2LOG" 2>&1 || prc2=$?
cat "$P2LOG"
[ "$prc2" != 0 ] || die "a SECOND RULESET_GEN2 proposal (effective $H_2ND) exited 0 — rule (a) single use did not refuse it"
! grep -q "proposal accepted" "$P2LOG" || die "the second RULESET_GEN2 proposal reported acceptance"
grep -q "Round 1: 1/$N approved" "$P2LOG" \
    || die "the second RULESET_GEN2 proposal did not end round 1 at 1/$N (only its own seat) — see $P2LOG"
n_ref=$(grep -c "REFUSED: stateful rules rejected" "$P2LOG" || true)
[ "$n_ref" = $(( N - 1 )) ] || die \
    "$n_ref of $(( N - 1 )) other seats refused the second RULESET_GEN2 proposal with 'stateful rules rejected' — another reason (rate limit, SKIP, TIMEOUT, grace) is not rule (a); see $P2LOG"
grep -q "Quorum not reached" "$P2LOG" || die "the second RULESET_GEN2 proposal did not abort on quorum (see $P2LOG)"
t=$(tip_of 1)
pump_to 1 $(( t + 3 ))
wait_all $(( t + 3 ))
for n in $(seq 1 "$N"); do
    c=$(sqlite3 "$(db_of "$n")" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $PARAM_GEN2;" 2>/dev/null || echo ERR)
    [ "$c" = 1 ] || die "node$n holds $c param-9 rows at tip >= $(( t + 3 )) — expected exactly the one effective at $H"
done
echo "[ok] the second RULESET_GEN2 proposal (effective $H_2ND) was REFUSED by the seats; param 9 has ONE row on 7/7 at tip >= $(( t + 3 ))"

# ── 6. between the vote and H: still generation 1, H named ──────────
[ $(( $(tip_of 1) + 1 )) -lt "$H" ] || die "node1's tip reached H-1 before the between-vote-and-H checks (widen H_MARGIN)"
for n in $(seq 1 "$N"); do
    require_ruleset "$n" 1 "$GEN1_SYS_V" "$GEN1_CORE_V" "$H"
done
name_register 1 "$NAME_A" "$LOGD/register_pre_H.log"
[ "$NR_RC" != 0 ] || die "name register $NAME_A was ACCEPTED by the CLI before H=$H"
grep -q "still runs rule-set generation 1" "$LOGD/register_pre_H.log" \
    || die "name register before H failed for ANOTHER reason (see $LOGD/register_pre_H.log)"
! grep -q "no vote committed yet" "$LOGD/register_pre_H.log" \
    || die "the CLI says no vote is committed although the param-9 row is (see $LOGD/register_pre_H.log)"
[ $(( $(tip_of 1) + 1 )) -lt "$H" ] || die "node1's tip reached H-1 while the between-vote-and-H checks ran (widen H_MARGIN)"
echo "[ok] between the vote and H (tip $(tip_of 1)): 7/7 generation 1 with H=$H; name register REFUSED (CLI pre-check)"

# ── 7. cross H: pumped to H-PUMP_STOP_GAP, then idle production ─────
pump_to 1 $(( H - PUMP_STOP_GAP ))
wait_all $(( H + 1 ))
stagef_sentinel TARGET_REACHED
for hh in $(( H - 1 )) "$H" $(( H + 1 )); do
    diff_at "$hh" "at-height-$hh"
done
echo "[info] REPORTED: v2_blocks.tx_count at H-1/H/H+1 on node1 = $(sqlite3 "$(db_of 1)" \
    "SELECT group_concat(global_height || ':' || tx_count, ' ') FROM v2_blocks
      WHERE global_height BETWEEN $(( H - 1 )) AND $(( H + 1 ));" 2>/dev/null || echo '?')"

RH_SYS=""; RH_CORE=""
for n in $(seq 1 "$N"); do
    s=$(rh_row "$n" "$DOM_SYSTEM" $(( H - 1 ))); c=$(rh_row "$n" "$DOM_CORE" $(( H - 1 )))
    [ -n "$s" ] && [ "$s" != ERR ] || die "node$n has no SYSTEM v2_root_history row at H-1=$(( H - 1 )) (phase 6b' marks it touched)"
    [ -n "$c" ] && [ "$c" != ERR ] || die "node$n has no CORE v2_root_history row at H-1=$(( H - 1 )) (phase 6b' marks it touched)"
    if [ -z "$RH_SYS" ]; then RH_SYS="$s"; RH_CORE="$c"
    else
        [ "$s" = "$RH_SYS" ] || die "node$n's SYSTEM root-history row at H-1 differs: $s vs $RH_SYS"
        [ "$c" = "$RH_CORE" ] || die "node$n's CORE root-history row at H-1 differs: $c vs $RH_CORE"
    fi
    sb=$(rh_below "$n" "$DOM_SYSTEM" $(( H - 1 ))); cb=$(rh_below "$n" "$DOM_CORE" $(( H - 1 )))
    [ "$sb" = "$GEN1_SYS_V|$GEN1_SYS_H" ] || die "node$n's last SYSTEM row below H-1 is '$sb', expected generation 1 ($GEN1_SYS_V|…)"
    [ "$cb" = "$GEN1_CORE_V|$GEN1_CORE_H" ] || die "node$n's last CORE row below H-1 is '$cb', expected generation 1 ($GEN1_CORE_V|…)"
    grep -q "rule-set generation 1 -> 2 at the end of height $(( H - 1 )) " "$(stagef_node_dir "$n")/nodus.log" \
        || die "node$n logged no 'rule-set generation 1 -> 2 at the end of height $(( H - 1 ))' line"
done
[ "${RH_SYS%%|*}" = "$GEN2_SYS_V" ] || die "the SYSTEM row at H-1 names v${RH_SYS%%|*}, expected v$GEN2_SYS_V"
[ "${RH_CORE%%|*}" = "$GEN2_CORE_V" ] || die "the CORE row at H-1 names v${RH_CORE%%|*}, expected v$GEN2_CORE_V"
for n in $(seq 1 "$N"); do
    require_ruleset "$n" 2 "$GEN2_SYS_V" "$GEN2_CORE_V" "$H"
    s="${RH_SYS#*|}"; c="${RH_CORE#*|}"
    [ "$RI_SYS_H" = "${s%%|*}" ] || die "node$n's ruleset-info SYSTEM hash differs from the H-1 root-history row's"
    [ "$RI_CORE_H" = "${c%%|*}" ] || die "node$n's ruleset-info CORE hash differs from the H-1 root-history row's"
done
echo "[ok] 7/7 at H-1=$(( H - 1 )): SYSTEM v$GEN2_SYS_V / CORE v$GEN2_CORE_V root-history rows identical, generation-1 rows below;"
echo "     7/7 ruleset-info generation 2 with those hashes; 7/7 logged the switch; blocks AT H-1/H/H+1 identical"

# ── 8. NAME_REGISTER after H ────────────────────────────────────────
FP1=$(fp_lc "$(node_keys 1)"); FP2=$(fp_lc "$(node_keys 2)")
name_register 1 "$NAME_A" "$LOGD/register_${NAME_A}.log"
[ "$NR_RC" = 0 ] || die "name register $NAME_A from node1's identity exited $NR_RC after H (see $LOGD/register_${NAME_A}.log)"
grep -q "generation=2" "$LOGD/register_${NAME_A}.log" \
    || die "name register $NAME_A did not build for generation 2 (see $LOGD/register_${NAME_A}.log)"
h=$(stagef_cmt_wait_row "$(db_of 1)" \
    "SELECT COUNT(*) FROM v2_names WHERE name = CAST('$NAME_A' AS BLOB);") && wrc=0 || wrc=$?
case "$wrc" in
    0) ;;
    1) die "chain STALLED waiting for the v2_names row '$NAME_A' on node1 (tip $h)" ;;
    *) die "the v2_names row '$NAME_A' did not land on node1 within 20 heights (tip $h) — dropped, not delayed" ;;
esac
R_NAME=$(sqlite3 "$(db_of 1)" "SELECT registered_height FROM v2_names WHERE name = CAST('$NAME_A' AS BLOB);")
[ "$R_NAME" -ge "$H" ] || die "the '$NAME_A' row says registered_height $R_NAME < H=$H"
wait_all "$R_NAME"
ROW_A="$NAME_A|$FP1|$R_NAME"
CORE_AT_R=""
for n in $(seq 1 "$N"); do
    rows=$(names_rows "$n")
    [ "$rows" = "$ROW_A" ] || die "node$n's v2_names is '$rows', expected exactly '$ROW_A'"
    lookup "$n" "$NAME_A"
    [ "$LK_RC" = 0 ] || { printf '%s\n' "$LK_OUT" >&2; die "name lookup $NAME_A on node$n exited $LK_RC"; }
    [[ "$LK_OUT" == *"owner=$FP1 registered_height=$R_NAME "* ]] \
        || { printf '%s\n' "$LK_OUT" >&2; die "name lookup $NAME_A on node$n does not return node1's fingerprint at height $R_NAME"; }
    name_of "$n" "$FP1"
    [ "$NO_RC" = 0 ] && [[ "$NO_OUT" == *"name=$NAME_A registered_height=$R_NAME "* ]] \
        || { printf '%s\n' "$NO_OUT" >&2; die "name of <node1 fp> on node$n does not return $NAME_A at height $R_NAME (rc $NO_RC)"; }
    c=$(rh_row "$n" "$DOM_CORE" "$R_NAME")
    [ -n "$c" ] && [ "$c" != ERR ] || die "node$n has no CORE v2_root_history row at the registration height $R_NAME"
    if [ -z "$CORE_AT_R" ]; then CORE_AT_R="$c"
    elif [ "$c" != "$CORE_AT_R" ]; then die "node$n's CORE root at height $R_NAME differs: $c vs $CORE_AT_R"; fi
done
stagef_cmt_diff_at_floor "post-name-register" || exit 2
echo "[ok] '$NAME_A' -> node1 ($(printf '%.16s' "$FP1")...) at height $R_NAME, identical on 7/7 (lookup, name of, v2_names, CORE root v${CORE_AT_R%%|*})"

name_register 2 "$NAME_A" "$LOGD/register_${NAME_A}_node2.log"
[ "$NR_RC" != 0 ] || die "name register $NAME_A from node2's identity was ACCEPTED by the CLI (the name is taken)"
grep -q "$NAME_A is already registered" "$LOGD/register_${NAME_A}_node2.log" \
    || die "the second claim on $NAME_A failed for ANOTHER reason (see $LOGD/register_${NAME_A}_node2.log)"
name_register 1 "$NAME_A2" "$LOGD/register_${NAME_A2}.log"
[ "$NR_RC" != 0 ] || die "name register $NAME_A2 from node1's identity was ACCEPTED by the CLI (one name per ID)"
grep -q "this ID already holds the name $NAME_A" "$LOGD/register_${NAME_A2}.log" \
    || die "node1's second name failed for ANOTHER reason (see $LOGD/register_${NAME_A2}.log)"
t=$(tip_of 1)
pump_to 1 $(( t + 2 ))
wait_all $(( t + 2 ))
for n in $(seq 1 "$N"); do
    [ "$(names_rows "$n")" = "$ROW_A" ] || die "node$n's v2_names changed after the refusals: '$(names_rows "$n")'"
done
name_of 1 "$FP2"
[ "$NO_RC" = 2 ] || { printf '%s\n' "$NO_OUT" >&2; die "node2's identity holds a name after the refused claim (name of rc $NO_RC)"; }
lookup 1 "$NAME_A2"
[ "$LK_RC" = 2 ] || { printf '%s\n' "$LK_OUT" >&2; die "$NAME_A2 is registered after the refused second name (lookup rc $LK_RC)"; }
echo "[ok] REFUSED (CLI pre-checks): '$NAME_A' from node2 — $(grep 'already registered' "$LOGD/register_${NAME_A}_node2.log")"
echo "     REFUSED (CLI pre-checks): '$NAME_A2' from node1 — $(grep 'already holds the name' "$LOGD/register_${NAME_A2}.log")"
echo "     at tip >= $(( t + 2 )): v2_names still exactly '$ROW_A' on 7/7; node2 holds no name"

# ── 9. restart convergence across H (kill -9) ───────────────────────
k="$RESTART_VICTIM"; vlog="$(stagef_node_dir "$k")/nodus.log"
chain_before=$(basename "$(db_of "$k")")
role0=$(grep -c 'chain role: COMETBFT' "$vlog" || true)
hsdone0=$(grep -c 'completed ABCI handshake' "$vlog" || true)
stagef_cmt_diff_at_floor "pre-kill-node$k" || exit 2
base=$(floor_of $(seq 1 "$N"))
stop_node "$k" KILL
start_node "$k" "$NEW_SRV"
node_runs "$k" "$NEW_SRV" || die "node$k's process is not the NEW binary after the kill -9 restart"
wait_log_delta "$vlog" 'chain role: COMETBFT' "$role0" "node$k did not re-establish the COMETBFT role after kill -9"
wait_log_delta "$vlog" 'completed ABCI handshake' "$hsdone0" "node$k did not complete a NEW ABCI handshake after kill -9"
[ "$(basename "$(db_of "$k")")" = "$chain_before" ] \
    || die "node$k came back on a DIFFERENT chain file after kill -9"
fleet=$(tip_of 1)
stagef_cmt_wait_height "$(db_of "$k")" "$fleet" 3 >/dev/null \
    || die "node$k did not catch up to the fleet tip $fleet after kill -9"
pump_to 1 $(( fleet + 2 ))
wait_all $(( fleet + 2 ))
[ "$(floor_of $(seq 1 "$N"))" -gt "$base" ] || die "the floor did not move past $base after node$k's restart"
stagef_cmt_diff_at_floor "post-kill-node$k" || exit 2
[ "$(names_rows "$k")" = "$ROW_A" ] || die "node$k's v2_names after kill -9 is '$(names_rows "$k")'"
require_ruleset "$k" 2 "$GEN2_SYS_V" "$GEN2_CORE_V" "$H"
echo "[ok] node$k kill -9'd after H, restarted on its own chain file, caught up; 7/7 agree at a floor > $base"

# ── 10. pinned rejoin across H (wipe + pin, test_v2_join.sh's wipe) ──
k="$JOIN_VICTIM"; nd=$(stagef_node_dir "$k")
fleet_gid=$(basename "$(db_of 1)")
stagef_cmt_diff_at_floor "pre-wipe-node$k" || exit 2
stop_node "$k" KILL
# everything except the identity (a fresh key would not be in the set)
rm -f "$nd/data/"*.db "$nd/data/"*.db-wal "$nd/data/"*.db-shm \
      "$nd/data/.witness_db_seen" "$nd/data/.bootstrap_in_progress" \
      "$nd/data/.recovery_in_progress"
rm -rf "$nd/data/archive"
: > "$nd/nodus.log"
if ls "$nd/data/"witness_*.db >/dev/null 2>&1; then die "the wipe did not remove node$k's chain DB"; fi
echo "[ok] node$k wiped (identity kept, databases gone, log truncated)"
start_node "$k" "$NEW_SRV" --v2-genesis-pin "$PIN"
adopted=0; gid=""
for _ in $(seq 1 120); do
    if ls "$nd/data/"witness_*.db >/dev/null 2>&1; then
        gid=$(basename "$(db_of "$k")" 2>/dev/null || true)
        [ -n "$gid" ] && { adopted=1; break; }
    fi
    sleep 1
done
[ "$adopted" = 1 ] || die "node$k never adopted a chain after the pinned restart"
[ "$gid" = "$fleet_gid" ] || die "node$k adopted a DIFFERENT chain: $gid vs the fleet's $fleet_gid"
role_ok=0; live_ok=0
for _ in $(seq 1 30); do
    grep -q 'chain role: COMETBFT' "$nd/nodus.log" && role_ok=1
    grep -q 'cometbft lane LIVE' "$nd/nodus.log" && live_ok=1
    [ "$role_ok" = 1 ] && [ "$live_ok" = 1 ] && break
    sleep 1
done
[ "$role_ok" = 1 ] && [ "$live_ok" = 1 ] || die \
    "node$k has the chain but never reported COMETBFT role + lane LIVE (role=$role_ok live=$live_ok)"
fleet=$(tip_of 1)
stagef_cmt_wait_height "$(db_of "$k")" "$fleet" 3 >/dev/null \
    || die "node$k adopted but did not catch up to the fleet tip $fleet (replaying across H=$H)"
grep -q "rule-set generation 1 -> 2 at the end of height $(( H - 1 )) " "$nd/nodus.log" \
    || die "node$k's replay from genesis logged no 'rule-set generation 1 -> 2 at the end of height $(( H - 1 ))' line"
[ "$(rh_row "$k" "$DOM_SYSTEM" $(( H - 1 )))" = "$RH_SYS" ] || die "node$k's replayed SYSTEM root-history row at H-1 differs from the fleet's"
[ "$(rh_row "$k" "$DOM_CORE" $(( H - 1 )))" = "$RH_CORE" ] || die "node$k's replayed CORE root-history row at H-1 differs from the fleet's"
[ "$(rh_row "$k" "$DOM_CORE" "$R_NAME")" = "$CORE_AT_R" ] || die "node$k's replayed CORE root at the registration height $R_NAME differs"
[ "$(names_rows "$k")" = "$ROW_A" ] || die "node$k's replayed v2_names is '$(names_rows "$k")', expected '$ROW_A'"
require_ruleset "$k" 2 "$GEN2_SYS_V" "$GEN2_CORE_V" "$H"
lookup "$k" "$NAME_A"
[ "$LK_RC" = 0 ] && [[ "$LK_OUT" == *"owner=$FP1 registered_height=$R_NAME "* ]] \
    || { printf '%s\n' "$LK_OUT" >&2; die "name lookup $NAME_A on the rejoined node$k does not return node1 at $R_NAME"; }
for hh in $(( H - 1 )) "$H" $(( H + 1 )); do
    diff_at "$hh" "rejoined-at-height-$hh"
done
echo "[ok] node$k rejoined by pin, replayed genesis -> tip $(tip_of "$k") through the switch at H-1=$(( H - 1 )); its switch rows, names and blocks AT H-1/H/H+1 equal the fleet's"

t=$(tip_of 1)
pump_to 1 $(( t + 2 ))
wait_all $(( t + 2 ))
for n in $(seq 1 "$N"); do
    node_runs "$n" "$NEW_SRV" || die "node$n is not running NEW at the end"
    [ "$(names_rows "$n")" = "$ROW_A" ] || die "node$n's v2_names at the end is '$(names_rows "$n")'"
done

stagef_sentinel ASSERT_RUN
stagef_cmt_diff_at_floor "post-hf4" || exit 2
stagef_sentinel PASS
echo ""
echo "[info] HEIGHTS: HF2 vote tip $T_V2, row commit $R_V2, H2=$H2 | HF3 vote tip $T_V3, row commit $R_V3, H3=$H3"
echo "       | upgraded-by $H_UPGRADED"
echo "       | GEN2 vote tip $T_VOTE, row commit $R_VOTE, H=$H (second proposal effective $H_2ND refused)"
echo "       | '$NAME_A' registered at $R_NAME | D2 0x$D2_HEX"
echo "[PASS] HF-4: HF-2 + HF-3 activated on OLD ($OLD_VER), 7 nodes rolled OLD -> NEW ($NEW_VER) one at a"
echo "       time with 7/7 agreement after every step; RULESET_GEN2 voted at H=$H (a second vote"
echo "       refused), the fleet switched to SYSTEM v$GEN2_SYS_V / CORE v$GEN2_CORE_V at the end of"
echo "       H-1 with 7/7 identical blocks AT H-1/H/H+1; '$NAME_A' registered and identical on 7/7;"
echo "       kill -9 and wipe + pin rejoin across H converge. E=15 / grace 15 — the LOGIC only;"
echo "       every name refusal here is the CLI's own pre-check, not the chain's (header)."
