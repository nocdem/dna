#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_hf1_gas_upgrade.sh — HF-1, the first live height-activated
# hard fork: a WIPELESS rolling binary upgrade, then a governance vote
# that switches the gas-price rule on (standalone — NOT in the sweep)
# ════════════════════════════════════════════════════════════════════
#
# Governing records: docs/plans/2026-09-26-hf1-gas-price-design.md §6
# (this scenario's spec), §2 (the rule), §3 D3/D4, §4 G3/G4;
# docs/plans/decisions/2026-09-25-gas-price.md ("HF-1 O4");
# docs/plans/decisions/2026-09-23-height-activated-upgrades-before-
# testnet.md (the wipeless binary upgrade + live cutover must be PROVEN
# before testnet — this scenario is that proof, on localhost, at the
# short grace).
#
# WHAT IT PROVES — two modes, two bring-ups
#
#   BOTH MODES, first (R3-F4 — "OLD is really old"): the OLD server and
#   CLI report a version < 0.19.80 and the NEW server and CLI report
#   exactly 0.19.80, each from its OWN `-h` banner ("Nodus Server v…" /
#   "Nodus CLI v…", NODUS_VERSION_STRING); every node's log shows
#   "Nodus v<OLD> running" at the start, and every upgraded node a NEW
#   "Nodus v0.19.80 running" line. A mismatch FAILs (rc 1).
#
#   POSITIVE (default). Seven properties, each of which would be false
#   if it failed:
#   1. A chain started on the OLD binary (0.19.79, pre-HF-1) is
#      committing and 7/7 agree.
#   2. D3 / G4 — rolling upgrade: nodes 1..7 are stopped ONE AT A TIME
#      (SIGTERM) and restarted on the NEW binary with the SAME data dir,
#      identity and ports. After EVERY step the restarted node is back
#      in its COMETBFT role, ran and completed the ABCI handshake on the
#      SAME chain file, reached the fleet tip, the chain advanced >= 2
#      heights past it with REAL spends carried by the mixed fleet, and
#      7/7 agree on global_root + block_id at a floor strictly past the
#      step's baseline. No param-5 row exists yet, so an OLD and a NEW
#      binary must compute identical blocks — this is the only place
#      that claim is tested (design §3 D3 ⚠ note: a unit test cannot).
#   3. Before activation, a spend built by the OLD nodus-cli (which knows
#      nothing about a gas price) at the flat 0.01 floor is admitted and
#      APPLIED — read from the ledger: its created utxo_set row exists
#      and the coin shrank by exactly the floor.
#   4. A GAS_PRICE_RAW_PER_UNIT vote (parameter id 5), cast with the NEW
#      CLI's `chain-config propose`, at a price P chosen so that the
#      step-3 spend shape UNDERPAYS (P = the smallest value with
#      units x P > 10^6, units read from the CLI's own `units=` print,
#      never a literal), effective = tip + 1 + 15 + 5, lands a
#      chain_config_history row byte-identical on 7/7.
#   4b. R3-F3 / D1 — the rule is OFF until H: after the row has landed
#      and while the tip is still < H, the SAME OLD-CLI floor-fee shape
#      (which underpays at P) is admitted and APPLIED, its created
#      utxo_set row's own block_height < H. If fewer than 3 heights of
#      that window remain when the row is seen, the run FAILs (never
#      skips); the window's heights are printed.
#   5. At/after the effective height H (every node's tip >= H, so every
#      CheckTx judges at >= H + 1):
#      (a) the OLD CLI's floor-fee spend is REFUSED at CheckTx and never
#          lands, its coin untouched;
#      (b) the NEW CLI's spend pays units x P (read from dnac_fee_info's
#          gas_price) and is APPLIED — the fee is read from the LEDGER
#          (old coin - new coin), not from the CLI;
#      (c) G3 — a SYSTEM-only governance envelope (a second vote, price
#          back to 0, fee 0) still lands, identically on 7/7;
#      and 7/7 agree at the end.
#
#   NEGATIVE (STAGEF_HF1_NEGATIVE=1, a SEPARATE fresh bring-up) — D4,
#   the operator mistake the activation procedure forbids: nodes 1..6
#   are upgraded (same step as above), node 7 stays on OLD, and the vote
#   is cast anyway. Asserted:
#   - the six keep committing and agree with each other (floor diff over
#     nodes 1..6), and all six hold the param-5 row, identically;
#   - node 7 holds NO param-5 row, and its tip is FROZEN across a window
#     in which the six advance >= 5 heights;
#   - N5a — a RESTART does not recover it (decision
#     docs/plans/decisions/2026-09-26-hard-fork-lagging-node.md item 2,
#     confirmed by this scenario's own first run): node 7 froze exactly at
#     the row's commit_block R; restarted on NEW it completes its ABCI
#     handshake, then stays at R, still without the row, while the six
#     advance >= 3 more heights. This is the EXPECTED, documented
#     property — the NEW binary inherits the forked state;
#   - N5b — the documented recovery works: node 7 is stopped, its chain
#     data wiped exactly as test_v2_join.sh wipes it (identity kept),
#     restarted on NEW with --v2-genesis-pin (the bring-up's recorded
#     pin); it adopts the fleet's chain (same DB filename = same derived
#     chain id), reports a new COMETBFT role + lane LIVE, catches up to
#     the fleet tip, the chain advances +2, node 7 holds the six's
#     param-5 row byte-identically (re-executed under the NEW rules), and
#     7/7 agree.
#
# WHAT IT REQUIRES
#   Compile flags — TWO short-grace builds, both halves of each pair
#   (nodus-server AND nodus-cli from the SAME tree):
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#   OLD = the pre-HF-1 tree (commit 9b7260c0, nodus 0.19.79); NEW = the
#   HF-1 tree. Parameter 5 is ERGONOMIC (grace 15 in these builds).
#   Environment (read by THIS script; stagef_up_v2.sh never reads the
#   grace variables — it has no reference to them):
#     STAGEF_NODUS_BIN_OLD / STAGEF_NODUSCLI_BIN_OLD   the OLD pair
#     STAGEF_NODUS_BIN_NEW / STAGEF_NODUSCLI_BIN_NEW   the NEW pair
#     STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     STAGEF_HF1_NEGATIVE=1                            negative mode only
#   The cluster must have been brought up with the OLD server exported as
#   STAGEF_NODUS_BIN (checked: every node's /proc/<pid>/exe must be the
#   OLD binary, else FAIL). A FRESH bring-up per mode: this scenario
#   claims the genesis leaves of v2user, node 2 and node 3.
#
#   Exact command sequence (ORCHESTRATOR):
#     SG='-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
#     git -C /opt/dna worktree add <OLD_TREE> 9b7260c0
#     cmake -S <OLD_TREE>/nodus -B <OLD_TREE>/nodus/build-sg -DCMAKE_C_FLAGS="$SG"
#     make -C <OLD_TREE>/nodus/build-sg -j"$(nproc)" nodus-server nodus-cli
#     cmake -S <NEW_TREE>/nodus -B <NEW_TREE>/nodus/build-sg -DCMAKE_C_FLAGS="$SG"
#     make -C <NEW_TREE>/nodus/build-sg -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN_OLD=<OLD_TREE>/nodus/build-sg/nodus-server
#     export STAGEF_NODUSCLI_BIN_OLD=<OLD_TREE>/nodus/build-sg/nodus-cli
#     export STAGEF_NODUS_BIN_NEW=<NEW_TREE>/nodus/build-sg/nodus-server
#     export STAGEF_NODUSCLI_BIN_NEW=<NEW_TREE>/nodus/build-sg/nodus-cli
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     S=/opt/dna/nodus/tests/integration/stagef
#     # positive mode
#     STAGEF_NODUS_BIN=$STAGEF_NODUS_BIN_OLD STAGEF_NODUSCLI_BIN=$STAGEF_NODUSCLI_BIN_OLD \
#         bash $S/stagef_up_v2.sh
#     bash $S/tests/test_cmt_hf1_gas_upgrade.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#     # negative mode — its own fresh bring-up
#     STAGEF_NODUS_BIN=$STAGEF_NODUS_BIN_OLD STAGEF_NODUSCLI_BIN=$STAGEF_NODUSCLI_BIN_OLD \
#         bash $S/stagef_up_v2.sh
#     STAGEF_HF1_NEGATIVE=1 bash $S/tests/test_cmt_hf1_gas_upgrade.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   SKIP (rc 99): any of the four binaries missing / not executable, the
#   OLD and NEW servers byte-identical (an upgrade to the same binary
#   proves nothing about D3), or STAGEF_CC_GRACE_SAFETY /
#   STAGEF_CC_GRACE_ERGONOMIC not 15. A skip is not a pass.
#   FAIL (rc 1), not skip: a binary whose -h banner reports the wrong
#   version (OLD not < 0.19.80, NEW not == 0.19.80) or none at all.
#   The script RUNS each of the four binaries once with `-h` (usage,
#   exit 0, nothing opened) to read that banner.
#
# WHAT IT LEAVES BEHIND
#   POSITIVE: all 7 nodes running the NEW binary under NEW pids (appended
#   to pids.txt; every node.log appended to, holding two runs); two
#   param-5 rows: price P effective at H, and price 0 effective at a
#   later H2 — once the chain passes H2 (it will, idly) the rule is OFF
#   again; v2user's, node 2's and node 3's genesis leaves claimed; node 3
#   holds one self-sent pump coin, node 2 one coin one fee smaller,
#   v2user one coin, two floors smaller (the step-3 and step-4b floor-fee
#   spends applied, the 5a one refused).
#   NEGATIVE: nodes 1..6 on NEW; node 7 REBUILT by wipe + genesis-pin
#   rejoin on NEW (identity kept, every database re-adopted; restarted
#   twice under new pids; its nodus.log APPENDED — it holds the OLD run,
#   the stuck NEW restart and the rejoin); one param-5 row on all 7;
#   node 3's leaf claimed. If N5b FAILS, node 7 is left wiped or half
#   rejoined. Only node 7's data dir is ever wiped. Tear down with
#   stagef_down.sh before re-running.
#
# HOW IT CAN LIE
#   - **A CheckTx refusal is detected as rc 7, not as item code 9.**
#     handle_dnac_spend answers a refused dry run with send_error(...,
#     NODUS_ERR_PROTOCOL_ERROR = 7, "CheckTx code N")
#     (nodus_witness_handlers.c, the `res.code != CMT_MEM_CODE_TYPE_OK`
#     branch); nodus_client_dnac_spend returns the error code and drops
#     the text (nodus_client.c `resp->type == 'e'`), so the CLI prints
#     only "dnac_spend RPC failed (rc=7)". The dry run's item code 9 is a
#     server QGP_LOG_DEBUG line, not visible here. What makes the rc 7
#     mean "the gas-price rule" is the CONTROL: the SAME shape from the
#     SAME OLD CLI was admitted and applied at step 3 (price 0), and the
#     NEW CLI's spend paying units x P is admitted right after (5b). Any
#     OTHER CheckTx refusal in 5a would still read as a pass of 5a — the
#     control is what narrows it, not the code.
#   - **Fees are read from the ledger.** 5b's fee is old coin - new coin
#     on node 1's utxo_set, compared with units x P; the CLI's `fee=`
#     print is cross-checked, never trusted alone.
#   - **The vote's effect is read from chain_config_history**, never the
#     CLI's "proposal accepted" (CheckTx admission, not inclusion); the
#     identity check compares new_value | commit_block | tx_hash on every
#     node (created_at_unix is a local wall-clock column and is not
#     compared).
#   - **Heights are driven by REAL spends** (node 3's leaf, self-sends,
#     one in flight, each confirmed by its created utxo_set row — the
#     stagef_cmt_pump_to shape, re-implemented here because that helper
#     pays an explicit 10^6 fee, which after activation the NEW CLI
#     refuses and the chain would refuse). After the vote the pump pays
#     max(10^6, units x P) for its 1-in/1-out shape from the start, so no
#     pump spend can be built at price 0 and judged at price P across
#     the activation boundary (admission is at tip + 1, inclusion can be
#     later — README "What flips" rule 3, DELTA 2).
#   - **P is the SMALLEST underpaying price**, so the OLD CLI's floor fee
#     misses by less than one unit's price x units (for 8 221 units, P =
#     122: required 1 002 962 vs the 1 000 000 floor). The margin is
#     exact integer arithmetic, not a tolerance.
#   - **D3 is proven only for what the mixed fleet carried**: idle
#     blocks, 1-in/1-out CORE SPENDs and claims. No stake, token or
#     governance envelope crosses a mixed fleet in this scenario.
#   - **NEGATIVE mode's proposer is node 7's identity** (the OLD node's
#     seat), running the NEW CLI and submitting to node 1 (NEW). The CLI
#     asks every OTHER seat and signs its own seat locally
#     (cc_propose_ask_seat, nodus-cli.c), so all 7 approvals come in
#     round 1. Proposing from any NEW node instead would ask node 7's OLD
#     responder, which refuses param 5 (nodus_chain_config_scalar_rules:
#     `param_id > CC_PARAM_MAX_ID`, 4 in the OLD tree) → round 1 = 6/7 →
#     the CLI's round 2 re-asks the six, whose responders recorded this
#     proposer on the round-1 accept (nodus_cc_rate_limit_record) inside
#     NODUS_CC_RATE_LIMIT_WINDOW_MS = 5000 ms — whether round 2 lands is
#     then a wall-clock race (forbidden in this harness). Consequence:
#     THE OLD RESPONDER'S REFUSAL PATH IS NOT EXERCISED HERE; only the
#     OLD node's SYSTEM-exec divergence is.
#   - **Why a restart cannot recover node 7 (N5a), and why N5a is an
#     assertion, not a tolerated failure.** An item refused at exec is a
#     PER-ITEM result (HEAD nodus_witness_v2_apply.c, the Comet item
#     loop: `code = NODUS_V2_TX_ERR_EXEC; goto cmt_item_failed;` — the
#     block still commits), so node 7 COMMITS the vote's block R with a
#     different global_root / results; block R+1's header carries the
#     six's AppHash / LastResultsHash, which node 7 refuses
#     (nodus_witness_cmt_host.c "wrong Block.Header.AppHash."), so it
#     stops at R. On restart the ABCI handshake with app == store ==
#     state height does NOT re-execute block R (nodus_witness_cmt_node.c
#     hs_replay_blocks_with_context, the `app_block_height ==
#     store_block_height` branch only asserts the app hash). The first
#     run of this scenario measured it (decision
#     2026-09-26-hard-fork-lagging-node.md "Harness sonucu": row at h22,
#     node 7 stuck at 22 on NEW while the fleet reached 31). N5a asserts
#     that property; if a future build makes a restart recover (the
#     record's open item (b): an old binary HALTING on an unknown
#     parameter instead of committing), N5a goes RED and this scenario
#     must be revised with the record — that RED is intended.
#   - **N5a is not vacuous:** it requires a NEW 'completed ABCI
#     handshake' line on the restarted NEW process before reading the
#     tip, so "it stayed at R" cannot be "it never started". It does not
#     prove WHY the node stays (the 'wrong Block.Header.' count is
#     printed as evidence only).
#   - **N5b's "holds the row" is re-derived, not copied:** the wipe
#     removes every database (verified: no witness_*.db before the
#     restart), so the row node 7 ends with came from re-executing the
#     chain under the NEW binary. The adoption wait (120 x 1 s) and the
#     role/LIVE wait (30 x 1 s) are attempt-bounded; the catch-up waits
#     are progress-bounded. The log is appended, so the role/LIVE checks
#     are before/after counts, not presence.
#   - The node-7 log lines in N4 are printed as EVIDENCE only, never
#     asserted: which check node 7 fails first is recorded in the
#     decision file from one run, not asserted here.
#   - **The version gate (R3-F4) trusts NODUS_VERSION_STRING.** It is
#     the string the binary was compiled with; a build of the HF-1 tree
#     with the version bump reverted, or a pre-HF-1 tree bumped by hand,
#     would pass or fail on the number, not on the code. The two log
#     checks ("Nodus v<X> running") only prove the RUNNING process is
#     the same compiled version as the file; the byte-difference gate
#     and the path-based /proc/<pid>/exe check are unchanged. NEW is
#     pinned to exactly 0.19.80: a later version bump in the HF-1 tree
#     makes this FAIL until HF1_VERSION is updated with it.
#   - **The rule-off window (4b, R3-F3) proves D1 at ONE height** — the
#     one the in-window spend landed at (printed), somewhere in
#     [landing, H). It does not probe H - 1 specifically, and the
#     window's length is decided by where the vote landed (grace 15 +
#     margin 5 minus the collection/inclusion delay); < 3 heights left
#     FAILs rather than skipping. Its wait is bounded by the window
#     (stagef_cmt_wait_row MAX_HEIGHTS = H - 1 - landing), not by time.
#   - rc 99 = SKIP, coverage that did not happen.
#   - Grace 15, epoch whatever the builds carry: this proves the LOGIC
#     of the cutover at grace 15 and NOTHING about the production 720.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"
# Split S3: upgrades EVERY node by restarting it as one nodus-server
# process — SKIP (99) in any split mode (splitw, mixedw).
stagef_split_skip_if $(seq 1 "$STAGEF_COMMITTEE_SIZE")

die() { echo "[FAIL] $*" >&2; exit 1; }

NEGATIVE="${STAGEF_HF1_NEGATIVE:-0}"
OLD_SRV="${STAGEF_NODUS_BIN_OLD:-}"
OLD_CLI="${STAGEF_NODUSCLI_BIN_OLD:-}"
NEW_SRV="${STAGEF_NODUS_BIN_NEW:-}"
NEW_CLI="${STAGEF_NODUSCLI_BIN_NEW:-}"
FLOOR_FEE=1000000          # DNAC_MIN_FEE_RAW = NODUS_W_BASE_TX_FEE (dnac.h:143, nodus_types.h:266)
PARAM_GAS=5                # DNAC_CFG_GAS_PRICE_RAW_PER_UNIT (HF-1)
GRACE_MARGIN=5             # same +5 margin test_cmt_chain_config.sh uses
CONF="$BASE_DIR/v2_genesis.conf"
LOGD="$BASE_DIR/hf1"
N="$STAGEF_COMMITTEE_SIZE"

# ── SKIP gates (rc 99 — a skip is not a pass) ───────────────────────
for pair in "STAGEF_NODUS_BIN_OLD=$OLD_SRV" "STAGEF_NODUSCLI_BIN_OLD=$OLD_CLI" \
            "STAGEF_NODUS_BIN_NEW=$NEW_SRV" "STAGEF_NODUSCLI_BIN_NEW=$NEW_CLI"; do
    name="${pair%%=*}"; bin="${pair#*=}"
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        echo "[SKIP] $name is unset or not executable ('$bin') — this scenario needs"
        echo "       an OLD (pre-HF-1, 0.19.79) and a NEW (HF-1) short-grace build; see the header"
        exit 99
    fi
done
if cmp -s "$OLD_SRV" "$NEW_SRV"; then
    echo "[SKIP] STAGEF_NODUS_BIN_OLD and STAGEF_NODUS_BIN_NEW are byte-identical —"
    echo "       an upgrade to the same binary proves nothing about D3"
    exit 99
fi
# R3-F4 — OLD must BE the pre-HF-1 build and NEW the HF-1 build, read
# from each binary's OWN version banner, not inferred from a path or a
# byte difference. `nodus-server -h` prints "Nodus Server v<STRING>" and
# exits 0 before anything is opened (tools/nodus-server.c usage(), the
# `case 'h'` of the first getopt pass); `nodus-cli -h` prints "Nodus CLI
# v<STRING>" and exits 0 (tools/nodus-cli.c usage(), `case 'h'`). The
# string is NODUS_VERSION_STRING: "0.19.79" at 9b7260c0, "0.19.80" in
# the HF-1 tree (nodus_types.h:30). A mismatch is a FAIL, not a skip:
# the binaries were supplied, they are the wrong ones.
HF1_VERSION="0.19.80"
ver_num() {                # "X.Y.Z" -> X*10^6 + Y*10^3 + Z
    local a b c
    IFS=. read -r a b c <<< "$1"
    echo $(( a * 1000000 + b * 1000 + c ))
}
bin_version() {            # BIN KIND ("Server" | "CLI") -> X.Y.Z, "" if no banner
    local out re="Nodus $2 v([0-9]+\.[0-9]+\.[0-9]+)"
    out=$("$1" -h 2>&1 || true)
    if [[ "$out" =~ $re ]]; then echo "${BASH_REMATCH[1]}"; fi
}
OLD_VER=$(bin_version "$OLD_SRV" Server); NEW_VER=$(bin_version "$NEW_SRV" Server)
OLD_CLI_VER=$(bin_version "$OLD_CLI" CLI); NEW_CLI_VER=$(bin_version "$NEW_CLI" CLI)
echo "[info] versions: OLD server ${OLD_VER:-?} / cli ${OLD_CLI_VER:-?}; NEW server ${NEW_VER:-?} / cli ${NEW_CLI_VER:-?}"
for pair in "OLD server=$OLD_VER" "OLD cli=$OLD_CLI_VER" "NEW server=$NEW_VER" "NEW cli=$NEW_CLI_VER"; do
    [ -n "${pair#*=}" ] || { echo "[FAIL] the ${pair%%=*} binary printed no version banner on -h" >&2; exit 1; }
done
for v in "$OLD_VER" "$OLD_CLI_VER"; do
    [ "$(ver_num "$v")" -lt "$(ver_num "$HF1_VERSION")" ] \
        || { echo "[FAIL] an OLD binary reports $v — not a pre-HF-1 build (< $HF1_VERSION)" >&2; exit 1; }
done
for v in "$NEW_VER" "$NEW_CLI_VER"; do
    [ "$v" = "$HF1_VERSION" ] \
        || { echo "[FAIL] a NEW binary reports $v — not the HF-1 build ($HF1_VERSION)" >&2; exit 1; }
done
if [ "${STAGEF_CC_GRACE_ERGONOMIC:-720}" != 15 ] || [ "${STAGEF_CC_GRACE_SAFETY:-17280}" != 15 ]; then
    echo "[SKIP] STAGEF_CC_GRACE_ERGONOMIC=${STAGEF_CC_GRACE_ERGONOMIC:-720}" \
         "STAGEF_CC_GRACE_SAFETY=${STAGEF_CC_GRACE_SAFETY:-17280} — needs the short-grace"
    echo "       builds (-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15"
    echo "       -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15) and both variables = 15"
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
[ -f "$CONF" ] || die "no $CONF — this scenario needs a stagef_up_v2.sh bring-up"
mkdir -p "$LOGD"

# ── script-local helpers ────────────────────────────────────────────
db_of()  { stagef_node_chain_db "$1"; }
tip_of() { stagef_cmt_tip "$(db_of "$1")"; }
fp_of()  { cat "$1/nodus.fp"; }                 # $1 = identity dir
node_keys() { echo "$(stagef_node_dir "$1")/identity"; }

# The server pid of node $1: the one process whose command line carries
# that node's data dir as its -d argument (the spawn line below and
# stagef_up_v2.sh's).
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

listening() {
    local out
    out=$(ss -ltnH "sport = :$1" 2>/dev/null || true)
    [ -n "$out" ]
}

# diff_nodes LABEL NODE... — stagef_diff.sh's exact comparison
# (global_height | first 8 bytes of global_root | first 8 of block_id)
# over a SUBSET of nodes, at the floor of their tips. Needed only where
# one node is known to have left the chain (negative mode); every 7-node
# comparison goes through stagef_cmt_diff_at_floor.
diff_nodes() {
    local label="$1"; shift
    local floor=-1 first=1 n h row ref="" bad=0 rows=""
    for n in "$@"; do
        h=$(tip_of "$n"); [ -n "$h" ] || h=-1
        if [ "$first" = 1 ]; then floor="$h"; first=0
        elif [ "$h" -lt "$floor" ]; then floor="$h"; fi
    done
    [ "$floor" -ge 0 ] || { echo "[FAIL] $label: a node has no Comet block" >&2; return 1; }
    for n in "$@"; do
        row=$(sqlite3 "$(db_of "$n")" \
            "SELECT global_height || '|v2:' || hex(substr(global_root,1,8)) \
             || '|bid:' || hex(substr(block_id,1,8)) \
             FROM v2_blocks WHERE global_height = $floor" 2>/dev/null || true)
        rows="$rows
  node$n  ${row:-NO_BLOCK}"
        [ -n "$row" ] || bad=1
        if [ -z "$ref" ]; then ref="$row"; elif [ "$row" != "$ref" ]; then bad=1; fi
    done
    if [ "$bad" = 1 ]; then
        echo "[FAIL] $label: divergence among nodes $*:$rows" >&2
        return 1
    fi
    echo "[ok] $label: nodes $* identical at height $floor ($ref)"
}

# floor_of NODE... — the minimum tip.
floor_of() {
    local floor=-1 first=1 n h
    for n in "$@"; do
        h=$(tip_of "$n"); [ -n "$h" ] || h=-1
        if [ "$first" = 1 ]; then floor="$h"; first=0
        elif [ "$h" -lt "$floor" ]; then floor="$h"; fi
    done
    echo "$floor"
}

largest_coin() {           # DB FP → the largest native coin amount, 0 if none
    local amt
    amt=$(sqlite3 "$1" "SELECT COALESCE(MAX(amount),0) FROM utxo_set
                         WHERE owner = '$2' AND token_id = zeroblob(64);" 2>/dev/null || echo 0)
    case "$amt" in ''|*[!0-9]*) amt=0 ;; esac
    echo "$amt"
}

# spend_field LOG KEY — KEY's value on the CLI's "v2-envelope spend k/n:"
# summary line (fee= / units= / tip=); printed BEFORE submission
# (nodus-cli.c cmd_v2_spend), so present on a refused spend too.
spend_field() {
    awk -v k="$2" '/^v2-envelope spend [0-9]+\/[0-9]+: /{
        for (i = 1; i <= NF; i++) { n = index($i, "=");
            if (n > 0 && substr($i, 1, n - 1) == k) { print substr($i, n + 1); exit } } }' "$1"
}
spend_intent() { awk -F= '/^  intent_id=/{print $2; exit}' "$1"; }

# claim_leaf CLI IDENTITY_DIR SUBMIT_NODE — claim the identity's genesis
# leaf and wait for the coin as a LEDGER EFFECT (stagef_pump_claim's
# shape, with the CLI, identity and node as arguments).
claim_leaf() {
    local cli="$1" keys="$2" node="$3" port db fp log h wrc
    port=$(stagef_tcp_port "$node"); db=$(db_of "$node"); fp=$(fp_of "$keys")
    log="$LOGD/claim_$(basename "$(dirname "$keys")").log"
    "$cli" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$db" \
        --keys "$keys" --submit "127.0.0.1:$port" > "$log" 2>&1 \
        || { cat "$log" >&2; die "v2-claim for $keys was refused (see $log)"; }
    h=$(stagef_cmt_wait_row "$db" \
        "SELECT COUNT(*) FROM utxo_set WHERE owner = '$fp'
           AND token_id = zeroblob(64) AND amount > $FLOOR_FEE;") && wrc=0 || wrc=$?
    [ "$wrc" = 0 ] || die "the claimed coin for $keys never appeared (wait rc=$wrc, tip $h)"
    echo "[ok] claimed the genesis leaf of $keys (tip $h)"
}

# spend CLI KEYS NODE LOG [FEE] — one self-send of the identity's LARGEST
# native coin (--amount all --count 1: one input, one output, no change),
# submitted to NODE. No FEE = the CLI's own default. Returns the CLI's rc;
# the output (stdout + stderr) is in LOG.
spend() {
    local cli="$1" keys="$2" node="$3" log="$4" fee="${5:-}" port
    port=$(stagef_tcp_port "$node")
    local -a extra=()
    [ -z "$fee" ] || extra=(--fee "$fee")
    "$cli" -s 127.0.0.1 -p "$port" v2-envelope spend --keys "$keys" \
        --to "$(fp_of "$keys")" --amount all --count 1 ${extra[@]+"${extra[@]}"} \
        --submit "127.0.0.1:$port" > "$log" 2>&1
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
# pump_to NODE TARGET FEE — self-send SPENDs by node 3's identity with the
# NEW CLI, submitted to and confirmed on NODE, one in flight, until NODE's
# tip >= TARGET. FEE is explicit (see "HOW IT CAN LIE").
pump_to() {
    local node="$1" target="$2" fee="$3" log intent
    while [ "$(tip_of "$node")" -lt "$target" ]; do
        PUMP_SEQ=$(( PUMP_SEQ + 1 ))
        log="$LOGD/pump_$PUMP_SEQ.log"
        spend "$NEW_CLI" "$PUMP_KEYS" "$node" "$log" "$fee" \
            || { cat "$log" >&2; die "pump spend $PUMP_SEQ was refused/failed on node$node (see $log)"; }
        intent=$(spend_intent "$log")
        [ "${#intent}" = 128 ] || { cat "$log" >&2; die "pump spend $PUMP_SEQ printed no intent_id"; }
        wait_applied "$node" "$intent" >/dev/null
    done
    echo "[ok] node$node tip $(tip_of "$node") >= $target (pumped, fee $fee)"
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

# start_node K BIN [EXTRA...] — stagef_up_v2.sh's spawn line, same
# identity, data dir, ports and config; EXTRA (e.g. --v2-genesis-pin PIN,
# test_v2_join.sh's placement) goes before -i. The log is APPENDED.
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

# upgrade_node K — one rolling step: stop node K, restart it on NEW, and
# prove it rejoined, the chain advanced >= 2 heights past the fleet tip
# with real spends, and 7/7 agree at a floor past the step's baseline.
upgrade_node() {
    local k="$1" ref vlog nd chain_before role0 hs0 hsdone0 refuse0 base fleet target i ok
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
    # the running process announces its own compiled version
    # (nodus_server.c nodus_server_run "Nodus v%s running", printed at
    # the start of the run loop — possibly AFTER the role line, which is
    # printed during init, so attempt-bounded) — R3-F4, from the inside
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
    echo "     $(grep 'ABCI replay blocks:' "$vlog" | tail -1)"

    fleet=$(tip_of "$ref")
    stagef_cmt_wait_height "$(db_of "$k")" "$fleet" 3 >/dev/null \
        || die "node$k did not catch up to the fleet tip $fleet after its upgrade"
    target=$(( fleet + 2 ))
    pump_to "$ref" "$target" "$FLOOR_FEE"
    for i in $(seq 1 "$N"); do
        stagef_cmt_wait_height "$(db_of "$i")" "$target" 3 >/dev/null \
            || die "node$i never reached height $target after node$k's upgrade"
    done
    [ "$(floor_of $(seq 1 "$N"))" -gt "$base" ] || die "the floor did not move past $base in node$k's step"
    stagef_cmt_diff_at_floor "post-upgrade-node$k" || exit 2
    echo "[ok] rolling step node$k: OLD -> NEW, chain advanced $base -> >= $target, 7/7 agree"
}

# propose CLI PROPOSER_NODE SUBMIT_NODE VALUE EFFECTIVE LOG — a
# GAS_PRICE_RAW_PER_UNIT vote with PROPOSER_NODE's identity, submitted to
# SUBMIT_NODE.
propose() {
    local cli="$1" who="$2" to="$3" value="$4" eff="$5" log="$6" rc=0
    "$cli" -s 127.0.0.1 -p "$(stagef_tcp_port "$to")" -i "$(node_keys "$who")" \
        chain-config propose --param GAS_PRICE_RAW_PER_UNIT --value "$value" \
        --effective "$eff" > "$log" 2>&1 || rc=$?
    cat "$log"
    [ "$rc" = 0 ] || die "chain-config propose (node$who -> node$to, value $value) exited $rc (see $log)"
    grep -q "proposal accepted" "$log" || die "propose did not report acceptance (see $log)"
}

cc_row() {                # NODE EFFECTIVE → new_value|commit_block|tx_hash, "" when absent
    sqlite3 "$(db_of "$1")" \
        "SELECT new_value || '|' || commit_block || '|' || hex(tx_hash) FROM chain_config_history
          WHERE param_id = $PARAM_GAS AND effective_block = $2;" 2>/dev/null || echo ERR
}

# wait_cc_row REF EFFECTIVE VALUE NODE... — the row lands on REF, then
# every listed node reaches that height and holds the SAME row.
wait_cc_row() {
    local ref="$1" eff="$2" val="$3"; shift 3
    local h wrc first="" r n rows=""
    h=$(stagef_cmt_wait_row "$(db_of "$ref")" \
        "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $PARAM_GAS
           AND effective_block = $eff AND new_value = $val;") && wrc=0 || wrc=$?
    case "$wrc" in
        0) ;;
        1) die "chain STALLED waiting for the param-$PARAM_GAS row (effective $eff) on node$ref" ;;
        *) die "the param-$PARAM_GAS row (effective $eff) never landed on node$ref within 20 heights — dropped" ;;
    esac
    for n in "$@"; do
        stagef_cmt_wait_height "$(db_of "$n")" "$h" 3 >/dev/null \
            || die "node$n never reached height $h (the row's detection height)"
        r=$(cc_row "$n" "$eff")
        rows="$rows node$n=$r"
        if [ -z "$first" ]; then first="$r"
        elif [ "$r" != "$first" ]; then die "the param-$PARAM_GAS row DIFFERS across nodes:$rows"; fi
    done
    case "$first" in ""|ERR) die "no param-$PARAM_GAS row readable";; esac
    [ "${first%%|*}" = "$val" ] || die "the row carries value ${first%%|*}, expected $val"
    CC_ROW="$first"
    echo "[ok] param-$PARAM_GAS row (value $val, effective $eff) identical on nodes $*: $first"
}

# ── 0. preconditions: fresh cluster, every node on the OLD binary ───
for n in $(seq 1 "$N"); do
    node_runs "$n" "$OLD_SRV" || die \
        "node$n is not running STAGEF_NODUS_BIN_OLD ($(readlink -f "$OLD_SRV")) — bring the cluster up with STAGEF_NODUS_BIN=\$STAGEF_NODUS_BIN_OLD (header)"
    grep -q "Nodus v$OLD_VER running" "$(stagef_node_dir "$n")/nodus.log" \
        || die "node$n's log has no 'Nodus v$OLD_VER running' line — it was not started from the OLD build"
done
stagef_sentinel SETUP_OK
echo "[ok] 7/7 nodes run the OLD binary $(readlink -f "$OLD_SRV")"
echo "     NEW binary: $(readlink -f "$NEW_SRV")  mode: $([ "$NEGATIVE" = 1 ] && echo NEGATIVE || echo POSITIVE)"

# ── 1. the OLD chain commits and agrees; fund the actors ────────────
stagef_cmt_diff_at_floor "on-OLD" || exit 2
claim_leaf "$OLD_CLI" "$PUMP_KEYS" 1
if [ "$NEGATIVE" != 1 ]; then
    USER_KEYS="$BASE_DIR/v2user/identity"
    NEWSPENDER_KEYS=$(node_keys 2)
    claim_leaf "$OLD_CLI" "$USER_KEYS" 1
    claim_leaf "$OLD_CLI" "$NEWSPENDER_KEYS" 1
fi
t=$(tip_of 1)
pump_to 1 $(( t + 2 )) "$FLOOR_FEE"
stagef_cmt_diff_at_floor "OLD-chain-committing" || exit 2

# The unit count of the 1-in/1-out spend shape, from the CLI's OWN print
# (a --dry-run of the pump identity: builds, self-checks, submits none).
dry="$LOGD/units_dry_run.log"
"$NEW_CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" v2-envelope spend \
    --keys "$PUMP_KEYS" --to "$(fp_of "$PUMP_KEYS")" --amount all --count 1 \
    --submit "127.0.0.1:$(stagef_tcp_port 1)" --dry-run > "$dry" 2>&1 \
    || { cat "$dry" >&2; die "the unit-count dry run failed"; }
UNITS=$(spend_field "$dry" units)
case "$UNITS" in ''|*[!0-9]*|0) cat "$dry" >&2; die "no units= in the dry run";; esac
PRICE=$(( FLOOR_FEE / UNITS + 1 ))           # smallest P with UNITS x P > 10^6
[ "$PRICE" -le 1000000 ] || die "price $PRICE exceeds MAX_GAS_PRICE 1000000"
REQ=$(( UNITS * PRICE ))
[ "$REQ" -gt "$FLOOR_FEE" ] || die "arithmetic: $UNITS x $PRICE = $REQ does not exceed the floor"
echo "[ok] 1-in/1-out spend declares $UNITS units -> test price P=$PRICE ($UNITS x $PRICE = $REQ > $FLOOR_FEE)"

# ════════════════════════════════════════════════════════════════════
if [ "$NEGATIVE" = 1 ]; then
# ════════════════════════════════════════════════════════════════════
    # The genesis pin the bring-up recorded (stagef_up_v2.sh writes
    # $BASE_DIR/v2_genesis_pin) — N5b's recovery needs it. Read, never
    # re-derived (test_v2_join.sh's rule).
    PINFILE="$BASE_DIR/v2_genesis_pin"
    [ -s "$PINFILE" ] || die "no $PINFILE — the negative arm's pin rejoin needs the bring-up's recorded pin"
    PIN=$(cat "$PINFILE")
    [ "${#PIN}" = 64 ] || die "the recorded pin is not 64 hex characters"

    # ── N2. upgrade nodes 1..6 only ─────────────────────────────────
    for k in 1 2 3 4 5 6; do upgrade_node "$k"; done
    node_runs 7 "$OLD_SRV" || die "node7 must still run the OLD binary in negative mode"
    echo "[ok] mixed fleet: nodes 1-6 NEW, node 7 OLD — 7/7 agreed after every step"

    # ── N3. the forbidden vote: node 7's seat proposes (see header) ──
    t=$(tip_of 1)
    EFF=$(( t + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
    echo "[ok] tip $t — node7's identity proposes GAS_PRICE_RAW_PER_UNIT=$PRICE effective=$EFF via node1"
    log7_bad0=$(grep -c 'wrong Block.Header.' "$(stagef_node_dir 7)/nodus.log" || true)
    propose "$NEW_CLI" 7 1 "$PRICE" "$EFF" "$LOGD/propose_negative.log"
    wait_cc_row 1 "$EFF" "$PRICE" 1 2 3 4 5 6
    R="${CC_ROW#*|}"; R="${R%%|*}"
    echo "[ok] the row landed at commit_block $R on the six"

    # ── N4. node 7 falls out while the six keep committing ──────────
    t=$(tip_of 1)
    pump_to 1 $(( t + 3 )) "$REQ"
    # Settle node 7 before the first read: it routinely finalizes a block
    # one round after the six, so a read taken while it is still applying
    # R would see R-1 then R and misread a correct fork as "still moving".
    # Bounded (one empty-block interval of no progress), non-fatal: a node
    # 7 that halted before R just times out here.
    stagef_cmt_wait_height "$(db_of 7)" "$R" 1 >/dev/null || true
    t7a=$(tip_of 7)
    t=$(tip_of 1)
    pump_to 1 $(( t + 5 )) "$REQ"
    t7b=$(tip_of 7)
    t1=$(tip_of 1)
    rows7=$(sqlite3 "$(db_of 7)" "SELECT COUNT(*) FROM chain_config_history
                                   WHERE param_id = $PARAM_GAS;" 2>/dev/null || echo ERR)
    echo "[info] node7 tip $t7a -> $t7b while node1 went to $t1 (row commit_block $R)"
    echo "[info] node7 process: $(pid7=$(node_pid 7); [ -n "$pid7" ] && kill -0 "$pid7" 2>/dev/null && echo "alive (pid $pid7)" || echo "NOT running")"
    echo "[info] node7 'wrong Block.Header.' log lines: $log7_bad0 -> $(grep -c 'wrong Block.Header.' "$(stagef_node_dir 7)/nodus.log" || true) (evidence only)"
    grep 'wrong Block.Header.\|CMT_FAULT' "$(stagef_node_dir 7)/nodus.log" | tail -5 || true
    if [ "$t7a" -ge 0 ]; then
        echo "[info] at node7's tip $t7a: node7 $(sqlite3 "$(db_of 7)" "SELECT hex(substr(global_root,1,8)) || '/' || hex(substr(block_id,1,8)) FROM v2_blocks WHERE global_height=$t7a" 2>/dev/null || true)" \
             "vs node1 $(sqlite3 "$(db_of 1)" "SELECT hex(substr(global_root,1,8)) || '/' || hex(substr(block_id,1,8)) FROM v2_blocks WHERE global_height=$t7a" 2>/dev/null || true) (global_root/block_id, evidence only)"
    fi
    [ "$rows7" = 0 ] || die "node7 (OLD) holds $rows7 param-$PARAM_GAS row(s) — the OLD binary did not refuse the row"
    [ "$t7b" = "$t7a" ] || die "node7's tip moved ($t7a -> $t7b) while it should have left the chain"
    [ "$t7a" -lt "$t1" ] || die "node7's tip $t7a is not behind the six ($t1)"
    [ $(( t1 - t7a )) -ge 5 ] || die "the six advanced only $(( t1 - t7a )) past node7 — window too small"
    diff_nodes "six-NEW-after-vote" 1 2 3 4 5 6 || exit 2
    echo "[ok] D4: node7 (OLD) holds no param-$PARAM_GAS row and is FROZEN at $t7a while the six committed to $t1 and agree"
    stagef_sentinel TARGET_REACHED

    # ── N5a. a RESTART on NEW does NOT recover node 7 ───────────────
    # Decision 2026-09-26-hard-fork-lagging-node.md item 2: node 7
    # COMMITTED the vote's block R under the OLD rules (a per-item exec
    # refusal, HEAD nodus_witness_v2_apply.c `code = NODUS_V2_TX_ERR_EXEC;
    # goto cmt_item_failed`), and the ABCI handshake at app == store ==
    # state height only asserts the app hash, it never re-executes R
    # (nodus_witness_cmt_node.c hs_replay_blocks_with_context) — so the
    # NEW binary inherits the forked state and stays at R. Expected.
    [ "$t7a" = "$R" ] || die "node7 froze at $t7a, not at the row's commit_block $R — the fork is not where the decision record says it is"
    v7log="$(stagef_node_dir 7)/nodus.log"
    hsdone7=$(grep -c 'completed ABCI handshake' "$v7log" || true)
    bad7=$(grep -c 'wrong Block.Header.' "$v7log" || true)
    stop_node 7
    start_node 7 "$NEW_SRV"
    node_runs 7 "$NEW_SRV" || die "node7's process is not the NEW binary after the restart"
    ok=0
    for i in $(seq 1 30); do
        [ "$(grep -c 'completed ABCI handshake' "$v7log" || true)" -gt "$hsdone7" ] && { ok=1; break; }
        sleep 1
    done
    [ "$ok" = 1 ] || die "node7 on NEW never completed its ABCI handshake — it did not even start, so 'it stays stuck' below would be vacuous"
    t7c=$(tip_of 7)
    t=$(tip_of 1)
    pump_to 1 $(( t + 3 )) "$REQ"
    t7d=$(tip_of 7)
    echo "[info] node7 on NEW: tip $t7c -> $t7d while node1 went $t -> $(tip_of 1);" \
         "'wrong Block.Header.' lines $bad7 -> $(grep -c 'wrong Block.Header.' "$v7log" || true) (evidence only)"
    [ "$t7c" = "$R" ] && [ "$t7d" = "$R" ] || die \
        "node7 restarted on NEW moved off the fork height $R ($t7c -> $t7d) — decision 2026-09-26-hard-fork-lagging-node.md says a restart cannot recover it; read node7's log"
    [ "$(cc_row 7 "$EFF")" = "" ] || die "node7 restarted on NEW holds the param-$PARAM_GAS row — the restart re-executed R, contrary to the record"
    echo "[ok] N5a: restarted on NEW, node7 stays FORKED at $R while the six advanced >= 3 more heights (restart is not a recovery)"

    # ── N5b. the documented recovery: wipe + genesis-pin rejoin ─────
    # test_v2_join.sh's exact wipe (every database, the markers and the
    # archive; the IDENTITY is kept — a new key is not in the validator
    # set), then a restart on NEW with --v2-genesis-pin. The log is
    # APPENDED, not truncated (it holds N4/N5a's evidence); every log
    # check below is a before/after count.
    nd7=$(stagef_node_dir 7)
    fleet_gid=$(basename "$(db_of 1)")
    role7=$(grep -c 'chain role: COMETBFT' "$v7log" || true)
    live7=$(grep -c 'cometbft lane LIVE' "$v7log" || true)
    stop_node 7
    rm -f "$nd7/data/"*.db "$nd7/data/"*.db-wal "$nd7/data/"*.db-shm \
          "$nd7/data/.witness_db_seen" "$nd7/data/.bootstrap_in_progress" \
          "$nd7/data/.recovery_in_progress"
    rm -rf "$nd7/data/archive"
    ! ls "$nd7/data/"witness_*.db >/dev/null 2>&1 || die "the wipe did not remove node7's chain DB"
    [ -s "$nd7/identity/nodus.fp" ] || die "node7's identity is gone — the wipe must keep it"
    echo "[ok] node7 wiped (identity kept, databases gone)"
    start_node 7 "$NEW_SRV" --v2-genesis-pin "$PIN"
    node_runs 7 "$NEW_SRV" || die "node7's process is not the NEW binary after the pin rejoin"
    adopted=0 gid=""
    for i in $(seq 1 120); do
        gid=$(basename "$(db_of 7)" 2>/dev/null || true)
        [ -n "$gid" ] && [ "$gid" != "." ] && { adopted=1; break; }
        sleep 1
    done
    [ "$adopted" = 1 ] || { tail -30 "$v7log" >&2; die "node7 never adopted a chain from its genesis pin"; }
    [ "$gid" = "$fleet_gid" ] || die "node7 adopted a DIFFERENT chain: $gid vs the fleet's $fleet_gid"
    ok=0
    for i in $(seq 1 30); do
        if [ "$(grep -c 'chain role: COMETBFT' "$v7log" || true)" -gt "$role7" ] && \
           [ "$(grep -c 'cometbft lane LIVE' "$v7log" || true)" -gt "$live7" ]; then ok=1; break; fi
        sleep 1
    done
    [ "$ok" = 1 ] || die "node7 adopted the chain but never reported a NEW COMETBFT role + lane LIVE"
    echo "[ok] node7 adopted the fleet's chain ($gid) from the pin and is LIVE on NEW"
    fleet=$(tip_of 1)
    stagef_cmt_wait_height "$(db_of 7)" "$fleet" 3 >/dev/null \
        || die "node7 adopted by pin but did not catch up to the fleet tip $fleet (stuck at $(tip_of 7))"
    target=$(( fleet + 2 ))
    pump_to 1 "$target" "$REQ"
    for i in $(seq 1 "$N"); do
        stagef_cmt_wait_height "$(db_of "$i")" "$target" 3 >/dev/null \
            || die "node$i never reached height $target after node7's pin rejoin"
    done
    [ "$(cc_row 7 "$EFF")" = "$CC_ROW" ] || die "node7 after the pin rejoin does not hold the six's param-$PARAM_GAS row ($(cc_row 7 "$EFF") vs $CC_ROW)"
    stagef_sentinel ASSERT_RUN
    stagef_cmt_diff_at_floor "post-negative-pin-rejoin" || exit 2
    stagef_sentinel PASS
    echo ""
    echo "[PASS] NEGATIVE (D4): with node7 on the OLD binary a param-$PARAM_GAS vote landed on"
    echo "       the six, node7 held no row and forked at $R while the six committed on;"
    echo "       a restart on NEW did NOT recover it; a wipe + genesis-pin rejoin on NEW did —"
    echo "       it re-derived the row and 7/7 agree. Grace 15 (short build) — the LOGIC"
    echo "       only, nothing about the production grace 720."
    exit 0
fi

# ════════════════════════════════════════════════════════════════════
# POSITIVE MODE
# ════════════════════════════════════════════════════════════════════

# ── 2. rolling upgrade, 7/7 after every step (D3 / G4) ──────────────
for k in $(seq 1 "$N"); do upgrade_node "$k"; done
for n in $(seq 1 "$N"); do node_runs "$n" "$NEW_SRV" || die "node$n is not on NEW after the rolling upgrade"; done
echo "[ok] D3/G4: all 7 nodes upgraded one at a time with no wipe; 7/7 agreed after every step"

# ── 3. before activation: the OLD CLI's floor-fee spend is applied ──
pre_log="$LOGD/old_cli_pre_activation.log"
coin0=$(largest_coin "$(db_of 1)" "$(fp_of "$USER_KEYS")")
spend "$OLD_CLI" "$USER_KEYS" 1 "$pre_log" || { cat "$pre_log" >&2; die "the OLD CLI's floor-fee spend was refused BEFORE activation"; }
cat "$pre_log"
pre_intent=$(spend_intent "$pre_log"); pre_fee=$(spend_field "$pre_log" fee)
[ "${#pre_intent}" = 128 ] || die "the step-3 spend printed no intent_id"
[ "$pre_fee" = "$FLOOR_FEE" ] || die "the OLD CLI's default fee is $pre_fee, not the floor $FLOOR_FEE"
wait_applied 1 "$pre_intent" >/dev/null
coin1=$(sqlite3 "$(db_of 1)" "SELECT amount FROM utxo_set WHERE lower(hex(tx_hash)) = '$pre_intent';")
[ $(( coin0 - coin1 )) = "$FLOOR_FEE" ] || die "step 3: the coin shrank by $(( coin0 - coin1 )), not the floor $FLOOR_FEE"
stagef_cmt_diff_at_floor "post-old-cli-spend" || exit 2
echo "[ok] step 3: OLD CLI spend at the floor fee APPLIED before activation ($coin0 -> $coin1)"

# ── 4. the vote ─────────────────────────────────────────────────────
t=$(tip_of 1)
EFF=$(( t + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $t — node1 proposes GAS_PRICE_RAW_PER_UNIT=$PRICE effective=$EFF"
propose "$NEW_CLI" 1 1 "$PRICE" "$EFF" "$LOGD/propose_price.log"
wait_cc_row 1 "$EFF" "$PRICE" $(seq 1 "$N")
stagef_cmt_diff_at_floor "post-vote" || exit 2

# ── 4b. R3-F3 / D1 — the rule is OFF between the vote and H ─────────
# The row is committed, the price is P, but get_u64 answers the row only
# at heights >= its effective_block, so a floor-fee spend of the SAME
# OLD-CLI shape 5a will see refused must still be ADMITTED and APPLIED at
# a height < EFF. Without this, a build that switched the rule on at the
# vote's commit would pass: every later pump pays REQ. "Applied" = its
# created utxo_set row exists — a refused item leaves no effect at all
# (HEAD nodus_witness_v2_apply.c cmt_item_failed: savepoint rolled back),
# so the row exists only for result code 0; its OWN block_height column
# says where it landed. The wait is height-bounded to the window: rc 2
# once the tip passes EFF - 1 without the row.
w_log="$LOGD/old_cli_in_window.log"
L=$(tip_of 1)
echo "[info] window: row landed, node1 tip $L, effective $EFF — $(( EFF - L )) height(s) of rule-off left"
[ $(( EFF - L )) -ge 3 ] || die \
    "R3-F3: the window [landing tip $L, effective $EFF) is too short for a spend to be admitted at tip+1 < $EFF and land before $EFF — the vote landed too late; not skipped"
spend "$OLD_CLI" "$USER_KEYS" 1 "$w_log" || { cat "$w_log" >&2; die "R3-F3: the OLD CLI's floor-fee spend was REFUSED at tip $(tip_of 1) < $EFF — the rule is ON before its effective height (D1 broken)"; }
cat "$w_log"
w_intent=$(spend_intent "$w_log"); w_fee=$(spend_field "$w_log" fee); w_units=$(spend_field "$w_log" units)
[ "${#w_intent}" = 128 ] || die "R3-F3: the in-window spend printed no intent_id"
[ "$w_fee" = "$FLOOR_FEE" ] || die "R3-F3: the in-window spend built fee $w_fee, not the floor"
[ $(( w_units * PRICE )) -gt "$w_fee" ] || die "R3-F3: $w_units x $PRICE does not exceed $w_fee — this spend would not underpay at H, so it proves nothing about the window"
w_h=$(stagef_cmt_wait_row "$(db_of 1)" \
    "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$w_intent';" 3 $(( EFF - 1 - L ))) && w_rc=0 || w_rc=$?
case "$w_rc" in
    0) ;;
    1) die "R3-F3: chain STALLED waiting for the in-window spend (tip $w_h)" ;;
    *) die "R3-F3: the in-window spend did not land before $EFF (tip $w_h, submitted at tip $L) — admitted but not applied inside the rule-off window" ;;
esac
w_bh=$(sqlite3 "$(db_of 1)" "SELECT block_height FROM utxo_set WHERE lower(hex(tx_hash)) = '$w_intent';")
case "$w_bh" in ''|*[!0-9]*) die "R3-F3: unreadable block_height for the in-window spend";; esac
[ "$w_bh" -lt "$EFF" ] || die "R3-F3: the in-window spend landed at $w_bh >= $EFF"
echo "[ok] 4b/D1: an OLD-CLI floor-fee spend ($w_units units x $PRICE = $(( w_units * PRICE )) > $w_fee) was APPLIED at height $w_bh < effective $EFF (window opened at tip $L) — the rule is OFF until H"

# ── 5. reach the effective height on every node ─────────────────────
pump_to 1 "$EFF" "$REQ"
for n in $(seq 1 "$N"); do
    stagef_cmt_wait_height "$(db_of "$n")" "$EFF" 3 >/dev/null || die "node$n never reached the effective height $EFF"
done
echo "[ok] every node's tip >= $EFF — CheckTx now judges at >= $(( EFF + 1 ))"

# 5a. the OLD CLI's floor-fee spend is refused at CheckTx
a_log="$LOGD/old_cli_post_activation.log"
a_coin=$(largest_coin "$(db_of 1)" "$(fp_of "$USER_KEYS")")
a_rc=0
spend "$OLD_CLI" "$USER_KEYS" 1 "$a_log" || a_rc=$?
cat "$a_log"
a_tip=$(tip_of 1)
a_intent=$(spend_intent "$a_log"); a_fee=$(spend_field "$a_log" fee); a_units=$(spend_field "$a_log" units)
[ "${#a_intent}" = 128 ] || die "5a: the OLD CLI printed no intent_id (it failed before building — see $a_log)"
[ "$a_fee" = "$FLOOR_FEE" ] || die "5a: the OLD CLI built fee $a_fee, not the floor"
[ $(( a_units * PRICE )) -gt "$a_fee" ] || die "5a: $a_units units x $PRICE does not exceed the fee $a_fee — this spend does not underpay"
[ "$a_rc" != 0 ] || die "5a: the OLD CLI's underpaying spend was ADMITTED after activation (G1 broken)"
a_out=$(cat "$a_log")
[[ "$a_out" == *"dnac_spend RPC failed (rc=7)"* ]] \
    || die "5a: the OLD CLI failed (rc $a_rc) but not with a CheckTx refusal (rc=7) — see $a_log"
echo "[ok] 5a: OLD CLI floor-fee spend REFUSED at CheckTx (rc=7) — $a_units units x $PRICE = $(( a_units * PRICE )) > $a_fee"
stagef_sentinel TARGET_REACHED

# 5b. the NEW CLI pays units x P and is applied
b_log="$LOGD/new_cli_post_activation.log"
b_coin=$(largest_coin "$(db_of 1)" "$(fp_of "$NEWSPENDER_KEYS")")
spend "$NEW_CLI" "$NEWSPENDER_KEYS" 1 "$b_log" || { cat "$b_log" >&2; die "5b: the NEW CLI's spend was refused after activation"; }
cat "$b_log"
b_intent=$(spend_intent "$b_log"); b_fee=$(spend_field "$b_log" fee); b_units=$(spend_field "$b_log" units)
[ "${#b_intent}" = 128 ] || die "5b: no intent_id"
[ "$b_fee" = $(( b_units * PRICE )) ] || die "5b: the NEW CLI built fee $b_fee, expected $b_units x $PRICE = $(( b_units * PRICE ))"
wait_applied 1 "$b_intent" >/dev/null
b_new=$(sqlite3 "$(db_of 1)" "SELECT amount FROM utxo_set WHERE lower(hex(tx_hash)) = '$b_intent';")
[ $(( b_coin - b_new )) = $(( b_units * PRICE )) ] \
    || die "5b: the ledger charged $(( b_coin - b_new )), not $b_units x $PRICE = $(( b_units * PRICE ))"
echo "[ok] 5b: NEW CLI spend APPLIED paying $b_units x $PRICE = $b_fee raw (ledger: $b_coin -> $b_new)"

# 5c. G3 — a SYSTEM-only governance envelope (fee 0) still lands.
#     A different proposer (node 2) than step 4: the per-proposer rate
#     limit keys on the proposer, so this vote does not depend on how
#     long ago step 4's was.
t=$(tip_of 2)
EFF2=$(( t + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
[ "$EFF2" -gt "$EFF" ] || die "arithmetic: second effective $EFF2 not after $EFF"
echo "[ok] tip $t — node2 proposes GAS_PRICE_RAW_PER_UNIT=0 effective=$EFF2 (fee 0, price $PRICE active)"
propose "$NEW_CLI" 2 2 0 "$EFF2" "$LOGD/propose_zero.log"
wait_cc_row 2 "$EFF2" 0 $(seq 1 "$N")
echo "[ok] 5c/G3: a fee-0 governance envelope landed while the price rule was ON"

# 5a, the ledger half: the refused spend never landed, its coin untouched.
now=$(tip_of 1)
[ $(( now - a_tip )) -ge 3 ] || pump_to 1 $(( a_tip + 3 )) "$REQ"
[ "$(sqlite3 "$(db_of 1)" "SELECT COUNT(*) FROM utxo_set WHERE lower(hex(tx_hash)) = '$a_intent';")" = 0 ] \
    || die "5a: the REFUSED spend ${a_intent:0:16}... has a utxo_set row — it landed"
[ "$(sqlite3 "$(db_of 1)" "SELECT COUNT(*) FROM utxo_set WHERE owner = '$(fp_of "$USER_KEYS")'
        AND token_id = zeroblob(64) AND amount = $a_coin;")" -ge 1 ] \
    || die "5a: v2user's coin ($a_coin) is gone — something spent it"
echo "[ok] 5a (ledger): $(( $(tip_of 1) - a_tip )) heights later the refused spend has no row and v2user's coin $a_coin is untouched"

stagef_sentinel ASSERT_RUN
stagef_cmt_diff_at_floor "post-hf1-activation" || exit 2
stagef_sentinel PASS
echo ""
echo "[PASS] HF-1 wipeless upgrade: 7 nodes moved OLD -> NEW one at a time with 7/7"
echo "       agreement after every step; the OLD CLI's floor-fee spend applied before"
echo "       and was refused at CheckTx after GAS_PRICE_RAW_PER_UNIT=$PRICE took effect at"
echo "       $EFF; the NEW CLI's spend paid $b_units x $PRICE and applied; a fee-0 governance"
echo "       vote still landed. Grace 15 (short build) — the LOGIC of the cutover only,"
echo "       nothing about the production grace 720."
