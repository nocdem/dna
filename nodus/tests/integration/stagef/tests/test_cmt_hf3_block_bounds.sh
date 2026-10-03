#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_hf3_block_bounds.sh — HF-3, the third height-activated hard
# fork: a WIPELESS rolling upgrade from the live (HF-2-active) binary to
# HF-3, then a vote that switches the block bounds to the cometbft
# consensus params only (standalone — NOT in the sweep)
# ════════════════════════════════════════════════════════════════════
#
# Governing records: docs/plans/2026-10-01-hf3-comet-block-bounds-design.md
# rev 3 (§0 rules 1-8, §1 test plan "Harness"); docs/plans/decisions/
# 2026-10-01-hf3-comet-only-block-bounds.md (APPROVED 2026-10-02; answers
# 6-11); docs/plans/decisions/2026-09-26-hard-fork-lagging-node.md (every
# node on the new binary BEFORE the vote); the HF-2 precedent
# test_cmt_hf2_gov_power.sh (this script's helpers are copied from it,
# unchanged unless noted).
#
# WHAT THIS SCENARIO IS — AND IS NOT
#   The capacity LIFT itself (more than 2 MiB / more than 255 envelopes in
#   one block at H, refused at H-1) is proven at UNIT level — test_v2_apply
#   test_hf3_engine and test_cmt_app t_hf3_bounds_and_fee — never here. A
#   per-block envelope count on one box is a wall-clock race (design §1
#   test plan, R4-2: the max ever seen was 152 envelopes per block), so
#   asserting a count here would be flaky or tuned until green. This
#   scenario proves the ACTIVATION: old -> new rolling with HF-2 already
#   active (the live chain's state), the param-8 vote, the crossing of H,
#   and that all 7 nodes agree on every block across it. Block size is
#   REPORTED (per-height applied-item counts), never asserted.
#
# WHAT IT PROVES — each item would be false if it failed
#   0. Version gate (FAIL, not skip): OLD knows HF2_ACTIVE and does NOT
#      know HF3_ACTIVE; NEW knows HF3_ACTIVE; each pair's server and CLI
#      banners agree; NEW's banner != OLD's.
#   1. A chain started on OLD commits and 7/7 agree.
#   2. HF-2 is made ACTIVE on the OLD fleet first (param 7 = 1 voted with
#      the OLD CLI, its row identical on 7/7, every node past its
#      effective height) — the live chain's state (param 7 active from
#      1500, read 2026-10-02, design §1 test plan).
#   3. Rolling upgrade (runbook §2.2 order): nodes 1..7 stopped ONE AT A
#      TIME (SIGTERM) and restarted on NEW with the SAME data dir,
#      identity and ports; after EVERY step the node is back in its
#      COMETBFT role, completed a NEW ABCI handshake on the SAME chain
#      file, the chain advanced >= 2 heights with REAL spends carried by
#      the mixed fleet, and 7/7 agree on global_root + block_id. With no
#      param-8 row an OLD and a NEW binary must decide every block
#      identically (design D3).
#   4. The HF3_ACTIVE vote (param 8, value 1) cast with the NEW CLI's
#      online `chain-config propose` at effective H lands a
#      chain_config_history row byte-identical on 7/7, committed < H.
#   5. The chain crosses H: every node's tip reaches H + 3 with real
#      spends, and 7/7 agree on global_root + block_id at the floor
#      before H, at a floor >= H, and at the end.
#   6. REPORTED (not asserted): the applied envelope count per height
#      below and from H (v2_tx_index), max and total.
#
# WHAT IT REQUIRES
#   Compile flags — TWO short-epoch + short-grace builds, nodus-server AND
#   nodus-cli from the SAME tree each (the HF-2 scenario's flag set; HF-3
#   reads no epoch quantity — the epoch flags are there because the design
#   names the short-epoch build and the two builds must agree, or NEW's
#   open of OLD's chain fails for an unrelated reason):
#     -DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#   (param 7 and param 8 are both ERGONOMIC.) OLD = the live binary at
#   build time (2026-10-02: Nodus Server v0.23.8 on EU-1 and EU-2,
#   59ea5733 — RE-CHECK on build day, design §1); NEW = the HF-3 tree WITH
#   its merge-time version bump (see VERSION GATE).
#   Environment:
#     exported BEFORE stagef_up_v2.sh (hashed into the genesis document):
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
#     git -C /opt/dna worktree add <OLD_TREE> <the live commit, 59ea5733 on 2026-10-02>
#     cmake -S <OLD_TREE>/nodus -B <OLD_TREE>/nodus/build-hf3 -DCMAKE_C_FLAGS="$F"
#     make -C <OLD_TREE>/nodus/build-hf3 -j"$(nproc)" nodus-server nodus-cli
#     # NEW_TREE = the HF-3 tree after the merge-time NODUS_VERSION bump
#     cmake -S <NEW_TREE>/nodus -B <NEW_TREE>/nodus/build-hf3 -DCMAKE_C_FLAGS="$F"
#     make -C <NEW_TREE>/nodus/build-hf3 -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN_OLD=<OLD_TREE>/nodus/build-hf3/nodus-server
#     export STAGEF_NODUSCLI_BIN_OLD=<OLD_TREE>/nodus/build-hf3/nodus-cli
#     export STAGEF_NODUS_BIN_NEW=<NEW_TREE>/nodus/build-hf3/nodus-server
#     export STAGEF_NODUSCLI_BIN_NEW=<NEW_TREE>/nodus/build-hf3/nodus-cli
#     export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     S=/opt/dna/nodus/tests/integration/stagef
#     STAGEF_NODUS_BIN=$STAGEF_NODUS_BIN_OLD STAGEF_NODUSCLI_BIN=$STAGEF_NODUSCLI_BIN_OLD \
#         bash $S/stagef_up_v2.sh
#     bash $S/tests/test_cmt_hf3_block_bounds.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   SKIP (rc 99): a binary missing / not executable, OLD and NEW servers
#   byte-identical, STAGEF_EPOCH_LENGTH != 15, a grace variable != 15, not
#   a Comet cluster. A skip is not a pass.
#
#   VERSION GATE — the HF-2 scenario's gate, re-aimed at HF-3:
#   (i) each pair's server and CLI banners agree ("Nodus Server v…" /
#   "Nodus CLI v…" from `-h`); (ii) NEW's banner != OLD's — a NEW built
#   from a tree WITHOUT the merge-time bump FAILS here by construction;
#   (iii) name-table probes against a port nothing listens on: OLD's CLI
#   must reach "client_connect failed" with --param HF2_ACTIVE (OLD is a
#   post-HF-2 build, needed for step 2) and must print "Unknown param
#   name: HF3_ACTIVE" with --param HF3_ACTIVE (OLD is pre-HF-3); NEW's CLI
#   must reach "client_connect failed" with --param HF3_ACTIVE. All exit
#   1, so the TEXTS are asserted, not the codes. (iv) every node's log
#   shows "Nodus v<OLD> running" at the start and "Nodus v<NEW> running"
#   after its upgrade. The script RUNS each binary once with `-h` and each
#   CLI for the probes (random in-memory identity, no disk writes, no
#   server reached).
#
# WHAT IT LEAVES BEHIND
#   All 7 nodes on NEW under new pids (appended to pids.txt; every
#   nodus.log appended, holding both runs). HF-2 ACTIVE from H2 and HF-3
#   ACTIVE from H on this chain (both one-way — no vote turns either off).
#   Two chain_config_history rows: param 7 = 1 at H2, param 8 = 1 at H.
#   Node 3's genesis leaf claimed (its coin shrinks by one fee per pump
#   step, into the reward pool). $BASE_DIR/hf3/ (every CLI log). The
#   chain several epochs further on. Nothing wiped. Tear down with
#   stagef_down.sh before re-running (the leaf is single-use).
#
# HOW IT CAN LIE
#   - **The capacity lift is NOT exercised here.** The pump keeps one
#     spend in flight, so every block carries at most a few envelopes —
#     far below both 255 and 2 MiB, on both sides of H. A green here says
#     the switch activates without splitting the fleet; the larger-block
#     behaviour is proven only by the unit tests named above (and the
#     pre-vote measurements — FinalizeBlock at ~3 000 envelopes, fsync +
#     PrepareProposal at 336 parts — design §2 / decision answer 11, which
#     this script does NOT perform).
#   - **The proposal fee check and rule 5 are NOT exercised here**: every
#     spend the pump sends pays the price and declares a small ceiling, so
#     neither can refuse anything. Their proofs are the unit tests.
#   - **D3 (identical blocks across the mixed fleet)** is proven only for
#     what the mixed fleet carried: idle blocks and 1-in/1-out CORE
#     SPENDs. The param-8 vote runs on 7/7 NEW (the lagging-node record:
#     an OLD node diverges at the vote block, so this script never votes
#     with one on OLD — the HF-1 scenario's negative arm covers that
#     shape for param 5).
#   - **The OLD CLI casts the param-7 vote** (step 2). If OLD is not the
#     live binary (re-check on build day), step 2 proves HF-2 activation
#     for THAT build, not for the live one.
#   - **Block size is REPORTED from v2_tx_index** (APPLIED envelopes per
#     height) — refused items and claims are not counted; nothing is
#     asserted on it.
#   - **The version gate trusts NODUS_VERSION_STRING + the CLI name
#     table.** A HF-3 tree with the bump reverted FAILS (ii); a pre-HF-3
#     tree bumped by hand FAILS (iii). The byte-difference SKIP and the
#     /proc/<pid>/exe check are path/byte based.
#   - Heights are driven by REAL spends (node 3's leaf, NEW CLI, its own
#     priced default fee), one in flight, each confirmed by its created
#     utxo_set row; every wait is progress- and height-bounded.
#   - rc 99 = SKIP, coverage that did not happen.
#   - E = 15, grace 15/15, BPY 20: this proves the LOGIC of the cutover at
#     those constants — NOTHING about the production epoch 720 / grace
#     720 / 17 280.
#   - Wall time is NOT measured (JUDGMENT: two rolling waves of pumped
#     blocks, tens of minutes on a 4-CPU machine).
#   - Written against the source; NOT yet run (written by the HF-3
#     builder, 2026-10-02 — the first run is the ORCHESTRATOR's).
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"
# Split S3/S6: upgrades EVERY node by restarting it as one nodus-server
# process (OLD/NEW binary pair) — SKIP (99) in every split mode (splitw,
# mixedw, splits, mixeds, split, mixed): split upgrade pairs are deferred
# (decision 2026-10-01-nodus-component-split.md item 23).
stagef_split_skip_if $(seq 1 "$STAGEF_COMMITTEE_SIZE")

die() { echo "[FAIL] $*" >&2; exit 1; }

OLD_SRV="${STAGEF_NODUS_BIN_OLD:-}"
OLD_CLI="${STAGEF_NODUSCLI_BIN_OLD:-}"
NEW_SRV="${STAGEF_NODUS_BIN_NEW:-}"
NEW_CLI="${STAGEF_NODUSCLI_BIN_NEW:-}"
PARAM_HF2=7                # DNAC_CFG_HF2_ACTIVE (dnac.h), value exactly 1
PARAM_HF3=8                # DNAC_CFG_HF3_ACTIVE (dnac.h), value exactly 1
GRACE_MARGIN=5             # same +5 margin test_cmt_hf2_gov_power.sh uses
E_REQ=15                   # the epoch length the builds carry
CONF="$BASE_DIR/v2_genesis.conf"
LOGD="$BASE_DIR/hf3"
N="$STAGEF_COMMITTEE_SIZE"

# ── SKIP gates (rc 99 — a skip is not a pass) ───────────────────────
for pair in "STAGEF_NODUS_BIN_OLD=$OLD_SRV" "STAGEF_NODUSCLI_BIN_OLD=$OLD_CLI" \
            "STAGEF_NODUS_BIN_NEW=$NEW_SRV" "STAGEF_NODUSCLI_BIN_NEW=$NEW_CLI"; do
    name="${pair%%=*}"; bin="${pair#*=}"
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        echo "[SKIP] $name is unset or not executable ('$bin') — this scenario needs"
        echo "       an OLD (the live, HF-2 binary) and a NEW (HF-3) short-epoch build; see the header"
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
    "NEW reports the SAME version as OLD ($NEW_VER) — build NEW from the HF-3 tree WITH its merge-time NODUS_VERSION bump (header, VERSION GATE (ii))"

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
probe() {                  # CLI PARAM -> the CLI's combined output (rc ignored: 1 either way)
    timeout 60 "$1" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose \
        --param "$2" --value 1 --effective 1 2>&1 || true
}
old_hf2=$(probe "$OLD_CLI" HF2_ACTIVE)
old_hf3=$(probe "$OLD_CLI" HF3_ACTIVE)
new_hf3=$(probe "$NEW_CLI" HF3_ACTIVE)
[[ "$old_hf2" != *"Unknown param name"* && "$old_hf2" == *"client_connect failed"* ]] || {
    printf '%s\n' "$old_hf2" >&2
    die "the OLD CLI does not know HF2_ACTIVE — OLD is not a post-HF-2 build (step 2 needs one)"; }
[[ "$old_hf3" == *"Unknown param name: HF3_ACTIVE"* ]] || {
    printf '%s\n' "$old_hf3" >&2
    die "the OLD CLI's name table ACCEPTED HF3_ACTIVE — OLD is not a pre-HF-3 build"; }
[[ "$new_hf3" != *"Unknown param name"* && "$new_hf3" == *"client_connect failed"* ]] || {
    printf '%s\n' "$new_hf3" >&2
    die "the NEW CLI did not pass HF3_ACTIVE through its name table to the connect step — NEW is not an HF-3 build"; }
echo "[ok] version gate: OLD $OLD_VER knows HF2_ACTIVE and refuses HF3_ACTIVE by name, NEW $NEW_VER knows HF3_ACTIVE (probe port $PROBE_PORT, nothing reached)"

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

# ── script-local helpers (test_cmt_hf2_gov_power.sh's, unchanged) ────
db_of()  { stagef_node_chain_db "$1"; }
tip_of() { stagef_cmt_tip "$(db_of "$1")"; }
fp_of()  { cat "$1/nodus.fp"; }                 # $1 = identity dir
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

wait_all() {
    local n
    for n in $(seq 1 "$N"); do
        stagef_cmt_wait_height "$(db_of "$n")" "$1" 3 >/dev/null \
            || die "node$n never reached height $1"
    done
}

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

# propose CLI NAME EFFECTIVE LOG — the online `chain-config propose` from
# node 1's identity; FAIL unless it reports acceptance.
propose() {
    local cli="$1" name="$2" eff="$3" log="$4" prc=0
    "$cli" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" -i "$(node_keys 1)" \
        chain-config propose --param "$name" --value 1 --effective "$eff" > "$log" 2>&1 || prc=$?
    cat "$log"
    [ "$prc" = 0 ] || die "chain-config propose $name exited $prc (see $log)"
    grep -q "proposal accepted" "$log" || die "propose $name did not report acceptance (see $log)"
}

# report_sizes FROM TO LABEL — REPORTED, never asserted: the APPLIED
# envelope count per height on node 1 (v2_tx_index rows), max and total.
report_sizes() {
    local from="$1" to="$2" label="$3" line
    line=$(sqlite3 "$(db_of 1)" \
        "SELECT COALESCE(MAX(c),0) || ' ' || COALESCE(SUM(c),0) || ' ' || COUNT(*)
           FROM (SELECT global_height, COUNT(*) AS c FROM v2_tx_index
                  WHERE global_height BETWEEN $from AND $to GROUP BY global_height);" \
        2>/dev/null || echo "? ? ?")
    echo "[info] REPORTED ($label, heights $from..$to): max applied envelopes per block / total / non-empty blocks = $line"
}

# ── 0. preconditions: fresh cluster, every node on the OLD binary ───
for n in $(seq 1 "$N"); do
    node_runs "$n" "$OLD_SRV" || die \
        "node$n is not running STAGEF_NODUS_BIN_OLD ($(readlink -f "$OLD_SRV")) — bring the cluster up with STAGEF_NODUS_BIN=\$STAGEF_NODUS_BIN_OLD (header)"
    grep -q "Nodus v$OLD_VER running" "$(stagef_node_dir "$n")/nodus.log" \
        || die "node$n's log has no 'Nodus v$OLD_VER running' line — it was not started from the OLD build"
done
for p in "$PARAM_HF2" "$PARAM_HF3"; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $p;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1 already holds a param-$p row — this scenario needs a fresh bring-up"
done
stagef_sentinel SETUP_OK
echo "[ok] 7/7 nodes run the OLD binary $(readlink -f "$OLD_SRV")"
echo "     NEW binary: $(readlink -f "$NEW_SRV")"

# ── 1. the OLD chain commits and agrees; fund the pump ──────────────
stagef_cmt_diff_at_floor "on-OLD" || exit 2
claim_leaf "$OLD_CLI" "$PUMP_KEYS" 1
t=$(tip_of 1)
pump_to 1 $(( t + 2 ))
stagef_cmt_diff_at_floor "OLD-chain-committing" || exit 2

# ── 2. HF-2 ACTIVE on the OLD fleet (the live chain's state) ────────
T_V2=$(tip_of 1)
H2=$(( T_V2 + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $T_V2 — node1 proposes HF2_ACTIVE=1 effective H2=$H2 with the OLD CLI"
propose "$OLD_CLI" HF2_ACTIVE "$H2" "$LOGD/propose_hf2.log"
wait_cc_row "$PARAM_HF2" "$H2" 1 20
R_V2="$CC_CB"
[ "$R_V2" -lt "$H2" ] || die "the HF2 row committed at $R_V2, not before its effective height $H2"
pump_to 1 $(( H2 + 1 ))
wait_all $(( H2 + 1 ))
stagef_cmt_diff_at_floor "OLD-past-HF2" || exit 2
echo "[ok] HF-2 is ACTIVE on the OLD fleet from H2=$H2 (row committed at $R_V2), 7/7 agree past it"

# ── 3. rolling upgrade, 7/7 after every step ────────────────────────
for k in $(seq 1 "$N"); do upgrade_node "$k"; done
for n in $(seq 1 "$N"); do node_runs "$n" "$NEW_SRV" || die "node$n is not on NEW after the rolling upgrade"; done
H_UPGRADED=$(tip_of 1)
echo "[ok] all 7 nodes upgraded one at a time with no wipe; 7/7 agreed after every step (tip $H_UPGRADED)"

# ── 4. the HF3_ACTIVE vote on 7/7 NEW ───────────────────────────────
T_VOTE=$(tip_of 1)
H=$(( T_VOTE + 1 + STAGEF_CC_GRACE_ERGONOMIC + GRACE_MARGIN ))
echo "[ok] tip $T_VOTE — node1 proposes HF3_ACTIVE=1 effective H=$H with the NEW CLI"
propose "$NEW_CLI" HF3_ACTIVE "$H" "$LOGD/propose_hf3.log"
wait_cc_row "$PARAM_HF3" "$H" 1 20
R_VOTE="$CC_CB"
[ "$R_VOTE" -lt "$H" ] || die "the HF3 row committed at $R_VOTE, not before its effective height $H"
stagef_cmt_diff_at_floor "post-hf3-vote" || exit 2

# ── 5. cross H ──────────────────────────────────────────────────────
pump_to 1 $(( H - 1 ))
wait_all $(( H - 1 ))
stagef_cmt_diff_at_floor "pre-H" || exit 2
F_PRE=$(floor_of $(seq 1 "$N"))
[ "$F_PRE" -lt "$H" ] || echo "[info] the pre-H comparison floor $F_PRE is already >= H (the fleet moved on during the wait)"
pump_to 1 $(( H + 3 ))
wait_all $(( H + 3 ))
stagef_sentinel TARGET_REACHED
stagef_cmt_diff_at_floor "post-H" || exit 2
F_POST=$(floor_of $(seq 1 "$N"))
[ "$F_POST" -ge "$H" ] || die "the post-H comparison floor $F_POST is below H=$H"
echo "[ok] every node's tip >= H + 3 = $(( H + 3 )); 7/7 agree at floor $F_POST >= H"

# ── 6. REPORTED, not asserted ───────────────────────────────────────
report_sizes 1 $(( H - 1 )) "below H"
report_sizes "$H" "$(tip_of 1)" "from H"

stagef_sentinel ASSERT_RUN
stagef_cmt_diff_at_floor "post-hf3" || exit 2
stagef_sentinel PASS
echo ""
echo "[info] HEIGHTS: HF2 vote tip $T_V2, row commit $R_V2, H2=$H2 | upgraded-by $H_UPGRADED"
echo "       | HF3 vote tip $T_VOTE, row commit $R_VOTE, H=$H | floors pre-H $F_PRE, post-H $F_POST"
echo "[PASS] HF-3: HF-2 activated on OLD ($OLD_VER), 7 nodes rolled OLD -> NEW ($NEW_VER) one at a"
echo "       time with 7/7 agreement after every step; HF3_ACTIVE voted at H=$H and crossed with"
echo "       7/7 agreement. E=15 / grace 15 — the LOGIC of the cutover only; the capacity lift,"
echo "       the proposal fee check and rule 5 are proven by unit tests, not here."
