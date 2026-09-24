# Genesis Protocol — Stage F Multi-Node Integration Harness

7-node localhost cluster for testing consensus-affecting changes
**before** production deploy. Catches block-identity / global-root
divergence bugs that single-node unit tests miss.

Mandatory per `MEMORY/feedback_genesis_protocol.md` before ANY
witness / consensus / Merkle / fee / validator / chain_config ship, and
before any chain-wipe deploy.

## Quick start

```bash
# Build prerequisites
cd /opt/dna/nodus/build     && make -j$(nproc)
cd /opt/dna/messenger/build && make -j$(nproc)   # dna-connect-cli (libdna)

# The ONE runner — the cometbft lane at production constants
bash /opt/dna/nodus/tests/integration/stagef/genesis_protocol_v2.sh

# The epoch-boundary scenario needs a SHORT-EPOCH build (it SKIPS at the
# shipped 720 — a skip is not a pass); see "Environment" below.
cmake -S nodus -B nodus/build-shortepoch \
      -DCMAKE_C_FLAGS="-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 \
                       -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 \
                       -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15"
make -C nodus/build-shortepoch -j"$(nproc)" nodus-server nodus-cli
export STAGEF_NODUS_BIN=$PWD/nodus/build-shortepoch/nodus-server
export STAGEF_NODUSCLI_BIN=$PWD/nodus/build-shortepoch/nodus-cli
export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
# tokenomics-v3 P2: test_v2_rewards.sh needs a payday within reach —
# written into the genesis document at bring-up (production: 24).
export STAGEF_PAYOUT_INTERVAL_EPOCHS=2
bash /opt/dna/nodus/tests/integration/stagef/genesis_protocol_v2.sh
```

**R3 W4 (2026-09-17) — THERE IS ONE LANE.** The legacy consensus lane
(the pre-Comet PBFT round, its sync, bootstrap discovery, mempool and
certificates) is DELETED from the tree, not merely closed — OBLIGATION
`atlas-dec-71525f3b4918f710b660707ac6bb5a3a`, D-17 rev 10 (9). With it
went the legacy runner (`genesis_protocol.sh`), the legacy bring-up
(`stagef_up.sh`, the genesis TRANSACTION), the 23 legacy scenarios and
the legacy leader-derivation helpers in `stagef_env.sh`. `nodus-server`
opens ONLY a version-3 (cometbft) chain: the witness's post-open gate
refuses everything else, fail closed, logged (`nodus_witness.c`
`witness_post_open_gate`). **Read "What flips on the Comet lane" before
anything else in this file** — four rules every scenario in the old
suite relied on are false on the lane that runs.

Exit code 0 = green, 1 = any scenario FAIL. Full stdout of any
failing test is echoed unbounded — no tail, no grep, no filter.

## What flips on the Comet lane (R3 W3 package C2d)

Four standing rules this README relied on for every scenario before
this wave. Read this before any Comet-lane scenario's own header.

1. **"The chain has no idle block production" → FALSE.** D-4 rev 3
   (governing this build's Comet consensus config) sets
   `CreateEmptyBlocks=true` and `CreateEmptyBlocksInterval=60 000 ms`
   (`nodus_witness_cmt_node.c:1699-1700`, overriding the library's own
   0 ms / on-demand-only default at `shared/dnac/cmt_config.h:121-122`).
   Height deltas are **no longer 1 per transaction**: a block carries
   whatever the mempool held at `PrepareProposal`, which can be zero,
   one, or (see rule 4) several. `test_cmt_empty_blocks.sh` measures this
   directly.
   ⚠ **DELTA 1 (HISTORICAL — SUPERSEDED BY tokenomics-v3 P1). Before P1:
   MEASURED FACT — 60 s was an UPPER BOUND, not the observed pace.** Rule
   N attendance wrote the proposer's `last_signed_block` on EVERY block,
   so the global root changed at every height and cometbft's
   `needProofBlock` (state.go:1106-1129, `cmt_cs.c:1872`) was TRUE at
   every height in that build — every block was a proof block, arriving
   at the `timeout_commit` pace (5 000 ms), not the 60 000 ms interval:
   measured live, seven nodes committed at roughly one block per 6 s.
   **tokenomics-v3 P1 (D-4) retired both `last_signed_block` and
   `signed_blocks_this_epoch`** — attendance is now credited out-of-root
   into `v2_attendance` (keyed by voter_id, not a validator merkle-leaf
   field), so an EMPTY block no longer moves `system_state_root` and
   `needProofBlock` is FALSE on an idle chain. The 60 s figure is now the
   OBSERVED pace again, as D-4 rev 3 always specified —
   `test_cmt_empty_blocks.sh` asserts this directly (>= 2 consecutive
   idle gaps >= 45 s, at ~1 s polling) rather than merely using 60 s as a
   stall ceiling.

2. **"A dead leader on an idle chain never triggers a view change" →
   FALSE, and the whole SENTENCE stops meaning anything.** There is no
   P3 deadman, no `pending_forward_count` gate, no view counter and no
   single "leader" on this lane at all: cometbft's PROPOSER rotates by
   accumulated priority every height (a weighted round-robin that
   degenerates to exact round-robin when every validator holds equal
   stake, which this build's genesis gives all seven —
   `shared/dnac/cmt_validator_set.c:849-977`), and a round simply TIMES
   OUT and moves to the next proposer in priority order whether or not
   demand exists — because idle production means there is always
   "work" (an empty block) for the round to be about. The legacy
   leader-derivation helpers `stagef_env.sh` used to carry
   (`stagef_leader_entry` / `node_view` / `cluster_view_max` /
   `log_count`) derived a position out of the legacy
   `validator_set_snapshots` positional layout and read
   `pbft_state.current_view` — neither exists on this lane, and the
   helpers are DELETED with it (R3 W4). `test_cmt_dead_proposer.sh` is
   the replacement for the deleted `test_v2_view_change.sh` — see that
   script's own header for the pigeonhole argument that stands in for a
   leader derivation this lane has no positional data to support.

3. **"Submit returns the committed height" → FALSE.** `dnac_spend`
   answers the Comet mempool's CheckTx result AT ONCE — `status:
   APPROVED` means "accepted into the mempool", nothing about a
   committed block (D-23 rev 7 item 22,
   `nodus_witness_handlers.c` `handle_dnac_spend`, the `cmt_mem_check_tx`
   call at ~:1861 — and since R3 W4 that is the handler's ONLY lane: the
   legacy leader/forward path below it is deleted). Every scenario that used to
   assert "height +1 after my transaction" from the client's own answer
   now does three things instead: submit → assert `status == APPROVED`
   (the CLI's exit code already is this verdict) → poll the
   transaction's INCLUSION with a PROGRESS bound expressed in blocks
   (`stagef_cmt_wait_height`, stagef_env.sh), never in seconds → THEN
   compare block identity 7/7 at that height. Inclusion is read either
   from the node's own `v2_tx_index` row (envelopes only — a claim gets
   no such row; see item 4) or, where no query exists, through the
   transaction's LEDGER EFFECT (the UTXO or validator row it should have
   produced).
   ⚠ **DELTA 2 — MEASURED: "height +1" isn't even the right bound to poll
   toward.** CheckTx admission does not promise next-block inclusion
   either — a stake envelope was APPROVED at tip 2 and its row did not
   appear until tip 4 (a transaction arriving while the next round is
   already in flight lands in a LATER one). `stagef_cmt_wait_row`
   (`stagef_env.sh`) polls for the LEDGER EFFECT ITSELF, progress-bounded
   on the chain's own tip, and the caller then reads the row's OWN
   height — never `submission_tip + 1`.

4. **"N claims submitted -> N blocks" → FALSE, silently, unless read.**
   The pre-Comet lane's own measurement ("40 leaves -> 40 blocks,
   height 0 -> 40") assumed the client's submit CALL blocked until a
   block committed, so a sequential loop of submissions naturally
   produced one block per call. Rule 3 above removes that blocking, so
   a tight loop of submissions (what `v2-claim` over a leaf batch does)
   queues many transactions in the mempool before the next
   `PrepareProposal` fires, and `PrepareProposal` drains what fits
   under its bounds into ONE block — the byte budget (`Block.MaxBytes`
   22 020 096 — D-23 rev 9 item 24) and the apply engine's PER-CLASS
   ITEM CAPS (R3 W4 package C, replacing the short-epoch run's original
   flat `NODUS_V2_APPLY_MAX_OPS` = 16-items-of-either-class fix,
   register R3-W3-C2a-19): envelopes ≤ `NODUS_V2_ENV_BATCH_MAX` (3 209,
   a derived MEMORY ceiling since delta 2 — 64 MiB scratch budget /
   20 908 B per envelope; NOT the governance hard cap of 10 delta 1
   briefly tied it to),
   claims ≤ `NODUS_V2_APPLY_MAX_CLAIMS` (14 162, derived from cometbft's
   own `MaxBlockSizeBytes` — `nodus_witness_v2_apply.h`), packed from the
   head of the fee order. A batch of 40 pump leaves (all claims) therefore
   lands in ONE block again, not three and not forty separate ones —
   `test_cmt_claim_flood.sh` proves exactly that, over the WHOLE batch in
   one call. `test_cmt_mempool_flood.sh` measures the smaller-scale
   batching directly; `test_v2_epoch_boundary.sh`'s reachability check
   still does not count leaves, because by the time it runs the pump
   batch is ordinarily already spent (see that script's own header).

Chain identity is also affected, though it is not a behavioural flip:
the pin and the derived chain id are the 32-byte document hash (64 hex
chars) — D-24 rev 4 item 1 — and a version-3 chain has NO
`global_height = 0` row in `v2_blocks` (genesis is a stored DOCUMENT,
not a block; `initial_height` starts the real block sequence, and 0 vs
1 there are two DIFFERENT chain ids for the same effective start —
`nodus_v2_gen_config.c`'s own required-key message says so). Any script
still comparing a 128-hex pin or reading a height-0 row is reading
pre-Comet assumptions.

**⚠ THE CLI PRINT WAS WRONG ON THIS LANE — FIXED IN R3 W4-C DELTA 4,
PULLED FORWARD FROM THE "package W4-H" NOTE THIS WARNING USED TO CARRY.**
`nodus-cli.c`'s `t6_submit_on` (the shared submit path both `v2-envelope
stake` and `v2-claim` funnel through since delta 4's session-reuse
split) used to print `"...committed: height=... index=..."` from
receipt fields (`sres.block_height`, `sres.tx_index`) that are always
ZERO on this lane — the version-3 response carries only `status`
(`nodus_witness_handlers.c` `handle_dnac_spend`, the `cbor_encode_cstr(&enc,
"status")` answer after CheckTx), and `nodus_client_dnac_spend` `memset`s
the result struct to zero before decoding it (`nodus_client.c:2065-2076`),
so nothing ever overwrote those two fields. It now prints `"accepted:
mempool CheckTx approved (query dnac_tx for the eventual commit
height)"` instead — what the field actually answers, not a fabricated
commit position. **No Comet-lane scenario THIS RUNNER RUNS parses that
line for a height** (`test_v2_claim.sh`, `test_v2_stake.sh`,
`test_cmt_mempool_flood.sh` all say so in their own headers and use the
ledger's own tables instead — those headers still quote the OLD string
as the thing they deliberately don't parse; harmless, but now a stale
quote, out of this delta's whitelist to fix). **`test_v2_grow_7_20.sh`
is the one exception and IS newly broken by this**: it is not in this
runner and not converted to the Comet lane (own row below), but it
still `grep -q '^committed: height='`s three of its own log files as a
pass signal (`:248`, `:449`, `:469`) — that grep can no longer match.
Also outside this delta's whitelist; flagged here and in the register
for whoever next runs or converts it.

## `genesis_protocol_v2.sh` — the runner

Single entry point. Assertion method: **exit code only**.

| rc of a scenario | Meaning |
|---|---|
| 0  | PASS |
| 99 | SKIP — the scenario declined to run because a prerequisite is absent (`test_v2_epoch_boundary.sh` at the shipped epoch length). A 99 is **not** a pass: it means that coverage did not happen, and the runner says so in its result block. |
| else | FAIL (full stdout echoed, then the runner returns 1) |

Modes:

```bash
bash genesis_protocol_v2.sh              # full run: bring-up + scenarios + teardown
bash genesis_protocol_v2.sh --scenarios  # scenarios only; assumes a Comet cluster is already up
```

Phases:

1. **Phase 1** — tear down any previous run (`stagef_down.sh`).
2. **Phase 2** — `stagef_up_v2.sh`: the OFFLINE version-3 ceremony, 7 nodes,
   four anti-vacuity lines per node (role, startup table, LIVE, height ≥ 1),
   then one 7/7 comparison of the first block.
3. **Phase 3** — the fifteen Comet scenarios in the EXPLICIT order the script's
   own header gives (`test_cmt_empty_blocks.sh` first, `test_cmt_arena_runway.sh`
   last — see "Order matters on the Comet lane"). **It does not glob
   `tests/*.sh`**: the list is explicit, so a red run means a red scenario.
4. **Phase 4** — teardown on an all-green run; on ANY failure the processes
   are stopped and `$BASE_DIR` (logs, DBs, config) is KEPT and its path
   printed.

**Reachability sentinels (R3 W4 package H — the gap the previous version
of this paragraph recorded is CLOSED).** Every Comet scenario records three
marks through `stagef_sentinel` (files under `$BASE_DIR/sentinels/`, the
first mark truncating the file so repeated `--scenarios` runs start
clean): `SETUP_OK` once its preconditions hold (right after its skip
gate), `ASSERT_RUN` immediately before its terminal assertion (the final
`stagef_cmt_diff_at_floor "post-…"` comparison, or the latch scan in
`test_cmt_arena_runway.sh`), and `PASS` at its end. The runner reads them
back: an rc-0 scenario with `SETUP_OK` but no `ASSERT_RUN` is reported as
**FAIL (VACUOUS pass)** and an rc-0 scenario with no mark at all as **FAIL
(UNINSTRUMENTED)** — a new scenario does not count until it carries the
three marks. A green line prints its marks, e.g. `PASS  test_v2_claim.sh
[SETUP_OK ASSERT_RUN PASS ]`. RED-proven: a sweep with `test_cmt_arena_
runway.sh`'s `ASSERT_RUN` line deleted ends `FAIL … a VACUOUS pass` and
keeps `$BASE_DIR`. rc 99 (SKIP) is decided by the exit code alone, marks
or not. (`test_cmt_env_flood.sh` used to be the one scenario with no marks
— a permanent SKIP; since CLI-SPEND it runs and carries all of them, plus
`TARGET_REACHED` once its batch is CheckTx-approved.)

### Environment

> ### ⚠ THE ONE THING TO UNDERSTAND FIRST
>
> **An env var alone changes nothing.** Epoch length and the tokenomic
> year are **compile-time** properties of `nodus-server`. `STAGEF_*`
> variables only tell the *test scripts* what the binary was built with —
> set one without the matching `-D`, and the scenario either skips, or
> measures the wrong thing and reports a green that means nothing. Every
> row below names both halves; supply them together.
>
> **And export them BEFORE `stagef_up_v2.sh`.** The ceremony writes the
> values it is given into every node's genesis config once, at bring-up.

| Var | Default | Requires the binary built with | Purpose |
|---|---|---|---|
| `STAGEF_EPOCH_LENGTH` | **720** (`stagef_env.sh:60`) | `-DDNAC_EPOCH_LENGTH=<E>` | Blocks per epoch. Production is 720. Use 15 to make `test_v2_epoch_boundary.sh` reachable. **This value does NOT reach the server** — the ceremony writes it into the genesis config (`stagef_up_v2.sh`) and the scripts use it to compute the next boundary; the BINARY's own `DNAC_EPOCH_LENGTH` must agree, or the ceremony refuses the config ("this build cannot derive this config's chain"). |
| `STAGEF_BLOCKS_PER_YEAR` | 6307200 (`stagef_up_v2.sh:248`) | `-DDNAC_BLOCKS_PER_YEAR=<BY>` | Written into the genesis config; must match the binary for the same reason. Use 20 with the short-epoch build. |
| `STAGEF_DECIMAL_UNIT` | 100000000 (`stagef_up_v2.sh:249`) | `-DDNAC_DECIMAL_UNIT` | Written into the genesis config; the shipped value is the only one this project ships. |
| `STAGEF_CC_GRACE_SAFETY` / `STAGEF_CC_GRACE_ERGONOMIC` | 17280 / 720 (`stagef_env.sh:61-62`) | `-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS` / `_ERGONOMIC_BLOCKS` | Blocks a chain_config change must wait before taking effect. No Comet scenario proposes a chain_config change today (the governance signature-collection RPC is being re-wired onto the Comet lane — package W4-CC); the variables are kept for `test_v2_grow_7_20.sh` (not in the sweep) and for the coming scenario. |
| `STAGEF_V2_CANDIDATES` | 0 | — | Additionally mints N funded identities under `$BASE_DIR/cand1..N` for a growth scenario (`test_v2_grow_7_20.sh`, not in the sweep). |
| `STAGEF_V2_PUMP_LEAVES` | (script default) | — | Size of the PUMP leaf batch `test_cmt_claim_flood.sh` spends in one call (R3 W4 package C); `test_v2_epoch_boundary.sh` only submits whatever, if anything, is left. |
| `STAGEF_EPOCH_BOUNDARY_BUDGET_S` | 1800 | — | Wall-clock budget `test_v2_epoch_boundary.sh` uses to decide reachability (SKIP when the boundary cannot be reached inside it). Blocks needed × the per-block pace: `STAGEF_CMT_PUMP_BLOCK_S` when the CLI-SPEND pump is usable, the 60 s idle interval otherwise. |
| `STAGEF_PAYOUT_INTERVAL_EPOCHS` | **24** (`stagef_up_v2.sh`, the production value) | — (a genesis-document field, not a compile constant) | tokenomics-v3 P2-7: written into the genesis config as `payout_interval_epochs` — every Nth boundary is a PAYDAY that turns the accrual table into coins. Part of the HASHED genesis document, so it must be exported BEFORE `stagef_up_v2.sh` and every value is a different chain id. Use 2 (with the short-epoch build) to make `test_v2_rewards.sh` reachable; 1 is refused by that scenario (every boundary a payday — no accrual between paydays to observe). The bring-up also reserves `reward_pool_initial` = 200M × 10^8 (P2-1), added to `total_supply_raw`; no knob. |
| `STAGEF_RULE_N_RETIRE_BUDGET_S` | 5400 | — | Wall-clock budget `test_cmt_rule_n_retire.sh` (round 2) uses to decide reachability of THREE boundaries + settle from the current tip (SKIP when they cannot be reached inside it — always true at the shipped epoch length, pumped or idle). Same pace rule as the row above. |
| `STAGEF_PUMP_FUNDER_NODE` / `STAGEF_PUMP_SUBMIT_NODE` | 3 / 1 (`stagef_env.sh`, CLI-SPEND section) | — | The CLI-SPEND pump: whose genesis leaf funds the self-send SPENDs that drive height (node 3 — no scenario in the sweep claims node 1's or node 3's leaf), and which node's client port they are submitted to. The helper reads the CALLER's database (the scenario's reference node, node 1) to size each step while the CLI lists coins on the submit node, so keep the default SUBMIT = 1: a submit node lagging node 1 by a block would re-spend an already-spent coin and the step would fail as "dropped" (rc 2) — never a false pass. Read at source time; export before running a scenario to change them. |
| `STAGEF_ENV_FLOOD_MAX` | 40 (capped at 100) | — | Upper bound on how many envelopes `test_cmt_env_flood.sh` submits in its one batch (it uses min(this, the PUMP identity's spendable coins)). |
| `STAGEF_NODUS_BIN` / `STAGEF_NODUSCLI_BIN` / `STAGEF_DNACLI_BIN` | `nodus/build/...`, `messenger/build/cli/dna-connect-cli` | — | Point the harness at a differently-configured build (e.g. `nodus/build-shortepoch/`) without disturbing the default one. `STAGEF_DNACLI_BIN` must name a built `dna-connect-cli` (the messenger build), which a git worktree does not carry. |

Note the `-DCMAKE_C_FLAGS=` form: `DNAC_EPOCH_LENGTH` and
`DNAC_BLOCKS_PER_YEAR` are **compiler defines, not CMake options**.
Passing them as `-DDNAC_EPOCH_LENGTH=15` directly to `cmake` produces
only a "Manually-specified variables were not used" warning and a binary
carrying the production defaults.

## Layout

All runtime state under `/tmp/stagef-$TIMESTAMP/` — **fully isolated**
from production:

- `/tmp/stagef-*/node[1-7]/identity/` — fresh Dilithium5 identities,
  auto-generated by `nodus-server` on first run. NOT the production
  keys in `/var/lib/nodus/identity/`.
- `/tmp/stagef-*/node[1-7]/data/` — witness DB + nodus DB + logs.
- `/tmp/stagef-*/user/.dna/` — fresh dna wallet for the test
  operator. NOT punk's `~/.dna/`. Isolated via `HOME=...`.

## Port map

Each node uses a 10-port stride starting at 14000. Disjoint from
production (4000-4004) so both can run simultaneously.

| Node | UDP | TCP client | TCP peer | TCP chan | TCP witness |
|---|---|---|---|---|---|
| 1 | 14000 | 14001 | 14002 | 14003 | 14004 |
| 2 | 14010 | 14011 | 14012 | 14013 | 14014 |
| 3 | 14020 | 14021 | 14022 | 14023 | 14024 |
| 4 | 14030 | 14031 | 14032 | 14033 | 14034 |
| 5 | 14040 | 14041 | 14042 | 14043 | 14044 |
| 6 | 14050 | 14051 | 14052 | 14053 | 14054 |
| 7 | 14060 | 14061 | 14062 | 14063 | 14064 |

## Identity isolation

**NEVER reads or writes:**
- `/var/lib/nodus/*` (production witness / identity)
- `~/.dna/*` (punk's production wallet)
- ports 4000-4004 (production)


## Scripts

| Script | Purpose |
|---|---|
| `genesis_protocol_v2.sh` | The runner (above): `stagef_up_v2.sh` + fifteen explicit scenarios (round 2 adds `test_cmt_rule_n_retire.sh`, tokenomics-v3 P2 adds `test_v2_rewards.sh` before it) + teardown. `--scenarios` runs against an already-up cluster. Reports SKIPs separately and says in as many words that a skip is not a pass. **Leaf budget:** claim/stake consume single-use node/user leaves each; mempool_flood spends node 4/5/6/7's own leaves; `test_cmt_claim_flood.sh` (R3 W4 package C) is the only scenario that reaches for the PUMP batch, in one call; `test_v2_epoch_boundary.sh` runs after it and ordinarily finds nothing left. A second run against the SAME cluster fails on the leaf-spending scenarios — correctly. **CLI-SPEND:** `test_cmt_env_flood.sh` spends the PUMP identity's claimed coins (self-sends — it needs `test_cmt_claim_flood.sh` first and never claims the batch itself), and the height pump used by `test_v2_epoch_boundary.sh` / `test_cmt_rule_n_retire.sh` claims **node 3's** genesis leaf in its first pump step (`STAGEF_PUMP_FUNDER_NODE`) — a leaf nothing else in the list claims; a scenario that SKIPs claims nothing. **Phase 4:** a FAILED sweep stops the processes but keeps `$BASE_DIR` for inspection; only an all-green sweep tears down. |
| `stagef_up_v2.sh` | The version-3 (**cometbft**) ceremony: no transaction and no cluster. The generated config carries `config_version = 3`, one shared `genesis_time_ms` (UTC ms, computed ONCE and written into every node's identical copy — the chain id hashes the whole document) and `initial_height = 1`. Each node runs the OFFLINE one-shot `nodus-server --derive-v2-genesis` against that one shared file **before anything is listening**, and agreement is CHECKED (all 7 chain ids must be identical, 64 hex / 32 bytes) rather than negotiated. Then spawns the 7 and asserts, per node, bounded by ATTEMPTS not a bare sleep, **FOUR** anti-vacuity lines: `chain role: COMETBFT`, `cometbft startup table built`, `cometbft lane LIVE`, AND that its Comet tip reaches height 1 (`stagef_cmt_wait_height <db> 1 3`) — every node can show role+startup+LIVE and still never produce. Once all seven have their first block, ONE `stagef_cmt_diff_at_floor "bring-up"` proves the seven first blocks are identical BEFORE any scenario runs. A node that shows the role but never goes live, or never produces, is a FAIL. Writes `pids.txt`, the pointer file and `$BASE_DIR/v2_genesis.conf` / `v2_genesis_pin` (64 hex). **What it does NOT prove:** that the seven can commit a block together under demand — that is the scenario suite's job. A green bring-up is a green BIRTH, not a green Comet lane. |
| `stagef_down.sh` | Kill PIDs + rm -rf the run dir |
| `stagef_diff.sh` | Read `global_root` + `block_id` from each node's witness DB (`v2_blocks`), assert identical across the 7, print. `--expect-height N` additionally requires each node's OWN latest height to equal N. **`--at-height N`** compares the ROW AT height N instead of each node's current latest — necessary because CreateEmptyBlocks means the chain keeps committing on its own, so "each node's own latest" races that ongoing production (seven sequential reads spanning even a fraction of a second can catch one node one idle block ahead of another and misreport it as divergence). Every scenario calls this through `stagef_env.sh`'s `stagef_cmt_diff_at_floor` wrapper, never bare. The legacy `blocks`/`state_root` branch is gone (R3 W4). |
| `stagef_env.sh` | Sourced by other scripts; exports `BASE_DIR`, ports, pubkey file paths, `STAGEF_*` overrides, the `stagef_dna` / `stagef_user_*` wrappers, `stagef_wait_ready`, and the **Comet-lane section**: `STAGEF_CMT_EMPTY_INTERVAL_MS` / `STAGEF_CMT_TIMEOUT_COMMIT_MS` (the two D-4 timing overrides, read from their exact source lines rather than hand-copied); `stagef_cmt_tip`; `stagef_cmt_wait_height` (a progress-bounded wait — a stall is N consecutive empty-block intervals with NO height increase, never a bare wall-clock cap); `stagef_cmt_wait_row DB SQL [N] [MAX_HEIGHTS]` — waits for a ledger EFFECT (a `COUNT(*)`-shaped SQL expression) to appear, with the SAME stall bound as `stagef_cmt_wait_height` (the chain's tip, not the row, is what must keep moving) AND a second, independent `MAX_HEIGHTS` bound (default 20): the stall bound alone waits FOREVER against a chain that keeps healthily committing while the awaited row never appears (measured: 34 minutes) — exceeding `MAX_HEIGHTS` past the call's starting tip returns a THIRD outcome (rc=2, "dropped, not delayed") distinct from a stall (rc=1); `stagef_cmt_diff_at_floor` (the race-free `stagef_diff.sh` wrapper). **CLI-SPEND pump:** `stagef_cmt_pump_ready DB` (a PURE feasibility check — submits nothing; call it directly, never in `$(...)`, it sets `STAGEF_PUMP_READY`), `stagef_pump_claim DB` (claims the funder node's genesis leaf and waits for the claimed coin as a ledger effect — `stagef_cmt_pump_to`'s first step when the funder holds no coin above the fee, once per call), `stagef_cmt_pump_to DB TARGET [N]` (drives the tip to TARGET with `nodus-cli v2-envelope spend` self-sends of the funder's largest coin minus `STAGEF_PUMP_FEE_RAW` — one input, one output, no dust — ONE in flight, each confirmed by its created `utxo_set` row via `stagef_cmt_wait_row` before the next; rc 0 reached / 1 stall / 2 dropped / 3 pump fault, never retried), `stagef_cmt_advance_to DB TARGET [N]` (the pump when ready, `stagef_cmt_wait_height` otherwise — what scenarios call), `STAGEF_CMT_PUMP_BLOCK_S` (15 s — a JUDGMENT per-block pace for SKIP budgets only, derived in the file, not measured). The legacy PBFT leader-derivation helpers (`stagef_leader_entry`, `running_nodes`, `node_view`, `cluster_view_max`, `log_count`, the `VSET_*` constants) are gone with the lane (R3 W4). A fault in this file breaks every scenario, not one. |


## Scenario tests (`tests/`)

Every script on disk is listed. **"Plain" means: a default `nodus/build`
binary and a freshly brought-up Comet cluster, nothing else.**

#### The Comet lane — needs a cluster from `stagef_up_v2.sh` (the only lane)

**These fifteen scenarios are the harness's entire coverage** (the list in
`genesis_protocol_v2.sh`; the count read "thirteen" before tokenomics-v3
P2 while the list already held fourteen). Read "What
flips on the Comet lane" near the top of this file FIRST: four standing
rules the deleted legacy suite relied on are false here.

Each exits **99 on a non-Comet cluster** rather than pretending to have
tested a Comet property. `genesis_protocol_v2.sh`'s order is EXPLICIT,
not alphabetical (see that script's own header) — `test_cmt_empty_blocks.sh`
must run first, `test_cmt_arena_runway.sh` must run last, and
`test_cmt_mempool_flood.sh` runs before `test_cmt_claim_flood.sh` and
`test_v2_epoch_boundary.sh` simply because it is quick and cheap.
**DELTA 1 correction (verifier CLAIM 5), UPDATED for R3 W4 package C:**
`test_cmt_mempool_flood.sh` does NOT touch the PUMP batch — it spends
node 4/5/6/7's own genesis leaves. `test_cmt_claim_flood.sh` (package C)
is now the ONLY scenario that reaches for the PUMP batch: one `v2-claim`
call over the WHOLE thing, proving a single block can carry more claims
than the retired 16-item cap. `test_v2_epoch_boundary.sh` runs after it
and finds the batch ordinarily already spent — its own pump submission is
opportunistic leftovers only.

⚠ **A genesis leaf can be claimed exactly once.** Re-running a claiming
scenario on the same cluster FAILS, correctly. Bring the cluster up fresh —
that is not flakiness, it is a single-use subject.

⚠ **Every "post-" comparison in every scenario below uses
`stagef_cmt_diff_at_floor`, never a bare `stagef_diff.sh` call.**
CreateEmptyBlocks means the chain keeps committing on its own throughout
every scenario's run, so comparing "each node's current latest block"
races that ongoing production; the floor wrapper compares the row at a
height every node has already, provably, reached. See `stagef_diff.sh`'s
row above and `stagef_cmt_diff_at_floor`'s own comment in `stagef_env.sh`.

⚠ **Every wait is bounded by BLOCK PROGRESS, never a bare `sleep`.**
`stagef_cmt_wait_height` (stagef_env.sh) declares a stall only after N
consecutive `CreateEmptyBlocksInterval`-lengths (60 000 ms each) with NO
height increase — a real failure signal, since idle production alone
should tick every interval on a healthy chain.

| Script | Proves | Requires (compile / env) | Leaves behind | How it can lie |
|---|---|---|---|---|
| `test_cmt_empty_blocks.sh` | tokenomics-v3 P1 REWRITE. TWO properties: (1) D-4 — an idle Comet chain commits at the FULL 60 s `CreateEmptyBlocksInterval`, measured directly as >= 2 consecutive wall-clock gaps >= 45 s (~1 s polling) between committed heights; every block in the observed window still shows `tx_count=0` and no claim landed. (2) D-5 — the probe identity's ONE genesis leaf, claimed mid-scenario, reaches `utxo_set` inclusion in < 30 s (printed), because the real `txsAvailable` callback wakes the round instead of waiting for the next interval tick. | Default build. **Must run FIRST** in the sweep — needs a window with no transaction of ITS OWN or anyone else's in flight. Needs a `stagef_up_v2.sh` bring-up that created the probe identity (`$BASE_DIR/v2probe`) — an older bring-up SKIPs (99). Takes ~2-3 minutes (>= 2 full 60 s idle intervals for part 1). | The chain a few blocks further on; the probe identity's ONE leaf permanently claimed (re-running against the SAME bring-up fails at the claim step — bring up fresh to re-run). Nothing else claimed, killed, or restarted. | A leftover mempool tx from elsewhere would make Part 1 vacuous — closed by the SAME two anti-vacuity guards as before (`tx_count=0` window check + no `utxo_set` row in the window; `tx_count` is BLIND to a claim, `v2_blocks.tx_count` counts applied ENVELOPES only). Part 2's latency is only honest to `stagef_cmt_wait_row`'s ~5 s poll granularity — the 30 s bound has enough margin (one interval is 60 s, one `timeout_commit` round is ~5 s) that this cannot flip the verdict in the cases this scenario exists to catch. BFT-time monotonicity is **NOT asserted** — `v2_blocks` carries no timestamp column on this lane (`nodus_witness_v2_apply.c:4798-4816` drops `header`); the value lives only in opaque Comet protobuf blobs this harness cannot decode. A REGRESSION shape this scenario now catches that the pre-P1 version could NOT: attendance moving the root on an empty block again (Part 1's gap floor would fail, loudly, instead of the old version's mere stall-bound pass). |
| `test_v2_claim.sh` | A genesis allocation is claimed and the V2 apply engine agrees across all 7 nodes. On a pure Comet chain a claim is the only transaction that can come FIRST. | Default build. Uses node 2's leaf. | Node 2's leaf claimed; chain one (or more) blocks higher. | Never parses `committed: height=` (always 0 on this lane). CheckTx APPROVED is admission, not inclusion — closed by the claim's own `utxo_set` row, keyed by the nullifier a `--dry-run` prints in full — matched against the `tx_hash` COLUMN, not `nullifier` (DELTA 1, verifier UNCOVERED FINDING 1: `nodus_rt_core_claim_apply` binds the claim's nullifier into `tx_hash` and a derived hash of it into `nullifier` — the first cut named the wrong column and was always RED on a healthy chain). A claim gets no `v2_tx_index` row (envelope-only index, Comet writer `cmt_item_index` at `nodus_witness_v2_apply.c:2085-2099`). **DELTA 2, MEASURED:** inclusion is asserted by the ledger effect itself, waited for with a PROGRESS bound (`stagef_cmt_wait_row`), then read at ITS OWN height — never at `submission_tip + 1`; the interval between CheckTx and inclusion is not asserted (measured elsewhere on this lane: 2 heights). **DELTA 3 — confirmed safe from Defect 1** (the nullifier used here is derived from the leaf and the manifest, never a signature — `shared/dnac/manifest_wire.c:624-648` — so a `--dry-run` capture is safe to match against the real submission, unlike `test_v2_stake.sh`'s `wire_id`). **DELTA 3, Defect 2:** the wait is also bounded by height (`MAX_HEIGHTS=20`), distinct from a stall. |
| `test_v2_stake.sh` | A `v2-envelope stake` SPENDS a claimed output and writes validator state — reaching state a claim never touches. Self-funds first (claims the non-validator user's leaf), so order-independent of `test_v2_claim.sh`. | Default build. Uses the non-validator `v2user` identity — all 7 nodes are already validators and would be refused. | `v2user`'s leaf claimed; a bond locked; two blocks (funding + stake). | Never parses `committed: height=`. A stake IS an envelope, so it DOES get an identity row — Comet writer `cmt_item_index`, `nodus_witness_v2_apply.c:2040-2099`. **DELTA 3, DEFECT 1, THE MEASUREMENT SITE (fixed):** the first cut keyed the wait on `wire_id`, which commits the ML-DSA-87 signature — RANDOMIZED per signing — so the dry-run capture could NEVER match the real submission's committed value (measured: `wire_id=c945d0cf…` vs committed `tx_id=781d6534…`, at a height where the stake HAD been applied). Fixed to key on `v2_intent_index.intent_id`, the signature-independent identity (`shared/dnac/env_wire.h:121-131`). **DELTA 2 — a separate defect, ALSO real:** a stake envelope was APPROVED at tip 2 and its row did not appear until tip 4 — both the funding claim and the stake wait for their OWN ledger effect and read ITS height, never `submission_tip+1`. **DELTA 3, DEFECT 2 (fixed):** the wait is now ALSO bounded by height (`MAX_HEIGHTS=20`), distinct from a stall — measured need: this exact wait sat 34 minutes at a healthy tip before Defect 1 was found. |
| `test_v2_partial_wipe.sh` | The H-10 boot gate is unchanged and still armed on a Comet node (confirmed lane-agnostic: `nodus_server_check_partial_wipe` reads only file presence): each of the three SQLite files removed in turn REFUSES START; without the marker the SAME half-wiped directory demonstrably boots (the negative control). | Default build. Needs `$BASE_DIR/v2_genesis_pin` (64 hex) from bring-up. | Node 5 rebuilt via wipe + pin-rejoin; new pid. **W4-H: an EXIT trap restores node 5 on ANY non-zero exit** — the moved database files are put back and the node restarted (with the pin, inert when a chain is present), so a mid-scenario `die` no longer leaves the rest of the sweep on six nodes (sweep 5, 2026-09-17). Proven live: an injected abort after the witness-DB move → node 5 back at the fleet tip within 20 s, the real scenario then PASSes on it. | "It did not come up" is not "the gate refused it" — the assertion greps `PARTIAL WIPE DETECTED` from a log truncated before each attempt. Restore now ALSO checks `chain role: COMETBFT` + `cometbft lane LIVE`, not just an open handle. **DELTA 1 (verifier UNCOVERED FINDING 5, fixed):** the verdict used to be decided by one fixed `sleep 8` — a gate refusing correctly but later than 8 s read as "booted", and the negative control's `!= "refused"` check then misread that late refusal as a disarmed gate (false GREEN in both directions). Replaced with a bounded 30 s poll for either real outcome; the negative control now requires the POSITIVE "booted" result specifically. |
| `test_v2_restart_convergence.sh` | A `kill -9`'d Comet node comes back on the SAME chain file, runs and completes the ABCI Handshake (the `ABCI replay blocks` line count rises by one), resumes AND KEEPS producing, and re-converges. | Default build. Victim is node 4, FIXED (no leader concept to derive from on this lane). | Node 4 restarted under a new pid; log appended, not truncated. | **R3 W4:** the `branch=HAVE_CHAIN` delta is gone with the legacy bootstrap state machine (`nodus_witness_bootstrap.c` deleted; a version-3 node's role is decided once by the post-open gate) — the ABCI Handshake delta is the scenario's sole restart-reconciliation proof. **DELTA 1 (item 4, CONFIRMED live and fixed):** "producing again" used to require ZERO progress — the catch-up wait targeted a fleet-tip snapshot the victim had often already reached by the time the wait started (measured: "tip 29 -> 29"), a vacuous pass. Fixed with an explicit second wait strictly past that snapshot and a floor-strictly-greater-than-baseline check before the final diff. |
| `test_v2_join.sh` | A WIPED node (identity kept) rejoins on nothing but its 64-hex genesis pin, adopts the fleet's exact chain, and catches up through the reactor's stored-part gossip (there is no separate blocksync — `wait_sync` is always false, D-23 rev 7 item 18). | Default build. Needs `$BASE_DIR/v2_genesis_pin`. | Node 6 rebuilt via wipe + rejoin; new pid; truncated log. | Pin length check is now 64 hex (was 128 — D-24 rev 4 item 1). "Adopted" is read from the witness DB's FILENAME (embeds the derived chain id's first 16 bytes), never a `global_height=0` row — a version-3 chain writes none (genesis is a document, not a block). |
| `test_cmt_dead_proposer.sh` | A stopped validator signs NOTHING for >= 7 heights while OTHERS keep committing, and it resumes and re-converges after `SIGCONT`. **Replaces `test_v2_view_change.sh`** — see this row's script header for why the legacy leader-derivation cannot be ported at all. | Default build. No leaf needed — CreateEmptyBlocks means demand is not required. Victim is node 2, FIXED. ⏱ Needs >= 7 intervals of wall time; post-tokenomics-v3-P1 that is >= 7 x 60 s (the pre-P1 ~6 s/block pace no longer applies — see "What flips" rule 1), so budget several minutes, not "usually well under a minute". | Node 2 `SIGSTOP`ped then `SIGCONT`ed; an EXIT trap resumes it on any early failure. | **No log line proves a round left round 0** — `cmt_cs.c` carries zero `QGP_LOG_INFO` calls; every transition function logs only on FAULT. The assertion is a PIGEONHOLE argument instead (>= CommitteeSize heights under exact round-robin at equal stake guarantees the victim's turn was hit at least once — CONFIRMED against the pinned reference's own tests, `types/validator_set_test.go` `TestProposerSelection2/3`) — read from the ported selection code's structure, not measured empirically this session; flagged as a QUESTION. Closed with a direct DB check: tokenomics-v3 P1 moved this from `validators.last_signed_block` (RETIRED) to `v2_attendance.last_signed_height`, keyed by voter_id (`stagef_voter_id`, `stagef_env.sh`) — the victim's row provably did not move; some other validator's did. Same property, now read from real SIGNING (decided_last_commit COMMIT votes) rather than proposer credit — a SIGSTOPped process can do neither. **DELTA 1 (verifier UNCOVERED FINDING 6, fixed):** the baseline reads used to happen BEFORE `kill -STOP`, racing the chain's own ongoing production in both directions (a block the victim proposed in that window read as a false RED; a block from another validator shrinking the observed window read as a false GREEN). The signal is now sent FIRST, synchronously, before either baseline DB read. **tokenomics-v3 P1 landing (MEASURED, first production sweep at 0.19.67):** attendance is credited ONE BLOCK LATE (block H carries the precommits for H-1), so a precommit the victim sent just before the stop appeared in its row after the stop (10 -> 11) and the old "unchanged since the stop" assertion went RED on a correct chain — a timing race. The frozen baseline is now read 3 heights past the stop (covers the victim leading node1 by one committed block; a larger lead would show as a visible RED, never a false GREEN) and the row must not move from there to the end of the window. |
| `test_cmt_chain_config.sh` (D-16 rev 7, W4-CC) | `nodus-cli chain-config propose`, run from a validator's OWN identity against ITS OWN node, collects committee approvals OVER THE NETWORK (verbs 40-41, the SYSTEM-governance approval-collection RPC replacing the retired vote-collect pair 14-15) and lands a `chain_config_history` row byte-identical on all 7 nodes — the FIRST networked exercise of verbs 40-41 anywhere (test_cc_appr.c drives the responder directly, no network; test_tier3.c is wire-codec-only). | ⚠ **SHORT-GRACE BUILD ONLY.** compile: `-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15`; env: `STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15` exported BEFORE `stagef_up_v2.sh`. SKIPS (99) at the shipped grace (17280 blocks). No leaf needed — a governance proposal, not a spend. | One committed `chain_config_history` row (BLOCK_INTERVAL_SEC -> 6) on every node. Nothing killed or restarted. | The CLI's exit code / "proposal accepted" line is CheckTx admission, never inclusion — the row is asserted from the CHAIN via `stagef_cmt_wait_row`, never CLI stdout. **The per-proposer rate limit is real** (`NODUS_CC_RATE_LIMIT_WINDOW_MS`=5000 ms) — this scenario asks all 7 seats in round 1 so it only reaches the CLI's round 2 if a real hiccup refuses a seat; a round-2 refusal of a previously-accepting seat is this design tension surfacing live, not a harness defect (register R3-W4-CC-writer's own BLOCKED ON). Does **NOT** prove the effective-height cutover (nothing waits for the chain to reach the proposal's effective height and read back the new interval) — only that the proposal round-trips and commits identically everywhere. |
| `test_cmt_mempool_flood.sh` | (A) A tx submitted to ONE node (3) commits on all 7, AND its own UTXO lands there — the mempool channel (verb 39, `NODUS_T3_CMT_TXS`) gossips it; there is no leader/forward-to-leader step to do it instead. (B) Several claims submitted back-to-back apply within a BOUNDED spread of heights (typically, and in the common case exactly, the SAME `block_height`) — PrepareProposal batches what is waiting when it runs, since CheckTx no longer blocks the client one-at-a-time. | Default build. Uses node 4's leaf (part A) and node 5/6/7's leaves (part B). Deliberately does NOT touch the PUMP batch. | Node 4/5/6/7 leaves claimed. PUMP batch untouched for `test_cmt_claim_flood.sh` / `test_v2_epoch_boundary.sh`. | **DELTA 1 (verifier UNCOVERED FINDINGS 2 and 4, fixed).** `tx_count` counts APPLIED ENVELOPES only (`nodus_witness_v2_apply.c:4593-4595`); a raw claim never increments it, so the first cut's `tx_count > 1` assertion was structurally ALWAYS RED. Part A used to assert only height agreement, which a completely broken mempool gossip could still satisfy via idle CreateEmptyBlocks production alone — closed by asserting node4's own claim's `utxo_set` row exists. **DELTA 2, MEASURED:** both parts now wait for their ledger effect(s) with a progress bound and read the ACTUAL height(s), never `submission_tip + 1`. Part B's "same block" is no longer a hard requirement — three separate CLI submissions can legitimately land on different rounds (the same mechanism DELTA 2 measured for a single transaction); the assertion is a bounded spread (2 heights), logging an exact batch as the common case. Inclusion is asserted by the ledger effect, waited for with progress bounds — the interval between CheckTx and inclusion is not asserted. **DELTA 3 — confirmed safe from Defect 1** (both parts key on claim nullifiers, never `wire_id`). **DELTA 3, Defect 2:** both waits are also bounded by height (`MAX_HEIGHTS=20`), distinct from a stall — the same bound `test_v2_stake.sh` measured sitting 34 minutes without. |
| `test_cmt_claim_flood.sh` | **R3 W4 package C.** ONE `v2-claim` call over the WHOLE pump batch (however many leaves this genesis config actually gave it, read from `v2_genesis.conf`) applies every leaf within 20 heights, AND at least one carrying block holds MORE than the retired flat 16-item cap — the engine's claim scratch is heap now, sized to the block's own `n_claims`, bounded by cometbft's own block-byte ceiling (`NODUS_V2_APPLY_MAX_CLAIMS`, 14 162, `nodus_witness_v2_apply.h`) rather than a flat item count. | Default build. The ONLY scenario that spends the PUMP batch — must run before `test_v2_epoch_boundary.sh`. | The WHOLE PUMP batch claimed and spent. Chain some number of blocks higher. | **NOT measured through `v2_blocks.tx_count`** — same structural reason `test_cmt_empty_blocks.sh`/`test_cmt_mempool_flood.sh` disclose: `tx_count` counts applied ENVELOPES only, never claims, so an all-claims block always shows `tx_count=0` regardless of this fix. Uses `v2_claims_spent.claimed_height` (one row per applied claim, with its own height column) instead. Does not capture each leaf's own nullifier before submitting (impractical for dozens of leaves) — reads `v2_claims_spent` rows newer than the submission's own starting tip instead, which assumes no OTHER scenario is spending claims concurrently (true here — this harness runs scenarios sequentially). The per-block wall-clock gap it prints is HARNESS-OBSERVED (polled from `v2_blocks`, ~1 s granularity), NOT the block's own committed header time (`cmt_blockstore`'s value column is an opaque encoded blob no bash+sqlite3 harness can decode) — printed for cost estimation, asserted on nowhere. **DELTA 4 (root cause was the CLI, not the engine):** at production constants this scenario FAILED — 40 leaves carried as 26:7, 27:16, 28:15, 29:2 across FOUR blocks, `max_in_one=16` never exceeding the retired cap (`/tmp/stagef-20260917T231618Z`). Read, not assumed: `cmd_v2_claim --submit`'s loop opened a NEW client session (Kyber1024 handshake + T2 auth) per leaf (`nodus-cli.c`'s old `t6_submit`), tens of seconds for 40 leaves against a chain committing every ~1-5 s — the batch never accumulated in one block, regardless of the engine fix above. Fixed in `nodus-cli.c`: the loop now opens ONE session (`t6_submit_on`) for the whole batch and prints the submission's own wall-clock duration so a future regression measures itself instead of being silently reintroduced (see the script's own "HOW IT CAN LIE"). |
| `test_cmt_env_flood.sh` | **R3 W4-C delta 2, made runnable by CLI-SPEND.** A burst of K ENVELOPES (not claims) all apply and all 7 nodes agree. How they split across blocks is PRINTED, NOT asserted (operator 2026-09-23): a proposer woken by txsAvailable may start before the client finishes, so the split is a wall-clock race (first pumped sweep at 0.19.68: 40 in 3 s -> 32 + 8); "a block may carry > 10 envelopes" is proven deterministically by `test_v2_apply.c` §6 (11 in one block). The envelopes are K real CORE SPENDs (`nodus-cli v2-envelope spend --count K`: K independent self-sends by the PUMP identity, each funded by its OWN coin, all on ONE client session); each is followed to its LEDGER EFFECT (the created `utxo_set` row, whose `tx_hash` is the envelope's `intent_id`), and the carrying blocks are grouped by that row's own `block_height`. Prints the CLI's wall-clock for the batch, harness-observed per-height gaps and each carrying block's `v2_blocks.tx_count` (none asserted). | Default build (nodus-server AND nodus-cli from the same tree — the CLI takes the CORE ruleset from its own compiled table). The PUMP identity must hold >= 11 spendable coins — `test_cmt_claim_flood.sh` must have run first; this scenario never claims the batch itself. `STAGEF_ENV_FLOOD_MAX` (default 40, max 100) bounds K. | The PUMP identity's K largest coins each replaced by one self-sent coin `STAGEF_PUMP_FEE_RAW` smaller (no change output with the equal-sized claim batch — coin count unchanged). Chain >= 1 block further on. | **SKIP (99) when the PUMP identity has < 11 spendable coins** (claim flood did not run first) — coverage that did not happen, not a pass. **The batch lands in one block only if the CLI submits faster than the chain commits** — the printed duration is what tells a client-pace failure from an engine one (the claim-flood trap, same shape). **The per-block envelope count is set by UNITS:** PrepareProposal's capacity seam reserves EVERY envelope's whole `res_max_total_units` against one 1 000 000-unit budget at once, without finalizing in between (`app_seam_check` → `nodus_witness_v2_produce.c:269` → `nodus_witness_v2_env.c:382`; `nodus_witness_v2_apply.h:290`), and trims the rest to a later block — so the declared ceiling IS the per-block limit. The CLI right-sizes it (`t6_spend_ceiling`: the metering module's own static units + one `w_read` per read): 23 946 units for a 1-in/1-out spend by ARITHMETIC (all weights 1), so at most 41 per block, K ≤ 40 by default. A round 200 000 ceiling (the test-fixture precedent) would have capped every block at 5 — not measured on a live block. The inclusion wait is an inline copy of `stagef_cmt_wait_row`'s rules (1 s poll for timestamps). Never parses `committed:`. |
| `test_v2_epoch_boundary.sh` | The chain crosses an epoch boundary at height `H=k*E_LEN` and freezes the snapshot for `epoch_start = H + E_LEN` (the one THIS crossing produces) byte-identically on all 7. | **Short-epoch binary, both halves:** `-DDNAC_EPOCH_LENGTH=<E>` + `STAGEF_EPOCH_LENGTH=<E>`. SKIPS at the shipped 720. Optional (CLI-SPEND): a built `nodus-cli` and `STAGEF_PUMP_FUNDER_NODE` / `STAGEF_PUMP_SUBMIT_NODE` (defaults 3 / 1) — without them the wait is idle production. | Ordinarily NOTHING of the PUMP batch — `test_cmt_claim_flood.sh` (package C), placed immediately before this scenario, already spent all of it; this scenario's own pump submission finds an already-fully-claimed identity and `v2-claim` SKIPS it. Chain past >= 1 boundary regardless. When pumped: node 3's genesis leaf claimed by the first pump step (unless an earlier pump already did) and one fee per pump step gone from node 3's single coin. A SKIP leaves nothing: the pace decision (`stagef_cmt_pump_ready`) is a pure check. | **Reachability is now a WALL-CLOCK BUDGET (1 800 s default), not a leaf count** — pumped claims no longer land 1:1 per block (see "What flips" rule 4), so counting leaves cannot say whether the boundary is reachable in this harness's patience. **CLI-SPEND:** the wait goes through `stagef_cmt_advance_to` — when the pump is usable the blocks are driven by confirmed self-send SPENDs (budget pace `STAGEF_CMT_PUMP_BLOCK_S`), otherwise by idle production (60 s pace) exactly as before; the `[ok] block driving:` line says which. A pumped green does not prove the idle-only crossing and vice versa. A dropped pump spend (rc 2) or a pump fault (rc 3) FAILS the run with its own message — never retried, never downgraded to idle mid-run. Never parses `committed:`. Can take MINUTES even at the short-epoch convention. **DELTA 1 (verifier CLAIM 16, fixed):** the cross-node comparison used to read `epoch_start = next_boundary` — the row GENESIS ALREADY SEEDED on every node identically, which can never differ and proved nothing about the crossing (`nodus_witness_vset.c:658-659`: crossing H writes `epoch_start = H + E_LEN`, not `H`). Fixed to compare at `next_boundary + E_LEN`. |
| `test_v2_rewards.sh` (tokenomics-v3 P2) | The reward reserve moves only pool → accrual → coin, identically on all 7: at each NON-payday boundary H the pool falls by EXACTLY what `v2_reward_accrual` gained (> 0, <= pool >> 16), every harness node that is a member of the GOVERNING snapshot(H−E) — decoded from `validator_set_snapshots`, never assumed to be the 7 genesis nodes — holds an accrual row, and pool + accrual table are identical on all 7; at the PAYDAY boundary (`(H/E) % payout_interval_epochs == 0`) the accrual table is empty afterwards and the coins at that height with `output_index >= 400` sum to exactly the prior accrual plus this boundary's distribution, owned by EXACTLY {pre-payday accrual owners} ∪ {harness nodes in snapshot(H−E)}, one each, identical on all 7; 7/7 state_root at the floor after. | **Short-epoch build + short payout interval, BOTH exported before `stagef_up_v2.sh`:** `-DDNAC_EPOCH_LENGTH=<E>` + `STAGEF_EPOCH_LENGTH=<E>` + `STAGEF_PAYOUT_INTERVAL_EPOCHS=2`. SKIPS (99) at the shipped 720 / 24, with interval 1, on a bring-up whose config names no `payout_interval_epochs`, and when the payday is over `STAGEF_EPOCH_BOUNDARY_BUDGET_S` (1800 s) — idle-only production always is; needs the CLI-SPEND pump. MUST run BEFORE `test_cmt_rule_n_retire.sh` (all seven must be paid). | Chain several epochs further on, past one payday: each committee validator holds one more native coin; one pump fee per step gone from node 3's coin — INTO the reward pool since P2, not burned; node 3's leaf claimed if no earlier pump did. Nothing killed or restarted. | Pre/post reads are ONE SQLite statement each (a consistent snapshot); the pre read is taken only after the last pump spend landed and the pump stays idle until the post reads are done; the window between is checked for NO envelope (`tx_count`) and NO coin other than payday (>= 400) / graduation (200) rows — a fee or claim in the window FAILS the run instead of being mis-attributed. A boundary the pump overshoots before its pre read is skipped for the next one; three misses FAIL. Payday coins are recognised by position (`block_height`, `output_index >= 400`). **Committee from the chain (fixed at the P2 landing, 0.19.69):** the first full short-epoch sweep FAILED "boundary 75: node2's fingerprint has no accrual row" on a CORRECT chain — `test_v2_stake.sh` bonds an 8th equal-stake validator (v2user) with no running node, the 7-seat set's tie-break rotates one genesis node out of each snapshot (snapshot(60) held v2user, not node2), and v2user never signs, so it misses the bar until Rule N retires it; the old check assumed the committee was the 7 genesis nodes. A running member that is not paid still FAILS; ≥ 1 harness node must be a member of every observed snapshot (vacuity guard). **Membership is matched in PURE BASH** — the fix's first cut used `printf | grep -qx` under `pipefail`, and `grep -q` exiting on an early match SIGPIPEs the writer (rc 141): measured 15 false "not a member" in 3 000 calls on a loaded machine, 0 idle; it failed sweep 2 on a correct chain (node7 dropped from the expected payday owners). Proves the LOGIC at E and interval 2, nothing about the production magnitudes. |
| `test_cmt_rule_n_retire.sh` (round 2, tokenomics-v3 P1 §A/D-3/D-11; re-checked round 5 against R5-1/R5-2/R5-3 and round 6 against the voting-power floor, unchanged) | A validator that signs nothing for TWO consecutive epochs (real `decided_last_commit` attendance, no hand-set row) is AUTO_RETIRED at the second boundary (`validators.status=3`, `consecutive_missed_epochs=2`, `active_count` -1 exactly once), AND that removal reaches cometbft's OWN validator set — but at the THIRD boundary, one epoch AFTER the DB flip, not the same one (`nodus_cmt_app_finalize_block`'s §A diff at boundary H compares snapshots frozen at H and H-E, neither of which has ever seen a decision made AT H itself; the removal is visible only once `commit_next(H)` writes `snapshot(H+E)`). The victim's `v2_attendance.last_signed_height` stays frozen the whole window while others' keep moving, and it re-converges after `SIGCONT`. **Round 5 re-check (arithmetic, not behavior, changed):** node 7 has a REAL duty at both e1 and e2 (R5-1 — it is a continuous 7-of-7 committee member, always a snapshot entry, never absent); at e2 retiring it alone leaves the next epoch's seatable set = the 6 other genesis validators (plus, if `test_v2_stake.sh` ran earlier, a staker whose bond is the SAME `DNAC_SELF_STAKE_AMOUNT`, `test_v2_stake.sh` `BOND`), all at equal power, so the largest member holds at most 1/6 of the set's power and `(P − max) > P*2/3` holds (round 6's voting-power floor, which replaced round 5's count floor `DNAC_RULE_N_MIN_BONDED` = 4 — neither engages here); graduation (R5-3) is candidate-gated on status first, and node 7 only BECOMES AUTO_RETIRED partway through e2's own Rule N step (step 4), AFTER e2's own graduation phase (step 2) already ran — so it was never a graduation candidate at e2 either way, with or without R5-3's snapshot check; by e3, `commit_next(e2)` has already excluded it from snapshot(e3) (top_n selects ACTIVE/ELIGIBLE only), so R5-3's deferral condition does not hold and it graduates at e3 exactly as before. Net: this scenario has no in-conflict candidate for R5-2's floor or R5-3's deferral to change, so e1/e2/e3 stay where they were. | **Short-epoch build only:** `-DDNAC_EPOCH_LENGTH=<E>` + `STAGEF_EPOCH_LENGTH=<E>`. SKIPS (99) at the shipped 720 — needs THREE boundaries' worth of wall time (`STAGEF_RULE_N_RETIRE_BUDGET_S`, default 5400 s), computed from the current tip the same way `test_v2_epoch_boundary.sh` computes its own reachability budget: blocks needed × the per-block pace — `STAGEF_CMT_PUMP_BLOCK_S` (15 s) when the CLI-SPEND pump is usable, `STAGEF_CMT_EMPTY_INTERVAL_MS` (60 s idle pace) otherwise. Optional (CLI-SPEND): a built `nodus-cli` and `STAGEF_PUMP_FUNDER_NODE` / `STAGEF_PUMP_SUBMIT_NODE` (defaults 3 / 1). Victim is node 7, FIXED. Placed AFTER every leaf-spending and epoch-boundary scenario. | Node 7 `SIGSTOP`ped then `SIGCONT`ed — an EXIT trap resumes it on any early exit. Node 7 is PERMANENTLY AUTO_RETIRED on this bring-up (not reversible within it) — nothing later in the sweep may assume 7 ACTIVE validators; this is why it runs immediately before `test_cmt_arena_runway.sh`, which only reads accumulated counters and does not care which validators are still ACTIVE. When pumped: node 3's genesis leaf claimed by the first pump step (unless an earlier pump already did) and one fee per pump step gone from node 3's single coin; a SKIP leaves nothing (the pace decision is a pure check). | The script does not stop node 7 immediately on entry — it first waits (node 7 still healthy) for a FRESH epoch start, so both watched epochs are unambiguously 0% attended BY CONSTRUCTION rather than by luck of where in an epoch the scenario happened to start; the epoch bounds are then RE-DERIVED from the height actually reached after the stop (self-correcting against a stop that races a boundary block), never assumed from the pre-stop height. The "1 removal" INFO line is asserted at the THIRD boundary specifically — asserting it at the second (where the DB flip happens) would either never fire or silently measure the wrong thing, exactly the mistake this row's own header explains was in this scenario's ORIGINAL dispatch text. Like `test_cmt_dead_proposer.sh`, no positive "round advanced" log line exists on this lane; height movement alone is never the load-bearing assertion — every check reads `v2_attendance` / `validators` / the CMT-APP log line directly. **Only the 50% bar is exercised here, never the 120-block recency window:** at E=15 the window is longer than the two watched epochs, so the victim's frozen `last_signed_height` is still inside it at e2 — the recency rule and the Rule N voting-power floor are covered only by `test_v2_epoch.c` (§11a; the floor §12c, §12e-§12i) at E=720 — this scenario's single retirement never exercises a refused one. **One-block credit lag (MEASURED, first short-epoch sweep at 0.19.67):** the victim's frozen `last_signed_height` is read 3 heights after the stop, not at it — a precommit sent just before the stop is credited one block later (29 -> 30), the same race `test_cmt_dead_proposer.sh` hit; the first watched epoch is therefore 0-1 signed blocks, not exactly 0 (still far below the bar). **CLI-SPEND:** every production wait (alignment, settle, the three boundaries, the final settle) goes through `stagef_cmt_advance_to` — pumped, the watched epochs carry self-send SPENDs; idle, they are empty blocks. Rule N reads signatures, not block content, so both exercise the same rule, but neither proves the other's shape; the `[ok] block driving:` line says which one ran. A dropped pump spend or a pump fault FAILS the wait it happened in — never retried or downgraded. The victim's catch-up waits after `SIGCONT` stay idle (replication, not production). **Fixed at the P1 landing:** the stop-SETTLE block used to reuse the name `settle_to` and overwrite the final "e3 + 7" target, so the final settle returned at once; it now has its own `stop_settle_to` (the short-epoch sweep run 2 at 0.19.67 still ran the old shape). |
| `test_cmt_arena_runway.sh` | The Comet receive arena's two one-shot latches (50% WARN, 90% ERROR) never fired on any node across the WHOLE sweep. Since R3 W3 package C2e the arena is a PER-MESSAGE scratch of `CMT_CONR_MAX_MSG_SIZE` (1 MiB, `nodus_witness_cmt_net.h:102`), reset before every decode, and exhaustion is unreachable for an admitted message — the latches are regression guards. **Must run LAST** — its subject is cumulative history. | Default build. Read-only; submits nothing. | Nothing. | **No per-block usage NUMBER exists to read from nodus-server** — `nodus_cmt_net_recv_arena_used()`'s only callers are the test binaries (`nodus/tests/test_cmt_net.c`, `test_cmt_live.c`); only the two one-shot latches are checked. A latch is one-shot PER PROCESS LIFETIME, so a node restarted mid-sweep (4, 5, 6) has a fresh flag from its last restart onward, not the whole sweep — disclosed, not hidden. **History (closed):** on the fourth W3 sweep, with the pre-C2e 64 MiB never-released runway, both latches fired on node 1 by height ~347 (≈174 KB per empty block) — that defect is register R3-A-5, CLOSED by C2e; a RED here today is a real regression. |

#### Not in the sweep

| Script | Requires | Exercises |
|---|---|---|
| `test_v2_grow_7_20.sh` | `-DDNAC_EPOCH_LENGTH=15` + `-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15`, `STAGEF_V2_CANDIDATES=13` exported BEFORE bring-up (0 → skips). ~30 min. **Run standalone**: it leaves 13 extra nodes running, a permanent 20-node committee, every candidate leaf spent. | The committee grows 7 → 14 → 20 by governance. **NOT converted to the Comet lane yet** — it still parses the CLI's `committed: height=` line (always 0 on this lane) and it is not in the runner; package W4-H decides convert-or-delete. Its FLAKY history (v0.19.48, a legacy view-boundary loss) belongs to the deleted lane. **R3 W4-C delta 4 (out-of-whitelist finding, NOT fixed here):** `nodus-cli.c`'s print this script greps for (`:248`, `:449`, `:469`, `grep -q '^committed: height='`) no longer exists — delta 4 reworded it to `"accepted: mempool CheckTx approved..."` because it was factually wrong on the Comet lane (see the README's own warning section above). This script is not in the runner and this file is outside delta 4's whitelist, so it was not touched; whoever runs or converts it next needs to update this grep too. |

#### Order matters on the Comet lane too (R3 W3, C2d)

The fifteen Comet scenarios are order-INDEPENDENT of each other's LEAVES
by construction (each spends only its own genesis allocation), but not of
each other's TIMING or LOG STATE. `genesis_protocol_v2.sh`'s list is an
explicit order for exactly these reasons — see its own header for the
full reasoning; the residue worth knowing if you run scenarios by hand:

- **round 2:** `test_cmt_rule_n_retire.sh` is the ONE exception to
  "spends only its own genesis allocation" — it PERMANENTLY AUTO_RETIREs
  node 7's VALIDATOR SEAT (not a leaf; a standing chain-state change with
  no reversal on this lane). Run it LAST among the Comet scenarios (its
  place in `genesis_protocol_v2.sh`'s order list), or standalone against
  its own fresh bring-up if run by hand before anything that assumes 7
  ACTIVE validators.
- **tokenomics-v3 P2:** `test_v2_rewards.sh` is such a scenario — it
  asserts all SEVEN committee validators are paid, so it runs immediately
  before `test_cmt_rule_n_retire.sh`. Every epoch boundary on this lane
  now writes `v2_reward_accrual` rows and debits the reward pool, and
  every PAYDAY (each `payout_interval_epochs`-th boundary) pays each
  validator a small native coin at `output_index >= 400` — a scenario
  that counts a node's coins or its `utxo_set` rows across a payday sees
  one more. And a SPEND's fee now lands in `supply_tracking.reward_pool`,
  not `total_burned`.

- **DELTA 1** — `stagef_up_v2.sh`'s bring-up now waits for all seven
  nodes to reach height 1 AND compares that first block 7/7
  (`stagef_cmt_diff_at_floor "bring-up"`) before returning. This makes
  `test_cmt_empty_blocks.sh`'s baseline read a REAL, already-agreed
  height on every run, never a fresh chain's `-1`/`0` transient — a
  strictly friendlier precondition than before, not a new hazard.
- `test_cmt_empty_blocks.sh` needs a window with NO transaction of
  anyone's in flight to prove idle production is genuinely idle (it
  checks `tx_count=0` AND no `utxo_set` row in its window). Run it
  FIRST, or standalone against a fresh bring-up.
- `test_v2_restart_convergence.sh` (node 4), `test_v2_partial_wipe.sh`
  (node 5) and `test_v2_join.sh` (node 6) each restart a node UNDER A
  NEW PID. `test_cmt_arena_runway.sh`'s two receive-arena latches are
  PER-PROCESS-LIFETIME flags (never cleared, but also never carried
  across a restart) — a node restarted earlier in the sweep only has
  arena history since ITS OWN last restart, not the whole sweep. Its own
  header discloses this; it is not a defect in that scenario, just a
  boundary on what "across the sweep" can mean for a node that was
  itself relaunched mid-sweep.
- **DELTA 1 correction, updated for R3 W4 package C:** `test_cmt_
  mempool_flood.sh` does NOT share the PUMP identity's leaf batch with
  `test_cmt_claim_flood.sh` or `test_v2_epoch_boundary.sh` — it spends
  node 4/5/6/7's own leaves. `test_cmt_claim_flood.sh` is now the only
  scenario that reaches for the PUMP batch at all (one call, the whole
  thing); `test_v2_epoch_boundary.sh` runs after it and ordinarily finds
  nothing left. None of the three compete for anything.
- **CLI-SPEND:** `test_cmt_env_flood.sh` needs the PUMP identity's
  claimed coins, so it must run AFTER `test_cmt_claim_flood.sh` (it SKIPs
  otherwise, and never claims the batch itself — claiming it would break a
  later claim flood). The height pump (`stagef_cmt_advance_to`, used by
  `test_v2_epoch_boundary.sh` and `test_cmt_rule_n_retire.sh`) is funded
  by node 3's OWN genesis leaf, claimed by whichever pumping scenario runs
  first — order-independent of every other scenario's leaves, because no
  scenario in the list claims node 3's leaf.
- `test_cmt_arena_runway.sh` must run LAST, unconditionally — its
  subject is the CUMULATIVE usage every other scenario in the sweep has
  already produced on every node. Running it earlier reads a partial
  history and understates whatever the full sweep would show.
- **History, closed (R3 W3 package C2e, register R3-A-5):** the fourth W3
  sweep measured the receive arena as a 64 MiB runway that was NEVER
  released — ≈174 KB per empty block, both latches on node 1 by height
  ~347, a node dead after ≈1 hour. The arena is now a PER-MESSAGE scratch
  of `CMT_CONR_MAX_MSG_SIZE` (1 MiB, `nodus_witness_cmt_net.h:102`),
  reset before every decode; exhaustion is unreachable for an admitted
  message and the two latches are regression guards that must never fire.
  A sweep may run for as long as it needs; a RED `test_cmt_arena_runway.sh`
  is a real regression, not the hour wall.

## Adding a new test

Any new consensus-affecting TX type, wire format, or state mutation
should get a scenario test here BEFORE landing in production.

### ►► DOCUMENTING IT IS PART OF ADDING IT ◄◄

**A scenario that is not in the tables above does not exist.** In the
same commit that adds or changes a script, add or update its row, and
say all four of these — the ones nobody can recover by reading the
script under time pressure:

1. **What it proves.** One line. Not "tests X" — the property that would
   be false if it failed.
2. **What it requires**, split into the two halves that are easy to
   confuse: the **compile flags** the binary must carry
   (`-DDNAC_EPOCH_LENGTH=<E>`, `-DDNAC_BLOCKS_PER_YEAR=<BY>`, …) and the
   **environment** the scripts read (`STAGEF_*`), including anything
   that must be exported before `stagef_up_v2.sh`. If it runs on a plain
   default build, say that explicitly.
3. **What it leaves behind**, if anything — extra node directories, an
   arm file, restarted nodes, a halted cluster. Whoever runs the next
   scenario inherits it.
4. **How it can lie.** If there is a way for it to report PASS without
   having exercised its subject (an idle chain, an unset knob, a skipped
   assertion), write that down. The rc=99 skip path counts.

Put the same four in the script's own header comment. The README says
which scenario to reach for; the header tells whoever is already in the
file why it is shaped the way it is.

Why this is a rule and not a suggestion (all three from the legacy suite,
deleted in R3 W4 — kept here as the history that made the rule):
`test_epoch_settlement.sh` slept instead of pumping and passed for years
by comparing a height against itself; `test_newview_convergence.sh`'s
header named an environment variable (`NODUS_FAULT_DROP_VC_FROM`) that
had never existed in the source; and 12 of the 24 scripts then on disk
had no README row at all. Each cost a debugging session that the missing
line would have saved. See the root `CLAUDE.md` documentation rule — docs
land in the SAME commit.

Template (the Comet-lane shape — every wait progress-bounded, every
comparison at a floor every node has reached, inclusion read from the
ledger effect):

```bash
#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

# 0. refuse a non-Comet cluster (rc 99 = SKIP, and a skip is not a pass)
# 1. baseline at a floor every node has already reached
stagef_cmt_diff_at_floor "pre-<label>"

# 2. submit via nodus-cli (v2-claim / v2-envelope) or dna-connect-cli;
#    the answer is the CheckTx verdict, NOT a block receipt
"$STAGEF_NODUSCLI_BIN" ... v2-claim ...

# 3. wait for the transaction's LEDGER EFFECT (progress-bounded, height-bounded)
stagef_cmt_wait_row "$db" "SELECT COUNT(*) FROM utxo_set WHERE ..." 3 20

# 4. compare block identity + global root 7/7 at the floor
stagef_cmt_diff_at_floor "post-<label>"

echo "[PASS] <test name>"
```

Exit code contract (enforced by `genesis_protocol_v2.sh`):

- `exit 0` on PASS.
- `exit 99` on a test you intentionally want to skip (missing env
  var, unimplemented injection path, etc.).
- Any other non-zero exit = FAIL (e.g. `set -e` tripping, `[ ... ]`
  guard failing, CLI non-zero RC).

**Never** decide PASS/FAIL by grepping your own stdout. The runner
looks at `$?` only.

## Design notes

- All scripts `set -euo pipefail` — fail fast on any error.
- PIDs written to `$BASE_DIR/pids.txt` so `stagef_down.sh` can
  reliably kill even if the shell session is new.
- `BASE_DIR` path is written to `/tmp/stagef_current` so helper
  scripts can find the active run without env-var plumbing.
- Each `nodus-server` logs to `$BASE_DIR/node$N/nodus.log`. Check
  these when a test fails — a global_root / block_id divergence usually
  leaves a trail (`CMT_FAULT`, `FinalizeBlock` refusals).
- Committee is 7 (+2/3 = 5). Matches production validator-set size so
  quorum-edge bugs reproduce.

## ⚠ WHAT A GREEN HARNESS RUN DOES **NOT** PROVE

**The harness runs the chain at parameters the production chain does not
use.** Several scenarios are only reachable at all because the binary was
compiled with small values in place of the shipped ones:

| Parameter | Production | Harness | Why the override exists |
|---|---|---|---|
| `DNAC_EPOCH_LENGTH` | **720** (~72 min at the measured ≈ 6 s/block) | 15 | 720 blocks is a ~72 min wait before the first boundary; the runner's budget for the scenario is 30 min |
| `DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS` | **17280** (~29 h) | 15 | no governance change could ever take effect inside a test run |
| `DNAC_BLOCKS_PER_YEAR` | **6307200** | 20 | the first halving sits 6.3 M blocks out — unreachable |

So a green `test_v2_epoch_boundary.sh` says: **the LOGIC is correct — the
boundary block freezes the next epoch's snapshot byte-identically on all
seven, the committee seed is read from the Comet blockstore, and every
node agrees.** It does **not** say the chain is correct at 720 / 17280 /
6307200. Anything that could depend on the
magnitude of those numbers — arithmetic that overflows only at large
heights, a window that is wide enough at 15 and not at 720, an off-by-one
that hides when epoch and grace happen to be equal — is **outside what
this harness has ever exercised**.

Two consequences, both load-bearing:

1. **Never quote a harness result as production readiness** without
   naming the parameters it ran at. "7/7 global_root at epoch length 15"
   is an honest claim; "the epoch boundary is proven" is not.
2. **Anything parameter-sensitive needs its own coverage** — a unit test
   at production constants, or a long-running soak. The
   `#ifndef`-guarded defaults in `dnac/include/dnac/dnac.h` and
   `nodus/src/witness/nodus_witness_emission.h` are what ships; the
   harness only ever sees the override.

This is a property of the harness's design, not of any one scenario, and
it does not have a fix short of a soak environment that can run for
hours at production values.

### A related discipline: never tune a timeout to make a scenario pass

Scenario waits assert **progress**, not speed. `pump_to_height` fails
when the chain produces no block across `PUMP_STALL_ROUNDS` consecutive
send rounds; the height-based waits pump until a target height is
reached and then report a missing snapshot as a consensus failure, not a
timeout. That shape is deliberate: an earlier version carried
hand-picked wall-clock budgets at every call site, and every time a
scenario failed with the chain healthy and still advancing
(`height 15 < 22`, `height 104 < 107`) the tempting fix was to raise the
number. Numbers calibrated on one machine, at one cluster size, with a
healthy committee, say nothing on the next machine — and a budget raised
until green will happily swallow a real stall. If a wait needs a bigger
number to pass, that is the signal to re-express it in blocks or in
progress, not to raise it.

The worked example came from the deleted legacy suite (its
`test_vset_grow_shrink.sh` section G, R3 W4): with the epoch leader dead
by design every round waited out a missing vote (measured ~63 s/block
against ~37 s on a healthy cluster), so the scenario failed repeatedly
with the chain advancing normally and each failure invited another number
bump. A raised pump budget would have turned a genuine dead-leader halt
into a green. The fix was to assert PROGRESS and to condition the PASS on
positive rotation evidence — never on the pump finishing. The Comet
scenarios inherit the rule: `stagef_cmt_wait_height` and
`stagef_cmt_wait_row` are progress- and height-bounded, never wall-clock
budgets (the wall-clock numbers — `STAGEF_EPOCH_BOUNDARY_BUDGET_S`,
`STAGEF_RULE_N_RETIRE_BUDGET_S` and the per-block pace
`STAGEF_CMT_PUMP_BLOCK_S` they are multiplied by — decide SKIP, never
PASS). The CLI-SPEND pump (`stagef_cmt_pump_to`) inherits the same
bounds: every step waits on its own ledger effect through
`stagef_cmt_wait_row`, and there is no cap on the whole call.

### What a green COMET run does not prove, additionally (R3 W3 C2d)

Everything above this line applies (the epoch-length / grace-block
override table is the same one — `test_v2_epoch_boundary.sh` needs the
short-epoch build). FIVE MORE things a green run does not say:

0. **DELTA 2, MEASURED: inclusion is asserted by the ledger effect,
   waited for with progress bounds — the interval between CheckTx
   admission and inclusion is not asserted.** A stake envelope on
   `test_v2_stake.sh` was APPROVED at tip 2 and its identity row did
   not appear until tip 4; the reference makes no promise that a
   CheckTx-accepted transaction lands in the very next block, or in any
   bounded number of blocks at all. Every Comet scenario that submits a
   transaction (`test_v2_claim.sh`, `test_v2_stake.sh`,
   `test_cmt_mempool_flood.sh`) waits for that transaction's own ledger
   effect to appear (`stagef_cmt_wait_row`, `stagef_env.sh`) and reads
   the height IT actually landed at — never `submission_tip + 1`.
   ⚠ **DELTA 3, DEFECT 1, MEASURED: `test_v2_stake.sh` was keying that
   wait on a value that could NEVER match.** `wire_id` commits the
   ML-DSA-87 signature, which is randomized per signing, and the
   dry-run capture used to build a DIFFERENT envelope from the one
   actually submitted — so the wait was unwinnable regardless of
   timing (measured: dry-run `wire_id=c945d0cf…`, committed
   `tx_id=781d6534…`, at a height where the stake HAD been applied).
   Fixed to key on `intent_id`, the signature-independent identity
   (`shared/dnac/env_wire.h:121-131`) — see that script's own header
   for the full citation. Confirmed (not assumed) that `test_v2_claim.sh`
   and `test_cmt_mempool_flood.sh` do not share this trap: a claim's
   identity for this harness's purposes is its NULLIFIER
   (`shared/dnac/manifest_wire.c:624-648`), whose preimage never
   includes a signature.
   ⚠ **DELTA 3, DEFECT 2, MEASURED: the stall bound alone let a wait run
   FOREVER against a HEALTHY chain.** `stagef_cmt_wait_row`'s only exit
   was "the chain's tip stopped advancing"; against a chain that keeps
   committing every ~6 s while the awaited row never appears (exactly
   what Defect 1's mis-keyed wait produced), that condition never fires
   — measured: 34 minutes at a healthy, advancing tip (347) before the
   run was killed by hand. A SECOND, independent bound (`MAX_HEIGHTS`,
   default 20 — a judgment: three proposer cycles at 7 validators, not a
   measured constant) is now the ONLY thing standing between "CheckTx
   approved this" and "this harness gives up" on a chain that never
   drops back to idle. Exceeding it (rc=2) means the chain kept
   producing for 20+ heights without this transaction landing — read as
   "dropped, not delayed"; it does NOT distinguish that from a genuine
   silent refusal by the ledger after CheckTx approved admission, which
   still needs the node logs read by hand either way. A green run says
   only "it landed within the stall budget AND within 20 heights of
   submission", never "promptly" and never "guaranteed to land at all
   past that budget".

1. **`CreateEmptyBlocksInterval` (60 000 ms) is NOT overridable by any
   `STAGEF_*` variable.** Unlike `DNAC_EPOCH_LENGTH`, it is a value this
   build's own code writes into the node's config
   (`nodus_witness_cmt_node.c:1700`), not read from the genesis document
   or the environment. Every wait bound on this lane
   (`stagef_cmt_wait_height`'s stall detection) is expressed in
   MULTIPLES of this fixed 60 s, which is why several Comet scenarios
   (`test_cmt_dead_proposer.sh`, `test_v2_epoch_boundary.sh` at a
   default 720) now take minutes rather than seconds — a property of
   this build's timing constants, not of the harness's patience knobs.
2. **One machine, one validator paused at a time.** `test_cmt_dead_proposer.sh`
   stops exactly one of seven; nothing here exercises a genuine network
   partition, an f=2 Byzantine minority, or two validators down at once.
3. **The CLI's own submit-confirmation print is not just unused here —
   it is WRONG on this lane, unconditionally**, and no amount of
   harness-side care changes that: `nodus-cli.c`'s `committed:
   height=... index=...` line prints from response fields that are
   always zero (see "What flips on the Comet lane", item 3, and "THE
   CLI PRINTS LIE" above). A green Comet-lane run proves this harness
   never trusted that line; it does not mean the line stopped printing,
   and an operator reading raw CLI output by hand would still be misled.
4. **No blocksync reactor exists to catch up a node that falls far
   behind.** `wait_sync` is permanently `false` (D-23 rev 7 item 18); a
   lagging node relies entirely on the consensus reactor's own
   stored-part gossip. This harness has never exercised a node that
   fell behind by more than a handful of blocks — every catch-up
   measured here (`test_v2_join.sh`, `test_v2_restart_convergence.sh`,
   `test_v2_partial_wipe.sh`) is over a SHORT gap. A node that fell
   behind by thousands of blocks (a long production outage) is
   untested, on this lane, by this harness.


## Known limitations

- Requires cluster to start from genesis — cannot replay an existing
  chain into the harness.
- Single machine — can't catch true network-partition bugs. The closest
  proxies are process signals: `test_cmt_dead_proposer.sh` (`SIGSTOP` +
  resume, no leader derivation needed or possible — see its own header)
  and `test_v2_restart_convergence.sh` (`kill -9` + restart). Neither
  produces a partition: the rest of the cluster stays fully connected, so
  a conflicting-proposal fork under partition is out of reach here (the
  unit-level multi-node driver `test_cmt_byzantine` covers that shape with
  four in-process state machines).
- One validator paused at a time: nothing here exercises an f=2 Byzantine
  minority or two validators down at once.
- `test_v2_epoch_boundary.sh` needs the short-epoch build AND
  `STAGEF_EPOCH_LENGTH` to match; at the shipped 720 it skips.
- `test_v2_rewards.sh` needs the same AND `STAGEF_PAYOUT_INTERVAL_EPOCHS=2`
  at bring-up; at the shipped 24 its payday is out of reach and it
  skips. The reward path at production parameters (a 720-block epoch, a
  24-epoch payday) is covered by unit tests only (`test_v2_econ.c`, at
  E = 720 through the engine for the distribution; the payday there is
  called directly, never reached through the engine).
- Scenarios share one live cluster and are **not** order-independent —
  see "Order matters on the Comet lane" and `genesis_protocol_v2.sh`'s
  own header for the order constraints (`test_cmt_empty_blocks.sh`
  first, `test_cmt_arena_runway.sh` last, `test_cmt_mempool_flood.sh`
  before `test_v2_epoch_boundary.sh`).
- The chain produces a block every ≈ 6 s whether or not there is demand
  (every block is a proof block — see "What flips" rule 1). A scenario
  CAN reach a future height by waiting alone (`test_cmt_empty_blocks.sh`
  is built entirely on this), but a wait must still be bounded by
  PROGRESS (`stagef_cmt_wait_height`'s stall detection), never a bare
  `sleep` for a fixed duration — the fact that waiting alone eventually
  works is not permission to stop bounding how long it is allowed to
  take.

## When the runner reports FAIL

Because `genesis_protocol_v2.sh` echoes the failing test's full stdout
(no tail), the triage flow is:

1. Find the `--- begin full output ---` block in the runner output.
2. Look for the first `[FAIL]` line or the error that exited non-zero.
3. If the failure references `global_root` / `block_id`, diff the
   per-node witness DBs under `$BASE_DIR/node$N/data/witness_*.db`.
4. Logs at `$BASE_DIR/node$N/nodus.log` show the Comet lines (`chain
   role: COMETBFT`, `cometbft startup table built`, `cometbft lane LIVE`,
   `ABCI replay blocks:`, every `CMT_FAULT`) and reject reasons.
5. On a FAILED sweep Phase 4 KEEPS `$BASE_DIR` (does not `rm -rf` it) —
   only stops the processes. The result block prints the kept path
   (`logs kept at ...`); a fully green run tears down as normal, so
   there is nothing to inspect after one. Do NOT expect `stagef_down.sh`
   to have run on a failed sweep — run it yourself once you are done
   reading the evidence.

## Historical note

Stage F was in the original hard-fork v1 plan and was skipped once.
The re-add caught the v0.17.1 `committed_fee` wire-format migration
regression (`cmd_chain_config_propose` in `nodus/tools/nodus-cli.c`
never set `tx->committed_fee` before `dnac_tx_compute_hash`) — a
bug that unit tests failed to detect because both sides of the
parity test had been updated together, making the self-consistency
check circular. Only end-to-end genesis + `test_cc_block_interval`
+ `test_cc_inflation` at 7/7 actually exercised the libdna ↔
libnodus wire boundary.

Rule: **Stage F genesis commit is the only real libdna ↔ libnodus
parity proof.** Unit tests are necessary but not sufficient.
