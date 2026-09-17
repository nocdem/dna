# Genesis Protocol — Stage F Multi-Node Integration Harness

7-node localhost cluster for testing consensus-affecting changes
**before** production deploy. Catches state_root divergence bugs that
single-node unit tests miss.

Mandatory per `MEMORY/feedback_genesis_protocol.md` before ANY
witness / BFT / Merkle / fee / validator / chain_config ship, and
before any chain-wipe deploy.

## Quick start

```bash
# Build prerequisites
cd /opt/dna/nodus/build     && make -j$(nproc)
cd /opt/dna/messenger/build && make -j$(nproc)
cd /opt/dna/dnac/build      && make -j$(nproc)   # rebuilds libdnac.a

# The Comet lane — the ONLY live lane (R3 W3, D-17 rev 10 item 9,
# atlas-dec-9d96e2ec31ad4840cf258df21732b67f, APPROVED)
bash /opt/dna/nodus/tests/integration/stagef/genesis_protocol_v2.sh

# The legacy runner prints a closure banner and exits 99 — it no longer
# brings anything up. Kept, unreached, for the deletion wave's own diff.
bash /opt/dna/nodus/tests/integration/stagef/genesis_protocol.sh
```

**⚠ R3 W3 — THE LEGACY LANE IS CLOSED, NOT MERELY "ALSO RUN".** Until
this wave the harness ran BOTH lanes because the consensus code was one
implementation threaded with `v2_successor` branches, and a legacy
cluster never took them. That is no longer the shape of the tree:
`nodus-server` never starts the legacy BFT or the pre-Comet Ledger V2
lane on ANY chain any more — the witness's post-open gate REFUSES a
chain database that is not a version-3 (cometbft) chain, fail closed,
logged (`nodus_witness.c:861-962`). A legacy bring-up (`stagef_up.sh`'s
genesis TRANSACTION) would produce a chain every node then refuses to
open. **See "What flips on the Comet lane" below before reading
anything else in this file** — four standing rules this README relied
on for every scenario before this wave are now FALSE on the only lane
that runs.

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
   ⚠ **DELTA 1 — MEASURED FACT: 60 s is an UPPER BOUND, not the observed
   pace.** Rule N attendance writes the proposer's `last_signed_block` on
   EVERY block (`nodus_witness_v2_apply.c:3801`), so the global root
   changes at every height and cometbft's `needProofBlock`
   (state.go:1106-1129, `cmt_cs.c:1872`) is TRUE at every height in this
   build — every block is a proof block. A proof block arrives at the
   `timeout_commit` pace (5 000 ms), not the 60 000 ms interval: measured
   live, seven nodes committed at roughly one block per 6 s. The 60 s
   figure is what the harness's stall detectors use as a conservative
   ceiling (`stagef_cmt_wait_height`); it is not what an operator watching
   a clock should expect to see.

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
   "work" (an empty block) for the round to be about. `stagef_env.sh`'s
   `stagef_leader_entry` / `node_view` / `cluster_view_max` /
   `log_count` machinery does not apply here at all: it derives a
   position out of the legacy `validator_set_snapshots` positional
   layout and reads `pbft_state.current_view`, neither of which the
   Comet lane ever writes (`nodus_witness.c:2545-2549` routes a
   version-3 chain past the entire legacy tick body, unconditionally).
   `test_cmt_dead_proposer.sh` replaces `test_v2_view_change.sh` for
   exactly this reason — see that script's own header for the
   pigeonhole argument that stands in for a leader derivation this lane
   has no positional data to support.

3. **"Submit returns the committed height" → FALSE.** `dnac_spend`
   answers the Comet mempool's CheckTx result AT ONCE — `status:
   APPROVED` means "accepted into the mempool", nothing about a
   committed block (D-23 rev 7 item 22,
   `nodus_witness_handlers.c:2047-2063`). Every scenario that used to
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
   `PrepareProposal` fires, and `PrepareProposal` drains as many as fit
   under its claim bound (~2 972 claims at `Block.MaxBytes`
   22 020 096 — D-23 rev 8 item 24) into ONE block. A batch of 40 pump
   leaves should be expected to land in one block (or a small handful),
   never forty. `test_cmt_mempool_flood.sh` measures this batching
   directly; `test_v2_epoch_boundary.sh`'s reachability check no longer
   counts leaves for exactly this reason (see that script's own
   header).

Chain identity is also affected, though it is not a behavioural flip:
the pin and the derived chain id are the 32-byte document hash (64 hex
chars) — D-24 rev 4 item 1 — and a version-3 chain has NO
`global_height = 0` row in `v2_blocks` (genesis is a stored DOCUMENT,
not a block; `initial_height` starts the real block sequence, and 0 vs
1 there are two DIFFERENT chain ids for the same effective start —
`nodus_v2_gen_config.c`'s own required-key message says so). Any script
still comparing a 128-hex pin or reading a height-0 row is reading
pre-Comet assumptions.

**⚠ THE CLI PRINTS LIE ON THIS LANE, RECORDED HERE, NOT FIXED HERE.**
`nodus-cli.c`'s `v2-envelope`/`v2-claim` submit sites (`cmd_v2_envelope`
~:1793-1794, `t6_submit` ~:1887-1888) print `"...committed:
height=... index=..."` from receipt fields (`sres.block_height`,
`sres.tx_index`) that are always ZERO on this lane — the version-3
response carries only `status` (`nodus_witness_handlers.c:2119-2131`),
and `nodus_client_dnac_spend` `memset`s the result struct to zero before
decoding it (`nodus_client.c:2065-2076`), so nothing ever overwrites
those two fields. **No Comet-lane scenario in this suite parses that
line for a height.** This is out of C2d's whitelist to fix (it is
`nodus-cli.c`, a C file) — flagged for whoever owns that file next.

## `genesis_protocol.sh` runner (CLOSED, R3 W3)

**This runner no longer brings anything up.** It prints
`legacy lane CLOSED in R3 W3 (D-17 rev 10 (9)); deleted next wave` and
exits 99, before touching anything else in it — the body below that
banner is unreached, byte-unchanged, kept for the deletion wave's own
diff (D-17 rev 10 (9): "No old-lane code is deleted in W3 ... it is
unreachable and byte-unchanged"). The sections below that describe its
Phase 1-4 behaviour are HISTORICAL — accurate about what the code still
says, not about what it still does. The live runner is
`genesis_protocol_v2.sh`.

Single entry point. Assertion method: **exit code only**.

| rc of a test | Meaning |
|---|---|
| 0  | PASS |
| 99 | SKIP — the scenario declined to run because a prerequisite is absent. Used by `test_supply_invariant_halt` (needs its own disposable cluster) and `test_halving_boundaries` (needs `STAGEF_BLOCKS_PER_YEAR` + a matching build). A 99 is **not** a pass: it means that coverage did not happen. |
| else | FAIL (full stdout echoed, then runner returns 1) |

Modes:

```bash
bash genesis_protocol.sh              # full run: ctest + stagef + scenarios + teardown
bash genesis_protocol.sh --scenarios  # scenarios only; assumes stagef already up
```

Environment:

> ### ⚠ THE ONE THING TO UNDERSTAND FIRST
>
> **An env var alone changes nothing.** Epoch length, tokenomic year and
> fault injection are all **compile-time** properties of `nodus-server`.
> `STAGEF_*` variables only tell the *test scripts* what the binary was
> built with — set one without the matching `-D`, and the scenario either
> skips, or measures the wrong thing and reports a green that means
> nothing. Every row below names both halves; supply them together.
>
> **And export them BEFORE `stagef_up.sh`.** The server reads its fault
> configuration once, at witness init. Exporting after bring-up has no
> effect and produces "predicate installed on 0 nodes"-shaped failures.
>
> **The chain has no idle block production.** A block exists only when a
> transaction is submitted. Any scenario that just `sleep`s while
> expecting height to advance is **vacuous** — it will pass by comparing
> a height against itself. Drive the chain with a pump loop instead
> (`test_vset_grow_shrink.sh:129`, `test_epoch_settlement.sh:122`).
>
> **And the same fact silences view changes.** A follower's P3
> demand-armed deadman is the only thing that can start a round when the
> leader is unresponsive, and its whole window is gated on pending work —
> `if (w->mempool.count > 0 || w->pending_forward_count > 0)`,
> `nodus_witness_bft.c:11986`. The branch below it says so in the node's
> own words: *"an IDLE node arms no timeout, so it can never initiate a
> view change"* (`:12084-12089`). So killing or pausing a leader on an
> idle chain produces **no rotation for as long as you care to wait**,
> and a scenario that measures "no view change in N seconds" without
> pending demand has measured nothing. See `test_view_change_fork.sh`
> lie-path 1.
> ⚠ The matching log line *"IDLE — no timeout armed, no view change
> possible"* (`:12111`) is inside `#ifdef O15H_DIAG_ENABLED` and **does
> not print in a default build** — don't go looking for it in `nodus.log`.

| Var | Default | Requires the binary built with | Purpose |
|---|---|---|---|
| `STAGEF_EPOCH_LENGTH` | **720** (`stagef_env.sh:59`) | `-DDNAC_EPOCH_LENGTH=<E>` | Blocks per epoch. Production is 720 (~1 h). Use 15 to keep epoch-boundary scenarios under ~2 min. **This value does NOT reach the server** — it only tells scripts how long to wait / where the next boundary is. Verify the binary actually took the `-D`: a fresh chain seeds `validator_set_snapshots` at exactly `{0, E}`. |
| `STAGEF_BLOCKS_PER_YEAR` | unset | `-DDNAC_BLOCKS_PER_YEAR=<BY>` | `test_halving_boundaries.sh` skips (rc=99) when unset. When set, the scenario measures the emission the chain actually credited against the declared schedule; a mismatch is a FAILURE, never a skip. At the production 6,307,200 the first halving is unreachable. |
| `STAGEF_CC_GRACE_SAFETY` | 17280 | `-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=<G>` | Blocks a `CHAIN_CONFIG` change must wait before taking effect. At the production 17,280 (~24 h) no harness scenario can ever see a governance change land, so any scenario that proposes one needs a small value in BOTH halves. A mismatch does not say so: the apply refuses with `[ERR/CHAIN_CONFIG] apply: grace -- effective=<x> < commit=<y> + grace=17280` in the node log, while the client only prints `dnac_spend RPC failed (rc=7)`. |
| `STAGEF_CC_GRACE_ERGONOMIC` | 720 | `-DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=<G>` | The ergonomic-class counterpart of the above; set it alongside. |
| `STAGEF_LEGACY_NODUS_BIN` | unset | — (a second, OLDER binary) | Path to a previous-protocol `nodus-server`. `test_mixed_version_reject.sh` fails immediately without it. Build it from an older tag into its own directory. |
| `STAGEF_NODUS_BIN` / `STAGEF_NODUSCLI_BIN` | `nodus/build/...` | — | Point the harness at a differently-configured build (e.g. `nodus/build-fault/`) without disturbing the default one. |

#### Fault injection (`NODUS_FAULT_*`)

Read by `nodus_witness_fault.c:129-176`, **only** in a binary built with
`-DQGP_FAULT_INJECT=ON` (the whole TU is `#ifdef`-ed out otherwise, and
CMake refuses the flag in a `Release` build). All of these must be
exported **before `stagef_up.sh`**.

| Var | Value | Purpose |
|---|---|---|
| `NODUS_FAULT_ARM_FILE` | a path | The predicate is installed at startup but stays INERT until this file EXISTS; scenarios arm by touching it and disarm by removing it. **It must not exist when a scenario starts** — a leftover from a previous scenario makes the next one abort. Delete it between scenarios. |
| `NODUS_FAULT_DROP_TYPE` | `precommit` \| `prevote` \| `commit` | Which vote type to drop. An unrecognised value refuses to install the predicate rather than silently matching nothing. |
| `NODUS_FAULT_DROP_VIEW` | integer (default 0) | View to scope the drop to. Ignored for `commit`, which carries no view. |
| `NODUS_FAULT_DROP_VC_ROTATE` | integer ≥ 1 | Per-node VIEW_CHANGE drop width, so nodes collect genuinely different first-2f+1 subsets. `test_newview_convergence.sh` aborts as vacuous without it. **The name is `_VC_ROTATE`** — a comment in that test said `NODUS_FAULT_DROP_VC_FROM` until 2026-08-27; no such variable ever existed. |
| `NODUS_FAULT_ONLY_TAG` | hex byte | Restrict the drop to the single node whose `my_id[0]` matches. |

A working fault-injection cluster:

```bash
cmake -S nodus -B nodus/build-fault -DQGP_FAULT_INJECT=ON \
      -DCMAKE_C_FLAGS="-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 \
                       -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 \
                       -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15"
make -C nodus/build-fault -j"$(nproc)" nodus-server nodus-cli

export STAGEF_NODUS_BIN=$PWD/nodus/build-fault/nodus-server
export STAGEF_NODUSCLI_BIN=$PWD/nodus/build-fault/nodus-cli
export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
export NODUS_FAULT_ARM_FILE=/tmp/stagef_fault_arm
export NODUS_FAULT_DROP_TYPE=precommit NODUS_FAULT_DROP_VIEW=0
export NODUS_FAULT_DROP_VC_ROTATE=2
rm -f "$NODUS_FAULT_ARM_FILE"
bash nodus/tests/integration/stagef/stagef_up.sh
```

Note the `-DCMAKE_C_FLAGS=` form: `DNAC_EPOCH_LENGTH` and
`DNAC_BLOCKS_PER_YEAR` are **compiler defines, not CMake options**.
Passing them as `-DDNAC_EPOCH_LENGTH=15` directly to `cmake` produces
only a "Manually-specified variables were not used" warning and a binary
carrying the production defaults.

Scenario scripts record **reachability sentinels** (`SETUP_OK` /
`TARGET_REACHED` / `ASSERT_RUN` / `PASS`); the runner converts a PASS
that never recorded `ASSERT_RUN` into a FAILURE — a scenario that
skipped its terminal assertion is not coverage.

Runner phases:

1. **Phase 1** — full nodus `ctest` suite in `nodus/build` (200 registered tests; STUB-by-design skips are recognized, real failures abort).
2. **Phase 2** — `stagef_down.sh` + `stagef_up.sh` (spawn 7 nodes, submit genesis).
3. **Phase 3** — every `tests/*.sh` in alphabetical order (24 scripts on disk). Per-test `bash <script>`, exit-code only. Note that running the whole directory blindly is NOT a clean sweep: `test_med28_negative.sh` is a negative control that must fail on a healthy build, `test_v2_grow_7_20.sh` needs its own cluster and leaves a 20-node committee behind, several scenarios need a differently-compiled binary, and the order effects listed under **Scenario tests** apply.
4. **Phase 4** — `stagef_down.sh`.

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
| `genesis_protocol.sh` | **CLOSED (R3 W3, D-17 rev 10 (9)).** Prints the closure banner and exits 99 before touching anything else; brings nothing up any more. Body kept, unreached, for the deletion wave. |
| `genesis_protocol_v2.sh` | The runner for the **Comet lane** — the harness's only live lane: `stagef_up_v2.sh` + ten explicit scenarios (not alphabetical any more — see the script's own header for the order and why) + teardown. `--scenarios` runs against an already-up cluster. **It does NOT glob `tests/*.sh`** — the closed legacy runner did, which is why ITS rc=1 was never evidence on its own. This list is explicit, so a red run means a red scenario. Reports SKIPs separately and says in as many words that a skip is not a pass. **Leaf budget:** claim/stake consume single-use node/user leaves each; mempool_flood spends node 4/5/6/7's own leaves — DELTA 1 correction (verifier CLAIM 5): it does **not** touch the PUMP batch, contrary to an earlier draft of this row — `test_v2_epoch_boundary.sh` is the only scenario that reaches for PUMP leaves. A second run against the SAME cluster fails on the leaf-spending scenarios — correctly. **Phase 4, DELTA 1 item 2:** a FAILED sweep stops the processes but keeps `$BASE_DIR` (logs, DBs, config) for inspection instead of calling `stagef_down.sh` (which kills AND `rm -rf`s in one step); only an all-green sweep tears down as before. Default mode brings the cluster up fresh. |
| `stagef_up.sh` | Generate identities + spawn 7 nodus-server + wait peer mesh + submit genesis + fund user. **Births a LEGACY chain** — the genesis is a TRANSACTION submitted to the running cluster. Its output chain is refused at open by this build's witness (`nodus_witness.c:928-935`); kept for the deletion wave, not useful to run against this tree. |
| `stagef_up_v2.sh` | The version-3 (**cometbft**) ceremony, born a completely different way from `stagef_up.sh`: no transaction and no cluster. The generated config now carries `config_version = 3`, one shared `genesis_time_ms` (UTC ms, computed ONCE and written into every node's identical copy — the chain id hashes the whole document) and `initial_height = 1`. Each node runs the OFFLINE one-shot `nodus-server --derive-v2-genesis` against that one shared file **before anything is listening**, and agreement is CHECKED (all 7 chain ids must be identical, 64 hex / 32 bytes) rather than negotiated — refuses loudly if `config_version` is missing (defaults to 2 and is refused by `nodus_witness_v2_gen_v3_validate`). Then spawns the 7 and asserts, per node, bounded by ATTEMPTS not a bare sleep, **FOUR** anti-vacuity lines, not three (DELTA 1): `chain role: COMETBFT`, `cometbft startup table built`, `cometbft lane LIVE`, AND that its Comet tip reaches height 1 (`stagef_cmt_wait_height <db> 1 3`) — the first production-constants sweep showed why the first three alone are not enough: every node can show role+startup+LIVE and still never produce, and the old check would have called that bring-up green. Once all seven have their first block, ONE `stagef_cmt_diff_at_floor "bring-up"` proves the seven first blocks are identical BEFORE any scenario runs, rather than leaving that for the first scenario's own pre-check to discover (or race). A node that shows the role but never goes live, or never produces, is a FAIL. Leaves the same `pids.txt` / pointer contract, so `stagef_down.sh` tears it down unchanged; the config is kept at `$BASE_DIR/v2_genesis.conf`. **What it does NOT prove:** that the seven can commit a block together — that is the scenario suite's job (`genesis_protocol_v2.sh`), not the bring-up's. A green bring-up is a green BIRTH, not a green Comet lane. **`STAGEF_V2_CANDIDATES=<N>`** (default 0) additionally mints N funded identities under `$BASE_DIR/cand1..N` — unchanged from before this wave; the growth scenario that would use them (`test_v2_grow_7_20.sh`) is not part of this sweep (see its own row below). |
| `stagef_down.sh` | Kill PIDs + rm -rf the run dir |
| `stagef_diff.sh` | Read `state_root` (legacy) or `global_root` + `block_id` (Comet) from each node's witness DB, assert identical across the 7, print. `--expect-height N` additionally requires each node's OWN latest height to equal N (unchanged). **New, R3 W3 (C2d): `--at-height N`** compares the ROW AT height N instead of each node's current latest — necessary on the Comet lane because CreateEmptyBlocks means the chain keeps committing on its own, so "each node's own latest" races that ongoing production (seven sequential reads spanning even a fraction of a second can catch one node one idle block ahead of another and misreport it as divergence). Every Comet-lane scenario should call this through `stagef_env.sh`'s `stagef_cmt_diff_at_floor` wrapper, never bare. |
| `stagef_env.sh` | Sourced by other scripts; exports `BASE_DIR`, ports, pubkey file paths, `STAGEF_*` overrides. **The legacy PBFT derivation** (`stagef_leader_entry`, `:543`) plus `running_nodes` / `ref_db` / `node_view` / `cluster_view_max` / `log_count` / `node_pubkey_hex` and the `VSET_*` wire constants (`:384-625`) — moved out of `test_vset_grow_shrink.sh` on 2026-09-02 so `test_view_change_fork.sh` derives its victim with the same code instead of a copy. NONE of it applies on the Comet lane (see "What flips on the Comet lane" above) — kept, unchanged, for the legacy scenarios that still use it. **New, R3 W3 (C2d) — the Comet-lane section**, clearly marked in the file: `STAGEF_CMT_EMPTY_INTERVAL_MS` / `STAGEF_CMT_TIMEOUT_COMMIT_MS` (the two D-4 timing overrides, read from their exact source lines rather than hand-copied); `stagef_cmt_tip`; `stagef_cmt_wait_height` (a progress-bounded wait — a stall is N consecutive empty-block intervals with NO height increase, never a bare wall-clock cap); **`stagef_cmt_wait_row` (DELTA 2, extended DELTA 3)** — waits for a ledger EFFECT (a `COUNT(*)`-shaped SQL expression) to appear, with the SAME stall bound as `stagef_cmt_wait_height` (the chain's tip, not the row, is what must keep moving), because CheckTx admission does not promise next-block inclusion (measured: approved at tip 2, included at tip 4) — a caller reads the row's own height afterward, never `submission_tip + 1`. **DELTA 3 added a SECOND, independent `MAX_HEIGHTS` bound (default 20)**: the stall bound alone could wait FOREVER against a chain that keeps healthily committing while the awaited row never appears — measured, 34 minutes at a live tip before a run was killed by hand — so exceeding `MAX_HEIGHTS` past the call's starting tip returns a THIRD, distinct outcome (rc=2, "dropped, not delayed") separate from a stall (rc=1); `stagef_cmt_diff_at_floor` (the race-free `stagef_diff.sh` wrapper described above). A fault in EITHER section breaks every scenario on that lane, not one. |

## Scenario tests (`tests/`)

All 24 scripts on disk are listed. **"Plain" means: a default
`nodus/build` binary and a freshly brought-up cluster, nothing else.**

#### Plain — run on any default build

| Script | Exercises |
|---|---|
| `test_cc_block_interval.sh` | `CHAIN_CONFIG` propose: `BLOCK_INTERVAL_SEC` param, committee 5-of-7 vote, `chain_config_history` identical 7/7 |
| `test_cc_inflation.sh` | `CHAIN_CONFIG` propose: `INFLATION_START_BLOCK` param |
| `test_delegate_to_retiring.sh` | `DELEGATE` targeting a RETIRING validator — expected reject, state_root still 7/7 |
| `test_epoch_boundary.sh` | Block production across an epoch boundary, validator rows identical 7/7 |
| `test_stake.sh` | `STAKE` (10 M self-stake, default commission) → state_root 7/7 |
| `test_undelegate.sh` | `DELEGATE` → `UNDELEGATE` → state_root 7/7 |
| `test_unstake.sh` | `UNSTAKE` marks validator RETIRING → state_root 7/7 |
| `test_validator_update.sh` | `VALIDATOR_UPDATE` schedules a pending commission change → state_root 7/7 |
| `test_view_change_fork.sh` | C5 view-change safety against a **DERIVED** epoch leader: pause the validator proven to lead the next block, require a completed view-change quorum **and** a committed TX without it, then state_root 7/7 after it resumes — see below |
| `test_funding_stability.sh` | Funding-stability proof (O15C-D.1 §5) against the OPEN harness-instability record |
| `test_bootstrap_cold_dr.sh` | C4 `--cold-bootstrap` operator escape; C-2 cabal-bypass behaviour |
| `test_bootstrap_join_live.sh` | Witness bootstrap join-live + orphan recovery. **Adds a node8 to the cluster** |
| `test_bootstrap_mixed_version.sh` | H-9 mixed-version fail-fast: a node in DISCOVER detects an incompatible peer |
| `test_bootstrap_partial_wipe.sh` | H-10 partial-wipe XOR boot gate (E5): `nodus_server_init` must refuse to start |
| `test_bootstrap_replay_attack.sh` | C-4 nonce-mismatch replay rejection (drives an in-process unit test) |

#### Comet lane — needs a cluster from `stagef_up_v2.sh` (R3 W3, the ONLY live lane)

**These ten scenarios are the harness's entire live coverage.** Every
table above this one describes the CLOSED legacy lane — historical, kept
for the deletion wave's diff, never run by `genesis_protocol_v2.sh`. Read
"What flips on the Comet lane" near the top of this file FIRST: four
standing rules every row below assumes are now false.

Each exits **99 on a non-Comet cluster** rather than pretending to have
tested a Comet property. `genesis_protocol_v2.sh`'s order is EXPLICIT,
not alphabetical (see that script's own header) — `test_cmt_empty_blocks.sh`
must run first, `test_cmt_arena_runway.sh` must run last, and
`test_cmt_mempool_flood.sh` runs before `test_v2_epoch_boundary.sh`
simply because it is quick and cheap. **DELTA 1 correction (verifier
CLAIM 5):** the two do NOT share the PUMP batch — `test_cmt_mempool_flood.sh`
spends node 4/5/6/7's own genesis leaves and never touches it;
`test_v2_epoch_boundary.sh` is the only scenario that reaches for PUMP
leaves.

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
| `test_cmt_empty_blocks.sh` | An idle Comet chain still commits — CreateEmptyBlocks is really on. Every block in the observed window shows `tx_count=0` AND no claim landed (`utxo_set` has no row in that height range). | Default build. **Must run FIRST** in the sweep — needs a window with no transaction of ITS OWN or anyone else's in flight. DELTA 1 measured pace: ~2 x timeout_commit (~10-12 s) in practice, not the 60 s interval — see "What flips" rule 1. | The chain a few blocks further on. Nothing claimed, killed, or restarted. | A leftover mempool tx from elsewhere would make height-advanced vacuous. **DELTA 1 (verifier UNCOVERED FINDING 2, fixed):** `tx_count=0` alone is BLIND to a claim — `v2_blocks.tx_count` counts applied ENVELOPES only, never `blk->claims[]`, and a claim is the only transaction a fresh harness identity can submit. Closed with a second guard: no `utxo_set` row may exist with `block_height` inside the window either. BFT-time monotonicity is **NOT asserted** — `v2_blocks` carries no timestamp column on this lane (`nodus_witness_v2_apply.c:4798-4816` drops `header`); the value lives only in opaque Comet protobuf blobs this harness cannot decode. |
| `test_v2_claim.sh` | A genesis allocation is claimed and the V2 apply engine agrees across all 7 nodes. On a pure Comet chain a claim is the only transaction that can come FIRST. | Default build. Uses node 2's leaf. | Node 2's leaf claimed; chain one (or more) blocks higher. | Never parses `committed: height=` (always 0 on this lane). CheckTx APPROVED is admission, not inclusion — closed by the claim's own `utxo_set` row, keyed by the nullifier a `--dry-run` prints in full — matched against the `tx_hash` COLUMN, not `nullifier` (DELTA 1, verifier UNCOVERED FINDING 1: `nodus_rt_core_claim_apply` binds the claim's nullifier into `tx_hash` and a derived hash of it into `nullifier` — the first cut named the wrong column and was always RED on a healthy chain). A claim gets no `v2_tx_index` row (envelope-only index, Comet writer `cmt_item_index` at `nodus_witness_v2_apply.c:2085-2099`). **DELTA 2, MEASURED:** inclusion is asserted by the ledger effect itself, waited for with a PROGRESS bound (`stagef_cmt_wait_row`), then read at ITS OWN height — never at `submission_tip + 1`; the interval between CheckTx and inclusion is not asserted (measured elsewhere on this lane: 2 heights). **DELTA 3 — confirmed safe from Defect 1** (the nullifier used here is derived from the leaf and the manifest, never a signature — `shared/dnac/manifest_wire.c:624-648` — so a `--dry-run` capture is safe to match against the real submission, unlike `test_v2_stake.sh`'s `wire_id`). **DELTA 3, Defect 2:** the wait is also bounded by height (`MAX_HEIGHTS=20`), distinct from a stall. |
| `test_v2_stake.sh` | A `v2-envelope stake` SPENDS a claimed output and writes validator state — reaching state a claim never touches. Self-funds first (claims the non-validator user's leaf), so order-independent of `test_v2_claim.sh`. | Default build. Uses the non-validator `v2user` identity — all 7 nodes are already validators and would be refused. | `v2user`'s leaf claimed; a bond locked; two blocks (funding + stake). | Never parses `committed: height=`. A stake IS an envelope, so it DOES get an identity row — Comet writer `cmt_item_index`, `nodus_witness_v2_apply.c:2040-2099`. **DELTA 3, DEFECT 1, THE MEASUREMENT SITE (fixed):** the first cut keyed the wait on `wire_id`, which commits the ML-DSA-87 signature — RANDOMIZED per signing — so the dry-run capture could NEVER match the real submission's committed value (measured: `wire_id=c945d0cf…` vs committed `tx_id=781d6534…`, at a height where the stake HAD been applied). Fixed to key on `v2_intent_index.intent_id`, the signature-independent identity (`shared/dnac/env_wire.h:121-131`). **DELTA 2 — a separate defect, ALSO real:** a stake envelope was APPROVED at tip 2 and its row did not appear until tip 4 — both the funding claim and the stake wait for their OWN ledger effect and read ITS height, never `submission_tip+1`. **DELTA 3, DEFECT 2 (fixed):** the wait is now ALSO bounded by height (`MAX_HEIGHTS=20`), distinct from a stall — measured need: this exact wait sat 34 minutes at a healthy tip before Defect 1 was found. |
| `test_v2_partial_wipe.sh` | The H-10 boot gate is unchanged and still armed on a Comet node (confirmed lane-agnostic: `nodus_server_check_partial_wipe` reads only file presence): each of the three SQLite files removed in turn REFUSES START; without the marker the SAME half-wiped directory demonstrably boots (the negative control). | Default build. Needs `$BASE_DIR/v2_genesis_pin` (64 hex) from bring-up. | Node 5 rebuilt via wipe + pin-rejoin; new pid. | "It did not come up" is not "the gate refused it" — the assertion greps `PARTIAL WIPE DETECTED` from a log truncated before each attempt. Restore now ALSO checks `chain role: COMETBFT` + `cometbft lane LIVE`, not just an open handle. **DELTA 1 (verifier UNCOVERED FINDING 5, fixed):** the verdict used to be decided by one fixed `sleep 8` — a gate refusing correctly but later than 8 s read as "booted", and the negative control's `!= "refused"` check then misread that late refusal as a disarmed gate (false GREEN in both directions). Replaced with a bounded 30 s poll for either real outcome; the negative control now requires the POSITIVE "booted" result specifically. |
| `test_v2_restart_convergence.sh` | A `kill -9`'d Comet node comes back on the SAME chain file, in the SAME HAVE_CHAIN bootstrap branch, runs and completes the ABCI Handshake, resumes AND KEEPS producing, and re-converges. | Default build. Victim is node 4, FIXED (no leader concept to derive from on this lane). | Node 4 restarted under a new pid; log appended, not truncated. | **DELTA 1 (verifier CLAIM 12, corrected):** the legacy HAVE_CHAIN/DISCOVER check was wrongly REMOVED on the mistaken premise that the bootstrap machine never runs on a version-3 chain — it does, and is deliberately routed into HAVE_CHAIN (`nodus_witness_bootstrap.c:457,480-482`); the delta is RESTORED alongside the ABCI Handshake delta, not replaced by it. **DELTA 1 (item 4, CONFIRMED live and fixed):** "producing again" used to require ZERO progress — the catch-up wait targeted a fleet-tip snapshot the victim had often already reached by the time the wait started (measured: "tip 29 -> 29"), a vacuous pass. Fixed with an explicit second wait strictly past that snapshot and a floor-strictly-greater-than-baseline check before the final diff. |
| `test_v2_join.sh` | A WIPED node (identity kept) rejoins on nothing but its 64-hex genesis pin, adopts the fleet's exact chain, and catches up through the reactor's stored-part gossip (there is no separate blocksync — `wait_sync` is always false, D-23 rev 7 item 18). | Default build. Needs `$BASE_DIR/v2_genesis_pin`. | Node 6 rebuilt via wipe + rejoin; new pid; truncated log. | Pin length check is now 64 hex (was 128 — D-24 rev 4 item 1). "Adopted" is read from the witness DB's FILENAME (embeds the derived chain id's first 16 bytes), never a `global_height=0` row — a version-3 chain writes none (genesis is a document, not a block). |
| `test_cmt_dead_proposer.sh` | A stopped validator proposes NOTHING for >= 7 heights while OTHERS keep committing, and it resumes and re-converges after `SIGCONT`. **Replaces `test_v2_view_change.sh`** — see this row's script header for why the legacy leader-derivation cannot be ported at all. | Default build. No leaf needed — CreateEmptyBlocks means demand is not required. Victim is node 2, FIXED. ⏱ Needs >= 7 intervals of wall time; DELTA 1's measured pace (~6 s/block, not 60 s) means this is usually well under a minute in practice, though the stall bound stays generous. | Node 2 `SIGSTOP`ped then `SIGCONT`ed; an EXIT trap resumes it on any early failure. | **No log line proves a round left round 0** — `cmt_cs.c` carries zero `QGP_LOG_INFO` calls; every transition function logs only on FAULT. The assertion is a PIGEONHOLE argument instead (>= CommitteeSize heights under exact round-robin at equal stake guarantees the victim's turn was hit at least once — CONFIRMED against the pinned reference's own tests, `types/validator_set_test.go` `TestProposerSelection2/3`) — read from the ported selection code's structure, not measured empirically this session; flagged as a QUESTION. Closed with a direct DB check: the victim's `validators.last_signed_block` provably did not move; some other validator's did. **DELTA 1 (verifier UNCOVERED FINDING 6, fixed):** the baseline reads used to happen BEFORE `kill -STOP`, racing the chain's own ongoing production in both directions (a block the victim proposed in that window read as a false RED; a block from another validator shrinking the observed window read as a false GREEN). The signal is now sent FIRST, synchronously, before either baseline DB read. |
| `test_cmt_mempool_flood.sh` | (A) A tx submitted to ONE node (3) commits on all 7, AND its own UTXO lands there — the mempool channel (verb 39, `NODUS_T3_CMT_TXS`) gossips it; there is no leader/forward-to-leader step to do it instead. (B) Several claims submitted back-to-back apply within a BOUNDED spread of heights (typically, and in the common case exactly, the SAME `block_height`) — PrepareProposal batches what is waiting when it runs, since CheckTx no longer blocks the client one-at-a-time. | Default build. Uses node 4's leaf (part A) and node 5/6/7's leaves (part B). Deliberately does NOT touch the PUMP batch. | Node 4/5/6/7 leaves claimed. PUMP batch untouched for `test_v2_epoch_boundary.sh`. | **DELTA 1 (verifier UNCOVERED FINDINGS 2 and 4, fixed).** `tx_count` counts APPLIED ENVELOPES only (`nodus_witness_v2_apply.c:4593-4595`); a raw claim never increments it, so the first cut's `tx_count > 1` assertion was structurally ALWAYS RED. Part A used to assert only height agreement, which a completely broken mempool gossip could still satisfy via idle CreateEmptyBlocks production alone — closed by asserting node4's own claim's `utxo_set` row exists. **DELTA 2, MEASURED:** both parts now wait for their ledger effect(s) with a progress bound and read the ACTUAL height(s), never `submission_tip + 1`. Part B's "same block" is no longer a hard requirement — three separate CLI submissions can legitimately land on different rounds (the same mechanism DELTA 2 measured for a single transaction); the assertion is a bounded spread (2 heights), logging an exact batch as the common case. Inclusion is asserted by the ledger effect, waited for with progress bounds — the interval between CheckTx and inclusion is not asserted. **DELTA 3 — confirmed safe from Defect 1** (both parts key on claim nullifiers, never `wire_id`). **DELTA 3, Defect 2:** both waits are also bounded by height (`MAX_HEIGHTS=20`), distinct from a stall — the same bound `test_v2_stake.sh` measured sitting 34 minutes without. |
| `test_v2_epoch_boundary.sh` | The chain crosses an epoch boundary at height `H=k*E_LEN` and freezes the snapshot for `epoch_start = H + E_LEN` (the one THIS crossing produces) byte-identically on all 7. | **Short-epoch binary, both halves:** `-DDNAC_EPOCH_LENGTH=<E>` + `STAGEF_EPOCH_LENGTH=<E>`. SKIPS at the shipped 720. | Whatever remains of the PUMP batch, opportunistically spent. Chain past >= 1 boundary. LAST leaf-spending scenario in the sweep. | **Reachability is now a WALL-CLOCK BUDGET (1 800 s default), not a leaf count** — pumped claims no longer land 1:1 per block (see "What flips" rule 4), so counting leaves cannot say whether the boundary is reachable in this harness's patience. Never parses `committed:`. Can take MINUTES even at the short-epoch convention if the pump batch is already spent — bounded by CreateEmptyBlocksInterval alone in that case. **DELTA 1 (verifier CLAIM 16, fixed):** the cross-node comparison used to read `epoch_start = next_boundary` — the row GENESIS ALREADY SEEDED on every node identically, which can never differ and proved nothing about the crossing (`nodus_witness_vset.c:658-659`: crossing H writes `epoch_start = H + E_LEN`, not `H`). Fixed to compare at `next_boundary + E_LEN`. |
| `test_cmt_arena_runway.sh` | The Comet receive-arena's fixed 64 MiB runway never approached its wall across the WHOLE sweep (neither one-shot latch — 50% WARN, 90% ERROR — fired on any node). **Must run LAST** — its subject is cumulative history. | Default build. Read-only; submits nothing. | Nothing. | **No per-block usage NUMBER exists to read from nodus-server** — `nodus_cmt_net_recv_arena_used()` has no caller in `nodus/src` or `nodus/tools` (DELTA 1, verifier CLAIM 17: it DOES have 7 callers, all in this build's own test binaries — `nodus/tests/test_cmt_net.c` and `test_cmt_live.c` — the earlier "no caller anywhere in this build" over-claimed); only the two one-shot latches are checked. A latch is one-shot PER PROCESS LIFETIME, so a node restarted mid-sweep (4, 5, 6) has a fresh flag from its last restart onward, not the whole sweep — disclosed, not hidden. **DELTA 3, MEASURED (recorded, not a fix — R3-A-5 is an open defect, not this scenario's):** on the fourth sweep both `[WRN/W_CMTNET] recv_arena at 50%` and `[ERR/W_CMTNET] recv_arena at 90% of its 67108864-byte runway` fired on node 1 by height ~347 — roughly 174 KB consumed per empty block at the measured ~6 s/block pace, so a node reaches the 64 MiB wall in about ONE HOUR of idle production at these constants. A sweep (or a manual run) left up that long will correctly go RED here — that is the open R3-A-5 arena-runway defect surfacing, not a false failure of this scenario. |

#### Legacy-only gates — there is no V2 counterpart, and that is the answer

Two scenarios in the tables above have **no Ledger V2 variant, by
construction**. Written down because the obvious next move is to port
them, and porting them would produce a scenario that tests nothing.

- **`test_bootstrap_mixed_version.sh` (H-9).** The check lives inside
  `nodus_witness_bootstrap_tick`, which returns immediately unless
  `bootstrap_state == DISCOVER`. A V2 node takes the HAVE_CHAIN branch
  (or the pinned-joiner INIT) and never enters DISCOVER, so the gate can
  never fire on it. Its purpose is narrower than its name suggests: it
  protects the legacy bootstrap from peers that would not understand T3
  types 16-19 — the legacy bootstrap messages themselves.
- **`test_bootstrap_cold_dr.sh` (C-4 / C-2 bypass).** The flag is read in
  `nodus_witness_bootstrap_handle_chain_q`, and that handler answers from
  `chain_tip_height`, which reads the LEGACY `blocks` table. On a V2
  chain that is always 0 and the handler returns before answering. A V2
  node has nothing to serve over that protocol whether the bypass is set
  or not.

**What plays their role on V2 is not a port of them:**

| Legacy protection | V2 equivalent | Covered by |
|---|---|---|
| C-2 cabal protection during DISCOVER | The **genesis pin**: a joiner adopts a peer's bundle only if it re-derives to the pin it holds locally | `test_v2_join.sh`, plus its wrong-pin negative control |
| H-9 mixed-version fail-fast | Two things, and both are stronger than a runtime detector: the T3 protocol-version gate on **every** frame (ctest `test_witness_protocol_version_gate`), and the economic build-identity refusal — a differently-built binary derives a **different chain id** and cannot join at all, rather than joining and being caught | ctest + `nodus_witness_v2_econ.c` |

The second row is the interesting one: on V2 a mismatched build does not
need to be detected at runtime, because it cannot produce the same chain
in the first place.

#### Needs a specially-built binary

| Script | Requires | Exercises |
|---|---|---|
| `test_epoch_settlement.sh` | `-DDNAC_EPOCH_LENGTH=<E>` + `STAGEF_EPOCH_LENGTH=<E>` | Push-per-epoch UTXO settlement. **Pumps TXs to cross a real boundary**, then asserts the boundary row committed, the pool DRAINED, payout UTXOs appeared, and state_root is 7/7. (Before 2026-08-27 it only slept, and passed vacuously on an idle chain — see the header in that file.) |
| `test_halving_boundaries.sh` | `-DDNAC_BLOCKS_PER_YEAR=<BY>` + `STAGEF_BLOCKS_PER_YEAR=<BY>` | Halving schedule cross-node consistency. SKIP (rc=99) when unset. Pumps across the boundary and measures credited emission; allow ≥ 20 min. |
| `test_vset_grow_shrink.sh` | **Compile flags — THREE, all of them:** `-DDNAC_EPOCH_LENGTH=<E>`, `-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=<E>`, `-DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=<E>`. No fault-injection build — `-DQGP_FAULT_INJECT` is **not** required, section G included. **Environment:** `STAGEF_EPOCH_LENGTH=<E>` matching the binary, exported **before `stagef_up.sh`** (`:52`), and `STAGEF_NODUS_BIN` (`:54`) which it uses to spawn nodes 8/9 and to restart the node section G kills. It does **not** read `STAGEF_CC_GRACE_SAFETY` / `STAGEF_CC_GRACE_ERGONOMIC` — here the two grace values matter only as compile defines; the env vars are read by the `test_cc_*` scenarios. It runs `nodus-cli` from a hardcoded `$STAGEF_REPO_ROOT/nodus/build/nodus-cli` (`:53`), so `STAGEF_NODUSCLI_BIN` does **not** redirect it. No `NODUS_FAULT_*`. | Ledger V2 S3 dynamic validator set 7 → 9 → 7 (sections A-F), then a **derived, deliberately killed epoch leader** the chain must rotate the view past (section G — see below). Spawns its own extra nodes (node8, node9) and leaves their directories behind, plus one committee node kill -9'd and restarted. **The grace defines are not optional**: at the production safety grace of 17,280 blocks the scenario's governance step is refused with `[ERR/CHAIN_CONFIG] apply: grace -- effective=45 < commit=7 + grace=17280`, surfacing at the client only as `dnac_spend RPC failed (rc=7)` (`NODUS_ERR_PROTOCOL_ERROR`) — a message that names neither grace nor the missing define. |
| `test_v2_grow_7_20.sh` | **The committee grows 7 → 14 → 20 by governance** — and it is the heaviest scenario in the suite. 13 funded strangers bond and become validators on a live chain; a vote raises the target (31, above the V2 ceiling of 30, is refused first); tenure (Rule R) gates selection so epoch 2E is still 7; the growth lands at epochs 3E and 4E, proven four ways (snapshot count, snapshot hash across all 20, the block header's validator-set digest changing, and the boundary block's certificate); then quorum is walked up and down, a full restart, a missed epoch, and a cold replay by a node that was never present. | **Needs `-DDNAC_EPOCH_LENGTH=15` + `-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15`, and `STAGEF_V2_CANDIDATES=13` exported BEFORE bring-up** (0 → skips). ~30 min. **Run LAST or standalone**: it leaves 13 extra nodes running, a permanent 20-node committee, every candidate leaf spent, and the chain past three boundaries. Joining is DHT-gated and takes MINUTES — the long waits are measured, not padding. ⚠ **FLAKY as of v0.19.48 — it passed one run and failed the next at STEP 6a**, same binary, same constants, clean cluster, no manual intervention. Treat a green run as one sample, not as a result; `feedback_no_flaky_blockchain` says "sometimes works" is a defect. FIVE consensus fixes went in first, every one invisible at N=7 and fatal at N=20 — a round needs `quorum` prevotes, and at 14 of 20 alive that is 14 of 14, so there is no slack for a stale round, a dropped early vote, or one peer whose signature cannot be verified. All five hold in the failing run (0 dropped votes, 0 signature failures). A SIXTH defect is underneath, and it is a **VIEW-boundary loss, not a round-numbering one** — the earlier "the round's identity is a node-LOCAL counter, so votes stop combining" reading is **contradicted by the measurement** and has been withdrawn: of 495 votes dropped at the stuck height only **9 were round-only mismatches**, while 486 (98%) involved a VIEW disagreement. Nodes cross a view boundary at different instants (each moves only on its own verified f+1 VIEW_OK proof) and every consensus frame is broadcast **exactly once**, so a node one view behind destroyed the new leader's PROPOSE — 45 refused as "round in progress", **35 of them from a view ahead of the refusing node**, at a gate sitting *above* the view gate, so it never reached the proof request that would have moved it — and every vote for that view. At 14 of 20 alive the quorum is 14 of 14, so one such node makes the round unwinnable: PREVOTE quorum was reached **74 times**, PRECOMMIT quorum **0 times**, commits **0**. It is not the dead-leader problem: of the 28 views that height passed through, 21 had a live leader that really opened a round. v0.19.49 parks the next view's PROPOSE and votes and replays them at the move, and restarts the P3 window there so the new leader gets the same grace P2 already gives it (`ctest test_bft_view_boundary`). **This scenario has NOT been re-measured since; treat the FLAKY label as standing until a run says otherwise.** Measurements in `nodus/BUGS.md` under the N=20 entry. |
| `test_mixed_version_reject.sh` | `STAGEF_LEGACY_NODUS_BIN` | O15C-D.4 — a stale-protocol validator must not participate. **Proves it by ARITHMETIC:** one node is swapped to the legacy binary and two current nodes are stopped, so the live set is 4 current + 1 legacy = quorum; if the stale vote counted the chain would advance, so it must STALL and then RESUME when a current node returns. ⚠ **Which side logs `INCOMPATIBLE PEER` depends on the legacy binary you build**, and the anti-vacuity check accepts either: a pre-v3 binary has no gate and keeps talking (the CURRENT nodes refuse it), while any v3+ binary carries the gate, drops every current frame on arrival and never votes (only the LEGACY node logs refusals — measured 2026-09-01, v4 vs v6: 33 on the legacy node, ZERO on the six current). Demanding a current-side refusal made the scenario UNPASSABLE with a modern legacy binary; fixed 2026-09-01 together with a `grep -c \|\| echo 0` bug that produced a two-line count and killed every numeric test on it. **Only a pre-gate legacy binary exercises the CURRENT node's gate** — that path is otherwise covered by `ctest test_witness_protocol_version_gate` §2/§3. |

#### `test_view_change_fork.sh` — the paused epoch leader

**What it proves.** That pausing the validator the cluster has **PROVEN
is its current epoch leader** does not fork the chain: the survivors
rotate the view away from it, commit new work without it, and it
re-converges to the same `state_root` when it resumes. The property that
would be false if it failed: *a BFT chain can make progress while its
designated leader is unresponsive, and the leader can rejoin without
divergence.* The full argument is in the script's own header (`:1-177`);
this is the summary the tables owe it.

Phase B is the whole scenario. It derives the leader for the epoch of
**head + 1** (`:261-392`), cross-checks the derived entry against the
node's own fingerprint (`:394-412`), `SIGSTOP`s exactly that node, and
then decides on a **truth table over two independent facts** (`:519-579`):
did a view-change quorum complete, and did a transaction commit? Only
*both* is a pass; the other three combinations each fail with their own
diagnosis, because they fail for different reasons.

⚠ **What it no longer does: pass having exercised nothing.** Until
2026-09-02 it stopped a **hardcoded node 1**. The leader is
`(epoch + view) % n` (`nodus_witness_bft.c:1195-1198`) over a committee
ordered by stake then by a `state_seed`-derived tiebreak, over identities
generated fresh on every run — so whether node 1 held that slot was a
coin flip. When it did not, no view change was required and a passing run
printed `view-change activity on 0 nodes` and `C5 reproposal activity on
0 nodes` immediately before `[PASS]`. The script said so out loud
("proceeding anyway — the original leader may still be node 1's slot"),
which read as tolerance but was the scenario conceding it did not control
its own subject. Both halves are now gone: the victim is DERIVED, and the
concession is an assertion.

**What it requires.** A default `nodus/build` binary — no compile flag of
its own, no fault-injection build, no `NODUS_FAULT_*`. **One new
requirement:** `STAGEF_EPOCH_LENGTH` must MATCH the binary's
`DNAC_EPOCH_LENGTH`, because the leader rank is derived from the epoch
ordinal. At the defaults (both 720) that is automatic and the scenario
stays "plain"; on a short-epoch campaign the `-D` and the env var must
agree. A mismatch **cannot produce a false green** — it pauses an
innocent follower, the real leader keeps producing, no view change forms,
and Phase B fails with the epoch, view and victim printed.

**What it leaves behind.** One committee node `SIGSTOP`ped and then
`SIGCONT`ed — **a different one on every run**, so it is printed. It
keeps its original pid (no restart, unlike section G's `kill -9`), and an
`EXIT` trap resumes it on every early exit. The cluster is left at a
**higher `current_view`** and with one extra funded user under
`$BASE_DIR/tusers/`.

**How it can lie.**

- **The idle window proves nothing, and it is not asserted.** The 90 s
  between the `SIGSTOP` and the funding send **cannot** observe a
  rotation: with an empty mempool the P3 deadman does not arm at all
  (`nodus_witness_bft.c:11986`; the comment at `:12084-12089` states it
  outright). A measurement of "0 of 6 reached view-change quorum in 90 s"
  taken in **that** window is the predicted behaviour, not a defect. The
  window is kept and REPORTED; the assertion is taken after the first
  demand arrives.
  ⚠ **Do not "fix" it by raising the 90 s** — a bigger idle window is
  still an idle window. And do not add a transaction pump to make it
  productive without deciding, deliberately, that the scenario should
  test something else.
- **Stale log lines.** `test_med28_reproposal.sh` and
  `test_newview_convergence.sh` both force view changes and both sort
  BEFORE this file in the alphabetical sweep, so `grep -q "view change
  quorum"` is **vacuously true** — it was, in the version this replaced.
  Every count is now a BEFORE/AFTER delta; only an INCREASE is evidence.
- **A pass means the REAL leader was paused**, not merely that node 1
  was. That rests entirely on the derivation and on the `voter_id` ↔
  fingerprint cross-check that guards it. Remove the cross-check and a
  wrong-bytes read would signal an innocent node.
- **View or epoch drift redirects leadership — residual, not closed.**
  The window before the pause IS closed (head and view re-read, derivation
  re-run twice, and a survivor already holding a higher view is a
  FAILURE). After the funding TX arrives a round timeout can still rotate
  the view and hand leadership elsewhere, and the scenario then fails on a
  healthy chain. Made diagnosable instead: every failure prints the
  pre-pause and post-pause views and heights.
- **A dead reference node.** Every single-node read goes through
  `$REF_NODE`, re-pointed off the victim before the signal.
- **`rc=99` is BANNED here**, for the same reason as in section G: the
  runner treats 99 as SKIP and a SKIP needs no `ASSERT_RUN`.
- **A known false-FAIL residual — `SIGSTOP` is not `kill -9`, and the
  client notices.** It cannot produce a green, only a misattributed red.
  `nodus_client_connect` tries the bootstrap list **in config order**
  (`nodus_client.c:663-679`) and `stagef_up.sh` writes node1 first. A
  SIGSTOPped process still holds its listening socket, so the kernel
  completes the handshake and the **connect succeeds** — then the HELLO
  times out (`connect_timeout_ms`, default 5000, `:621-622`, `:768`).
  Section G is immune: `kill -9` closes the socket and the connect is
  refused at once. So when the derived victim IS node1, the funding TX
  can be delayed or lost client-side and the cluster never sees demand.
  Not new — the previous version paused node1 on **every** run and its
  funding step was observed to succeed, so the client does recover in
  practice. Phase B's failure branch **splits on the P3 delta** to keep
  the two apart: `P3 +0` means the cluster never saw demand (suspect this
  residual and read `tusers/vcfork_*/fund.log`); `P3 > 0` means demand was
  seen and the rotation still did not converge — that one is the
  consensus finding.
- **Known gaps, recorded not hidden:** it records **no reachability
  sentinels**, so the runner classifies it UNINSTRUMENTED and cannot
  convert a vacuous PASS into a failure for it (every path to `[PASS]`
  now runs through the truth table, but the runner does not know that);
  Phase C still waits with a blind `sleep 30`; and Phase D's
  `stagef_diff.sh` compares each node's LATEST block, so a node one block
  behind reads as divergence rather than lag.

#### `test_vset_grow_shrink.sh` section G — the dead epoch leader

The last section of the last scenario, and the harness's only
**`kill -9`** of a node it has PROVEN is the leader — where
`test_view_change_fork.sh` above `SIGSTOP`s one and resumes it. The two
now share ONE derivation (`stagef_leader_entry` in `stagef_env.sh`);
before 2026-09-02 only G had it, and the fork test killed a hardcoded
node 1. G's full argument lives in the script's own header (`:779-896`);
this is the summary the scenario tables owe it.

**What it proves.** That a chain whose designated EPOCH LEADER is killed
recovers by ROTATING THE VIEW past it. The property that would be false
if G failed: *a BFT chain can make progress across an epoch boundary
whose designated leader is dead.* It is pinned by three independent
positive checks, all captured while the victim is still dead
(`:1046-1118`):

1. a follower's demand-armed **P3 deadman FIRED** — the count of
   `P3 committed tip frozen` across every node log INCREASED;
2. a **view change COMPLETED** — the persisted `pbft_state.current_view`
   (max over the survivors) advanced **and** some node logged
   `view change quorum! new view:`. Both are required: the number alone
   cannot say where the rotation came from;
3. **leadership genuinely moved** — no block in
   `[NEXT_B, NEXT_B + E_LEN)` carries the victim's 32-byte witness id in
   `blocks.proposer_id`, guarded by a non-vacuity check that the range
   is non-empty.

Then, as before, the restarted node re-converges to byte-identical
snapshots, `state_root` and block identity.

⚠ **What it no longer does: pass because the chain crossed the
boundary.** Until 2026-08-27 G killed a **hardcoded node 4** and asserted
only that blocks kept coming. The leader is `(epoch + view) % n` over a
committee ordered by stake DESC then by a `state_seed`-derived tiebreak,
over identities generated fresh on every run — node 4 was the boundary
leader only by luck, and "the chain crossed the boundary" is fully
compatible with "the victim was never the leader". The victim is now
DERIVED: read positionally out of the frozen `validator_set_snapshots`
row for `epoch_start == NEXT_B` at entry
`(NEXT_B / E_LEN + current_view) % active_count`, then cross-checked
against the node's own `nodus.pk` fingerprint prefix (`:896-995`).
Crossing the boundary is now a PRECONDITION, not the assertion.

The geometry checks and the positional slice themselves live in
`stagef_env.sh` as `stagef_leader_entry` (`:543`) since 2026-09-02, shared
with `test_view_change_fork.sh`. G still owns everything around the call
— the bounded snapshot re-read, the two-attempt view pin, the `REF_NODE`
re-point, the fingerprint cross-check and every `fail` — so a change to
the shared function can only make the derivation refuse, never make G
assert less.

**What it requires.** Nothing beyond the row above — the same
short-epoch build (three defines) and `STAGEF_EPOCH_LENGTH` exported
before bring-up. **G adds no compile flag and no environment variable of
its own**; it needs no fault-injection build. It DOES require that
sections A-F ran in the same process: G consumes the 9-bonded /
7-active cluster they build and the head they leave.

**What it leaves behind.** One committee node `kill -9`'d and restarted
under a NEW pid (appended to `pids.txt`; its `nodus.log` is appended to,
not truncated, so it holds two runs). **Which node that is VARIES PER
RUN** — it is derived from fresh identities, so it is printed, and it
may be node1. The chain is left a few blocks past the boundary at a
**permanently higher `current_view`** (`current_view` never resets and is
persisted per chain DB), with the post-shrink 7-ACTIVE / 2-ELIGIBLE set
from section F. Nothing is cleaned up.

⚠ **Since O15L the restart can leave the victim RUNNING WITHOUT its
witness role.** `kill -9` leaves the dying process's WAL lock behind, and
the restarting node now waits it out over three attempts sharing one
`NODUS_W_DB_BUSY_TIMEOUT_MS` budget (`nodus_witness.c:355-407`). If the
open still fails, `nodus_witness_init` REFUSES rather than pretending to
be pre-genesis (`:1347-1367`), and `nodus_server_init` keeps the process
alive as a DHT-only node instead of exiting
(`nodus_server.c:6114-6169`). So a failed G.5 can leave a node that is
**up, serving DHT traffic, and casting no vote** — and `running_nodes()`
reads *directories*, not live witnesses, so the next scenario counts it
as a participant.

**How it can lie.**

- **The pump cannot see this halt.** `pump_to_height` fails only after
  `PUMP_STALL_ROUNDS=8` consecutive no-progress rounds (~5 min at the
  measured ~37 s/round), while the deadman fires at
  `NODUS_T3_ROUND_TIMEOUT_MS` = 15 s and a rotation converges well
  inside a minute. Pump success is therefore **not** evidence and is not
  asserted as such. Delete the three positive checks and G silently
  reverts to a liveness test that cannot observe the thing it is named
  for.
- **Stale log lines.** Every line G looks for already exists when G
  starts — `test_view_change_fork.sh` deliberately forces view changes
  and sorts earlier. G compares BEFORE/AFTER counts and requires an
  INCREASE; "simplifying" any of them to `grep -q` makes them vacuously
  true.
- **View drift redirects leadership — RESIDUAL, NOT CLOSED.** The
  derivation is only as good as the view it used. The window BEFORE the
  kill is closed (re-read and re-derive, twice, then fail; plus a check
  that no survivor already holds a higher view than the node the
  derivation read). The window AFTER cannot be closed from outside the
  node: a round timeout while the victim is dead rotates the view and
  hands leadership to somebody else, and G then **fails on a healthy
  chain**. It is made DIAGNOSABLE instead — the pre-kill and
  post-boundary views are printed in every failure message.
- **A victim that maps to no node, or a missing snapshot row.** An
  absent `validator_set_snapshots` row for the boundary epoch (after a
  bounded re-read), a blob whose length disagrees with `active_count`,
  or a derived leader that is none of this harness's nodes are all
  **FAILURES**. G must not pump to produce the row — pumping is exactly
  what would carry the head past the boundary it needs to arrive at with
  a dead leader.
- **`rc=99` is BANNED in G.** The runner treats 99 as SKIP and exits 0
  with SKIPs allowed, and a SKIP needs no `ASSERT_RUN` sentinel — so
  encoding any of the preconditions above as a skip would make this
  coverage silently absent while the suite reported green. A skip is not
  a pass.
- **A dead reference node.** Every single-node read goes through
  `$REF_NODE`, re-pointed off the victim before the kill. The old
  catch-up loop compared node1's height against the victim's, so with
  `victim == node1` both sides would read the SAME database and the
  comparison would be trivially true. Reintroduce a raw node1 read here
  and that returns.
- **G.5's catch-up assertion reports a restart fault as a sync failure,
  and that has already cost one diagnosis.** The final step waits up to
  300 s for the victim's `blocks` table to reach `$REF_NODE`'s height and
  then says `node$victim did not catch up (vh < ref_h)` (`:1140-1149`).
  That message names a symptom, never a cause. Before O15L a restart
  that lost the SQLite race came back reporting `chain_db=active` with a
  **zeroed chain_id**, could not verify a single certificate, and
  surfaced here as exactly that line — which is how the CRITICAL entry at
  the top of `nodus/BUGS.md` was found. Today the lock is waited out and,
  if it still fails, the node prints `REFUSING START` and a multi-line
  degraded-mode `ERROR:` block instead of failing silently. The
  assertion is unchanged and still correct; **when it fires, read the
  victim's `nodus.log` before suspecting consensus.**
- **A known false-FAIL residual** (it cannot produce a green): the pump
  submits through `dna-connect-cli`, and the victim is one of the nodes
  that CLI may connect to. All committee nodes are in `bootstrap_nodes`
  and `stagef_dna` rebuilds the list before every call, so there are
  failover candidates — but the failover ORDER is not verifiable from
  the script. If the pump stalls immediately after the kill with the
  cluster otherwise healthy, suspect this before suspecting consensus.

#### Needs a fault-injection build (`-DQGP_FAULT_INJECT=ON` + `NODUS_FAULT_*`)

Export the fault vars **before `stagef_up.sh`**, and `rm -f` the arm file
**between** scenarios — each arms it itself and refuses to start if it
already exists.

| Script | Extra vars | Exercises |
|---|---|---|
| `test_med28_reproposal.sh` | arm file absent at start | MED-28 end-to-end: a failed round's batch is RETAINED and repropose-able |
| `test_newview_convergence.sh` | `DROP_TYPE=precommit`, `DROP_VIEW=0`, `DROP_VC_ROTATE≥1` | O15C-D.3 — NEW_VIEW convergence under genuinely different VIEW_CHANGE subsets |

#### Negative control — NOT part of any sweep

| Script | Why |
|---|---|
| `test_med28_negative.sh` | Proves the MED-28 scenario depends on the repair, by running the SAME injection against a build with the retention call REMOVED. It is **driven manually against a throwaway neutralized build in /tmp**, never the worktree. Against a healthy build it FAILS with "a node retained a batch — this build is NOT neutralized", and that failure is the CORRECT result. Never add it to an automated run. |

#### Self-skipping

| Script | Why |
|---|---|
| `test_supply_invariant_halt.sh` | rc=99. It halts nodes with no recovery path, so it needs its own disposable cluster rather than the shared one. The gate itself is covered by ctest `test_witness_state_root_failclose` + `test_supply_invariant`. |

#### Order matters — scenarios share one live cluster

They are **not** independent. Running them back-to-back leaves residue
that makes later ones fail for reasons that have nothing to do with the
code under test. Observed, and each cost real debugging time:

- `test_bootstrap_join_live.sh` leaves a **node8** directory behind. The
  next `test_vset_grow_shrink.sh` counts it (its `running_nodes()` reads
  *directories*, not live processes), sees it at height 0, and fails with
  `nodes did not converge (lo=0 hi=27)`.
- Any armed fault scenario leaves `NODUS_FAULT_ARM_FILE` in place, and
  the next one aborts with "arm file already exists".
- **A scenario that COMPLETES a view change disarms the next scenario
  whose injection is view-scoped.** `NODUS_FAULT_DROP_VIEW` pins the
  drop to one view number (`nodus_witness_fault.c`), and both
  `test_med28_reproposal.sh` and `test_newview_convergence.sh` use
  `DROP_VIEW=0`. But `test_newview_convergence.sh` exists to force a
  rotation and reports *"view change completed on 7/7"* — so a cluster
  that has run it is no longer at view 0, the predicate cannot match,
  and med28 fails at `[FAIL] no node logged a round timeout — the
  injection did not bite`. Observed 2026-08-29; the same run passed end
  to end (`round timeout on 6/7`) on a fresh cluster. Either bring the
  cluster up fresh between the two, or run the view-scoped one FIRST.
  The alphabetical sweep is safe by luck — `med28` sorts before
  `newview` — so this bites hand-picked runs, not `genesis_protocol.sh`.
- Bootstrap scenarios restart nodes; a scenario run immediately after may
  see a node still syncing and report a false divergence.
- `test_view_change_fork.sh` now pauses and resumes the node it DERIVES
  as the current epoch leader — a **different one on every run** — and
  therefore leaves the cluster at a **higher `current_view`** than it
  found it, plus one extra funded user under `tusers/`. It sorts before
  `test_vset_grow_shrink.sh`, whose section G is written for exactly that
  (G counts view-change log lines as BEFORE/AFTER deltas, never as
  presence, and reads `current_view` rather than assuming 0). Before
  2026-09-02 it paused a hardcoded node 1 and this was only *sometimes*
  true; it is now guaranteed on every run.
- `test_vset_grow_shrink.sh` **section G** kills and restarts one
  committee node — a DIFFERENT one on every run — and leaves the cluster
  at a permanently higher `current_view`. It sorts last, so nothing
  inherits it inside one sweep; anything you run manually afterwards
  does.

Bring the cluster up fresh for a scenario whose result you intend to
trust, or clean the specific residue named above.

#### Order matters on the Comet lane too (R3 W3, C2d)

The ten Comet scenarios are order-INDEPENDENT of each other's LEAVES by
construction (each spends only its own genesis allocation), but not of
each other's TIMING or LOG STATE. `genesis_protocol_v2.sh`'s list is an
explicit order for exactly these reasons — see its own header for the
full reasoning; the residue worth knowing if you run scenarios by hand:

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
- **DELTA 1 correction:** `test_cmt_mempool_flood.sh` does NOT share the
  PUMP identity's leaf batch with `test_v2_epoch_boundary.sh` — it
  spends node 4/5/6/7's own leaves. The two do not compete for anything;
  `test_v2_epoch_boundary.sh` is the only scenario that reaches for PUMP
  leaves at all.
- `test_cmt_arena_runway.sh` must run LAST, unconditionally — its
  subject is the CUMULATIVE usage every other scenario in the sweep has
  already produced on every node. Running it earlier reads a partial
  history and understates whatever the full sweep would show.
- **DELTA 3, MEASURED — a sweep (or any manual run) left up longer than
  ~1 hour of idle production trips the R3-A-5 receive-arena runway.**
  Both latches fired on node 1 by height ~347 at the measured ~6 s/block
  pace (≈174 KB per empty block against the 64 MiB / 67108864-byte
  runway). `test_cmt_arena_runway.sh` will (correctly) go RED in that
  case — that is the OPEN R3-A-5 defect surfacing, not a false failure
  of the scenario or an ordering mistake. Keep a full sweep, or any
  manual sequence of scenarios run back to back, well under an hour of
  total wall time if a green `test_cmt_arena_runway.sh` result is meant
  to say something.

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
   (`-DQGP_FAULT_INJECT=ON`, `-DDNAC_EPOCH_LENGTH=<E>`, …) and the
   **environment** the scripts read (`STAGEF_*`, `NODUS_FAULT_*`),
   including anything that must be exported before `stagef_up.sh`.
   If it runs on a plain default build, say that explicitly.
3. **What it leaves behind**, if anything — extra node directories, an
   arm file, restarted nodes, a halted cluster. Whoever runs the next
   scenario inherits it.
4. **How it can lie.** If there is a way for it to report PASS without
   having exercised its subject (an idle chain, an unset knob, a skipped
   assertion), write that down. The rc=99 skip path counts.

Put the same four in the script's own header comment. The README says
which scenario to reach for; the header tells whoever is already in the
file why it is shaped the way it is.

Why this is a rule and not a suggestion: `test_epoch_settlement.sh` slept
instead of pumping and passed for years by comparing a height against
itself; `test_newview_convergence.sh`'s header named an environment
variable (`NODUS_FAULT_DROP_VC_FROM`) that has never existed in the
source; and 12 of the 24 scripts here had no README row at all. Each cost
a debugging session that the missing line would have saved. See the root
`CLAUDE.md` documentation rule — docs land in the SAME commit.

Template:

```bash
#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"

# 1. pre-TX baseline (optional)
bash "$(dirname "$0")/../stagef_diff.sh" "pre-<label>"

# 2. submit TX via dna-connect-cli or nodus-cli
"$STAGEF_DNACLI_BIN" ... submit ...

# 3. post-TX assert state_root identical 7/7
bash "$(dirname "$0")/../stagef_diff.sh" "post-<label>"

echo "[PASS] <test name>"
```

Exit code contract (enforced by `genesis_protocol.sh`):

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
  these when a test fails — state_root divergence usually leaves a
  trail.
- Committee is 7 (quorum 5). Matches production BFT size so
  quorum-edge bugs reproduce.

## ⚠ WHAT A GREEN HARNESS RUN DOES **NOT** PROVE

**The harness runs the chain at parameters the production chain does not
use.** Several scenarios are only reachable at all because the binary was
compiled with small values in place of the shipped ones:

| Parameter | Production | Harness | Why the override exists |
|---|---|---|---|
| `DNAC_EPOCH_LENGTH` | **720** (~1 h) | 15 | 720 blocks at the harness's real pump rate is a ~7 h scenario |
| `DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS` | **17280** (~24 h) | 15 | no governance change could ever take effect inside a test run |
| `DNAC_BLOCKS_PER_YEAR` | **6307200** | 20 | the first halving sits 6.3 M blocks out — unreachable |

So a green `test_vset_grow_shrink`, `test_epoch_settlement` or
`test_halving_boundaries` says: **the LOGIC is correct — governance takes
effect at the boundary, the pool drains, the set grows and shrinks, the
emission halves, and every node agrees.** It does **not** say the chain is
correct at 720 / 17280 / 6307200. Anything that could depend on the
magnitude of those numbers — arithmetic that overflows only at large
heights, a window that is wide enough at 15 and not at 720, an off-by-one
that hides when epoch and grace happen to be equal — is **outside what
this harness has ever exercised**.

Two consequences, both load-bearing:

1. **Never quote a harness result as production readiness** without
   naming the parameters it ran at. "7/7 state_root at epoch length 15"
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

The worked example is `test_vset_grow_shrink.sh` **section G**: with the
epoch leader dead by design every round waits out a missing vote
(measured ~63 s/block against ~37 s on a healthy cluster), so the
scenario failed repeatedly with the chain advancing normally and each
failure invited another number bump. A raised pump budget would have
turned a genuine dead-leader halt into a green. The fix was to assert
PROGRESS (`PUMP_STALL_ROUNDS`) and to condition the PASS on positive
rotation evidence — never on the pump finishing.

### R3 W3 (C2d) — what a green COMET run does not prove, additionally

Everything above this line still applies to the Comet lane (it inherits
the shared consensus layer, and the epoch-length / grace-block override
table is unchanged — `test_v2_epoch_boundary.sh` needs the same
short-epoch build the legacy `test_epoch_settlement.sh` did). FIVE MORE
things a green Comet-lane run does not say:

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
2. **One machine, one validator paused at a time.** Same limitation the
   legacy lane always had (see below) — `test_cmt_dead_proposer.sh`
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
  proxies are process signals against a **derived** leader:
  `test_view_change_fork.sh` (`SIGSTOP` + resume, legacy lane, CLOSED)
  and `test_vset_grow_shrink.sh` section G (`kill -9` + restart, legacy
  lane, CLOSED) — and, on the live Comet lane, `test_cmt_dead_proposer.sh`
  (`SIGSTOP` + resume, no derivation needed or possible — see its own
  header) and `test_v2_restart_convergence.sh` (`kill -9` + restart).
  None of the four produces a partition: the rest of the cluster stays
  fully connected, so a conflicting-prepared-cert fork is still out of
  reach on either lane.
- **Legacy lane (CLOSED): a dead leader on an IDLE chain never triggers a
  view change**, by design (`nodus_witness_bft.c:11986`). Any liveness
  property involving a missing leader had to be measured with demand
  pending, or it measured nothing. **Comet lane: this no longer applies**
  — see "What flips on the Comet lane" item 2; a round times out and
  rotates whether or not demand exists, because CreateEmptyBlocks means
  there is always "work" for a round to be about.
- `test_halving_boundaries` needs `STAGEF_BLOCKS_PER_YEAR=20` (or
  similar) AND a binary compiled with the matching
  `-DDNAC_BLOCKS_PER_YEAR`; default skips it.
- `test_supply_invariant_halt` halts nodes with no recovery path, so it
  needs its own disposable cluster; it skips on the shared one.
- Scenarios share one live cluster and are **not** order-independent —
  see the residue list under **Scenario tests**, and see
  `genesis_protocol_v2.sh`'s own header for the Comet lane's order
  constraints (`test_cmt_empty_blocks.sh` first,
  `test_cmt_arena_runway.sh` last, `test_cmt_mempool_flood.sh` before
  `test_v2_epoch_boundary.sh`).
- **Legacy lane (CLOSED): the chain produces no blocks while idle**, so
  no scenario could reach a future height by sleeping; it had to pump
  transactions. **Comet lane: FALSE** — see "What flips on the Comet
  lane" item 1. A scenario CAN reach a future height by waiting alone
  (`test_cmt_empty_blocks.sh` is built entirely on this), but a wait
  must still be bounded by PROGRESS (`stagef_cmt_wait_height`'s stall
  detection), never a bare `sleep` for a fixed duration — the fact that
  waiting alone eventually works is not permission to stop bounding how
  long it is allowed to take.

## When the runner reports FAIL

Because `genesis_protocol_v2.sh` echoes the failing test's full stdout
(no tail), the triage flow is:

1. Find the `--- begin full output ---` block in the runner output.
2. Look for the first `[FAIL]` line or the error that exited non-zero.
3. If the failure references `state_root` (legacy) or `global_root` /
   `block_id` (Comet), diff the per-node witness DBs under
   `$BASE_DIR/node$N/data/witness_*.db`.
4. Logs at `$BASE_DIR/node$N/nodus.log` show BFT phase transitions
   (`WITNESS-BFT: ...`, legacy lane) or Comet lines (`chain role:
   COMETBFT`, `cometbft lane LIVE`, `ABCI replay blocks:`) and reject
   reasons.
5. **DELTA 1, Comet lane only:** `genesis_protocol_v2.sh` Phase 4 KEEPS
   `$BASE_DIR` (does not `rm -rf` it) whenever any scenario in the sweep
   FAILED — only stops the processes. The result block prints the kept
   path (`logs kept at ...`); a fully green run tears down as normal, so
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
