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

# Run the full protocol (ctest + bring-up + all scenarios + teardown)
bash /opt/dna/nodus/tests/integration/stagef/genesis_protocol.sh
```

Exit code 0 = green, 1 = any scenario FAIL. Full stdout of any
failing test is echoed unbounded — no tail, no grep, no filter.

## `genesis_protocol.sh` runner

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
> (`test_vset_grow_shrink.sh:85`, `test_epoch_settlement.sh:88`).

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
3. **Phase 3** — every `tests/*.sh` in alphabetical order (24 scripts on disk). Per-test `bash <script>`, exit-code only. Note that running the whole directory blindly is NOT a clean sweep: `test_med28_negative.sh` is a negative control that must fail on a healthy build, `test_v2_grow_7_20.sh` is currently broken by design, several scenarios need a differently-compiled binary, and the order effects listed under **Scenario tests** apply.
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
| `genesis_protocol.sh` | Top-level runner: ctest + bring-up + all scenarios + teardown. Exit-code-only assertion. |
| `stagef_up.sh` | Generate identities + spawn 7 nodus-server + wait peer mesh + submit genesis + fund user |
| `stagef_down.sh` | Kill PIDs + rm -rf the run dir |
| `stagef_diff.sh` | Read state_root from each node's witness DB, assert identical across the 7, print |
| `stagef_env.sh` | Sourced by other scripts; exports `BASE_DIR`, ports, pubkey file paths, `STAGEF_*` overrides |

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
| `test_view_change_fork.sh` | C5 view-change + partial-participation safety → state_root converges 7/7 |
| `test_funding_stability.sh` | Funding-stability proof (O15C-D.1 §5) against the OPEN harness-instability record |
| `test_bootstrap_cold_dr.sh` | C4 `--cold-bootstrap` operator escape; C-2 cabal-bypass behaviour |
| `test_bootstrap_join_live.sh` | Witness bootstrap join-live + orphan recovery. **Adds a node8 to the cluster** |
| `test_bootstrap_mixed_version.sh` | H-9 mixed-version fail-fast: a node in DISCOVER detects an incompatible peer |
| `test_bootstrap_partial_wipe.sh` | H-10 partial-wipe XOR boot gate (E5): `nodus_server_init` must refuse to start |
| `test_bootstrap_replay_attack.sh` | C-4 nonce-mismatch replay rejection (drives an in-process unit test) |

#### Needs a specially-built binary

| Script | Requires | Exercises |
|---|---|---|
| `test_epoch_settlement.sh` | `-DDNAC_EPOCH_LENGTH=<E>` + `STAGEF_EPOCH_LENGTH=<E>` | Push-per-epoch UTXO settlement. **Pumps TXs to cross a real boundary**, then asserts the boundary row committed, the pool DRAINED, payout UTXOs appeared, and state_root is 7/7. (Before 2026-08-27 it only slept, and passed vacuously on an idle chain — see the header in that file.) |
| `test_halving_boundaries.sh` | `-DDNAC_BLOCKS_PER_YEAR=<BY>` + `STAGEF_BLOCKS_PER_YEAR=<BY>` | Halving schedule cross-node consistency. SKIP (rc=99) when unset. Pumps across the boundary and measures credited emission; allow ≥ 20 min. |
| `test_vset_grow_shrink.sh` | **FOUR** defines, all four matching env vars: `-DDNAC_EPOCH_LENGTH=<E>`, `-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=<E>`, `-DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=<E>` (+ `STAGEF_EPOCH_LENGTH`, `STAGEF_CC_GRACE_SAFETY`, `STAGEF_CC_GRACE_ERGONOMIC`) | Ledger V2 S3 dynamic validator set 7 → 9 → 7. Spawns its own extra nodes (node8, node9) and leaves their directories behind. **The grace defines are not optional**: at the production safety grace of 17,280 blocks the scenario's governance step is refused with `[ERR/CHAIN_CONFIG] apply: grace -- effective=45 < commit=7 + grace=17280`, surfacing at the client only as `dnac_spend RPC failed (rc=7)` (`NODUS_ERR_PROTOCOL_ERROR`) — a message that names neither grace nor the missing define. |
| `test_v2_grow_7_20.sh` | **BROKEN — do not run** | Wants `-DNODUS_V2_ACTIVATION=ON`, an option deleted with the activation ceremony (O15J Faz 3). Rewriting it is Faz 4's job. |
| `test_mixed_version_reject.sh` | `STAGEF_LEGACY_NODUS_BIN` | O15C-D.4 — a stale-protocol validator must not participate |

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
- Bootstrap scenarios restart nodes; a scenario run immediately after may
  see a node still syncing and report a false divergence.

Bring the cluster up fresh for a scenario whose result you intend to
trust, or clean the specific residue named above.

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

## Known limitations

- Requires cluster to start from genesis — cannot replay an existing
  chain into the harness.
- Single machine — can't catch true network-partition bugs (see
  `test_view_change_fork.sh` for the closest proxy via view change).
- `test_halving_boundaries` needs `STAGEF_BLOCKS_PER_YEAR=20` (or
  similar) AND a binary compiled with the matching
  `-DDNAC_BLOCKS_PER_YEAR`; default skips it.
- `test_supply_invariant_halt` halts nodes with no recovery path, so it
  needs its own disposable cluster; it skips on the shared one.
- Scenarios share one live cluster and are **not** order-independent —
  see the residue list under **Scenario tests**.
- The chain produces no blocks while idle, so no scenario can reach a
  future height by sleeping; it must pump transactions.

## When the runner reports FAIL

Because `genesis_protocol.sh` echoes the failing test's full stdout
(no tail), the triage flow is:

1. Find the `--- begin full output ---` block in the runner output.
2. Look for the first `[FAIL]` line or the error that exited non-zero.
3. If the failure references `state_root`, diff the per-node witness
   DBs under `$BASE_DIR/node$N/data/witness_*.db`.
4. Logs at `$BASE_DIR/node$N/nodus.log` show BFT phase transitions
   (`WITNESS-BFT: ...`) and reject reasons.

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
