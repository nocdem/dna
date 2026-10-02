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
   register R3-W3-C2a-19): envelopes ≤ `NODUS_V2_ENV_BATCH_MAX` (3 075
   since general multisig grew the auth verdict — 3 209 before;
   a derived MEMORY ceiling since delta 2 — 64 MiB scratch budget /
   21 824 B per envelope — FROZEN at 3 075 by HF-2, budget 65 MiB for
   21 856 B; NOT the governance hard cap of 10 delta 1
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
quote, out of this delta's whitelist to fix). (`test_v2_grow_7_20.sh`
used to be the one exception — it grepped `^committed: height=`; its
Comet conversion (GROW-7-20-COMET, own row below) reads ledger effects
instead and parses no such line.)

## P2P-PORT F6 — the 4004 mesh on the new stack

The witness port (4004) is a literal port of cometbft's p2p layer
(`docs/plans/2026-09-26-p2p-port-design.md`). A node dials only its
**persistent peers** (`id@ip:port`, the ID pinned); the DHT `nodus:pk`
roster the old transport found its peers through is deleted. The harness
therefore gives every node ONE published **network file**,
`$BASE_DIR/network.json` (decision
`docs/plans/decisions/2026-09-26-witness-port-session.md` "Ağ config
dosyası"):

```json
{
  "v2_genesis_pin": "<64 hex — the chain id>",
  "persistent_peers": ["<p2p id>@127.0.0.1:14004", "...", "<p2p id>@127.0.0.1:14064"]
}
```

named by the `"network_file"` key of `$BASE_DIR/nodus.json` — which EVERY
start and restart in this harness already passes with `-c`, so restart
scenarios (`test_v2_join.sh`, `test_v2_partial_wipe.sh`,
`test_v2_restart_convergence.sh`, `test_cmt_hf1_gas_upgrade.sh`, GROW)
pick it up with no change of their own. The p2p IDs come from
`nodus-cli -i <identity> whoami`'s `P2P ID:` line (`stagef_p2p_id`,
`stagef_env.sh`), never guessed. The pin starts EMPTY: `stagef_up_v2.sh`
runs every ceremony with `-c nodus.json`, node 1's derivation WRITES the
chain id into the file (pin-auto) and nodes 2..7 find it equal — asserted.
A node holding a chain whose id differs from the file's pin refuses to
start; a node with no chain joins by it (exactly `--v2-genesis-pin`).

**HARNESS-ONLY settings, also in nodus.json:** `"allow_duplicate_ip":
true` (every node is 127.0.0.1 — reference `config.go:601`, "test only")
and `"addr_book_strict": false` (loopback addresses are not routable under
the strict rule). A production node never carries either.

**Older servers.** The file is passed as a JSON key, never as
`--network-file` on the command line: a server older than the p2p port
ignores an unknown key but refuses an unknown option. `stagef_up_v2.sh`
reads the server's `-h`: a p2p-aware server gets the network file (and
needs a nodus-cli that prints `P2P ID:` — `STAGEF_NODUSCLI_BIN`, or
`STAGEF_P2PID_CLI`); an older one (`test_cmt_hf1_gas_upgrade.sh`'s and
`test_p2p_stopall_nowipe.sh`'s OLD bring-ups) gets none and meshes through
its `-s` seeds exactly as before.

## `genesis_protocol_v2.sh` — the runner

Single entry point. Assertion method: **exit code only**.

| rc of a scenario | Meaning |
|---|---|
| 0  | PASS |
| 99 | SKIP — the scenario declined to run because a prerequisite is absent (`test_v2_epoch_boundary.sh` at the shipped epoch length; a scenario that spawns/stops a split node itself in `STAGEF_MODE=splitw` / `mixedw` — "Harness modes"). A 99 is **not** a pass: it means that coverage did not happen, and the runner says so in its result block. |
| else | FAIL (full stdout echoed, then the runner returns 1) |

Modes:

```bash
bash genesis_protocol_v2.sh              # full run: bring-up + scenarios + teardown
bash genesis_protocol_v2.sh --scenarios  # scenarios only; assumes a Comet cluster is already up
```

Phases:

1. **Phase 1** — tear down any previous run (`stagef_down.sh`).
2. **Phase 2** — `stagef_up_v2.sh`: the OFFLINE cometbft ceremony, 7 nodes,
   four anti-vacuity lines per node (role, startup table, LIVE, height ≥ 1),
   then one 7/7 comparison of the first block.
   **Final pre-testnet wipe W-A (genesis document version 4):** the config
   it writes says `config_version = 4` and ends with the nine
   `[treasury]` blocks the parser requires, every `balance = 0` — so the
   harness total, every leaf and Rule P.2 are unchanged, but every node's
   `v2_treasury` holds the nine pool rows (a SYSTEM-root leg). Behaviour a
   scenario inherits: none beyond the rows — general multisig (decision
   2026-09-29-general-multisig.md) WITHDREW W-A's refund of a genesis
   validator's bond into pool 8: a **genesis** validator (the C harness
   nodes, `active_since_block = 1`) that graduates releases its 10M bond
   as a locked UTXO at output index 200 to its `unstake_destination_fp`
   exactly like a validator that joined later by STAKE (e.g.
   `test_v2_stake.sh`'s `v2user`), and no block path moves a pool
   balance. (On the production genesis that destination is the
   Foundation multisig address; the harness keeps each node's own
   fingerprint.) Requires a binary with the W-A
   parser (config_version 4) — an older binary refuses this config, and a
   W-A binary refuses an older one (config_version 3).
   **Final pre-testnet wipe W-C (same document version 4):** the config
   also names `gas_price_raw_per_unit = 121` and
   `token_create_fee_raw = 100000000000` (the production genesis values,
   decisions 2026-09-25-gas-price.md and 2026-09-28-token-create-fee-
   governance.md), and every node commits them as height-0
   `chain_config_history` rows (params 5 and 6). Behaviour every scenario
   inherits: **the gas-price rule is ON from block 1 on every harness
   chain** — a non-SYSTEM envelope must pay at least
   `max(res_max_total_units × 121, 10^6)` raw (a simple 1-in/1-out SPEND
   still pays the flat 0.01; a CLI stake's 400 000-unit declaration pays
   ≈ 0.48 NODUS; SYSTEM-only governance stays fee 0). `nodus-cli` flows
   read the price from `dnac_fee_info` and pay it; a scenario that builds
   envelopes itself, or funds a signer with less than the priced fee,
   is refused (CheckTx item code 9). **Token creation costs the governed
   param 6** (10^11 raw = 1 000 NODUS at genesis), not the compiled
   10^15 — `nodus-cli v2-envelope token-create` reads it from
   `dnac_fee_info` (`token_create_fee`). Requires a W-C server; an older
   (post-HF-1, pre-W-C) CLI still works but overpays the compiled 10^15
   for a token creation, and a pre-HF-1 CLI cannot price the gas rule.
   **General multisig (genesis document version 5):** the config now
   says `config_version = 5` (a version-4 file and binary are refused
   both ways), every validator's `unstake_destination_pubkey` is 5184
   `0` characters (a genesis row must carry zeros — decision
   `2026-09-29-general-multisig.md` ONAY 2), and — when a nodus-cli with
   `msig address` is present (`STAGEF_NODUSCLI_BIN` or
   `nodus/build/nodus-cli`) — it ends with ONE `[genesis_output]`
   (1 000 NODUS, added on top of the harness total) to the 2-of-3
   address over nodes 2/3/4, whose descriptor and address are left in
   `$BASE_DIR/msig_genesis_2of3.desc` / `msig_genesis.addr`. Every
   node's `utxo_set` therefore starts with that one coin (height 0,
   identity = tx_hash). Behaviour a scenario inherits: a scenario that
   counts ALL of `utxo_set` sees one more row; only
   `test_cmt_multisig.sh` spends it.
3. **Phase 3** — the nineteen Comet scenarios in the EXPLICIT order the script's
   own header gives (`test_cmt_empty_blocks.sh` first, `test_p2p_seam_faults.sh`
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
`stagef_cmt_diff_at_floor "post-…"` comparison, or the log scan in
`test_p2p_seam_faults.sh`), and `PASS` at its end. The runner reads them
back: an rc-0 scenario with `SETUP_OK` but no `ASSERT_RUN` is reported as
**FAIL (VACUOUS pass)** and an rc-0 scenario with no mark at all as **FAIL
(UNINSTRUMENTED)** — a new scenario does not count until it carries the
three marks. A green line prints its marks, e.g. `PASS  test_v2_claim.sh
[SETUP_OK ASSERT_RUN PASS ]`. RED-proven: a sweep with `test_cmt_arena_
runway.sh`'s `ASSERT_RUN` line deleted (that scenario's successor is
`test_p2p_seam_faults.sh`, P2P-PORT F6) ended `FAIL … a VACUOUS pass` and
kept `$BASE_DIR`. rc 99 (SKIP) is decided by the exit code alone, marks
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
| `STAGEF_CC_GRACE_SAFETY` / `STAGEF_CC_GRACE_ERGONOMIC` | 17280 / 720 (`stagef_env.sh:61-62`) | `-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS` / `_ERGONOMIC_BLOCKS` | Blocks a chain_config change must wait before taking effect. No Comet scenario proposes a chain_config change today (the governance signature-collection RPC is being re-wired onto the Comet lane — package W4-CC); the variables are kept for `test_v2_grow_7_20.sh` (not in the sweep — it SKIPs when `STAGEF_CC_GRACE_SAFETY` > the epoch length, because its two committee-size votes must land before the boundary that reads them). `test_v2_grow_7_32.sh` reads neither — it proposes no governance change. |
| `STAGEF_V2_CANDIDATES` | 0 | — | Additionally mints N funded identities under `$BASE_DIR/cand1..N` for a growth scenario (not in the sweep): `test_v2_grow_7_20.sh` uses `cand1..13`, `test_v2_grow_7_32.sh` uses `cand1..25`; fewer → SKIP. Candidate i gets `source_id` 2000 + i and port block C+3+i (25 → ports up to 14344); no bring-up change is needed for 25. |
| `STAGEF_V2_PUMP_LEAVES` | (script default) | — | Size of the PUMP leaf batch `test_cmt_claim_flood.sh` spends in one call (R3 W4 package C); `test_v2_epoch_boundary.sh` only submits whatever, if anything, is left. With `STAGEF_V2_PUMP_IDENTITIES` > 1 it is the batch size PER pump identity. |
| `STAGEF_V2_PUMP_IDENTITIES` | **1** (`stagef_up_v2.sh`, section 1d) | — (a genesis-document shape, not a compile constant) | Block capacity trial B (operator 2026-09-24): K-1 EXTRA pump identities `$BASE_DIR/v2pump2 .. v2pumpK`, generated exactly like `v2pump`, each owning its own `STAGEF_V2_PUMP_LEAVES` leaves of the same 10-DNAC size in its own `source_id` band `j × 10^9 + 1 ..` (j = 2..K — above every other band for any derivable config: the builder takes at most 65 536 leaves), counted into `total_supply_raw`. Only `bench_tps_v2.sh` uses them: one coin listing returns at most 100 coins PER identity, so K identities raise the bench's in-flight bound to ≈ 100 × K. Must be exported BEFORE `stagef_up_v2.sh`; K > 1 is a different chain id. **K = 1 (the default) is BYTE-IDENTICAL to the pre-knob config:** the extra-leaf block is guarded by `K > 1` and emits no line, and the total adds `PUMP_ALLOC × PUMP_LEAVES × (K − 1)` = 0 — so no sweep scenario and no chain id changes. Allowed 1..100. |
| `STAGEF_EPOCH_BOUNDARY_BUDGET_S` | 1800 | — | Wall-clock budget `test_v2_epoch_boundary.sh` uses to decide reachability (SKIP when the boundary cannot be reached inside it). Blocks needed × the per-block pace: `STAGEF_CMT_PUMP_BLOCK_S` when the CLI-SPEND pump is usable, the 60 s idle interval otherwise. |
| `STAGEF_PAYOUT_INTERVAL_EPOCHS` | **24** (`stagef_up_v2.sh`, the production value) | — (a genesis-document field, not a compile constant) | tokenomics-v3 P2-7: written into the genesis config as `payout_interval_epochs` — every Nth boundary is a PAYDAY that turns the accrual table into coins. Part of the HASHED genesis document, so it must be exported BEFORE `stagef_up_v2.sh` and every value is a different chain id. Use 2 (with the short-epoch build) to make `test_v2_rewards.sh` reachable; 1 is refused by that scenario (every boundary a payday — no accrual between paydays to observe). The bring-up also reserves `reward_pool_initial` = 200M × 10^8 (P2-1), added to `total_supply_raw`; no knob. |
| `STAGEF_RULE_N_RETIRE_BUDGET_S` | 5400 | — | Wall-clock budget `test_cmt_rule_n_retire.sh` (round 2) uses to decide reachability of THREE boundaries + settle from the current tip (SKIP when they cannot be reached inside it — always true at the shipped epoch length, pumped or idle). Same pace rule as the row above. |
| `STAGEF_BLOCKSYNC_DISTANCE` | 20 (`tests/test_cmt_blocksync.sh`) | — | Blocks the fleet moves while `test_cmt_blocksync.sh`'s victim (node 4) is down — the gap block sync must close. Integer; CAPPED at `STAGEF_EPOCH_LENGTH`/2 − 2 (5 at E = 15) so the victim is never Rule-N-retired; the result must be ≥ 3. Read at run time, nothing to export before bring-up. |
| `STAGEF_PUMP_FUNDER_NODE` / `STAGEF_PUMP_SUBMIT_NODE` | 3 / 1 (`stagef_env.sh`, CLI-SPEND section) | — | The CLI-SPEND pump: whose genesis leaf funds the self-send SPENDs that drive height (node 3 — no scenario in the sweep claims node 3's leaf; node 1's is claimed by `test_cmt_token_create.sh` as its creator's funding — or by `test_cmt_self_delegate.sh` if that runs first — so do not export FUNDER = 1), and which node's client port they are submitted to. The helper reads the CALLER's database (the scenario's reference node, node 1) to size each step while the CLI lists coins on the submit node, so keep the default SUBMIT = 1: a submit node lagging node 1 by a block would re-spend an already-spent coin and the step would fail as "dropped" (rc 2) — never a false pass. Read at source time; export before running a scenario to change them. |
| `STAGEF_ENV_FLOOD_MAX` | 40 (capped at 100) | — | Upper bound on how many envelopes `test_cmt_env_flood.sh` submits in its one batch (it uses min(this, the PUMP identity's spendable coins)). |
| `STAGEF_ADDR_HISTORY_INDEX` | 0 | a binary with the address history index (nodus 0.23.5+) | `1` writes `"addr_history_index": true` into `$BASE_DIR/nodus.json`, so every node writes its node-local address history rows inside each block's transaction (decision `2026-10-01-node-address-history-index.md`). Export BEFORE `stagef_up_v2.sh`. The index is out of every root, so a sweep with it on must stay 7/7 identical exactly like one with it off; a writer fault would stop the node (block fault) and show as a RED scenario. No scenario reads the rows — run `nodus-cli addr-history` by hand to look at them. |
| `STAGEF_NODUS_BIN` / `STAGEF_NODUSCLI_BIN` / `STAGEF_DNACLI_BIN` | `nodus/build/...`, `messenger/build/cli/dna-connect-cli` | — | Point the harness at a differently-configured build (e.g. `nodus/build-shortepoch/`) without disturbing the default one. `STAGEF_DNACLI_BIN` must name a built `dna-connect-cli` (the messenger build), which a git worktree does not carry. |
| `STAGEF_NODUS_BIN_OLD` / `STAGEF_NODUSCLI_BIN_OLD` / `STAGEF_NODUS_BIN_NEW` / `STAGEF_NODUSCLI_BIN_NEW` | unset (→ SKIP 99) | OLD: the pre-HF-1 tree (9b7260c0, 0.19.79); NEW: the HF-1 tree — BOTH short-grace (`-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15`) | Read by `test_cmt_hf1_gas_upgrade.sh` (not in the sweep): the binaries it upgrades FROM and TO. The cluster must be brought up with the OLD server as `STAGEF_NODUS_BIN` (checked through every node's `/proc/<pid>/exe`). Byte-identical OLD and NEW servers SKIP. **P2P-PORT F6:** `STAGEF_NODUS_BIN_OLD` / `STAGEF_NODUS_BIN_NEW` are ALSO read by `test_p2p_stopall_nowipe.sh` (not in the sweep) with a DIFFERENT pair: OLD = a 0.19.80 build without the 4004 p2p port (its `-h` has no `--network-file` — checked, FAIL otherwise), NEW = the p2p-port build; default constants, no short grace; that scenario uses `STAGEF_NODUSCLI_BIN` (a NEW CLI) and no `_CLI_OLD/_NEW`. **HF-2:** all four are ALSO read by `test_cmt_hf2_gov_power.sh` (not in the sweep) with a THIRD pair: OLD = a82a2544 (0.23.1, pre-HF-2), NEW = the HF-2 tree WITH its merge-time version bump — BOTH short-epoch + short-grace (`-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20` + the two grace flags = 15); a NEW whose banner equals OLD's FAILs its version gate. **HF-3:** all four are ALSO read by `test_cmt_hf3_block_bounds.sh` (not in the sweep) with a FOURTH pair: OLD = the live binary at build time (2026-10-02: 0.23.8, 59ea5733 — a post-HF-2 build; re-check on build day), NEW = the HF-3 tree WITH its merge-time version bump — BOTH with the HF-2 scenario's short-epoch + short-grace flag set. **HF-4:** all four are ALSO read by `test_cmt_hf4_names.sh` (not in the sweep) with a FIFTH pair: OLD = the live binary at build time (2026-10-02: 0.23.9, main 547fa773 / 30010235 — a post-HF-3 build; re-check on build day), NEW = the HF-4 tree WITH its merge-time version bump — BOTH with the same short-epoch + short-grace flag set. The five scenarios' pairs are different builds — export the pair of the one you run. |
| `STAGEF_MODE` | **`combined`** (`stagef_env.sh`) | `splitw` / `mixedw`: a build with `nodus-witness` and `nodus-server --witness-external` (split S3) — both from the SAME build; `nodus-witness` is started with `--witness-external` too (it refuses to start without `witness_external`) | Split S3 harness mode — see "Harness modes" below. `combined` = today's harness, unchanged. `splitw` = every node is `nodus-server --witness-external` + a `nodus-witness` process. `mixedw` = nodes 1-3 as in `splitw`, nodes 4-7 combined. Split S5b: `splits` = every node is `nodus-server --storage-external` (witness in-process) + a `nodus-storage` process; `mixeds` = nodes 1-3 as in `splits`, nodes 4-7 combined ("Harness modes, split S5b"). Export BEFORE `stagef_up_v2.sh`; the bring-up records it in `$BASE_DIR/stagef_mode` and every later script reads that file (`stagef_mode`), so `--scenarios` from another shell sees the cluster's real mode. Any other value is refused (exit 2). |
| `STAGEF_NODUSWITNESS_BIN` | `nodus/build/nodus-witness` (same directory as the default `STAGEF_NODUS_BIN`) | — | The external witness binary, read only in `splitw` / `mixedw` (bring-up refuses a split mode when it is not executable; prints a `[warn]` when it is not in the same directory as `STAGEF_NODUS_BIN`). A scenario must see the SAME value as the bring-up: `stagef_node_witness_pid` finds a node's witness by its `/proc/<pid>/exe`. |
| `STAGEF_NODUSSTORAGE_BIN` | `nodus/build/nodus-storage` (same directory as the default `STAGEF_NODUS_BIN`) | — | Split S5b: the external storage binary, read only in `splits` / `mixeds` (bring-up refuses a storage-split mode when it is not executable; `[warn]` when it is not beside `STAGEF_NODUS_BIN`). `stagef_node_storage_pid` finds a node's storage process by its `/proc/<pid>/exe` — a scenario must see the bring-up's value. |
| `STAGEF_P2PID_CLI` | `STAGEF_NODUSCLI_BIN` | — | P2P-PORT F6: the nodus-cli whose `whoami` prints `P2P ID:` (`stagef_p2p_id`, used to write the network file). Set it only when `STAGEF_NODUSCLI_BIN` is an older CLI but the server is p2p-aware. |
| `STAGEF_HF1_NEGATIVE` | 0 | — | `1` runs `test_cmt_hf1_gas_upgrade.sh`'s NEGATIVE arm (D4: vote with one node still on OLD) instead of the positive one — its own fresh bring-up. |
| `STAGEF_STOPALL_NEGATIVE` | 0 | — | P2P-FIX-1 E2: `1` runs `test_p2p_stopall_nowipe.sh`'s negative control of the consensus-WAL carry-over (the 4 signers' `cmt_wal` rows deleted before NEW; the chain must HALT at H) instead of its items 4-6 — its own bring-up; leaves the chain halted. |

Note the `-DCMAKE_C_FLAGS=` form: `DNAC_EPOCH_LENGTH` and
`DNAC_BLOCKS_PER_YEAR` are **compiler defines, not CMake options**.
Passing them as `-DDNAC_EPOCH_LENGTH=15` directly to `cmake` produces
only a "Manually-specified variables were not used" warning and a binary
carrying the production defaults.

### Harness modes (`STAGEF_MODE`, split S3)

Decision `docs/plans/decisions/2026-10-01-nodus-component-split.md`:
item 15 requires the harness in combined, split AND mixed mode before any
split deploy; item 22 splits the witness out first; item 23 runs "mixed"
with the SAME commit's combined binary, not the previous release. The
three modes here are that, at the witness-only stage (S3): `splitw` is
item 15's "split" with core + DHT still one process, not the later
three-process split.

| Mode | Node layout | Run it |
|---|---|---|
| `combined` (default) | every node one `nodus-server` | `bash genesis_protocol_v2.sh` |
| `splitw` | every node: `nodus-server --witness-external` (core + DHT; no witness, does not open the 14xx4 witness port) + `nodus-witness` (consensus, the 14xx4 port, the chain DB) | `STAGEF_MODE=splitw bash genesis_protocol_v2.sh` |
| `mixedw` | nodes 1-3 as `splitw` (`STAGEF_MIXEDW_SPLIT_NODES=3`, fixed in `stagef_env.sh`), nodes 4-7 combined — one build | `STAGEF_MODE=mixedw bash genesis_protocol_v2.sh` |

**What it proves.** `splitw`: a fleet whose every validator runs consensus
in a separate `nodus-witness` process is born, commits and stays 7/7
identical, and the client path (submit to a node's 14xx1 client port →
core → witness over `<data>/witness.sock`) carries every transaction the
sweep's client scenarios submit. `mixedw`: split and combined nodes of the
SAME build run one chain together. Bring-up adds, per split node, to the
four anti-vacuity lines (read from `witness.log`): the `nodus-witness`
process is alive, the core's `nodus.log` carries NO `chain role: COMETBFT`
(the core did not run a witness in-process), and `<data>/witness.sock`
exists.

**What it requires.** `nodus-server` AND `nodus-witness` from ONE build
(`STAGEF_NODUS_BIN`, `STAGEF_NODUSWITNESS_BIN`; default `nodus/build/`).
`STAGEF_MODE` exported before bring-up (or before `genesis_protocol_v2.sh`
for a full run). No compile flag of its own; the short-epoch scenarios
need their usual build in every mode. `nodus-witness` REQUIRES
`witness_external` in its loaded config — the `--witness-external` flag
or the `nodus.json` key `"witness_external": true` — and exits 1 without
it (the guard against a second in-process witness with the same validator
key). The harness sets it on the command line only, for the core AND for
`nodus-witness` (never as a `nodus.json` key: that one file is also read
by the derive ceremony, the combined nodes and every restart). Anything
that starts or restarts a `nodus-witness` must pass the flag too; no
scenario does today (the adapted ones SIGSTOP/SIGCONT it).

**What it leaves behind.** Two processes per split node, both in
`$BASE_DIR/pids.txt` — lines 1-7 are still node 1-7's `nodus-server` in
node order in every mode (`bench_tps_v2.sh` reads line N as node N), each
split node's `nodus-witness` pid is appended after them; `stagef_down.sh`
and the runner's Phase 4 kill every line. Per split node
`node<N>/witness.log` (the witness lines: `chain role: COMETBFT`, `cometbft
startup table built`, `cometbft lane LIVE`, `p2p on … persistent
peer(s)`, `completed ABCI handshake`, `ABCI replay blocks`, every
`CMT_FAULT`) beside the core's `node<N>/nodus.log`,
`node<N>/data/witness.sock`, `node<N>/data/nodus-witness.lock` (the
witness's one-per-data-directory lock) and, if it signs an own address
record at all, `node<N>/data/nodus.addr_seq` (a split node keeps it in the data
directory, never in `identity/` — decision items 10 and 21; the harness
starts from fresh directories, so there is nothing to migrate). A split node's
`node<N>/data` is mode **0700**: bring-up `chmod`s it right after creating it
(`stagef_up_v2.sh`, dir layout step), because the Unix socket entry refuses a
group/other-writable socket directory (`nodus_tcp.c` `unix_parent_dir_ok`) and
`mkdir -p` under a 0002 umask gives 0775; combined nodes keep the umask's mode.
`$BASE_DIR/stagef_mode` in every mode
(`combined` included). Read witness lines through `stagef_node_log N`.

**Scenarios in a split mode.**

| Scenario | `splitw` | `mixedw` |
|---|---|---|
| `test_cmt_empty_blocks`, `test_v2_claim`, `test_v2_stake`, `test_cmt_chain_config`, `test_cmt_mempool_flood`, `test_cmt_claim_flood`, `test_cmt_env_flood`, `test_cmt_token_create`, `test_cmt_self_delegate`, `test_cmt_multisig`, `test_v2_epoch_boundary`, `test_v2_rewards` | run unchanged (client / CLI + DB reads only — no node log read) | run unchanged |
| `test_cmt_dead_proposer` (victim 2) | **adapted** — SIGSTOP/SIGCONT the victim's `nodus-witness` | adapted (node 2 is split) |
| `test_cmt_rule_n_retire` (victim 7) | **adapted** — SIGSTOP/SIGCONT node 7's `nodus-witness`; the CMT-APP line read from `stagef_node_log 1` | runs the combined path (node 7 combined); line from node 1's `witness.log` |
| `test_p2p_seam_faults` | **adapted** — scans each node's `stagef_node_log` | adapted |
| `test_v2_restart_convergence` (4), `test_cmt_blocksync` (4), `test_v2_partial_wipe` (5), `test_v2_join` (6) | **SKIP 99** — victim is split | run unchanged (victim combined) |
| not in the sweep: `test_p2p_stopall_nowipe`, `test_cmt_hf1..hf4_*`, `test_v2_grow_7_20`, `test_v2_grow_7_32` | **SKIP 99** | **SKIP 99** |

The SKIP reason line is `[SKIP] <mode>: scenario spawns/stops nodes
directly — not yet adapted (split S6) (node<N> is split)`
(`stagef_split_skip_if`, `stagef_env.sh`), printed before the scenario's
`SETUP_OK` and before any EXIT trap.

**How it can lie.**
- **Every SKIP in a split mode is coverage that did not happen.** A green
  `splitw` sweep has NOT restarted, killed, wiped, rejoined or
  block-synced a split node, and has upgraded nothing — those paths stay
  untested for a split witness until split S6 adapts the scenarios. The
  runner counts them as SKIP and says so, never as PASS.
- **`mixedw` is the SAME build** (decision item 23): it proves split and
  combined nodes of one commit agree, nothing about a split node beside
  the previous release (that compatibility run is deferred by the same
  item).
- **Stopping a split node's witness is not stopping the host.** In
  `test_cmt_dead_proposer` / `test_cmt_rule_n_retire` the core keeps
  serving clients while its witness is frozen; nothing in those scenarios
  submits to the frozen node, so that path is not exercised.
- **`witness.sock` existing is config evidence**, not proof core and
  witness exchanged a message — that is proven only by the client
  scenarios whose transactions land.
- **`test_p2p_seam_faults` reads the witness's log only** on a split
  node; anything the core logs about its witness connection is not
  scanned.
- **`bench_tps_v2.sh`** (not a scenario) reads `pids.txt` line N, which is
  the core in a split mode — its per-node CPU% then excludes the witness.

### Harness modes, split S5b (`splits` / `mixeds`)

Decision `2026-10-01-nodus-component-split.md` items 15, 23, 34: the DHT /
storage half runs as `nodus-storage` (`tools/nodus-storage.c`) beside a
`nodus-server --storage-external` core, reached over `<data>/storage.sock`.
By the `splitw` naming, `splits` is the STORAGE-only split — the witness
stays in the core; the three-process split (both external) is S6's.

| Mode | Node layout | Run it |
|---|---|---|
| `splits` | every node: `nodus-server --storage-external` (core: 4000 / 4001 / 4002, sessions, cluster, presence, the witness in-process; opens no `nodus.db` / `channels.db`) + `nodus-storage` (the DHT: routing, replication on its OWN outbound 4002 dials, `nodus.db`, `channels.db`; listens on no network port) | `STAGEF_MODE=splits bash genesis_protocol_v2.sh` |
| `mixeds` | nodes 1-3 as `splits` (`STAGEF_MIXEDS_SPLIT_NODES=3`), nodes 4-7 combined — one build | `STAGEF_MODE=mixeds bash genesis_protocol_v2.sh` |

**What it proves.** `splits`: a fleet whose every node serves its DHT from
a separate process is born, commits and stays 7/7 identical, and the
client DHT path (14xx1 → core → `storage.sock` → `nodus-storage`) and the
inter-node DHT path (replication dialled by `nodus-storage`, received by
the peer's core on 14xx2 and handed to ITS storage) carry what the sweep
does. `mixeds`: storage-split and combined nodes of the same build share
one DHT and one chain. Bring-up adds, per storage-split node: `nodus-storage`
alive with its running line; the core's `nodus.log` says `STORAGE:
external`; `<data>/storage.sock` exists; and the core logged `routing
snapshot from nodus-storage: N peer(s)` with N ≥ 1 — routing that storage
built from THIS core's relayed peer events came back over the control
connection (data both ways). `test_split_storage_restart.sh` (in the
sweep, SKIP outside these modes) kills and restarts a node's
`nodus-storage`: core + witness stay up, DHT requests get the decision-31
error at once, the control connection and the routing snapshot come back.

**What it requires.** `nodus-server`, `nodus-storage` (and `nodus-cli`)
from ONE build (`STAGEF_NODUS_BIN`, `STAGEF_NODUSSTORAGE_BIN`).
`nodus-storage` REQUIRES `storage_external` in its loaded config and exits
1 without it; the harness passes `--storage-external` on the command line
to the core AND to `nodus-storage` (never a `nodus.json` key, for the
`splitw` reason). Anything that starts a `nodus-storage` uses
`stagef_spawn_storage N`.

**What it leaves behind.** Two processes per storage-split node, both in
`pids.txt` (lines 1-7 still node 1-7's `nodus-server`; storage pids
appended after any witness pids, in node order; a restarted one appended
again); per storage-split node `node<N>/storage.log`,
`node<N>/data/storage.sock`, `node<N>/data/nodus-storage.lock`; the
node's `data/` is mode 0700 (the Unix socket's parent-directory rule).

**Scenarios in a storage-split mode.** Every scenario that calls
`stagef_split_skip_if` SKIPs (99) when its victim's storage is split
(the reason line ends `(node<N>'s storage is split)`).
`test_cmt_dead_proposer.sh` (node 2 — storage-split in both modes) and
`test_cmt_rule_n_retire.sh` (node 7 — storage-split in `splits`) SIGSTOP
the validator: on a node whose witness runs in-process (combined,
`splits`, `mixeds`) that is its `nodus-server`, picked by
`stagef_node_core_pid N` — the one process naming node N's data
directory whose `/proc/<pid>/exe` is `STAGEF_NODUS_BIN` (none or more
than one → the scenario dies, never guesses). Before S5b they took
`pgrep -f node<N>/data | head -1`, which on a storage-split node also
matches `nodus-storage`. The core keeps nothing of the DHT, so a frozen
storage-split core freezes its witness while its `nodus-storage` keeps
running.

**How it can lie.**
- **Every SKIP is coverage that did not happen** — a green `splits` sweep
  has not restarted, wiped, rejoined or block-synced a storage-split node.
- **`mixeds` is the SAME build** (item 23).
- **`storage.sock` existing is config evidence**; the routing-snapshot line
  is the bring-up's proof that the two processes exchanged data.
- **The witness runs in the core** in these modes: nothing here says how a
  node with BOTH halves external behaves (S6).

## Layout

All runtime state under `/tmp/stagef-$TIMESTAMP/` — **fully isolated**
from production:

- `/tmp/stagef-*/node[1-7]/identity/` — fresh Dilithium5 identities,
  auto-generated by `nodus-server` on first run. NOT the production
  keys in `/var/lib/nodus/identity/`.
- `/tmp/stagef-*/node[1-7]/data/` — witness DB + nodus DB + logs (and,
  on the p2p-port build, the 4004 address book and own-ADDR sequence;
  on a split node also `witness.sock` and `nodus-witness.lock`; a split
  node's `data/` is mode 0700 — see "Harness modes").
- `/tmp/stagef-*/node[1-7]/nodus.log` — `nodus-server`'s log;
  `/tmp/stagef-*/node[1-3 or 1-7]/witness.log` — `nodus-witness`'s log on
  a split node (`STAGEF_MODE` mixedw / splitw); `stagef_node_log N` names
  the one holding node N's witness lines.
- `/tmp/stagef-*/stagef_mode` — the harness mode the cluster was born in.
- `/tmp/stagef-*/nodus.json` — the config every start passes with `-c`;
  `/tmp/stagef-*/network.json` — the published network file (pin + peers,
  P2P-PORT F6; see "the 4004 mesh on the new stack").
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
| `genesis_protocol_v2.sh` | The runner (above): `stagef_up_v2.sh` + twenty explicit scenarios (split S5b adds `test_split_storage_restart.sh` just before `test_p2p_seam_faults.sh`; round 2 adds `test_cmt_rule_n_retire.sh`, tokenomics-v3 P2 adds `test_v2_rewards.sh` before it, `test_cmt_token_create.sh` follows `test_cmt_env_flood.sh`, W-B's `test_cmt_self_delegate.sh` follows `test_cmt_token_create.sh`, general multisig's `test_cmt_multisig.sh` follows `test_cmt_self_delegate.sh`, the blocksync port adds `test_cmt_blocksync.sh` between `test_v2_rewards.sh` and `test_cmt_rule_n_retire.sh`) + teardown. `--scenarios` runs against an already-up cluster. Reports SKIPs separately and says in as many words that a skip is not a pass. **Leaf budget:** claim/stake consume single-use node/user leaves each; mempool_flood spends node 4/5/6/7's own leaves; `test_cmt_claim_flood.sh` (R3 W4 package C) is the only scenario that reaches for the PUMP batch, in one call; `test_v2_epoch_boundary.sh` runs after it and ordinarily finds nothing left. A second run against the SAME cluster fails on the leaf-spending scenarios — correctly. **CLI-SPEND:** `test_cmt_env_flood.sh` spends the PUMP identity's claimed coins (self-sends — it needs `test_cmt_claim_flood.sh` first and never claims the batch itself), and the height pump used by `test_v2_epoch_boundary.sh` / `test_cmt_rule_n_retire.sh` claims **node 3's** genesis leaf in its first pump step (`STAGEF_PUMP_FUNDER_NODE`) — a leaf nothing else in the list claims; a scenario that SKIPs claims nothing. `test_cmt_token_create.sh` claims **node 1's** leaf (only if node 1 is not already funded) — `test_cmt_self_delegate.sh` and `test_cmt_multisig.sh` are the only other scenarios that may, under the same "only if not already funded" rule. **Phase 4:** a FAILED sweep stops the processes but keeps `$BASE_DIR` for inspection; only an all-green sweep tears down. |
| `stagef_up_v2.sh` | The version-3 (**cometbft**) ceremony: no transaction and no cluster. The generated config carries `config_version = 3`, one shared `genesis_time_ms` (UTC ms, computed ONCE and written into every node's identical copy — the chain id hashes the whole document) and `initial_height = 1`. Each node runs the OFFLINE one-shot `nodus-server --derive-v2-genesis` against that one shared file **before anything is listening**, and agreement is CHECKED (all 7 chain ids must be identical, 64 hex / 32 bytes) rather than negotiated. Then spawns the 7 and asserts, per node, bounded by ATTEMPTS not a bare sleep, **FOUR** anti-vacuity lines: `chain role: COMETBFT`, `cometbft startup table built`, `cometbft lane LIVE`, AND that its Comet tip reaches height 1 (`stagef_cmt_wait_height <db> 1 3`) — every node can show role+startup+LIVE and still never produce. Once all seven have their first block, ONE `stagef_cmt_diff_at_floor "bring-up"` proves the seven first blocks are identical BEFORE any scenario runs. A node that shows the role but never goes live, or never produces, is a FAIL. Writes `pids.txt`, the pointer file and `$BASE_DIR/v2_genesis.conf` / `v2_genesis_pin` (64 hex). **P2P-PORT F6:** also writes `$BASE_DIR/nodus.json` (4002 auth, `network_file`, the harness-only `allow_duplicate_ip` / `addr_book_strict=false`) and, on a p2p-aware server (its `-h` lists `--network-file`), `$BASE_DIR/network.json` with an EMPTY pin and the seven `<p2p id>@127.0.0.1:<witness port>` peers (IDs from `nodus-cli whoami`); every ceremony runs with `-c nodus.json` and the script ASSERTS pin-auto: exactly one ceremony printed `network-file … pin-written`, six printed `pin-already-equal`, and the file pins exactly the chain id — plus, per node, the `p2p on … 7 persistent peer(s)` start line (config evidence; the mesh itself is proven by every node reaching height 1). An older server gets no network file (and the script says so) and meshes through the `-s` seeds. **What it does NOT prove:** that the seven can commit a block together under demand — that is the scenario suite's job. A green bring-up is a green BIRTH, not a green Comet lane. **Split S3 (`STAGEF_MODE` splitw / mixedw, "Harness modes"):** records the mode in `$BASE_DIR/stagef_mode`; starts every node's `nodus-server` first (split nodes with `--witness-external` on the command line — never a `nodus.json` key, which the ceremony, the combined nodes and every restart also read), keeping `pids.txt` lines 1-7 = node 1-7's server; then, per split node, waits (attempt-bounded) for its identity files and starts `nodus-witness` with the same arguments — `--witness-external` included, which `nodus-witness` requires — into `node<N>/witness.log`, appending its pid. The four lines are read from `stagef_node_log`; a split node must also show a live witness, no `chain role: COMETBFT` in the core's `nodus.log`, and `<data>/witness.sock`. |
| `stagef_down.sh` | Kill PIDs + rm -rf the run dir. Kills EVERY line of `pids.txt`, so both processes of a split node (`nodus-server` + `nodus-witness`, split S3; `nodus-server` + `nodus-storage`, split S5b, including a `nodus-storage` a scenario restarted) go with the same loop. |
| `stagef_diff.sh` | Read `global_root` + `block_id` from each node's witness DB (`v2_blocks`), assert identical across the 7, print. `--expect-height N` additionally requires each node's OWN latest height to equal N. **`--at-height N`** compares the ROW AT height N instead of each node's current latest — necessary because CreateEmptyBlocks means the chain keeps committing on its own, so "each node's own latest" races that ongoing production (seven sequential reads spanning even a fraction of a second can catch one node one idle block ahead of another and misreport it as divergence). Every scenario calls this through `stagef_env.sh`'s `stagef_cmt_diff_at_floor` wrapper, never bare. The legacy `blocks`/`state_root` branch is gone (R3 W4). |
| `stagef_env.sh` | Sourced by other scripts; exports `BASE_DIR`, ports, pubkey file paths, `STAGEF_*` overrides, the `stagef_dna` / `stagef_user_*` wrappers, `stagef_wait_ready`, and the **Comet-lane section**: `STAGEF_CMT_EMPTY_INTERVAL_MS` / `STAGEF_CMT_TIMEOUT_COMMIT_MS` (the two D-4 timing overrides, read from their exact source lines rather than hand-copied); `stagef_cmt_tip`; `stagef_cmt_wait_height` (a progress-bounded wait — a stall is N consecutive empty-block intervals with NO height increase, never a bare wall-clock cap); `stagef_cmt_wait_row DB SQL [N] [MAX_HEIGHTS]` — waits for a ledger EFFECT (a `COUNT(*)`-shaped SQL expression) to appear, with the SAME stall bound as `stagef_cmt_wait_height` (the chain's tip, not the row, is what must keep moving) AND a second, independent `MAX_HEIGHTS` bound (default 20): the stall bound alone waits FOREVER against a chain that keeps healthily committing while the awaited row never appears (measured: 34 minutes) — exceeding `MAX_HEIGHTS` past the call's starting tip returns a THIRD outcome (rc=2, "dropped, not delayed") distinct from a stall (rc=1); `stagef_cmt_diff_at_floor` (the race-free `stagef_diff.sh` wrapper). **CLI-SPEND pump:** `stagef_cmt_pump_ready DB` (a PURE feasibility check — submits nothing; call it directly, never in `$(...)`, it sets `STAGEF_PUMP_READY`), `stagef_pump_claim DB` (claims the funder node's genesis leaf and waits for the claimed coin as a ledger effect — `stagef_cmt_pump_to`'s first step when the funder holds no coin above the fee, once per call), `stagef_cmt_pump_to DB TARGET [N]` (drives the tip to TARGET with `nodus-cli v2-envelope spend` self-sends of the funder's largest coin minus `STAGEF_PUMP_FEE_RAW` — one input, one output, no dust — ONE in flight, each confirmed by its created `utxo_set` row via `stagef_cmt_wait_row` before the next; rc 0 reached / 1 stall / 2 dropped / 3 pump fault, never retried), `stagef_cmt_advance_to DB TARGET [N]` (the pump when ready, `stagef_cmt_wait_height` otherwise — what scenarios call), `STAGEF_CMT_PUMP_BLOCK_S` (15 s — a JUDGMENT per-block pace for SKIP budgets only, derived in the file, not measured). The legacy PBFT leader-derivation helpers (`stagef_leader_entry`, `running_nodes`, `node_view`, `cluster_view_max`, `log_count`, the `VSET_*` constants) are gone with the lane (R3 W4). **P2P-PORT F6 section "THE 4004 MESH":** `stagef_network_file` (the path), `stagef_server_has_network_file BIN` (its `-h` lists `--network-file`), `stagef_p2p_id IDENTITY_DIR` (the `P2P ID:` line of `nodus-cli whoami`; FAILS on a CLI that prints none), `stagef_write_network_file PIN [DIR PORT ...]` (temp + rename; default the 7 nodes), `stagef_write_nodus_json`, `stagef_network_file_pin`. **Split S3 section "HARNESS MODES":** `STAGEF_MODE`, `STAGEF_NODUSWITNESS_BIN`, `stagef_mode` (the recorded `$BASE_DIR/stagef_mode`, else `$STAGEF_MODE`), `stagef_node_is_split N`, `stagef_node_witness_log N`, `stagef_node_log N` (the log carrying node N's witness lines — EVERY witness-line read goes through it), `stagef_node_witness_pid N` (pgrep on node N's data dir filtered by `/proc/<pid>/exe` = `STAGEF_NODUSWITNESS_BIN`), `stagef_split_skip_if NODE...` (SKIP 99 with the one-line reason when any named node is split — its witness or, split S5b, its storage). **Split S5b:** `STAGEF_NODUSSTORAGE_BIN`, `STAGEF_MIXEDS_SPLIT_NODES`, `stagef_node_is_storage_split N`, `stagef_node_storage_log N`, `stagef_node_storage_pid N` (`/proc/<pid>/exe` = `STAGEF_NODUSSTORAGE_BIN`), `stagef_node_core_pid N` (`/proc/<pid>/exe` = `STAGEF_NODUS_BIN`; exactly one or it fails), `stagef_spawn_storage N` (the bring-up's storage spawn line, appending to `storage.log`; prints the pid). A fault in this file breaks every scenario, not one. |


## Scenario tests (`tests/`)

Every script on disk is listed. **"Plain" means: a default `nodus/build`
binary and a freshly brought-up Comet cluster, nothing else.**

#### The Comet lane — needs a cluster from `stagef_up_v2.sh` (the only lane)

**These twenty scenarios are the harness's entire coverage** (the list in
`genesis_protocol_v2.sh`; the count read "thirteen" before tokenomics-v3
P2 while the list already held fourteen; `test_cmt_token_create.sh` made
it sixteen, `test_cmt_self_delegate.sh` (final pre-testnet wipe W-B)
seventeen, `test_cmt_multisig.sh` (general multisig) eighteen,
`test_cmt_blocksync.sh` (blocksync port) nineteen,
`test_split_storage_restart.sh` (split S5b) twenty — it SKIPs outside
`splits` / `mixeds`). Read "What
flips on the Comet lane" near the top of this file FIRST: four standing
rules the deleted legacy suite relied on are false here.

Each exits **99 on a non-Comet cluster** rather than pretending to have
tested a Comet property. `genesis_protocol_v2.sh`'s order is EXPLICIT,
not alphabetical (see that script's own header) — `test_cmt_empty_blocks.sh`
must run first, `test_p2p_seam_faults.sh` must run last, and
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
| `test_v2_stake.sh` | A `v2-envelope stake` SPENDS a claimed output and writes validator state — reaching state a claim never touches. Self-funds first (claims the non-validator user's leaf), so order-independent of `test_v2_claim.sh`. | Default build. Uses the non-validator `v2user` identity — all 7 nodes are already validators and would be refused. | `v2user`'s leaf claimed; a bond locked; two blocks (funding + stake). | Never parses `committed: height=`. A stake IS an envelope, so it DOES get an identity row — Comet writer `cmt_item_index`, `nodus_witness_v2_apply.c:2040-2099`. **DELTA 3, DEFECT 1, THE MEASUREMENT SITE (fixed):** the first cut keyed the wait on `wire_id`, which commits the ML-DSA-87 signature — RANDOMIZED per signing — so the dry-run capture could NEVER match the real submission's committed value (measured: `wire_id=c945d0cf…` vs committed `tx_id=781d6534…`, at a height where the stake HAD been applied). Fixed to key on `v2_intent_index.intent_id`, the signature-independent identity (`shared/dnac/env_wire.h:121-131`). **DELTA 2 — a separate defect, ALSO real:** a stake envelope was APPROVED at tip 2 and its row did not appear until tip 4 — both the funding claim and the stake wait for their OWN ledger effect and read ITS height, never `submission_tip+1`. **DELTA 3, DEFECT 2 (fixed):** the wait is now ALSO bounded by height (`MAX_HEIGHTS=20`), distinct from a stall — measured need: this exact wait sat 34 minutes at a healthy tip before Defect 1 was found. **P2P-PORT F6 (K3):** the stake builder takes no `--db` (chain id, coins, tip and gas price come from node 1 over one session), so an older nodus-cli that still requires `--db` fails the build step, loudly; and the `intent_id` waited for is now read from the SUBMIT's own output — it commits `expiry_height` = tip + 90, so the dry run (kept as a build + self-check gate only) and the submit give DIFFERENT intent_ids whenever a block lands between them, which would have been a false RED at 20 heights. |
| `test_v2_partial_wipe.sh` (**split S3: SKIP 99 in `splitw`** — victim node 5 is split; runs unchanged in `mixedw`) | The H-10 boot gate is unchanged and still armed on a Comet node (confirmed lane-agnostic: `nodus_server_check_partial_wipe` reads only file presence): each of the three SQLite files removed in turn REFUSES START; without the marker the SAME half-wiped directory demonstrably boots (the negative control). | Default build. Needs `$BASE_DIR/v2_genesis_pin` (64 hex) from bring-up. | Node 5 rebuilt via wipe + pin-rejoin; new pid. **W4-H: an EXIT trap restores node 5 on ANY non-zero exit** — the moved database files are put back and the node restarted (with the pin, inert when a chain is present), so a mid-scenario `die` no longer leaves the rest of the sweep on six nodes (sweep 5, 2026-09-17). Proven live: an injected abort after the witness-DB move → node 5 back at the fleet tip within 20 s, the real scenario then PASSes on it. | "It did not come up" is not "the gate refused it" — the assertion greps `PARTIAL WIPE DETECTED` from a log truncated before each attempt. Restore now ALSO checks `chain role: COMETBFT` + `cometbft lane LIVE`, not just an open handle. **DELTA 1 (verifier UNCOVERED FINDING 5, fixed):** the verdict used to be decided by one fixed `sleep 8` — a gate refusing correctly but later than 8 s read as "booted", and the negative control's `!= "refused"` check then misread that late refusal as a disarmed gate (false GREEN in both directions). Replaced with a bounded 30 s poll for either real outcome; the negative control now requires the POSITIVE "booted" result specifically. |
| `test_v2_restart_convergence.sh` (**split S3: SKIP 99 in `splitw`** — victim node 4 is split; runs unchanged in `mixedw`) | A `kill -9`'d Comet node comes back on the SAME chain file, runs and completes the ABCI Handshake (the `ABCI replay blocks` line count rises by one), resumes AND KEEPS producing, and re-converges. | Default build. Victim is node 4, FIXED (no leader concept to derive from on this lane). | Node 4 restarted under a new pid; log appended, not truncated. | **R3 W4:** the `branch=HAVE_CHAIN` delta is gone with the legacy bootstrap state machine (`nodus_witness_bootstrap.c` deleted; a version-3 node's role is decided once by the post-open gate) — the ABCI Handshake delta is the scenario's sole restart-reconciliation proof. **DELTA 1 (item 4, CONFIRMED live and fixed):** "producing again" used to require ZERO progress — the catch-up wait targeted a fleet-tip snapshot the victim had often already reached by the time the wait started (measured: "tip 29 -> 29"), a vacuous pass. Fixed with an explicit second wait strictly past that snapshot and a floor-strictly-greater-than-baseline check before the final diff. **2026-10-02 (FAILED once live, fixed):** the handshake delta was read ONCE, the instant the role line appeared — but the Handshaker logs several init steps AFTER the role line, so the read raced it (measured: role at log line 98, `ABCI replay blocks` at 105, reported `before=1 after=1`). Now an attempt-bounded poll (30 × 1 s, the role wait's shape) for BOTH `ABCI replay blocks` and `completed ABCI handshake`; the latter is now a delta too (the old `>= 1` was satisfied by the first boot's line). |
| `test_v2_join.sh` (**split S3: SKIP 99 in `splitw`** — victim node 6 is split; runs unchanged in `mixedw`) | A WIPED node (identity kept) rejoins on nothing but its 64-hex genesis pin, adopts the fleet's exact chain, and catches up — since the blocksync port (decision `2026-09-29-blocksync-before-testnet.md`) through the block sync reactor on channel 0x40 (`wait_sync` = node.go:375's `blockSync`, true for any node that is not the only validator), then consensus; D-23 rev 7 item 18's "no blocksync" deviation is removed. This scenario asserts adoption and agreement, not WHICH path carried the blocks — `test_cmt_blocksync.sh` asserts that. | Default build. Needs `$BASE_DIR/v2_genesis_pin`. | Node 6 rebuilt via wipe + rejoin; new pid; truncated log. | Pin length check is now 64 hex (was 128 — D-24 rev 4 item 1). "Adopted" is read from the witness DB's FILENAME (embeds the derived chain id's first 16 bytes), never a `global_height=0` row — a version-3 chain writes none (genesis is a document, not a block). |
| `test_cmt_dead_proposer.sh` (**split S3, adapted:** in `splitw` / `mixedw` node 2 is split and the process SIGSTOPped/SIGCONTed is its `nodus-witness` — `stagef_node_witness_pid`; its core keeps serving, and nothing submits to node 2, so a client request meeting a frozen witness behind a live core is NOT exercised) | A stopped validator signs NOTHING for >= 7 heights while OTHERS keep committing, and it resumes and re-converges after `SIGCONT`. **Replaces `test_v2_view_change.sh`** — see this row's script header for why the legacy leader-derivation cannot be ported at all. | Default build. No leaf needed — CreateEmptyBlocks means demand is not required. Victim is node 2, FIXED. ⏱ Needs >= 7 intervals of wall time; post-tokenomics-v3-P1 that is >= 7 x 60 s (the pre-P1 ~6 s/block pace no longer applies — see "What flips" rule 1), so budget several minutes, not "usually well under a minute". | Node 2 `SIGSTOP`ped then `SIGCONT`ed; an EXIT trap resumes it on any early failure. | **No log line proves a round left round 0** — `cmt_cs.c` carries zero `QGP_LOG_INFO` calls; every transition function logs only on FAULT. The assertion is a PIGEONHOLE argument instead (>= CommitteeSize heights under exact round-robin at equal stake guarantees the victim's turn was hit at least once — CONFIRMED against the pinned reference's own tests, `types/validator_set_test.go` `TestProposerSelection2/3`) — read from the ported selection code's structure, not measured empirically this session; flagged as a QUESTION. Closed with a direct DB check: tokenomics-v3 P1 moved this from `validators.last_signed_block` (RETIRED) to `v2_attendance.last_signed_height`, keyed by voter_id (`stagef_voter_id`, `stagef_env.sh`) — the victim's row provably did not move; some other validator's did. Same property, now read from real SIGNING (decided_last_commit COMMIT votes) rather than proposer credit — a SIGSTOPped process can do neither. **DELTA 1 (verifier UNCOVERED FINDING 6, fixed):** the baseline reads used to happen BEFORE `kill -STOP`, racing the chain's own ongoing production in both directions (a block the victim proposed in that window read as a false RED; a block from another validator shrinking the observed window read as a false GREEN). The signal is now sent FIRST, synchronously, before either baseline DB read. **tokenomics-v3 P1 landing (MEASURED, first production sweep at 0.19.67):** attendance is credited ONE BLOCK LATE (block H carries the precommits for H-1), so a precommit the victim sent just before the stop appeared in its row after the stop (10 -> 11) and the old "unchanged since the stop" assertion went RED on a correct chain — a timing race. The frozen baseline is now read 3 heights past the stop (covers the victim leading node1 by one committed block; a larger lead would show as a visible RED, never a false GREEN) and the row must not move from there to the end of the window. |
| `test_cmt_chain_config.sh` (D-16 rev 7, W4-CC; decision 2026-09-26-cc-approval-via-own-node) | `nodus-cli chain-config propose`, run from a validator's OWN identity against ITS OWN node, collects committee approvals OVER THE NETWORK and lands a `chain_config_history` row byte-identical on all 7 nodes. The CLI never dials 4004: it hands the envelope to its own node (`dnac_cc_collect` on 4001), which asks every other seat on channel 0x71 (the former verbs 40-41) over its existing 4004 connections and answers with one result per seat — the only networked exercise of that whole path (test_cc_appr.c drives the responder's verdict directly; test_cc_collect.c the node-side collection with injected answers; test_witness_p2p.c (2d) one in-process 0x71 round trip; test_tier3.c is wire-codec-only). **The vote (0.20.3): `TARGET_ACTIVE_COUNT` (id 4) = 32** — it voted `BLOCK_INTERVAL_SEC` (id 2) until 0.20.3, when CHAIN_CONFIG began refusing every parameter the running consensus does not read (`dnac_cfg_param_read_by_consensus` = {4, 5}; decision `2026-09-23-height-activated-upgrades-before-testnet.md` item 1). 32 is the no-row default (`DNAC_TARGET_ACTIVE_DEFAULT` = `NODUS_V2_ACTIVE_SET_MAX`) inside the version-3 range [7, 32], so the row changes no seat count when the chain later passes its effective height (below 8 it would rotate out the 8th validator `test_v2_stake.sh` bonds). | ⚠ **SHORT-GRACE BUILD ONLY.** compile: `-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15`; env: `STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15` exported BEFORE `stagef_up_v2.sh`. SKIPS (99) at the shipped grace (17280 blocks). No leaf needed — a governance proposal, not a spend. | One committed `chain_config_history` row (TARGET_ACTIVE_COUNT -> 32, param_id 4, effective ≈ 21 blocks past the proposal at grace 15) on every node; later scenarios on the same cluster pass that height and read 32 — the same as the no-row default. `test_v2_grow_7_32.sh` asserts NO TARGET_ACTIVE_COUNT row exists, so it must keep its own fresh bring-up (it already does). Nothing killed or restarted. | The CLI's exit code / "proposal accepted" line is CheckTx admission, never inclusion — the row is asserted from the CHAIN via `stagef_cmt_wait_row`, never CLI stdout. **Round 2 is rarely exercised** — this scenario asks all 7 seats in round 1, so it only reaches the CLI's round 2 if a seat refuses, is not connected to the proposer's node ("SKIP"), or misses the node's 5000 ms collection deadline; before round 2 the CLI waits out the seats' per-proposer cooldown (`NODUS_CC_RATE_LIMIT_WINDOW_MS`=5000 ms), so a round-2 "rate-limited" refusal is a defect, not a design tension. A green "Round 1: 7/7 approved" says nothing about round 2. Does **NOT** prove the effective-height cutover (nothing waits for the chain to reach the proposal's effective height and read back the new target) — only that the proposal round-trips and commits identically everywhere; and because 32 equals the no-row default, even a waiting run could not tell an applied row from an ignored one by counting seats (the cutover scenario needs a non-default value — the decision's item 2). Does **NOT** exercise the refusal of an unread parameter over the network — that is unit-tested only (test_chain_config_verify.c, test_v2_econ_params.c, test_cc_appr.c, test_v2_native.c). |
| `test_cmt_mempool_flood.sh` | (A) A tx submitted to ONE node (3) commits on all 7, AND its own UTXO lands there — the mempool channel (verb 39, `NODUS_T3_CMT_TXS`) gossips it; there is no leader/forward-to-leader step to do it instead. (B) Several claims submitted back-to-back apply within a BOUNDED spread of heights (typically, and in the common case exactly, the SAME `block_height`) — PrepareProposal batches what is waiting when it runs, since CheckTx no longer blocks the client one-at-a-time. | Default build. Uses node 4's leaf (part A) and node 5/6/7's leaves (part B). Deliberately does NOT touch the PUMP batch. | Node 4/5/6/7 leaves claimed. PUMP batch untouched for `test_cmt_claim_flood.sh` / `test_v2_epoch_boundary.sh`. | **DELTA 1 (verifier UNCOVERED FINDINGS 2 and 4, fixed).** `tx_count` counts APPLIED ENVELOPES only (`nodus_witness_v2_apply.c:4593-4595`); a raw claim never increments it, so the first cut's `tx_count > 1` assertion was structurally ALWAYS RED. Part A used to assert only height agreement, which a completely broken mempool gossip could still satisfy via idle CreateEmptyBlocks production alone — closed by asserting node4's own claim's `utxo_set` row exists. **DELTA 2, MEASURED:** both parts now wait for their ledger effect(s) with a progress bound and read the ACTUAL height(s), never `submission_tip + 1`. Part B's "same block" is no longer a hard requirement — three separate CLI submissions can legitimately land on different rounds (the same mechanism DELTA 2 measured for a single transaction); the assertion is a bounded spread (2 heights), logging an exact batch as the common case. Inclusion is asserted by the ledger effect, waited for with progress bounds — the interval between CheckTx and inclusion is not asserted. **DELTA 3 — confirmed safe from Defect 1** (both parts key on claim nullifiers, never `wire_id`). **DELTA 3, Defect 2:** both waits are also bounded by height (`MAX_HEIGHTS=20`), distinct from a stall — the same bound `test_v2_stake.sh` measured sitting 34 minutes without. |
| `test_cmt_claim_flood.sh` | **R3 W4 package C.** ONE `v2-claim` call over the WHOLE pump batch (however many leaves this genesis config actually gave it, read from `v2_genesis.conf`) applies every leaf within 20 heights, AND at least one carrying block holds MORE than the retired flat 16-item cap — the engine's claim scratch is heap now, sized to the block's own `n_claims`, bounded by cometbft's own block-byte ceiling (`NODUS_V2_APPLY_MAX_CLAIMS`, 14 162, `nodus_witness_v2_apply.h`) rather than a flat item count. | Default build. The ONLY scenario that spends the PUMP batch — must run before `test_v2_epoch_boundary.sh`. | The WHOLE PUMP batch claimed and spent. Chain some number of blocks higher. | **NOT measured through `v2_blocks.tx_count`** — same structural reason `test_cmt_empty_blocks.sh`/`test_cmt_mempool_flood.sh` disclose: `tx_count` counts applied ENVELOPES only, never claims, so an all-claims block always shows `tx_count=0` regardless of this fix. Uses `v2_claims_spent.claimed_height` (one row per applied claim, with its own height column) instead. Does not capture each leaf's own nullifier before submitting (impractical for dozens of leaves) — reads `v2_claims_spent` rows newer than the submission's own starting tip instead, which assumes no OTHER scenario is spending claims concurrently (true here — this harness runs scenarios sequentially). The per-block wall-clock gap it prints is HARNESS-OBSERVED (polled from `v2_blocks`, ~1 s granularity), NOT the block's own committed header time (`cmt_blockstore`'s value column is an opaque encoded blob no bash+sqlite3 harness can decode) — printed for cost estimation, asserted on nowhere. **DELTA 4 (root cause was the CLI, not the engine):** at production constants this scenario FAILED — 40 leaves carried as 26:7, 27:16, 28:15, 29:2 across FOUR blocks, `max_in_one=16` never exceeding the retired cap (`/tmp/stagef-20260917T231618Z`). Read, not assumed: `cmd_v2_claim --submit`'s loop opened a NEW client session (Kyber1024 handshake + T2 auth) per leaf (`nodus-cli.c`'s old `t6_submit`), tens of seconds for 40 leaves against a chain committing every ~1-5 s — the batch never accumulated in one block, regardless of the engine fix above. Fixed in `nodus-cli.c`: the loop now opens ONE session (`t6_submit_on`) for the whole batch and prints the submission's own wall-clock duration so a future regression measures itself instead of being silently reintroduced (see the script's own "HOW IT CAN LIE"). |
| `test_cmt_env_flood.sh` | **R3 W4-C delta 2, made runnable by CLI-SPEND.** A burst of K ENVELOPES (not claims) all apply and all 7 nodes agree. How they split across blocks is PRINTED, NOT asserted (operator 2026-09-23): a proposer woken by txsAvailable may start before the client finishes, so the split is a wall-clock race (first pumped sweep at 0.19.68: 40 in 3 s -> 32 + 8); "a block may carry > 10 envelopes" is proven deterministically by `test_v2_apply.c` §6 (11 in one block). The envelopes are K real CORE SPENDs (`nodus-cli v2-envelope spend --count K`: K independent self-sends by the PUMP identity, each funded by its OWN coin, all on ONE client session); each is followed to its LEDGER EFFECT (the created `utxo_set` row, whose `tx_hash` is the envelope's `intent_id`), and the carrying blocks are grouped by that row's own `block_height`. Prints the CLI's wall-clock for the batch, harness-observed per-height gaps and each carrying block's `v2_blocks.tx_count` (none asserted). | Default build (nodus-server AND nodus-cli from the same tree — the CLI takes the CORE ruleset from its own compiled table). The PUMP identity must hold >= 11 spendable coins — `test_cmt_claim_flood.sh` must have run first; this scenario never claims the batch itself. `STAGEF_ENV_FLOOD_MAX` (default 40, max 100) bounds K. | The PUMP identity's K largest coins each replaced by one self-sent coin `STAGEF_PUMP_FEE_RAW` smaller (no change output with the equal-sized claim batch — coin count unchanged). Chain >= 1 block further on. | **SKIP (99) when the PUMP identity has < 11 spendable coins** (claim flood did not run first) — coverage that did not happen, not a pass. **The batch lands in one block only if the CLI submits faster than the chain commits** — the printed duration is what tells a client-pace failure from an engine one (the claim-flood trap, same shape). **The per-block envelope count is set by UNITS:** PrepareProposal's capacity seam reserves EVERY envelope's whole `res_max_total_units` against one block budget at once, without finalizing in between (`app_seam_check` → `nodus_witness_v2_produce.c:269` → `nodus_witness_v2_env.c:382`; `NODUS_V2_GLOBAL_UNIT_BUDGET`, `nodus_witness_v2_apply.h:298`), and trims the rest to a later block — so the declared ceiling IS the per-block limit. The CLI right-sizes it (`t6_spend_ceiling`: the metering module's own static units + one `w_read` per read) over an EXACT effect declaration (`t6_spend_effect_decl`: inputs + outputs + 1 effects, 116 + 148·in + 432·out result bytes, pinned by `test_v2_native.c` §19). **Block capacity trial B (operator 2026-09-24, `docs/plans/decisions/2026-09-24-block-capacity-trial-b.md`), ARITHMETIC until measured:** budget 2 097 152, a 1-in/1-out spend 8 221 units (all weights 1), so at most 255 per block — far above K ≤ 40, so the unit budget no longer shapes this scenario's split. Before trial B (budget 1 000 000, a flat 40 / 16 384 effect declaration, 23 946 units): at most 41 per block — MEASURED on live blocks by `bench_tps_v2.sh` at 0.19.69, 110 of 110 loaded blocks carried exactly 41. A round 200 000 ceiling (the test-fixture precedent) would cap every block at 10. The inclusion wait is an inline copy of `stagef_cmt_wait_row`'s rules (1 s poll for timestamps). Never parses `committed:`. |
| `test_cmt_token_create.sh` | A CORE TOKEN_CREATE envelope (runtime_op 3, `nodus-cli v2-envelope token-create`) is admitted and APPLIED, and its token MOVES: (1) the `tokens` registry row and the token genesis output (`utxo_set`, `tx_hash` = the envelope's `intent_id`, output_index 0) exist, are identical on all 7 nodes, and say what was asked (name / symbol / decimals / supply, `creator_fp` = the genesis output's owner, amount = the supply); (2) a `v2-envelope spend --token <id>` moves a quarter of the supply to node 2: the genesis output is gone on every node and exactly two token outputs (recipient + change) sum to the supply, identical 7/7; (3) `stagef_cmt_diff_at_floor` 7/7 after both. The first scenario that reaches the `tokens` table and a non-native UTXO. | Default build (nodus-server AND nodus-cli from the same tree — a CLI without `token-create` fails the build step, loudly). No `STAGEF_*` of its own. **Funding:** the creator is NODE 1, whose genesis leaf is 10^16 raw (`stagef_up_v2.sh` `ALLOC`); since W-C the creation fee the chain charges is the governed param 6 (10^11 at genesis, read by the CLI from `dnac_fee_info`), while the script's funding threshold still uses the compiled 10^15 (`TC_FEE`, its own header — over-funding, harmless); claimed here (the `test_v2_stake.sh` pattern) only when node 1 does not already hold fee + 1 NODUS spendable. The only other scenario that may claim node 1's leaf is `test_cmt_self_delegate.sh`, under the same "only if not already funded" rule. | Node 1's leaf claimed; ONE permanent `tokens` row (fresh random id per run, `HTK`); 75% of the token supply owned by node 1, 25% by node 2; the creation fee (since W-C the governed 10^11 raw, or `units × 121` if larger) + one spend fee moved from node 1 into `supply_tracking.reward_pool`; chain ≥ 2 blocks further on. Nothing killed or restarted. | **SKIP (99)** on a non-Comet cluster — coverage that did not happen. **Happy path only:** no refusal rule (duplicate token id, bad name, low fee, non-native input) is exercised here. **Gas-price raise not exercised:** since W-C the harness genesis has `GAS_PRICE_RAW_PER_UNIT` = 121, but a TOKEN_CREATE leg's `units × 121` stays far below the 10^11 creation fee, so the CLI still pays exactly the creation fee in one planning pass; the raise branch is not reached. **The param-6 value is not varied here** — the engine-level proof that the committed row (not the compiled constant) is the floor is `test_v2_native` `test_core_token_create_param6`. **The TOKEN_CREATE effect declaration (`t6_tc_effect_decl`) has no unit-test pin** (the SPEND one has, `test_v2_native.c` §19): an under-declaration is admitted by CheckTx and refused in-block → this scenario FAILS "dropped, not delayed" (not a false pass); an over-declaration passes silently. **The reward-pool credit is not asserted** (the pool also moves at epoch boundaries and paydays). A rerun on the same cluster skips the claim and creates a SECOND token under a new id — keyed on its own ids, so it neither fails on funding nor reads the first run's rows. `STAGEF_PUMP_FUNDER_NODE=1` would make the pump and this scenario claim the same leaf. `token_id=` / `intent_id=` are read from the SUBMIT output, never the dry run (intent_id commits the tip-relative expiry). Never parses `committed:`. |
| `test_cmt_self_delegate.sh` (final pre-testnet wipe, W-B) | A GENESIS validator delegates to ITSELF and it counts (decision `2026-09-28-treasury-pools-and-exact-self-stake.md` item 6): (1) node 1's `nodus-cli v2-envelope delegate --validator <its own pubkey>` is admitted and APPLIED (its `v2_intent_index` row exists — Rule S would have refused it); (2) 7/7: the delegation row node1 → node1 holds the amount, node 1's `total_delegated` AND `external_delegated` rose by exactly it, `self_stake` stays exactly 10M; (3) 7/7: the frozen copy of the first boundary after it, `copy(nb)`, holds node 1's bond (`kind` 0, 10^15) and its self-delegation (`kind` 1) as TWO rows under the (epoch, validator, owner, kind) key; (4) 7/7: node 1's `total_stake` in `snapshot(nb+2E)` (the first set built from `copy(nb)`, `nodus_v2_power_exit_boundary`) is its `snapshot(nb+E)` value + exactly the amount — ranking and voting power grew; (5) `stagef_cmt_diff_at_floor` 7/7 before and after. | **Short-epoch build:** `-DDNAC_EPOCH_LENGTH=<E>` + `STAGEF_EPOCH_LENGTH=<E>` exported before `stagef_up_v2.sh`, and the CLI-SPEND pump (node 3's leaf); SKIPS (99) when up to 3E blocks exceed `STAGEF_EPOCH_BOUNDARY_BUDGET_S` (1800 s) — always at the shipped 720, and idle-only. nodus-server AND nodus-cli from THIS tree (an older CLI has no `v2-envelope delegate` and fails the build step, loudly; an older server has no `v2_balance_copy.kind` and the scenario SKIPS). No fault-injection env, no `STAGEF_*` of its own. **Funding:** node 1's own coins (1M NODUS + 1 000 NODUS fee margin); its genesis leaf is claimed here only when node 1 is not already funded (ordinarily `test_cmt_token_create.sh` already claimed it). | 1M NODUS of node 1's coins permanently bonded as a self-delegation (node 1's power and reward share are larger from `snapshot(nb+2E)` on); node 1's leaf claimed if it was not; the chain 2-3 epochs further on; one pump fee per step moved from node 3's coin into the reward pool, node 3's leaf claimed if no earlier pump did. Nothing killed or restarted. Runs BEFORE `test_cmt_rule_n_retire.sh`. | **SKIP (99)** = coverage that did not happen (non-W-B cluster, or the E / pump budget). **Epoch length E, not 720** — proves the LOGIC (admission, storage, the copy's kind split, the power lift), nothing about the magnitude of E. **A rerun on the same cluster tops the row up** — every assertion is a delta from values read before the submission, so it still holds; `copy(nb)`'s kind-1 amount is then the running total, which is what is asserted. **(4)'s delta would include any OTHER delegation to node 1 in the window** — none in the list delegates, and the live `total_delegated` is checked to have moved by exactly the amount across the window. **Node 1 must be seated in both compared snapshots** (seat target 32), else FAIL — never a vacuous compare. Inclusion is the SUBMIT's `intent_id` in `v2_intent_index` with `stagef_cmt_wait_row`'s stall / 20-height bounds; never parses `committed:`, never keys on `wire_id`. The copy is out of every root, so (3) is compared explicitly on all 7, not inferred from the state_root. |
| `test_cmt_multisig.sh` (general multisig, final pre-testnet wipe) | An M-of-N address is an ordinary coin owner that M of its keys — never fewer — can spend (decision `2026-09-29-general-multisig.md`, design §7 rev 2): (1) `nodus-cli msig address --m 2` over nodes 2/3/4's public keys prints the address (descriptor 18 + 3×2592 bytes); node 1 pays FUND (1 000 NODUS) to it with an ordinary `v2-envelope spend`, and the coin is owned by the address on all 7 nodes; (2) `v2-envelope spend --msig` builds the UNSIGNED auth_kind-3 envelope; `msig combine` with ONE signature is refused locally ("fixed 2 signers" — auth_len is signed) and writes/sends nothing; (3) nodes 2 and 3 `msig sign` offline, `msig combine` submits over node 5's session and the envelope is APPLIED (its `v2_intent_index` row); (4) 7/7: the multisig coin is gone, node 5 holds SEND (400 NODUS) and the change (if any) is owned by the address, both under the envelope's `intent_id`; (5) GENESIS-FUNDED (config_version 5): `stagef_up_v2.sh` writes ONE `[genesis_output]` (1 000 NODUS) to the same 2-of-3 address and leaves it in `$BASE_DIR/msig_genesis.addr`; 7/7 hold it as a height-0 coin (identity = tx_hash, output_index 0) and nodes 2 + 4 spend it the same way (7/7 gone, node 5 +300 NODUS); (6) `stagef_cmt_diff_at_floor` 7/7 before and after. | **Default build** — no `-D`, no fault-injection env, no `STAGEF_*` of its own, no epoch wait. nodus-server AND nodus-cli from THIS tree (an older CLI has no `msig` and FAILS the address step; an older server refuses auth_kind 3 at CheckTx and FAILS the submit). **Funding:** node 1's own coins (FUND + 1 000 NODUS fee margin); node 1's leaf is claimed here only when node 1 is not already funded (ordinarily an earlier scenario already claimed it). | A 2-of-3 address holding the change; 400 NODUS more on node 5; two fees moved into the reward pool; node 1's leaf claimed if it was not; `$BASE_DIR/msig_*` files (descriptor, export, signatures, logs); the chain a few blocks on. Nothing killed or restarted. | **Chain-side refusals are NOT exercised here** — the M-1 case is refused by the CLI's own count check and never sent; M-1 signers, a wrong or unused descriptor and the kind-3 parse matrix at the chain are `test_v2_native.c` §MSIG. **The genesis-funded path (5) can be absent:** the bring-up writes the genesis output only when a nodus-cli with `msig address` was present (its `[warn] no genesis multisig output` line says otherwise) — then (5) does not run and the PASS line says "not run", coverage that did not happen; a rerun on the same cluster finds the genesis coin spent and FAILS (5). A rerun funds a second coin of the same amount; the scenario keys on its OWN funding transfer's `intent_id` (`tx_hash`), never on "a coin of that amount". Inclusion is the SUBMIT's `intent_id` in `v2_intent_index` with `stagef_cmt_wait_row`'s stall / 20-height bounds; combine's `intent_id` is checked equal to the export's. **SKIP (99)** only on a cluster without this tree's genesis config — coverage that did not happen. |
| `test_v2_epoch_boundary.sh` | The chain crosses an epoch boundary at height `H=k*E_LEN` and freezes the snapshot for `epoch_start = H + E_LEN` (the one THIS crossing produces) byte-identically on all 7. | **Short-epoch binary, both halves:** `-DDNAC_EPOCH_LENGTH=<E>` + `STAGEF_EPOCH_LENGTH=<E>`. SKIPS at the shipped 720. Optional (CLI-SPEND): a built `nodus-cli` and `STAGEF_PUMP_FUNDER_NODE` / `STAGEF_PUMP_SUBMIT_NODE` (defaults 3 / 1) — without them the wait is idle production. | Ordinarily NOTHING of the PUMP batch — `test_cmt_claim_flood.sh` (package C), placed immediately before this scenario, already spent all of it; this scenario's own pump submission finds an already-fully-claimed identity and `v2-claim` SKIPS it. Chain past >= 1 boundary regardless. When pumped: node 3's genesis leaf claimed by the first pump step (unless an earlier pump already did) and one fee per pump step gone from node 3's single coin. A SKIP leaves nothing: the pace decision (`stagef_cmt_pump_ready`) is a pure check. | **Reachability is now a WALL-CLOCK BUDGET (1 800 s default), not a leaf count** — pumped claims no longer land 1:1 per block (see "What flips" rule 4), so counting leaves cannot say whether the boundary is reachable in this harness's patience. **CLI-SPEND:** the wait goes through `stagef_cmt_advance_to` — when the pump is usable the blocks are driven by confirmed self-send SPENDs (budget pace `STAGEF_CMT_PUMP_BLOCK_S`), otherwise by idle production (60 s pace) exactly as before; the `[ok] block driving:` line says which. A pumped green does not prove the idle-only crossing and vice versa. A dropped pump spend (rc 2) or a pump fault (rc 3) FAILS the run with its own message — never retried, never downgraded to idle mid-run. Never parses `committed:`. Can take MINUTES even at the short-epoch convention. **DELTA 1 (verifier CLAIM 16, fixed):** the cross-node comparison used to read `epoch_start = next_boundary` — the row GENESIS ALREADY SEEDED on every node identically, which can never differ and proved nothing about the crossing (`nodus_witness_vset.c:658-659`: crossing H writes `epoch_start = H + E_LEN`, not `H`). Fixed to compare at `next_boundary + E_LEN`. |
| `test_cmt_blocksync.sh` (**split S3: SKIP 99 in `splitw`** — victim node 4 is split; runs unchanged in `mixedw`) (blocksync port, decision `2026-09-29-blocksync-before-testnet.md`; **run 2026-09-29 on the blocksync branch: PASS at production constants (distance 20) and at E=15 (capped to 5)**) | A validator stopped while the fleet moves on by a DISTANCE in blocks, restarted on its own data dir, decides `blockSync` = ON (log `block sync ON`, node.go:375), catches up by BLOCK SYNC — log `block sync done at height H (N block(s) synced) — consensus started`, asserted N ≥ 1 and H ≥ target − 2 (IsCaughtUp stops at maxPeerHeight − 1, pool.go:220; a block is applied only with its successor's commit, reactor.go:456-461) — reopens the SAME chain file, keeps producing past the fleet tip it rejoined at, and 7/7 agree at a floor ≥ the target (`stagef_cmt_diff_at_floor`). Every wait is progress-bounded (the distance via `stagef_cmt_advance_to`; the sync wait fails after 3 empty-block intervals with neither a new done-line nor tip movement). | **Compile:** none — a default build WITH the blocksync port (0x40); nodus-cli from the same tree when the pump is used. **Env:** `STAGEF_BLOCKSYNC_DISTANCE` (default 20, read at run time) — CAPPED at `STAGEF_EPOCH_LENGTH`/2 − 2 (5 at the short-epoch 15, 358 at 720; printed when it applies) so node 4 misses Rule N's 50 % bar in at most ONE epoch and is never AUTO_RETIRED; optional CLI-SPEND pump (`STAGEF_PUMP_FUNDER_NODE` 3 / `STAGEF_PUMP_SUBMIT_NODE` 1 — both must differ from the victim, node 4, or it FAILS at once); without the pump the distance is covered by idle production at 60 s per block (~20 min at 720). **Order:** AFTER `test_v2_rewards.sh` (a missed epoch could cost node 4 an accrual row that scenario asserts) and BEFORE `test_cmt_rule_n_retire.sh` (once node 7 is retired, stopping node 4 could leave the set without a quorum). A `stagef_up_v2.sh` cluster; anything else SKIPs (99). | Node 4 stopped (SIGTERM, SIGKILL after 15 s) and restarted under a new pid, appended to `pids.txt`, log appended; possibly ONE epoch in which node 4 is below Rule N's bar (never two); the chain ≥ the distance further on; when pumped, node 3's leaf claimed (unless an earlier pump did) and one fee per pump step spent. Nothing wiped. | The block-sync evidence is two log lines of THIS build — a build without the port prints neither and FAILS, never passes; N ≥ 1 proves block sync applied blocks, not that it applied every missing one (the last one or two can arrive through consensus after the switch, the reference's own shape); one node behind, six honest peers — the bad-peer paths (bad commit → stop + ban + redo) are unit-tested only (`test_cmt_bsync_reactor`); the distance is modest (5 blocks in the short-epoch sweep) — a thousands-of-blocks outage is the same path but not measured; the victim is RESTARTED, never SIGSTOPped (block sync runs only at start, reactor.go:132-146). The peers' StatusResponses that reach node 4 before its lane is live are HELD and replayed at lane-live (a labelled deviation, `nodus_witness_p2p.h` "THE BLOCK SYNC SEAM"), so the sync does not wait for the 10 s status broadcast; that path is unit-tested by `test_witness_p2p` (1b'), not asserted here. The Rule N cap rests on the README's "two consecutive misses retire" rule — a RED `test_cmt_rule_n_retire.sh` right after this scenario needs node 4's `consecutive_missed_epochs` read before it is called a consensus defect. |
| `test_v2_rewards.sh` (tokenomics-v3 P2) | The reward reserve moves only pool → accrual → coin, identically on all 7: at each NON-payday boundary H the pool falls by EXACTLY what `v2_reward_accrual` gained (> 0, <= pool >> 16), every harness node that is a member of the GOVERNING snapshot(H−E) — decoded from `validator_set_snapshots`, never assumed to be the 7 genesis nodes — holds an accrual row, and pool + accrual table are identical on all 7; at the PAYDAY boundary (`(H/E) % payout_interval_epochs == 0`) the accrual table is empty afterwards and the coins at that height with `output_index >= 400` sum to exactly the prior accrual plus this boundary's distribution, owned by EXACTLY {pre-payday accrual owners} ∪ {harness nodes in snapshot(H−E)}, one each, identical on all 7; 7/7 state_root at the floor after. | **Short-epoch build + short payout interval, BOTH exported before `stagef_up_v2.sh`:** `-DDNAC_EPOCH_LENGTH=<E>` + `STAGEF_EPOCH_LENGTH=<E>` + `STAGEF_PAYOUT_INTERVAL_EPOCHS=2`. SKIPS (99) at the shipped 720 / 24, with interval 1, on a bring-up whose config names no `payout_interval_epochs`, and when the payday is over `STAGEF_EPOCH_BOUNDARY_BUDGET_S` (1800 s) — idle-only production always is; needs the CLI-SPEND pump. MUST run BEFORE `test_cmt_rule_n_retire.sh` (all seven must be paid). | Chain several epochs further on, past one payday: each committee validator holds one more native coin; one pump fee per step gone from node 3's coin — INTO the reward pool since P2, not burned; node 3's leaf claimed if no earlier pump did. Nothing killed or restarted. | Pre/post reads are ONE SQLite statement each (a consistent snapshot of tip, pool, Σaccrual, accrual row count AND the accrual owners — the pre-payday owner list comes from the same statement as the tip that says the boundary has not landed; until the fix it was a second read, and a boundary committing between the two FAILED a mixedw sweep with "re-run" after the pump overshot its H−2 target by one block, `tip 104 >= 103` → boundary 105); the payday coin reads (count/sum, then owners) are two statements keyed to the fixed payday height, not the tip, and nothing spends those rows while the pump is idle; the pre read is taken only after the last pump spend landed and the pump stays idle until the post reads are done; the window between is checked for NO envelope (`tx_count`) and NO coin other than payday (>= 400) / graduation (200) rows — a fee or claim in the window FAILS the run instead of being mis-attributed. (A graduation (200) row is ALLOWED, never required. Since general multisig withdrew W-A's pool-8 refund, EVERY graduate — genesis harness node or STAKE-joined `v2user` — writes one; the tolerance W-A needed for a genesis node that wrote none is no longer exercised.) A boundary the pump overshoots before its pre read (pre read tip ≥ H) is skipped for the next one — a miss, never a re-run; three misses FAIL. Payday coins are recognised by position (`block_height`, `output_index >= 400`). **Committee from the chain (fixed at the P2 landing, 0.19.69):** the first full short-epoch sweep FAILED "boundary 75: node2's fingerprint has no accrual row" on a CORRECT chain — `test_v2_stake.sh` bonds an 8th equal-stake validator (v2user) with no running node, the 7-seat set's tie-break rotates one genesis node out of each snapshot (snapshot(60) held v2user, not node2), and v2user never signs, so it misses the bar until Rule N retires it; the old check assumed the committee was the 7 genesis nodes. (Tokenomics-v3 P3, NOT yet re-measured on a sweep: the default seat target is now 32 — `DNAC_TARGET_ACTIVE_DEFAULT` — and selection ranks by the FROZEN balance copy two epochs back, so there is no rotation any more: v2user is seated alongside all 7 genesis nodes from the first snapshot whose source copy already holds its bond, and stays a non-signing member until Rule N retires it. The chain-derived committee check covers both shapes.) A running member that is not paid still FAILS; ≥ 1 harness node must be a member of every observed snapshot (vacuity guard). **Membership is matched in PURE BASH** — the fix's first cut used `printf | grep -qx` under `pipefail`, and `grep -q` exiting on an early match SIGPIPEs the writer (rc 141): measured 15 false "not a member" in 3 000 calls on a loaded machine, 0 idle; it failed sweep 2 on a correct chain (node7 dropped from the expected payday owners). Proves the LOGIC at E and interval 2, nothing about the production magnitudes. |
| `test_cmt_rule_n_retire.sh` (**split S3, adapted:** in `splitw` node 7's `nodus-witness` is the process SIGSTOPped/SIGCONTed, its core keeps running; in `mixedw` node 7 is combined — original path; the CMT-APP `n_removed=1` line is read from `stagef_node_log 1`) (round 2, tokenomics-v3 P1 §A/D-3/D-11; re-checked round 5 against R5-1/R5-2/R5-3 and round 6 against the voting-power floor, unchanged) | A validator that signs nothing for TWO consecutive epochs (real `decided_last_commit` attendance, no hand-set row) is AUTO_RETIRED at the second boundary (`validators.status=3`, `consecutive_missed_epochs=2`, `active_count` -1 exactly once), AND that removal reaches cometbft's OWN validator set — but at the THIRD boundary, one epoch AFTER the DB flip, not the same one (`nodus_cmt_app_finalize_block`'s §A diff at boundary H compares snapshots frozen at H and H-E, neither of which has ever seen a decision made AT H itself; the removal is visible only once `commit_next(H)` writes `snapshot(H+E)`). The victim's `v2_attendance.last_signed_height` stays frozen the whole window while others' keep moving, and it re-converges after `SIGCONT`. **Round 5 re-check (arithmetic, not behavior, changed):** node 7 has a REAL duty at both e1 and e2 (R5-1 — it is a continuous 7-of-7 committee member, always a snapshot entry, never absent); at e2 retiring it alone leaves the next epoch's seatable set = the 6 other genesis validators (plus, if `test_v2_stake.sh` ran earlier, a staker whose bond is the SAME `DNAC_SELF_STAKE_AMOUNT`, `test_v2_stake.sh` `BOND`), all at equal power, so the largest member holds at most 1/6 of the set's power and `(P − max) > P*2/3` holds (round 6's voting-power floor, which replaced round 5's count floor `DNAC_RULE_N_MIN_BONDED` = 4 — neither engages here); graduation (R5-3) is candidate-gated on status first, and node 7 only BECOMES AUTO_RETIRED partway through e2's own Rule N step (step 4), AFTER e2's own graduation phase (step 2) already ran — so it was never a graduation candidate at e2 either way, with or without R5-3's snapshot check; by e3, `commit_next(e2)` has already excluded it from snapshot(e3) (top_n selects ACTIVE/ELIGIBLE only), so R5-3's deferral condition does not hold and it graduates at e3 exactly as before. (Node 7 is a GENESIS seat: under W-A its bond went into treasury pool 8 with no release UTXO; general multisig withdrew that refund, so at e3 its 10M bond is released as a locked UTXO at output index 200 to its own fingerprint like any seat's. This scenario asserts status / attendance / the CMT-APP removal line, never that UTXO or the pool, so no assertion changes.) Net: this scenario has no in-conflict candidate for R5-2's floor or R5-3's deferral to change, so e1/e2/e3 stay where they were. **Tokenomics-v3 P3 fix round (header only, NOT re-measured, no assertion changed):** with the default target at 32 the `test_v2_stake.sh` staker (`v2user`, no running node, never signs) is SEATED from the first snapshot built from a copy holding its bond (start of that epoch = S) until Rule N retires it at S+2E; while it is seated the set is 8, `dna_bft_quorum(8) = 6`, and with node 7 stopped exactly 6 of 8 sign — the chain commits with ZERO margin (the old "6 of 7 > 5" holds only once the staker is gone). And since cometbft drops a retiree one boundary after Rule N, the staker leaves at S+3E and node 7 at e3 = A+3E (A = the aligned stop); they land at the SAME boundary only when S == A, in which case node 1 logs `n_removed=2` at e3 and this scenario's `n_removed=1` grep FAILS on a correct chain — check the staker's retirement boundary against A before calling such a FAIL a consensus defect. | **Short-epoch build only:** `-DDNAC_EPOCH_LENGTH=<E>` + `STAGEF_EPOCH_LENGTH=<E>`. SKIPS (99) at the shipped 720 — needs THREE boundaries' worth of wall time (`STAGEF_RULE_N_RETIRE_BUDGET_S`, default 5400 s), computed from the current tip the same way `test_v2_epoch_boundary.sh` computes its own reachability budget: blocks needed × the per-block pace — `STAGEF_CMT_PUMP_BLOCK_S` (15 s) when the CLI-SPEND pump is usable, `STAGEF_CMT_EMPTY_INTERVAL_MS` (60 s idle pace) otherwise. Optional (CLI-SPEND): a built `nodus-cli` and `STAGEF_PUMP_FUNDER_NODE` / `STAGEF_PUMP_SUBMIT_NODE` (defaults 3 / 1). Victim is node 7, FIXED. Placed AFTER every leaf-spending and epoch-boundary scenario. | Node 7 `SIGSTOP`ped then `SIGCONT`ed — an EXIT trap resumes it on any early exit. Node 7 is PERMANENTLY AUTO_RETIRED on this bring-up (not reversible within it) — nothing later in the sweep may assume 7 ACTIVE validators; this is why it runs immediately before `test_p2p_seam_faults.sh`, which only reads node logs and does not care which validators are still ACTIVE. When pumped: node 3's genesis leaf claimed by the first pump step (unless an earlier pump already did) and one fee per pump step gone from node 3's single coin; a SKIP leaves nothing (the pace decision is a pure check). | The script does not stop node 7 immediately on entry — it first waits (node 7 still healthy) for a FRESH epoch start, so both watched epochs are unambiguously 0% attended BY CONSTRUCTION rather than by luck of where in an epoch the scenario happened to start; the epoch bounds are then RE-DERIVED from the height actually reached after the stop (self-correcting against a stop that races a boundary block), never assumed from the pre-stop height. The "1 removal" INFO line is asserted at the THIRD boundary specifically — asserting it at the second (where the DB flip happens) would either never fire or silently measure the wrong thing, exactly the mistake this row's own header explains was in this scenario's ORIGINAL dispatch text. Like `test_cmt_dead_proposer.sh`, no positive "round advanced" log line exists on this lane; height movement alone is never the load-bearing assertion — every check reads `v2_attendance` / `validators` / the CMT-APP log line directly. **Only the 50% bar is exercised here, never the 120-block recency window:** at E=15 the window is longer than the two watched epochs, so the victim's frozen `last_signed_height` is still inside it at e2 — the recency rule and the Rule N voting-power floor are covered only by `test_v2_epoch.c` (§11a; the floor §12c, §12e-§12i) at E=720 — this scenario's single retirement never exercises a refused one. **One-block credit lag (MEASURED, first short-epoch sweep at 0.19.67):** the victim's frozen `last_signed_height` is read 3 heights after the stop, not at it — a precommit sent just before the stop is credited one block later (29 -> 30), the same race `test_cmt_dead_proposer.sh` hit; the first watched epoch is therefore 0-1 signed blocks, not exactly 0 (still far below the bar). **CLI-SPEND:** every production wait (alignment, settle, the three boundaries, the final settle) goes through `stagef_cmt_advance_to` — pumped, the watched epochs carry self-send SPENDs; idle, they are empty blocks. Rule N reads signatures, not block content, so both exercise the same rule, but neither proves the other's shape; the `[ok] block driving:` line says which one ran. A dropped pump spend or a pump fault FAILS the wait it happened in — never retried or downgraded. The victim's catch-up waits after `SIGCONT` stay idle (replication, not production). **Fixed at the P1 landing:** the stop-SETTLE block used to reuse the name `settle_to` and overwrite the final "e3 + 7" target, so the final settle returned at once; it now has its own `stop_settle_to` (the short-epoch sweep run 2 at 0.19.67 still ran the old shape). |
| `test_split_storage_restart.sh` (split S5b; **SKIP 99 unless `splits` / `mixeds`**) | On the first storage-split node (core = `nodus-server --storage-external` with its witness in-process, DHT = `nodus-storage`): a `nodus-cli put` + `get` through the core works; `kill -9` of `nodus-storage` leaves the core alive and the node's own Comet tip still advancing (`stagef_cmt_wait_height`, progress-bounded); once the core has logged `control connection to nodus-storage lost`, a put gets AT ONCE `PUT error: [21] storage module not available` (decision 31 — `NODUS_ERR_UNAVAILABLE`); restarted (`stagef_spawn_storage`), the core logs a NEW `control connection to nodus-storage up` AND a NEW `routing snapshot from nodus-storage` (the snapshot re-pushed on the new control connection), and a new put + get work and the pre-kill value reads back. The property that would be false: *storage is a separate failure domain — its death costs DHT service only, is reported to clients at once, and its return needs no core restart.* | Compile: none (default build; `nodus-server`, `nodus-storage`, `nodus-cli` from ONE build). Env: a cluster born in `STAGEF_MODE=splits` / `mixeds`; `STAGEF_NODUSCLI_BIN`; the bring-up's `STAGEF_NODUS_BIN` / `STAGEF_NODUSSTORAGE_BIN` (both processes are found by executable). | The victim's `nodus-storage` under a NEW pid appended to `pids.txt`; its `storage.log` holds two runs (every log assertion is a BEFORE/AFTER count delta); two DHT values with random keys (7-day TTL) on the victim and its replicas; the victim's DHT-active client sessions were closed when storage died (decision 32). | "At once" is read from the CLI's output (the decision-31 text vs its 5 s "No response to PUT"), not a clock; the error is asserted only after the core has SEEN storage go — a request racing the kill is not tested; the witness is in the core in these modes, so "chain keeps committing" says nothing about a three-process node (S6); the post-restart reads prove storage serves again and the on-disk value survived, nothing about state the dead process held only in memory; rc 99 = SKIP (no storage-split node). |
| `test_p2p_seam_faults.sh` (**split S3, adapted:** scans each node's `stagef_node_log` — `witness.log` on a split node, `nodus.log` otherwise; a split node's core log is not scanned) (P2P-PORT F6 — REPLACES `test_cmt_arena_runway.sh`, DELETED: it grepped the old transport glue's `recv_arena at 50%/90%` latches, which died with `nodus_witness_cmt_net.c`, so it passed vacuously) | Across the WHOLE sweep, on every node, the 4004 host started (`p2p on … persistent peer(s)`) and never handed the consensus or mempool reactor a message that made it report a NODE-LOCAL fault: no `conr receive: CMT_FAULT` / `memr receive: CMT_FAULT` line (`nodus_witness_p2p.c` cons_receive / mem_receive). CMT_FAULT from `cmt_conr_receive` / `cmt_memr_receive` is the reference's panic class (`cmt_conr.h` "NODE-LOCAL → CMT_FAULT") — never a property of what a remote peer sent (that is CMT_REJECT, a WARN, not counted); R-P2P-53 made it log-and-continue, so this scan is its only verdict. **Must run LAST** — its subject is every earlier scenario's traffic (kills, stops, restarts, floods included). | Default build with the 4004 p2p port (F5+). Read-only; submits nothing. | Nothing. | A green scan on a binary without the seam would be vacuous — the host's start line is REQUIRED on every node (a missing one FAILS). Absence of a fault line is not proof of delivery (a message dropped before the reactor knew the peer, R-P2P-47, is a DEBUG line; a REJECT is not counted) — the sweep's 7/7 agreement covers delivery. `test_v2_partial_wipe.sh` (node 5) and `test_v2_join.sh` (node 6) TRUNCATE their node's log, so for those two the scan covers only the lifetime since that scenario — disclosed, not hidden. Read, not assumed (`cmt_conr.c` cmt_conr_receive, `cmt_memr.c` cmt_memr_receive): the one peer-state fault ("Peer %d has no state") is unreachable from a stopped / killed / re-added peer because the host drops such messages first (`nodus_witness_p2p.c` cons_receive / mem_receive guards); memr's `cmt_mem_check_tx` fault is the app's CheckTx faulting — node-local, but a disk/DB error could produce it, so a RED naming `memr receive` needs the node log read first. |

#### Not in the sweep

| Script | Requires | Exercises |
|---|---|---|
| `test_v2_grow_7_20.sh` (**split S3: SKIP 99 in `splitw` and `mixedw`**) (Comet lane since GROW-7-20-COMET, 2026-09-26; **adapted to the 4004 p2p port in P2P-PORT F6 — written against the source, NOT yet run on either**) | **Compile** (nodus-server AND nodus-cli from ONE build — the CLI enforces the grace floor with its own constant): the Quick-start short-epoch line, all four: `-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15`, from a tree with the 4004 p2p port. **Env, ALL exported BEFORE `stagef_up_v2.sh`:** `STAGEF_NODUS_BIN` / `STAGEF_NODUSCLI_BIN` → that build, `STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20 STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15 STAGEF_V2_CANDIDATES=13`; `STAGEF_PUMP_SUBMIT_NODE` must stay 1 (nodes 2..7 are stopped). No pump leaves needed (height comes from the CLI-SPEND pump, node 3's leaf). **SKIPs (99)**: not a version-3 cluster, no network file (a bring-up on a pre-p2p server — P2P-PORT F6), a candidate missing, E outside [15, 20] (15 = the STEP 6a pigeonhole window; below it Rule N could retire the stopped validators), grace > E, pump unavailable, submit node ≠ 1. ≈ 45-75 min on a 4-CPU machine (JUDGMENT, not measured). **Run standalone on its own fresh bring-up, then tear down.** **Leaves behind:** 13 candidate nodes (`cand1..13`, derived locally from the config, ports C+3+i) plus a 21st non-validator replay node (`grow_replay`), all in `pids.txt`; a PERMANENT 20-seat committee and two `chain_config_history` rows (param 4); every candidate leaf claimed and bonded; node 3's leaf claimed by the pump; every node restarted once, cand12 twice; nodes 2..7 and cand13 SIGSTOPped and resumed (an EXIT trap SIGCONTs; a node KILLED inside STEP 7/8 is NOT restarted on failure); `$BASE_DIR/grow_ping/` (STEP 4f's raw probe results). | **Proves:** a running version-3 chain grows its validator set 7 → 10 → 20 by governance and cometbft's OWN voting set follows, and at N=20 with equal power the chain commits with 14 alive and stops with 13. Steps: (1) 13 strangers claim + bond (ledger effects; 20 equal `self_stake`, no delegation — read, not assumed), bonding is not membership; (3) TARGET_ACTIVE_COUNT=33 built by the OFFLINE `v2-envelope chain-config` path is refused by the CheckTx of each of the 7 genesis nodes (`rc=7 status=0`; `chain-config propose` would refuse it in the CLI itself, `nodus-cli.c:1393`); (2) vote A = 10 at E_MID via networked `chain-config propose`, vote B = 20 at E_GROW via the SAME offline path as the refusal (its control) — E_MID / E_GROW are DERIVED from the bond heights that landed (tenure `active_since + 2E ≤ e`, frozen copy(e−2E), "okuma B"), every vote committed before the boundary that reads it; (5) the epoch before E_MID is still 7 seats while all 20 are eligible at E_MID at equal frozen totals; (4) E_MID seats exactly 10 (the default would seat 20), E_GROW 20 — counts and hashes identical on all 20 nodes, cometbft's `validator_updates n_added/n_removed` line identical on all 20, and the committed header's NEXT-validators hash (`v2_blocks.vset_hash`, `nodus_witness_cmt_app.c:2356-2364`) equal at H−1/H, changed at H+1, equal again at H+2 (the two-height lag); **(4f, P2P-PORT F6, NEW) at N=20 node 1 and cand1 answer EVERY back-to-back `nodus-cli ping` (fresh connect + AUTH + PING each) while the pump drives ≥ 3 commits — the defect `nodus/BUGS.md` "P1 LIVENESS AT N≥20" measured on the old transport (5-15 s of no client service per commit) must be gone; the bound is the CLI's own fixed 5 s per step, never a number of the script;** (6) arithmetic `sum > total*2/3` (`cmt_vote_set.c:967`), power 10^7 each: N=20 needs 14 (N=10 needs 7). Aligned to a fresh epoch start (Rule N), genesis nodes 2..7 are SIGSTOPped: the chain commits ≥ 15 heights (pigeonhole: a stopped round-0 proposer — an INFERENCE from the ported selection, not observed), the 6 sign nothing, all 14 running sign; cand13 stopped too: NO height across 3 CreateEmptyBlocks intervals with a CheckTx-approved spend pending (the expected safety stall, ≤ 2 in-flight heights allowed); all resumed: that spend lands, 20/20 agree; (7) all 20 killed and restarted, chain resumes, latest snapshot 20; (8) cand12 down across a boundary, catches up, agrees on that boundary's snapshot; (9) a fresh, non-validator node adopts by pin and replays genesis → head, both growth boundaries identical. Ends asserting no validator AUTO_RETIRED and the latest snapshot still 20, then `stagef_cmt_diff_at_floor` (7) + its own 20+1-node floor comparison (the helper only loops 1..7). **P2P-PORT F6 adaptation:** the stake builder takes no `--db` (K3); every node (genesis, candidates, the STEP 9 joiner) finds its 4004 peers through the network file in `nodus.json` — the candidates DIAL the seven genesis nodes (reference inbound admission, max 40; bonded identities exempt from the cap, K2) and PEX spreads their addresses; 20 nodes on 127.0.0.1 need the harness-only `allow_duplicate_ip` / `addr_book_strict=false`. **How it can lie:** CheckTx APPROVED is never read as inclusion (every wait is `stagef_cmt_wait_row` on the ledger effect); the stall is framed by a positive control (6a) and a recovery of the SAME pending spend (6c), which is what tells a quorum stall from 20 processes starving on 4 CPUs; `rc=7` is also other mempool refusals — the same-path vote B is the control; STEP 4f SAMPLES two nodes back-to-back — a stall shorter than the gap between two probes, or on an unprobed node, is not seen (the slowest probe is printed, never asserted); how long a from-genesis catch-up of 13 candidates takes over the new 4004 stack is NOT measured yet — the candidate catch-up waits with a wide 8-interval progress bound and FAILS with that reason; the joiner's adoption is attempt-bounded at 600 s; STEP 1c (~10 blocks from genesis, 13 nodes at once) and STEP 9 (~130 blocks) are the FIRST long-gap catch-ups this harness asks of this lane (see "What a green COMET run does not prove" item 4) — the likeliest place for a first-run stall; 6a runs at EXACT majority (14 of 14 running must sign), so a RED there needs the node logs read for round timeouts before it is called a defect; the Rule N safety of the stop windows rests on each resumed validator signing ≥ 50 % of the following epoch, which 6c's all-20 catch-up wait provides — a RED at the terminal "no validator AUTO_RETIRED" check points at resume/catch-up lag first; green at E=15 / grace 15 proves the LOGIC only. Its FLAKY history (v0.19.48, a legacy view-boundary loss) belongs to the deleted lane. |
| `test_v2_grow_7_32.sh` (**split S3: SKIP 99 in `splitw` and `mixedw`**) (P2P-PORT F6, the operator's FINAL scenario, design `docs/plans/2026-09-26-p2p-port-design.md` §10 — **written against the source, NOT yet run**) | **Compile** (nodus-server AND nodus-cli from ONE build, a tree with the 4004 p2p port): **an EPOCH LENGTH OF 30, not the Quick-start 15** — either the four-flag line with 30 (`-DDNAC_EPOCH_LENGTH=30 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15`) or `-DDNAC_EPOCH_LENGTH=30` alone (no governance, no halving here — then leave `STAGEF_BLOCKS_PER_YEAR` at its default). Why not 15: at N = 32 ten validators stop for a 23-height pigeonhole window plus the halt and the recovery (≈ 30 heights); at E = 15 they miss two consecutive epochs and Rule N (`signed_count·10000 >= E·5000`, `nodus_witness_v2_epoch.c:907-930`; 2 misses retire, `dnac.h:321`) AUTO_RETIREs them by construction. **Env, ALL exported BEFORE `stagef_up_v2.sh`:** `STAGEF_NODUS_BIN` / `STAGEF_NODUSCLI_BIN` → that build, `STAGEF_EPOCH_LENGTH=30` (+ `STAGEF_BLOCKS_PER_YEAR=20` with the four-flag build), `STAGEF_V2_CANDIDATES=25`; `STAGEF_PUMP_SUBMIT_NODE` stays 1. **SKIPs (99)**: not a version-3 cluster, no network file (pre-p2p server), a candidate missing, E outside [30, 40], pump unavailable, submit node ≠ 1. ≈ 45-90 min on a 4-CPU machine (JUDGMENT, not measured). **Run standalone on its own fresh bring-up, LAST, then tear down.** **Leaves behind:** 25 candidate nodes (`cand1..25`, ports C+3+i) in `pids.txt`; a PERMANENT 32-seat committee; every candidate leaf claimed and bonded; node 3's leaf claimed by the pump; nodes 2..7 and cand21..25 SIGSTOPped and resumed (an EXIT trap SIGCONTs on any exit); `$BASE_DIR/grow32_claim_*.log` / `grow32_stake_*.log`; the chain ≈ 7 epochs on. | **Proves:** on the 4004 p2p port a running version-3 chain seats 25 strangers who bond on it — 32 validators, the ceiling, with **no governance vote** (default target 32, `dnac.h:253` = `NODUS_V2_ACTIVE_SET_MAX`, `nodus_witness.h:151-155`) — cometbft's OWN set follows, and at N = 32 with equal power (`sum > total*2/3`, `cmt_vote_set.c:967`: 22 needed) the chain commits with 22 alive, halts with 21, and comes back at 22. Steps: (1) 25 candidates derive the fleet's chain, start with `-c nodus.json` (persistent peers = the 7, PEX for the rest — each log's `p2p on … 7 persistent peer(s)` line asserted), go LIVE and catch up; each claims and bonds (`v2-envelope stake`, no `--db`), every step waited on its ledger effect; 32 equal bonds, no delegation; bonding is not membership; (2) E_ALL = max over the 25 of ceil(a/E)·E + 2E (a = the bond height; tenure `active_since + 2E <= e`, `nodus_witness_validator.c:357-395`; a stake in boundary block B is inside copy(B), `nodus_witness_committee.c` "okuma B" comment) — checked on the chain: every bond in copy(E_ALL − 2E), that copy 32 equal totals, snapshot(E_ALL − E) = 7 + the candidates already eligible then, snapshot(E_ALL) EXACTLY 32 (count + hash identical on 32 nodes), no TARGET_ACTIVE_COUNT row, the ValidatorUpdates line identical on 32 (added 32 − previous, removed 0), and the committed next-validators hash equal at E_ALL−1/E_ALL, changed at E_ALL+1, equal at E_ALL+2 on all 32; (3) aligned to a fresh epoch start, nodes 2..7 + cand22..25 SIGSTOPped: the chain commits 23 heights (pigeonhole), the ten sign nothing, all 22 running sign; (4) cand21 stopped too: a CheckTx-approved spend pending and NO height across 3 CreateEmptyBlocks intervals (≤ 2 in-flight); (5) cand21 alone resumed: the SAME spend lands, the chain advances 3 heights with the other ten still stopped (their attendance frozen), then the ten resume and all 32 agree at a floor (its own 32-node comparison — `stagef_cmt_diff_at_floor` loops 1..7); (6) past boundary b + 2E (the first that could retire a stopped validator) no validator is AUTO_RETIRED and the latest snapshot still seats 32. **How it can lie:** CheckTx APPROVED is never read as inclusion; the halt is framed by the positive control (3) and the recovery of the SAME spend (5), which is what separates a quorum halt from 33 processes starving on 4 CPUs — every STEP 3-5 failure names its step and prints per-node state, tip and one-second CPU share (/proc); (3) runs at EXACT majority (22 of 22 must sign), so a RED there needs the node logs read for round timeouts before it is called a defect; (5) resumes the LAST node stopped (≤ 2 heights behind), so it tests quorum restoration, not long catch-up; the pigeonhole is an INFERENCE from the ported proposer selection; **the K2 inbound-cap exemption for bonded identities is NOT exercised** — a genesis node's inbound peers are ≤ 31 < 40 (`cmt_p2p_switch.h:138`); a 25-node from-genesis catch-up on the new stack is not measured yet (8-interval progress bound, FAILs with that reason); the snapshot's members are counted, not decoded (32 seats of exactly 32 eligible rows); `allow_duplicate_ip` / `addr_book_strict=false` are harness-only; green at E = 30 proves the LOGIC only, nothing about the production 720. |
| `test_p2p_stopall_nowipe.sh` (**split S3: SKIP 99 in `splitw` and `mixedw`**) (P2P-PORT F6, NEW; item 1b + negative mode P2P-FIX-1 E2 — written against the source, NOT yet run) | **Compile:** TWO default builds, nodus-server from each: OLD = a 0.19.80 build WITHOUT the 4004 p2p port (e.g. the operator's main tree `nodus/build`), NEW = the p2p-port build (0.20.0+); same compiled constants. **Env:** `STAGEF_NODUS_BIN_OLD`, `STAGEF_NODUS_BIN_NEW`, `STAGEF_NODUSCLI_BIN` = a NEW nodus-cli (it writes the network file's IDs and pumps NEW nodes only); `STAGEF_STOPALL_NEGATIVE` (unset/0 = default run, 1 = the negative control of the WAL carry-over INSTEAD of items 4-6 — never in a default run); OLD must be the SQLite-WAL build (0.19.80 — consensus WAL rows in the chain DB's `cmt_wal`, checked, FAIL otherwise); bring-up ON OLD: `STAGEF_NODUS_BIN=$STAGEF_NODUS_BIN_OLD bash stagef_up_v2.sh` (it sees an OLD server and writes no network file). **SKIP (99):** a binary missing, OLD == NEW byte-identical, not a Comet cluster. **FAIL (1)** on the capability/version gate: OLD's `-h` lists `--network-file`, NEW's does not, or the `-h` banner versions are not OLD < NEW. The script runs each server once with `-h`. **Run standalone.** **Leaves behind:** all 7 nodes on NEW under new pids (logs appended — node 7's holds OLD, NEW, OLD, NEW); `$BASE_DIR/network.json` (pin = the chain id, the 7 peers); the NEW build's p2p files in each data dir; node 3's leaf claimed and pump fees spent when the pump was usable; nothing wiped; up to 7 extra heights committed through freeze/resume cycles (item 1b; an EXIT trap SIGCONTs a node still frozen); every data dir gains `cs.wal/wal` (the carried tail) while the SQLite `cmt_wal` rows stay. On a FAIL the nodes stay as they were (node 7 possibly on OLD) — tear down. **Negative mode** deletes the 4 signers' `cmt_wal` rows and leaves the chain HALTED at H on NEW by design (a SKIP 99 there leaves the cluster resumed on OLD) — tear down. | **Proves:** the 4004 p2p port ships as STOP-ALL, NO WIPE (decision `2026-09-26-witness-port-session.md` "Deploy: zincir SİLİNMEZ"): (1) the chain started on OLD commits, 7/7 agree, advances ≥ 2 heights; **(1b, P2P-FIX-1 E2 — decision `2026-09-26-cmt-wal-file-group.md` DÜZELTME + item 6 AMENDED) the dangerous precondition exists at the stop:** right after a fresh commit at tip H, 3 of 7 are SIGSTOPped inside the idle 60 s window and that is CHECKED (each frozen node's `priv_validator_state.json` height ≤ H and 0 `cmt_wal` MsgInfo rows at H+1, else the attempt is discarded); the other 4 (below > 2/3) sign at H+1 — each privval shows height H+1, step ≥ 2, printed with round/step and BLOCK or NIL (decoded from `signbytes`), and each holds ≥ 1 MsgInfo row at H+1; the dangerous form is ≥ 3 BLOCK signers (the rest hold 4 of 7 < 5), searched for over ≤ 7 attempts with the frozen trio rotated (an attempt with fewer is resumed and the chain commits); (2) the stop: the 3 frozen SIGKILLed and the 4 SIGTERMed in one loop, every process and client port gone, and every chain tip ≤ H (no commit at H+1 during the stop); (3) the network file written (pin = the bring-up's chain id — the devnet plan) and all 7 restarted on NEW over the SAME data dirs with `-c nodus.json`: per node the process IS NEW (`/proc/<pid>/exe`), NEW `Nodus v<NEW> running`, NEW role + `completed ABCI handshake`, `p2p on … 7 persistent peer(s)`, no `REFUSING START` (the pin-at-start check passed), the SAME chain file, tip ≥ its own pre-stop tip (no genesis restart); (3b) each of the 4 signers logs a NEW `consensus WAL carry-over:` line (its SQLite-era tail re-framed into `cs.wal/wal` before NewWAL; the frozen 3's printed); (4) EVERY node's own tip passes the pre-stop maximum + 3 — so H+1, which the 4 had signed, committed — and 7/7 agree past it — blocks travel only over 4004, so each node's progress is its mesh evidence; (5) NEGATIVE: node 7 restarted on OLD comes up (NEW role + LIVE lines, process alive at the end) and its tip stays FROZEN while the six NEW nodes advance ≥ 5 heights; (6) node 7 back on NEW catches up, +2 heights, 7/7 agree; **(N, opt-in `STAGEF_STOPALL_NEGATIVE=1`, instead of 4-6) negative control of the carry:** same precondition, the 4 signers' `cmt_wal` rows deleted before NEW (their carry finds nothing — NEW without the carry); requires the BLOCK form (else SKIP 99); expected, derived from the recorded privval state: every block signer logs a NEW `failed signing vote: height H+1 round 0` (privval refuses the step regression / conflicting data) and the tip does not pass H across 3 CreateEmptyBlocks intervals — a commit at H+1 FAILS it. Deterministic in the BLOCK form only; the NIL form (a nil signer may re-sign nil or refuse a new proposal, depending on whether the proposal beats its propose timeout) is NOT deterministic and never asserted. **How it can lie:** the OLD phase advances by idle production only (60 s/block; the NEW CLI never talks to an OLD server) — item 1b too: the dispatch asked for a pumped chain during the freeze, but a pumped chain proposes H+1 ≈ 4 s after H and races the freeze, so the 4 sign at the 60 s empty-block interval instead; item 1b's BLOCK form is SEARCHED for (the round-0 proposer is not readable anywhere — `cmt_cs.c` logs none, `v2_blocks` has no proposer column): if 7 attempts give fewer than 3 block signers the default run continues on the NIL form, prints `[WARN] PRECONDITION: NIL form` and names the form in its PASS line — such a PASS proves the carry on a restart after signing, NOT that it prevented a halt; block/nil is decoded from the CanonicalVote field layout (a layout change prints `unknown` = no block signer); the frozen-node proof is "privval ≤ H and no MsgInfo row at H+1" — a proposal sitting unread in a frozen node's socket buffer is not seen and dies with the SIGKILL; item 3b reads a log line — that the replay carried the 4's own votes is inferred from H+1 committing; "the mesh formed" is inferred from per-node progress — the new stack logs no per-peer "added" line and the "persistent peer(s)" line is config; "no genesis restart" = same chain file + tip never behind its pre-stop value; the negative arm is ONE old node for ≥ 5 heights, and the six's `connection rejected` lines are printed as evidence only (which check refuses the old handshake first is not pinned); both builds must carry the same compiled constants or the NEW open fails for an unrelated reason; allow_duplicate_ip / addr_book_strict=false are harness-only. |
| `test_cmt_hf1_gas_upgrade.sh` (**split S3: SKIP 99 in `splitw` and `mixedw`**) (HF-1, design `docs/plans/2026-09-26-hf1-gas-price-design.md` §6) | **Compile:** TWO short-grace builds, each `nodus-server` + `nodus-cli` from one tree, both with `-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15`: OLD = 9b7260c0 (0.19.79, pre-HF-1), NEW = the HF-1 tree. **Env:** `STAGEF_NODUS_BIN_OLD` / `STAGEF_NODUSCLI_BIN_OLD` / `STAGEF_NODUS_BIN_NEW` / `STAGEF_NODUSCLI_BIN_NEW`, `STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15` (read by the script only — `stagef_up_v2.sh` never reads them); bring-up with `STAGEF_NODUS_BIN=$STAGEF_NODUS_BIN_OLD STAGEF_NODUSCLI_BIN=$STAGEF_NODUSCLI_BIN_OLD bash stagef_up_v2.sh`; the negative arm is `STAGEF_HF1_NEGATIVE=1` on its OWN fresh bring-up. Exact build + run sequence in the script header. SKIPs (99) when a binary is missing, OLD == NEW, or a grace variable is not 15. FAILs (1) when a binary's own `-h` banner (`Nodus Server v…` / `Nodus CLI v…` = `NODUS_VERSION_STRING`) is not OLD < 0.19.80 / NEW == 0.19.80 — the script runs each binary once with `-h` for that. **Run standalone** — it restarts every node on another binary and claims v2user's, node 2's and node 3's leaves. **Leaves:** positive — all 7 nodes on NEW (new pids, appended logs), two param-5 rows (price P at H, price 0 at a later H2 — the rule is OFF again once the chain passes H2), the three leaves claimed and partly spent (v2user: two floor-fee spends applied — step 3 and the rule-off-window spend — the post-activation one refused); negative — nodes 1-6 on NEW; node 7 REBUILT by wipe + genesis-pin rejoin on NEW (identity kept, databases re-adopted, log appended across all three of its runs; left wiped or half-rejoined if N5b fails); the param-5 row on all 7. Negative mode also needs `$BASE_DIR/v2_genesis_pin` (written by `stagef_up_v2.sh`). **How it can lie:** a CheckTx refusal reaches the CLI only as `dnac_spend RPC failed (rc=7)` (`NODUS_ERR_PROTOCOL_ERROR`; the dry run's item code 9 is a server DEBUG line) — the step-3 control (same OLD-CLI shape applied at price 0) and the NEW CLI's spend admitted right after are what tie that rc 7 to the price rule; P is the SMALLEST underpaying price (8 221 units → 122, 1 002 962 vs 1 000 000); the version gate trusts `NODUS_VERSION_STRING` (a tree with the bump reverted or hand-bumped passes/fails on the number, not the code; NEW is pinned to exactly 0.19.80, so a later bump must update `HF1_VERSION`); the rule-off window check proves D1 at the ONE height the in-window spend landed at (printed), not at H − 1 specifically, and FAILs (never skips) when fewer than 3 heights of the window remain after the row lands; D3 covers only what the mixed fleet carried (idle blocks, 1-in/1-out spends, claims); the negative arm's proposer is node 7's own seat via the NEW CLI (self-signed, so round 1 is 7/7 — proposing from a NEW node would hit the OLD responder's refusal and a round 2 that races the 5 000 ms per-proposer rate limit), so the OLD responder's refusal path is NOT exercised; **N5a ASSERTS that a restart does NOT recover node 7** (decision `2026-09-26-hard-fork-lagging-node.md`, measured by this scenario's first run: row at h22, node 7 stuck at 22 on NEW while the fleet reached 31) — the OLD binary's refusal is a per-item exec code, so node 7 commits the vote's block with a divergent state, and the ABCI handshake does not re-execute a committed block when app == store == state height; if a later build makes the old binary HALT instead (the record's open item (b)), N5a goes RED by intent and the scenario is revised with the record; N5a requires a NEW `completed ABCI handshake` line first, so "stayed at R" cannot be "never started", but it does not prove WHY it stays (log lines are evidence only); N5b's row is re-derived by re-execution, not copied — the wipe is verified before the restart. Grace 15: the LOGIC of the cutover, nothing about the production 720. | HF-1's **wipeless binary upgrade + live cutover** (decision `2026-09-23-height-activated-upgrades-before-testnet.md`). Both modes first prove OLD is really pre-HF-1 and NEW is HF-1 (R3-F4: version banners, plus `Nodus v<X> running` in every node's log at start and after every upgrade). Positive: 7 nodes rolled OLD → NEW one at a time (SIGTERM, same data dir / identity / ports), each rejoining (role, completed handshake, same chain file) with real spends carried and 7/7 agreement after EVERY step (D3/G4); before activation the OLD CLI's floor-fee spend is applied; a `GAS_PRICE_RAW_PER_UNIT` vote (NEW CLI) lands identically on 7/7; between the row's landing and the effective height the SAME underpaying OLD-CLI floor-fee spend is still APPLIED at a height < H (D1: the rule is OFF until H, R3-F3); after the effective height the OLD CLI's floor-fee spend is refused at CheckTx and never lands (coin untouched), the NEW CLI's spend pays `units × P` (fee read from the ledger) and applies, and a fee-0 governance vote still lands (G3). Negative arm (D4): with node 7 left on OLD the six hold the row and keep committing and agreeing, node 7 holds no row and its tip freezes at the row's commit height while the six advance ≥ 5 heights; (N5a) restarted on NEW it completes its handshake but STAYS at that height, still without the row, while the six advance ≥ 3 more — a restart is not a recovery; (N5b) the documented recovery — stop, wipe the chain data exactly as `test_v2_join.sh` does (identity kept), restart on NEW with `--v2-genesis-pin` — adopts the fleet's chain, goes LIVE, catches up, advances +2, holds the six's param-5 row byte-identically, and 7/7 agree. |
| `test_cmt_hf2_gov_power.sh` (**split S3: SKIP 99 in `splitw` and `mixedw`**) (HF-2, design `docs/plans/2026-09-30-gov-weight-netzero-design.md` rev 2 + §4a; decision `2026-09-30-governance-stake-weight-and-power-cap.md` item 1; runbook §2.2 "HF-2" — **written against the source, NOT yet run**) | **Compile:** TWO short-epoch + short-grace builds, `nodus-server` + `nodus-cli` from one tree each, both with `-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15` (the epoch because a power change reaches the committee two boundaries after the delegation): OLD = a82a2544 (0.23.1), NEW = the HF-2 tree **with its merge-time `NODUS_VERSION` bump** (at e05048e2..a9d55a4a the HF-2 tree still says 0.23.1 = OLD, and the gate FAILs by construction). **Env:** `STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20` exported BEFORE `stagef_up_v2.sh` (hashed into the genesis document); `STAGEF_NODUS_BIN_OLD` / `STAGEF_NODUSCLI_BIN_OLD` / `STAGEF_NODUS_BIN_NEW` / `STAGEF_NODUSCLI_BIN_NEW` and `STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15` (read by the script only); bring-up with `STAGEF_NODUS_BIN=$STAGEF_NODUS_BIN_OLD STAGEF_NODUSCLI_BIN=$STAGEF_NODUSCLI_BIN_OLD bash stagef_up_v2.sh`. Exact build + run sequence in the script header. **SKIPs (99)**: a binary missing, OLD == NEW byte-identical, `STAGEF_EPOCH_LENGTH` ≠ 15, a grace variable ≠ 15, not a Comet cluster. **FAILs (1)** on the version gate: pair banners disagree, NEW banner == OLD banner, or the `HF2_ACTIVE` name-table probe (`chain-config propose --param HF2_ACTIVE` against a port nothing listens on: OLD must print `Unknown param name: HF2_ACTIVE`, NEW must reach `client_connect failed`). **Run standalone** on its own fresh bring-up. Wall time not measured (JUDGMENT: tens of minutes). **Leaves:** all 7 nodes on NEW (new pids, appended logs); HF-2 ACTIVE from H — one-way; node 1's power doubled for good (10M NODUS self-delegated from its claimed leaf); rows param 7 = 1 at H and param 5 = the price in force at H+1000/+1002/+1003 (never reached, a no-op if reached); node 1's and node 3's leaves claimed; `$BASE_DIR/hf2/` (CLI logs + `node1_preH.db`, the pre-H copy). | **Proves:** HF-2's wipeless rolling upgrade and its power rule cutover. (0) OLD is 0.23.1-without-HF-2 and NEW is HF-2 (gate above). (1) the OLD chain commits, 7/7. (2) 7 nodes rolled OLD → NEW one at a time (same data dir / identity / ports), each back in its role with a completed handshake on the same chain file, real spends carried by the mixed fleet, 7/7 after every step. (3) node 1 self-delegates 10M NODUS; the first unequal set snapshot(P), P = ⌈h/E⌉·E + 2E, is DECODED on 7/7 (`vset_wire.h` layout) and ASSERTED: 7 seats, the 5 small seats (nodes 2-6) a seat quorum holding ≤ ⌊2T/3⌋ of the power, the big seat + 4 small > ⌊2T/3⌋ (power = total_stake / 10^8). (4) `chain-config propose --param HF2_ACTIVE --value 1` (NEW CLI, seat rule, 7/7 in round 1) at H (epoch offset 8, ≥ P + E) lands byte-identically on 7/7. (5) BEFORE H, with that row committed and power unequal, an OFFLINE `v2-envelope chain-config` approved by EXACTLY the 5 small seats is APPLIED (its param-5 row 7/7, commit < H, governing snapshot decoded again). (6) AFTER H: (a) the live-DB offline builder refuses the 5 small seats locally with its HF-2 power line; (b) the same 5-small shape built from a pre-H COPY of node 1's DB (seat rule) is REFUSED by the CheckTx of each of the 7 nodes (`rc=7 status=0`) and its row is absent on 7/7 three heights later; (c) CONTROL: big + 4 from the SAME copy, same epoch, same seat count LANDS on 7/7; (d) the live builder's big + 4 prints its HF-2 line (5 approvers, power > ⌊2T/3⌋) and LANDS on 7/7. (7) 7/7 at the end; every height printed. **How it can lie:** **GW-2 (a net-zero block applies instead of halting every node) is NOT exercised** — an honest mempool cannot produce that block; the only proof is `test_v2_native` `test_hf2_netzero_block`. **6b is a DEVIATION from its dispatch:** the offline builder with a live DB refuses a ≤ 2/3 set locally and sends nothing (`nodus-cli.c` cmd_v2_envelope, the `hf2_on` block), so the chain refusal is reached through a builder whose view is behind H — a SQLite `.backup` copy at T0 ≤ H−2 (it stands for any stale builder, above all the online `propose`, which keeps the seat rule because no RPC reports param 7); approvals bind epoch(T0) + the committee at T0, so T0 and every submission tip are ASSERTED to share one epoch, and 6c is the control that the stale path itself lands. `rc=7` is ANY CheckTx refusal — narrowed by 5, 6c and those epoch checks, not by a reason code (the dry run's reason is a DEBUG line). 6a/6d rest on the builder's own quorum logic (the builder and the engine share the total_stake / 10^8 derivation — self-consistent, not independent). Committee power vs commit power is taken as one value (ARCHITECTURE.md "HF-2" honest labels; never measured here). The online `propose` runs only under the seat rule. Fable F2's one-block offset after a boundary is NOT exercised (every CC submission is kept ≥ 3 heights from a boundary; a submission too close FAILs, never passes). Step 5 proves the seat rule at ONE height (printed), height-bounded to H − 1, FAIL if it does not land before H. The version gate trusts `NODUS_VERSION_STRING` + the name table. D3 across the mixed fleet covers idle blocks, 1-in/1-out spends and claims only (the delegation and every vote run on 7/7 NEW). E = 15 / grace 15 / BPY 20 — the LOGIC, nothing about production 720 / 720 / 17 280. rc 99 = coverage that did not happen. |
| `test_cmt_hf3_block_bounds.sh` (**split S3: SKIP 99 in `splitw` and `mixedw`**) (HF-3, design `docs/plans/2026-10-01-hf3-comet-block-bounds-design.md` rev 3 §1 "Harness"; decision `2026-10-01-hf3-comet-only-block-bounds.md` — **written against the source, NOT yet run**) | **Compile:** TWO builds with the HF-2 scenario's flag set, `nodus-server` + `nodus-cli` from one tree each: `-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15` (HF-3 reads no epoch quantity; the epoch flags are the design's short-epoch build and the two builds must agree): OLD = the live binary at build time (2026-10-02: 0.23.8, 59ea5733, a post-HF-2 build — **re-check on build day**), NEW = the HF-3 tree **with its merge-time `NODUS_VERSION` bump**. **Env:** `STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20` exported BEFORE `stagef_up_v2.sh`; `STAGEF_NODUS_BIN_OLD` / `STAGEF_NODUSCLI_BIN_OLD` / `STAGEF_NODUS_BIN_NEW` / `STAGEF_NODUSCLI_BIN_NEW` and `STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15` (read by the script only); bring-up with `STAGEF_NODUS_BIN=$STAGEF_NODUS_BIN_OLD STAGEF_NODUSCLI_BIN=$STAGEF_NODUSCLI_BIN_OLD bash stagef_up_v2.sh`. Exact sequence in the script header. **SKIPs (99)**: a binary missing, OLD == NEW byte-identical, `STAGEF_EPOCH_LENGTH` ≠ 15, a grace variable ≠ 15, not a Comet cluster. **FAILs (1)** on the version gate: pair banners disagree, NEW banner == OLD banner, or the name-table probes (`chain-config propose` against a port nothing listens on): OLD must reach `client_connect failed` with `HF2_ACTIVE` and print `Unknown param name: HF3_ACTIVE`; NEW must reach `client_connect failed` with `HF3_ACTIVE`. **Run standalone** on its own fresh bring-up. Wall time not measured (JUDGMENT: tens of minutes). **Leaves:** all 7 nodes on NEW (new pids, appended logs); HF-2 ACTIVE from H2 and HF-3 ACTIVE from H — both one-way; rows param 7 = 1 at H2, param 8 = 1 at H; node 3's leaf claimed; `$BASE_DIR/hf3/` (CLI logs). | **Proves:** HF-3's ACTIVATION on a fleet that already runs HF-2 (the live chain's state). (0) OLD knows HF2_ACTIVE but not HF3_ACTIVE, NEW knows HF3_ACTIVE (gate above). (1) the OLD chain commits, 7/7. (2) `chain-config propose --param HF2_ACTIVE` (OLD CLI) lands on 7/7 and every node passes its height — HF-2 active on OLD. (3) 7 nodes rolled OLD → NEW one at a time (same data dir / identity / ports), each back in its role with a completed handshake on the same chain file, real spends carried by the mixed fleet, 7/7 after every step (D3: no param-8 row = identical blocks). (4) `chain-config propose --param HF3_ACTIVE --value 1` (NEW CLI, 7/7 NEW — the lagging-node record) lands byte-identically on 7/7, committed < H. (5) the fleet crosses H with real spends: 7/7 at the floor before H, at a floor ≥ H and at the end. (6) REPORTED only: applied envelopes per height below / from H (`v2_tx_index`). **How it can lie:** **the capacity lift is NOT exercised** — one spend in flight keeps every block far below 255 envelopes and 2 MiB on both sides of H; the lift (> 2 MiB AND > 255 at H, refused at H−1), the proposal fee check, rule 5 and rule 4 are proven by the unit tests `test_v2_apply` (`test_hf3_engine`) and `test_cmt_app` (`t_hf3_bounds_and_fee`), and the pre-vote measurements (FinalizeBlock at ~3 000 envelopes, fsync + PrepareProposal at 336 parts — decision answer 11) are NOT performed here. A per-block count is never asserted (a wall-clock race — design §1, R4-2). The block-size report counts APPLIED envelopes only. D3 across the mixed fleet covers idle blocks and 1-in/1-out spends only. If OLD is not the live binary, step 2 proves HF-2 activation for that build, not the live one. The version gate trusts `NODUS_VERSION_STRING` + the CLI name table. E = 15 / grace 15 / BPY 20 — the LOGIC of the cutover, nothing about production 720 / 720 / 17 280. rc 99 = coverage that did not happen. |
| `test_cmt_hf4_names.sh` (**split S3: SKIP 99 in `splitw` and `mixedw`**) (HF-4, design `docs/plans/2026-10-02-onchain-names-design.md` rev 4 §1.2-§1.5, §2, §3; decision `2026-10-02-onchain-names.md` items 1-18 — **written against the source, NOT yet run**) | **Compile:** TWO builds with the HF-2/HF-3 scenarios' flag set, `nodus-server` + `nodus-cli` from one tree each: `-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15` (param 9's rule (c) reads the epoch length; the two builds must agree): OLD = the live binary at build time (2026-10-02: 0.23.9, main 547fa773 / 30010235 — **re-check on build day**), NEW = the HF-4 tree **with its merge-time `NODUS_VERSION` bump**. **Env:** `STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20` exported BEFORE `stagef_up_v2.sh`; `STAGEF_NODUS_BIN_OLD` / `STAGEF_NODUSCLI_BIN_OLD` / `STAGEF_NODUS_BIN_NEW` / `STAGEF_NODUSCLI_BIN_NEW` and `STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15` (read by the script only); bring-up with `STAGEF_NODUS_BIN=$STAGEF_NODUS_BIN_OLD STAGEF_NODUSCLI_BIN=$STAGEF_NODUSCLI_BIN_OLD bash stagef_up_v2.sh` (it must record `$BASE_DIR/v2_genesis_pin`). Exact sequence in the script header. **SKIPs (99)**: a binary missing, OLD == NEW byte-identical, `STAGEF_EPOCH_LENGTH` ≠ 15, a grace variable ≠ 15, not a Comet cluster, no recorded pin. **FAILs (1)** on the version gate: pair banners disagree, NEW banner == OLD banner, or the name-table probes (`chain-config propose` against a port nothing listens on): OLD must reach `client_connect failed` with `HF2_ACTIVE` and `HF3_ACTIVE` and print `Unknown param name: RULESET_GEN2`; NEW must reach `client_connect failed` with `RULESET_GEN2`. **Run standalone** on its own fresh bring-up. Wall time not measured (JUDGMENT: tens of minutes — two rolling waves of pumped blocks, ~8 idle 60 s blocks across H, a from-genesis rejoin). **Leaves:** all 7 nodes on NEW (new pids; logs appended except node 6's, TRUNCATED by its wipe; node 4 restarted twice); HF-2 ACTIVE from H2, HF-3 ACTIVE from H3 and rule-set generation 2 from H — all one-way; rows param 7 = 1 at H2, param 8 = 1 at H3 and param 9 = D2 at H; ONE `v2_names` row (`punk` → node 1, permanent) with its price + fee in the reward pool; the leaves of nodes 1, 2 and 3 claimed; node 6's data dir rebuilt by pin adoption (identity kept); `$BASE_DIR/hf4/` (CLI logs). Param 9 and the leaves are single-use — tear down before re-running. | **Proves:** HF-4's wipeless rolling upgrade, the rule-set generation switch at H and the first on-chain name. (0) OLD knows HF2_ACTIVE/HF3_ACTIVE but not RULESET_GEN2, NEW knows RULESET_GEN2 (gate above). (1) the OLD chain commits, 7/7; nodes 3 (pump), 1 and 2 claim their leaves on OLD. (2) BEFORE the roll, the live testnet's state (`DEPLOY_RUNBOOK.md` §2.2: param 7 effective 1500, param 8 effective 2926): `chain-config propose --param HF2_ACTIVE` (OLD CLI; param 9's rule (b)) and then `--param HF3_ACTIVE` (OLD CLI, the HF-3 scenario's shape) each land identically on 7/7, committed below their effective heights H2 / H3, and every node passes each height — the HF-4 crossing runs with HF-3's block bounds in force. (3) 7 nodes rolled OLD → NEW one at a time (same data dir / identity / ports), each back in its role with a completed handshake on the same chain file, real spends carried by the mixed fleet (the CLI of each spend is the one the TARGET node runs — a NEW CLI asks `dnac_ruleset_info`, which an OLD node does not know), 7/7 after every step; then all 7 logs name the SAME `generation-2 vote D2 0x… built from git commit …` line (design §1.5). (4) before the vote: `ruleset-info` on 7/7 = generation 1, H = 0, one tuple; `name register` (NEW CLI) REFUSED ("still runs rule-set generation 1 … no vote committed yet"); `v2_names` empty on 7/7. (5) `chain-config propose --param RULESET_GEN2 --value <D2 decimal>` (D2 read from `ruleset-info`, equal to the NEW CLI's) at H = vote tip + 1 + grace + 20, moved up until H−1 is not an epoch boundary (rule (c)) — printed; the row is byte-identical on 7/7, committed < H; a SECOND param-9 proposal with its own valid effective, from node 2's seat (node 1's first vote left a per-proposer cooldown record at every seat, which the responder answers "rate-limited" before the rules), is refused by all 6 other seats with "stateful rules rejected" (rule (a); round 1 ends 1/7, "Quorum not reached") and param 9 keeps ONE row on 7/7 three heights later. (6) between the vote and H (tip + 1 < H checked before and after): 7/7 `ruleset-info` = generation 1 with H named; `name register` still REFUSED. (7) the fleet crosses H (pumped to H−7, then idle production): 7/7 identical global_root + block_id AT H−1, AT H and AT H+1; the `v2_root_history` rows at global_height H−1 name SYSTEM v7 / CORE v5 with the hashes `ruleset-info` prints, identical (version, hash, state_root) on 7/7, and the last rows below H−1 still name generation 1; 7/7 `ruleset-info` = generation 2 carried by the NEW CLI; every node logged `rule-set generation 1 -> 2 at the end of height H−1`. (8) after H `name register punk` from node 1 applies: on every node `name lookup punk` = node 1's fingerprint at the same registered_height R, `name of` = punk, the sqlite `v2_names` row identical, the CORE `state_root` in `v2_root_history` at R identical; `name register punk` from node 2 REFUSED ("already registered") and `punk2` from node 1 REFUSED ("already holds the name punk"); two heights later still ONE row on 7/7, node 2 holds no name. (9) node 4 kill -9'd after H, restarted on NEW on its own chain file, catches up, 7/7 at a later floor. (10) node 6 wiped as `test_v2_join.sh` does and restarted on NEW with `--v2-genesis-pin`: adopts the fleet's chain file, replays genesis → tip through the switch (its truncated log carries the switch line again), its H−1 rows, `v2_names` row, `ruleset-info` and blocks AT H−1/H/H+1 equal the fleet's; 7/7 at the end. **How it can lie:** **every `name register` refusal here is the CLI's OWN pre-check** (`cmd_name_register`: generation 1, its `dnac_name_lookup`, its `dnac_name_of`) — the CLI has no flag to skip them, so the chain-side first-wins / one-per-ID refusal (exec NAME/OWNER reads + PRE_ABSENT CREATE), the mempool's synthetic OWNER conflict key and the node's generation-1 refusal of an op-8 leg are NOT exercised (unit tests are their proof); the scenario adds only the chain state after each refusal. **A refused param-9 leg COMMITTED BY THE OLD BINARY is NOT replayed** (design §1.2 "Replay of old blocks", §3) — an honest OLD CLI cannot name param 9, so no such block exists on this chain; the stand-in is the unit test `test_hf4_switch` case E, itself a proxy (a param-14 leg refused by the range gate, same gas as the HF-4 refusals, on one binary — no real OLD-built block is replayed anywhere); step 10's replay covers only what this chain holds (idle blocks, 1-in/1-out SPENDs, claims, the param-7/9 votes, the switch, one NAME_REGISTER). Rule (a) is proven at the approval responder only (the second proposal never reaches CheckTx or the exec), and its text "stateful rules rejected" is shared with rules (b)/(c), which hold here by construction; rules (b) and (c) are not exercised as refusals (H is only CHOSEN to satisfy (c)). HF-2 and HF-3 are activated by the OLD CLI on the OLD fleet — if OLD is not the live binary, step 2 proves that build's activation; HF-3's capacity lift is not exercised (one spend in flight), only that HF-4 switches with it on. H−1/H/H+1 are crossed on idle production because the NEW CLI caps an envelope's expiry at H−1 before H (`cli_env_expiry`, design §1.6) — a spend pumped close to H would expire and read as "dropped" (false RED); `tx_count` there is REPORTED, the expiry cap is not asserted. The registry is read through `ruleset-info` and the H−1 `v2_root_history` rows (outside the app hash, design §1.3 — compared explicitly); the `domain_registry` blobs are not decoded. "Same D2 + git commit on 7/7" reads log lines — one build reported, not identical bytes. The name price is not asserted (no balance / reward-pool arithmetic); price votes (params 10-13) are not exercised. The step-6 checks need tip + 1 < H while they run — a fleet that got there first FAILS, never passes. The version gate trusts `NODUS_VERSION_STRING` + the CLI name table. E = 15 / grace 15 / BPY 20 — the LOGIC of the switch, nothing about production 720 / 720 / 17 280. rc 99 = coverage that did not happen. |
| `bench_tps_v2.sh` (in `stagef/`, not `tests/`) | Default build (`nodus-server` + `nodus-cli` from the same tree). `STAGEF_V2_PUMP_IDENTITIES=<K>` and `STAGEF_V2_PUMP_LEAVES=<N>` (per identity) exported BEFORE `stagef_up_v2.sh` — suggested for trial B: **K = 7, N = 150** (see "The TPS bench"); knobs `STAGEF_BENCH_WORKERS` (M, default 7 = one per node, max 7 — a node EVICTS an older session of the same identity, `SESSION_EVICT`, so two workers on one node kill each other's handshake; measured with M=8) and `STAGEF_BENCH_DURATION_S` (D, default 600). Optional: `ss` (iproute2) with `-i` byte counters for the bandwidth section (SKIPPED with a message otherwise; the bench still runs). **Run standalone** against its own fresh bring-up — it claims and churns the whole PUMP batch. rc 99 on a non-Comet cluster. | A **measurement, not a scenario**: sustained CORE SPEND TPS at today's unit budget, per-node TCP bandwidth during the load, (the per-channel NETSTATS section is deleted in P2P-PORT F6 — no such counters on the new stack). See "The TPS bench" below. |
| `bench_tps_live.sh` (in `stagef/`, not `tests/`) | **Targets the LIVE 7-node devnet, not a localhost cluster.** Default build of this tree (the unit budget is read from its header; the live nodes and every client host's `nodus-cli` should be built from the same source). `ssh -o BatchMode=yes root@<node>` to all 7 nodes (each with `sqlite3`, `ss`, `journalctl`, `systemctl`, unit `nodus`, one `witness_*.db`); ssh to every remote client host in `BENCH_HOSTS`; the claimed test identities in `/home/nocdem/testkeys` (2026-09-25 devnet baseline genesis). Knobs `BENCH_HOSTS`, `BENCH_K`, `BENCH_COINS` (N, 150), `BENCH_WORKERS` (M, default K), `BENCH_DURATION_S` (D, 600), `BENCH_OUT`, `BENCH_CLIENT_IPS` — see "The live TPS bench". **Run by the operator / ORCHESTRATOR only**: it writes to the live chain. | A **measurement, not a scenario**: the same TPS / cap / CPU / bandwidth report as `bench_tps_v2.sh`, over a real network, with the load from several client machines. See "The live TPS bench" below. |

#### The TPS bench (`bench_tps_v2.sh`)

**What it measures.** M parallel `nodus-cli v2-envelope spend --amount
all --count all --shard R/W` sessions of the K pump identities (worker I
spends identity `I mod K + 1`; see "Why `--shard`") keep the
mempool fed for D seconds; the script reports K and the in-flight bound,
committed envelopes, the
window, TPS, blocks, mean/max/p50 envelopes per block, mean/max
harness-observed block interval, per-node `nodus-server` CPU%, per-worker
submitted/refused/dropped/applied counts, and the theoretical per-block
cap `floor(NODUS_V2_GLOBAL_UNIT_BUDGET / declared units)` next to the
measured max — the budget is READ at run time from this tree's
`nodus_witness_v2_apply.h` (the `#define` line, a plain literal), the
declared units from the CLI's own `units=` print; it ends with
`stagef_cmt_diff_at_floor`. Output: stdout plus
`$BASE_DIR/bench/summary.txt` and `$BASE_DIR/bench/blocks.csv` (height,
first-seen second, `tx_count`, in-window flag), and one log + stats file
per worker.

**Bandwidth (operator requirement, trial B).** During the load window the
bench samples every `nodus-server` pid's TCP sockets with `ss -tinpH`
about once a second (appended raw to `$BASE_DIR/bench/bw_samples.raw`:
phase, time, pid, node, local port, peer port, bytes sent, bytes
received). Sent is `bytes_sent` (`bytes_acked` where `bytes_sent` is not
printed), received is `bytes_received`. Per socket — keyed by (pid, local
port, peer port) — the LAST value seen is its MAX (the counters only
grow), so a socket that closes mid-run still counts what it carried up to
its last sample; sockets already open at load start have their start
value subtracted as a baseline; a counter that goes DOWN is read as a new
socket re-using the key. Per node the summary prints bytes sent /
received in the window, bytes/s, and bytes per committed envelope, split
by class: INCOMING connections by the node's own listening port
(`in_client` 14xx1, `in_internode` 14xx2, `in_channel` 14xx3,
`in_witness` 14xx4 — the port map above), OUTGOING ones by the peer's
port class (`out_client` … `out_witness`, `out_other` outside the
cluster's range); then the cluster total. One CSV per node:
`$BASE_DIR/bench/bandwidth_node<N>.csv` (class, sockets, bytes sent /
received, B/s each, bytes per envelope each; a `total` row). Missing `ss`,
or an `ss` without byte counters, SKIPS this section with a message and
nothing else.

**Inter-node counters (NETSTATS) — DELETED in P2P-PORT F6.** Both
benches used to read per-direction / channel / message-kind witness-port
counters that the old transport glue logged every 60 s
(`nodus_witness_cmt_net.c`, period from `nodus_witness_cmt_net.h`). That
glue is deleted with the 4004 p2p port and the new stack emits no such
counters, so the section, its `netstats*` outputs and the header read are
gone (the live bench would otherwise have refused to start: it `die`d
when the header could not be read). `in_witness` / `out_witness` in the
bandwidth section still count every 4004 byte — consensus, mempool, PEX,
the 0x70/0x71 channels, the secret-connection handshake and the AES-GCM
framing — with no split by channel or kind.

**Why `--shard`.** One CLI call cannot keep blocks full: a second call
made before the first batch commits lists the same unspent coins and
would double-spend them. `--shard I/M` makes the shard a property of the
COIN — first 8 nullifier bytes (big-endian) mod M — and re-draws every
output seed until the new coin's id lands in the same shard, so M
sessions never share a coin. A rank in a listing would not work: the
listing is capped at 100 rows with no `ORDER BY`, is taken at different
moments from different nodes, and every committed spend replaces a coin
under a fresh nullifier. Worker I submits to, lists on and confirms on
node `I mod 7 + 1` only. **With K pump identities** the shard is taken
only AMONG THE WORKERS OF ONE IDENTITY: worker I uses identity
`I mod K + 1` and shard `R/W` with R = `I div K` and W = the number of
workers on that identity; workers on different identities can never list
the same coin (different owners), so they need no sharding at all. With
K = M every worker owns one identity and runs `--shard 0/1` (the CLI's
no-sharding case); with K = 1 it is exactly the old `--shard I/M`.
Every identity's batch is claimed with ONE `v2-claim` call per identity,
and the load starts only after every identity's coins are all
spendable. The one-worker-per-node rule (M ≤ 7) stays: it was measured
with one identity (`SESSION_EVICT`), and keeping it keeps the node-side
load shape comparable between runs.

**Suggested trial-B settings: M = 7, K = 7, `STAGEF_V2_PUMP_LEAVES=150`,**
all exported before `stagef_up_v2.sh` (K and the leaves are in the genesis
document). Why: the listing returns at most 100 coins PER identity, so
the in-flight bound is Σ min(100, leaves) over the identities with a
worker = 7 × 100 = 700, ≥ 2.7 × the 255 cap. 150 rather than 100 leaves
per identity keeps each identity's listing FULL while spent coins are
being replaced (the 50 extra rotate into view), and 1 050 pump leaves
plus the 9 others is far under the builder's 65 536-leaf ceiling. The
summary prints K and the bound, and adds a "STRUCTURAL" line under the
verdict whenever the bound is below the cap (then no block can fill,
whatever the chain does). A bound above the cap is necessary, not
sufficient: per-round session setup and the ~1 s confirmation poll can
still leave blocks short of the cap, and the verdict then still says
CLIENTS.
⚠ Pre-existing, not changed here: the ORIGINAL pump band
(`1001 .. 1000 + STAGEF_V2_PUMP_LEAVES`) reaches the candidate band
(2001..) at ≥ 1 001 leaves when `STAGEF_V2_CANDIDATES` > 0 and the probe
leaf (3000) at ≥ 2 000 leaves — the builder then refuses the duplicate
`source_id`. Keep `STAGEF_V2_PUMP_LEAVES` < 1 000.

**What it leaves behind.** Every pump identity's batch claimed; every spent coin
replaced by one coin `STAGEF_PUMP_FEE_RAW` smaller; the chain many blocks
further on; `$BASE_DIR/bench/` (including the bandwidth CSVs and raw
samples when `ss` qualified). Nothing killed or restarted.

**Block capacity trial B (operator 2026-09-24,
`docs/plans/decisions/2026-09-24-block-capacity-trial-b.md`) — ARITHMETIC,
NOT MEASURED YET.** `NODUS_V2_GLOBAL_UNIT_BUDGET` 1 000 000 → 2 097 152
(= the 2 MiB envelope byte bound; all weights 1, so a unit is about a
byte), and `nodus-cli v2-envelope spend` declares the EXACT effects of
each SPEND leg (inputs + outputs + 1 effects, 116 + 148·in + 432·out
result bytes) instead of a flat 40 / 16 384. A 1-in/1-out spend then
declares 8 221 units → cap floor(2 097 152 / 8 221) = **255** per block
(the byte bound alone would allow floor(2 097 152 / 7 591-byte envelope)
= 276, so units still bind first). **With ONE pump identity the bench
cannot fill such a block:** the 100-row coin listing bounds all workers
together to about 100 coins in flight, below 255 — a client-bound FLOOR
(the summary says STRUCTURAL). Bring the cluster up with the suggested
K = 7 / 150 leaves above (bound 700). Measuring this trial needs a new bring-up
on a binary carrying the new budget (a consensus value: wipe + fresh
chain).

**First measurement (2026-09-24, nodus 0.19.69, production constants
E = 720, 7 nodes + clients on ONE 4-CPU machine, M = 7, D = 600 s, 400
pump leaves):** 7.55 TPS (4 469 envelopes / 592 s); 110 loaded blocks,
every one at exactly 41 envelopes = the unit cap (1 000 000 / 23 946);
block interval mean 5.43 s / max 7 s (harness-observed, 1 s
granularity); nodus-server CPU ≈ 32% of one core per node; 4 569
submitted = accepted = applied, 0 refused, 0 dropped; 7/7 agreement
after. Verdict: the UNIT BUDGET binds, not CPU — the rate is
41 / (timeout_commit 4 s + consensus rounds). Localhost numbers: a real
network adds latency to every round.

**How it can lie** (the script header has the full list): 1 s timing
granularity (first sighting on node 1, not header time); seven nodes and
all clients share one machine; localhost has no network latency;
**client pacing** — if the measured max per block is below the cap, no
block was full, the clients were the bottleneck and the TPS is a floor,
which the summary states explicitly; the 100-row listing cap bounds
in-flight coins to ~100 PER PUMP IDENTITY whatever the leaf count (with
K = 1 that alone keeps every block below the trial-B cap of 255; with
K = 7 the bound is 700); the
result holds at today's `NODUS_V2_GLOBAL_UNIT_BUDGET` and metering weights
only. **Bandwidth** is localhost TCP payload (it includes nodus's own
framing, CBOR and any session crypto overhead, excludes IP/TCP headers;
no real link, no loss, no limit); a socket opened and closed between two
~1 s samples is missed, bytes after a socket's last sample are missed,
and the report says how many sockets were seen (open at start, opened
during, gone before the end, key re-uses); node-to-node bytes appear once
as sent and once as received across the cluster; client (`nodus-cli`)
sessions are measured on the server side only; bytes per envelope divide
the wall-clock window's bytes by the window blocks' envelopes (edges
differ) and include idle consensus traffic, so they are an upper bound,
not a marginal cost. **No per-channel view (P2P-PORT F6):** the NETSTATS
counters are gone with the old transport; `in/out_witness` is every 4004
byte (consensus, mempool, PEX, 0x70/0x71, handshake, AES-GCM framing)
with no split. Every wait is progress-bounded (the inline `stagef_cmt_wait_row`
rules: a stall aborts the bench, 20 heights without inclusion counts the
spend as DROPPED); refused and dropped spends are counted, never retried
silently, and a worker fault aborts the whole bench with no partial
result.

#### The live TPS bench (`bench_tps_live.sh`)

The live-devnet counterpart of `bench_tps_v2.sh`: the same worker loop,
queries, output shapes and honesty rules, but the chain is the live
7-node devnet reached over the network and the `nodus-cli` sessions run
on several client machines. It is a MEASUREMENT, not a scenario — never
add it to `genesis_protocol_v2.sh`. The script header has the full text
of all four headings below.

**What it measures.** M workers keep the live mempool fed for D seconds
with `nodus-cli v2-envelope spend --amount all --count all --shard R/W`.
Worker I spends pump identity `I mod K + 1` (the first K of the test
identities in `BENCH_IDENTITIES`, default the 9 `test_*` key dirs of the
2026-09-25 baseline genesis), with shard `I div K` of that identity's W
workers, runs its CLI on client host `I mod H + 1`, and submits to,
lists on and confirms on ONE node chosen so that no two workers of one
identity share a node (a node evicts an older session of the same
identity whatever the client IP: `nodus_auth.c:99-117` compares the
fingerprint only — `SESSION_EVICT`). The worker LOOP runs on the
controller; only the CLI call runs on the client host; the confirmation
(the created `utxo_set` row per accepted intent id) is a read-only
`sqlite3 -readonly` query to the worker's node over ssh. Before the
load, a resumable PREPARATION gives every pump identity N spendable
coins (`BENCH_COINS`, default 150) by halving splits with the existing
CLI: per round, amount = (smallest coin − fee) / 2 and count =
min(coins, N − coins, 100), `--to <own fp> --amount <amount> --count
<count>`; the CLI picks each spend's inputs largest-first
(`nodus-cli.c` `t6_spend_pick`), every coin covers amount + fee alone,
and each spend returns two coins (amount + native change) — the coin
count doubles per round, 8 rounds for N = 150, all K identities in
parallel. A fixed `--amount` would not double: after one split the
small output cannot cover amount + fee and the whole planned batch is
refused before anything is sent. Identities already holding ≥ N coins
are skipped. During the load one node's `v2_blocks` (`BENCH_REF_NODE`)
is streamed over one ssh session (a read-only loop on the node polling
about once a second, each new height stamped with the controller's
clock on arrival), and every node streams its `nodus-server`
`/proc/<pid>/stat` and `ss -tinpH` sockets about once a second. Output in
`$BENCH_OUT` (default `/tmp/bench_tps_live.<UTC>`): `summary.txt`,
`blocks.csv`, `worker_<I>.log` / `.stats`, `prep_<identity>.log`,
`bandwidth_node<N>.csv`, `nodes.txt`, `agreement.txt`,
`cluster_status.txt` and the raw streams. The summary prints the
parameters (hosts, K, N, M, D), the measured controller→node ssh round
trip and node clock offsets, committed envelopes, window, TPS, blocks,
mean / max / p50 envelopes per block, mean / max observed interval, the
unit cap next to the measured max (with the CLIENTS / STRUCTURAL verdict
of the local bench), per-node CPU%, per-node bandwidth by live port
class, per-worker counts, and the closing agreement
check over all nodes (7 on the live devnet): every node's tip, the
minimum as a floor, then full `global_root` and `block_id` at that
height on every node (`nodus-cli cluster-status` is
printed after it, informational only — it shows current heights, read
at different moments).

**What it requires.** No compile flags beyond a default build of this
tree (`NODUS_V2_GLOBAL_UNIT_BUDGET` from `nodus_witness_v2_apply.h`,
read at run time); the live nodes and the client hosts' CLIs should run binaries
of the same source. Controller: bash ≥ 4.4 (checked), OpenSSH
(ControlMaster), awk, sort, pgrep / pkill, a `nodus-cli` (`BENCH_CTRL_CLI`) for the preparation
and `cluster-status`, the test key dirs (`BENCH_KEYS_SRC`, default
`/home/nocdem/testkeys`). Nodes (`BENCH_NODES`, default the 7 live IPs;
`ssh -o BatchMode=yes root@<ip>`): `sqlite3`, `ss` with `-i` byte
counters, `systemctl`, `getconf`, `nproc`, `awk`, the unit
`nodus` running `nodus-server`, exactly one
`/var/lib/nodus/data/witness_*.db` — all checked at start, refused with
the reason. Client hosts (`BENCH_HOSTS`, space-separated
`<host>:<nodus-cli path>:<key dir>`; `local` = this machine with key dir
`-`; default `local:<tree>/nodus/build/nodus-cli:-`): BatchMode ssh from
the controller, an executable `nodus-cli`, a writable key dir path. The
chain: every pump identity's allocation CLAIMED (the bench never
claims). Optional `BENCH_CLIENT_IPS` (the client hosts' public IPs, to
separate the bench's client-port sockets as `in_client_bench`),
`BENCH_FEE_RAW` (1 000 000, the CLI default). Limits: M ≤ 7 × K (one
session per identity per node), W ≤ 100 (`--shard`).

**What it leaves behind.** On the LIVE chain: the pump identities' coins
split into N each and then churned (each spent coin replaced by one coin
one fee smaller); every fee in the reward pool
(`docs/plans/decisions/2026-09-22-nodus-tokenomics-v3-operator.md` §1);
the chain many blocks further on. Nothing on any node is stopped,
restarted or written — every node command is read-only (`sqlite3
-readonly`, `ss`, `/proc`, `systemctl show`); a WAL
reader does update the read marks in the database's `-shm` index, as
every SQLite reader does. On each remote client host: a copy of each
test identity dir its workers use (all seven `nodus.*` files — a partial
copy would let `nodus_identity_load` generate and write new KEM files),
mode 0700 / 0600, NOT removed. On this machine: `$BENCH_OUT`, and an ssh
control-socket dir `/tmp/btl.XXXXXX` removed at exit. On EVERY exit
path (normal end, a fault, Ctrl-C / TERM — exit 130) the cleanup kills
what the script started, and always runs to its end (its first act
re-routes INT / TERM / HUP to a log line, so a second Ctrl-C cannot cut
it short): each preparation job and each worker runs in
its OWN process group, and the cleanup sends TERM, then KILL after 1 s,
to the whole group — reaching the `nodus-cli` / ssh grandchild that a
plain kill of the job's pid would orphan. `nodus-cli` does not stop on
SIGINT during a spend (`nodus-cli.c:116-119` only clears a flag
`cmd_v2_spend` never reads), so a Ctrl-C reaches only the script, whose
trap kills the groups. Afterwards it runs `pgrep -af 'v2-envelope spend
--keys <dir>/'` on the controller for every key dir it used and prints a
`[warn]` for every survivor; if workers had started it also runs `pkill
-f` with the same pattern on each remote client host and prints the
hosts where that failed. The first failing preparation job stops the
others the same way. A spend already submitted before the kill may still
commit — a kill stops further submissions, it cannot recall one. The
remote key copies are `chmod`ed 0700 / 0600 explicitly and the modes
read back are printed. The remote read-only loops on the nodes end at
their next write after their ssh session is gone, and stop by themselves
after D + 1800 iterations.

**How it can lie.** Real network latency and bandwidth between the
nodes now, but the client hosts are the operator's machines, not the
network's wallets — their links and CPUs shape the offered load. Block
times are the controller's first sighting of one node's heights, ~1 s
polling plus one-way ssh latency (the summary prints the measured round
trip), not header time; one polling node. **Client pacing:** max per
block below the unit cap means the clients were the bottleneck and the
TPS is a floor (each round also pays a session over a real link and
ssh-round-trip confirmation polls). The 100-row listing cap bounds
in-flight coins to ≈ Σ min(100, N) over the identities with a worker
(K = 9, N = 150: 900); the preparation reads coin counts from the DB
directly and is not bounded by it. The cap is arithmetic at today's
budget and weights. **The live DHT shares the nodes:** CPU% is the whole
`nodus-server`; bandwidth `in/out_witness` (4004) is the witness port —
on the p2p-port build consensus plus mempool, PEX, 0x70/0x71 and the
session crypto,
`in/out_internode` (4002) is DHT replication (not consensus),
`in_client` (4001) mixes real Connect users with the bench's own
sessions — separated only when `BENCH_CLIENT_IPS` is set, otherwise the
summary says it is not; UDP 4000 is never seen. Bandwidth windows are
each node's own sampled span on its own clock. (The journald NETSTATS
section is deleted — P2P-PORT F6; the bench no longer needs
`journalctl` on the nodes.) Stall and drop rules are
the local bench's inline `stagef_cmt_wait_row` rules, with the stall
measured in wall-clock seconds (180 s with the tip not moving) because a
poll costs an ssh round trip. `tx_count` counts ANY submitter's
envelopes on the live chain — the workers' own applied total is printed
next to it. The preparation's blocks precede the window and are not
counted. **An unreadable node is not a height:** a failed tip / row read
is retried once a second, and a node with no valid answer for 180 s is
declared UNREACHABLE — the worker or preparation fails with that status;
it is never counted as a stall and never as DROPPED spends (the time a
node was unreadable is kept off the stall clock, which counts readable
time without progress only). **ssh
session limit:** each node and client host is reached through ONE ssh
ControlMaster connection, and sshd allows `MaxSessions` sessions per
connection (default 10; the targets' real setting is not read). The
bench refuses a placement whose concurrent sessions on one target (node:
its workers + its sampler, + the block poller on the reference node, or
its preparation jobs; client host: its workers) exceed
`BENCH_MAX_SSH_SESSIONS` − 1 (default 9 — one kept free for the
controller's own commands); a target configured lower refuses a session,
ssh exits 255 and the worker fails loudly. Exit codes: 0 · 1 setup or
worker fault · 2 divergence (two readable nodes differ at the floor
height; always wins) · 3 incomplete: the readable nodes agree at the
floor of THEIR tips, but at least one node (tip or row) could not be
checked, or fewer than 2 nodes were readable — a divergence on an
unchecked node is not excluded; the unchecked nodes are listed in
`agreement.txt` · 129 hang-up (HUP, trapped so the cleanup still runs)
· 130 interrupted (INT / TERM).

#### Order matters on the Comet lane too (R3 W3, C2d)

The nineteen Comet scenarios are order-INDEPENDENT of each other's LEAVES
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
  NEW PID. `test_p2p_seam_faults.sh` scans each node's nodus.log; nodes 5
  and 6 have theirs TRUNCATED by their restart scenario, so for them the
  scan covers only the lifetime since that restart (node 4's log is
  appended). Its own header discloses this; it is a boundary on what
  "across the sweep" can mean for a node relaunched mid-sweep.
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
- `test_cmt_token_create.sh` funds its creator from **node 1's** own
  leaf (claimed only if node 1 is not already funded) — the only other
  scenario touching that leaf is `test_cmt_self_delegate.sh`, which uses
  the SAME "claim only if not already funded" rule, so the two are
  order-independent of each other and of every other scenario's leaves;
  token_create runs after the two flood scenarios only so their
  batches are not interleaved with it. It leaves a `tokens` row and token
  coins on nodes 1 and 2 — a later scenario counting node 1's or node 2's
  `utxo_set` rows sees them (none in the list does today).
- `test_cmt_self_delegate.sh` (W-B) bonds 1M NODUS of node 1's coins as a
  permanent self-delegation, so node 1's voting power and reward share
  are larger from the snapshot two epochs after it on. Placed after
  `test_cmt_token_create.sh` (which ordinarily funded node 1 already) and
  BEFORE `test_cmt_rule_n_retire.sh`; `test_v2_rewards.sh` after it is
  unaffected (it checks pool → accrual conservation and membership,
  never per-node amounts).
- `test_p2p_seam_faults.sh` must run LAST, unconditionally — its
  subject is every node's log across the whole sweep. Running it earlier
  reads a partial history.
- **History, closed (R3 W3 package C2e, register R3-A-5; subject deleted
  in P2P-PORT F6):** the fourth W3 sweep measured the old transport
  glue's receive arena as a 64 MiB runway that was NEVER released —
  ≈174 KB per empty block, both latches on node 1 by height ~347, a node
  dead after ≈1 hour. C2e made it a per-message scratch; the glue itself
  (`nodus_witness_cmt_net.c`) is now deleted with the 4004 p2p port, and
  with it the latches `test_cmt_arena_runway.sh` scanned for — that
  scenario is DELETED (it had become vacuous) and replaced by
  `test_p2p_seam_faults.sh`.

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
- Each `nodus-server` logs to `$BASE_DIR/node$N/nodus.log`; on a split
  node (`STAGEF_MODE` splitw / mixedw) the witness lines are in
  `$BASE_DIR/node$N/witness.log` instead (`stagef_node_log N`). Check
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
4. **Block sync is exercised over a MODEST gap only.** Since the
   blocksync port (decision `2026-09-29-blocksync-before-testnet.md`) a
   restarted or joining node that is not the only validator starts with
   `wait_sync` = `blockSync` = true (node.go:375) and catches up through
   the block sync reactor on channel 0x40 before consensus starts
   (D-23 rev 7 item 18's "always false" deviation is removed).
   `test_cmt_blocksync.sh` (in the sweep) proves one node catching up
   over `STAGEF_BLOCKSYNC_DISTANCE` blocks (default 20, capped at
   epoch/2 − 2 — 5 blocks in the short-epoch sweep);
   `test_v2_join.sh`, `test_v2_restart_convergence.sh` and
   `test_v2_partial_wipe.sh` go through the same path over SHORT gaps.
   A node that fell behind by thousands of blocks (a long production
   outage) is still untested, on this lane, by this harness — the same
   code path, but its time and memory profile at that length is not
   measured.


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
- P2P-PORT F6: every node is 127.0.0.1, so the 4004 mesh runs with the
  harness-only `allow_duplicate_ip: true` / `addr_book_strict: false`.
  The production admission filter (one connection per IP,
  `ConnDuplicateIPFilter`) and the strict address book are NEVER
  exercised here — they are covered by the unit tests
  (`test_p2p_switch`, `test_p2p_pex`) only.
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
  first, `test_p2p_seam_faults.sh` last, `test_cmt_mempool_flood.sh`
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
   `ABCI replay blocks:`, every `CMT_FAULT`) and reject reasons — on a
   split node (`STAGEF_MODE` splitw / mixedw) those lines are in
   `$BASE_DIR/node$N/witness.log`, and `nodus.log` holds the core's side.
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
