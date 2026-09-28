# Nodus Deploy Runbook

Operational procedures for deploying, verifying and rolling back Nodus nodes.

> **2026-07-28 — this file was rewritten after an audit.** The previous Appendix B
> described a `.deb` / APT / multi-operator process that **has never existed in this
> repository**: there is no `debian/` directory, nothing produces a `.deb`, the path
> `/var/cache/nodus/` appeared nowhere else in the tree, nothing ever created
> `/var/lib/nodus/snapshots/`, the cross-referenced "multi-tx block refactor design
> doc §6.5 (15-trigger list)" does not exist, and this is a single-operator project —
> there is no Signal bridge, no coordinator, no phone tree. `nodus-server --version`
> was also instructed but that flag does not exist. All of it was invented prose,
> committed 2026-04-14 (`b5a07213`), never executed, and therefore never caught.
> What survived the audit is kept below and marked; everything else is rewritten
> against what the code and the deploy method actually do. **Where a value cannot be
> determined from this repository it is written as a step to VERIFY on the node, not
> as an assumed value.**

---

## 0. How Nodus is actually deployed

Deployment is **`git pull` + `make` on each node**. There is no package, no artifact
registry, no installer. Consequently **rollback is also a git operation** — check out
the previous commit and rebuild. Record the commit you are rolling back *to* before
you start; after the fact it is guesswork.

Deploy is **ORCHESTRATOR/operator-only and always requires explicit permission.**
One node at a time for a rolling deploy; all nodes at once for a stop-all.

### Choosing rolling vs stop-all

| Change | Deploy mode |
|---|---|
| Anything that changes **which blocks are valid** (verify/admission rules, fee gates, consensus checks) | **STOP-ALL** |
| `state_root` format / wire format / DB schema | **STOP-ALL + chain wipe** |
| Any consensus change (the cometbft port's `cmt_*`, the application's ABCI rows, the genesis document) | **STOP-ALL + fresh chain** — a version-3 chain has no migration; §2.1 explains why there is no `pbft_state` step any more |
| A **height-activated** rule that is inert until a chain-config vote turns it on (HF-1 gas price, nodus 0.19.80) | **Rolling** binary upgrade (the rule is byte-identical to the old binary while no row exists) — then the vote, ONLY after 7/7 run the new binary. §2.2 |
| Logging, metrics, non-consensus tooling | Rolling, one node at a time |

**Why stop-all for validity changes:** during a rolling window the cluster runs mixed
versions. If the new binary accepts a block the old one rejects (or vice versa), the
disagreement *is* a chain split. This is not hypothetical — it is the failure mode the
v0.18.17 fee-gate fix was written to remove.

⚠ **The code will NOT stop you from getting this wrong.** The old mixed-version
fail-fast lived in `nodus_witness_bootstrap.c`, which was deleted with the legacy lane
(W4-D, `e72d8cb5`, v0.19.62). Since 0.20.0 the `PEER SCHEMA MISMATCH` log is gone too
(the IDENT message that carried the version was deleted with the old 4004 transport,
P2P-PORT F5). What the 4004 p2p port checks is the p2p protocol version and the chain id
in NodeInfo (`CompatibleWith`) — so a 0.19.x node cannot join a 0.20.x mesh — but two
0.20.x builds that differ in a consensus rule connect without complaint. Restarting
nodes on mixed versions is therefore **silently permitted**. The discipline is yours,
not the binary's.

---

## 1. Archive on-disk witness chain state

Required before any **chain-wipe** deploy (state_root format change, witness chain
format change). Not required for an ordinary code deploy.

**First: find the real data directory. Do not assume it.**

`data_path` defaults to `/var/lib/nodus` (`nodus/tools/nodus-server.c:162`) but is
overridden by `data_path` in the node's config (`nodus-server.c:113-114`) or by `-d`
(`:178`). (Until 0.19.x a log line in the since-deleted `nodus_witness_peer.c`
pointed at `/var/lib/nodus/data/`; the source no longer names that path.) So:

```bash
grep -E '"?data_path"?' /etc/nodus.conf || echo "not set — default /var/lib/nodus"
DATA_DIR=<the path you just confirmed>
ls -la "$DATA_DIR"/witness_*        # must list the files you intend to archive
```

**Do not proceed until that `ls` shows the witness files.** The previous version of
this runbook hardcoded `/var/lib/nodus` and then "verified" the archive with a command
that prints `archive ok` when it finds nothing — so archiving the *wrong* directory
reported success. That false-pass is the reason for the check above.

**Archive (run on each node):**

```bash
TS=$(date +%s)
mkdir -p "$DATA_DIR/archive/$TS"
mv "$DATA_DIR"/witness_* "$DATA_DIR/archive/$TS/"
```

**Critical — the glob is `witness_*`, NOT `witness_*.db`.** *(This section survived the
audit unchanged; it is correct.)* Witness state lives in three sibling files per chain:

- `witness_<chain_id>.db`     — main SQLite database
- `witness_<chain_id>.db-wal` — write-ahead log
- `witness_<chain_id>.db-shm` — shared memory index

Archiving only `.db` leaves `-wal` and `-shm` behind, which SQLite merges back into a
freshly-created database, producing a corrupted hybrid state.

**Verify — note this checks the archive is populated, not merely that the source is empty:**

```bash
ls "$DATA_DIR"/witness_* 2>/dev/null && echo "SOURCE NOT EMPTY — archive incomplete"
ls -la "$DATA_DIR/archive/$TS/"     # MUST list .db and, if WAL was active, -wal/-shm
```

---

## 1.5 Birth of the Ledger V2 chain — the one-time ceremony (v0.19.37)

**This is a HARD CUTOVER.** There is no migration, no coexistence, no V1→V2
path. Every node stops, its V1 chain files are removed, each node derives the V2
chain from one shared config file, and the fleet starts. **You do this once.**
Everything below assumes §1's `DATA_DIR` check has already been done.

### What actually creates the chain

```
nodus-server --derive-v2-genesis <config-file> -d "$DATA_DIR"
```

It parses the config, derives the chain, prints the chain id (`chain-id` and
`v2-genesis-pin` — the same 32 bytes; a version-3 chain has no genesis
block, the document is its genesis), and **exits**. It never opens a socket and never starts a server. That
is deliberate: the genesis validator set comes only from the config file, and
there is no running process for anything on the network to reach.

### Determinism is the verification, not a formality

The same config file produces a byte-identical chain on every host. So the
config file is the ONLY artifact that travels — **never copy a derived database
between machines.** Each node derives its own, and each prints the chain id. If
two nodes print different chain ids, their configs differ; stop and fix the
config before starting anything. A wrong config does not corrupt a chain, it
produces a DIFFERENT chain that cannot join — a loud refusal, not a silent split.

### Order of operations

1. **Stop every node.** This is a chain wipe; rolling is not an option
   (`feedback_consensus_deploy_stop_all`).
2. **Remove the V1 chain on each node.** The derive command REFUSES to run
   beside a foreign chain database — it will tell you to remove it first, by
   name. This is devnet, so archiving is optional; use §1's archive procedure if
   you want the forensics.
   ```bash
   rm "$DATA_DIR"/witness_*.db*
   rm -f "$DATA_DIR"/priv_validator_state.json
   rm -rf "$DATA_DIR"/cs.wal                  # 0.20.0+: the consensus WAL file group
   rm -f "$DATA_DIR"/p2p_addrbook.pb          # 0.20.0+: the old chain's peer addresses
   ```
   **`cs.wal/` must go with the chain (0.20.0+).** The consensus WAL left the
   chain database for the reference's file group `$DATA_DIR/cs.wal/wal`
   (decision `2026-09-26-cmt-wal-file-group.md`). A new chain started beside
   the old chain's `cs.wal` replays the OLD chain's round messages at start.
   The second line matters from the SECOND version-3 wipe on. The
   version-3 signer records the last height it signed in
   `$DATA_DIR/priv_validator_state.json` (`nodus_witness.c:1625`) and
   refuses to sign any lower height (`shared/dnac/cmt_privval.c:117-118`,
   the reference's height-regression rule). A leftover file from the
   previous chain therefore stops the node voting on the new one, and with
   all seven affected the new chain never produces a block. The legacy
   binary (v0.18.x) never writes the file, so the first cutover is
   unaffected. Only chain files go: `nodus.db`, `channels.db`,
   `identity/` and `archive/` stay — they are the DHT/Connect store and
   the node's identity.
2b. **Check for leftover sentinels.** Two dot-files live beside the chain and
   **survive step 2** — `rm witness_*` does not match a name starting with a
   dot:

   ```bash
   ls -la "$DATA_DIR"/.bootstrap_in_progress "$DATA_DIR"/.recovery_in_progress 2>/dev/null
   ```

   Either one means a node died mid-operation and was never restarted since.
   `--derive-v2-genesis` refuses while either is present and prints the remedy,
   so you cannot walk past this by accident — but knowing why saves the
   guesswork. `.bootstrap_in_progress` is the dangerous one: without that
   refusal, the next start after a successful ceremony would ARCHIVE the chain
   you just derived and come up reporting "no chain DB found — pre-genesis
   state", with no error anywhere. Establish why the node died, then remove the
   file.

3. **Put the SAME config file on every node.** Byte-identical. Verify with a
   checksum, do not eyeball it:
   ```bash
   sha256sum /etc/nodus/genesis.conf     # must match on all 7
   ```
4. **Derive on each node** with the command above. Record each node's printed
   chain id.
5. **Compare the chain ids.** All 7 identical, or stop.
6. **Start the fleet.**

### The config file

Line-oriented text, `#` comments, `key = value`. Every key and fingerprint is
lowercase hex. Deliberately not JSON: the server's JSON support is an optional
build dependency, and a ceremony performed once must not depend on which
libraries a host happened to have.

A complete, commented template with the decision's numbers (1B supply, 200M
reward reserve, 7 × 10M bonds, the ten pool allocations) and a checker live in
`nodus/tools/genesis/` (`testnet_v3.conf.template`, `check_genesis_conf.sh`,
`README.md`) — start from there. The shape:

```
config_version         = 3          # REQUIRED; only 3 is accepted (P4)
genesis_time_ms        = <UTC ms, written ONCE, the same in every copy>
initial_height         = 1
total_supply_raw       = 100000000000000000
epoch_length           = 720
blocks_per_year        = 6307200
decimal_unit           = 100000000
inflation_start_block  = 0          # MUST be 0: the mint is deleted (P2)
reward_pool_initial    = 20000000000000000
payout_interval_epochs = 24

[validator]                         # exactly 7 of these
pubkey                     = <5184 hex chars>
unstake_destination_pubkey = <5184 hex chars>
unstake_destination_fp     = <128 hex chars — SHA3-512 of the payout pubkey>
self_stake                 = 1000000000000000
commission_bps             = 500

[allocation]                        # 1 or more
source_id    = <128 hex chars>
dest_binding = <128 hex chars — SHA3-512 of the claimant's pubkey>
amount       = 5000000000000
```

The parser refuses rather than repairs: a duplicate key, an unknown key, a
missing key, an out-of-range number, uppercase hex, a wrong-length value or an
over-long line each stop the derivation with the line number. It never fills a
default for anything that reaches the chain identity.

`epoch_length`, `blocks_per_year` and `decimal_unit` MUST equal the values the
binary was compiled with, or the derivation refuses — the mismatch would
otherwise produce a node that mints on a schedule its peers do not share.

### Three values you are nailing down permanently

- **`epoch_length`, `blocks_per_year`, `decimal_unit`** — governance cannot
  reach these. Changing them later means a new chain.
- **`inflation_start_block` must be `0`.** Tokenomics-v3 P2 deleted the
  per-block mint and retired its governance parameter (id 3); the builder
  refuses any other value. Rewards come only from `reward_pool_initial`.
- **The validator payout fingerprints.** The builder now verifies that each one
  derives from the payout key beside it, so a copy-paste error is refused rather
  than stranding that validator's 10,000,000 DNAC self-bond at an address no key
  opens. It cannot check that the KEY is the right key.

### The distribution list does not travel on-chain

Only its Merkle root and leaf count are committed. Whoever will claim an
allocation needs the leaf data from you. Publishing it is part of the ceremony,
not something the chain does.

### Re-running the command

Safe and idempotent, but only for the SAME config: it compares the stored
genesis digest against the one your config produces. Same config → "nothing to
derive", exit 0. Different config → refusal, printing both digests. It will
never replace a chain in place.

### After the first successful start

`.witness_db_seen` appears in the data directory — written by the server, not by
the derive command (see `BOOTSTRAP.md`, "Who writes `.witness_db_seen`"). Its
presence is what arms the partial-wipe gate from then on. **It is normal for it
to be absent between the derivation and the first successful start.**

### Joining a node to an existing V2 chain

Not the ceremony — this is for a node added later, or one rebuilt from scratch.
Give it the chain id the ceremony printed (since R3 W3 the pin IS the 32-byte
chain id — a version-3 chain has no genesis block to pin a BlockID to; the
`chain-id` and `v2-genesis-pin` lines the ceremony prints carry the same
64-hex value):

```
nodus-server --v2-genesis-pin <64 hex chars> -d "$DATA_DIR"
```

It pulls the genesis bundle (format v3: the six base tables plus the genesis
document) from peers and adopts it only if the bundle re-derives to the pinned
chain id AND its document's `app_hash` equals the ledger root the re-derivation
actually produced; a 128-hex value is refused outright. `--derive-v2-genesis` and `--v2-genesis-pin` are
mutually exclusive and the binary refuses both together — deriving and joining
are opposite intents.

---

## 2. Stop-all deploy

1. **Record the rollback point before touching anything:**
   ```bash
   git -C /opt/dna rev-parse HEAD      # write this down; it is your rollback target
   ```
2. Stop every node. Do not deploy any node until **all** are stopped:
   ```bash
   sudo systemctl stop nodus
   systemctl is-active nodus           # must print "inactive" on every node
   ```
3. Chain wipe only: archive per §1.
4. On each node, build the new version:
   ```bash
   cd /opt/dna && git pull && cd nodus/build && cmake .. && make -j$(nproc)
   ```
   The build must be clean. A node that fails to build must not be started.
5. Start every node, then verify per §3.

**One SSH session per node.** Do not write a 7-node `for` loop — a partial failure
inside a loop is very hard to reason about afterwards.

## 2.3 The 4004 p2p port (0.19.x → 0.20.0) — STOP-ALL, NO WIPE

0.20.0 replaces the witness port 4004 with a literal port of cometbft's p2p
layer (secret connection, MConnection, switch, PEX — `docs/ARCHITECTURE.md`
"The 4004 p2p port"). An old node cannot talk to a new one on 4004, so this is
§2's stop-all, **without** §1's archive: the chain continues on the same data
directories (decision `2026-09-26-witness-port-session.md`, "Deploy: zincir
SİLİNMEZ"). Proven on localhost by `test_p2p_stopall_nowipe.sh`.

1. **Publish the network file first** and point every node at it — nodus.json
   key `network_file` (or `--network-file <path>`):
   ```json
   { "v2_genesis_pin": "<the chain id, 64 hex>",
     "persistent_peers": ["<p2p id>@<ip>:4004", "..."] }
   ```
   A node's p2p ID is `nodus-cli -i <identity dir> whoami` → `P2P ID:`. A pin
   that differs from the chain the node holds REFUSES the start. A node with a
   chain and zero connected peers logs `this node holds a chain but has … 0
   connected` at ERROR every 60 s — it is not refused, but it cannot vote.
2. **Stop every node inside an idle window.** The consensus WAL moves from the
   chain database (SQLite `cmt_wal`) to `$DATA_DIR/cs.wal/wal`; 0.20.0 copies
   the old tail over ONCE at its first start (decision
   `2026-09-26-cmt-wal-file-group.md` item 6 AMENDED — log line
   `consensus WAL carry-over: N rows …`). Without that copy, a stop landing
   while ≥ 1/3 of the voting power has already signed at the next height halts
   the chain for good (proven: the scenario's negative control). The copy makes
   the stop safe at any moment; stopping right after a commit (an idle chain
   waits 60 s for the next block) keeps the carried tail small.
3. Build and start as §2 steps 4-5; verify per §3, plus on every node:
   `grep 'consensus WAL carry-over' <log>` (one line per node that held rows)
   and `grep 'persistent peer(s)' <log>`.

**0.20.0 and 0.20.1 do not mix.** 0.20.1 adds a request digest (`rq`) to the
0x71 governance-approval response; a 0.20.0 node's response without it is
refused. 0.20.0 was never deployed — deploy 0.20.1 (or later) to every node in
the same stop-all.

**Rolling back 0.20.x → 0.19.x (and forward again).** 0.19.x reads only the
SQLite rows, so a node that signed at the next height under 0.20.0 has that
vote only in `cs.wal`. Therefore:
- Roll back only in an idle window, and on every node confirm, before
  starting 0.19.x, that `priv_validator_state.json`'s `height` is ≤ the chain
  tip (a node that has signed past the tip cannot replay that vote on 0.19.x;
  with ≥ 1/3 of the power in that state the chain halts).
- Before rolling FORWARD to 0.20.0 again, move each node's `cs.wal/` aside
  (`mv "$DATA_DIR"/cs.wal "$DATA_DIR/archive/cs.wal-$(date +%s)"`). The copy
  runs only when `cs.wal/wal` is empty; a `cs.wal` left from the first 0.20.0
  run would hide the rows 0.19.x wrote during the rollback.

---

## 2.2 Height-activated parameter (hard fork) — the HF-1 gas price procedure

Decisions: `docs/plans/decisions/2026-09-25-gas-price.md`,
`docs/plans/decisions/2026-09-26-hard-fork-lagging-node.md`. Mechanism:
`ARCHITECTURE.md` "HF-1". Proven on localhost only, at grace 15/15
(`test_cmt_hf1_gas_upgrade.sh`, both modes PASS) — the LOGIC of the cutover, nothing
about the production grace (720 blocks).

**Why the order matters.** A binary older than the rule does not know the parameter
id. When the vote's envelope lands in block R, the old binary refuses that ITEM (item
code 7) but still COMMITS block R — its chain_config state now differs from every new
node's, so on block R+1 it reports `wrong Block.Header.AppHash` and stops participating
(`CMT_FAULT in cmt_cs_step`). It diverges at the VOTE's block, not at the activation
height. If nodes holding more than 1/3 of the voting power are still old, the whole
chain halts.

1. **Rolling binary upgrade, one node at a time** (§0 rules: one SSH session per node,
   record the rollback commit). No wipe — while no row for the new parameter exists the
   new binary produces the same roots as the old one. After each node: it is back at the
   tip, the chain advanced, and 7/7 agree (§3).
2. **Verify 7/7 are on the new binary BEFORE voting.** On every node:
   `journalctl -u nodus | grep 'Nodus v.* running'` (`nodus_server.c` startup line)
   shows the new version as the LAST such line, and a fresh
   `PEER SCHEMA MISMATCH` line must NOT appear after the last restart (every peer now
   reports the same version). There is no on-chain "how many upgraded" indicator yet
   (planned: `docs/plans/decisions/2026-09-26-governance-before-testnet.md`).
3. **Vote** with the new CLI:
   `nodus-cli chain-config propose --param GAS_PRICE_RAW_PER_UNIT --value <P> --effective <H>`
   (`<P>` ≤ 1 000 000; `<H>` ≥ tip + grace, ERGONOMIC class). The row must appear
   identically on 7/7 (`chain_config_history`: param_id 5, same commit_block and tx_hash).
4. **Before H** nothing changes (the rule is off). **From H** every envelope with a
   non-SYSTEM leg must pay `max(res_max_total_units × P, 0.01)`; underpayers are refused
   at CheckTx and, if carried in a block, refused per item with code 9. Wallets/CLIs must
   read `gas_price` from `dnac_fee_info` (the 0.19.80 CLI does). An old CLI's floor-fee
   transfer still passes while `units × P` stays under the floor.
5. **Turning it off**: vote the same parameter to 0 at a later effective height.
   ⚠ The shipped CLI's approval round 2 re-asks every seat within 5 s and hits the
   per-proposer rate limit, so a vote with ANY non-approving seat fails today — a price
   change needs all seats to approve in round 1 (HF-1 red-team R3-F1; the real fix is the
   on-chain governance package).

**A node that missed the vote (still on the old binary when R committed):**
- Upgrading its binary and restarting does **NOT** recover it: the ABCI handshake at
  app == store == state height re-executes nothing, so the diverged state carries over
  (measured: stuck at R while the fleet advanced).
- Recovery = **wipe + genesis-pin rejoin on the new binary** (§1.5 "Joining a node to
  an existing V2 chain"): stop it; archive/remove its chain DB files, the markers and
  `archive/` (keep the identity directory); start the NEW binary with
  `--v2-genesis-pin <the fleet's pin>`; it re-derives the chain, including the vote's
  block under the new rules, and must match the fleet's `state_root` at a common height.

## 2.1 View-authority cutover — DOES NOT APPLY to a version-3 (cometbft) chain

This section used to describe the O15N Faz 2C2 stop-all cutover: quiesce the
fleet, then clear the `pbft_state` row (`current_view` + `last_prepared_blob`)
on every stopped node so that no node wakes on a view counter written under
the old rules. **R3 W4 (2026-09-17) deleted the mechanism the step served**
(OBLIGATION `atlas-dec-71525f3b4918f710b660707ac6bb5a3a`): there is no PBFT
view counter, no `nodus_witness_db_load_pbft_state`, no prepared-value lock
of that kind, and a fresh database no longer creates the `pbft_state` table.
A version-3 chain's round state lives in the cometbft WAL (since 0.20.0 the
file group `$DATA_DIR/cs.wal/wal`; before, the SQLite tables `cmt_wal`,
`cmt_wal_sync`) and its last-sign state file, and it is replayed by the
Handshaker at every start (`nodus_witness_cmt_node.c`, "ABCI replay blocks")
— there is nothing to clear by hand, and clearing anything by hand there
would be the defect, not the fix.

A `pbft_state` table left on disk by an older binary is inert: nothing reads
it. A stop-all deploy of a consensus change on this lane is §2 exactly as
written — stop every node, deploy, start; with a **fresh chain** (no V1/V2
ancestor) the ceremony in §1.5 births it, and the harness's restart scenario
(`test_v2_restart_convergence.sh`) is the model of what a correct restart
looks like: `chain role: COMETBFT`, `cometbft startup table built`,
`ABCI replay blocks: app H, store H, state H`, `cometbft lane LIVE`, then
the node catches up through the reactor's stored-part gossip.

---

## 3. Post-deploy verification

```bash
nodus/build/nodus-cli cluster-status <host1:4001> <host2:4001> ...
```

`cluster-status` prints, per node, `STATUS / HEIGHT / PEERS / UPTIME / DF% /
WALL_CLOCK / STATE_ROOT` (`nodus/tools/nodus-cli.c:500-560`).

**R3 W4 package H — on a version-3 chain `STATE_ROOT` is the committed
GLOBAL ROOT of the tip** (`nodus_server.c` `handle_t2_status`: on a
`v2_successor` chain it reads `nodus_witness_v2_committed_global_root`, the
stored `v2_blocks.global_root` at `MAX(global_height)` — never a recompute;
before W4-H it copied the legacy `cached_state_root`, which a version-3
chain never fills, so the column printed empty). `HEIGHT` is the version-3
tip: `nodus_witness_block_height` reads `MAX(global_height)` from
`v2_blocks` (`nodus_witness_db.c`, the `v2_successor` branch of
`nodus_witness_block_height_checked`). So the table's AGREEMENT check is
now what it was on the legacy lane: every node at the same `HEIGHT` must
print the same `STATE_ROOT` (a node one height behind prints the previous
root — compare at equal heights). The per-node database read the harness
uses (`stagef_cmt_diff_at_floor`) additionally compares `block_id`; use it
when the CLI's table is not enough:

```bash
# on every node, the same three values must agree at the same height
sqlite3 /var/lib/nodus/data/witness_*.db \
  "SELECT global_height, hex(global_root), hex(block_id) FROM v2_blocks \
   ORDER BY global_height DESC LIMIT 1;"
```

**The pass condition is agreement, not liveness:**

- every node `UP`;
- **every node reporting the SAME `global_root` and `block_id` at the same
  height** — a node that is up and advancing while disagreeing is exactly
  the failure a consensus deploy can introduce;
- height advancing over successive samples — on this lane a block every
  ≈ 6 s whether or not there is traffic (every block is a proof block).

Then check logs. A version-3 node that stops participating says so with
`CMT_FAULT` (the W1.7 rule: log + stop, never a peer blame); a decided
block the engine refuses says `FinalizeBlock`; the readiness and
quarantine lines keep their names:

```bash
journalctl -u nodus -n 200 | grep -i "CMT_FAULT\|FinalizeBlock\|SUPPLY\|QUARANTINED\|REFUSING START"
```

The same checks are automated by `nodus/tests/smoke_post_deploy.sh`, **rewritten
2026-07-28** (the previous version could not run at all, and would not have detected
divergence if it had — see its header comment for the specifics):

```bash
# Agreement only — no wallet needed, safe to run any time:
./nodus/tests/smoke_post_deploy.sh <host1:4001> <host2:4001> ...

# Agreement + liveness (needs a funded wallet on this machine):
SMOKE_SPEND_TO=<fingerprint> SMOKE_SPEND_AMOUNT=<raw base units> \
    ./nodus/tests/smoke_post_deploy.sh <host1:4001> ...
```

It fails immediately on **same height with different `state_root`** (a real divergence,
never retried) and retries while heights merely differ (a node catching up), so it is
not flaky by construction. Verified against a live 7-node harness on 2026-07-28: 7/7
agreement passes, and a single unreachable node fails it.

---

## 4. Rollback

Rollback is a git checkout plus a rebuild — the same mechanism as deploy.

1. Stop **all** nodes (mixed versions during a rollback are the same split hazard):
   ```bash
   sudo systemctl stop nodus
   systemctl is-active nodus           # "inactive" on every node
   ```
2. On each node, return to the commit recorded in §2 step 1:
   ```bash
   cd /opt/dna && git checkout <ROLLBACK_COMMIT>
   cd nodus/build && cmake .. && make -j$(nproc)
   ```
3. **Chain state:** an ordinary code rollback needs **no** DB restore — the on-disk
   chain is unchanged by a binary swap. Only a rollback that crosses a
   `state_root`/schema change needs the archived DB, restored from the `§1`
   `archive/<TS>/` directory that deploy created:
   ```bash
   mv "$DATA_DIR"/witness_* "$DATA_DIR/archive/failed-$(date +%s)/"   # keep the bad state
   cp -a "$DATA_DIR/archive/<TS>"/witness_* "$DATA_DIR/"
   ```
   Confirm ownership/permissions match what the running service expects — **check what
   the existing files use, do not assume a user name**:
   ```bash
   ls -l "$DATA_DIR/archive/<TS>"/witness_*
   ```
4. Start all nodes, then run §3. Every node must return to the same height and
   `state_root` as before the failed deploy.

If a step fails, stop and diagnose. Do not improvise a partial cluster.

---

## 5. Known gaps (honest list, not a to-do disguised as procedure)

- `smoke_post_deploy.sh` is broken and divergence-blind (§3).
- There is no automated pre-deploy DB snapshot. §1 archiving is manual and only
  happens on chain-wipe deploys, so an ordinary deploy has no DB safety net — which is
  acceptable only because an ordinary deploy does not touch the DB.
- No health-check or rollback automation exists; every step here is manual.
- The old `data_path` inconsistency (`nodus_witness_peer.c:558` naming
  `/var/lib/nodus/data/`) left with that file in 0.20.0; §1 still verifies the data
  directory rather than assuming it.
