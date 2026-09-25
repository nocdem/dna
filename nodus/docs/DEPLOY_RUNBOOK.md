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
| Logging, metrics, non-consensus tooling | Rolling, one node at a time |

**Why stop-all for validity changes:** during a rolling window the cluster runs mixed
versions. If the new binary accepts a block the old one rejects (or vice versa), the
disagreement *is* a chain split. This is not hypothetical — it is the failure mode the
v0.18.17 fee-gate fix was written to remove.

⚠ **The code will NOT stop you from getting this wrong.** There is a mixed-version
fail-fast (`nodus_witness_bootstrap.c:500-520`, `exit(3)`), but it only runs in the
DISCOVER branch — i.e. for a **fresh node with an empty chain DB**. A node that already
has a chain (`tip >= 1`) takes the HAVE_CHAIN branch and goes straight to
`BOOTSTRAP_DONE` (`nodus_witness_bootstrap.c:340-357`) without ever evaluating peer
versions. Restarting existing production nodes on mixed versions is therefore
**silently permitted**. The discipline is yours, not the binary's.

---

## 1. Archive on-disk witness chain state

Required before any **chain-wipe** deploy (state_root format change, witness chain
format change). Not required for an ordinary code deploy.

**First: find the real data directory. Do not assume it.**

`data_path` defaults to `/var/lib/nodus` (`nodus/tools/nodus-server.c:162`) but is
overridden by `data_path` in the node's config (`nodus-server.c:113-114`) or by `-d`
(`:178`). Note the tree is inconsistent about this: an operator-facing log line at
`nodus/src/witness/nodus_witness_peer.c:558` points at `/var/lib/nodus/data/`. So:

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
   ```
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

---

## 2.1 View-authority cutover — DOES NOT APPLY to a version-3 (cometbft) chain

This section used to describe the O15N Faz 2C2 stop-all cutover: quiesce the
fleet, then clear the `pbft_state` row (`current_view` + `last_prepared_blob`)
on every stopped node so that no node wakes on a view counter written under
the old rules. **R3 W4 (2026-09-17) deleted the mechanism the step served**
(OBLIGATION `atlas-dec-71525f3b4918f710b660707ac6bb5a3a`): there is no PBFT
view counter, no `nodus_witness_db_load_pbft_state`, no prepared-value lock
of that kind, and a fresh database no longer creates the `pbft_state` table.
A version-3 chain's round state lives in the cometbft WAL (`cmt_wal`,
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
- The `data_path` inconsistency between `nodus-server.c:162` (`/var/lib/nodus`) and
  `nodus_witness_peer.c:558` (`/var/lib/nodus/data/`) is unresolved in the code. §1
  works around it by verifying rather than assuming; the underlying inconsistency
  should be fixed.
