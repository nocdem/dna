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
| Changes to **when the PBFT view counter may move** | **STOP-ALL + `pbft_state` reset, NO chain wipe** — see §2.1 |
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

## 2.1 View-authority cutover (O15N Faz 2C2)

**This is a STOP-ALL deploy with NO chain wipe.** The blocks on disk stay. What
changes is the RULE for moving `w->current_view`, and one persisted row was
written under the old rule.

**What changed.** Before this build the PBFT view counter had three
message-driven writers, none of which needed a proof: a PROPOSE copied the
leader's claimed view unconditionally (in *either* direction), a NEW_VIEW raised
it on one signature, and reaching your own view-change quorum set it. After it,
the counter moves in exactly one place — on a **VIEW_OK proof**: f+1 distinct,
signature-verified statements for a strictly higher view, judged against the
committee governing the height the proof carries. A PROPOSE at any other view is
now REFUSED, in both directions. (Mechanism: `nodus/docs/MEMPOOL_BLOCK_TIME.md`,
"Who writes `current_view`".)

Two ordered steps. **Do them in this order; the reasons are different.**

### Step 1 — QUIESCE the fleet BEFORE stopping it

No transaction in flight, last block committed, on every node.

**Why, and it is not tidiness.** Step 2 clears the `pbft_state` row, and that row
holds **two** things: `current_view` and `last_prepared_blob`. `last_prepared` is
the prepared-value lock — the record of a value this node PREVOTE-quorum'd but
has not yet committed — and it is what makes a node refuse a conflicting value at
that height. That refusal is the quorum intersection safety relies on. Clearing
it on ONE node is harmless (the other holders still refuse). Clearing it on
**every node at the same moment** removes the protection entirely, and a value
that reached PREVOTE quorum without committing could then be replaced. Quiescing
first means no such value exists to lose.

```bash
# On each node: confirm nothing is in flight and the tip is stable.
nodus/build/nodus-cli cluster-status <host1:4001> <host2:4001> ...
# Sample twice, ~30 s apart, with NO client traffic being submitted.
# Required: every node UP, every node the SAME HEIGHT and SAME STATE_ROOT,
# and the height IDENTICAL between the two samples.
```

Do not proceed while heights differ or are still advancing.

### Step 2 — Clear the `pbft_state` row on every node, while it is stopped

**Why.** The `current_view` on disk was written under the OLD rules, where an
unproven message could move it. Every node restores its own value at startup
(`nodus_witness_db_load_pbft_state`), and those values need not agree — one node
may have been pushed up by a PROPOSE or a NEW_VIEW that no proof ever backed.
With the equality gate now in force, a fleet that wakes split across views does
not converge on its own: **no node accepts another's proposal at all** until the
escalation ladder happens to land a majority on the same rung. Starting every
node at view 0 is byte-identical to a fresh cluster, which is the best-tested
path in the tree.

Run **after** `systemctl stop nodus` on that node and **before** starting it
again (step 5 of §2). The database must not be open.

```bash
# Find the real data directory first — do not assume it (see §1).
grep -E '"?data_path"?' /etc/nodus.conf || echo "not set — default /var/lib/nodus"
DATA_DIR=<the path you just confirmed>

systemctl is-active nodus            # MUST print "inactive" before touching the DB
ls "$DATA_DIR"/witness_*.db          # confirm exactly which file you are about to edit
DB=<the witness_<chain_id>.db you just listed>

# Show the row BEFORE, so the change is recorded rather than assumed:
sqlite3 "$DB" "SELECT id, current_view FROM pbft_state;"

sqlite3 "$DB" "DELETE FROM pbft_state WHERE id = 1;"

# Verify: zero rows. load_pbft_state with no row leaves current_view at 0
# and last_prepared absent, which is the fresh-cluster default.
sqlite3 "$DB" "SELECT COUNT(*) FROM pbft_state;"      # MUST print 0
```

`pbft_state` is a singleton table (`id` is always 1) created by the schema-v16
migration. Deleting the row is not a schema change and does not touch blocks,
nullifiers, UTXOs or validator snapshots.

**If `sqlite3` is not installed on the node**, install it or stop — do not
improvise with a partial cluster, and do not start a node whose row you could not
clear. A single node restoring a stale view is the split this step exists to
prevent.

### After starting: what "correct" looks like

Run §3 as usual, and additionally:

```bash
journalctl -u nodus -n 500 | grep -i "VIEW_OK"
```

- `VIEW_OK — statement emitted for view N` on a node that reached its own
  view-change quorum: expected, and it means the node SPOKE without moving.
- `VIEW_OK PROOF ACCEPTED — view A -> B`: the counter moved on a proof. This is
  the only line that means a rotation happened.
- `VIEW_OK — no committee at height H`: **not** expected on a chain that has
  committed its genesis. If it appears, the node cannot resolve its committee and
  its view can never move — diagnose before continuing.
- A quiet, healthy chain prints none of these. Their absence is not a fault.

### The one behaviour this cutover cannot fix

On a chain with **no committee snapshot at all** — a fleet that has not yet
committed its genesis block — no VIEW_OK statement can be signed, so no proof can
exist, so the view cannot move. A brand-new cluster whose genesis round lands on
a silent leader will not rotate away from it. This does not affect an existing
chain, which has a committee from its genesis onward; it is recorded here because
it changes how a **fresh** bring-up must be handled.

---

## 3. Post-deploy verification

```bash
nodus/build/nodus-cli cluster-status <host1:4001> <host2:4001> ...
```

`cluster-status` prints, per node, `STATUS / HEIGHT / PEERS / UPTIME / DF% /
WALL_CLOCK / STATE_ROOT` (`nodus/tools/nodus-cli.c:505-535`).

**The pass condition is agreement, not liveness:**

- every node `UP`;
- **every node reporting the SAME `HEIGHT` and the SAME `STATE_ROOT`** — a node that is
  up and advancing while disagreeing is exactly the failure a consensus deploy can
  introduce;
- height advancing over successive samples once traffic exists.

Then check logs for divergence. The real log string is `state_root DIVERGED`
(`nodus/src/witness/nodus_witness_bft.c:3251`):

```bash
journalctl -u nodus -n 200 | grep -i "DIVERGED\|SUPPLY INVARIANT\|QUARANTINED"
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
