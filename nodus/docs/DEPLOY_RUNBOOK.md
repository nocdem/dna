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

Deployment is **`git pull` + `make` on each node**. There is no package and no artifact
registry; a tar.gz installer can be BUILT (component split S7, "tar.gz installer" below)
but it is not the deploy method of the live cluster, and where a tarball is published and
how it is signed is not decided. Consequently **rollback is also a git operation** — check out
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
| A **height-activated** rule that is inert until a chain-config vote turns it on (HF-1 gas price, nodus 0.19.80; HF-2 param 7; HF-3 param 8; HF-4 param 9 — the rule-set generation switch, nodus 0.23.10) | **Rolling** binary upgrade (the rule is byte-identical to the old binary while no row exists) — then the vote, ONLY after 7/7 run the new binary. §2.2 |
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

### Three-process node (`nodus-core` + `nodus-storage` + `nodus-witness`) — NOT declared deployable yet

Component split S6 (decision `2026-10-01-nodus-component-split.md`; `docs/ARCHITECTURE.md`
§10 "Component split", S6) ships the pieces of a three-process node: the binaries
`nodus-core`, `nodus-storage`, `nodus-witness` (beside the combined `nodus-server`, which
stays — item 8) and three systemd units in `nodus/deploy/`. **Keep production nodes on
the combined `nodus.service` until the two OPEN items below are decided.** This section
describes what exists so a test host can be switched and switched back.

**What runs.** `nodus-core.service` (`nodus-core -c /etc/nodus.conf --storage-external
--witness-external`): UDP 4000, TCP 4001 (+ the WebSocket entry), the 4002 listener,
cluster, presence, circuits, the partial-wipe gate, and the identity — it is the only
process that creates or writes `identity/`. `nodus-storage.service` (`--storage-external`):
`nodus.db`, `channels.db`, routing, replication, its own outbound 4002 dials; no port of
its own, `<data_path>/storage.sock`. `nodus-witness.service` (`--witness-external`): 4004
and consensus, the chain database, `<data_path>/witness.sock`. Same `/etc/nodus.conf`, same
`/var/lib/nodus`. The `--*-external` flags are on the units' command lines, NOT in the
config file — keep `witness_external` / `storage_external` false (or absent) in
`/etc/nodus.conf`, so the same file still starts `nodus.service`.

**Installed by** `deploy/build-nodus.sh` (Release): all five binaries (`nodus-server`,
`nodus-core`, `nodus-storage`, `nodus-witness`, `nodus-cli`) to `/usr/local/bin`, the
three units to `/etc/systemd/system/` — copied, **not enabled**. `tools/nodus-update.sh`
installs the same five binaries and re-copies the three unit files from `nodus/deploy/`
(then `systemctl daemon-reload`), so a unit fix reaches hosts kept current with it.

**Which layout an update touches — decided by `systemctl is-enabled`, never by
`is-active`** (both scripts, before they pull or install anything):
- `nodus.service` enabled → the combined server is stopped, updated, started.
- `nodus-core` enabled → the split units that are enabled are stopped, updated, started
  (core is in every layout; storage and witness are each optional — decision item 12).
- Both enabled, neither enabled, or `nodus-storage` / `nodus-witness` enabled without
  `nodus-core` → the script **refuses** with a message and changes nothing (no pull, no
  install). It never guesses, and never starts `nodus.service` on a host whose split
  units are enabled. A layout that is down at the moment is still the host's layout —
  that is why `is-active` is not used.
- Binaries are installed **atomically**: `install -m 0755 src dest.new && mv -f dest.new
  dest`, after the layout's units are stopped — a running binary is never written in
  place.
- `build-nodus.sh --debug` refuses on a host where any split unit is enabled or active
  (`nodus-debug` would be a second server on the same data directory); a first install
  (no `nodus.service` file yet) refuses the same way rather than enable and start
  `nodus.service` beside split units.

**First install from a fresh clone needs `/etc/nodus.conf` written by hand.**
`deploy/nodus.conf.example` is gitignored, so a fresh clone does not have it;
`build-nodus.sh` then skips the config copy with a message and goes on to install and
start `nodus.service`, which cannot start without a config (and stops after 3 failed
starts in 300 s, `StartLimitBurst=3`). Write `/etc/nodus.conf` first — or after, then
`systemctl reset-failed nodus && systemctl restart nodus`.

**Start order and dependencies.** Storage and witness carry `After=` + `Wants=
nodus-core.service` — never `Requires=` / `BindsTo=`. So `systemctl start nodus-witness`
pulls core in and starts core first; **stopping core does NOT stop the witness** (item 5:
consensus runs on; this node's clients drop until core is back). `After=` orders STARTS only (`Type=simple`, no readiness signal): on a
FIRST boot storage and witness may start before core has written the identity, exit 1
("identity … missing"), and are retried every 5 s within `StartLimitBurst=10` /
`StartLimitIntervalSec=300` (core: 3 / 300, as `nodus.service`). If either unit hits the
limit: `systemctl reset-failed <unit> && systemctl start <unit>` once core is up.

**Never both layouts.** All three units carry `Conflicts=nodus.service` AND
`After=nodus.service`: starting the combined unit stops the split units and vice versa,
and the `After=` makes systemd finish the stop before the start (`Conflicts=` alone
implies no ordering — systemd.unit(5); a stop job is always ordered before a start job
whichever direction the order names). Not exercised on a host in S6 — do not rely on it
as the switch procedure; the steps below stop one layout explicitly. Two layouts at once
on one data directory would mean two DHTs on one `nodus.db` and two signers with one
validator key.

**Switch a host to three processes** (test host; consensus bytes, `app_hash` and the 4004
wire are unchanged, so no hard fork is involved):
1. `systemctl disable --now nodus` (the combined unit), and check `systemctl is-active
   nodus` prints `inactive` before step 3.
2. `nodus.addr_seq`: the witness writes it under `data/`, never `identity/` (item 10); an
   existing host's file in `identity/` is moved only by the S7 installer (item 21,
   "tar.gz installer" below) — switching by hand, move it yourself while every unit is
   stopped: `mv <identity_path>/nodus.addr_seq <data_path>/nodus.addr_seq`, only if the
   data copy does not exist. nodus-witness only WARNs once at start when it sees the old
   file and no new one.
3. `systemctl enable --now nodus-core nodus-storage nodus-witness`.
4. Verify: `journalctl -u nodus-core` shows `STORAGE: external` and `WITNESS: external`;
   `journalctl -u nodus-witness` shows `chain role: COMETBFT` and `cometbft lane LIVE`;
   `<data_path>/storage.sock` and `witness.sock` exist; then §3 as for any node.

**Rollback = the combined unit:** `systemctl disable --now nodus-core nodus-storage
nodus-witness && systemctl enable --now nodus`. Same config, same data directory; no
data migration in either direction (the `addr_seq` caveat above aside).

**OPEN — decide before declaring this layout deployable:**
- **nodus-witness runs no partial-wipe gate.** Core and nodus-storage both refuse a
  half-wiped data directory; nodus-witness does not check (it takes its lock, checks the
  network-file pin, loads the identity, then opens the chain). Under systemd, on a
  half-wiped host core and storage would sit in their restart loops while the witness
  opens the surviving chain database and keeps voting alone. Decision item 9 gives the
  check to core; it does not say the witness may proceed when core refuses. Operator
  decision pending; nothing was added in S6. Until it is decided, a host whose data
  directory may have lost files must have **all three** units stopped by hand.
- **Restart order on a live validator.** Restarting the witness first opens a consensus
  gap for this validator; restarting core first drops its clients. The units order only
  starts (`After=`); `nodus-update.sh` and `build-nodus.sh` stop the enabled split units
  together and start them together, and claim no order beyond that. Decision item 22 is the rollout order of the SPLIT itself (witness seam
  before storage), not a restart rule.
- `ReadOnlyPaths=/var/lib/nodus/identity` for storage / witness (item 10 enforced by the
  OS) is NOT in the units: only the witness's `addr_seq` / lock / marker writes were
  checked, not every write (`cs.wal`, address book, `priv_validator_state`); a blocked
  write would be a restart loop.
- The harness proves the three-process layout on localhost only (`STAGEF_MODE=split` /
  `mixed`, stagef README "Harness modes"); OLD/NEW upgrade runs of split nodes are
  deferred (decision item 23).

### tar.gz installer (`deploy/make-dist.sh` + `install.sh`) — component split S7

Decision `2026-10-01-nodus-component-split.md` item 26: the installer artefact is a
**tar.gz** (binaries + install script); a `.deb` is later work. **OPEN (decision file,
"Açık kalanlar"): where the tarball is downloaded from and how it is signed.** Until that
is decided the tarball is carried by hand, and its only integrity check is the SHA-256
you compare yourself. Everything in "Three-process node" above still holds — the
installer automates those steps, it does not make the split layout deployable.

**1. Build the tarball** (on a build machine, from an existing build directory):
```
cmake -S nodus -B nodus/build -DCMAKE_BUILD_TYPE=Release
cmake --build nodus/build -j$(nproc)
nodus/deploy/make-dist.sh nodus/build /tmp/out
```
Output: `/tmp/out/nodus-<NODUS_VERSION_STRING>-linux-<uname -m>.tar.gz`, and its SHA-256
printed on the last line — record it. The version comes from
`include/nodus/nodus_types.h`. make-dist.sh refuses when any of the five binaries
(`nodus-server`, `nodus-core`, `nodus-storage`, `nodus-witness`, `nodus-cli`) is missing,
when a binary's `-h` banner reports a version other than the header's (a stale build
directory), when the header's MAJOR.MINOR.PATCH disagree with its version string, when
the build carries `-fsanitize`, when the build directory's `CMAKE_BUILD_TYPE` is not
exactly `Release` (an empty build type is an unoptimized build and refuses too), when the
git tree has uncommitted or untracked changes under `nodus/` or `shared/` (both are
compiled into the binaries — commit first), when git cannot be asked at all (git
missing, not a checkout — the commit and the clean tree cannot be verified, so the
tarball's provenance cannot be either), or when the output file already exists.
The payload is an explicit list — the five binaries, the four units, `install.sh`,
`README` (`deploy/README-dist.md`), `VERSION` (version, arch, commit, tree, build type)
and `SHA256SUMS`. Tree is always `clean` (anything else refuses). No config (`deploy/nodus.conf.example` is never packaged), no
identity, no addresses. Staged modes are set explicitly (directory, binaries and
`install.sh` 0755, the rest 0644 — not the umask); archive entries are sorted, owned 0:0
and stamped with the last commit's time; the archive is written to a `mktemp` file in
the output directory and renamed into place. The binaries link the system's `libcrypto.so.3`,
`libsqlite3.so.0`, `libjson-c.so.5` (`readelf -d`; nodus-cli has no json-c) — the target
host needs those packages and a glibc no older than the build machine's.

**2. Copy and verify** on the target: copy the tarball, `sha256sum` it and compare with
the value from step 1, `tar -xzf` it, `cd` into the directory. `install.sh` verifies
`SHA256SUMS` itself before anything else (an unexpected or unlisted file also refuses) —
that proves the files match each other, not where they came from. It then checks that
the package runs on this host: `VERSION`'s arch must equal `uname -m`, and each of the
five binaries is run with `-h` (it prints its banner and exits before any init —
`tools/nodus_node_config.c` / `tools/nodus-cli.c` `usage()`), bounded by `timeout 10`;
a non-zero exit (missing shared library, too old a glibc) or a banner version other than
`VERSION`'s refuses, with the binary's error in the message, before any unit is touched.

**3. Install.** `/etc/nodus.conf` must exist, or pass `--config <file>` (installed as
`/etc/nodus.conf` with mode 0600 only when no such file exists — an existing one is never
overwritten; a `--config` that differs from it refuses). Always print the plan first:
```
sudo ./install.sh --layout split --dry-run      # prints every action, changes nothing
sudo ./install.sh --layout split                # core + storage + witness
sudo ./install.sh --layout split --no-witness   # core + storage   (decision item 12)
sudo ./install.sh --layout split --no-storage   # core + witness
sudo ./install.sh --layout combined             # nodus.service
```
**Run it inside `tmux` (or `screen`) on a remote host.** The installer traps Ctrl-C,
SIGTERM and SIGHUP and exits through the same path as a failure, so the rollback
commands are printed — but after an SSH drop they go to a terminal that no longer
exists; under tmux the run is not interrupted at all.

`--prefix DIR` (default `/usr/local/bin`) moves the binaries and rewrites the units'
`ExecStart=` to match. A prefix under `/home`, `/root`, `/run/user` (the units'
`ProtectHome=true` hides them) or `/tmp`, `/var/tmp` (`PrivateTmp=true` gives the service
an empty private one) refuses — checked as typed and with symlinks resolved. The same
check is applied to `data_path` / `identity_path`, which must in any case lie under the
units' `ReadWritePaths=/var/lib/nodus`. **`deploy/build-nodus.sh` and
`tools/nodus-update.sh` install to `/usr/local/bin` only:** on a host installed with
another `--prefix` they would put the new binaries where the units do not look — keep
updating that host with `install.sh`. `--dry-run` does not require root but must read
the config — an `/etc/nodus.conf` this installer wrote is 0600, so run it under `sudo`
there; a real run refuses without root.

`--allow-downgrade`: the installer reads the installed version — `-h` of every nodus
binary in the prefix and of every binary an installed nodus unit's `ExecStart=` names —
and refuses when that version is NEWER than the package's, or when an installed binary's
version cannot be read (its `-h` fails or prints no version, so a downgrade cannot be
ruled out). An equal version (reinstall) proceeds. **Going back to an older release
after this chain has voted a hard fork that release lacks makes this node stop following
the chain:** hard forks are height-activated, and a binary older than the one that
introduced a voted fork stops participating (§2.2 — "Why the order matters", and the
"Live hard forks" table for which binary introduced each fork). Pass `--allow-downgrade`
only for a release at or above every introducing binary in that table.

What a run checks, in the script's order — any failure refuses and changes nothing:
1. arguments: `--layout` and the `--no-*` flags; `readlink -m` must work (GNU coreutils —
   without it the symlink half of the next check would be skipped, so it refuses);
   `--prefix` a plain absolute path, not under the protected directories above (as typed
   and resolved); `--config` a file;
2. the payload (step 2 above): `SHA256SUMS`, `VERSION`, arch, each binary's `-h`;
3. root (not for `--dry-run`); `systemctl` present;
4. the config: `/etc/nodus.conf`, or `--config` when it does not exist (a `--config` that
   differs from an existing file refuses); readable;
5. `identity_path` / `data_path`: present twice, or not a non-empty string → refuse; then
   each must be a plain absolute path, not under the protected directories (checked like
   `--prefix`). The key count and the value are read from the config flattened to one
   line, so a line break between a key, its colon and its value neither hides the key nor
   a second copy of it;
6. `"witness_external": true` or `"storage_external": true` in the file (same flattened
   read) → refuse; then each packaged unit must carry one `ReadWritePaths=` and all four
   the same, and `data_path` / `identity_path` must lie under it (`/var/lib/nodus`);
   then `--layout split` without `identity_path` → refuse;
7. `nodus-debug.service` (written by `build-nodus.sh --debug`: same `/etc/nodus.conf`,
   same data directory, no `Conflicts=` with these units, not in the installer's stop
   list) enabled or running → refuse — `systemctl disable --now nodus-debug` first;
8. a systemd drop-in that applies to `nodus`, `nodus-core`, `nodus-storage` or
   `nodus-witness` → refuse: `*.conf` in `<unit>.service.d/`, in `nodus-.service.d/` (the
   dash-prefix drop-in systemd applies to all three split units, `man 5 systemd.unit`) or
   in the top-level `service.d/` (every service), under `/etc/systemd/system`,
   `/run/systemd/system`, `/lib/systemd/system` or `/usr/lib/systemd/system`. Every
   check here reads the PACKAGED unit, not what a drop-in turns it into;
9. the installed version (the `--allow-downgrade` paragraph above);
10. the current layout, by `systemctl is-enabled` (exactly `enabled`), the same rule as
   `build-nodus.sh` / `nodus-update.sh`: both layouts enabled, or storage / witness
   enabled without core → refuse; then a split unit that is enabled but not asked for →
   refuse (it never removes a split service — disable it yourself first);
11. `nodus.addr_seq` in both the identity and the data directory → refuse (below).

Then it prints the plan and, in order:
- installs `--config` as `/etc/nodus.conf` when that file did not exist, and creates the
  missing ones of `data_path`, `identity_path` and the prefix;
- copies the five binaries and the four units next to their destinations as
  `<dest>.new` while the node still runs (each packaged unit must have exactly one
  `ExecStart=/usr/local/bin/` line — the `--prefix` rewrite needs it — checked here). A
  failure up to here — that check, or a full disk while copying — stops nothing: the `.new` files are removed, and the message says the running
  node was not touched and names only what this run created (`/etc/nodus.conf` if it
  installed it, directories it made); it prints no layout-switch commands, because none
  are needed;
- stops every nodus unit that is running and the current layout's units; disables the
  old layout's units the new one does not use;
- renames every staged `.new` over its destination (`mv -f`; binaries, then units), then
  `systemctl daemon-reload` — a failed copy can no longer leave old and new binaries
  mixed. If the rename itself is interrupted midway (a signal, a failing `mv`), the
  message says the prefix may hold a mix of old and new binaries (or `/etc/systemd/system`
  a mix of units) and that running the same `install.sh` again with the same arguments
  stages everything again and completes the swap;
- **`nodus.addr_seq` (item 21):** when the split witness is about to run on this host for
  the first time (witness wanted, `nodus-witness` not enabled before), moves
  `<identity_path>/nodus.addr_seq` to `<data_path>/nodus.addr_seq` if the data copy does
  not exist; if BOTH exist it refuses before changing anything and prints both paths
  (keep the current one, remove the other). No other identity file is touched; nothing
  is wiped;
- enables and starts the wanted units: `nodus-core` first, then waits — at most 60 × 1 s,
  stopping early if core fails — until the six identity files core writes (`nodus.pk`,
  `nodus.sk`, `nodus.kyber_pk`, `nodus.kyber_sk`, `nodus.mlkem_pk`, `nodus.mlkem_sk`) exist
  in `identity_path`, then `nodus-storage`, then `nodus-witness`;
- after a fixed 5 s prints `systemctl is-active` of each wanted unit and exits 1 if any
  is not `active`. That is a snapshot, not a health check — run §3 afterwards.

**4. Switch layout** = run `install.sh` with the other `--layout`. combined → split: stop +
disable `nodus`, the `addr_seq` move, enable + start core → storage → witness. split →
combined: stop + disable the split units, enable + start `nodus`; the `addr_seq` file is
NOT moved back (item 21 names only the forward move) — the plan prints a note, and the
combined server's own sequence lives in `<identity_path>/nodus.addr_seq`; move it back by
hand while `nodus` is stopped if you want to keep the sequence. Never both layouts
enabled at any step.

**5. Rollback.** The signal traps are installed before the first check (harmless until
something changes: an interrupt then only says nothing was changed). A failure or
signal before any unit is stopped needs no rollback (see the staging item above). On
any failure once the stop / disable step has begun — and on Ctrl-C, SIGTERM or SIGHUP
then — the installer prints: `systemctl disable --now nodus-core nodus-storage
nodus-witness && systemctl enable --now nodus`, plus the `addr_seq` move-back when it had
moved the file, and says whether the binaries were replaced. When they were, the prefix
holds the NEW version: to return to the previous version run the previous tarball's
`install.sh --layout combined --allow-downgrade` (or the git rollback in §4). **That is
safe only while the chain has voted no hard fork the previous release lacks** — after
such a vote the older binary stops following the chain (§2.2); the printed hint says so.

What the installer does NOT do: pick a restart order on a live validator beyond core →
storage → witness at start (the "Restart order" item above stays OPEN), add a
partial-wipe gate to the witness (OPEN above), publish or sign anything, or touch any
node it is not run on.

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
reward reserve, 7 × 10M bonds, the Founder allocation, the nine treasury
pools of which the Foundation's five are genesis outputs to the Foundation
multisig address) and a checker live in `nodus/tools/genesis/`
(`testnet_v3.conf.template`, `check_genesis_conf.sh`, `README.md`) — start
from there. The checker needs the Foundation's keys and threshold (it
recomputes the Foundation multisig address through `nodus-cli msig
address`):

```
./check_genesis_conf.sh genesis.conf --cli /path/to/nodus-cli \
    --foundation-m 2 --foundation-pubkey keyA/nodus.pk \
    --foundation-pubkey keyB/nodus.pk --foundation-pubkey keyC/nodus.pk \
    [--derive /path/to/nodus-server]
```

The shape (abridged — the `[treasury]`, W-C fee keys and
`[genesis_output]` blocks are in the template):

```
config_version         = 5          # REQUIRED; only 5 is accepted
                                    # (general multisig; 4 = W-A/W-C)
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
unstake_destination_pubkey = <5184 '0' characters — MUST be all zero>
unstake_destination_fp     = <128 hex chars — the Foundation multisig address>
self_stake                 = 1000000000000000
commission_bps             = 500

[allocation]                        # 1 or more
source_id    = <128 hex chars>
dest_binding = <128 hex chars — SHA3-512 of the claimant's pubkey>
amount       = 5000000000000

[genesis_output]                    # 0 or more, FILE ORDER = coin index
owner  = <128 hex chars — an address, e.g. the Foundation multisig>
amount = 5000000000000000
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
   On a three-process host ("Three-process node" above) the stop set is the three
   units — the witness keeps running if only core is stopped:
   ```bash
   sudo systemctl stop nodus-core nodus-storage nodus-witness
   systemctl is-active nodus-core nodus-storage nodus-witness   # all "inactive"
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

**0.20.3 is a consensus-rule change (chain-config param 2 refused) — STOP-ALL.**
A 0.20.2 node would commit a param-2 vote a 0.20.3 node refuses. Stop all,
build, start all (no wipe; the devnet had no param-2 row, checked 2026-09-28).
Then update Nodus Scan (node BEFORE explorer — the explorer needs
`dnac_v3_block` / `dnac_balance`): on the explorer host
`git -C /opt/dna pull && cmake -S /opt/dna/messenger -B /opt/dna/messenger/build
&& make -C /opt/dna/messenger/build -j$(nproc) dna-explorerd && systemctl restart
dna-explorerd`; the index rebuilds from height 1 (schema v2). Then the static
site per `website/deploy/README.md`.

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

### Live hard forks — testnet chain `a48d1a785500a1cd…` (genesis 2026-09-30)

The chain's own record is `chain_config_history` (one row per vote; the row is the same
on every node). Read it on any node:
`sqlite3 /var/lib/nodus/data/witness_*.db "SELECT param_id,new_value,effective_block,commit_block,hex(tx_hash) FROM chain_config_history ORDER BY param_id;"`.
**Add a row here in the same push as every new vote**, read back from 7/7.

| Fork | Rule from the effective height | Param | Value | Voted in block | Effective block | Binary that introduced it | tx_hash (first 8 bytes) |
|---|---|---|---|---|---|---|---|
| HF-1 | gas price: an envelope with a non-SYSTEM leg pays `max(units × price, floor)` | 5 `GAS_PRICE_RAW_PER_UNIT` | 121 | genesis document (0) | 0 | 0.19.80 | `DE43BDFAD6600BF5` |
| HF-2 | governance approvals weighed by voting power (> 2/3); a touched domain that nets to zero applies | 7 `HF2_ACTIVE` | 1 | 724 | 1500 | 0.23.2 | `477E05BD7C62EE4A` |
| HF-3 | block bounded by cometbft's limits only (no 2 MiB / 2 097 152-unit bound); ProcessProposal checks gas price, committed replay, units ≤ INT64_MAX | 8 `HF3_ACTIVE` | 1 | 2206 | 2926 | 0.23.9 | `4CE838897C4F853B` |
| HF-4 | rule-set generation 2 (SYSTEM v7 / CORE v5): the registry switches at the end of H−1; CORE op 8 NAME_REGISTER (on-chain names) and the name-price params 10-13 are in force from H | 9 `RULESET_GEN2` | 4962894749133920991 (D2 = 0x44dfbe7ad3c75adf) | 2431 | 3151 | 0.23.10 | `BD84A28A3D3EE5B1` |

Read 2026-10-02: the HF-4 row on 7/7 (identical; proposed from EU-5, 7/7 approvals; the
seven nodes on 0.23.10 with identical D2/commit/consensus-constants startup lines, the web
wallet, Connect, explorer and Scan released before the vote). The HF-3 row on 7/7 (identical; proposed from EU-5, 7/7 approvals); the
HF-1 and HF-2 rows on EU-5 (the HF-2 row was read on 7/7 when it was voted, 2026-09-30). A node that was not on the introducing binary when a vote committed
diverges at that block — recovery at the end of this section.

### Procedure

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
   shows the new version as the LAST such line. (Earlier text also told you to look for
   the absence of a `PEER SCHEMA MISMATCH` line; no code emits that line since 0.20.0 —
   see the warning at the top of this file — so its absence proves nothing. The version
   line is the only check.) There is no on-chain "how many upgraded" indicator yet
   (planned: `docs/plans/decisions/2026-09-26-governance-before-testnet.md`), and the code
   does not enforce 7/7: an approval collects as soon as seats holding more than 2/3 of the
   committee power run the new binary — 7/7 first is procedure.
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

**HF-2 — the same procedure for chain-config param 7 `HF2_ACTIVE`** (design
`docs/plans/2026-09-30-gov-weight-netzero-design.md` rev 2; mechanism
`ARCHITECTURE.md` "HF-2"). From H, governance approvals are weighed by voting
power (> 2/3) instead of seats, and a block whose touched domain nets to zero
applies instead of stopping every node.
1. **Rolling binary upgrade to the HF-2 build, one node at a time**, as step 1
   above. Before the vote the HF-2 binary decides every block exactly as 0.23.1
   (the consensus-read envelope bound stays 3 075 — ARCHITECTURE.md "HF-2",
   "Byte-identical while off").
2. **Verify 7/7 are on the HF-2 binary BEFORE voting** (step 2 above). An old
   binary refuses id 7 per item (code 7), commits the vote's block anyway and
   halts on the next header — the same lagging-node rule and recovery as HF-1.
3. **Vote under TODAY's rule — seats**:
   `nodus-cli chain-config propose --param HF2_ACTIVE --value 1 --effective <H>`
   (`<H>` ≥ tip + 1 + 720, the ERGONOMIC grace). The value domain is exactly 1; there is no
   "off" vote. The row must appear identically on 7/7 (`chain_config_history`:
   param_id 7).
4. **Before H** nothing changes. **From H** every CHAIN_CONFIG approval set must
   carry > 2/3 of the governing committee's voting power (`nodus-cli witness`
   prints the threshold). The online `propose` still uses the seat count for its
   own early abort (it cannot read param 7); a proposal it submits is judged by
   the chain's power rule. The offline `v2-envelope chain-config` follows the
   power rule itself.
5. **Every later hard fork is voted under the power rule** (decision
   `2026-09-30-governance-stake-weight-and-power-cap.md` item 1: this is the
   activation path of the others).

**HF-3 — the same procedure for chain-config param 8 `HF3_ACTIVE`** (design
`docs/plans/2026-10-01-hf3-comet-block-bounds-design.md` rev 3; decision
`docs/plans/decisions/2026-10-01-hf3-comet-only-block-bounds.md`; mechanism
`ARCHITECTURE.md` "HF-3"). From H a block is bounded by cometbft's consensus params only
(`Block.MaxBytes` 22 020 096 and the 3 075-envelope bound): the 2 MiB envelope-byte bound
is not checked, the global unit budget and every quota-0 domain's budget are unbounded
(today ≤ 255 one-in/one-out spends per block; afterwards up to ~3 000 envelopes), a
declared `res_max_total_units` above `INT64_MAX` is refused, and ProcessProposal refuses
a block carrying an envelope that underpays the gas price or is already committed. The
decision orders HF-3 BEFORE the nodus component split (answer 8).
1. **Rolling binary upgrade to the HF-3 build, one node at a time**, as step 1 above.
   No wipe: with no param-8 row the HF-3 binary decides every block exactly as the binary
   it replaces (ARCHITECTURE.md "HF-3", "Byte-identical while off") — HF-3 is inert until
   voted.
2. **Before the vote — all of the following, on every validator:**
   - **Per-node version check.** Each node's own log shows the HF-3 build's
     `Nodus v… running` line as the LAST such line (step 2 above). Do NOT rely on the
     absence of a `PEER SCHEMA MISMATCH` line — nothing has emitted it since 0.20.0. An
     old binary does not know id 8: it refuses the vote's item, commits the vote's block
     anyway and diverges there — at the VOTE's block, whatever the grace. Recovery is
     the one below (decision `2026-09-26-hard-fork-lagging-node.md`): wipe +
     genesis-pin rejoin on the HF-3 binary; a restart alone does not recover it.
   - **6 live peers per validator (full mesh on 4004).** A post-H block can reach 22 MB;
     over one link at 5 120 000 B/s that is ≥ 4.3 s, longer than `timeout_propose` in
     rounds 0-2, so a validator fed through a single link may prevote nil (design R4-5).
     ⚠ This runbook has no command that reads it yet: `cluster-status`'s `PEERS` column
     counts the inter-node cluster table's ALIVE entries (`nodus_server.c`
     `handle_t2_status`), not the 4004 p2p mesh, and the only 4004 signal in the log is
     the ERROR `this node holds a chain but has … connected` (`nodus_witness_p2p.c`
     `no_peer_check`), which fires only at 0 connected. The method is an open item —
     settle it before the vote.
   - **Harness measurements** (decision answer 11; design §2), on the HF-3 build: fsync +
     PrepareProposal time at 336 block parts (PrepareProposal runs after the propose timer
     is armed, and each internal part message is WAL-fsync'd before the first is
     gossiped), and FinalizeBlock time on a block of ~3 000 envelopes. Liveness at that
     size is NOT measured anywhere else. `test_cmt_hf3_block_bounds.sh` does NOT perform
     these measurements (stagef README, its row) — they are separate runs.
   - **The effective height `<H>` is asked of the operator** before the vote (decision
     item 4), never chosen by whoever runs the vote.
3. **Vote** with the HF-3 CLI:
   `nodus-cli chain-config propose --param HF3_ACTIVE --value 1 --effective <H>`
   (`<H>` ≥ tip + 1 + 720, the ERGONOMIC grace). The value domain is exactly 1; there is
   no "off" vote. The row must appear identically on 7/7 (`chain_config_history`:
   param_id 8). HF-2's step 3 ("vote under TODAY's rule — seats") described the vote
   BEFORE HF-2's own H; HF-3's vote comes after it on the live chain, so its approval set
   is judged by the power rule (HF-2 step 4) — the design records the live chain's
   param 7 = 1 effective 1500 (read 2026-10-02, EU-1 + EU-2).
4. **Before H** nothing changes. **From H** the bounds above hold. Wallets and CLIs need
   no new release (no wire or pin change); the per-block count is no longer capped by
   the declared unit ceiling, which stays the fee base (`units × gas price`).
5. **Reverting** is another hard fork: there is no off value, and the application sends
   no `consensus_param_updates`, so `Block.MaxBytes` cannot be lowered by governance.
   Accepted by the operator (decision answer 7): any seat on the HF-3 binary can propose
   param 8 at a height the operator did not pick — today all 7 seats are the operator's.

**HF-4 — the same procedure for chain-config param 9 `RULESET_GEN2`, with more pre-vote
checks** (design `docs/plans/2026-10-02-onchain-names-design.md` rev 4; decision
`docs/plans/decisions/2026-10-02-onchain-names.md` items 1-18; mechanism `ARCHITECTURE.md`
"HF-4"). At the end of block H−1 every node rewrites the SYSTEM and CORE registry records from
rule-set generation 1 (SYSTEM v6 / CORE v4) to the compiled generation 2 (SYSTEM v7 / CORE v5);
from H the chain accepts CORE op 8 NAME_REGISTER (on-chain names: first come, one per ID,
permanent, priced by length into the reward pool) and the name-price parameters 10-13 become
votable. Unlike HF-1..HF-3 the vote's VALUE names the target: it must equal the build's compiled
D2, `0x44dfbe7ad3c75adf` = **4962894749133920991** in decimal. The decision orders HF-4 BEFORE
the nodus component split (item 13).
1. **Rolling binary upgrade to the HF-4 build (nodus 0.23.10), one node at a time**, as step 1
   above. No wipe: with no param-9 row the registry stays at generation 1 and the HF-4 binary
   decides every block as the binary it replaces (ARCHITECTURE.md "HF-4", "Byte-identical while
   off"). Do not change any node's binary between the vote and H.
2. **Before the vote — all of the following:**
   - **Per-node version check** (step 2 above): each node's own log shows the HF-4 build's
     `Nodus v0.23.10 running` line as the LAST such line. An old binary does not know id 9
     (its `CC_PARAM_MAX_ID` is 8): it refuses the vote's item, commits the vote's block
     anyway and diverges there.
   - **Same generation 2 and same build on 7/7.** On every node:
     `journalctl -u nodus | grep -E 'rule-set generations|consensus build constants'` — the
     LAST pair of lines (tag `WITNESS`, printed at start after the runtime selfcheck) must be
     identical on all seven:
     `rule-set generations 2, generation-2 vote D2 0x44dfbe7ad3c75adf (switch spec v1), built from git commit <sha>`
     `consensus build constants: epoch_length 720, grace_safety 17280, grace_ergonomic 720, blocks_per_year 6307200, fault_inject off`
     A different D2 means a different generation 2 (that node would refuse the vote at the
     vote block and diverge — the lagging-node case); a different commit, or a `-dirty` /
     `-status-unknown` / `unknown` commit, means the seven are not provably the same source —
     settle it before the vote. Generation-2 details that D2 does not bind (the name alphabet,
     the compiled prices, the name-leaf layout, the ranges of params 10-13) are guarded ONLY by
     this comparison: two builds that differ there agree at the vote and split at the first
     registration after H. Binary SHA-256 is not compared — the build is not reproducible.
     Any other `consensus build constants` value (a short-epoch or fault-injection build) must
     never reach a validator.
   - **HF-2 is active.** Rule (b): the vote is refused unless param 7 is active at the vote
     height. On the testnet chain it is (param 7 effective 1500 — "Live hard forks" above).
     The switch leaves CORE's root unchanged at H−1, which only HF-2 accepts.
   - **6 live peers per validator (full mesh on 4004)** — the HF-3 item above; the method of
     reading it is still the open item recorded there.
   - **Clients released BEFORE the vote** (design §1.6, §1.7): from H the node refuses a
     generation-1 envelope at preflight (`DNA_ENV_PF_ERR_CTX_VERSION` — SYSTEM v6 ≠ v7, CORE
     v4 ≠ v5; CheckTx answers code **100**, "generation not in force", instead of 1), so a
     client that cannot build generation 2 stops working at H. In this tree: the 0.23.10
     `nodus-cli` asks the node (`dnac_ruleset_info`) and builds for the generation it names;
     the web wallet's WASM module still builds generation 1 only
     (`nodus_v2_ruleset_from_pins`, `web-wallet/crypto/nodus-send-wasm.c`); Nodus Connect and
     the explorer are not changed by HF-4. An older CLI reading the address history of an ID
     that registered a name fails closed on that page (new row kind `name`). Settle every
     client before the vote.
   - **Name-root cost** (design §2 "Cost"): FinalizeBlock time with 10^5 and 10^6 `v2_names`
     rows on the slowest validator, against the 4 s commit pace. Not measured anywhere yet;
     the harness scenario does not measure it.
   - **Pick `<H>` — asked of the operator** (never chosen by whoever runs the vote), with
     BOTH constraints, else the chain refuses the vote: `<H>` ≥ (the vote's block) + 720, the
     ERGONOMIC grace (decision item 17); and `(<H> − 1) mod 720 ≠ 0` — H−1 must not be an
     epoch boundary (rule (c), `DNAC_EPOCH_LENGTH` 720). Once committed, H can be neither
     moved nor voted again: param 9 is single use (rule (a)), and a far-future H retires it
     for good (decision item 15).
3. **Vote** with the HF-4 CLI (the value is parsed as DECIMAL — `strtoull(…, 10)` — while the
   log and `ruleset-info` print D2 in hex; `nodus-cli chain-config propose` run without
   `--value` prints the decimal it accepts):
   `nodus-cli chain-config propose --param RULESET_GEN2 --value 4962894749133920991 --effective <H>`
   The row must appear identically on 7/7 (`chain_config_history`: param_id 9, new_value
   4962894749133920991, same commit_block and tx_hash). Each seat's responder checks the
   scalar rule (exactly D2) and the stateful rules (no earlier param-9 row, HF-2 active, H−1
   not an epoch boundary); a refusal reads `stateful rules rejected`. The approval set is
   judged by the power rule (HF-2). Then **add the row to "Live hard forks" above in the same
   push**, read back from 7/7.
4. **Check** on every node with `nodus-cli -s <ip> ruleset-info`: before H it prints
   `generation=1` and `RULESET_GEN2 height H=<H>`; from H, `generation=2` (SYSTEM v7, CORE v5)
   and `this CLI carries it as compiled generation 2`; `node D2` equal to `this CLI D2` (else
   it prints `MISMATCH`). Each node logs once, at the end of H−1:
   `HF-4: rule-set generation 1 -> 2 at the end of height <H-1> (D2 0x44dfbe7ad3c75adf); height <H> is judged under generation 2`
   (tag `W_V2APPLY`).
5. **Between the vote and H** nothing changes on chain, but the HF-4 CLI caps a
   generation-1 envelope's expiry at H−1, and once H−1 is no longer above the tip it refuses
   to build at all ("retry after height H") — expect a short window around H in which
   `nodus-cli` builds nothing. **From H**: `nodus-cli name register <name> --keys <dir>
   --submit ip:port` works; the prices are params 10-13 (compiled defaults 1 000 / 500 / 100 /
   1 NODUS for 3 / 4 / 5 / 6+ characters, `dnac_fee_info` "np"), votable from H only, range
   [1, 10 000 000] NODUS, ERGONOMIC grace.
6. **Reverting** is another hard fork: generation 1 cannot be voted back. Accepted by the
   operator (decision item 15): any seat on the HF-4 binary can propose param 9 at an H the
   operator did not pick — today all 7 seats are the operator's.

**A node that missed the vote (still on the old binary when R committed):**
- Upgrading its binary and restarting does **NOT** recover it: the ABCI handshake at
  app == store == state height re-executes nothing, so the diverged state carries over
  (measured: stuck at R while the fleet advanced).
- Recovery = **wipe + genesis-pin rejoin on the new binary** (§1.5 "Joining a node to
  an existing V2 chain"): stop it; archive/remove its chain DB files, the markers and
  `archive/` (keep the identity directory); start the NEW binary with
  `--v2-genesis-pin <the fleet's pin>`; it re-derives the chain, including the vote's
  block under the new rules, and must match the fleet's `state_root` at a common height.
- **HF-4:** the same applies to a node on an old binary AND to a node on an HF-4 build whose
  D2 differs from the fleet's (both refuse the vote's item and diverge at the vote's block).
  The rejoining HF-4 binary seeds genesis from generation 1 (byte-identical to the
  pre-HF-4 genesis) and re-executes the generation switch at H−1 itself — its log carries the
  `rule-set generation 1 -> 2 at the end of height <H-1>` line again. Proven on localhost only
  by `test_cmt_hf4_names.sh` step 10, which is written but NOT yet run (stagef README).

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

## 2.4 WebSocket entry for browsers (web wallet / Web Connect) — per node, no chain impact

Decision: `docs/plans/decisions/2026-09-25-web-wallet-nodus-send-transport.md`.
Design: `docs/ARCHITECTURE.md` §10 "WebSocket entry". The entry touches no
consensus code; enabling it is a client-port change, so a rolling restart of one
node at a time is enough. **Deploying it, and installing Caddy on a node, needs the
operator's explicit permission like every deploy.**

**What runs where.** nodus listens with plain `ws` on `127.0.0.1:<ws_port>` ONLY
(there is no setting to change the address). Caddy on the same host terminates TLS
on 443 and forwards to it. The decision's port is `4005`; the decision gives
browsers `wss://<validator IP>:443` (no domain name).

**1. nodus config** — add to the node's `nodus.json`:

```json
{
    "ws_port": 4005,
    "ws_origins": ["https://wallet.nodusnetwork.io", "https://connect.nodusnetwork.io"]
}
```

`ws_origins` may be left out: the default is
`["https://wallet.nodusnetwork.io", "https://connect.nodusnetwork.io"]` (the
Connect site since 0.23.8, decision 2026-10-01-connect-own-origin). A node
that sets the list explicitly must name both, or the Connect site cannot
reach it.
A malformed `ws_port` (not an integer 0..65535) or `ws_origins` entry (not a
string, empty, containing a space or control character, over 255 bytes, more than
8 entries) refuses the start. A `ws_port` equal to `tcp_port`, `peer_port`,
`witness_port` or `ch_port` refuses the start.

**2. Caddy** — reverse proxy only. **Proven on EU-5, 2026-09-30** (Debian 13, Caddy
2.11.2 from `trixie-backports`; the `trixie` main package is 2.6.2 — not tried).
Caddy's default for a bare IP is a self-signed certificate
(caddyserver.com/docs/automatic-https: publicly-trusted certificates apply to
names that "are not an IP address"); a Let's Encrypt IP certificate needs the
`shortlived` ACME profile explicitly. `/etc/caddy/Caddyfile`:

```
{
	default_sni <node public IP>
}

https://<node public IP> {
	tls {
		issuer acme {
			profile shortlived
			disable_http_challenge
		}
	}
	reverse_proxy 127.0.0.1:4005
}
```

- `default_sni`: a client connecting to an IP sends no SNI.
- `disable_http_challenge`: port 80 stays closed; Let's Encrypt validated the IP
  over 443 with `tls-alpn-01` (observed: http-01 timed out behind ufw, tls-alpn-01
  succeeded). Only 443/tcp must be open (`ufw allow 443/tcp`).
- **Try against staging first** (`dir https://acme-staging-v02.api.letsencrypt.org/directory`
  inside `issuer acme`) — Let's Encrypt limits identical certificates to five per
  seven days. When switching to production, delete the staging certificate
  (`/var/lib/caddy/.local/share/caddy/certificates/acme-staging-v02.api.letsencrypt.org-directory`)
  and `systemctl restart caddy`; a reload alone kept serving the staging one.
- Result: issuer `Let's Encrypt YE2`, SAN `IP Address:<ip>`, valid ~6 days; Caddy renews.

nodus takes the LAST `X-Forwarded-For` value as the client's address (only because
the connection comes from 127.0.0.1); Caddy's `reverse_proxy` sets it — observed on
EU-5: `ws: upgrade ok slot=1 ip=<the testing machine's public IP>`. Do NOT put
another proxy in front of Caddy without re-reading this: the last value must be the
one Caddy wrote.

**Browser side — proven 2026-09-30 (web wallet 0.1.25+).** Headless Chromium 131 on
the live wallet opened `wss://164.68.116.180/`, the pinned tier-2 session came up
(server key verified, ML-KEM-1024 channel) and the NODUS balance was read. A plain
`curl` negotiates HTTP/2 and gets 400 (`Upgrade: websocket missing`); use
`curl --http1.1` for the remote check. The wallet server's nginx CSP header must
list every entry: `connect-src 'self' https: wss://<ip> …` (the page meta tag alone
is not enough — both policies apply).

**Where it runs (2026-09-30):** EU-5, US-1, EU-1, EU-2, EU-3, EU-4 — Caddy 2.11.2 from
`trixie-backports`, `ws_port` 4005, each with its own Let's Encrypt IP certificate
(the five later nodes went to production ACME directly; each IP is its own
certificate, so the identical-certificate limit is not shared). `nodus.conf` backup:
`/etc/nodus.conf.bak-pre-ws`. **EU-6 has no entry:** its 443 is nginx (websites and
the wallet); an entry there needs an nginx stream/location design, not Caddy.

**3. Verify on the node** (after restart):

```bash
journalctl -u nodus | grep 'WebSocket entry listening'     # 127.0.0.1:4005, 1 allowed origin(s)
ss -ltn | grep ':4005'                                     # must show 127.0.0.1:4005, never 0.0.0.0
curl -si -N --max-time 3 http://127.0.0.1:4005/ \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Origin: https://wallet.nodusnetwork.io' \
  -H 'X-Forwarded-For: 192.0.2.1' | head -5
# expect: HTTP/1.1 101 Switching Protocols
#         Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=   (RFC 6455 §1.3 vector)
```

Same request with `Origin: https://example.com` must answer `403`; without the
`X-Forwarded-For` line it must answer `400`. From another machine, the same request
against `https://<node IP>/` with `curl --http1.1` (without the `X-Forwarded-For`
line — Caddy adds it) must answer `101` (EU-5, 2026-09-30: 101, correct accept key), and the nodus log must show `ws: upgrade ok slot=… ip=<that
machine's public IP>`. If it instead shows `ws: upgrade refused … X-Forwarded-For
missing or malformed`, the header is not reaching nodus — stop and fix the proxy
(nodus refuses a loopback connection without it rather than count every browser
as the proxy's address).

**Capacity.** One node serves at most **256** browser (WebSocket) connections at
once, Upgrades in progress included; the remaining 768+ of the 1024 client slots
stay for app clients on 4001. A further browser connection is closed right after
accept and the log shows `ws: 256 WebSocket connections open, new connection
refused` — a node that prints this steadily is full, not broken. Per browser
address the limit is 20 connections; an IPv6 address is counted by its /64
(`ws: per-IP limit 20 reached for <ip>` names the address that hit it).

**Rollback:** remove `ws_port` (or set it to 0) and restart; the listener is not
opened and nothing else changes.

---

## 2.5 Block retention — pruned validators and archive nodes — per node, no chain impact

Decision: `docs/plans/decisions/2026-10-03-block-pruning-7-paydays.md` (operator: a
validator keeps the last 7 paydays; two archive nodes keep everything). Design:
`docs/ARCHITECTURE.md` "Block retention (pruning) and the SeenCommit cleanup". No
consensus byte, block, app_hash or state root depends on it, so nodes may differ and
no hard fork is involved; a rolling restart of one node at a time is enough. **Turning
it on on any node needs the operator's explicit permission like every deploy.**

**Two kinds of node.**

| Kind | `retain_blocks` | Keeps | Who (default; the operator may change) |
|---|---|---|---|
| Archive | `0` (or absent) | every block, every FinalizeBlock response | **EU-6 and US-1** |
| Pruned validator | `120960` (= 7 paydays × 17 280 blocks) | the last 120 960 blocks | every other node |

**1. Config** — add to the pruned node's `/etc/nodus.conf` (nodus.json format), and
make sure both archive nodes are in its witness-port `persistent_peers` (or in the
network file's list) so block sync always has a peer that holds old blocks:

```json
{
    "retain_blocks": 120960,
    "persistent_peers": ["<EU-6 p2p id>@<EU-6 ip>:4004", "<US-1 p2p id>@<US-1 ip>:4004", "..."]
}
```

A value that is not an integer ≥ 0 refuses the start at config load — the parser is
`load_config_json` in `tools/nodus_node_config.c` (:379-388, called at :526), the ONE
file every binary links (`nodus/CMakeLists.txt`: nodus-server, nodus-witness,
nodus-storage, nodus-core), so a malformed value refuses **nodus-core, nodus-storage,
nodus-witness and nodus-server alike**. A valid value is used only by the process that
runs the chain (nodus-server's in-process witness, or nodus-witness); nodus-core and
nodus-storage link no witness object and ignore it. A value from 1 up
to the chain's evidence window `max_age_num_blocks` (100 000 unless the genesis set
another) refuses the start too, with `retain_blocks <N> refused: it must be 0 (keep
every block) or greater than this chain's evidence window …`. At start a pruned node
logs `block retention: the last <N> blocks are kept (evidence window <M> blocks)`.

**2. What happens.** Nothing until the chain is taller than N. From then on every
Commit prunes the blocks below `tip − N + 1`: their parts, their FinalizeBlock
responses and their seen commits. Block meta and commits stay until the evidence
window has passed. The FIRST commit after enabling it on a node with long history
walks every height from genesis up to `tip − N + 1` in one go (flushed every 1 000
heights) — expect one slow block on that node. A prune error is logged
(`failed to prune blocks: retain_height …`) and does not stop the node.

**Exception: block 1's header row (`H:1`) is never pruned** (decision item 5). Every
start runs a check (the V2 preflight) that compares the genesis document with block 1's
header; without that row a pruned node would, after its next restart, refuse every
transaction submitted to it (V2 ingress stays closed). So the node keeps that one row
forever; everything else of block 1 is pruned as usual, and block 1 is not served to
anyone (block sync answers "no block"). This is a deliberate deviation from cometbft's
pruning; the design note is in `docs/ARCHITECTURE.md`.

**Rollout order (decision item 5).** Enable pruning on **EU-5 first**. Let its chain
pass height **120 961** (the first height at which `tip − 120 960 + 1` is above 1, so
the first real prune has run), then **restart EU-5** and check that it still admits
transactions (submit one through EU-5 and see it accepted; the start log must not say
`Ledger V2 NOT ACTIVATED` or `Ledger V2 ingress remains CLOSED`). Only then enable it on
the other pruned nodes, one at a time.

**3. Consequences — read before choosing which nodes prune.**
- **Joining / catching up needs an archive peer.** Block sync skips a peer whose
  lowest stored block (its base) is above the height the joiner needs; consensus
  catch-up cannot serve a block that is gone. A joiner whose only peers are pruned
  nodes, and who is further behind than N blocks, never catches up. Keep the archive
  nodes in every node's persistent peers, and keep them running.
- **Scan / the explorer must read from an archive node.** A pruned node no longer
  has old blocks or old FinalizeBlock responses (per-transaction results); history
  queries against it for heights below its base find nothing.
- **Disk does not shrink by itself.** SQLite reuses the freed pages for new blocks,
  so the file stops growing at roughly the retained size; it gets SMALLER only after
  `VACUUM` on the chain database with the node stopped (needs free space about the
  size of the file). Whether and when to vacuum is an operator decision.
- **SeenCommit cleanup runs on EVERY node, archive included** (independent of
  `retain_blocks`): each new block deletes the previous height's seen commit. Rows
  written before the build that carries it stay until that height is pruned (never,
  on an archive node).

**Rollback:** remove `retain_blocks` (or set it to 0) and restart. That only **stops
further pruning**; it does **not** restore any row already pruned — the node stays
based at the height it last pruned to. There is no in-place way to restore full history
on that node; history is read from the archive nodes.

**Harness proof (decision item 4, "no hard fork"):** `tests/integration/stagef/tests/test_cmt_prune.sh`
(not in the sweep; its own bring-up with `STAGEF_EVIDENCE_MAX_AGE_BLOCKS` /
`STAGEF_EVIDENCE_MAX_AGE_DURATION_NS`, stagef README) — two pruned and five archive nodes,
7/7 agreement, the start floor, kill -9 of a pruned node, a pin rejoin that block-syncs
from height 1, and that a restarted pruned node still admits transactions. Expected PASS
on f8ecb5ac and later (decision item 5: block 1's meta `H:1` is never pruned, because the
Ledger V2 preflight reads it at every open, `nodus_witness_v2_preflight.c:334-349`); on
605b748b, which pruned it, a restarted pruned node logged `Ledger V2 NOT ACTIVATED …
INSPECTION_FAULT` and refused transactions (measured).

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
   Three-process host: `sudo systemctl stop nodus-core nodus-storage nodus-witness`
   and check all three are inactive (stopping core alone leaves the witness voting).
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
