# Running a storage node

A **storage node** keeps a copy of the Nodus chain's block archive and is paid for it from
the Storage pool. Anyone can run one. You need a Linux server that stays online, and a
wallet holding the bond of **1 000 000 NODUS** plus a small fee. The bond is not spent:
you get it back when you leave.

The role has been live on the testnet chain since block **176100** (2026-10-13). This page
takes you from an empty machine to a registered node. The full mechanism — probes, segments,
grace, settlement — is in [`DEPLOY_RUNBOOK.md` §2.6](DEPLOY_RUNBOOK.md); this page links to
it wherever a detail matters.

> **Two words that look alike.** The `nodus-storage` *program* is the DHT half of a node. It
> is **not** what makes a storage node. The storage-node role is held by the process that
> keeps the chain (`nodus-witness` in the layout below). You install all three programs
> anyway.

## How it works, in five lines

1. Your node syncs the whole chain and keeps it (it never prunes).
2. You — the **owner** — register the node with your wallet. The wallet pays the bond and
   later receives the rewards. The node itself only signs a *consent*: "I agree to be
   registered under this wallet".
3. The archive is cut into **segments** of 17 280 blocks (one payday period). Every segment
   is held by 3 storage nodes, chosen by the chain.
4. Every epoch (720 blocks) the witnesses ask each storage node for a few random pieces of
   its segments. A node that answers is OK for that epoch.
5. You are paid in proportion to the blocks you hold, from the Storage pool. Rewards accrue to
   the owner wallet and are paid on paydays.

## 1. What you need

| | |
|---|---|
| Machine | Linux, x86-64. The CPU must have **AVX, BMI2 and ADX** — the node runs a self-test of the EVM precompiles at start and refuses to start without them. |
| Disk | The whole chain plus the segment files you are given. The chain database was about **10 GB** in mid-October 2026 and grows with every block; one segment file is estimated at ≈ 1.7 GB. Leave plenty of room — 50 GB free is a sensible start (a recommendation, not a measured limit). |
| Network | A public IP that stays the same. **TCP 4004** must be reachable from the internet: the witnesses talk to your node on that port. |
| Clock | NTP must be on (`timedatectl` shows `System clock synchronized: yes`). A witness's question carries a deadline 10 s ahead; a node whose clock is off by a few seconds starts missing answers. |
| Wallet | A Nodus wallet with **1 000 000 NODUS + the fee** (≈ 0.5 NODUS at today's gas price). [Nodus Connect](https://connect.nodusnetwork.io) does the registration for you. |

## 2. Build the programs

Install the build tools (Debian / Ubuntu package names):

```bash
sudo apt install git cmake build-essential pkg-config \
    libssl-dev libsqlite3-dev libjson-c-dev m4 xz-utils xxd
```

Get the source and build a **Release** build:

```bash
git clone https://github.com/nocdem/dna.git
cd dna/nodus
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

The `main` branch carries every hard fork the network has voted. A rule that is not voted yet
stays switched off in the binary until its vote, so a newer build is safe to run.

Package the build and keep the package for the install step:

```bash
cd ..                                   # back in dna/nodus
deploy/make-dist.sh build ~/nodus-dist  # prints the file name and its SHA-256
```

## 3. Write the configuration

Two files. First the **network file** — the chain you join and the seven witnesses you connect
to. Save it as `/etc/nodus-network.json`:

```json
{
  "v2_genesis_pin": "a48d1a785500a1cdecd739ecd53ef0e95b1dc4a7a300f49176a7fa25ae176114",
  "persistent_peers": [
    "fd429639366cbc41d98db7603d51166ed5542d2d161cf69ff1ab6dbe80176197@161.97.85.25:4004",
    "16af3eaa620ab5d239ca63abd01943c7b1a8580a3c0204ec8a093bf7992c79df@156.67.24.125:4004",
    "04cdf00b3c37782b7df02fc0f71ba3b74893a60cbb800369d9ee6e97c46dd3ed@156.67.25.251:4004",
    "681c12a60cae6956d1c7a1b8c75b08594961888e0d8319882fee4c94ce77b55f@164.68.105.227:4004",
    "a7b23e52f02af2d2f526d58c741bb405825af8e31d753dc670b9c94cc01d2401@164.68.116.180:4004",
    "6573f74c177c9d97ba784e9607b487125f973f71026931e522051d9ba6fe713a@75.119.141.51:4004",
    "03499d1fae35f9e9aaf60a1c3f18d8c7d1ffa49f2c65bd4b6a531bdf8ef92c21@154.38.182.161:4004"
  ]
}
```

- `v2_genesis_pin` is the testnet chain id (Scan shows the same value). On the first start your
  node downloads the chain's genesis from the peers and accepts it only if it matches this id.
- Each peer is `<p2p id>@<ip>:4004`. The list was read from the chain on 2026-10-14. To read the
  current list yourself, from any node:
  `nodus-cli -s 161.97.85.25 -p 4001 witness` — it prints each witness's `p2p id` and `address`.

Then the **node configuration**, `/etc/nodus.conf` (replace `203.0.113.10` with your server's
public IP):

```json
{
  "bind_ip": "0.0.0.0",
  "external_ip": "203.0.113.10",
  "udp_port": 4000,
  "tcp_port": 4001,
  "peer_port": 4002,
  "witness_port": 4004,
  "identity_path": "/var/lib/nodus/identity",
  "data_path": "/var/lib/nodus/data",
  "network_file": "/etc/nodus-network.json"
}
```

Do **not** add `retain_blocks`. A storage node keeps every block until its segment files are
complete; pruning early makes it fail its checks ([runbook §2.6](DEPLOY_RUNBOOK.md) step 1a).

## 4. Install and start

```bash
cd ~/nodus-dist
tar -xzf nodus-*-linux-*.tar.gz && cd nodus-*-linux-*/
sudo ./install.sh --layout split --dry-run   # shows the plan, changes nothing
sudo ./install.sh --layout split
```

The installer reads `/etc/nodus.conf` from step 3 and never overwrites it. Run it inside
`tmux` or `screen` if you are connected over SSH, so a dropped connection cannot interrupt it.

The installer checks the package, installs the five programs to `/usr/local/bin` and starts
three services: `nodus-core`, `nodus-storage`, `nodus-witness`. On the first start `nodus-core`
creates the node's key in `/var/lib/nodus/identity`. **Back up that directory** — it is your
node's identity; a lost key cannot be replaced (a new key is a new node that registers again).

Check that it runs:

```bash
systemctl status nodus-core nodus-storage nodus-witness
journalctl -u nodus-witness -n 50     # look for "cometbft lane LIVE"
```

## 5. Wait until the node has caught up

The node now downloads the whole chain from the witnesses. This takes a while. Compare its
height with the chain's:

```bash
nodus-cli -s 127.0.0.1 ruleset-info      # first line: tip=<height> generation=4
```

and the latest block on [scan.nodusnetwork.io](https://scan.nodusnetwork.io). Register only
when the two are close (a few blocks apart).

## 6. Register the node (Nodus Connect)

1. Open [Nodus Connect](https://connect.nodusnetwork.io) with the wallet that will own the
   node. Go to **More → Nodus → Become a storage node**.
2. The page shows a command. **Change one thing before you run it**: the page writes
   `-i ~/.nodus`. Your node's key is in `/var/lib/nodus/identity`, so on the node run:

   ```bash
   sudo nodus-cli -i /var/lib/nodus/identity -s 127.0.0.1 storage consent \
       --owner <the owner shown by the page> --expiry <the block shown by the page>
   ```

   It prints a consent beginning `nodus-valbind-consent v1`. The consent contains no secret.
3. Paste the consent into the page. The page checks it and shows your node's fingerprint;
   compare it with `sudo nodus-cli -i /var/lib/nodus/identity whoami` on the node — it must
   be the same. If it is not, cancel.
4. Review and confirm. The wallet locks the bond (exactly 1 000 000 NODUS) and pays the fee.

The consent is valid only until the block it names (at most 720 blocks ahead), so do the
steps in one go. If it expires, run the command again for a fresh one.

**Without the web page** (a command line wallet, or a multisig owner): the same three steps
with `nodus-cli storage consent | register` — [runbook §2.6](DEPLOY_RUNBOOK.md) step 4.

## 7. After registration

```bash
sudo nodus-cli -i /var/lib/nodus/identity -s 127.0.0.1 storage status
```

shows your row: status, bond, owner, `fail_streak`, and whether the node is in the storage set
this epoch.

- **The first epoch boundary.** The node joins the storage set at the next epoch boundary
  (every 720 blocks, about an hour).
- **The grace period — no pay for a while.** A new node is given older segments it must fetch
  from other nodes. It gets one epoch per such segment to do that, and earns nothing until the
  grace is over (`storage status` says `IN GRACE` and how many epochs are left). Six segments
  ≈ six hours. Keep the node running: it fetches the files during this time.
- **Earning.** After the grace, each good epoch counts. Rewards accrue to the owner and are
  paid on paydays (every 17 280 blocks).
- **When something is wrong.** A failed epoch raises `fail_streak`. After 3 failed epochs in a
  row the node is skipped; it comes back by itself after 12 epochs, or at once after a good
  epoch. Usual causes: TCP 4004 not reachable, the node not connected to the witnesses, the
  clock off, or the node behind the chain.

## 8. Leaving

In Nodus Connect: **More → Nodus**, or `nodus-cli storage exit` ([runbook §2.6](DEPLOY_RUNBOOK.md)).
The owner signs and pays only the fee. The node leaves the storage set at the next epoch
boundary; the bond comes back to the owner as one coin, locked for 12 epochs.

**Stopping the machine is not leaving.** The bond stays locked and the node fails its checks
until it is skipped. Always leave first, then shut down.

## Good to know

- One machine can be a witness and a storage node at the same time; each role has its own
  owner and its own pay.
- A storage node registered under the **same owner** as the witnesses that check it gets no
  credit from them (a witness cannot vouch for itself). This matters only if you also run
  witnesses.
- The node must keep TCP 4004 open and stay connected: the witnesses' checks and the segment
  downloads both travel on 4004. The other ports (4000-4002) serve the DHT and clients; the
  storage role does not need them reachable from the internet (`nodus-cli` on the node itself
  uses 4001 on `127.0.0.1`).
