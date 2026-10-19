# Nodus — Post-Quantum DHT and Chain Node

<p align="center">
  <strong>Pure C Kademlia DHT and Nodus Chain validator — Dilithium5 signatures, ML-KEM-1024 / Kyber1024 key exchange</strong>
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/License-Apache%202.0-blue" alt="Apache 2.0"></a>
  <a href="#witness-system-nodus-chain"><img src="https://img.shields.io/badge/Status-Testnet%20v0.24.1-orange" alt="Testnet"></a>
  <a href="#channel-encryption-kyber-round-3--ml-kem-1024"><img src="https://img.shields.io/badge/Crypto-Post--quantum-red" alt="Post-quantum cryptography"></a>
</p>

---

## What is Nodus?

`nodus-server` is the one server of the Nodus network. Every node is two things at once: the distributed hash table (DHT) that stores, replicates and pushes signed records, and a validator of **Nodus Chain** — the post-quantum UTXO chain whose coin is NODUS (public testnet since 30 September 2026). The DHT is open — anyone can run a Nodus node and join; becoming a chain validator takes a self-stake of exactly 10M NODUS.

- **C** — written in C. One exception: the standalone non-Windows build (`cd nodus/build && cmake ..`) compiles the Nodus EVM engine, whose bn254 precompiles use the vendored C++ library mcl behind its C API, so `nodus-server` links `libstdc++` (`nodus/CMakeLists.txt`, `NODUS_EVM_ENABLED`). The messenger tree's libnodus and a Windows build stay C-only and carry no EVM
- **Dilithium5 signatures** — All stored values cryptographically signed using the ML-DSA-87 algorithm profile; no validation or certification claim
- **ML-KEM-1024 / Kyber round-3 channel encryption** — All client connections encrypted (AES-256-GCM after a KEM key exchange). A node uses ML-KEM-1024 (FIPS 203) whenever its peer advertises a signed ML-KEM key and falls back to Kyber round-3 otherwise. This two-path state is permanent: no forced update removes the Kyber path (decision `2026-09-23-kem-mlkem-migration.md`, K1 rev 2) — see `shared/crypto/enc/qgp_kyber.h` (legacy) and `shared/crypto/enc/qgp_mlkem.h` (FIPS 203).
- **Cluster management** — Heartbeat-based health monitoring with Kademlia replication
- **512-bit keyspace** — Kademlia routing with k=8 buckets
- **7-day TTL** — Values persist across restarts with SQLite storage
- **CBOR wire format** — Efficient binary serialization
- **Embedded Nodus Chain validator** — a literal C port of CometBFT v0.38.26 drives the Ledger V2 engine
- **Circuit relay** — Peer-to-peer VPN mesh with optional per-circuit E2E encryption; it is not onion-routed
- **Media storage and replication** — Binary blob storage with cluster-wide replication
- **Multi-token support** — Custom token creation (`TOKEN_CREATE`) on Nodus Chain
- **Nodus EVM (HF-5, 0.24.0)** — smart contracts as the chain's third domain, inactive until the `EVM_ACTIVE` vote (see "Nodus EVM" below)
- **Browser entry** — an optional WebSocket listener for the web wallet, off by default

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                           nodus-server                               │
├──────────┬──────────┬──────────┬───────────────────┬─────────────────┤
│ UDP 4000 │ TCP 4001 │ TCP 4002 │ TCP 4004          │ ws_port         │
│ Kademlia │ Client   │ Inter-   │ Chain p2p         │ WebSocket       │
│          │          │ node     │ (CometBFT port)   │ (127.0.0.1,     │
│ ping     │ auth     │ repl.    │ secret conn.      │  off by         │
│ find_node│ dht_put  │ heartbt  │  ML-KEM-1024      │  default)       │
│ store    │ dht_get  │ circuit  │ consensus,        │ same verbs as   │
│ find_val │ get_batch│ fwd      │ mempool, block-   │ TCP 4001        │
│          │ cnt_batch│          │ sync, PEX         │                 │
│          │ listen   │          │ reactors          │                 │
│          │ presence │          │                   │                 │
│          │ circuits │          │                   │                 │
│          │ media    │          │                   │                 │
│          │ dnac_*   │          │                   │                 │
├──────────┴──────────┴──────────┼───────────────────┴─────────────────┤
│  KEM + AES-256-GCM on 4001/4002│  Nodus Chain validator              │
├─────────────────────┬──────────┴──────────┬──────────────────────────┤
│  Kademlia Routing   │  Cluster Management │  Ledger V2 engine        │
│  512-bit keyspace   │  Heartbeat health   │  CometBFT v0.38.26 port  │
│  k=8 buckets        │  K-closest repl.    │  (shared/dnac/cmt_*)     │
├─────────────────────┼─────────────────────┼──────────────────────────┤
│  SQLite Storage     │  Presence Table     │  Media Storage           │
│  7-day TTL          │  45s TTL, p_sync 30s│  Binary blobs            │
└─────────────────────┴─────────────────────┴──────────────────────────┘
```

**Network ports:**

| Port | Protocol | Purpose |
|------|----------|---------|
| UDP 4000 | Kademlia | Peer discovery (ping, find_node, store, find_value) |
| TCP 4001 | Client | Auth, dht_put, dht_get, get_batch, cnt_batch, listen, presence, circuits, media, and the chain RPCs (`dnac_*`) |
| TCP 4002 | Inter-node | Cluster replication, heartbeat, circuit forwarding |
| TCP 4004 | Chain p2p | The ported CometBFT p2p layer: secret connection (ML-KEM-1024 + AES-256-GCM), consensus / mempool / block-sync / PEX reactors |
| `ws_port` (e.g. 4005) | WebSocket | Optional browser entry to the client protocol; listens on `127.0.0.1` only, a local TLS proxy serves it (see "Configuration") |

TCP 4003 is the planned RELAY port of the bandwidth role (`docs/plans/decisions/2026-10-16-relay-port-4003-bandwidth-role.md`, approved 2026-10-16). It is not opened yet: no relay code exists, the constant still carries its old name and meaning (`NODUS_DEFAULT_CH_PORT`, "Channel client TCP port", `nodus_types.h:107`), and the old channel server stays compiled out (`NODUS_CHANNELS_DISABLED`, `nodus/CMakeLists.txt:1095`) until the bandwidth design lands.

**Windows:** the transport's plain TCP listener (`nodus_tcp_listen`) builds and runs on Windows over a `select()` loop with the same pool cap, per-IP limit, frame cap and read budget as Linux; the WebSocket entry (`nodus_tcp_ws_listen`) and the Unix socket entry (`nodus_tcp_unix_listen` / `_unix_connect`) are Linux-only (`src/transport/nodus_tcp.h:1-10`). The server and witness sources themselves are still Linux-only (`nodus/CMakeLists.txt:588-589`), so there is no Windows server yet.

**Wire Protocol:** CBOR over framed TCP/UDP on 4000-4002 — 7-byte header (magic `0x4E44` + version + length). Port 4004 does not use these frames; it speaks the ported CometBFT p2p protocol with its own protocol version.

---

## Source Layout

```
nodus/
├── src/
│   ├── server/      # Server event loop (epoll), nodus_server.c — core: auth, sessions, presence,
│   │                #   circuits, 4002 handshake, cluster heartbeat; the DHT backend door (split S4)
│   ├── dht/         # The DHT / storage half: nodus_dht.h (state + seam), nodus_dht_server.c
│   │                #   (DHT handlers, lookups, replication, republish), nodus_dht_media.c (split S4)
│   ├── client/      # Client SDK, nodus_client.c
│   ├── protocol/    # Wire protocol, Tier 1 + Tier 2 dispatch
│   ├── core/        # Kademlia routing, storage
│   ├── transport/   # UDP/TCP transport
│   ├── channel/     # Channel/subscription system
│   ├── consensus/   # Cluster heartbeat + membership management
│   ├── crypto/      # Nodus-specific crypto helpers
│   ├── circuit/     # Circuit relay for P2P VPN mesh (optional per-circuit E2E encryption)
│   └── witness/     # Nodus Chain validator: Ledger V2 engine + CometBFT host (one lane) — embedded in
│                    #   nodus-server by default, or the separate nodus-witness process (opt-in, split S3)
├── include/
│   └── nodus/
│       ├── nodus.h       # Client SDK public API
│       └── nodus_types.h # Constants, version
├── tools/               # nodus-server.c, nodus-witness.c, nodus_node_config.c (shared options/config), nodus-cli, …
└── tests/               # Unit + integration tests
```

---

## Build

```bash
cd nodus/build
cmake ..
make -j$(nproc)
```

Produces:
- `nodus-server` — the combined node binary (DHT + the in-process chain witness; with `witness_external` / `storage_external` it leaves that half to `nodus-witness` / `nodus-storage`)
- `nodus-core` — the core of a three-process node (component split S6): UDP 4000, client TCP 4001, the 4002 listener, cluster, presence, circuits, the partial-wipe gate, identity creation; reaches `nodus-storage` and `nodus-witness` over Unix sockets only. Refuses to start unless both `storage_external` and `witness_external` are set; no `--derive-v2-genesis`.
- `nodus-storage` — the DHT / storage half (`nodus.db`, `channels.db`, routing, replication) as its own process (component split S5b); refuses to start unless `storage_external` is set. Not to be confused with a **storage node** of the archive reward: that role is held by the process that keeps the chain (`nodus-witness`, or `nodus-server`) — see "Storage reward" below and `docs/STORAGE_NODE.md`.
- `nodus-witness` — the chain witness (4004 p2p + consensus) as its own process (component split S3); refuses to start unless the config sets `witness_external`.
- Same options and config file for all four. The three-process layout is the one all seven live nodes run since 2026-10-09 (`docs/DEPLOY_RUNBOOK.md` "Three-process node", with its two open items); the combined `nodus-server` stays for rollback. Systemd units for both are in `deploy/`. See `docs/ARCHITECTURE.md` §10 "Component split".
- `nodus-cli` — CLI tool for testing and chain operations
- `nodus-circ` — circuit relay test tool
- `nodus-light` — the light client program (Linux and Windows): follows the chain over pinned 4001 sessions without executing blocks; `nodus-light run --data <dir> --trust-height <H> --trust-hash <128 hex>` on a first run (this build carries no default checkpoint), `status`, `clear-attack`. See `docs/ARCHITECTURE.md` "nodus-light — the light client program"
- `test_*` — Unit test binaries

### Windows (nodus-light only)

A Windows cross build (llvm-mingw) generates only the `nodus` library and
`nodus-light.exe` (linked `-static`, so it imports only Windows system DLLs); the
server, witness, storage, core, `nodus-cli`, tests and fuzz targets are Linux-only
and are not generated. The sysroot (`<llvm-mingw>/x86_64-w64-mingw32`) must already
hold cross-built OpenSSL, SQLite3 and json-c; `PKG_CONFIG_LIBDIR` points the host
`pkg-config` at the sysroot's `json-c.pc`:

```bash
PKG_CONFIG_LIBDIR=<sysroot>/lib/pkgconfig:<sysroot>/lib64/pkgconfig PKG_CONFIG_PATH= \
cmake -S nodus -B nodus/build-win \
  -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_SYSTEM_PROCESSOR=x86_64 \
  -DCMAKE_C_COMPILER=<llvm-mingw>/bin/x86_64-w64-mingw32-clang \
  -DCMAKE_RC_COMPILER=<llvm-mingw>/bin/x86_64-w64-mingw32-windres \
  -DCMAKE_FIND_ROOT_PATH=<sysroot> \
  -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER \
  -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
  -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY \
  -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY \
  -DOPENSSL_ROOT_DIR=<sysroot>
cmake --build nodus/build-win -j$(nproc)
```

Built with llvm-mingw 20251118; the `.exe` has not yet been run on Windows.

### `nodus-cli` chain commands (version-3 chain)

`nodus-cli -h` prints the full list (DHT verbs included). The envelope and
claim builders — every one answers with the mempool **CheckTx** verdict
(`accepted: mempool CheckTx approved ...`), never a commit; inclusion is
read from the chain:

| Command | What it builds |
|---|---|
| `v2-claim --config <conf> --db <db> --keys <dir> (--dry-run \| --submit ip:port)` | GENESIS_CLAIM of every genesis leaf bound to the key, one session |
| `v2-envelope stake --db <db> --keys <dir> --bond <raw> --commission <bps> --dest-fp <hex128> (--dry-run \| --submit ip:port)` | two-leg SYSTEM STAKE + CORE SYSFUND. Declares 400 000 units; with `--submit` it opens the session first, reads `gas_price` from `dnac_fee_info` and pays `max(floor, 400 000 × gas_price)` (HF-1, 0.19.80); `--dry-run` cannot know the price and says so. |
| `v2-envelope spend --keys <dir> --to <fp128hex> --amount <raw> [--fee <raw>] [--token <hex128>] [--count <N>] [--submit ip:port] [--dry-run]` | single-leg CORE SPEND — a coin transfer. Networked end to end on ONE session authenticated as the sender: chain id from `dnac_supply`, the sender's coins from `dnac_utxo` (unlocked only, largest first, ties by nullifier), CORE ruleset from the binary's compiled table — since 0.23.10 (HF-4) for the rule-set generation the node names in `dnac_ruleset_info` (every networked builder does this; an older node or a generation this CLI does not carry → nothing is built), with the expiry capped at H−1 for a generation-1 envelope while a `RULESET_GEN2` height H is committed. Fee defaults to `max(the chain floor 1 000 000 raw, units × gas_price)` — `gas_price` read from `dnac_fee_info` on the same session, the fee found by a bounded fixed-point over the plan's own units (HF-1, 0.19.80); an explicit `--fee` below that is refused, never raised; change returns to the sender; `--count N` submits N independent spends with disjoint inputs. `res_max_total_units` is right-sized per envelope (the block reserves every envelope's full ceiling at once, so the ceiling sets how many fit one block — ≈ 41 one-input spends). Prints `intent_id=` per envelope — the `tx_hash` of the UTXOs it creates. Refuses insufficient funds, more than 15 inputs, amount 0, a fee below the floor. `--dry-run` still needs the node (it lists the coins) and submits nothing. |
| `v2-envelope token-create --keys <dir> --name <n> --symbol <s> --decimals <0..18> --supply <raw> [--to <fp128hex>] [--fee <raw>] [--token-id <hex128>] (--dry-run \| --submit ip:port)` | single-leg CORE TOKEN_CREATE (runtime_op 3) — registers a new token and mints its whole supply as ONE output to `--to` (default the `--keys` identity; that owner is also the registry's `creator_fp`). Same one-session flow as `spend`. Refuses before connecting what the chain refuses (`nodus_witness_rt_native.c` `rtn_tc_parse` / `rtn_tc_exec`): name 1..32 and symbol 1..8 printable ASCII without `:`, decimals 0..18, supply 1..INT64_MAX, an all-zero token id. Inputs are the creator's unlocked NATIVE coins only (largest first, at most 14); the fee is `NODUS_W_TOKEN_CREATE_FEE` (10^15 raw, a compiled constant until the governance parameter lands — decision `2026-09-28-token-create-fee-governance`), raised to `units × gas_price` when the node reports a price above it, and credited to the reward pool by the chain; native change returns to the creator. The leg declares the exact effects it emits (`in + out + 2`, `452 + 148·in + 432·out` bytes) and a right-sized `res_max_total_units` (reads `in + 2`). `--token-id` defaults to 64 fresh random bytes; an id already registered is refused by the chain. Prints `token_id=` (use it with `spend --token`) and `intent_id=` (the `tx_hash` of the UTXOs it creates). |
| `-i <node identity dir> validator consent --op stake (--owner <owner_fp hex128> \| --msig <descriptor>) --expiry <height> [--out <file>]`; `-i <node identity dir> storage consent (--owner <hex128> \| --msig <descriptor>) --expiry <height> [--out <file>]` | (HF-6, rule-set generation 4 — in force from block 176100) the NODE's consent (design `2026-10-03-hf5-validator-owner-stake` rev 6 §6.1): the `-i` identity — the node's consensus key — signs, with ML-DSA-87 and ctx `nodus.valbind.v1`, the 2765-byte message `dna_valbind_consent_msg` builds (version 1, the chain id, op 1 STAKE / op 3 STORAGE_REGISTER, subject = 64 zero bytes, the owner, its own key, `--expiry`). `-i` is required. `--op rotate` and `--subject` are gone: HF-6 has no key rotation (`docs/DEPLOY_RUNBOOK.md` §2.7). The chain id (`dnac_supply` `chain_id32`) and the tip (`dnac_ruleset_info`) come from the `-s` node; a consent the chain could not accept at tip + 1 (`expiry ≥ h` and `expiry − h ≤ 720`) is not signed. Output: the consent file — text lines `nodus-valbind-consent v1`, `op`, `chain_id`, `subject`, `owner`, `consensus_pk`, `expiry`, `sig` (lowercase hex, `src/client/nodus_v2_stake.h` `NODUS_V2_CONSENT_MAGIC`) — to `--out`, or to stdout without it; with `--out` it also prints `consensus_pk=`, `sig=` and the expiry. No secret is printed. |
| `consent <code> [--config <file>] [--yes]` | (decision `2026-10-14-consent-request-code`) the same consent, from the one-line request code Nodus Connect shows: `nodus-consent-v1:<storage\|witness>:<owner hex128>:<expiry>:<chain id hex64>` (lowercase hex, expiry decimal without leading zero, nothing else — any other form is refused; `src/client/nodus_consent_req.c`). Run on the node as `sudo nodus-cli consent <code>`: the key directory is `-i`, else `identity_path` in `--config` (default `/etc/nodus.conf`), loaded read-only; the node is `-s`, else `127.0.0.1`, on `-p` / `-s host:port`, else the config's `tcp_port`, else 4001. Before signing it prints on stderr the role, owner, valid-until block, chain id and this node's fingerprint and asks `Sign this consent? [y/N]` (only `y` / `yes`; `--yes` skips the question). Then it runs the `storage consent` (role `storage`, op 3) or `validator consent --op stake` (role `witness`, op 1) path with `--chain-id` = the code's chain id: a node on another chain signs nothing. stdout carries only the consent text, to paste back into Connect. The `storage consent` / `validator consent` commands are unchanged. |
| `status [--config <file>]` | READ-ONLY, run on the node as `sudo nodus-cli status`: the whole node on one screen, in sections. The node is found like `consent` (`-i` / `-s` / `-p` override the config, default `/etc/nodus.conf`; the key is loaded read-only, only for its fingerprint and public key). Every session — to this node and to the witnesses — authenticates with a throwaway identity generated for the run, never with the node key: a tier-2 auth registers presence for its fingerprint on the node it reaches (`src/server/nodus_auth.c`), and none of the RPCs used is bound to the session. **Node**: this CLI's version, `/var/lib/nodus/install-commit`, fingerprint, P2P ID. **Services**: `systemctl is-active` / `is-enabled` of `nodus-core`, `nodus-storage`, `nodus-witness` (and `nodus` when enabled). **Chain**: this node's tip and rule-set generation (`dnac_ruleset_info`), its chain id (`dnac_supply` `chain_id32`), nodus-core's uptime, DHT cluster peers and clock (tier-2 `status`); the network height = the highest tip of the first 3 witnesses of the config's `network_file` that answer (each asked on port 4001, 3 s connect / 4 s request), `behind by` OK at ≤ 2 blocks; chain id OK when this node = the network file's `v2_genesis_pin` = every answering witness. **Roles**: the storage registry row of this node's fingerprint (`dnac_storage_status`: status, bond, owner, `fail_streak` — WARN above 0 —, `grace_until`, the frozen storage set, eligible segments) and whether its key is in the committee for the next block (`dnac_committee`); "not registered" is a normal answer. **Resources**: free / total on `data_path` (WARN under 20 GiB), the chain database (`witness_<id>.db` + `-wal` / `-shm`), the segment directory (`seg-<k>.ok` count, bytes), load average and CPUs, memory, resident memory of the nodus processes. **Clock**: `timedatectl` NTP synchronized (WARN on `no`). **Config**: `external_ip`, ports, `data_path`, `network_file`, `retain_blocks` (information only). A value it cannot read prints as `unknown (<reason>)`; exit 0 whenever the screen was printed, 1 for bad arguments or an unreadable config. The library's own log lines are not shown (stderr is silenced while it runs). Helpers: `src/client/nodus_node_status.c` (test `test_node_status`). |
| `v2-envelope stake2 --keys <owner dir> --consent <file> --bond <raw> [--commission <bps>] (--dry-run \| --submit ip:port)` | (HF-6) the generation-4 STAKE (7301-byte call `owner_fp ‖ consensus_pk ‖ consent_sig ‖ expiry ‖ commission ‖ bond`) + CORE SYSFUND locking the bond. The `--keys` identity is the OWNER: owner_fp = SHA3-512 of its key (kind 1), it signs both legs and its coins pay bond + fee. Before building, the consent is re-checked on the session: op STAKE, this node's chain id, owner = the `--keys` identity, the signature over the rebuilt message, the expiry window at tip + 1. Commission defaults to 0 (≤ `DNAC_COMMISSION_BPS_MAX`); bond 1..INT64_MAX (a bond below this build's STAKE_MIN — 2 000 000 NODUS — is warned about, the chain refuses it). Prints `validator_id=` — `SHA3-512("NDS.VALID.v1" ‖ chain id ‖ intent_id)` of THIS envelope (a dry run's can differ from the submitted one's: the expiry is tip-relative). Refused below generation 4. A multisig (kind-3) owner: `--msig <descriptor> --in <nullifier>:<amount> … --export <file>` in place of a signing owner, then `msig sign` / `msig combine` (`docs/DEPLOY_RUNBOOK.md` §2.6 "Multisig owner") — the same for every generation-4 owner verb. Under generation 4 the legacy `stake` is refused (use `stake2`); `delegate`, `undelegate` and `unstake` take the generation-4 form below. |
| `v2-envelope delegate\|undelegate --keys <dir> --validator <validator_id hex128 \| hex5184 pubkey> --amount <raw> (--dry-run \| --submit ip:port)` | two-leg SYSTEM DELEGATE (op 2) / UNDELEGATE (op 4) + CORE SYSFUND. The `--keys` identity is the delegator: it signs both legs and its coins pay (DELEGATE: amount + fee; UNDELEGATE: the fee only — the chain returns the amount as a coin locked 12 epochs). The node's rule-set generation decides the form: below generation 4 `--validator` is the validator's public key (5184 hex) and the call is `delegator_pk ‖ validator_pk ‖ amount` (5192 B); at generation 4 (HF-6) it is the validator_id (128 hex) and the call is `SHA3-512(delegator key) ‖ validator_id ‖ amount` (136 B). The other form is refused, naming the generation. amount 1..total supply; the minimum for a new delegation, the delegator cap and (HF-8) the on-chain-name rule are the chain's. |
| `v2-envelope unstake --keys <dir> [--validator <validator_id hex128>] (--dry-run \| --submit ip:port)` | two-leg SYSTEM UNSTAKE (op 3) + fee-only CORE SYSFUND. Below generation 4 the `--keys` identity is the validator and the call is its key (2592 B; `--validator` refused). At generation 4 (HF-6) `--validator` is required, the call is the validator_id (64 B) and the `--keys` identity must be the validator's owner; the row is read by validator_id and an unstake the chain would refuse (status not ACTIVE / ELIGIBLE, another owner) is refused here. The bond comes back locked 84 epochs after graduation — at generation 4 to the owner. |
| `v2-envelope validator-update --keys <owner dir> --validator <validator_id hex128> --commission <bps> (--dry-run \| --submit ip:port)` | (HF-6; generation 4 only — refused below) SYSTEM VALIDATOR_UPDATE (op 5, 66-byte call `validator_id ‖ commission u16`) + a fee-only CORE SYSFUND, signed by the validator's owner. commission 0..`DNAC_COMMISSION_BPS_MAX`; a lower or equal commission takes effect at once, a higher one two epochs after the update lands. The row is read by validator_id; a frozen status (UNSTAKED / AUTO_RETIRED) or another owner is refused. A multisig (kind-3) owner works as for `stake2`. |
| `[-i <node identity dir>] storage status [--fp <hex128> \| --owner <hex128>]` | READ-ONLY. Without `--owner`: `dnac_storage_status` for the `-i` node's fingerprint (or `--fp`) — the storage registry row (status, bond, fail_streak, grace, owner), the frozen storage-set membership for the current epoch and the eligible segments. (HF-6) `--owner`: `dnac_storage_by_owner` — every storage node that owner registered (ACTIVE, EXITING and RELEASED), node fingerprint ascending, each printed as above; at most 256 are listed and a note says how many more the owner has. `--fp` and `--owner` together are refused; an older node answers "unknown DNAC method". |
| `v2-envelope chain-config --db <db> --keys <dirs>` | offline-signed SYSTEM CHAIN_CONFIG (rehearsal driver) |
| `chain-config propose --param <NAME> --value <N> --effective <H>` | networked SYSTEM CHAIN_CONFIG with committee approvals collected over the wire. NAME (the parameters the running consensus reads; run without `--value` for the ranges): `TARGET_ACTIVE_COUNT` (id 4), `GAS_PRICE_RAW_PER_UNIT` (HF-1, id 5, `[0, 1 000 000]` raw per declared unit; 0 = off), `TOKEN_CREATE_FEE_RAW` (id 6), `HF2_ACTIVE` (id 7, exactly 1), `HF3_ACTIVE` (id 8, exactly 1), `RULESET_GEN2` (HF-4, id 9, exactly the build's D2 in decimal — 4962894749133920991; once only; HF-2 must be active; `--effective − 1` not an epoch boundary), `NAME_PRICE_3P` / `NAME_PRICE_4P` / `NAME_PRICE_5P` / `NAME_PRICE_6P` (HF-4, ids 10-13, `[10^8, 10^15]` raw — the price of a 3 / 4 / 5 / 6+ character name; votable once generation 2 is in force), `EVM_ACTIVE` (Nodus EVM / HF-5, id 14, exactly the build's D in decimal — 188948158701949959 = `DNAC_CFG_EVM_ACTIVE_D` (EVM ruleset v2, the address width committed); once only; HF-2 and HF-3 active, a non-zero gas price active, the chain at rule-set generation 2, `--effective − 1` not an epoch boundary and `--effective` ≥ the chain's initial height + 256; SAFETY grace), `EVM_BLOCK_GAS_LIMIT` (Nodus EVM, id 15, `[10^6, 10^9]` gas, no-row default 30 000 000 — a placeholder until the measurement gate; SAFETY grace). `BLOCK_INTERVAL_SEC` is not read by the running consensus and is refused. See `docs/DEPLOY_RUNBOOK.md` §2.2 before voting a new parameter |
| `ruleset-info` | (0.23.10, HF-4) the node's `dnac_ruleset_info`: its tip, the rule-set generation governing tip + 1, the SYSTEM / CORE (version, hash), the SYSTEM meter-policy digest, the `RULESET_GEN2` height H (0 = no vote) and the node's D2 next to this CLI's (`MISMATCH` if they differ); whether this CLI carries that generation (exit 0) or is out of date (exit 1). An older node does not know the method |
| `name register <name> --keys <dir> (--dry-run \| --submit ip:port) [--fee <raw>]` | (0.23.10, HF-4) single-leg CORE NAME_REGISTER (runtime_op 8): registers `<name>` (3-36 of a-z0-9, lower-cased ASCII-only; an all-hex name of 8+ characters is never a name) to the one `--keys` identity — first come, one name per ID, permanent. Refuses before building when the node still runs rule-set generation 1, when the name is taken (`dnac_name_lookup`) or the ID already holds a name (`dnac_name_of`). The price for the name's length comes from `dnac_fee_info` `np` (no `np` = an older node, refused — a price is never guessed) and is declared in the call; the network fee is the floor (1 000 000 raw) or `units × gas_price`, an explicit `--fee` below either is refused. Inputs: the identity's unlocked native coins (largest first, at most 13); native change returns to it. Price + fee go to the reward pool. `--dry-run` still needs the node |
| `name lookup <name>` / `name of <fp128>` | (0.23.10, HF-4) `dnac_name_lookup` / `dnac_name_of` — one node's committed answer (owner or name, registered height, committed height); exit 2 when not registered |
| `evm …` | (0.24.0, Nodus EVM) smart contracts on the EVM domain — the subcommands below. Every transaction is the two-leg envelope `[CORE EVMFUND] + [EVM op]`, built by the shared builder `src/client/nodus_v2_evm.c`; the reads are the node's §18 RPC. Before the `EVM_ACTIVE` edge the node answers every `evm_*` query "the EVM domain is not active". |

`nodus-cli evm` with no subcommand prints its usage (`tools/nodus-cli.c` `evm_usage`), copied here:

```
Usage (smart contracts, the EVM domain):
  evm address --keys <dir>                  this key's 32-byte EVM address (offline)
  evm balance [<address>] [--keys <dir>]    nonce and balance
  evm deploy (<bytecode-hex> | --solc <file.sol>:<Contract>)
             [--solc-bin <path>] [--args "(t1,t2)" v1 v2 ...]
  evm send <address> <sig> [args ...]       a state-changing call
  evm call <address> <sig> [args ...] [--from <address> | --keys <dir>]
                                            read-only (evm_call); sig may end
                                            with a return list: f(t)(r1,r2)
  evm deposit <raw>                         NODUS -> EVM balance
  evm withdraw <raw> [--to <fp128>]         EVM balance -> NODUS (default: self)
  evm redeem <ticket_id>                    pay out a contract's withdrawal ticket
  evm receipt <intent_id>
  evm logs --from-height <H> --to-height <H> [--address <a>]
           [--topic0..3 <t>] [--limit 1..1000]   (at most 10 000 blocks)
           [--cursor h:x:li]  resume a page (its "more: next" line)
Transactions (deploy / send / deposit / withdraw / redeem) take
  --keys <dir> (--dry-run | --submit ip:port) [--value <wei>] [--gas <N>]
  [--no-wait] [--force]   (--force: send even when the simulation fails)
  [--max-fee <raw>]       refuse a fee above it (no question asked)
  [--yes]                 no question when the fee is above the local
                          bound (5000000000 raw = 50 NODUS)
  The node's estimate is refused when it is malformed (gas used above
  the suggested gas, gas above the asked limit / the cap, read units
  outside the engine's read cap). Receipts are as reported by the
  connected node; a deployment's address is checked against the one
  computed from the signed sender and nonce (exit 4 on a mismatch).
  The solc is $NODUS_SOLC or --solc-bin (default /usr/local/bin/solc-nodus);
  it must be the Nodus 32-byte-address variant (nodus/tools/evm/solc).
ABI types: uint<M> int<M> bool address bytes<M> bytes string.
1 NODUS = 10^8 raw = 10^18 wei.
```

(The default path is `EVM_SOLC_DEFAULT`, `tools/nodus-cli.c:6396`; the 32-byte-address Solidity compiler is built from `nodus/tools/evm/solc/` — see its README.)

## Run Tests

```bash
cd nodus/build
ctest --output-on-failure    # count: see `ctest -N` (and `ctest -N -L bench`). At split S3 (1faf4d4f), json-c found, the orchestrator measured 234 registered, 9 labelled bench, 225 run by `ctest -LE bench`; at split S4 (8eced563), 226 run by `ctest -LE bench`
```

**Test coverage (representative areas — `ctest` runs all):**

| Area | Examples |
|------|-----------|
| Core Kademlia | `test_routing`, `test_bucket_refresh`, `test_storage`, `test_value`, `test_hashring` |
| Client SDK | `test_client`, `test_tier2`, `test_tcp`, `test_fetch_batch` |
| Protocol | `test_tier1`, `test_tier3`, `test_wire`, `test_cbor` |
| Auth | `test_inter_auth`, `test_identity` (+ the read-only loader, split S2), `test_sign_domain_separation` |
| Component split S2 — local IPC | `test_tcp_unix` (Unix domain socket entry: mode 0600, frames both ways, `SO_PEERCRED` refusal, stale / live / regular-file path handling, unlink on close) |
| Component split S3 — `nodus-witness` + IPC chain backend | `test_witness_ipc` (core's IPC chain backend against the witness IPC listener over a real socket, test handlers in place of the witness: preface key/token reach the handler and `find_session_conn`, reply relayed unchanged, `dnac_cc_collect` routing, `session_closed` → no session, status snapshot round-trip, non-preface first frame closed, no witness / control connection down → the "witness module not enabled" error and no session dial, the per-session queue bound, `read_pending`); `test_split_linked` (an `nm` gate: the linked `nodus-witness` carries no `nodus_server_init` / `nodus_cluster_init` / `nodus_storage_open` / `nodus_presence_tick`, and does carry the witness's own entry points) |
| Component split S6 — `nodus-core` | `test_core_linked` (an `nm` gate on the linked `nodus-core`: no `nodus_storage_open` / `nodus_routing_try_insert` / `nodus_witness_init` / `nodus_dht_backend_inproc_new` / `nodus_chain_backend_inproc_open`; carries `nodus_auth_handle_auth` / `nodus_presence_tick` / `nodus_cluster_tick` / `nodus_inter_circuit_table_init` / `nodus_dht_backend_ipc_open` / `nodus_chain_backend_ipc_open`) |
| Component split S4 — core/DHT seam | `test_dht_linked` (an `nm` gate on the never-run `dht_link_probe`, which references only the core → DHT entry points of `dht/nodus_dht.h`: the DHT objects must reach no `nodus_server_init` / `nodus_server_dht_host` / `nodus_auth_handle_auth` / `nodus_presence_tick` / `nodus_cluster_init` / `nodus_cluster_tick` / `nodus_dht_backend_inproc_new`, and must carry `nodus_dht_init` / `nodus_dht_client_request` / `nodus_dht_tick` / `handle_t2_media_put` / `nodus_storage_open` / `nodus_routing_try_insert`); `test_bf_forward_frames` and `test_bf_recv_frame` call the renamed `nodus_dht_bf_*`; `test_bf_forward_frames`, `test_inter_preauth_gate`, `test_circuit_cross_live` (and `circuit_latency_probe`) reach the DHT state through `nodus_dht_backend_inproc_state` |
| Channels | `test_channel_*` (channel system currently disabled in production) |
| Circuits (VPN mesh) | `test_circuit_wire`, `test_circuit_table`, `test_circuit_live` |
| Media / DHT features | `test_media_storage`, `test_media_tier2`, `test_put_if_newer`, `test_hinted_handoff` |
| Presence / Server | `test_presence`, `test_server` |
| Witness (the ledger side; the legacy PBFT lane's tests are gone with it, R3 W4) | `test_witness_verify`, `test_vset_*`, `test_qc_v2`, `test_witness_state_root_failclose`, `test_v2_seam_linked` (an `nm` gate: no old-lane symbol is linked into `nodus-server`) |
| cometbft literal port, R1 types (live since R3 W3; the only consensus since R3 W4) | `test_cmt_pb`, `test_cmt_merkle`, `test_cmt_bits`, `test_cmt_safemath`, `test_cmt_time`, `test_cmt_block`, `test_cmt_vote`, `test_cmt_part_set`, `test_cmt_validator_set`, `test_cmt_results`, `test_cmt_params`, `test_cmt_genesis`, `test_cmt_validation`, `test_cmt_evidence`, `test_cmt_state` |
| cometbft literal port, R2 consensus core (live since R3 W3) | `test_cmt_vote_set`, `test_cmt_hvs`, `test_cmt_msgs`, `test_cmt_wal`, `test_cmt_ticker`, `test_cmt_privval`, `test_cmt_replay`, `test_cmt_cs_unit`, `test_cmt_cs` (44 whole-height scenarios — every `state_test.go` test a single-node fixture can drive; + W3's two P0 part-set-bound scenarios and C2e's two ownership scenarios: a decoded block part and a vote extension survive the overwrite of their wire source), `test_cmt_byzantine` (4 nodes, byzantine proposer, partition — no fork; + R3 W3 P0: the two part-set-bound obligation scenarios — a forged +2/3 for a BlockID whose part count the port's bound refuses: the round recovers on a nil precommit / the commit site parks with no block) |
| cometbft literal port, R3 wave W1 — reactor / host+stores / mempool (live since R3 W3) | `test_cmt_conr` (19 scenarios: the `reactor_test.go` ValidateBasic tables plus four multi-node runs over an in-memory switch; + C2e's `recv_arena_resets_every_receive` — 392 full-size block parts from four peers leave the receive arena at one message's size and stop no peer), `test_cmt_host` (48 cases against a real SQLite database and real ML-DSA-87 keys: schema S14, the block and state stores, the WAL, the file privval, the BlockExecutor — S14 is no longer the live rung; the file also carries the S15 migration matrix added by tokenomics-v3 P1), `test_cmt_mem`, `test_cmt_memr`, `test_cmt_clist` |
| Tier-3 message bodies (P2P-PORT F5: the tier-3 envelope and consensus verbs 35-39 are DELETED; the bodies survive on 4004 channels 0x70 / 0x71) | `test_tier3` (the four bodies that channel 0x70 — genesis bundle, the former verbs 24/25 — and 0x71 — governance approval, the former verbs 40/41 — carry: round trip of every field, request/response told apart by the key set, the request body pinned to the former `a` map's bytes, a 31- or 33-byte pin a hard decode error, an over-ceiling chunk refused) |
| 0.20.0+ — the 4004 p2p port, block sync, WebSocket entry, address history index | `test_p2p_secret`, `test_p2p_mconn`, `test_p2p_switch`, `test_p2p_pex`, `test_witness_p2p`, `test_p2p_host` (0.26.15, the witness-free host), `test_net_poll` (0.26.14), `test_network_file`, `test_cmt_autofile`, `test_cc_collect`, `test_cmt_bsync_msgs`, `test_cmt_bsync_pool`, `test_cmt_bsync_reactor`, `test_ws_frame`, `test_ws_upgrade`, `test_ws_server`, `test_v3_block_query`, `test_addr_index` |
| cometbft literal port — the live server binding (C2a/C2c, ported onto the 4004 p2p host in P2P-PORT F5) | `test_cmt_live` (3 cases on a REAL version-3 chain through the REAL `nodus_witness_init` → `nodus_witness_tick`, with a real second p2p host on 127.0.0.1: the genesis-time wait and peer admission, CheckTx admitting a real signed claim and refusing it under another key, a restart reopening the same role; block PRODUCTION is the harness's — one process holds one of seven equal votes. The old version-gate, mesh-tick and adopt-then-live cases went with the deleted transport; joiner adoption is `test_witness_p2p`), `test_cmt_app` (21 cases: + the EMPTY decided block, the byte-bound seam with a policy-verified unit ceiling, the count guards at `env_bound + 1`), `test_cmt_host` (50: + the half-present S14 catalogue refusal through the real open path; + `store_get_then_full_write_then_main_write` — the harness-found SQLite snapshot lock that stopped every node after height 1, RED on the old store), `test_cmt_node` (14: + the nilWAL no-op before start), `test_v2_preflight` (the document-based genesis check: READY on a derived chain; absent row / one flipped byte / app_hash mismatch / chain-id disagreement each raised by one corruption, whole-DB digest unchanged; + harness-found: READY stays true after the FIRST committed block — the check reads block 1's header app hash from that height on — and a block 1 carrying a wrong app hash still raises the mismatch), `test_v2_bundle` (v3 round trip carrying the document, adopt only with the 32-byte chain id, wrong pin / tampered stake / foreign bundle / old magic refused), `test_v2_pools` (`t_s14_flip`: the pool replay REALLY runs at S14 — the old silent skip proven RED) |
| cometbft literal port, R3 wave W2 — application / genesis v3 / startup table (live since R3 W3) | `test_cmt_app` (18 cases on a REAL version-3 chain: InitChain as a genesis check, FinalizeBlock with per-item SAVEPOINT isolation proven against a twin chain, both crash windows, CheckTx incl. the signature stage, PrepareProposal/ProcessProposal), `test_cmt_node` (14 cases: the genesis-document loader's row/provider table, the Handshaker's height cases, both crash windows healed through the real Handshaker, LoadOrGenFilePV, init/start/release), `test_v2_gen` §5-§11 (the version-3 document: oracle KATs, strict decoder, derive end to end, tampered stored rows refused) |
| D-16 rev 7 (W4-CC) — SYSTEM-governance approval collection on the Comet lane, carried since P2P-PORT F5 on 4004 channel 0x71 | `test_cc_appr` (the responder's verdict `nodus_witness_cc_appr_answer` — the 0x71 handler without its send — over a REAL derived version-3 chain with 7 REAL ML-DSA-87 committee keys: every seat's approval assembled into an envelope that `nodus_witness_v2_env_dry_run` accepts, an independent recomputation of the `NDS.CCSET.v1` / `NDS.CCAPPR.v1` preimages checked against a seat's signature, and a refusal matrix — requester or responder not a seat, wrong `auth_kind`, nonzero fee, `TARGET_ACTIVE_COUNT` above the ceiling, effective below the grace floor, the retired parameter 3, `BLOCK_INTERVAL_SEC`, a gas price above its ceiling, the rate limit). The transport half — a 0x71 request and reply over real sockets, and a foreign-chain requester refused at the secret connection — is `test_witness_p2p`; node-side collection is `test_cc_collect` |
| Merkle / state_root | `test_witness_merkle`, `test_merkle_utxo_root`, `test_state_root_4subtree`, `test_merkle_scan_fail_close` (`test_merkle_proof` and `test_merkle_state_root_golden` deleted in the root-layout round — their only subjects, `build_proof` and the legacy five-input `compute_state_root`, are gone) |
| Ledger V2 (the engine; driven through the cometbft application on the live lane) | `test_v2_apply`, `test_v2_native`, `test_v2_epoch`, `test_block_v2`, `test_domain_wire`, `test_v2_pools`, `test_v2_claims`, `test_v2_gen` (§3.5 L2-F1: the supply probe fails closed on a version-3 chain — R3 W4-S), `test_v2_econ_params` (its reopening cases derive version-3 chains) |
| tokenomics-v3 P2 — rewards, fees, the reward pool (no mint; parameter 3 retired) | `test_v2_econ` (REWRITTEN: the frozen balance copy, the pro-rata distribution through the engine at a boundary, the source copy src(H) and the consistency gate, a mid-epoch withdrawal paid through L(h), partial withdraw + top-up (earned ≤ locked), the decimal_unit refusal, a bar miss forfeiting the whole share, payday, the payout-interval reader, the F55/F56/F59 and payday stage rollbacks, a determinism twin), `test_v2_native` / `test_v2_apply` (every fee leg credits `reward_pool`; an explicit BURN still burns; the supply gate's pool and accrual terms; P2-10 — the UNDELEGATE release UTXO born locked to L(h) + 12E, partial and full drain, refused by the SPEND / SYSFUND / TOKEN_CREATE gates at U and accepted at U+1), `test_roots_v2` (supply-leaf v2, accrual leaf/root and the 7-leg `core_state_root` KATs), `test_cmt_host` (the S16 migration matrix), `test_v2_gen` (Rule P.2 with the reserve). DELETED with their subjects: `test_epoch_state`, `test_emission_boundaries`, `test_epoch_snapshot`, `test_epoch_snapshot_failclose`. Harness: `test_v2_rewards.sh` |
| tokenomics-v3 P3 — stake parameters (okuma B, 84/12 locks, exit with delegators, min delegation, 32 seats, 2048 delegators, commission 50% / increase +2E, re-stake, Rule M) | `test_committee_election` (okuma B: ranking follows the frozen copy, status the live row; frozen 0 not seated), `test_v2_econ` (src = H−3E and 3-copy retention to 4E; the 2-epoch commission notice under okuma B, with the old writer reproduced), `test_v2_epoch` (84E / 12E locks; graduation auto-release of delegations — ranks, 0x40000000 band, F60 rollback restores rows and totals), `test_v2_native` (Rule A gone; min delegation and the partial-remainder rule; commission 5000; target [7, 32]; re-stake of an UNSTAKED row — hook level and through real blocks after a graduation; Rule M: the 129th STAKE refused), `test_stake_constants`, `test_v2_active_max`, `test_cc_appr`, `test_vset_boundary`, `test_vset_persist`, `test_committee_cache`, `test_v2_committee_seed`, `test_chain_config_failclose` (updated expectations). Measurement (LABELS bench, not in the default run): `test_v2_deleg_cap_bench` (32 × 2048: boundary, payday, auto-release wall times) |
| tokenomics-v3 P4 — version 3 only (the version-2 derivation, the version-2 engine genesis and the engine's legacy block lane deleted; `v2_tx_bytes` deleted — its UNIQUE `tx_id` halted the chain on a re-carried envelope) | Converted suites (`test_v2_apply`, `test_v2_native`, `test_v2_claims`, `test_v2_exec`, `test_v2_pools`, `test_v2_epoch`, `test_v2_econ`, `test_v2_schema`, `test_v2_bundle`, `test_v2_committee_seed`, `test_cmt_app`, `test_cmt_host`): every block they apply goes through the cometbft lane, the engine's only one (`tests/v2_genesis_fixture.h`: `v2x_chain_open` / `v2x_seed_genesis` with derive_v3 post-conditions, `v2x_cmt_apply`, per-item class helpers `V2X_VERDICT` / `V2X_FAULT` / `V2X_DEFER`); `test_v2_native` `test_resubmission_no_halt` (a re-carried envelope is refused per item, the block commits) and `test_undelegate_totals_underflow`; `test_v2_seam_linked` (the deleted genesis symbols are absent from `nodus-server`); `tools/genesis/check_genesis_conf.sh` (the ceremony template checker; since general multisig it requires `--cli <nodus-cli> --foundation-m <M> --foundation-pubkey <file>...` to recompute the Foundation multisig address — usage in `tools/genesis/README.md`) |
| tokenomics-v3 root-layout round — `unlock_block` in the UTXO leaf (340 B), `epoch_state` removed (`NDS.SYS.v3` 7 legs, `NDS.SYSPAYL.v2` 4 legs, bundle `NDS.GBUNDLE.v4` 5 tables), the legacy five-input state root deleted (IDENT `state_root` and the `dnac_utxo` proof fields stay on the wire, zero / depth 0) | `test_merkle_utxo_root` (340-byte leaf KAT vs a hand-built preimage; `unlock_block` moves leaf and root; a negative `unlock_block` fails closed), `test_merkle_scan_fail_close` (+K1 negative-lock case; the composite step-error case on the CORE root), `test_roots_v2` (SYS.v3 / SYSPAYL.v2 KATs; the witness compositions equal the shared functions in K2 order), `test_v2_bundle` (the six-table v3 magic refused, joiner byte-identical), `test_witness_state_root_failclose` (retargeted to the SYSTEM / CORE roots), `test_stake_schema` / `test_v2_gen` (no `epoch_state` table), `dnac/tests/test_merkle_verify` (the client leaf on the same KAT) |
| 0.19.77 PrepareProposal byte bound (the 2026-09-25 devnet halt) + 0.19.78 CHECKTX-P1 — CheckTx = a write-free dry run of the apply engine's per-item stages, a pending conflict set, the ≤ 100-block lifetime, a unit-aware fee-per-unit pack (node-local; ProcessProposal / FinalizeBlock unchanged) | `test_cmt_app` (45 cases: the byte bound, unit truncation and entry-invalid seam cases; the dry run refusing a ceiling below static cost / above the budget and a spend of an absent row; the 0-unit chain_config poison; conflict keys — second spend of one row, one intent twice, a claim signature-variant, a second `PRE_ABSENT` CREATE refused, two VHASH SETs of one row BOTH admitted; the light recheck and kind-2 re-verification; expiry 0 / tip+101 refused, tip+100 admitted, an admitted tx dropped at recheck once expired; the corrupted approval refused at the AUTH stage; PrepareProposal: a refused chain_config no longer empties the block, refill after a drop, claims past the envelope window, a full-budget hog skipped with everything behind it kept, fee-per-unit order), `test_cmt_node` (`t_txs_available_fires` on expiring, distinct-effective envelopes), `test_cc_appr` (the responder's happy path through the dry run) |
| 0.19.80 HF-1 gas price — chain-config id 5 `GAS_PRICE_RAW_PER_UNIT` (range [0, 1 000 000], 0 = off); an envelope with a non-SYSTEM leg must pay `max(res_max_total_units × price, floor)` from the row's effective height, item code 9 `NODUS_V2_TX_ERR_FEE`, checked after admission and before reservation in both the item loop and the CheckTx dry run; `dnac_fee_info` returns `gas_price`; CLI spend/stake price their fee from it; the chain-config cache stays cold instead of dropping the newest rows past 64 | `test_v2_gas_price` (NEW, 4 cases / 106 checks: the scalar-rule matrix incl. the ceiling and 0, the price rule incl. the SYSTEM exemption, the floor, the u64-overflow refusal, rule-off inertness, the cache capacity past the array), `test_cc_appr` (+2: a param-5 proposal through the responder), dnac `test_chain_config_verify` (case 8b, the client mirror's range), `test_v2_deleg_cap_bench` (stale band assertion corrected to the P3 auto-release band [2^30, 2^31)). Harness: `test_cmt_hf1_gas_upgrade.sh` (standalone, two binaries, positive + negative mode — stagef README) |
| 0.19.79 CHAINID-CACHE — `nodus_witness_v2_chain_id` answers from `v2_chain32` while `v2_chain32_valid` (set only by the post-open gate) is true, instead of re-deriving the stored genesis document per call (node-local; no consensus value changes) | `test_v2_chain_id_cache` (NEW, 35 checks: the gate arms the flag and the answer equals the canonical-strict derivation; after the "genesisDoc" row is deleted under the open handle the cached answer still holds while the derivation, a never-gated handle and a flag-cleared handle fail closed and a re-open is refused by the gate — mutation-proven: disabling the cache branch fails it; a never-gated handle with `v2_successor` set and a garbage/zero `v2_chain32` still derives; the joiner's scratch steps keep the flag false and answer the pin) |
| 0.23.10 HF-4 rule-set generation switch + on-chain names — the compiled table becomes a list of rule-set generations (1 = SYSTEM v6 / CORE v4, the genesis generation, byte-identical; 2 = SYSTEM v7 / CORE v5 with CORE op 8 NAME_REGISTER); chain-config id 9 `RULESET_GEN2` (value exactly the compiled D2, single use, HF-2 active, H−1 not an epoch boundary — the stateful half in `nodus_chain_config_stateful_rules`, applied by the SYSTEM exec and the 0x71 responder) moves the SYSTEM and CORE registry records to generation 2 at the end of H−1 (engine phase 6b′); ids 10-13 `NAME_PRICE_3P..6P` ([10^8, 10^15] raw, defaults 1 000 / 500 / 100 / 1 NODUS, votable under generation 2 only); `v2_names` (base schema, DDL checked on every open) and the real `name_root` as CORE's 5th leg; CheckTx code 100 "generation not in force"; queries `dnac_ruleset_info` / `dnac_name_lookup` / `dnac_name_of` and `dnac_fee_info` `np` / `ns`; `dnac_v3_block` `nm` / `pr`; address-history kind `name`; startup lines with D2, the build's git commit and the consensus build constants; the legacy `nodus_chain_config_apply` deleted (no caller). Mechanism: `docs/ARCHITECTURE.md` "HF-4"; procedure: `docs/DEPLOY_RUNBOOK.md` §2.2 "HF-4" | `test_hf4_table`, `test_hf4_params`, `test_hf4_switch`, `test_hf4_genesis`, `test_hf4_names`, `test_hf4_names_engine` (NEW — what each proves: their file headers and `docs/ARCHITECTURE.md` "HF-4", Tests), `test_cc_appr` (+6: HF-2 off / second vote / epoch-boundary H−1 / wrong value / a name price under generation 1 refused, a param-9 vote that signs and is then single use), dnac `test_chain_config_verify` (cases 5a′ / 5a″ / 5b: the client mirror and the read list {4..13}); independent oracles `shared/dnac/tests/hf4_oracle.py` and `hf4_switch_oracle.py`. Harness: `test_cmt_hf4_names.sh` (standalone, two binaries — stagef README; written, NOT yet run) |
| 0.24.0 Nodus EVM (HF-5) — the EVM domain (domain 2, runtime ABI 2) in rule-set generation 3, activated by chain-config id 14 `EVM_ACTIVE` (phase 6b″ at the end of H−1); id 15 `EVM_BLOCK_GAS_LIMIT`; CORE op 9 EVMFUND; schema S17; VM-less CheckTx with the conflict probe; the price-0 rule; the §18 `evm_*` read RPC; the start-up precompile self-test. Mechanism: `docs/ARCHITECTURE.md` "Nodus EVM (HF-5, v0.24.0)" | `test_v2_evm` (EVM build only), `test_evm_call_wire`, `test_keccak256` (EVM build only), updated `test_v2_schema` (S17), `test_hf4_table`, `test_hf4_params`, `test_v2_gas_price`, `test_v2_gen`, `test_server`, `test_v3_block_query`, dnac `test_chain_config_verify`; the engine's own suite `cd shared/evm && make test` (README `shared/evm/README.md`); bench `bench_evm_apply` (EVM build only; label `bench`, minutes at its defaults — `ctest -LE bench` leaves it out). Harness: `test_cmt_evm.sh` (standalone, two binaries — stagef README) |
| 0.26.7 Windows plain TCP listener + light client package 1 (cometbft v0.38.26 `light/verifier.go`, `types.LightBlock` + its proto codec, `light/store` over SQLite, the `light/provider` interface — no node path calls any of it yet; the light client itself, the detector, a network provider and any proven RPC are NOT on main) | `test_tcp_listen_portable` (3 cases through the public API alone, the same source for Linux epoll and mingw select: listen on port 0 and read the bound port back; connect + accept + one frame each way + disconnect seen; `NODUS_MAX_CONNS_PER_IP` + 1 connections → `on_accept` exactly `NODUS_MAX_CONNS_PER_IP` times and one client closed), `test_cmt_light_verifier` (real ML-DSA-87 signatures, fixed `now`: VerifyAdjacent / VerifyNonAdjacent / Verify with the reference's error classes, the strict future-time bound, ValidateTrustLevel = [1/3, 1], VerifyCommitLightTrusting early exit vs the AllSignatures form, overflow and zero-denominator refusals, SignedHeader.ValidateBasic, VerifyBackwards), `test_cmt_light_block` (LightBlock.ValidateBasic accepts / refuses, the proto round trip gives the same bytes, presence bytes `0a 00` / `12 00` / empty as the generated encoder writes them, unknown field skipped, truncation and wrong wire type refused, the provider interface through a port of the reference's mock provider), `test_cmt_light_store` (the reference store's behaviour plus the deviations `cmt_light_store.h` D2-D7 — idempotent re-save, count = rows on disk after prune and restart, per-prefix counts, a tampered count refused at open, a row under the wrong height refused — and a FAILED COMMIT rolled back). What each proves and how it can lie: the file headers |
| 0.26.8 Light client packages 2-3 (cometbft v0.38.26 `light/client.go` + `trust_options.go`, `light/detector.go`) + the `dnac_light_block` RPC on 4001 with its pinned provider (no caller yet) + ML-DSA-87 RNG-failure fix (key generation and hedged signing return -1 when randomness fails instead of using uninitialised bytes; secret temporaries cleared; success-path outputs byte-identical) | `test_cmt_light_client` (208 checks), `test_cmt_light_detector` (87 checks), `test_light_block_rpc` (4 cases, 193 checks: the node's answer over a real derived chain — seen vs canonical commit, above-tip 22, below-base NOT_FOUND, open transaction INTERNAL; the strict client decoder; the provider's pin refusal and error mapping). The ML-DSA test `shared/crypto/sign/dsa/test/test_rng_failure.c` is standalone (not in ctest). What each proves and how it can lie: the file headers |
| 0.26.9 DHT v2 package 1 — the record codec in `shared/dht2/` (design `2026-10-14-dht-v2-design.md` rev 5 §3.1, §3.2, §4.2, §13 rows 1, 3-6, 21-23): strict DAG-CBOR, the IPNS v2 signed record (ML-DSA-87, ctx `nodus.dht.record.v1`) + its canonical stored envelope, `_id` / address, §4.2 Select, `nearest_R` / `eligible`, the RFC 0002 Signed Envelope + the owner-signed LIST request. In the common `NODUS_SOURCES` list; no node or client calls it yet; no wire, port, consensus or state-root change. Storage, pull-sync, sessions and quotas are later packages. Mechanism: `docs/ARCHITECTURE.md` "DHT v2 package 1"; functions: `messenger/docs/functions/dht2.md` | `test_dht2_codec` (12 sections, 429 checks in the ORCHESTRATOR's run: pinned data-map bytes per class, canonical envelope, every row-22 strict-decode reject, §3.2 identifiers against hand-assembled preimages, §4.1 code order, row-5 matrix + class max, the §4.2 A/B two-arrival case, `nearest_R`, Validity round trips, row 23 `not-owner` / `bad-signature`). What it proves and how it can lie: the file header |
| 0.26.10 Light client fix rounds (still no caller): a detected attack LOCKS the light client until the operator clears it, every attack record is kept durably in a new light-store table and a restart reloads the lock (Kurultay #25 K25-10; new error `CMT_LIGHT_CLIENT_ERR_ATTACK_LOCKED` = 29, `cmt_light_client_attack_locked` / `_attack_clear`, `cmt_light_store_db_*attack_record*`); an established attack is never downgraded to a local fault, an unknown commit signer past the 2/3 point is skipped and counted (BUGS Z-42); a recorded wait pins its target and after it the STORED block is judged, never re-fetched (Z-41, client D21); the node answers `dnac_light_block` at most 4 times per second node-wide (`NODUS_LIGHT_BLOCK_RATE_PER_SEC`, refusal `NODUS_ERR_RATE_LIMITED` before any store read; measured worst case 15 / 57 / 220 ms at 7 / 32 / 128 validators) and the pinned provider maps RATE_LIMITED and a local failure to NO_RESPONSE (Z-44, Z-45). Node-local; no wire, consensus or state-root change. Mechanism: `docs/ARCHITECTURE.md` "Light client packages 2 and 3"; functions: `messenger/docs/functions/ledger.md` §25.6, §25.9, §25.10, §26 | `test_cmt_light_detector` (170 checks), `test_cmt_light_store` (34), `test_cmt_light_client` (208), `test_light_block_rpc` (5 cases, 239 checks) — counts in the ORCHESTRATOR's run. New rows: the lock, restart and clear, the moving target, the unknown signer, the not-durable write retry, two clients on one prefix, the attack-record table, the limiter's burst / refill / refusal and the serve seam. What each proves and how it can lie: the file headers |
| 0.26.11 `nodus-light` — the light client as a program (`tools/nodus-light.c`, `tools/nodus_light_checkpoint.h`): `run` / `status` / `clear-attack`, options `--data`, `--trust-height` + `--trust-hash`, `--node host:port:pin` (min 2, max 16), `--interval` (default 10 s), `--chain-id`. Pinned 4001 sessions only (Kurultay #25 item 8), one client per store via `DIR/identity.lock` (item 9 / D20), trusting period 48 h (K25-2), an attack locks until `clear-attack` (K25-10). Trust root (K25-1): operator input, else the stored block, else the release default — which is EMPTY in this build (no block has been read through `dnac_light_block`, which is on no live node), so an empty store needs `--trust-height` / `--trust-hash`. Default nodes: the 7 testnet nodes on 4001 with the web wallet's pins. Windows: the CMake configure now works and builds the library + `nodus-light` only; five POSIX-only witness-server files leave the WIN32 source list (Linux unchanged); `nodus-light.exe` is linked `-static`; two fixed-width tag arrays get `nonstring` (bytes unchanged). Mechanism: `docs/ARCHITECTURE.md` "nodus-light — the light client program" | No new test (none in scope). ORCHESTRATOR run 2026-10-19: Linux build 0 warnings; llvm-mingw 20251118 build → static `nodus-light.exe` (12 133 888 B, PE32+ x86-64 console, imports only Windows system DLLs); local 7-node harness chain (bring-up, production constants, combined mode): 7 pinned sessions, root height 2 from operator input, height 5 reached in 150 s, stored hash at 5 = the nodes' `block_id`, no lock, 0 attack records. The `.exe` was NOT run on Windows (no Windows host) |
| 0.26.12 `nodus-light` node-list refresh (Kurultay #25 K25-11, operator 2026-10-19): 30 s after start and every 600 s the program asks one connected pinned node for `dnac_roster` and ADDS a node only if its key is in the validator set of its own verified trusted block (pin = SHA3-512(key), client port = witness port − 3); the compiled list and `--node` entries are never removed; after an addition the light client is rebuilt from the same store (library unchanged, the K25-10 lock comes back from the store). Storage-only nodes are not discovered (membership not provable before HF-7). Mechanism: `docs/ARCHITECTURE.md` "The node-list refresh" | ORCHESTRATOR run 2026-10-19 on a local 7-node harness chain (production constants, combined mode): started with 2 `--node`s, the first refresh read 7 roster rows — 5 added, 2 already listed, 0 outside the verified set — and the rebuilt client verified heights 2-3 with 6 witnesses. Linux build 0 warnings; Windows `nodus-light.exe` builds. Not exercised: a roster row outside the verified set, a rebuild while locked |
| 0.26.13 `nodus-light` takes its starting block from the pinned nodes by itself (Kurultay #25 K25-12, operator 2026-10-19, amending K25-1): with no `--trust-*` and no fresh stored block it asks the primary for the latest height H, asks every compiled / `--node` node for block H − 2, and starts there when ≥ 2 answer with the same header hash; fewer → retry; any disagreement → stop, exit 1. The end user runs `nodus-light run --data DIR` and types nothing; `--trust-*` stays for an operator's own root. The never-filled release-default checkpoint is removed. Mechanism: `docs/ARCHITECTURE.md` nodus-light "The trust root" | ORCHESTRATOR run 2026-10-19 on the LIVE testnet (nodus 0.26.12 on 7/7): `run --data DIR` alone → "starting point: block 263171 taken from 7 nodes that all agree", followed with 6 witnesses, the refresh added the 8th validator; a second run resumed from the light store and advanced. Linux build 0 warnings; Windows `nodus-light.exe` builds (12 150 272 B, system DLLs only). The disagreement stop, the short-answer retry, the expired-store re-root, the locked store and the pinned-only rule are pinned by `test_nodus_light` (74 checks, mutation-proven: disabling each rule turns it red) |
| 0.26.14 One network layer, package N1 (Kurultay #26b, operator-approved 2026-10-19, order N1 → N3): `nodus/src/net/nodus_net_poll.{c,h}` — one socket-readiness backend for ports 4000-4004 plus socket shims (create / accept / send / recv / close / non-blocking / close-on-exec, the Winsock startup owner, the `NODUS_NET_IS_*` error classes). Linux / Android epoll; Windows `select` over a 1026-socket registry (file-local `FD_SETSIZE 1026`) with a loopback wake pair, fair rotation (every socket that stays ready reported within ⌈n / cap⌉ waits) and `WSAENOTSOCK` eviction reported as `ERR\|HUP`; Emscripten refused by `#error` (browser arm is N2). No framing, no session crypto: 4004 stays cometbft's raw mconn stream. The only user today is the 4004 host's io seam (`nodus_p2p_io_*`, Linux-only): its epoll set + eventfd became a `nodus_net_poll_t`, its sockets `nodus_sock_t`. Linux syscalls unchanged on every success path; one stated error-path deviation (`nodus_net_set_nonblocking` skips `F_SETFL` when `F_GETFL` fails). The Windows backend has run only under Wine 8.0 (test_net_poll_win, next column), never on native Windows. Known gap: a Windows handle value reused after a close without `_del` is not evicted — root `BUGS.md` C-06 is the gate before N2a. No wire, consensus or state-root change. Mechanism: `docs/ARCHITECTURE.md` "Network readiness layer (`nodus_net_poll`)"; functions: `messenger/docs/functions/transport.md` "Nodus network readiness layer" | `test_net_poll` (9 cases, Linux epoll arm). Proves: add / mod / del under the last tag, mask 0 silent, double add and the reserved wake tag refused; level vs `NODUS_NET_EDGE` (`EPOLLET` passed through); `RDHUP` / `HUP` / `ERR` kept apart (refused connect → `ERR` + `SO_ERROR` `ECONNREFUSED`); a wake from another thread ends a wait without limit, is not reported and is drained, two pending wakes drained by one wait, a set without wake ignores it; a wake + a ready socket in one wait; the connect probe finished for refused and succeeded connects; the cap (3 ready, cap 2 → 2; 64 accepted; 0 and 65 refused); the shims' flags, `nodus_net_close` keeping `errno`. Requires: a default Linux build, no flags, no environment; loopback with kernel-chosen ports, `/proc` mounted, one helper thread; ctest `TIMEOUT 120` is a hang guard only. Leaves behind: nothing. How it can lie: it tests the backend, not that `nodus_witness_p2p.c` issues the same syscalls as before (that rests on the diff and the preprocessed-TU comparison); HUP, arrive-before-add and refused-connect cases rely on Linux kernel behaviour (a different kernel FAILS them, never passes them wrongly); if the waker never sees the main thread asleep in `/proc`, the wake case exercises only the pending-wake path, still PASSES and prints a NOTE — read the output; the Windows arm is NOT exercised by it. `test_net_poll_win` (9 cases, Windows `select` arm; `nodus/tests/test_net_poll_win.c`, a Windows-only executable — no ctest entry). Proves: Winsock startup reference counting; add / mod / del refusals with `WSAEINVAL`; level-triggered IN until read; FAIR ROTATION (10 ready, cap 3: every wait 3 distinct tags, every 4 consecutive waits cover all 10; a delete mid-rotation, then every 3 waits cover the 9 left); a wake from another thread ends a wait without limit; wake + a ready socket in one wait; the connect probe for a succeeded and a refused connect (`SO_ERROR` 10061 `WSAECONNREFUSED`); a socket closed without `_del` reported once as `ERR\|HUP` then gone; an empty set. Requires: a Windows build (the README's cross build), run natively or under Wine. Leaves behind: nothing. How it can lie: under Wine the Winsock behaviours (`WSANOTINITIALISED`, refused connect through the except set, `WSAENOTSOCK`) are Wine's emulation, not Windows; a broken wake HANGS case 5 instead of failing (no ctest timeout — treat a hang as FAIL); a reused handle value is not tested (C-06). ORCHESTRATOR run 2026-10-20 under Wine 8.0 (Debian bookworm): 3 runs, 9/9 each; and `nodus-light.exe` under Wine against the live testnet: root from 7 agreeing nodes at 267715, followed to 267726, the refresh added the 8th validator. ORCHESTRATOR evidence: ctest 283/283 at `d2b146494`; Genesis Protocol sweep at `d2b146494`, production constants E720 / grace 17280 / BPY 6307200, combined mode: 14 PASS / 6 SKIP (`chain_config`, `self_delegate`, `epoch_boundary`, `rewards`, `rule_n_retire`, `split_storage_restart` — skips are coverage that did not happen) / 0 FAIL, `test_p2p_seam_faults` PASS; N1-FIX: Linux preprocessed translation unit byte-identical to `d2b146494`, `test_net_poll` 3 runs 9/9; Windows cross build (llvm-mingw 20251118) 0 warnings; 8 red-team lenses (at `d2b146494`, before N1-FIX; their Windows findings are what N1-FIX addressed): Linux 0 high / medium |
| 0.26.15 One network layer, package N3 (Kurultay #26b item 8, operator-approved 2026-10-19; design 2026-10-19 §11): the witness-free 4004 host `nodus/src/net/nodus_p2p_host.{c,h}`, split out of `nodus_witness_p2p.c` with the logic unchanged — sockets (`nodus_p2p_io_*`), the handshake / ADDR-verify worker, clocks, identity, own ADDR record (`nodus.addr_seq`), address-book file (`p2p_addrbook.pb`), NodeInfo, transport, switch, PEX, the P2P config type. `nodus_witness_p2p.c` keeps the bonded set, the consensus seam, the seven reactors (0x20-0x23, 0x30, 0x40, 0x70-0x73), M4, the approval-collection tick and the genesis bundle, embeds the host by value and hands it six policy rows (`is_bonded`, `bonded_count`, `bonded_pubkey`, `may_receive`, `recv_near_full`, `queue_mark`; a NULL row is the shared layer's neutral answer, a NULL `queue_mark` gives the transport no row). Two-step start (`_init` / `_start`) and poll in steps (`_poll_io`, `_pex_tick`, `_own_record_check`, `_flush`) keep the witness's order; `LOG_TAG` stays `"W_P2P"`; every `nodus_witness_p2p_*` keeps its signature. N3-FIX contract: `_init` refuses unbounded inputs (peer-list counts, path lengths), PEX on without `bonded_pubkey`, and a NodeInfo channel set unequal to the registered reactors' channels; `init_ok` / `started` lifecycle flags (`_start` once, steps and accessors neutral unless built, `nodus_p2p_host_poll` returns -1 when not running). The host is in the common source list and COMPILES for Windows (wide-path atomic replace with `_commit` + `MoveFileExW(REPLACE_EXISTING \| WRITE_THROUGH)`, wide-path read, `SO_EXCLUSIVEADDRUSE` listener, Winsock codes in the logs) — never run on Windows or Wine. Not in N3: the connect-probe caller still tests `<= 0` (`nodus_p2p_host.c:708`; design §10 had assigned it to N3). No program runs a witness-free host yet: `nodus-light` does not call it; the storage packages will, after HF-7 (design). Link gates: nodus-storage forbids, nodus-witness requires `nodus_p2p_host_init`. Witness Linux behaviour unchanged (K25-5); no wire, consensus or state-root change. Mechanism: `docs/ARCHITECTURE.md` "The witness-free 4004 host (`nodus_p2p_host`)"; functions: `messenger/docs/functions/transport.md` "Nodus witness-free 4004 host" | `test_p2p_host` (Linux; ctest entry, `nodus/tests/test_p2p_host.c`). Proves: two hosts built with `nodus_p2p_host_init` + `_start` from fresh REAL ML-DSA-87 / ML-KEM-1024 identities and an all-NULL policy, no `nodus_witness_t` in the process, PEX off; B's persistent dial to A ends in a secret connection both switches admit, each peer set holding the other's key-derived ID (`cmt_p2p_pubkey_to_id`); a caller's reactor on test channel 0x7E carries a 37-byte payload A→B and a 1500-byte payload B→A (split over 1024-byte packets and reassembled), each followed by a sentinel — each receiver gets exactly two messages, payload byte for byte then sentinel, from the other's ID; A freed and rebuilt with the same identity, data directory and port, B's persistent redial reconnects to the same ID and the exchange holds again; a second `_start` refused, `_start` after a failed init refused, `nodus_p2p_host_poll` on a freed host -1; `_free` twice after an init refused before anything is built (no ML-KEM) and after one refused with the listener and mutex built (`external_ip` "x"); the temporary directory's removal is a CHECK. Requires: the default nodus build, no flag, no environment; Linux only; two kernel-chosen loopback ports (A's re-bound for the restart, `SO_REUSEADDR`). Leaves behind: `/tmp/test_p2p_host_XXXXXX` (A/ and B/ with `nodus.addr_seq`) — removed on success, kept and logged on failure. How it can lie: waits are bounded by passes (`MAX_PASSES` 60000 rounds, ≥ 1 ms per host per idle pass ⇒ ≥ 120 s), not tuned to a measurement, an expired cap is a FAIL; the switch's timers (dial randomizer up to 3 s; redial 5 s + up to 3 s) run on the monotonic clock meanwhile; a duplicate arriving after the sentinel and after the wait is not seen; the restart does not prove a NEWER ADDR record is signed (PEX off); it does not exercise PEX, the address-book file, an inbound limit, a bonded peer, backpressure or Windows (the witness path is `test_witness_p2p`'s; the Windows build is a compile check only); test channel descriptor values are ⚠ NOT GROUNDED test choices. ORCHESTRATOR-reported evidence: ctest 284/284 at `ff81e4c44` (before N3-FIX); at `88284e668`: `test_p2p_host` 3 runs 34/34, `test_witness_p2p` and `test_p2p_switch` pass, Linux build 0 warnings, Windows cross build 0 warnings, `test_net_poll_win` under Wine 9/9; 8 red-team lenses at `ff81e4c44`: the witness path 0 high / medium; the findings for future witness-free callers and for Windows were fixed in N3-FIX. Full ctest and Genesis Protocol sweep at `88284e668`: see the next commit |

Integration tests (Genesis Protocol harness, 7-node localhost) — **one
lane** (the legacy runner `genesis_protocol.sh`, its bring-up and its 23
scenarios were deleted in R3 W4-D; see the stagef README — this block
read "two lanes" until tokenomics-v3 P2 corrected it):
```bash
# Ledger V2 chain — genesis is DERIVED OFFLINE from an operator config
bash nodus/tests/integration/stagef/genesis_protocol_v2.sh
```
Several scenarios need a short-epoch build and matching `STAGEF_*`
exports BEFORE bring-up (including `STAGEF_PAYOUT_INTERVAL_EPOCHS=2` for
`test_v2_rewards.sh`) — read `nodus/tests/integration/stagef/README.md`
in full first.

---

## Deployment

### Configuration

`nodus-server -c <file>` (and `nodus-witness`, `nodus-storage`, `nodus-core -c <file>` — the same loader; storage and core skip the witness-side keys) reads a **JSON** config (`nodus/tools/nodus_node_config.c`, `load_config_json`). The common keys:

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
  "seed_nodes": ["<id>@198.51.100.20:4000", "198.51.100.21:4000"]
}
```

A `seed_nodes` entry `"ip:udp_port"` seeds the DHT. Written as `"id@ip:udp_port"` it also makes that node a persistent peer of the chain p2p layer on `udp_port + 4` — the 4004 layer never dials a peer whose ID is not pinned. Other keys the loader reads: `ws_port`, `ws_origins`, `require_peer_auth`, `addr_history_index`, `witness_external` / `storage_external` (booleans, default false — see "Build" above), `network_file`, `ch_port`, and the p2p tuning keys (`moniker`, `send_rate`, `recv_rate`, `dial_timeout`, `handshake_timeout`, …).

**WebSocket entry (browsers — web wallet / Nodus Connect), off by default.**
`"ws_port": 4005` opens a plain WebSocket listener of the client port on
`127.0.0.1` only (a local TLS proxy serves it on 443 and forwards to it);
`"ws_origins": [...]` lists the allowed browser `Origin` values (default
`["https://wallet.nodusnetwork.io", "https://connect.nodusnetwork.io"]`). See `docs/ARCHITECTURE.md` §10
"WebSocket entry" and `docs/DEPLOY_RUNBOOK.md` §2.4.

**Address history index, off by default.** `"addr_history_index": true` builds
a node-local address history index and answers the `dnac_addr_history` RPC;
it is not consensus state.

A chain validator additionally needs the chain's genesis and its own validator
key — see `docs/DEPLOY_RUNBOOK.md` §1.5 and `tools/genesis/README.md`.

### Systemd

The shipped units are in `deploy/`: `nodus.service` (the combined `nodus-server`,
`Restart=on-failure` with a start limit of 3 per 300 s — reproduced and explained in
`docs/ARCHITECTURE.md` §13 "Systemd Service") and, for a three-process node,
`nodus-core.service`, `nodus-storage.service`, `nodus-witness.service` (split S6; they
conflict with `nodus.service`; `docs/DEPLOY_RUNBOOK.md` "Three-process node").
`deploy/build-nodus.sh` installs them.

### Installer tarball (split S7)

Build a self-contained tar.gz from an existing build directory, then install it on a
host (decision `2026-10-01-nodus-component-split.md` item 26; where the tarball is
published and how it is signed is not decided yet):

```bash
deploy/make-dist.sh build /tmp/out
# -> /tmp/out/nodus-<version>-linux-<arch>.tar.gz (+ its SHA-256 printed)
#    five binaries of that build, four units, install.sh, README, VERSION, SHA256SUMS;
#    refuses on a missing binary or a version mismatch; no config, no identity

tar -xzf nodus-<version>-linux-<arch>.tar.gz && cd nodus-<version>-linux-<arch>
sudo ./install.sh --layout split --dry-run   # print the plan, change nothing
sudo ./install.sh --layout split             # core + storage + witness
sudo ./install.sh --layout split --no-witness   # core + storage (or --no-storage)
sudo ./install.sh --layout combined          # nodus.service
#   --prefix DIR (default /usr/local/bin), --config FILE (only if /etc/nodus.conf is absent)
```

`install.sh` verifies `SHA256SUMS`, refuses on two enabled layouts, installs binaries
and units atomically, moves `nodus.addr_seq` into the data directory on the first split
start, starts core → storage → witness and reports each unit's state. Full procedure and
rollback: `docs/DEPLOY_RUNBOOK.md` "tar.gz installer".

---

## Client SDK

The Nodus client SDK (`include/nodus/nodus.h`) is how applications reach the network: `libdna` uses it, and so does the web wallet's browser build. All connections are encrypted with AES-256-GCM after a KEM key exchange — ML-KEM-1024 when the server advertises a signed ML-KEM key, otherwise the legacy Kyber1024 round-3 (see "Channel Encryption" below). This protects connection content; it does not hide network metadata.

Calls are synchronous; the signatures below are copied from `include/nodus/nodus.h`.

```c
#include <nodus/nodus.h>

nodus_client_t client;
nodus_client_config_t cfg = { .servers = {{"203.0.113.10", 4001}}, .server_count = 1 };
nodus_client_init(&client, &cfg, &identity);   /* identity: the caller's nodus_identity_t */
nodus_client_connect(&client);                  /* KEM handshake + AES-256-GCM */

/* Store a value — the caller signs it with Dilithium5 */
nodus_client_put(&client, &key, data, data_len, type, ttl, vid, seq, &sig);

/* Read one value / every value stored under a key */
nodus_client_get(&client, &key, &val);
nodus_client_get_all(&client, &key, &vals, &count);

/* Batch read, batch count */
nodus_client_get_batch(&client, keys, key_count, &results, &result_count);
nodus_client_count_batch(&client, keys, key_count, &my_fp, &counts, &count_n);

/* Subscribe to key changes, presence query */
nodus_client_listen(&client, &key);
nodus_client_presence_query(&client, fps, fp_count, &presence);

/* Media: chunked put, metadata + chunk get */
nodus_client_media_put(&client, content_hash, chunk_index, chunk_count, total_size,
                       media_type, encrypted, ttl, chunk, chunk_len, &sig,
                       &complete, progress_cb, progress_user_data);
nodus_client_media_get_meta(&client, content_hash, &meta);
nodus_client_media_get_chunk(&client, content_hash, chunk_index, &chunk_out, &chunk_out_len);

nodus_client_close(&client);
```

---

## Channel Encryption (Kyber round-3 / ML-KEM-1024)

Client and inter-node TCP connections (ports 4001 and 4002) are encrypted with a KEM key exchange followed by AES-256-GCM symmetric encryption. The handshake occurs immediately after TCP connection, before any protocol messages are exchanged. This ensures all client operations, inter-node replication, and circuit relay traffic are protected against quantum adversaries. The chain p2p port 4004 has its own session: the ported CometBFT secret connection, ML-KEM-1024 only (decision `2026-09-26-witness-port-session.md`).

**KEM state** (`docs/plans/decisions/2026-09-23-kem-mlkem-migration.md`, rolling-compatible, no wire version bump): a node that has generated an ML-KEM-1024 (FIPS 203) keypair signs and advertises its public key (`mpk`/`mpk_sig`) in AUTH_OK, alongside the existing Kyber round-3 `kpk`/`kpk_sig` — unconditional, unchanged. A peer uses ML-KEM-1024 (`alg=1` on KEY_INIT) only when it has verified the OTHER side's signed `mpk`; a node never sends an ML-KEM ciphertext to a peer that did not itself advertise one. Every peer without an ML-KEM keypair still talks Kyber round-3 (NIST Level 5). This two-path state is the final one: the decision (K1 rev 2) publishes no forced update, so the Kyber round-3 fallback stays. The divergences from FIPS 203 in that legacy path are documented in `shared/crypto/enc/qgp_kyber.h` (the wrapper API; the underlying implementation is `shared/crypto/enc/kyber_r3_legacy.h`); the FIPS 203 implementation is `shared/crypto/enc/qgp_mlkem.h`. The `mpk`/`mpk_sig` binding uses a new purpose byte, `NODUS_PURPOSE_MLKEM_BIND` (0x09) — the first **tier-2** purpose to be STRICT (no raw-signature fallback either side), because its preimage is the same shape as `KYBER_BIND`'s and a non-strict signature here would be swappable with a `kpk_sig`. Circuits (VPN mesh) carry the same optional `alg`, but `alg=1` must not be used until every relay on the path forwards the tag, or an old relay silently drops it and the far end decapsulates with the wrong algorithm. An inbound E2E circuit whose `alg` this client cannot decapsulate is refused outright, never accepted with encryption silently disabled. See `docs/ARCHITECTURE.md` §5 for the wire format and the four handshake sites' exact fallback rule.

---

## Witness System (Nodus Chain)

Every node embeds a Nodus Chain validator. Consensus is a literal C port of **CometBFT v0.38.26** (`shared/dnac/cmt_*`; host glue in `src/witness/nodus_witness_cmt_*.c`): proposal, prevote, precommit and commit rounds as in the reference, with SHA3-512 hashes and ML-DSA-87 (Dilithium5) votes. The p2p layer runs on TCP 4004. Clients never talk to 4004: they submit transactions and read the chain through the `dnac_*` RPCs on TCP 4001, and the receiving node gossips a transaction to its peers through the mempool reactor.

**Light client package 1 (0.26.7, no caller yet).** For the planned Windows bandwidth / storage nodes, which must not execute blocks (`docs/plans/decisions/2026-10-16-relay-port-4003-bandwidth-role.md`, Kurultay #25 `docs/plans/decisions/2026-10-16-kurultay-25-summary.md`), `shared/dnac/` carries ports of cometbft v0.38.26's light-client building blocks: `cmt_light_verifier` (`light/verifier.go`, with the `VerifyCommitLightTrusting` family in `cmt_validation`), `cmt_light_block` (`types.LightBlock` and its SignedHeader / LightBlock proto codec), `cmt_light_store` (`light/store/db` over SQLite; its count accounting deliberately does not copy the reference's), `cmt_light_provider.h` (the provider interface only — in 0.26.7 the one implementation was the mock inside `tests/test_cmt_light_block.c`; 0.26.8 adds the pinned network provider `src/client/nodus_light_provider.c`), `cmt_fraction.h` (the `Fraction` type), and `cmt_time_after` / `cmt_time_add_ns` in `cmt_time` (moved from `cmt_cs.c`, bodies unchanged, shared with the verifier). Package 1 alone was not a light client; 0.26.8 adds the rest below. No consensus, wire, block or state-root change.

**Light client packages 2-3 + `dnac_light_block` (0.26.8, still no caller).** `cmt_light_client` ports `light/client.go` + `trust_options.go` (the provider contract — height match and `LightBlock.ValidateBasic` — is enforced by the client itself, `cmt_light_client.c` `provider_light_block`), and `cmt_light_detector` ports `light/detector.go` (full priority vector, Kurultay #25 K25-3; a detected attack STOPS the call and keeps a local record — evidence is never sent, Kurultay #25 item 2; the reference's in-call sleep is a two-call wait, DD2). The node answers the approved `dnac_light_block` RPC on 4001 (`docs/plans/decisions/2026-10-16-dnac-light-block-rpc.md`: `{"h"}` → `{"h","lb"}`, `lb` = the `tendermint.types.LightBlock` proto, seen commit at the tip and canonical below it, errors NOT_FOUND / HEIGHT_TOO_HIGH (22) / INTERNAL), and `nodus/src/client/nodus_light_provider.{c,h}` is the provider over it, which refuses an unpinned client (Kurultay #25 item 8). Nothing in a node or a client calls the light client or the provider yet; the light-client caps have no defaults, so a caller must choose them. 0.26.10 closes the items found before the RPC goes live (root `BUGS.md` Z-41 … Z-44, and the RATE_LIMITED / not-connected error classes of Z-45; Z-45's other parts and Z-46 stay open): the detector's moving-target wait (the stored target is judged after the wait), the attack that was reported as a local fault, how far "stop" reaches (a detected attack now locks the client until the operator clears it, with every record kept in the light store across restarts — Kurultay #25 K25-10), and the RPC's worst-case validator-set replay cost (measured; a node-wide limit of 4 builds per second, a refusal the provider treats as "no response"). 0.26.11 adds `nodus-light`, the program that runs the light client (Linux and a static Windows `.exe`), with the operator's trust root (`--trust-height` / `--trust-hash`). Still open: the release default checkpoint (empty until a real block is read through the live RPC), the RPC's deploy to live nodes, a run of the `.exe` on Windows, and a node-side caller. This is not a proven RPC.

**Block pace** is a compiled node setting, not a governed parameter: a 4 s commit timeout and, when no transaction is waiting, an empty block every 60 s (`src/witness/nodus_witness_cmt_node.c`). Chain-config parameter 2 (`BLOCK_INTERVAL_SEC`) has no effect on this lane.

**Voting authority is chain-derived:** the validator set is the stake-ranked active set, frozen per epoch into a committed validator-set snapshot; a validator's voting power is its stake / 10^8. The set size is the governance parameter `TARGET_ACTIVE_COUNT` (chain-config param 4, range [7, 32]). Every validator must produce a byte-identical state for every block — any divergence is a chain split and blocks deploy (Genesis Protocol harness enforces 7/7 identity).

**Upgrades.** The testnet (30 September 2026) is never wiped. A consensus, block-format, hash or state-root change is a hard fork that activates at a committed block height; the binaries roll out before that height (`docs/DEPLOY_RUNBOOK.md` §2.2).

Source: `src/witness/`

### Ledger V2 (the validator's only ledger engine)

The validator carries **one lane**: the Ledger V2 engine, driven by the CometBFT port. The legacy V1 lane (flat 5-leg `state_root`, block identity = batch digest, 144-byte finalization certificates) and the old PBFT round were deleted in R3 W4-D (`docs/ARCHITECTURE.md`, "THE DELETION of the closed lane").

- **Domain model** — state is partitioned into registered domains (SYSTEM, DNA_CORE; and EVM, domain 2, once the `EVM_ACTIVE` vote has taken effect — Nodus EVM below) with per-domain state roots composed into one global root; new state kinds register a domain instead of forking the root format.
- **Envelope transactions** — multi-leg envelopes with typed per-domain runtimes (verified authorization, mediated reads, metered execution) and a dual identity (`wire_id` + authorization-witness-stable `intent_id`). An entry that is not an envelope is classified as a genesis CLAIM (`nodus_witness_v2_classify_entry`, `src/witness/nodus_witness_v2_produce.c`); the older DNAC transaction format is not accepted as a transfer.
- **Atomic apply** — one host-owned SQLite transaction per decided CometBFT block, one SAVEPOINT per item (a refused item gets a nonzero result code and the block goes on), with deterministic fault-point rollback proofs. `nodus_witness_v2_apply_block()` refuses a block that does not come from the CometBFT lane.
- **Birth without an ancestor** — a chain is derived directly from an operator config (`config_version = 3`, the CometBFT genesis document) by `nodus_witness_v2_gen_derive_v3()` (`src/witness/nodus_witness_v2_gen.c`, run by `nodus-server --derive-v2-genesis`): validators, allocations and the genesis manifest come from the config, and the chain id is the hash of the stored genesis document. The one genesis is `nodus_witness_v2_genesis_cmt()`. A fill-in template for the ceremony config lives in `tools/genesis/`.

Activation authority is a property of the chain itself: `nodus_witness_v2_gate_authority_present()` (`src/witness/nodus_witness_v2_gate.c`) reads the chain's own committed height-0 genesis manifest and grants authority only when its `source_tag` is `NODUS_V2_GEN_SOURCE_TAG`. A manifest that cannot be read or decoded yields `NODUS_V2_GATE_FAULT` — never a silent "no authority".

### Storage reward — the block archive (live since HF-6, block 176100)

**Want to run a storage node?** Step by step, from an empty machine: [`docs/STORAGE_NODE.md`](docs/STORAGE_NODE.md).

Nodes that keep the block ARCHIVE are paid for it (the DHT is not rewarded). The archive is cut into segments of one payday period each (24 epochs = 17,280 blocks at production); each segment has a root over its block header hashes and is assigned to the R = 3 registered storage nodes closest (XOR) to a hash of that root. Each epoch the validators probe the assigned nodes (3 samples) over the witness channel and file the results on chain (`STORAGE_REPORT`, keyed by validator seat); each epoch is settled two epochs later, paying nodes from pool 1 in proportion to the eligible blocks they hold; three failed epochs in a row (`fail_streak` ≥ 3) skip a node until it recovers, and a node that takes over an existing segment gets a grace period. Segment files carry the validator set and the terminal commit, signature-checked, and are fetched between storage nodes over a second witness channel. CLI: `nodus-cli storage consent | register | exit | status` (`status --owner <hex128>` lists every storage node one owner registered) — a storage node is registered and taken out by its OWNER (the owner signs, pays the 1M-NODUS bond and receives the reward; the node's key only signs a consent; the web wallet's Nodus page does the owner's part), and a validator's report about a storage node of the same owner or the same key does not count (`docs/DEPLOY_RUNBOOK.md` §2.6). It came into force with HF-6: chain-config id 18 `RULESET_GEN_ROLES` (exactly the build's D4 literal, 7217855907516077065 = 0x642af9b4bf735409), voted in block 175307 and effective from block 176100 (2026-10-13, nodus 0.26.0), switched the chain from the EVM generation 3 to generation 4 (SYSTEM v10 / CORE v9) and opened storage AND the HF-6 validator role in one generation; id 16 `RULESET_GEN_STORAGE` is retired. It is compiled only into EVM-enabled builds. Full mechanism: `docs/ARCHITECTURE.md` "Storage reward v1" sections; the fork record: `docs/DEPLOY_RUNBOOK.md` §2.2 table.

### Nodus EVM (HF-5, 0.24.0)

An EVM written for this project (`shared/evm/`, Prague semantics pinned to `ethereum/execution-specs @a87891f7`, 32-byte addresses, the full Prague precompile set from vendored, version-pinned libraries) runs as the chain's THIRD domain, inside rule-set generation 3. It is **inactive until a committed chain-config vote**: id 14 `EVM_ACTIVE` (value exactly the build's activation digest D) switches SYSTEM / CORE from generation 2 to 3 and registers the EVM domain at the end of block H−1; id 15 `EVM_BLOCK_GAS_LIMIT` bounds a block's declared EVM gas. Until then the EVM path is inert — the activation phase does nothing on a chain without a param-14 row (`src/witness/nodus_witness_v2_apply.c` `phase_6b_evm_activation`; `test_v2_evm`'s inertness twin) — except that the binary's first open migrates the witness database to schema S17 (empty EVM tables), which 0.23.18 cannot open (`docs/DEPLOY_RUNBOOK.md` §4.1). Every EVM transaction is the pair `[CORE EVMFUND] + [EVM op]`: CORE pays the fee into the reward pool and moves NODUS into or out of the CORE EVM reserve (1 raw unit = 10^10 wei); a reverted or out-of-gas call is still applied and pays its fee. The node starts only if the EVM precompile self-test passes — on x86-64 that needs AVX + BMI2 + ADX (SHA-256 / RIPEMD-160 come from vendored, pinned code, not the host OpenSSL); building needs `m4` and `xz` (`docs/DEPLOY_RUNBOOK.md` top) and `xxd` (`nodus/CMakeLists.txt`, the embedded KZG setup). The gas limits are placeholders until a measurement; there is no deploy / vote procedure for HF-5 in the runbook yet. **0.24.1 (Kurultay #9, 2026-10-06):** EVM ruleset v2 — a bridge DEPOSIT / WITHDRAW from an account that carries code is refused (EIP-3607 on the bridge), and the address width (32) is committed in the activation digest D; D and the EVM ruleset hash changed, so a 0.24.0 binary and a 0.24.1 binary vote different D. Full mechanism: `docs/ARCHITECTURE.md` "Nodus EVM (HF-5, v0.24.0)"; commands: `nodus-cli evm` above.

---

## Circuit Relay

Nodus provides a peer-to-peer circuit relay for VPN mesh connectivity. Circuits are established via TCP 4001 (`circ_open`, `circ_data`, `circ_close`) and forwarded between nodes via TCP 4002 (`ri_open`, `ri_data`, `ri_close`). Circuits opened with `nodus_circuit_open_e2e()` are encrypted end to end (KEM key exchange + AES-256-GCM), so relay nodes forward opaque payloads; plain `nodus_circuit_open()` circuits remain cleartext at the relay. This is endpoint-to-endpoint encryption, not per-hop onion routing: relay servers still learn the source and destination fingerprints. See `docs/CIRCUIT_PROTOCOL.md` for the full protocol specification.

Source: `src/circuit/`

---

## Documentation

| Doc | Description |
|-----|-------------|
| [Architecture](docs/ARCHITECTURE.md) | Nodus system architecture and design |
| [Deploy Runbook](docs/DEPLOY_RUNBOOK.md) | Deploy procedure, health checks, rollback |
| [Running a storage node](docs/STORAGE_NODE.md) | Step-by-step guide for a new storage node operator |
| [Mempool & Block Time](docs/MEMPOOL_BLOCK_TIME.md) | Mempool, block timing, witness rounds |
| [Bootstrap](docs/BOOTSTRAP.md) | Node bootstrap procedure |
| [Circuit Protocol](docs/CIRCUIT_PROTOCOL.md) | Circuit relay protocol specification |
| [Replication Issues](docs/REPLICATION_ISSUES.md) | Known replication issues and fixes |
| [DNA Nodus Deployment](../messenger/docs/DNA_NODUS.md) | Full deployment guide |
| [DHT System](../messenger/docs/DHT_SYSTEM.md) | DHT architecture |
| [P2P Architecture](../messenger/docs/P2P_ARCHITECTURE.md) | Transport layer |

---

## License

Licensed under the [Apache License 2.0](LICENSE).
