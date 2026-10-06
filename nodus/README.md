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

TCP 4003 (`NODUS_DEFAULT_CH_PORT`, channels) is still defined, but the channel server is compiled out (`NODUS_CHANNELS_DISABLED`, `nodus/CMakeLists.txt`); the port is not opened.

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
- `nodus-storage` — the DHT / storage half (`nodus.db`, `channels.db`, routing, replication) as its own process (component split S5b); refuses to start unless `storage_external` is set.
- `nodus-witness` — the chain witness (4004 p2p + consensus) as its own process (component split S3); refuses to start unless the config sets `witness_external`.
- Same options and config file for all four. Split layouts are opt-in and **not declared deployable yet** (`docs/DEPLOY_RUNBOOK.md` "Three-process node" — open items); systemd units for the three-process node are in `deploy/`. See `docs/ARCHITECTURE.md` §10 "Component split".
- `nodus-cli` — CLI tool for testing and chain operations
- `nodus-circ` — circuit relay test tool
- `test_*` — Unit test binaries

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
| 0.20.0+ — the 4004 p2p port, block sync, WebSocket entry, address history index | `test_p2p_secret`, `test_p2p_mconn`, `test_p2p_switch`, `test_p2p_pex`, `test_witness_p2p`, `test_network_file`, `test_cmt_autofile`, `test_cc_collect`, `test_cmt_bsync_msgs`, `test_cmt_bsync_pool`, `test_cmt_bsync_reactor`, `test_ws_frame`, `test_ws_upgrade`, `test_ws_server`, `test_v3_block_query`, `test_addr_index` |
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

### Storage reward — the block archive (0.25.0, not voted)

Nodes that keep the block ARCHIVE are paid for it (the DHT is not rewarded). The archive is cut into segments of one payday period each (24 epochs = 17,280 blocks at production); each segment has a root over its block header hashes and is assigned to the R = 3 registered storage nodes closest (XOR) to a hash of that root. Each epoch the validators probe the assigned nodes (3 samples) over the witness channel and file the results on chain (`STORAGE_REPORT`, keyed by validator seat); each epoch is settled two epochs later, paying nodes from pool 1 in proportion to the eligible blocks they hold; three failed epochs in a row (`fail_streak` ≥ 3) skip a node until it recovers, and a node that takes over an existing segment gets a grace period. Segment files carry the validator set and the terminal commit, signature-checked, and are fetched between storage nodes over a second witness channel. CLI: `nodus-cli storage register | exit | status`. It is **inactive until a committed chain-config vote**: id 16 `RULESET_GEN_STORAGE` (exactly the build's vote literal, 896171186953543716) switches from the EVM generation 3 to generation 4 (SYSTEM v9 / CORE v7), and the chain refuses that vote until HF-5 is in force; it is compiled only into EVM-enabled builds. Full mechanism: `docs/ARCHITECTURE.md` "Storage reward v1" sections; vote procedure: `docs/DEPLOY_RUNBOOK.md` fork table.

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
