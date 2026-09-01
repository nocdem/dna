# Nodus — Post-Quantum DHT Server

<p align="center">
  <strong>Pure C Kademlia DHT with Dilithium5 signatures and Kyber1024 encryption</strong>
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/License-Apache%202.0-blue" alt="Apache 2.0"></a>
  <a href="#status"><img src="https://img.shields.io/badge/Status-RC%20v0.19.29-orange" alt="RC"></a>
  <a href="#security"><img src="https://img.shields.io/badge/Crypto-Dilithium5%20(FIPS%20204)-red" alt="Dilithium5"></a>
</p>

---

## What is Nodus?

Nodus is the distributed hash table (DHT) infrastructure for the DNA ecosystem. It provides decentralized storage, replication, and real-time subscriptions — all signed with post-quantum cryptography. The network is open — anyone can run a Nodus node and join.

- **Pure C** — No C++ dependencies, minimal footprint
- **Dilithium5 signatures** — All stored values cryptographically signed (FIPS 204)
- **Kyber1024 channel encryption** — All client connections encrypted (Kyber round-3 key exchange + AES-256-GCM; *not* ML-KEM/FIPS 203 — see `shared/crypto/enc/qgp_kyber.h`)
- **Cluster management** — Heartbeat-based health monitoring with Kademlia replication
- **512-bit keyspace** — Kademlia routing with k=8 buckets
- **7-day TTL** — Values persist across restarts with SQLite storage
- **CBOR wire format** — Efficient binary serialization
- **Embedded DNA Chain witness** — BFT consensus for DNA Chain (DNAC) transactions
- **Circuit relay** — Peer-to-peer VPN mesh with onion-style E2E encryption
- **Media storage and replication** — Binary blob storage with cluster-wide replication
- **Multi-token support** — Custom token creation and management on the DNA Chain
- **Open network** — Community-managed, anyone can run a node

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Nodus Server                              │
├──────────────────────────────────────────────────────────────────┤
│              Kyber1024 Encryption Layer (AES-256-GCM)            │
├──────────┬──────────┬──────────┬──────────┬──────────────────────┤
│ UDP 4000 │ TCP 4001 │ TCP 4002 │ TCP 4003 │ TCP 4004             │
│ Kademlia │ Client   │ Inter-   │ Channels │ Witness BFT          │
│          │          │ node     │          │                      │
│ ping     │ auth     │ repl.    │ channel  │ PROPOSE              │
│ find_node│ dht_put  │ heartbt  │ subs     │ PREVOTE              │
│ store    │ dht_get  │ circuit  │ (idle)   │ PRECOMMIT            │
│ find_val │ get_batch│ fwd      │          │ COMMIT               │
│          │ cnt_batch│          │          │                      │
│          │ listen   │          │          │                      │
│          │ presence │          │          │                      │
│          │ circuits │          │          │                      │
│          │ media    │          │          │                      │
├──────────┴──────────┴──────────┴──────────┴──────────────────────┤
│  Kademlia Routing   │  Cluster Management  │  Witness BFT        │
│  512-bit keyspace   │  Heartbeat health    │  DNAC consensus      │
│  k=8 buckets        │  K-closest repl.     │  PBFT phases         │
├─────────────────────┴──────────────────────┴─────────────────────┤
│  SQLite Storage     │  Presence Table      │  Media Storage       │
│  7-day TTL          │  45s TTL, p_sync 30s │  Binary blobs        │
└──────────────────────────────────────────────────────────────────┘
```

**Five Network Ports:**

| Port | Protocol | Purpose |
|------|----------|---------|
| UDP 4000 | Kademlia | Peer discovery (ping, find_node, store, find_value) |
| TCP 4001 | Client | Auth, dht_put, dht_get, get_batch, cnt_batch, listen, presence, circuits, media |
| TCP 4002 | Inter-node | Cluster replication, heartbeat, circuit forwarding |
| TCP 4003 | Channels | Dedicated channel traffic (currently disabled) |
| TCP 4004 | Witness BFT | DNAC consensus (PROPOSE, PREVOTE, PRECOMMIT, COMMIT) |

**Wire Protocol:** CBOR over framed TCP/UDP — 7-byte header (magic `0x4E44` + version + length)

---

## Source Layout

```
nodus/
├── src/
│   ├── server/      # Server event loop (epoll), nodus_server.c
│   ├── client/      # Client SDK, nodus_client.c
│   ├── protocol/    # Wire protocol, Tier 1 + Tier 2 dispatch
│   ├── core/        # Kademlia routing, storage
│   ├── transport/   # UDP/TCP transport
│   ├── channel/     # Channel/subscription system
│   ├── consensus/   # Cluster heartbeat + membership management
│   ├── crypto/      # Nodus-specific crypto helpers
│   ├── circuit/     # Circuit relay for P2P VPN mesh (onion-style E2E encryption)
│   └── witness/     # DNA Chain BFT witness (embedded in nodus-server; legacy + Ledger V2 lanes)
├── include/
│   └── nodus/
│       ├── nodus.h       # Client SDK public API
│       └── nodus_types.h # Constants, version
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
- `nodus-server` — DHT server binary
- `nodus-cli` — CLI tool for testing and chain operations
- `nodus-circ` — circuit relay test tool
- `test_*` — Unit test binaries

## Run Tests

```bash
cd nodus/build
ctest --output-on-failure    # 200 registered tests (~125 test source files)
```

**Test coverage (representative areas — `ctest` runs all):**

| Area | Examples |
|------|-----------|
| Core Kademlia | `test_routing`, `test_bucket_refresh`, `test_storage`, `test_value`, `test_hashring` |
| Client SDK | `test_client`, `test_tier2`, `test_tcp`, `test_fetch_batch` |
| Protocol | `test_tier1`, `test_tier3`, `test_wire`, `test_cbor`, `test_strict_decoder` |
| Auth | `test_inter_auth`, `test_udp_auth`, `test_identity`, `test_sign_domain_separation` |
| Channels | `test_channel_*` (channel system currently disabled in production) |
| Circuits (VPN mesh) | `test_circuit_wire`, `test_circuit_table`, `test_circuit_live` |
| Media / DHT features | `test_media_storage`, `test_media_tier2`, `test_put_if_newer`, `test_hinted_handoff` |
| Presence / Server | `test_presence`, `test_server` |
| Witness / BFT | `test_witness_verify`, `test_witness_cert_verify`, `test_bft_quorum_formula`, `test_commit_atomicity`, `test_vset_*`, `test_qc_v2` |
| Merkle / state_root | `test_witness_merkle`, `test_merkle_proof`, `test_state_root_4subtree`, `test_merkle_scan_fail_close` |
| Ledger V2 | `test_v2_apply`, `test_v2_native`, `test_v2_epoch`, `test_v2_finalize`, `test_v2_produce`, `test_block_v2`, `test_v2_qc_authority`, `test_domain_wire`, `test_v2_pools`, `test_v2_claims` |

Integration tests (Genesis Protocol harness, 7-node localhost):
```bash
bash nodus/tests/integration/stagef/stagef_up.sh
```

---

## Deployment

### Configuration

Config file: `/etc/nodus.conf`

Each node seeds the other nodes in the cluster:
```
# /etc/nodus.conf on node-1
listen_port = 4000
tcp_port = 4001
data_dir = /var/lib/nodus
seed_nodes = 164.68.105.227:4000,164.68.116.180:4000
```

### Systemd

```ini
# /etc/systemd/system/nodus.service
[Unit]
Description=Nodus DHT Server
After=network.target

[Service]
ExecStart=/usr/local/bin/nodus-server -c /etc/nodus.conf
Restart=always

[Install]
WantedBy=multi-user.target
```

### Current Nodes (community-managed)

| Node | IP | UDP | TCP |
|------|-----|-----|-----|
| US-1 | 154.38.182.161 | 4000 | 4001 |
| EU-1 | 161.97.85.25 | 4000 | 4001 |
| EU-2 | 156.67.24.125 | 4000 | 4001 |
| EU-3 | 156.67.25.251 | 4000 | 4001 |
| EU-4 | 164.68.105.227 | 4000 | 4001 |
| EU-5 | 164.68.116.180 | 4000 | 4001 |
| EU-6 | 75.119.141.51 | 4000 | 4001 |

---

## Client SDK

The Nodus client SDK (`include/nodus/nodus.h`) is used by DNA Connect to connect to the DHT network. All connections are encrypted with Kyber1024 key exchange + AES-256-GCM.

```c
#include <nodus/nodus.h>

// Connect (Kyber1024 encrypted)
nodus_client_t *client = nodus_client_create(config);
nodus_client_connect(client, "154.38.182.161", 4001);

// Store a value (signed with Dilithium5)
nodus_client_put(client, key, value, value_len, callback, userdata);

// Retrieve a value
nodus_client_get(client, key, callback, userdata);

// Batch retrieve multiple values
nodus_client_get_batch(client, keys, key_count, callback, userdata);

// Count values by prefix
nodus_client_cnt_batch(client, prefix, prefix_len, callback, userdata);

// Subscribe to key changes
nodus_client_listen(client, key, on_update, userdata);

// Presence query
nodus_client_presence_query(client, fingerprints, count, callback, userdata);

// Media storage
nodus_client_media_put(client, key, data, data_len, callback, userdata);
nodus_client_media_get(client, key, callback, userdata);
```

---

## Kyber Channel Encryption

All TCP connections (ports 4001 and 4002) are encrypted with Kyber1024 key exchange (Kyber **round-3**, NIST Level 5 — this is *not* ML-KEM-1024 and *not* FIPS 203; the divergences are documented in `shared/crypto/enc/qgp_kyber.h`) followed by AES-256-GCM symmetric encryption. The handshake occurs immediately after TCP connection, before any protocol messages are exchanged. This ensures all client operations, inter-node replication, and circuit relay traffic are protected against quantum adversaries.

---

## Witness System (DNA Chain)

Nodus embeds the DNA Chain witness for BFT consensus on DNAC transactions. The witness runs on TCP port 4004 and implements PBFT-style consensus with four phases: PROPOSE, PREVOTE, PRECOMMIT, and COMMIT. The leader collects pending transactions from the mempool and proposes blocks at 5-second intervals (max 10 TXs per round); non-leader nodes forward received transactions to the current leader.

**Voting authority is chain-derived, not gossip-derived:** the committee is the stake-ranked active validator set, frozen per epoch into a committed validator-set snapshot. Quorum is `dna_bft_quorum(n) = (2n)/3 + 1` over the set governing the height (7 seats ⇒ 5); leader election rotates `(epoch + view) % N`. The committee size is a governance parameter (`TARGET_ACTIVE_COUNT`, chain-config param 4). Every witness must produce a byte-identical `state_root` per block — any divergence is a chain split and blocks deploy (Genesis Protocol harness enforces 7/7 identity).

Source: `src/witness/`

### Ledger V2 (successor chain — staged for activation)

The witness carries **two lanes in one binary**. The legacy lane (V1) is what the live chain runs today: flat 5-leg `state_root`, block identity = batch digest, 144-byte finalization certificates. The **Ledger V2** lane is the successor architecture, built and tested across the S1–O15F seasons and staged for activation:

- **Canonical block identity** — 413-byte BlockHeader v3, BlockID over the full header, quorum certificates (QC v2) bound to the committed validator-set snapshot.
- **Domain model** — state is partitioned into registered domains (SYSTEM, DNA_CORE) with per-domain state roots composed into one global root; new state kinds register a domain instead of forking the root format.
- **Envelope transactions** — multi-leg envelopes with typed per-domain runtimes (verified authorization, mediated reads, metered execution) and a dual identity (`wire_id` + authorization-witness-stable `intent_id`).
- **Atomic apply** — one SQLite transaction per global block with deterministic fault-point rollback proofs.
- **Birth without an ancestor** — a V2 chain is derived directly from an operator config by `nodus_witness_v2_gen_derive()` (`src/witness/nodus_witness_v2_gen.c`): validators, allocations and the genesis manifest come from the config, and the chain id is the manifest hash. There is no V1→V2 migration and none is planned — moving to V2 means **wiping the V1 chain and starting fresh**.

Ledger V2 is **no longer compile-gated**. The `NODUS_V2_ACTIVATION` CMake option and the whole V1→V2 activation ceremony (quorum-voted SCHEDULE / all-validator READY, the terminal-chain seam, TX types 15 and 16) were removed in season O15J Faz 3.

Activation authority is now a property of the chain itself: `nodus_witness_v2_gate_authority_present()` (`src/witness/nodus_witness_v2_gate.c`) reads the chain's own committed height-0 genesis manifest and grants authority only when its `source_tag` is `NODUS_V2_GEN_SOURCE_TAG` (`"DNA.GENESIS.v1"`). A manifest that cannot be read or decoded yields `NODUS_V2_GATE_FAULT` — never a silent "no authority". A pure-V2 chain therefore opens the gate and arms its V2 ingress at database open, in an ordinary default build.

Nothing about this changes what is deployed: the production cluster still runs the V1 chain, and this change deploys nothing by itself. The grounded V1↔V2 difference reference is [`../docs/ledger-v1-vs-v2.md`](../docs/ledger-v1-vs-v2.md); season-by-season detail lives in [`CLAUDE.md`](CLAUDE.md).

---

## Circuit Relay

Nodus provides a peer-to-peer circuit relay for VPN mesh connectivity. Circuits are established via TCP 4001 (`circ_open`, `circ_data`, `circ_close`) and forwarded between nodes via TCP 4002 (`ri_open`, `ri_data`, `ri_close`). End-to-end encryption uses Kyber1024 key exchange, providing onion-style privacy where relay nodes cannot read the payload. See `docs/CIRCUIT_PROTOCOL.md` for the full protocol specification.

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
| [Replication Design](docs/REPLICATION_DESIGN.md) | DHT value replication strategy |
| [Replication Issues](docs/REPLICATION_ISSUES.md) | Known replication issues and fixes |
| [Dynamic Witness Design](docs/DYNAMIC_WITNESS_DESIGN.md) | Witness discovery and roster (superseded for BFT voting — the committee is chain-derived since F17) |
| [Version Enforcement](docs/PLAN_VERSION_ENFORCEMENT.md) | Version update enforcement plan |
| [Channel Rewrite Design](docs/archive/CHANNEL_REWRITE_DESIGN.md) | Channel TCP 4003 redesign (archived — channels disabled) |
| [DNA Nodus Deployment](../messenger/docs/DNA_NODUS.md) | Full deployment guide |
| [DHT System](../messenger/docs/DHT_SYSTEM.md) | DHT architecture |
| [P2P Architecture](../messenger/docs/P2P_ARCHITECTURE.md) | Transport layer |

---

## License

Licensed under the [Apache License 2.0](LICENSE).
