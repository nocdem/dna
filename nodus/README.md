# Nodus — Post-Quantum DHT Server

<p align="center">
  <strong>Pure C Kademlia DHT with Dilithium5 signatures and Kyber1024 encryption</strong>
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/License-Apache%202.0-blue" alt="Apache 2.0"></a>
  <a href="#status"><img src="https://img.shields.io/badge/Status-RC%20v0.10.30-orange" alt="RC"></a>
  <a href="#security"><img src="https://img.shields.io/badge/Crypto-Dilithium5%20(FIPS%20204)-red" alt="Dilithium5"></a>
</p>

---

## What is Nodus?

Nodus is the distributed hash table (DHT) infrastructure for the DNA ecosystem. It provides decentralized storage, replication, and real-time subscriptions — all signed with post-quantum cryptography. The network is open — anyone can run a Nodus node and join.

- **Pure C** — No C++ dependencies, minimal footprint
- **Dilithium5 signatures** — All stored values cryptographically signed (FIPS 204)
- **Kyber1024 channel encryption** — All client connections encrypted (FIPS 203 key exchange + AES-256-GCM)
- **Cluster management** — Heartbeat-based health monitoring with Kademlia replication
- **512-bit keyspace** — Kademlia routing with k=8 buckets
- **7-day TTL** — Values persist across restarts with SQLite storage
- **CBOR wire format** — Efficient binary serialization
- **Embedded DNAC witness server** — BFT consensus for digital cash transactions
- **Circuit relay** — Peer-to-peer VPN mesh with onion-style E2E encryption
- **Media storage and replication** — Binary blob storage with cluster-wide replication
- **Multi-token support** — Custom token creation and management via DHT
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
│   ├── consensus/   # Cluster health + leader election
│   ├── crypto/      # Nodus-specific crypto helpers
│   ├── circuit/     # Circuit relay for P2P VPN mesh (onion-style E2E encryption)
│   └── witness/     # DNAC BFT witness (embedded in nodus-server, PBFT consensus)
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
- `nodus-cli` — CLI tool for testing
- `test_*` — Unit test binaries

## Run Tests

```bash
cd nodus/build
ctest --output-on-failure    # All 41 unit tests
```

**Test Coverage:**

| Area | Test Files |
|------|-----------|
| Core Kademlia | `test_routing`, `test_routing_stale`, `test_bucket_refresh`, `test_storage`, `test_storage_cleanup`, `test_value`, `test_hashring` |
| Client SDK | `test_client`, `test_tier2`, `test_tcp`, `test_fetch_batch` |
| Channels | `test_channel_primary`, `test_channel_protocol`, `test_channel_replication`, `test_channel_ring`, `test_channel_server`, `test_channel_store`, `test_channel_crypto`, `test_channel_encrypted` |
| Circuits | `test_circuit_wire`, `test_circuit_table`, `test_circuit_ri_wire`, `test_circuit_live`, `test_circuit_cross_live` |
| Media | `test_media_storage`, `test_media_tier2` |
| Batch | `test_batch_forward`, `test_batch_forward_live`, `test_batch_real_data` |
| Auth | `test_inter_auth`, `test_udp_auth`, `test_identity` |
| Server | `test_server` |
| Presence | `test_presence` |
| DHT Features | `test_put_if_newer`, `test_hinted_handoff` |
| Protocol | `test_tier1`, `test_tier3`, `test_wire`, `test_cbor` |
| Witness | `test_witness_verify` |

Integration tests (requires SSH access to test cluster):
```bash
bash nodus/tests/integration_test.sh
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

All TCP connections (ports 4001 and 4002) are encrypted with Kyber1024 key exchange (FIPS 203) followed by AES-256-GCM symmetric encryption. The handshake occurs immediately after TCP connection, before any protocol messages are exchanged. This ensures all client operations, inter-node replication, and circuit relay traffic are protected against quantum adversaries.

---

## Witness System

Nodus embeds a DNAC witness server for BFT consensus on digital cash transactions. The witness runs on TCP port 4004 and implements PBFT (Practical Byzantine Fault Tolerance) with four phases: PROPOSE, PREVOTE, PRECOMMIT, and COMMIT. The leader node collects pending transactions from the mempool and proposes blocks at 5-second intervals (max 10 TXs per round). Non-leader nodes forward received transactions to the current leader.

Source: `src/witness/`

---

## Circuit Relay

Nodus provides a peer-to-peer circuit relay for VPN mesh connectivity. Circuits are established via TCP 4001 (`circ_open`, `circ_data`, `circ_close`) and forwarded between nodes via TCP 4002 (`ri_open`, `ri_data`, `ri_close`). End-to-end encryption uses Kyber1024 key exchange, providing onion-style privacy where relay nodes cannot read the payload. See `docs/CIRCUIT_PROTOCOL.md` for the full protocol specification.

Source: `src/circuit/`

---

## Documentation

| Doc | Description |
|-----|-------------|
| [DNA Nodus Deployment](../messenger/docs/DNA_NODUS.md) | Full deployment guide |
| [DHT System](../messenger/docs/DHT_SYSTEM.md) | DHT architecture |
| [P2P Architecture](../messenger/docs/P2P_ARCHITECTURE.md) | Transport layer |
| [Architecture](docs/ARCHITECTURE.md) | Nodus system architecture and design |
| [Circuit Protocol](docs/CIRCUIT_PROTOCOL.md) | Circuit relay protocol specification |
| [Replication Design](docs/REPLICATION_DESIGN.md) | DHT value replication strategy |
| [Channel Rewrite Design](docs/CHANNEL_REWRITE_DESIGN.md) | Channel TCP 4003 redesign |
| [Dynamic Witness Design](docs/DYNAMIC_WITNESS_DESIGN.md) | Witness discovery and roster |
| [Version Enforcement](docs/PLAN_VERSION_ENFORCEMENT.md) | Version update enforcement plan |

---

## License

Licensed under the [Apache License 2.0](LICENSE).
