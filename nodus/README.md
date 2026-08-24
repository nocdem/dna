# Nodus — Post-Quantum DHT Server

<p align="center">
  <strong>Pure C Kademlia DHT with Dilithium5 signatures and Kyber1024 encryption</strong>
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/License-Apache%202.0-blue" alt="Apache 2.0"></a>
  <a href="#status"><img src="https://img.shields.io/badge/Status-RC%20v0.18.22-orange" alt="RC"></a>
  <a href="#security"><img src="https://img.shields.io/badge/Crypto-Post--quantum-red" alt="Post-quantum cryptography"></a>
</p>

---

## What is Nodus?

Nodus is the distributed hash table (DHT) infrastructure for the DNA ecosystem.
It provides decentralized storage, replication and real-time subscriptions.
The software is designed for independently operated nodes; admission and
reachability of any particular deployment are operational facts, not something
the source tree alone can prove.

- **Pure C** — No C++ dependencies, minimal footprint
- **Dilithium5 signatures** — All stored values cryptographically signed using the ML-DSA-87 algorithm profile; no validation or certification claim
- **Kyber1024 channel encryption** — Authenticated TCP client channels use Kyber round-3 key exchange + AES-256-GCM; UDP 4000 is outside this channel layer (*not* ML-KEM/FIPS 203 — see `shared/crypto/enc/qgp_kyber.h`)
- **Cluster management** — Heartbeat-based health monitoring with Kademlia replication
- **512-bit keyspace** — Kademlia routing with k=8 buckets
- **Configurable TTL** — 7 days is the default; permanent/exclusive values and
  values with TTL 0 do not expire
- **CBOR wire format** — Efficient binary serialization
- **Embedded DNAC witness server** — BFT consensus for digital cash transactions
- **Circuit relay** — Peer-to-peer relay with optional per-circuit E2E
  encryption; it is not onion-routed
- **Media storage and replication** — Binary blob storage with cluster-wide replication
- **DNAC witness integration** — Custom-token state is managed by witness
  consensus, not by the DHT value store
- **Independent operation** — The server can be built and operated by third
  parties; live-network policy is deployment-specific

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Nodus Server                              │
├──────────────────────────────────────────────────────────────────┤
│      TCP 4001/4002 Kyber1024 + AES-256-GCM channel layer         │
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
│  per-value TTL      │  45s TTL, p_sync 30s │  Binary blobs        │
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
│   ├── circuit/     # Circuit relay; optional endpoint-to-endpoint encryption
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
cmake -S nodus -B nodus/build -DCMAKE_BUILD_TYPE=Release
cmake --build nodus/build -j"$(nproc)"
```

Produces:
- `nodus-server` — DHT server binary
- `nodus-cli` — CLI tool for testing
- `test_*` — Unit test binaries

## Run Tests

```bash
ctest --test-dir nodus/build --output-on-failure
```

The standalone CMake tree currently registers 140 CTest entries, including the
benchmark-labelled tests. Because this count changes as coverage is added, use
`ctest --test-dir nodus/build -N` for the configured build rather than copying
an old count into automation. Coverage spans Kademlia/storage, protocol and
transport, channels, circuits, media, authentication, witness consensus,
Merkle/state-root logic, staking/delegation, chain configuration and failure
injection.

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

### Documented network endpoints

These endpoints are operational configuration carried in the repository.
Verify reachability and deployed versions independently before relying on them.

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

The Nodus client SDK (`include/nodus/nodus.h`) is used by DNA Connect to
connect to the DHT network. The authenticated TCP client path negotiates a
Kyber1024 round-3 shared secret and protects subsequent payloads with
AES-256-GCM. UDP 4000 Kademlia datagrams are framed but are not protected by
that TCP channel.

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

Authenticated TCP connections on ports 4001 and 4002 negotiate Kyber1024 key
exchange (Kyber **round-3**, NIST Category 5 target — this is *not*
ML-KEM-1024 and *not* FIPS 203; the divergences are documented in
`shared/crypto/enc/qgp_kyber.h`) followed by AES-256-GCM symmetric
encryption. This protects connection content at the cryptographic layer; it
does not protect UDP 4000, hide network metadata or constitute an independent
security certification.

---

## Witness System

Nodus embeds a DNAC witness server for BFT consensus on digital-cash
transactions. The witness runs on TCP port 4004 and implements PBFT-like
PROPOSE, PREVOTE, PRECOMMIT and COMMIT phases. The compile-time default proposal
interval is 5 seconds and the hard batch cap is 10 transactions; active chain
configuration can change the interval and lower the effective batch maximum.
Non-leader nodes forward received transactions to the current leader.

Source: `src/witness/`

---

## Circuit Relay

Nodus provides a peer-to-peer circuit relay. Circuits are established via TCP
4001 (`circ_open`, `circ_data`, `circ_close`) and forwarded between nodes
via TCP 4002 (`ri_open`, `ri_data`, `ri_close`). Calls opened with
`nodus_circuit_open_e2e()` use a peer Kyber key and AES-256-GCM so relay nodes
forward opaque payloads. Plain `nodus_circuit_open()` circuits remain
cleartext at the relay. This is endpoint-to-endpoint encryption, not per-hop
onion routing: relay servers still learn the source and destination
fingerprints. See `docs/CIRCUIT_PROTOCOL.md`.

Source: `src/circuit/`

---

## Documentation

| Doc | Description |
|-----|-------------|
| [DNA Nodus Deployment](../messenger/docs/DNA_NODUS.md) | Full deployment guide |
| [DHT System](../messenger/docs/DHT_SYSTEM.md) | DHT architecture |
| [P2P Architecture](../messenger/docs/P2P_ARCHITECTURE.md) | Transport layer |
| [Architecture](docs/ARCHITECTURE.md) | Nodus system architecture and design |
| [Bootstrap](docs/BOOTSTRAP.md) | Node bootstrap and peer discovery |
| [Circuit Protocol](docs/CIRCUIT_PROTOCOL.md) | Circuit relay protocol specification |
| [Deployment Runbook](docs/DEPLOY_RUNBOOK.md) | Operational deployment procedure |
| [Mempool and Block Time](docs/MEMPOOL_BLOCK_TIME.md) | Witness batching and timing |
| [Replication Issues](docs/REPLICATION_ISSUES.md) | Known replication limitations |
| [Performance Baselines](docs/perf_baselines/README.md) | Benchmark capture and comparison |

---

## License

Licensed under the [Apache License 2.0](LICENSE).
