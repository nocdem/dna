# Nodus — Post-Quantum DHT Server

<p align="center">
  <strong>Pure C Kademlia DHT with Dilithium5 signatures</strong>
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/License-Apache%202.0-blue" alt="Apache 2.0"></a>
  <a href="#status"><img src="https://img.shields.io/badge/Status-RC%20v0.6.3-orange" alt="RC"></a>
  <a href="#security"><img src="https://img.shields.io/badge/Crypto-Dilithium5%20(FIPS%20204)-red" alt="Dilithium5"></a>
</p>

---

## What is Nodus?

Nodus is the distributed hash table (DHT) infrastructure for the DNA ecosystem. It provides decentralized storage, replication, and real-time subscriptions — all signed with post-quantum cryptography. The network is open — anyone can run a Nodus node and join.

- **Pure C** — No C++ dependencies, minimal footprint
- **Dilithium5 signatures** — All stored values cryptographically signed (FIPS 204)
- **Cluster management** — Heartbeat-based health monitoring with Kademlia replication
- **512-bit keyspace** — Kademlia routing with k=8 buckets
- **7-day TTL** — Values persist across restarts with SQLite storage
- **CBOR wire format** — Efficient binary serialization
- **Open network** — Community-managed, anyone can run a node

---

## Architecture

```
┌─────────────────────────────────────────────┐
│              Nodus Server                    │
├─────────────────────────────────────────────┤
│  UDP 4000          │  TCP 4001              │
│  Tier 1: Kademlia  │  Tier 2: Client        │
│  ─────────────     │  ───────────────       │
│  ping              │  auth (Dilithium5)     │
│  find_node         │  dht_put / dht_get     │
│  store / find_val  │  listen (subscriptions)│
│                    │  channels              │
│                    │  presence              │
│                    │  replication           │
├─────────────────────────────────────────────┤
│  Kademlia Routing  │  Cluster Management    │
│  512-bit keyspace  │  Heartbeat health      │
│  k=8 buckets       │  K-closest replication │
├─────────────────────────────────────────────┤
│  SQLite Storage    │  Presence Table        │
│  7-day TTL         │  45s TTL, p_sync 30s   │
└─────────────────────────────────────────────┘
```

**Two Protocol Tiers:**
- **Tier 1 (UDP)** — Kademlia peer discovery: `ping`, `find_node`, `store`, `find_value`
- **Tier 2 (TCP)** — Client connections: `auth`, `dht_put`, `dht_get`, `listen`, `channels`, `presence`

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
│   └── crypto/      # Nodus-specific crypto helpers
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
ctest --output-on-failure    # All 16 unit tests
```

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
| EU-1 | 164.68.105.227 | 4000 | 4001 |
| EU-2 | 164.68.116.180 | 4000 | 4001 |
| EU-3 | 161.97.85.25 | 4000 | 4001 |
| EU-4 | 156.67.24.125 | 4000 | 4001 |
| EU-5 | 156.67.25.251 | 4000 | 4001 |

---

## Client SDK

The Nodus client SDK (`include/nodus/nodus.h`) is used by DNA Connect to connect to the DHT network:

```c
#include <nodus/nodus.h>

// Connect
nodus_client_t *client = nodus_client_create(config);
nodus_client_connect(client, "154.38.182.161", 4001);

// Store a value (signed with Dilithium5)
nodus_client_put(client, key, value, value_len, callback, userdata);

// Retrieve a value
nodus_client_get(client, key, callback, userdata);

// Subscribe to key changes
nodus_client_listen(client, key, on_update, userdata);

// Presence query
nodus_client_presence_query(client, fingerprints, count, callback, userdata);
```

---

## Documentation

| Doc | Description |
|-----|-------------|
| [DNA Nodus Deployment](../messenger/docs/DNA_NODUS.md) | Full deployment guide |
| [DHT System](../messenger/docs/DHT_SYSTEM.md) | DHT architecture |
| [P2P Architecture](../messenger/docs/P2P_ARCHITECTURE.md) | Transport layer |

---

## License

Licensed under the [Apache License 2.0](LICENSE).
