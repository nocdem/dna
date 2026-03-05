# DNA Nodus - Post-Quantum DHT Network

**Current Version:** Nodus v5 (v0.5.6)
**Security:** FIPS 204 / ML-DSA-87 (Dilithium5) - NIST Category 5

## Overview

DNA Nodus is the DHT (Distributed Hash Table) infrastructure for DNA Messenger. It is a pure C implementation (no C++ dependencies) providing:

1. **Kademlia DHT** - Decentralized key-value storage with 512-bit keyspace
2. **PBFT Consensus** - Byzantine fault-tolerant replication across nodes
3. **Client SDK** - TCP-based client protocol for messenger integration
4. **SQLite Persistence** - Durable storage for DHT values

**Architecture:** Nodus v5 replaced the former OpenDHT-PQ (C++) backend entirely. The `vendor/opendht-pq/` directory has been deleted. All messenger DHT operations now go through the Nodus v5 client SDK directly via `nodus_ops.c` / `nodus_init.c`.

## Architecture

```
+-----------------------------------------------------------------+
|                      Nodus v5 Server                            |
|                   (Pure C, CBOR protocol)                       |
+-----------------------------------------------------------------+
|                                                                 |
|  +-----------------------------------------------------------+ |
|  |         UDP Layer (port 4000) - Kademlia                   | |
|  |  - Peer discovery (ping, find_node)                        | |
|  |  - Inter-node DHT operations (put, get)                    | |
|  |  - k=8 routing buckets, 512-bit keyspace                   | |
|  +-----------------------------------------------------------+ |
|                                                                 |
|  +-----------------------------------------------------------+ |
|  |         TCP Layer (port 4001) - Client + Replication       | |
|  |  - Client auth (Dilithium5 challenge/response)             | |
|  |  - Client DHT operations (dht_put, dht_get, listen)        | |
|  |  - PBFT consensus + cross-node replication                 | |
|  |  - Channel subscriptions                                   | |
|  +-----------------------------------------------------------+ |
|                                                                 |
|  +-----------------------------------------------------------+ |
|  |              SQLite Persistence Layer                      | |
|  |         /var/lib/nodus/ (identity + data)                  | |
|  +-----------------------------------------------------------+ |
|                                                                 |
+-----------------------------------------------------------------+
```

### Protocol

- **Wire format:** CBOR over wire frames with 7-byte header (magic `0x4E44` + version + length)
- **Two tiers:**
  - **Tier 1 (Kademlia):** ping, find_node, put, get (UDP, inter-node)
  - **Tier 2 (Client):** auth, dht_put, dht_get, listen, channels (TCP, client-facing)

### Messenger Integration

```
DNA Engine
    |
    v
nodus_ops.c / nodus_init.c  (messenger/dht/shared/)
    |
    v
Nodus v5 Client SDK  (nodus/src/client/)
    |
    v  TCP connection
Nodus v5 Server Cluster
```

The messenger integrates directly with Nodus v5 -- no compatibility layer, no OpenDHT. Key files:
- `messenger/dht/shared/nodus_ops.c` - Convenience wrappers (`nodus_ops_put`, `nodus_ops_get`, `nodus_ops_listen`)
- `messenger/dht/shared/nodus_init.c` - Lifecycle management (init/connect/cleanup)
- `nodus/include/nodus/nodus.h` - Client SDK public API
- `nodus/include/nodus/nodus_types.h` - Constants, version, crypto sizes

**Internal Read Thread (v0.5.6+):** The Nodus client SDK runs an internal read thread after `nodus_client_connect()` that continuously reads TCP via blocking `epoll_wait`. Push notifications (value_changed, ch_ntf, offline messages) are delivered instantly via callbacks. `nodus_client_poll()` is a no-op when the read thread is running. This replaces the old model where the heartbeat thread polled every 60s. Zero battery impact (kernel wait queue, no CPU spin).

## Nodus v5 Test Cluster

Three nodes running v0.5.6 with PBFT ring formed and cross-node replication verified.

| Node | IP | UDP Port | TCP Port |
|------|-----|----------|----------|
| nodus-01 | 161.97.85.25 | 4000 | 4001 |
| nodus-02 | 156.67.24.125 | 4000 | 4001 |
| nodus-03 | 156.67.25.251 | 4000 | 4001 |

**Configuration:** `/etc/nodus-v5.conf` (per-machine, each seeds the other 2)
**Data directory:** `/var/lib/nodus/` (identity + SQLite storage)
**Systemd service:** `nodus-v5.service` (enabled, auto-start)

### Deployment

```bash
# Build Nodus v5
cd /opt/dna/nodus/build && cmake .. && make -j$(nproc)

# Redeploy to a server
ssh root@<IP> 'bash /tmp/nodus-redeploy.sh'
```

### Configuration (v5)

Nodus v5 uses `/etc/nodus-v5.conf`:

```json
{
    "listen_port": 4001,
    "udp_port": 4000,
    "seed_nodes": [
        "161.97.85.25:4000",
        "156.67.24.125:4000"
    ],
    "data_dir": "/var/lib/nodus",
    "identity": "nodus-01"
}
```

## Production Servers (Legacy v0.4.5)

These servers still run the legacy dna-nodus v0.4.5 (OpenDHT-based) for production clients. They will be migrated to Nodus v5 during production cutover.

| Server | IP | DHT Port | Location |
|--------|-----|----------|----------|
| US-1 | 154.38.182.161 | 4000 | United States |
| EU-1 | 164.68.105.227 | 4000 | Europe |
| EU-2 | 164.68.116.180 | 4000 | Europe |

**Note:** The legacy v0.4 codebase was in `vendor/opendht-pq/` which has been deleted from the monorepo. The production servers still run the old binary from `/opt/dna-messenger/` on each server.

## Building

### Nodus v5 (current)

```bash
cd /opt/dna/nodus/build
cmake .. && make -j$(nproc)
```

This produces the server binary and client SDK library. The messenger build links against the Nodus v5 client SDK automatically.

### Messenger (with Nodus v5 integration)

```bash
cd /opt/dna/messenger/build
cmake .. && make -j$(nproc)
```

The messenger CMake configuration links against the Nodus v5 client library. No separate build step is needed for the SDK.

## Key Source Files

```
/opt/dna/nodus/
├── include/nodus/
│   ├── nodus.h               # Client SDK public API
│   └── nodus_types.h         # Constants, version (NODUS_VERSION_*)
├── src/
│   ├── server/
│   │   └── nodus_server.c    # Server event loop (epoll)
│   ├── client/
│   │   └── nodus_client.c    # Client SDK implementation
│   ├── protocol/
│   │   └── nodus_tier2.c     # Client protocol message dispatch
│   └── ...
└── tests/
    ├── integration_test.sh   # SSH to 3-node cluster
    └── test_*.c              # Unit tests (13 tests via ctest)

/opt/dna/messenger/dht/shared/
├── nodus_ops.c               # Convenience wrappers for nodus singleton
├── nodus_ops.h
├── nodus_init.c              # Lifecycle management
└── nodus_init.h
```

## Security Considerations

1. **Post-Quantum Signatures** - All DHT operations require Dilithium5 (ML-DSA-87) signatures
2. **Client Authentication** - Dilithium5 challenge/response on TCP connect
3. **No IP Leakage** - DHT-only mode prevents IP disclosure to third parties
4. **Distributed Architecture** - No central servers for message relay
5. **PBFT Consensus** - Byzantine fault tolerance for data replication
6. **Timestamp-Only Presence** - Online status without IP disclosure

## Monitoring

### Nodus v5 Status

```bash
# Check service status
ssh root@<IP> 'systemctl status nodus-v5'

# View logs
ssh root@<IP> 'journalctl -u nodus-v5 -f'
```

### Legacy v0.4 Status

```bash
ssh root@<IP> 'systemctl status dna-nodus'
```

## Version History

### Nodus v5 (Pure C rewrite)
- **v0.5.6** - Internal read thread for instant push notification delivery
  - Client SDK spawns read thread after connect (blocking epoll_wait, zero CPU)
  - Push notifications (value_changed, ch_ntf) delivered instantly via callbacks
  - `nodus_client_poll()` is no-op when read thread is running
  - `nodus_pending_t.ready` changed to `_Atomic bool` for cross-thread visibility
  - Thread safety: poll_mutex (reads), send_mutex (writes), pending_mutex (slots)
- **v0.5.0** - Production-ready Nodus v5: Kademlia DHT + PBFT consensus + TCP client SDK
  - Pure C implementation (no C++ dependencies)
  - CBOR wire protocol with 7-byte frame header
  - Two-tier protocol (Kademlia + Client)
  - 3-node test cluster deployed and verified
  - Direct messenger integration via nodus_ops.c (OpenDHT removed)

### Legacy (OpenDHT-based, now removed from codebase)
- **v0.4.5** - Removed STUN/TURN for privacy (DHT-only mode)
- **v0.3.1** - Added direct UDP credential server (port 3479)
- **v0.3** - Added TURN server and credential management
- **v0.2** - Added bootstrap registry and peer discovery
- **v0.1** - Initial DHT bootstrap with SQLite persistence
