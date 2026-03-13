# DNA Nodus - Post-Quantum DHT Network

**Current Version:** Nodus (v0.8.1)
**Security:** FIPS 204 / ML-DSA-87 (Dilithium5) - NIST Category 5

## Overview

DNA Nodus is the DHT (Distributed Hash Table) infrastructure for DNA Connect. It is a pure C implementation (no C++ dependencies) providing:

1. **Kademlia DHT** - Decentralized key-value storage with 512-bit keyspace
2. **PBFT Consensus** - Byzantine fault-tolerant replication across nodes
3. **Client SDK** - TCP-based client protocol for messenger integration
4. **Channel System** - PRIMARY/BACKUP architecture over dedicated TCP 4003
5. **SQLite Persistence** - Durable storage for DHT values and channel posts

**Architecture:** Nodus replaced the former OpenDHT-PQ (C++) backend entirely. The `vendor/opendht-pq/` directory has been deleted. All messenger DHT operations now go through the Nodus client SDK directly via `nodus_ops.c` / `nodus_init.c`.

## Architecture

```
+-----------------------------------------------------------------+
|                      Nodus Server                            |
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
|  |         TCP Layer (port 4001) - Client DHT                 | |
|  |  - Client auth (Dilithium5 challenge/response)             | |
|  |  - Client DHT operations (dht_put, dht_get, listen)        | |
|  |  - TCP 4002: PBFT consensus + cross-node DHT replication   | |
|  +-----------------------------------------------------------+ |
|                                                                 |
|  +-----------------------------------------------------------+ |
|  |      Channel Layer (port 4003) - PRIMARY/BACKUP            | |
|  |  - Dedicated TCP port for all channel traffic              | |
|  |  - Client: create, post, get, subscribe                    | |
|  |  - Inter-node: replication, sync, ring management          | |
|  |  - Hashring-deterministic: 3 nodes per channel             | |
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
- **Three transport layers:**
  - **Tier 1 (Kademlia):** ping, find_node, put, get (UDP 4000, inter-node)
  - **Tier 2 (Client DHT):** auth, dht_put, dht_get, listen (TCP 4001, client-facing)
  - **Channel (TCP 4003):** ch_create, ch_post, ch_get, ch_sub, ch_rep (dedicated port)

### Messenger Integration

```
DNA Engine
    |
    v
nodus_ops.c / nodus_init.c  (messenger/dht/shared/)
    |
    v
Nodus Client SDK  (nodus/src/client/)
    |
    v  TCP connection
Nodus Server Cluster
```

The messenger integrates directly with Nodus -- no compatibility layer, no OpenDHT. Key files:
- `messenger/dht/shared/nodus_ops.c` - Convenience wrappers (`nodus_ops_put`, `nodus_ops_get`, `nodus_ops_listen`)
- `messenger/dht/shared/nodus_init.c` - Lifecycle management (init/connect/cleanup)
- `nodus/include/nodus/nodus.h` - Client SDK public API
- `nodus/include/nodus/nodus_types.h` - Constants, version, crypto sizes

**Internal Read Thread:** The Nodus client SDK runs an internal read thread after `nodus_client_connect()` that continuously reads TCP via blocking `epoll_wait`. Push notifications (value_changed, ch_ntf, offline messages) are delivered instantly via callbacks. `nodus_client_poll()` is a no-op when the read thread is running. Zero battery impact (kernel wait queue, no CPU spin).

**Channel Connection Pool (v0.8.0+):** The messenger maintains a pool of TCP 4003 connections in `nodus_ops.c` — one per active channel. On subscribe, the client connects to the PRIMARY node (discovered via DHT lookup) and auto-subscribes. Ring changes trigger automatic disconnect and reconnect to the new PRIMARY, with catch-up for missed posts via `ch_get(since=last_received_at)`.

## Nodus Production Cluster

Six nodes running v0.8.1 with PBFT ring formed and cross-node replication verified.

| Node | IP | UDP | TCP (DHT) | TCP (Channel) |
|------|-----|-----|-----------|---------------|
| US-1 | 154.38.182.161 | 4000 | 4001 | 4003 |
| EU-1 | 164.68.105.227 | 4000 | 4001 | 4003 |
| EU-2 | 164.68.116.180 | 4000 | 4001 | 4003 |
| EU-3 | 161.97.85.25 | 4000 | 4001 | 4003 |
| EU-4 | 156.67.24.125 | 4000 | 4001 | 4003 |
| EU-5 | 156.67.25.251 | 4000 | 4001 | 4003 |

**Configuration:** `/etc/nodus.conf` (per-machine, each seeds the others)
**Data directory:** `/var/lib/nodus/` (identity + SQLite storage)
**Systemd service:** `nodus.service` (enabled, auto-start)

### Deployment

```bash
# Build Nodus
cd /opt/dna/nodus/build && cmake .. && make -j$(nproc)

# Redeploy to a server
ssh root@<IP> 'bash /tmp/nodus-redeploy.sh'
```

### Configuration (v0.8+)

Nodus uses `/etc/nodus.conf`:

```json
{
    "bind_ip": "0.0.0.0",
    "tcp_port": 4001,
    "udp_port": 4000,
    "ch_port": 4003,
    "seed_nodes": [
        "154.38.182.161:4000",
        "164.68.105.227:4000",
        "164.68.116.180:4000"
    ],
    "data_dir": "/var/lib/nodus",
    "identity_path": "/var/lib/nodus"
}
```

**Ports:**
- **UDP 4000** — Kademlia peer discovery
- **TCP 4001** — Client DHT operations
- **TCP 4002** — Inter-node PBFT + DHT replication (auto = tcp_port + 1)
- **TCP 4003** — Channel system (PRIMARY/BACKUP + client channel connections)

## Legacy Servers (REMOVED)

The legacy dna-nodus v0.4.5 (OpenDHT-based) has been completely removed. All 6 production
nodes now run Nodus v0.8.1+ (pure C). The `vendor/opendht-pq/` directory was deleted.

## Building

### Nodus (current)

```bash
cd /opt/dna/nodus/build
cmake .. && make -j$(nproc)
```

This produces the server binary and client SDK library. The messenger build links against the Nodus client SDK automatically.

### Messenger (with Nodus integration)

```bash
cd /opt/dna/messenger/build
cmake .. && make -j$(nproc)
```

The messenger CMake configuration links against the Nodus client library. No separate build step is needed for the SDK.

## Key Source Files

```
/opt/dna/nodus/
├── include/nodus/
│   ├── nodus.h               # Client SDK public API
│   └── nodus_types.h         # Constants, version (NODUS_VERSION_*)
├── src/
│   ├── server/
│   │   ├── nodus_server.c    # Server event loop (epoll, all 4 ports)
│   │   ├── nodus_auth.c      # Dilithium5 challenge-response auth
│   │   └── nodus_presence.c  # Native presence tracking
│   ├── client/
│   │   └── nodus_client.c    # Client SDK (DHT + channel connections)
│   ├── channel/
│   │   ├── nodus_channel_server.c    # TCP 4003 listener + sessions
│   │   ├── nodus_channel_primary.c   # PRIMARY role: posts, broadcast, DHT announce
│   │   ├── nodus_channel_replication.c # BACKUP replication + hinted handoff
│   │   ├── nodus_channel_ring.c      # Ring management via heartbeat
│   │   ├── nodus_channel_store.c     # SQLite channel + post storage
│   │   └── nodus_hashring.c          # Consistent hash ring
│   ├── protocol/
│   │   └── nodus_tier2.c     # Protocol message encode/decode
│   └── ...
└── tests/
    ├── test_channel_*.c      # Channel system tests (5 test files)
    └── test_*.c              # Unit tests (27 tests total via ctest)

/opt/dna/messenger/dht/shared/
├── nodus_ops.c               # Convenience wrappers (DHT + channel pool)
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

### Nodus Status

```bash
# Check service status
ssh root@<IP> 'systemctl status nodus'

# View logs
ssh root@<IP> 'journalctl -u nodus -f'
```


## Version History

### Nodus (Pure C rewrite)
- **v0.8.1** - Wire dht_put_signed callback for channel DHT announcements
- **v0.8.0** - Channel system rewrite: modular PRIMARY/BACKUP architecture
  - 4 new modules: channel_server, channel_primary, channel_replication, channel_ring
  - Dedicated TCP 4003 for all channel traffic (no DHT PUT/GET for posts)
  - Hashring-deterministic role assignment (3 nodes per channel)
  - Hinted handoff for failed replication (SQLite, 24h TTL, 30s retry)
  - Ring management via TCP 4003 heartbeat (not PBFT)
  - Client auto-reconnect on ring change with catch-up
  - 27 unit tests, cross-node replication verified on 6-node cluster
- **v0.5.6** - Internal read thread for instant push notification delivery
- **v0.5.0** - Production-ready Nodus: Kademlia DHT + PBFT consensus + TCP client SDK

### Legacy (OpenDHT-based, removed from codebase)
- **v0.4.5** - Removed STUN/TURN for privacy (DHT-only mode)
- **v0.3.1** - Added direct UDP credential server (port 3479)
- **v0.1** - Initial DHT bootstrap with SQLite persistence
