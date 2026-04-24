# DNA Nodus - Post-Quantum DHT Network

**Current Version:** Nodus v0.17.7 | **Last Updated:** 2026-04-24
**Security:** FIPS 204 / ML-DSA-87 (Dilithium5) - NIST Category 5

> **Since v0.10.30 (2026-04-10) Nodus shipped:**
> - **v0.10.14**: Mempool + batch BFT (5s block timer, up to 10 TXs per round) — see `nodus/docs/MEMPOOL_BLOCK_TIME.md`.
> - **v0.11.0**: DNAC Merkle `state_root` in BFT commit; chain id `4a68e146` live.
> - **v0.14.1**: `CLAIM_REWARD` + `UNDELEGATE` finalized (accumulator attendance determinism fix).
> - **v0.15.0–v0.15.1** (F17): chain-derived top-7 committee is now the BFT voting authority; gossip roster is transport-only.
> - **v0.17.1**: TX wire v2 — `committed_fee` field in 82-byte header; `DNAC_MIN_FEE_RAW = 0.01 DNAC` gate.
> - **v0.17.7**: current release; 7/7 cluster live.
>
> **Hard-fork mechanism (`DNAC_TX_CHAIN_CONFIG`)** shipped 2026-04-19: committee-voted consensus-parameter changes without chain wipe. See `dnac/docs/plans/2026-04-19-hard-fork-mechanism-design.md`.
>
> **Channel system (TCP 4003)** is **SOFT-DISABLED** (2026-03-28, ifdef `DNA_CHANNELS_ENABLED`). Infrastructure remains, port listens, but messenger does not exercise it.

## Overview

DNA Nodus is the DHT (Distributed Hash Table) infrastructure for DNA Connect. It is a pure C implementation (no C++ dependencies) providing:

1. **Kademlia DHT** - Decentralized key-value storage with 512-bit keyspace
2. **Cluster Membership** - Node discovery and replication across cluster
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
|  |  - TCP 4002: Inter-node replication                        | |
|  +-----------------------------------------------------------+ |
|                                                                 |
|  +-----------------------------------------------------------+ |
|  |    Channel Layer (port 4003) [SOFT-DISABLED 2026-03-28]    | |
|  |  - Port listens; runtime paths guarded by                  | |
|  |    DNA_CHANNELS_ENABLED ifdef (inert)                      | |
|  +-----------------------------------------------------------+ |

|  +-----------------------------------------------------------+ |
|  |      Witness BFT (port 4004) — DNAC consensus              | |
|  |  - PROPOSE / PREVOTE / PRECOMMIT / COMMIT                  | |
|  |  - Chain-derived top-7 committee (since F17, v0.15.x)      | |
|  |  - Mempool + 5s batch timer; up to 10 TXs per round        | |
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
- **Transport layers:**
  - **Tier 1 (Kademlia):** ping, find_node, put, get (UDP 4000, inter-node)
  - **Tier 2 (Client DHT):** auth, dht_put, dht_get, listen (TCP 4001, client-facing)
  - **Channel (TCP 4003):** *(soft-disabled 2026-03-28; port listens, runtime paths ifdef-guarded)*
  - **Witness BFT (TCP 4004):** DNAC consensus — propose, prevote, precommit, commit

### DNAC Witness (Block Production)

- **Block time:** 5 seconds (no empty blocks — only when mempool has TXs)
- **Mempool:** Fee-ordered queue (max 64 TXs), leader accumulates and batches
- **Batch size:** Up to 10 TXs per BFT round (128KB wire limit)
- **Consensus:** PBFT-style (PROPOSE → PREVOTE → PRECOMMIT → COMMIT)
- **Atomic commit:** All TXs in batch committed in single SQLite transaction
- **Genesis:** Bypasses mempool, uses legacy single-TX BFT path
- **State sync:** Compatible — each TX produces its own block with commit certificates
- See: `nodus/docs/MEMPOOL_BLOCK_TIME.md` for full design

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

**Channel Connection Pool (v0.8.0+, soft-disabled 2026-03-28):** infrastructure retained but the messenger no longer opens TCP 4003 connections for channel traffic. The pool / subscribe / ring-change reconnect paths are guarded by `DNA_CHANNELS_ENABLED` and compile to inert stubs.

## Nodus Production Cluster

Seven nodes running v0.17.7 with cluster membership formed, cross-node replication verified, and DNAC chain `4a68e146` live (9 blocks, 7/7 consistent).

| Node | IP | UDP | TCP (DHT) | TCP (Inter-node) | TCP (Channel) | TCP (Witness) |
|------|-----|-----|-----------|-------------------|---------------|---------------|
| US-1 | 154.38.182.161 | 4000 | 4001 | 4002 | 4003 | 4004 |
| EU-1 | 161.97.85.25 | 4000 | 4001 | 4002 | 4003 | 4004 |
| EU-2 | 156.67.24.125 | 4000 | 4001 | 4002 | 4003 | 4004 |
| EU-3 | 156.67.25.251 | 4000 | 4001 | 4002 | 4003 | 4004 |
| EU-4 | 164.68.105.227 | 4000 | 4001 | 4002 | 4003 | 4004 |
| EU-5 | 164.68.116.180 | 4000 | 4001 | 4002 | 4003 | 4004 |
| EU-6 | 75.119.141.51 | 4000 | 4001 | 4002 | 4003 | 4004 |

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
- **TCP 4002** — Inter-node replication (auto = tcp_port + 1)
- **TCP 4003** — Channel system (PRIMARY/BACKUP + client channel connections)
- **TCP 4004** — Witness BFT consensus (DNAC block production)

## Legacy Servers (REMOVED)

The legacy dna-nodus v0.4.5 (OpenDHT-based) has been completely removed. All 7 production
nodes now run Nodus v0.17.7 (pure C). The `vendor/opendht-pq/` directory was deleted.

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
5. **Cluster Membership** - Node discovery and data replication
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
