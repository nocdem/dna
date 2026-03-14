# Nodus - Development Guidelines

**Last Updated:** 2026-03-14 | **Status:** BETA | **Version:** v0.9.1

**Note:** Framework rules (checkpoints, identity override, protocol mode, violations) are in root `/opt/dna/CLAUDE.md`. This file contains Nodus-specific guidelines only.

---

## Project Overview

Nodus is a **post-quantum Kademlia DHT** with BFT witness consensus. Pure C, no C++ dependencies.

- 512-bit keyspace (SHA3-512), k=8 Kademlia routing
- Dilithium5 signatures on all stored values
- CBOR wire format over 7-byte framed protocol (magic `0x4E44`)
- SQLite storage with 7-day default TTL
- Cluster heartbeat + membership management
- Embedded DNAC witness server (BFT consensus)

---

## Source Layout

```
nodus/
├── include/nodus/
│   ├── nodus.h              # Client SDK public API
│   └── nodus_types.h        # Constants, types, version
├── src/
│   ├── server/              # Event loop (epoll), nodus_server.c
│   ├── client/              # Client SDK, nodus_client.c
│   ├── protocol/            # Wire protocol: Tier 1 + Tier 2 + Tier 3
│   ├── core/                # Kademlia routing, storage, value mgmt
│   ├── transport/           # UDP (Kademlia) + TCP (client)
│   ├── channel/             # Channel system: primary, replication, hashring
│   ├── consensus/           # Cluster heartbeat, membership
│   ├── crypto/              # Identity generation, Dilithium5 signing
│   └── witness/             # DNAC BFT witness (embedded in server)
├── tests/                   # 28 unit test files + integration test
└── docs/                    # Architecture, design docs
```

### Protocol Tiers

| Tier | Transport | Purpose |
|------|-----------|---------|
| Tier 1 | UDP 4000 | Kademlia peer discovery (ping, find_node, put, get) |
| Tier 2 | TCP 4001 | Client operations (auth, dht_put, dht_get, listen, channels) |
| Inter-node | TCP 4002 | Cluster replication, heartbeat |
| Channels | TCP 4003 | Dedicated channel port |
| Witness BFT | TCP 4004 | Dedicated witness consensus (T3 "w_" messages) |

---

## Key Constants

**Network:**
| Constant | Value | Description |
|----------|-------|-------------|
| UDP port | 4000 | Kademlia peer discovery |
| TCP client port | 4001 | Client connections |
| Inter-node port | 4002 | Cluster replication |
| Channel port | 4003 | Dedicated channel traffic |
| Witness port | 4004 | Witness BFT consensus |

**Kademlia:**
| Constant | Value | Description |
|----------|-------|-------------|
| Keyspace | 512 bits (64 bytes) | SHA3-512 |
| Bucket size (k) | 8 | Peers per bucket |
| Replication factor (r) | 3 | Copies per value |
| Buckets | 512 | One per keyspace bit |
| Parallel lookups (alpha) | 3 | Concurrent queries |

**DHT Values:**
| Constant | Value | Description |
|----------|-------|-------------|
| Max value size | 1 MB | Payload limit |
| Max values per owner | 10,000 | Per-identity limit |
| Default TTL | 7 days | Value expiry |
| Permanent TTL | 0 | Never expires |

**Channels:**
| Constant | Value | Description |
|----------|-------|-------------|
| Max post body | 4,000 chars | UTF-8 |
| Channel retention | 7 days | Post lifetime |
| Max channel sessions | 1,024 | Concurrent subscriptions |
| Hinted retry | 30 seconds | Failed replication retry |
| Hinted TTL | 24 hours | Hinted handoff expiry |

**Protocol Framing:**
| Constant | Value | Description |
|----------|-------|-------------|
| Frame magic | 0x4E44 ("ND") | Wire frame identifier |
| Frame header | 7 bytes | magic + version + length |
| Max TCP frame | 4 MB | Maximum frame size |
| Max UDP frame | 1,400 bytes | Safe MTU |

**Timing:**
| Constant | Value | Description |
|----------|-------|-------------|
| Cluster heartbeat | 10 seconds | Membership check |
| Suspect timeout | 30 seconds | Node marked suspect |
| Routing stale | 1 hour | Bucket refresh trigger |
| Bucket refresh | 15 minutes | Periodic refresh |
| Republish interval | 60 minutes | Value re-announce |
| Presence TTL | 45 seconds | Server-side presence |
| Presence p_sync | 30 seconds | Inter-node broadcast |

**Rate Limits:**
| Constant | Value | Description |
|----------|-------|-------------|
| PUTs/minute | 60 | Per-client rate limit |
| Max listeners | 100 | Per-client subscriptions |
| Max connections | 1,000 | Server-wide limit |

---

## Build & Test

```bash
cd /opt/dna/nodus/build && cmake .. && make -j$(nproc)
```

**Run all tests:**
```bash
cd nodus/build && ctest --output-on-failure
```

**Run single test:**
```bash
cd nodus/build && ./test_cbor    # or any test_* binary
```

**Integration test (SSH to cluster):**
```bash
bash nodus/tests/integration_test.sh
```

### Test Coverage

| Area | Test Files |
|------|-----------|
| Core Kademlia | `test_routing`, `test_routing_stale`, `test_bucket_refresh`, `test_storage`, `test_storage_cleanup`, `test_value` |
| Client SDK | `test_client`, `test_tier2`, `test_tcp`, `test_fetch_batch` |
| Channels | `test_channel_primary`, `test_channel_protocol`, `test_channel_replication`, `test_channel_ring`, `test_channel_server`, `test_channel_store` |
| Presence | `test_presence` |
| DHT Features | `test_put_if_newer`, `test_hinted_handoff`, `test_hashring` |
| Protocol | `test_tier1`, `test_tier3`, `test_wire`, `test_cbor`, `test_identity` |
| Witness | `test_witness_verify` |

---

## Messenger Integration

Messenger integrates via convenience wrappers:
- `messenger/dht/shared/nodus_ops.c` — `nodus_ops_put`, `nodus_ops_get`, `nodus_ops_listen`
- `messenger/dht/shared/nodus_init.c` — Singleton lifecycle management
- `dna_engine_is_dht_connected()` — Used by Flutter FFI + CLI

---

## Documentation

| File | Topic |
|------|-------|
| `docs/ARCHITECTURE.md` | System architecture & design |
| `docs/CHANNEL_REWRITE_DESIGN.md` | Channel TCP 4003 redesign |
| `docs/DYNAMIC_WITNESS_DESIGN.md` | Witness discovery & roster |
| `docs/REPLICATION_DESIGN.md` | DHT value replication strategy |
| `docs/REPLICATION_ISSUES.md` | Known replication issues & fixes |
| `docs/PLAN_VERSION_ENFORCEMENT.md` | Version update enforcement |
| `../messenger/docs/DNA_NODUS.md` | Deployment guide |

---

## Server Configuration

Production servers use `/etc/nodus.conf`. Data stored in `/var/lib/nodus/`. Managed via `systemd` service `nodus`.

Server details (IPs, ports, deploy procedures) are in internal documentation only — not tracked in git.

---

**Priority:** Security, correctness, simplicity. When in doubt, ask.
