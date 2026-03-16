# Channel System Rewrite — Design Document

**Date:** 2026-03-13
**Status:** APPROVED
**Motivation:** Current channel replication is broken across nodes (only works when clients connect to same node). Code has accumulated random patches. Clean rewrite needed.

---

## Architecture Overview

```
Client → TCP 4003 → PRIMARY node
                        ├→ push to subscribed clients (ch_post_notify)
                        ├→ replicate to BACKUP-1 (TCP 4003: ch_replicate)
                        └→ replicate to BACKUP-2 (TCP 4003: ch_replicate)
```

- **No DHT PUT/GET for posts** — all post traffic over TCP 4003
- **Channel metadata stays on DHT** — name, description, creator, is_public
- **Node discovery stays on DHT** — `dna:channel:nodes:<uuid>` with ordered list

---

## 1. Node Roles

### Hashring — 3 Nodes, Deterministic Order

```
channel_position = SHA3-512(channel_uuid)
Clockwise from channel_position:
  [0] = PRIMARY    — accepts client connections, receives posts, replicates, pushes
  [1] = BACKUP-1   — receives replication from PRIMARY, stores data
  [2] = BACKUP-2   — receives replication from PRIMARY, stores data
```

### PRIMARY Responsibilities
- Accept client TCP 4003 connections
- Receive posts → verify signature → store → push to clients → replicate to BACKUPs
- Write ordered node list to DHT: `[PRIMARY, BACKUP-1, BACKUP-2]`
- Update DHT on ring change

### BACKUP Responsibilities
- Accept replication from PRIMARY only (no client connections)
- Store posts (INSERT OR IGNORE — dedup by post_uuid)
- If PRIMARY dies → BACKUP-1 becomes new PRIMARY

### Client Behavior
- Get `dna:channel:nodes:<uuid>` from DHT → ordered list
- Connect to first (PRIMARY) on TCP 4003
- If fails → try second → try third
- On connect: auth → subscribe → post/get
- On disconnect: reconnect + `ch_get(since_last_received_at)` for catch-up

---

## 2. Failover

### PRIMARY Dies
```
PRIMARY dies
  → BACKUPs detect via TCP 4003 heartbeat timeout
  → BACKUP-1 and BACKUP-2 confirm "PRIMARY dead" (TCP 4003)
  → Dead node removed from ring
  → BACKUP-1 becomes new PRIMARY (hashring recalculated)
  → New PRIMARY writes new ordered list to DHT
  → New 3rd node enters ring → incremental sync (last 1 day of posts)
  → Clients disconnect → get new list from DHT → connect to new PRIMARY → catch-up
```

### Node Rejoin (Hashring Always Wins)
```
Old PRIMARY comes back online
  → Connects to ring nodes (TCP 4003)
  → ch_node_hello with old ring_version
  → Receives current ring_version + ring membership
  → ALL nodes recalculate hashring (old PRIMARY included)
  → Deterministic result: old PRIMARY is position [0] again → becomes PRIMARY
  → Previous temporary PRIMARY drops to BACKUP
  → ring_version++
  → New PRIMARY updates DHT
  → New PRIMARY syncs missed posts (last 1 day)
  → If 4 nodes now → 4th by hashring priority gets ring_evict
  → Displaced PRIMARY's clients receive ch_ring_changed → disconnect → reconnect to new PRIMARY
```

**Rule: Hashring is always authoritative.** No negotiation, no election. Math decides.

---

## 3. TCP 4003 Protocol

### Two Connection Types, One Port

```
TCP 4003
  ├── Client connection (user → PRIMARY)
  └── Node connection (PRIMARY ↔ BACKUP, BACKUP ↔ BACKUP)
```

### Auth — Client
```
Client → ch_hello(pubkey, fingerprint)
Server ← ch_challenge(nonce)
Client → ch_auth(signature)
Server ← ch_auth_ok(token)
```

### Auth — Node (peer-to-peer)
```
Node A → ch_node_hello(pubkey, fingerprint, ring_version)
Node B ← ch_node_challenge(nonce)
Node A → ch_node_auth(signature)
Node B ← ch_node_auth_ok(token, current_ring_version, current_ring[])
```

If ring_version differs: higher version shares current ring, lower version accepts it. All nodes recalculate hashring.

### Messages — Client → PRIMARY
| Message | Description |
|---------|-------------|
| `ch_post` | Post to channel |
| `ch_get` | Get posts (since_received_at) |
| `ch_sub` | Subscribe to channel |
| `ch_unsub` | Unsubscribe |

### Messages — PRIMARY → Client (push)
| Message | Description |
|---------|-------------|
| `ch_post_notify` | New post arrived |
| `ch_ring_changed` | Ring changed, reconnect needed |

### Messages — Node ↔ Node (TCP 4003)
| Message | Description |
|---------|-------------|
| `ch_replicate` | PRIMARY → BACKUP: new post |
| `ch_sync_request` | New node → PRIMARY: request last 1 day of posts |
| `ch_sync_response` | PRIMARY → new node: post batch |
| `ch_heartbeat` | Periodic liveness check |
| `ch_ring_check` | "Is PRIMARY dead?" confirmation request |
| `ch_ring_ack` | "Yes/no" response |
| `ch_ring_evict` | "You are no longer in the ring" |
| `ch_ring_rejoin` | Returning node: "I want to rejoin, my version is X" |

---

## 4. Replication & Data Flow

### Post Flow (Normal)
```
Client → TCP 4003 → PRIMARY
  1. PRIMARY receives post
  2. Verify Dilithium5 signature
  3. Store in local SQLite
  4. Push to all subscribed clients (ch_post_notify)
  5. Replicate to BACKUP-1 (TCP 4003: ch_replicate) — background
  6. Replicate to BACKUP-2 (TCP 4003: ch_replicate) — background
```

**Order: push first, replicate after.** User experience before data safety. This is chat, not a stock exchange.

### Replication Failure → Hinted Handoff
```
PRIMARY → ch_replicate to BACKUP
  → Fails (timeout / connection dead)
  → Queue to hinted_handoff SQLite table
  → Retry every 30 seconds
  → 24 hour TTL (then discard)
```

### Incremental Sync (New Node Joins)
```
New node enters ring
  → Connects to PRIMARY (TCP 4003)
  → ch_sync_request(channel_uuid, since=24_hours_ago)
  → PRIMARY sends last 1 day of posts (ch_sync_response)
  → New node stores locally (INSERT OR IGNORE — dedup)
  → Sync complete, enters normal replication flow
```

---

## 5. File Structure

### Keep (clean, unchanged):
```
nodus/src/channel/
  ├── nodus_channel_store.c/h    — SQLite per-channel tables
  └── nodus_hashring.c/h         — Consistent hashring computation
```

### Rewrite from scratch:
```
nodus/src/channel/
  ├── nodus_channel_server.c/h   — TCP 4003 listener, session mgmt, auth
  │                                 Client session + Node session separation
  │                                 Heartbeat timer
  │
  ├── nodus_channel_primary.c/h  — PRIMARY role logic
  │                                 Post accept → store → push → replicate
  │                                 DHT announce (ordered list)
  │                                 Subscriber management
  │
  ├── nodus_channel_replication.c/h — Replication logic
  │                                    PRIMARY → BACKUP ch_replicate
  │                                    Hinted handoff (SQLite queue, 30s retry, 24h TTL)
  │                                    Incremental sync (ch_sync_request/response)
  │
  └── nodus_channel_ring.c/h     — Ring management
                                     Heartbeat-based dead detection (NOT PBFT)
                                     ring_check / ring_ack / ring_evict / ring_rejoin
                                     Ring version management
                                     Rejoin logic (hashring always wins)
```

### Delete:
```
  nodus_replication.c/h    — Old 4002 replication (remove entirely)
  nodus_ring_mgmt.c/h      — Old ring mgmt with PBFT dependency (remove entirely)
```

### nodus_server.c Changes:
- Remove all channel handlers from TCP 4002
- Move TCP 4003 event loop to `nodus_channel_server.c`
- Main loop calls `nodus_channel_tick()` (heartbeat, hinted handoff retry)

---

## 6. Client Side (Messenger)

### Changes:
```
messenger/dht/shared/nodus_ops.c
  — ch_pool connection strategy changes:
  — Get ordered list from DHT → connect to first (PRIMARY)
  — If fails → second → third
  — On reconnect: ch_get(since_last_received_at) for catch-up
  — On ch_ring_changed: disconnect → get new list from DHT → reconnect
```

### No changes:
```
messenger/src/api/engine/dna_engine_channels.c  — Task handlers stay the same
messenger/include/dna/dna_engine.h              — Public API stays the same
messenger/dna_messenger_flutter/                — Flutter UI stays the same
channel_cache.db                                — Cache logic stays the same
channel_subscriptions.db                        — Subscription logic stays the same
```

**Client-side impact is minimal.** Only the connection strategy in nodus_ops.c changes. API surface and Flutter are untouched.

---

## Key Principles

1. **PBFT has NOTHING to do with channels** — dead detection via TCP 4003 heartbeat only
2. **Hashring is always authoritative** — deterministic, no election, math decides
3. **Everything channel-related on TCP 4003** — no 4002 for channels
4. **Push first, replicate after** — user experience before data safety
5. **Metadata on DHT, posts on TCP 4003** — separation of concerns
6. **Hinted handoff for resilience** — failed replications retried for 24h
7. **1-day incremental sync** — new nodes only need recent data (7-day retention anyway)
