# Nodus — Custom DHT for DNA Connect

**Date:** 2026-02-27
**Status:** DESIGN
**Author:** nocdem + EXECUTOR

---

## Motivation

Replace OpenDHT (37,968 lines C++, 7 external dependencies) with a DNA-specialized DHT implementation in pure C.

**Goals:**
1. **Dependency cleanup** — Remove GnuTLS, nettle, argon2, msgpack-cxx, fmt, ASIO, gmp (7 libs)
2. **Protocol control** — DNA-optimized DHT instead of general-purpose Kademlia
3. **New capabilities** — TCP transport, public Nodus servers (anyone can host)
4. **Simplicity** — ~6,000 lines pure C replacing 37,968 lines C++ + 2,124 line C++ bridge

**Non-goals (v1):**
- NAT traversal / hole-punching (future: Phase 16 voice/video)
- Relay service (future: when P2P direct connections needed)
- WebSocket transport (future: Phase 15 web client)
- Sybil attack protection (Dilithium5 signatures prevent data tampering; censorship risk accepted for v1)

---

## Architecture: Two-Tier Model

```
═══════════════════════════════════════════════════════════
                    NODUS NETWORK (Tier 1)
               Kademlia DHT — Nodus servers only
═══════════════════════════════════════════════════════════
  Nodus-A ◄══Kademlia══► Nodus-B ◄══Kademlia══► Nodus-C
    ▲  ▲                   ▲  ▲                    ▲  ▲
    │  │                   │  │                    │  │
═══════════════════════════════════════════════════════════
                    CLIENTS (Tier 2)
                   Simple TCP — any Nodus
═══════════════════════════════════════════════════════════
    │  │                   │  │                    │  │
  Alice Bob              Carol Dave              Eve  Frank
```

### Tier 1: Nodus Network
- **Participants:** Public Nodus servers (anyone can run one)
- **Routing:** Kademlia XOR-distance (k=8 bucket size, r=3 replication)
- **Transport:** TCP (persistent connections between Nodus nodes)
- **Storage:** SQLite persistent
- **Identity:** Each Nodus has a Dilithium5 key pair, mutual authentication

### Tier 2: Clients
- **Participants:** DNA Connect users
- **Routing:** None — delegates to connected Nodus
- **Transport:** TCP (persistent connection for push notifications)
- **Storage:** Local SQLite (dnac.db, unchanged)

### Security Model
- All values signed with Dilithium5 — malicious Nodus cannot tamper with data
- Clients verify signatures — never trust Nodus blindly
- Each Nodus has a Dilithium5 identity, mutual auth on Nodus↔Nodus connections
- PUT operations require valid signature — unsigned data rejected
- Per-identity rate limiting prevents spam

### Kademlia Parameters
- **k = 8** — bucket size (routing table capacity: 256 × 8 = 2,048 entries)
- **r = 3** — replication factor (each value on 3 nearest Nodus nodes)
- **Key space:** 256-bit (SHA3-256 of raw key)

---

## Wire Protocol

### Transport: TCP Everywhere

Both tiers use TCP. No UDP, no chunking needed.

| Connection | Transport | Persistence | Why |
|-----------|-----------|-------------|-----|
| Nodus ↔ Nodus | TCP | Connection pool (persistent) | No chunk limit, reliable delivery |
| Client ↔ Nodus | TCP | Persistent (for LISTEN push) | Natural for request/response + push |

### Frame Format

```
┌──────┬──────┬──────┬───────────────────────┐
│ Magic│ Ver  │ Len  │     Payload            │
│ 2B   │ 1B   │ 4B   │     N bytes            │
│ 0x4E44│ 0x01 │ LE32 │     (CBOR encoded)     │
└──────┴──────┴──────┴───────────────────────┘
  "ND"    v1
```

- **Magic:** `0x4E44` ("ND" = Nodus)
- **Version:** Protocol version (future compatibility)
- **Length:** Payload length (little-endian 32-bit)
- **Payload:** CBOR (RFC 8949) encoded message

### Serialization: Custom Minimal CBOR (~500-700 lines C)

Only encodes/decodes types we use: maps, byte strings, text strings, unsigned integers, arrays. No floats, tags, or indefinite-length encoding. Still standards-compliant (debuggable at cbor.me).

### Tier 1 Messages (Nodus ↔ Nodus)

Kademlia routing:
```
PING                          → PONG
FIND_NODE(target_id)          → NODES_FOUND([node1, node2, ...])
STORE(key, value, sig)        → STORE_ACK
FIND_VALUE(key)               → VALUE(data, sig) | NODES_FOUND([...])
```

Distributed pub/sub (for LISTEN):
```
SUBSCRIBE(key, subscriber_nodus_id)    → SUB_ACK
UNSUBSCRIBE(key, subscriber_nodus_id)  → UNSUB_ACK
NOTIFY(key, value)                     → (one-way push)
```

CBOR structure:
```cbor
{
  "t": <uint32>,              // transaction_id (request/response matching)
  "y": "q" | "r" | "e",      // query, response, error
  "q": "ping"|"fn"|"sv"|"fv"|"sub"|"unsub"|"ntf",
  "a": { ... },               // arguments
  "r": { ... },               // results
  "sig": <bytes>,              // Dilithium5 message signature
  "pk": <bytes>                // sender public key
}
```

### Tier 2 Messages (Client ↔ Nodus)

```
Client → Nodus:
  HELLO(client_pubkey)                   — Start handshake
  AUTH(signed_nonce)                     — Complete handshake
  PUT(key, value, ttl)                   — Store value
  GET(key)                               — Retrieve first value
  GET_ALL(key)                           — Retrieve all values for key
  LISTEN(key)                            — Subscribe to key changes
  UNLISTEN(key)                          — Unsubscribe
  BATCH_GET([key1, key2, ...])           — Parallel multi-key fetch
  PING                                   — Keepalive

Nodus → Client:
  CHALLENGE(random_nonce)                — Auth challenge
  AUTH_OK(session_token)                 — Auth success
  VALUE_CHANGED(key, value, sig)         — Push notification (LISTEN result)
  RESULT(data)                           — GET/PUT response
  ERROR(code, message)                   — Error response
```

### Authentication

**Client → Nodus:**
```
1. Client → Nodus:  HELLO(client_pubkey)
2. Nodus → Client:  CHALLENGE(random_nonce)
3. Client → Nodus:  AUTH(sign(nonce, client_privkey))
4. Nodus → Client:  AUTH_OK(session_token)
```
Session token for subsequent messages (avoids per-message Dilithium5 cost).

**Nodus ↔ Nodus (mutual):**
```
1. Nodus-A → Nodus-B:  HELLO(A_pubkey, A_node_id)
2. Nodus-B → Nodus-A:  CHALLENGE(nonce_for_A)
3. Nodus-A → Nodus-B:  VERIFY(sign(nonce_for_A, A_privkey))
4. Nodus-B validates signature → A is authenticated
5. (Reverse direction: B authenticates to A similarly)
6. Both sides derive session HMAC key for subsequent messages
```

---

## Data Model

### NodusValue

```cbor
{
  "id":      <uint64>,    // Unique value ID per writer
  "key":     <bytes>,     // DHT key (raw, pre-hash)
  "data":    <bytes>,     // Payload (encrypted or plain, no size limit over TCP)
  "type":    <uint8>,     // 0x01=EPHEMERAL, 0x02=PERMANENT
  "ttl":     <uint32>,    // TTL seconds (0 = permanent)
  "created": <uint64>,    // Unix timestamp
  "seq":     <uint64>,    // Sequence number for updates
  "owner":   <bytes>,     // Dilithium5 public key (2,592 bytes)
  "sig":     <bytes>      // Dilithium5 signature (4,627 bytes)
}
```

### Value Types

| Type | ID | TTL | SQLite | Republish on restart | Use |
|------|----|-----|--------|---------------------|-----|
| EPHEMERAL | 0x01 | 7 days | Yes | Yes, if `created_at + ttl > now` | Messages, ACKs, temp data |
| PERMANENT | 0x02 | ∞ | Yes | Always | Profiles, names, keys, backups, wall posts |

**Cleanup rule:** Expired EPHEMERAL values deleted on periodic sweep. Once `created_at + ttl` has passed, the value is deleted and never republished.

### Conflict Resolution
- Same `(key, owner, value_id)` → highest `seq` wins
- Different owners on same key → all values stored (multi-writer)
- Client uses GET_ALL to retrieve all writers' values

---

## Storage (Nodus Server)

### SQLite Schema

```sql
CREATE TABLE nodus_values (
  key_hash    TEXT NOT NULL,
  value_id    INTEGER NOT NULL,
  data        BLOB NOT NULL,
  type        INTEGER NOT NULL,
  ttl         INTEGER NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER,           -- NULL = permanent
  owner_pk    BLOB NOT NULL,
  signature   BLOB NOT NULL,
  seq         INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (key_hash, value_id)
);
CREATE INDEX idx_expires ON nodus_values(expires_at);
CREATE INDEX idx_key ON nodus_values(key_hash);

CREATE TABLE nodus_peers (
  node_id     TEXT PRIMARY KEY,
  ip          TEXT NOT NULL,
  port        INTEGER NOT NULL,
  pubkey      BLOB,
  last_seen   INTEGER NOT NULL,
  rtt_ms      INTEGER DEFAULT 0
);

CREATE TABLE nodus_subscriptions (
  key_hash      TEXT NOT NULL,
  subscriber_id TEXT NOT NULL,   -- which Nodus is listening to this key
  subscribed_at INTEGER NOT NULL,
  PRIMARY KEY (key_hash, subscriber_id)
);
```

### Replication (r=3)

```
PUT flow:
1. Client → Nodus-X: PUT(key, value)
2. Nodus-X: find 3 nearest Nodus by XOR distance to SHA3-256(key)
3. Nodus-X → Nodus-A, Nodus-B, Nodus-C: STORE(key, value)
4. 2/3 ACK (quorum) → return success to client

GET flow:
1. Client → Nodus-X: GET(key)
2. Nodus-X: am I responsible? → serve directly
3. Not responsible → route to nearest responsible Nodus, proxy response back
```

### Distributed LISTEN (Pub/Sub)

```
1. Alice → Nodus-X: LISTEN("bob:outbox")

2. Nodus-X determines responsible Nodus for key (Kademlia routing)
   → Nodus-Z is responsible (nearest XOR distance)

3. Nodus-X → Nodus-Z: SUBSCRIBE("bob:outbox", nodus_x_id)

4. Nodus-Z stores subscription in nodus_subscriptions table

5. Bob → Nodus-Y: PUT("bob:outbox", message)

6. Nodus-Y routes STORE to responsible nodes → reaches Nodus-Z

7. Nodus-Z: new value + has subscriber(s)!
   → Nodus-Z → Nodus-X: NOTIFY("bob:outbox", value)

8. Nodus-X: Alice still connected?
   → Nodus-X → Alice: VALUE_CHANGED("bob:outbox", value)
```

**Edge cases:**
- Nodus-Z goes down → responsibility transfers to next nearest; client re-LISTENs on reconnect
- Alice disconnects → Nodus-X removes listener, sends UNSUBSCRIBE to Nodus-Z
- Nodus-X goes down → Nodus-Z applies subscriber timeout (no heartbeat for 5min → remove)

### Rate Limiting

Configurable per Nodus operator:
```json
{
  "limits": {
    "max_puts_per_minute": 60,
    "max_value_size": 1048576,
    "max_values_per_owner": 10000,
    "max_listeners_per_client": 100
  }
}
```

All PUTs require Dilithium5 signature → anonymous spam impossible.
Rate limits are per authenticated identity.

---

## Module Structure

```
nodus/
├── include/nodus/
│   ├── nodus.h                 // Public API (client SDK)
│   ├── nodus_server.h          // Server API
│   └── nodus_types.h           // Shared types
│
├── src/
│   ├── core/
│   │   ├── nodus_routing.c     // Kademlia routing table (k-buckets, XOR)
│   │   ├── nodus_storage.c     // SQLite value storage + cleanup
│   │   └── nodus_value.c       // Value create/verify/serialize
│   │
│   ├── protocol/
│   │   ├── nodus_wire.c        // Frame encode/decode
│   │   ├── nodus_cbor.c        // Minimal CBOR encoder/decoder (~500 lines)
│   │   ├── nodus_tier1.c       // Nodus↔Nodus: Kademlia + pub/sub messages
│   │   └── nodus_tier2.c       // Client↔Nodus: request/response + push
│   │
│   ├── transport/
│   │   └── nodus_tcp.c         // TCP socket + connection pool
│   │
│   ├── crypto/
│   │   ├── nodus_sign.c        // Dilithium5 sign/verify (wraps DNA's existing code)
│   │   └── nodus_identity.c    // Key generation, import/export
│   │
│   ├── client/
│   │   └── nodus_client.c      // Client SDK (connect, auth, put, get, listen)
│   │
│   └── server/
│       ├── nodus_server.c      // Server main loop + client handling
│       └── nodus_discovery.c   // Peer discovery (Nodus registry in DHT)
│
├── tools/
│   └── nodus-server.c          // Server binary entry point
│
└── CMakeLists.txt
```

### Estimated Size

| Module | Lines (est.) | Description |
|--------|-------------|-------------|
| core/ | ~2,000 | Routing table, storage, value |
| protocol/ | ~1,500 | Wire, CBOR, Tier 1/2 messages |
| transport/ | ~600 | TCP socket + connection pool |
| crypto/ | ~500 | Dilithium5 sign/verify wrapper |
| client/ | ~800 | Client SDK |
| server/ | ~800 | Server, discovery |
| **Total** | **~6,200** | **vs OpenDHT 37,968 + bridge 2,124 + chunked 2,000** |

---

## DNA Connect Integration

### What Changes

```
BEFORE:
  dna_engine → dht_context.cpp (C++) → OpenDHT DhtRunner (C++)
                  2,124 lines              37,968 lines
               + dht_chunked.c (C)
                  ~2,000 lines

AFTER:
  dna_engine → nodus_client.c (Pure C)  →  Nodus Server (Pure C)
                    ~800 lines                  ~6,200 lines
```

### Files Removed
- `vendor/opendht-pq/` — entire directory (37,968 lines C++)
- `dht/core/dht_context.cpp` — C++ bridge (2,124 lines)
- `dht/core/dht_listen.cpp` — C++ listen wrapper (569 lines)
- `dht/core/dht_stats.cpp` — C++ stats (81 lines)
- `dht/client/dht_identity.cpp` — C++ identity (replaced by nodus_identity.c)
- `dht/shared/dht_value_storage.cpp` — C++ storage (replaced by nodus_storage.c)
- `dht/shared/dht_chunked.c` — chunking no longer needed (TCP, no size limit)

### Files Preserved (with API changes)
- `dht/shared/dht_offline_queue.c` — same logic, API rename dht_* → nodus_*
- `dht/client/` domain modules — API rename: dht_put_signed() → nodus_put()
- All Flutter/Dart code — unchanged (goes through dna_engine API)

### Dependencies Removed

| Dependency | Before | After |
|-----------|--------|-------|
| GnuTLS | Required | **Removed** |
| libnettle | Required | **Removed** |
| libargon2 | Required | **Removed** |
| msgpack-cxx | Required | **Removed** |
| libfmt | Required | **Removed** |
| ASIO | Required | **Removed** |
| libgmp | Required | **Removed** |

**7 dependencies removed.** Remaining: SQLite3, OpenSSL, json-c (all already used by DNA).

---

## Nodus Server Configuration

```json
{
  "port": 4000,
  "seed_nodes": [
    "154.38.182.161:4000",
    "164.68.105.227:4000",
    "164.68.116.180:4000"
  ],
  "persistence_path": "/var/lib/nodus/data",
  "public_ip": "auto",
  "identity_path": "/var/lib/nodus/identity",
  "limits": {
    "max_puts_per_minute": 60,
    "max_value_size": 1048576,
    "max_values_per_owner": 10000,
    "max_listeners_per_client": 100,
    "max_connections": 1000
  }
}
```

---

## Migration Strategy

1. **No backward compatibility** — clean break (beta project, acceptable)
2. **Client local data safe** — `dnac.db` is the source of truth
3. **DHT data republished** — after upgrade, clients republish profiles/contacts/keys from local DB
4. **Nodus operators** — must upgrade to new nodus-server binary
5. **Rollout:** ship new client + new nodus-server simultaneously

---

## Future Extensions (Not in v1)

- NAT traversal / UDP hole punching (Phase 16: voice/video)
- Relay service (when P2P direct connections needed)
- WebSocket transport (Phase 15: web client)
- Sybil protection (reputation system, Proof-of-Work, or staking)
- Bandwidth/storage quotas per node
- Multi-transport (TCP + WebSocket simultaneously)
