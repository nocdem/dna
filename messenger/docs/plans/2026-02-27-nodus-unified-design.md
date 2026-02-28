# Nodus — Unified DHT & Channel Hosting Platform

**Date:** 2026-02-27
**Status:** DESIGN
**Author:** nocdem + EXECUTOR
**Supersedes:** `2026-02-27-nodus-dht-rewrite-design.md`, `2026-02-26-tcp-channel-hosting-design.md`

---

## 1. Motivation

Replace OpenDHT (37,968 lines C++, 7 external dependencies) and the current DHT-only channel system with a unified **Nodus** platform in pure C.

**Goals:**
1. **Dependency cleanup** — Remove GnuTLS, nettle, argon2, msgpack-cxx, fmt, ASIO, gmp (7 libs)
2. **Protocol control** — DNA-optimized DHT instead of general-purpose Kademlia
3. **TCP channel hosting** — Nodus servers actively host channel data with replication
4. **Public Nodus servers** — Anyone can run a Nodus (scalable network)
5. **Simplicity** — ~10,900 lines pure C replacing 37,968 lines C++ + 2,124 line bridge + 2,000 line chunking

**Non-goals (v1):**
- NAT traversal / hole-punching (future: Phase 16 voice/video)
- Relay service (future: when P2P direct connections needed)
- WebSocket transport (future: Phase 15 web client)
- Sybil protection (Dilithium5 signatures prevent data tampering; censorship risk accepted for v1)
- TLS for TCP connections (posts are already Dilithium5-signed; all DHT values are signed)
- Channel moderation / admin controls
- Channel encryption at rest on Nodus

---

## 2. Architecture

Nodus is a **two-tier network** that provides both DHT key-value storage (profiles, keys, messages) and TCP channel hosting (real-time channel posts).

```
═══════════════════════════════════════════════════════════════
                    NODUS NETWORK (Tier 1)
         Kademlia DHT + Channel Hosting — Nodus servers only
═══════════════════════════════════════════════════════════════

  UDP 4000 (Kademlia routing):
  Nodus-A ◄──FIND_NODE──► Nodus-B ◄──FIND_NODE──► Nodus-C
     │                        │                       │
  TCP 4001 (persistent mesh — data, replication, consensus):
  Nodus-A ◄══STORE/REP══► Nodus-B ◄══STORE/REP══► Nodus-C
     ▲  ▲                   ▲  ▲                    ▲  ▲
     │  │                   │  │                    │  │
═══════════════════════════════════════════════════════════════
                    CLIENTS (Tier 2)
              TCP 4001 — connect to any Nodus
═══════════════════════════════════════════════════════════════
     │  │                   │  │                    │  │
   Alice Bob              Carol Dave              Eve  Frank
```

### Tier 1: Nodus Network

- **Participants:** Public Nodus servers (anyone can run one)
- **DHT routing:** Kademlia XOR-distance (k=8 bucket size, r=3 replication)
- **Channel hosting:** Consistent hash ring sharding with replication factor 3 (1 Primary + 2 Backup)
- **Consensus:** PBFT for ring membership changes (who is in the network)
- **Transport:**
  - **UDP 4000** — Kademlia routing signals only (PING, FIND_NODE, NODES_FOUND). Small, stateless, fast.
  - **TCP 4001** — Persistent mesh for data (STORE, FIND_VALUE), replication, consensus, pub/sub, channel ops.
- **Storage:** SQLite persistent (DHT values + channel post tables)
- **Identity:** Each Nodus has a Dilithium5 key pair, mutual authentication

### Tier 2: Clients

- **Participants:** DNA Messenger users
- **Routing:** None — delegates to connected Nodus
- **Transport:** TCP 4001 (persistent connections for push notifications + channel subscriptions)
- **Storage:** Local SQLite (dnac.db, unchanged)
- **Identity:** User's Dilithium5 key pair (from BIP39 mnemonic)

**Client connection model:**
- **One primary Nodus connection** for DHT operations (PUT, GET, LISTEN)
- **Additional connections per channel** when channel's responsible Nodus differs from primary
- Connection pool with auto-reconnect (exponential backoff: 1s, 2s, 4s, max 30s)
- On disconnect: re-subscribe to all active LISTEN keys and channel subscriptions
- Client learns ring version from first channel operation response; stale ring → `ch_ring_update` from Nodus

### Security Model

- All DHT values signed with Dilithium5 — malicious Nodus cannot tamper with data
- All channel posts signed with Dilithium5 — even a malicious Primary cannot inject fake posts
- Clients verify signatures — never trust Nodus blindly
- Backups independently verify author signatures before storing replicated posts (BFT protection)
- PUT operations require valid signature — unsigned data rejected
- Per-identity rate limiting prevents spam
- Each Nodus has a Dilithium5 identity — mutual auth on all Nodus↔Nodus connections

### Nodus Identity

- **nodus_id** = `SHA3-512(dilithium5_public_key)` = 64 bytes (same as client fingerprint)
- One hash function everywhere: SHA3-512 for all identities (users and Nodus)
- Generated on first startup, stored in identity directory
- Used for: Kademlia routing, authentication, PBFT voting, display
- Keypair used for: inter-nodus mutual auth, PBFT consensus signing, DHT registry publication

### Kademlia Parameters

- **k = 8** — bucket size (routing table capacity: 512 × 8 = 4,096 entries)
- **r = 3** — replication factor (each DHT value on 3 nearest Nodus nodes)
- **Key space:** 512-bit (SHA3-512). All keys and node IDs use SHA3-512 for uniformity

### DHT vs TCP Role Separation

| Concern | Layer | Rationale |
|---------|-------|-----------|
| DHT values (profiles, keys, messages, ACKs) | Kademlia DHT | Distributed, any-key lookup |
| Channel metadata (name, description, UUID) | DHT | Discovery, search, browse |
| Channel post data | TCP Channel Hosting | Real-time, persistent, ordered, replicated |
| Nodus registry ("I'm alive") | DHT | Decentralized, 7-day TTL |
| Ring membership decisions | PBFT Consensus | Deterministic, BFT-safe |
| User authentication | TCP (Dilithium5) | Per-connection challenge-response |

**Design principle:** DHT = phone book (metadata, discovery). TCP = real conversation (data, real-time).

---

## 3. Wire Protocol

### Dual Transport: UDP Routing + TCP Data

| Connection | Transport | Port | What | Persistence |
|-----------|-----------|------|------|-------------|
| Nodus ↔ Nodus (routing) | UDP | 4000 | PING, FIND_NODE, NODES_FOUND | Stateless |
| Nodus ↔ Nodus (data) | TCP | 4001 | STORE, FIND_VALUE, replication, consensus, pub/sub | Persistent mesh |
| Client ↔ Nodus | TCP | 4001 | Auth, PUT, GET, LISTEN, channel ops | Persistent |

**Why UDP for routing?** Kademlia routing messages (PING, FIND_NODE) are tiny (<500 bytes), stateless, and high-frequency. UDP avoids TCP handshake overhead. Traditional DHTs use UDP for this reason.

**Why TCP for data?** STORE/FIND_VALUE carry actual payloads (up to 1MB+). TCP gives reliable delivery, no size limit, no chunking. Channel replication, PBFT consensus, and client connections all need persistent ordered streams.

### Frame Format (shared by UDP and TCP)

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
- **Header size:** 7 bytes fixed

**Size limits:**
- **UDP (port 4000):** Max payload 1400 bytes (safe MTU, no fragmentation). Routing messages are always well under this.
- **TCP (port 4001):** Max frame 4 MB (`NODUS_MAX_FRAME_SIZE`). No practical limit for individual values.

### Serialization: Custom Minimal CBOR (~500-700 lines C)

Only encodes/decodes types we use: maps, byte strings, text strings, unsigned integers, arrays. No floats, tags, or indefinite-length encoding. Still standards-compliant (debuggable at cbor.me).

### CBOR Message Structure

All messages use this common CBOR envelope:

```cbor
{
  "t": <uint32>,              // transaction_id (request/response matching)
  "y": "q" | "r" | "e",      // query, response, error
  "q": "<method_name>",       // method (only in queries)
  "a": { ... },               // arguments (only in queries)
  "r": { ... },               // results (only in responses)
  "tok": <bytes:32>,           // session token (Tier 2 post-auth only)
  "sig": <bytes>,             // Dilithium5 message signature (Tier 1 only)
  "pk": <bytes>               // sender public key (Tier 1 only)
}
```

### Tier 1 Messages (Nodus ↔ Nodus)

**Kademlia routing (UDP 4000):**

| Method | Direction | Transport | Description |
|--------|-----------|-----------|-------------|
| `ping` | N↔N | UDP | Keepalive / liveness check |
| `pong` | N↔N | UDP | Ping response |
| `fn` (find_node) | N↔N | UDP | Find k closest nodes to target |
| `fn_r` (nodes_found) | N↔N | UDP | Response: list of closest nodes |

**DHT data operations (TCP 4001):**

| Method | Direction | Transport | Description |
|--------|-----------|-----------|-------------|
| `sv` (store_value) | N↔N | TCP | Store DHT value on responsible node (carries full NodusValue: data + owner_pk + sig) |
| `sv_ack` | N↔N | TCP | Store acknowledgment |
| `fv` (find_value) | N↔N | TCP | Get value or nearest nodes |
| `fv_r` (value_found) | N↔N | TCP | Response: value data or node list |

**Distributed pub/sub (TCP 4001):**

| Method | Direction | Transport | Description |
|--------|-----------|-----------|-------------|
| `sub` (subscribe) | N→N | TCP | Subscribe Nodus to key changes |
| `unsub` (unsubscribe) | N→N | TCP | Unsubscribe from key |
| `ntf` (notify) | N→N | TCP | Push: value changed (one-way) |

**Channel replication (TCP 4001):**

| Method | Direction | Transport | Description |
|--------|-----------|-----------|-------------|
| `ch_rep` (replicate_post) | Primary→Backup | TCP | Forward post to backup |
| `ch_rep_ack` | Backup→Primary | TCP | Confirm receipt |
| `ch_sync_req` | N→N | TCP | Request full channel sync |
| `ch_sync_data` | N→N | TCP | Channel table dump (chunked) |

**Consensus — PBFT (TCP 4001):**

| Method | Direction | Transport | Description |
|--------|-----------|-----------|-------------|
| `pbft` | N↔N | TCP | PBFT protocol messages (PRE-PREPARE, PREPARE, COMMIT, VIEW_CHANGE) |

### Tier 2 Messages (Client ↔ Nodus — TCP 4001)

**Authentication (pre-auth):**

| Method | Direction | Description |
|--------|-----------|-------------|
| `hello` | C→N | fingerprint + public_key |
| `challenge` | N→C | 32-byte random nonce |
| `auth` | C→N | SIGN(nonce, private_key) |
| `auth_ok` | N→C | Session authenticated |

**DHT operations (post-auth):**

| Method | Direction | Description |
|--------|-----------|-------------|
| `put` | C→N | Store DHT value |
| `get` | C→N | Retrieve newest value for key (highest seq, single-writer shortcut) |
| `get_all` | C→N | Retrieve all values for key (all owners — multi-writer) |
| `batch_get` | C→N | Parallel multi-key fetch |
| `listen` | C→N | Subscribe to key changes |
| `unlisten` | C→N | Unsubscribe from key |
| `ping` | C→N | Keepalive |

**DHT push responses:**

| Method | Direction | Description |
|--------|-----------|-------------|
| `value_changed` | N→C | Push: LISTEN key updated |
| `result` | N→C | GET/PUT response |
| `error` | N→C | Error response |
| `pong` | N→C | Keepalive response |

**Channel operations (post-auth):**

| Method | Direction | Description |
|--------|-----------|-------------|
| `ch_create` | C→N | Create new channel on responsible Nodus |
| `ch_post` | C→N | Submit post (channel_uuid + body + signature) |
| `ch_get_posts` | C→N | Fetch posts since seq_id |
| `ch_subscribe` | C→N | Subscribe to real-time channel posts |
| `ch_unsubscribe` | C→N | Unsubscribe from channel |

**Channel push responses:**

| Method | Direction | Description |
|--------|-----------|-------------|
| `ch_post_notify` | N→C | Push: new post arrived |
| `ch_posts_response` | N→C | Response to ch_get_posts |
| `ch_ring_update` | N→C | New ring version + nodus list |
| `ch_created` | N→C | Channel creation confirmed |

### CBOR Payload Examples

**PUT (DHT value):**
```cbor
{
  "t": 42,
  "y": "q",
  "q": "put",
  "a": {
    "k": <bytes:key>,
    "d": <bytes:data>,
    "type": 1,          // EPHEMERAL
    "ttl": 604800,      // 7 days
    "vid": 1,           // value_id
    "seq": 0,           // sequence number
    "sig": <bytes:4627> // Dilithium5 SIGN(k + d + type + ttl + vid + seq)
    // NOTE: owner not sent — Nodus fills owner_fp and owner_pk from authenticated session
  }
}
```

**Channel POST:**
```cbor
{
  "t": 43,
  "y": "q",
  "q": "ch_post",
  "a": {
    "ch": <bytes:16>,   // channel_uuid
    "id": <bytes:16>,   // post_uuid (client-generated UUID v4)
    "ts": 1709000000,   // author's timestamp
    "body": "Hello world",
    "sig": <bytes:4627> // SIGN(ch + id + ts + body)
    // NOTE: author_fp not sent — Nodus fills it from authenticated session identity
  }
}
```

**PBFT Consensus:**
```cbor
{
  "t": 100,
  "y": "q",
  "q": "pbft",
  "a": {
    "phase": 1,         // 1=PRE_PREPARE, 2=PREPARE, 3=COMMIT, 4=VIEW_CHANGE
    "view": 0,
    "seq": 1,
    "change": 2,        // 1=ADD_NODUS, 2=REMOVE_NODUS
    "target": <bytes:64>,  // target nodus_id (SHA3-512)
    "ring_ver": 2,      // proposed new version
    "ring": [<bytes:64>, ...],  // proposed nodus list (SHA3-512 IDs)
    "evidence": <bytes> // suspect votes / proof
  },
  "sig": <bytes:4627>,
  "pk": <bytes:2592>
}
```

### Error Codes

| Code | Meaning |
|------|---------|
| 1 | NOT_AUTHENTICATED |
| 2 | NOT_FOUND |
| 3 | INVALID_SIGNATURE |
| 4 | RATE_LIMITED |
| 5 | TOO_LARGE |
| 6 | TIMEOUT |
| 7 | PROTOCOL_ERROR |
| 8 | INTERNAL_ERROR |
| 10 | CHANNEL_NOT_FOUND |
| 11 | NOT_RESPONSIBLE — wrong Nodus for this channel |
| 12 | RING_MISMATCH — client ring is stale |

---

## 4. Authentication

### Client → Nodus (3-Way Handshake)

```
1. Client → Nodus:  HELLO(client_pubkey, fingerprint)
2. Nodus:           verify: fingerprint == SHA3-512(pubkey)
3. Nodus → Client:  CHALLENGE(random_nonce_32B)
4. Client → Nodus:  AUTH(sign(nonce, client_privkey))
5. Nodus:           VERIFY(signature, nonce, pubkey)
                    ✓ → AUTH_OK(session_token)
                    ✗ → ERROR, disconnect
```

- Authentication is **mandatory** for all operations (reads and writes)
- **Session token:** 32-byte random token generated by Nodus on AUTH_OK. Included as `"tok"` field in all subsequent CBOR messages from client. Nodus maps token → authenticated identity (in-memory hash table). No per-message Dilithium5 verification needed after auth.
- **Session expiry:** Token valid for TCP connection lifetime. On disconnect → token invalidated. No application-level timeout.
- **Dead client detection:** Nodus sets aggressive TCP keepalive on client sockets: `TCP_KEEPIDLE=30s, TCP_KEEPINTVL=10s, TCP_KEEPCNT=3` → ~60s detection of crashed clients. On TCP drop → session invalidated, all subscriptions cleaned up.
- Client sends public_key in HELLO to avoid DHT lookup delay
- Even users who haven't registered a DHT profile can connect (key-only identity)

### Nodus ↔ Nodus (Mutual Handshake)

```
1. Nodus-A → Nodus-B:  HELLO(A_pubkey, A_node_id)
2. Nodus-B → Nodus-A:  CHALLENGE(nonce_for_A)
3. Nodus-A → Nodus-B:  AUTH(sign(nonce_for_A, A_privkey))
4. Nodus-B validates → A is authenticated
5. (Reverse direction: B authenticates to A similarly)
6. Both sides: session established, mutual trust
```

### Crypto Functions Used

| Operation | Function | Header |
|-----------|----------|--------|
| Sign | `qgp_dsa87_sign()` | `crypto/utils/qgp_dilithium.h` |
| Verify | `qgp_dsa87_verify()` | `crypto/utils/qgp_dilithium.h` |
| Fingerprint | `qgp_sha3_512_fingerprint()` | `crypto/utils/qgp_sha3.h` |
| Hash (key) | `qgp_sha3_512()` | `crypto/utils/qgp_sha3.h` |
| Random nonce | `qgp_platform_random()` | `crypto/utils/qgp_platform.h` |

### Crypto Constants

| Constant | Value |
|----------|-------|
| `QGP_DSA87_PUBLICKEYBYTES` | 2592 |
| `QGP_DSA87_SECRETKEYBYTES` | 4896 |
| `QGP_DSA87_SIGNATURE_BYTES` | 4627 |
| `QGP_SHA3_512_DIGEST_LENGTH` | 64 |

---

## 5. Data Model

### 5.1 DHT Values (NodusValue)

```cbor
{
  "vid":     <uint64>,    // Unique value ID per writer
  "key":     <bytes>,     // DHT key (raw, pre-hash)
  "data":    <bytes>,     // Payload (up to 4 MB, TCP frame limit)
  "type":    <uint8>,     // 0x01=EPHEMERAL, 0x02=PERMANENT
  "ttl":     <uint32>,    // TTL seconds (0 = permanent)
  "created": <uint64>,    // Unix timestamp
  "seq":     <uint64>,    // Sequence number for updates
  "owner":   <bytes>,     // Dilithium5 public key (2,592 bytes)
  "sig":     <bytes>      // Dilithium5 SIGN(key + data + type + ttl + vid + seq)
}
```

**Value Types:**

| Type | ID | TTL | Republish on restart | Use |
|------|----|-----|---------------------|-----|
| EPHEMERAL | 0x01 | 7 days | Yes, if `created_at + ttl > now` | Messages, ACKs, temp data |
| PERMANENT | 0x02 | ∞ | Always | Profiles, names, keys, backups, wall posts |

**Cleanup rule:** Expired EPHEMERAL values deleted on periodic sweep. Once `created_at + ttl` has passed, the value is deleted and never republished.

**Conflict Resolution:**
- Same `(key, owner, value_id)` → highest `seq` wins (old value overwritten via INSERT OR REPLACE)
- Different owners on same key → all values stored side-by-side (multi-writer)
- `GET` returns single best match (highest seq among all owners) — for single-owner keys like profiles
- `GET_ALL` returns every owner's values — for multi-writer keys like registry, outbox
- Receiving Nodus verifies signature with owner_pk before storing — tampered values rejected
- **Delete:** No explicit delete operation. EPHEMERAL values expire naturally. PERMANENT values: overwrite with empty data (`PUT` same key/vid, higher seq, data=empty). Nodus treats zero-length data as tombstone.

### 5.2 Channel Posts

```cbor
{
  "ch":      <bytes:16>,  // channel_uuid (UUID v4)
  "id":      <bytes:16>,  // post_uuid (client-generated UUID v4)
  "seq":     <uint32>,    // sequential ID (assigned by Primary nodus)
  "author":  <bytes:64>,  // SHA3-512 fingerprint
  "ts":      <uint64>,    // author's timestamp (for UX display)
  "recv_at": <uint64>,    // nodus receive time (for system ops)
  "body":    <text>,      // UTF-8 post content (max 4000 chars)
  "sig":     <bytes>      // Dilithium5 SIGN(ch + id + ts + body)
}
```

**Two timestamps, two purposes:**
- `ts` — author's claimed time → displayed in UI
- `recv_at` — nodus receive time → used for retention, sync, ordering

Why not trust author timestamp for retention? A malicious user could set their clock to 2030 — the post would never expire. `recv_at` prevents this.

**Sequence ID:**
- Assigned by Primary Nodus on receipt
- Monotonically increasing per channel
- **seq_ids are immutable** — once assigned, never changed (even after failover)
- On primary failover: new primary continues from `MAX(seq_id) + 1`
- Gaps in seq_id sequence are normal (caused by failover transitions)
- Client uses seq_id for sync: "give me posts after seq_id X" — always valid

**Posts are immutable** — once created, never modified or deleted (within retention window). This eliminates write conflicts (CRDT-like).

**Conflict Resolution (after failover):**
- Each post has globally unique `post_uuid` (UUID v4, client-generated)
- Duplicate detection: if `post_uuid` already exists, discard
- After ring change with data merge: new posts get new seq_ids from `MAX(seq_id) + 1`, existing posts keep their seq_ids unchanged
- Client's `last_seq_id` remains valid across failovers — no refetch needed

---

## 6. DHT Core

### 6.1 Kademlia Routing

Standard Kademlia with 512-bit key space (SHA3-512). Routing table = 512 k-buckets. Each bucket holds up to k=8 peers. Bucket index = leading zero bits in `XOR(my_id, peer_id)`.

**PUT flow:**
```
1. Client → Nodus-X: PUT(key, value)
2. Nodus-X: find 3 nearest Nodus by XOR distance to SHA3-512(key)
3. Nodus-X → Nodus-A, Nodus-B, Nodus-C: STORE(key, value)
4. 2/3 ACK (quorum) → return success to client
```

**GET flow:**
```
1. Client → Nodus-X: GET(key)
2. Nodus-X: am I responsible? → serve directly
3. Not responsible → route to nearest responsible Nodus, proxy response
```

### 6.2 Distributed LISTEN (Pub/Sub)

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
- Nodus-X goes down → TCP connection drops → Nodus-Z immediately removes all Nodus-X subscriptions

### 6.3 DHT Replication (r=3)

Each value replicated to r=3 nearest Nodus nodes by XOR distance. Quorum: 2/3 ACK for success. Background republish from SQLite on restart.

### 6.4 Rate Limiting

Configurable per Nodus operator:
```json
{
  "limits": {
    "max_puts_per_minute": 60,
    "max_value_size": 1048576,
    "max_values_per_owner": 10000,
    "max_listeners_per_client": 100,
    "max_connections": 1000
  }
}
```

All PUTs require Dilithium5 signature → anonymous spam impossible. Rate limits are per authenticated identity.

---

## 7. Channel Hosting

### 7.1 Consistent Hash Ring (Sharding)

**Algorithm:**
1. Each Nodus has a position on the ring: `nodus_id` (already SHA3-512 of pubkey — no double hash)
2. Each channel has a position: `SHA3-512(channel_uuid)`
3. Walk clockwise from channel position → first 3 distinct Nodus = [Primary, Backup1, Backup2]

**Determinism:** Every participant (client + all Nodus) MUST compute the same ring from the same input. Same hash function, same Nodus list (sorted by nodus_id), same clockwise walk.

**Ring Versioning:**
- Every ring change produces a new version number (uint32)
- Nodus detects stale client ring → sends `ch_ring_update`
- Client recalculates and reconnects if needed

### 7.2 Nodus Discovery (DHT Registry)

```
DHT Key:   SHA3-512("dna:system:nodus:registry")
Value:     { nodus_id, ip, udp_port, tcp_port, pubkey, timestamp }
TTL:       7 days (EPHEMERAL)
```

- Each Nodus publishes its registry entry on startup and periodically
- Clients fetch and cache the Nodus list
- TCP connectivity is the real liveness check, not DHT presence

### 7.3 Channel Lifecycle

**Channel Creation:**
```
1. User generates channel UUID (client-side, UUID v4)
2. User publishes channel metadata to DHT:
   Key: SHA3-512("dna:channel:" + uuid)
   Value: { uuid, name, description, creator_fp, created_at }
3. Client computes: SHA3-512(uuid) → ring → [Primary, B1, B2]
4. Client TCP connects to Primary
5. Sends ch_create { uuid, name, description }
6. Primary creates SQLite table → replicates to B1, B2
7. Primary responds ch_created { uuid, seq_id_start: 0 }
8. Channel is live
```

**Posting:**
```
1. Client computes channel's Nodus: SHA3-512(uuid) → [Primary, B1, B2]
2. TCP connect to Primary (or next available on failover)
3. Send ch_post { channel_uuid, post_uuid, timestamp, body, signature }
   - signature = SIGN(channel_uuid + post_uuid + timestamp + body)
4. Nodus verifies signature using client's authenticated public_key
5. Nodus assigns seq_id, stores in SQLite, ACKs
6. Nodus pushes ch_post_notify to all subscribed TCP clients
7. Nodus async replicates to backups (ch_rep)
```

**Subscribe (Real-Time):**
```
1. Client sends ch_subscribe { channel_uuid }
2. Nodus registers client in in-memory subscriber map
3. When new post arrives → ch_post_notify pushed to all subscribers
4. Client sends ch_unsubscribe or TCP disconnects → removed
```

**Reconnection / Sync:**
```
1. Client reconnects, authenticates
2. Sends ch_get_posts { channel_uuid, since_seq_id: last_known }
3. Nodus returns all posts with seq_id > since_seq_id
4. Client merges into local SQLite cache
5. Client re-sends ch_subscribe for real-time push
```

### 7.4 Channel Replication (Async)

```
Client ──ch_post──► Primary Nodus
                        │
                        ├─► store locally (SQLite) → assign seq_id → ACK to client
                        │
                        └─► background: ch_rep to Backup1, Backup2
                              ├─► Backup1: verify sig, store → ch_rep_ack
                              └─► Backup2: verify sig, store → ch_rep_ack

                        ch_rep_ack failure → hinted handoff queue
```

**Async tradeoff:** Primary ACKs immediately without waiting for backup confirmation. If primary crashes between ACK and replication, the last few posts may be lost. For channel posts (not banking transactions), this is acceptable for low latency.

**BFT protection:** Backup independently verifies the author's Dilithium5 signature on every replicated post. Even a malicious Primary cannot inject fake posts.

**Hinted Handoff (Temporary Failures):**
- When backup is temporarily unreachable: store post in `hinted_handoff` queue
- Retry every 30 seconds
- When backup returns: flush all hinted posts
- Max 1000 hinted posts per target Nodus (oldest dropped if exceeded — full sync catches up)

### 7.5 Client-Driven Failover

```
Channel X → ring says [N3, N7, N1]

Client:
  TCP connect N3 (Primary)  → timeout/refused → N3 is down
  TCP connect N7 (Backup1)  → success → use N7
  TCP connect N1 (Backup2)  → last resort
  All 3 fail                → error to user
```

No coordination needed. Client knows the ring, tries in order.

### 7.6 Channel Transfer (Ring Change)

```
Ring v2 → v3: Channel X moves from [N1, N5, N2] back to [N3, N7, N1]

N1 (has data, stays in set):
  - Sends ch_sync_data to N3 (new primary)
  - N3 receives full channel table dump (chunked)
  - N7 also receives full channel table dump
  - Transfer complete, N3 is new primary
  - N5, N2 drop Channel X table (no longer responsible)
```

**Transfer initiator:** The surviving Nodus that has channel data initiates sync. If the removed Nodus was the only one with data (unlikely with r=3), the channel data is lost until clients re-post.

### 7.7 Nodus Bootstrap (Joining the Network)

Fully automatic — no manual approval needed.

```
New Nodus (N-new) starts for the first time:

1. IDENTITY
   - Generate Dilithium5 keypair
   - nodus_id = SHA3-512(pubkey)
   - Store in identity_path

2. CONNECT TO SEEDS
   - TCP 4001 connect to each seed_node in config
   - Mutual Dilithium5 authentication
   - First successful connection = bootstrap peer

3. PEER DISCOVERY
   - Bootstrap peer sends current ring member list (nodus_id, ip, ports)
   - N-new populates routing table
   - UDP 4000: FIND_NODE(own_id) to discover nearest peers (standard Kademlia bootstrap)

4. ANNOUNCE
   - N-new publishes registry entry to DHT:
     Key: SHA3-512("dna:system:nodus:registry")
     Value: { nodus_id, ip, udp_port, tcp_port, pubkey, timestamp }
   - Establishes TCP mesh connections to all known Nodus

5. AUTO-PROPOSE (triggered by bootstrap peer)
   - Bootstrap peer detects new authenticated Nodus connection
   - Bootstrap peer automatically initiates PBFT proposal: "add N-new to ring"
   - Other Nodus verify: N-new is reachable (TCP + UDP) → vote YES
   - Quorum reached → ring version incremented, N-new is in the ring

6. CHANNEL DATA SYNC
   - N-new computes new ring → determines which channels it's now responsible for
   - For each channel: requests ch_sync_data from existing responsible Nodus
   - Receives full channel table dumps
   - N-new is now fully operational
```

**First-ever bootstrap (genesis):** When the very first 3 Nodus start with each other as seeds, there's no existing ring. Each Nodus proposes itself. With f=0 (3 nodes), quorum=2. Once 2 Nodus see each other, they form the initial ring. Third joins via normal bootstrap.

**Spam prevention:** A Nodus can only be proposed if it has a valid Dilithium5 identity and is reachable on both UDP 4000 and TCP 4001. Existing Nodus verify connectivity before voting YES.

### 7.8 Nodus Graceful Shutdown

```
Nodus N3 wants to leave for maintenance:

1. N3 sends PBFT proposal: "remove N3 from ring" (self-removal)
2. Quorum reached → new ring version without N3
3. N3 initiates channel transfer:
   - For each channel N3 is responsible for:
     compute new responsible set (without N3)
     send ch_sync_data to new responsible Nodus
4. All transfers complete → N3 closes TCP connections, shuts down
5. If N3 crashes before transfers complete:
   - Remaining backups already have data (r=3)
   - Normal failover handles it
```

---

## 8. PBFT Consensus (Ring Membership)

### Purpose

Consensus decides ONE thing: **who is in the ring**. Posts, subscriptions, and data operations do NOT go through consensus.

### Quorum

```
n = total Nodus count
f = max Byzantine faults tolerated
Constraint: n ≥ 3f + 1

For 3 nodus:   f = 0, quorum = 1 (no fault tolerance — bootstrap mode)
For 8 nodus:   f = 2, quorum = 6 out of 8
For 12 nodus:  f = 3, quorum = 7 out of 12
For 20 nodus:  f = 6, quorum = 13 out of 20
```

### Failure Detection

```
┌─────────┐   30s no heartbeat   ┌──────────┐   quorum vote   ┌──────┐
│  ALIVE  │ ──────────────────► │  SUSPECT  │ ──────────────► │ DEAD │
└─────────┘                      └──────────┘                  └──────┘
     ▲                                │                            │
     │         heartbeat received     │                            │
     └────────────────────────────────┘                            │
     │                                                             │
     │              nodus comes back + PBFT "add" proposal         │
     └─────────────────────────────────────────────────────────────┘
```

1. Each Nodus sends PING to all peers every 10 seconds via UDP 4000
2. No PONG for 30 seconds AND TCP 4001 connection lost → mark peer as SUSPECT
3. When `ceil(n/2)` Nodus independently mark same peer as SUSPECT → trigger PBFT proposal
4. PBFT proposal: "remove N3 from ring" → requires 2f+1 votes
5. If Nodus comes back: new PBFT proposal "add N3 to ring"

### PBFT Protocol Phases

```
Phase 1: PRE-PREPARE
  Proposer → all: "I propose removing N3 (view=V, seq=S)"

Phase 2: PREPARE
  Each Nodus that agrees → all: "I accept (view=V, seq=S)"
  Wait for 2f+1 PREPARE messages

Phase 3: COMMIT
  Each Nodus that received 2f+1 PREPAREs → all: "I commit (view=V, seq=S)"
  Wait for 2f+1 COMMIT messages

Result: New ring version applied by all committed Nodus
```

**View Change:** If proposer fails during consensus, PBFT view change elects new leader.

### Split Brain Prevention

```
8 nodus, partition into [N1-N4] and [N5-N8]:
  - Each side has 4 nodus
  - PBFT quorum requires 6 (for f=2)
  - Neither side reaches quorum
  - Ring does NOT change → no split brain
  - Both sides continue serving existing data
  - No ring changes until partition heals
```

### Consensus Interface (Swappable)

```c
typedef struct {
    int (*propose_ring_change)(ring_change_t *change);
    ring_t* (*get_current_ring)(void);
    uint32_t (*get_ring_version)(void);
    int (*on_consensus_msg)(const uint8_t *data, size_t len, const char *sender_fp);
} consensus_interface_t;
```

Future: if Nodus count exceeds ~50, swap PBFT (O(n²)) for HotStuff (O(n)) behind same interface.

### Scalability

| Nodus Count | Messages Per Round | Practical? |
|-------------|-------------------|------------|
| 3 | 9 | Yes — minimum deployment |
| 8 | 64 | Yes — current target |
| 20 | 400 | Yes — manageable |
| 50 | 2,500 | Borderline — consider swap |
| 100+ | 10,000+ | No — swap to HotStuff |

---

## 9. Storage

### 9.1 Nodus DHT Storage (SQLite)

```sql
CREATE TABLE nodus_values (
  key_hash    TEXT NOT NULL,
  owner_fp    TEXT NOT NULL,           -- SHA3-512 of owner pubkey (128 hex chars)
  value_id    INTEGER NOT NULL,
  data        BLOB NOT NULL,
  type        INTEGER NOT NULL,       -- 1=EPHEMERAL, 2=PERMANENT
  ttl         INTEGER NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER,                -- NULL = permanent
  owner_pk    BLOB NOT NULL,          -- Dilithium5 pubkey (2592 bytes, for sig verify)
  signature   BLOB NOT NULL,          -- Dilithium5 sig (4627 bytes)
  seq         INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (key_hash, owner_fp, value_id)  -- multi-writer: same key, different owners
);
CREATE INDEX idx_expires ON nodus_values(expires_at);
CREATE INDEX idx_key ON nodus_values(key_hash);

CREATE TABLE nodus_peers (
  node_id     TEXT PRIMARY KEY,
  ip          TEXT NOT NULL,
  udp_port    INTEGER NOT NULL,       -- Kademlia routing (default 4000)
  tcp_port    INTEGER NOT NULL,       -- Data, clients, channels (default 4001)
  pubkey      BLOB,
  last_seen   INTEGER NOT NULL,
  rtt_ms      INTEGER DEFAULT 0
);

CREATE TABLE nodus_subscriptions (
  key_hash      TEXT NOT NULL,
  subscriber_id TEXT NOT NULL,        -- which Nodus is listening
  subscribed_at INTEGER NOT NULL,
  PRIMARY KEY (key_hash, subscriber_id)
);
-- Cleanup: when TCP connection to subscriber_id drops, DELETE all its subscriptions.
-- No heartbeat column needed — TCP connection state is the liveness signal.
```

**Restart recovery:** On startup, Nodus re-joins ring via bootstrap flow (7.7). To discover which channel tables it already has locally: `SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'channel_%'`. Compare with ring-computed responsibilities — drop tables no longer owned, request sync for newly assigned channels.

### 9.2 Nodus Channel Storage (SQLite)

**SECURITY: UUID validation required.** Channel UUID is client-generated. Before using in table name, Nodus MUST validate: `^[0-9a-f]{32}$` (hex-only, exactly 32 chars). Reject anything else — prevents SQL injection via crafted UUIDs.

```sql
-- Created dynamically when channel is assigned to this Nodus
-- Table name: "channel_" + validated hex UUID (e.g., channel_550e8400e29b41d4a716446655440000)
CREATE TABLE channel_<uuid_hex> (
    seq_id       INTEGER NOT NULL,
    post_uuid    BLOB NOT NULL,
    author_fp    BLOB NOT NULL,       -- 64 bytes SHA3-512
    timestamp    INTEGER NOT NULL,    -- author's timestamp (UX display)
    body         BLOB NOT NULL,
    signature    BLOB NOT NULL,       -- Dilithium5 (4627 bytes)
    received_at  INTEGER NOT NULL,    -- nodus receive time (system ops)
    PRIMARY KEY (seq_id)
);
CREATE INDEX idx_<uuid_hex>_recv ON channel_<uuid_hex>(received_at);
CREATE UNIQUE INDEX idx_<uuid_hex>_uuid ON channel_<uuid_hex>(post_uuid);

-- 7-day retention cleanup (periodic, every hour)
DELETE FROM channel_<uuid_hex> WHERE received_at < strftime('%s','now') - 604800;

-- Hinted handoff queue (shared across all channels)
CREATE TABLE hinted_handoff (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_fp    BLOB NOT NULL,       -- Target nodus fingerprint
    channel_uuid BLOB NOT NULL,
    post_data    BLOB NOT NULL,       -- Full serialized post
    created_at   INTEGER NOT NULL,
    retry_count  INTEGER DEFAULT 0,
    expires_at   INTEGER NOT NULL     -- created_at + 86400 (24h TTL)
);
CREATE INDEX idx_hinted_target ON hinted_handoff(target_fp);
CREATE INDEX idx_hinted_expires ON hinted_handoff(expires_at);

-- Hinted handoff cleanup (periodic, every 10 min)
-- Permanently dead targets get cleaned up after 24h
DELETE FROM hinted_handoff WHERE expires_at < strftime('%s','now');
```

### 9.3 Client-Side Cache (SQLite)

**Note:** Client uses TEXT for UUIDs/fingerprints (hex strings) to match existing `dnac.db` conventions. Server uses BLOB for efficiency. Wire protocol uses binary (CBOR bytes). Client converts on receive.

```sql
-- Channel post cache on client device
CREATE TABLE tcp_channel_posts (
    channel_uuid TEXT NOT NULL,
    seq_id       INTEGER NOT NULL,
    post_uuid    BLOB NOT NULL,
    author_fp    TEXT NOT NULL,        -- 128 hex chars
    timestamp    INTEGER NOT NULL,
    body         TEXT NOT NULL,
    received_at  INTEGER NOT NULL,
    PRIMARY KEY (channel_uuid, seq_id)
);

CREATE TABLE tcp_channel_sync_state (
    channel_uuid TEXT PRIMARY KEY,
    last_seq_id  INTEGER NOT NULL,
    last_sync    INTEGER NOT NULL,
    nodus_ip     TEXT,
    nodus_port   INTEGER
);
```

---

## 10. Inter-Nodus Communication

### UDP 4000 — Kademlia Routing

Stateless UDP for lightweight routing signals:
- **PING/PONG** — liveness check (every 10s per peer)
- **FIND_NODE / NODES_FOUND** — routing table population

Each Nodus sends/receives UDP datagrams to any known peer. No persistent connection. Same 7-byte frame header + CBOR payload. Max 1400 bytes per datagram (safe MTU).

### TCP 4001 — Persistent Mesh

All Nodus maintain **persistent TCP connections** to every other Nodus:

```
8 nodus → each has 7 TCP connections = 28 total (full mesh)
  N1 ←→ N2, N3, N4, N5, N6, N7, N8
  N2 ←→ N3, N4, N5, N6, N7, N8
  ... (full mesh)
```

**Used for:**
1. DHT data operations (STORE, FIND_VALUE — payload can be large)
2. Channel replication (ch_rep / ch_rep_ack)
3. PBFT consensus messages
4. Channel transfer (ch_sync_req / ch_sync_data)
5. Pub/sub (SUBSCRIBE, NOTIFY)

**Connection management:**
- Same wire protocol (7-byte header + CBOR)
- Mutual Dilithium5 authentication on TCP connect
- Auto-reconnect with exponential backoff (1s, 2s, 4s, max 30s)
- TCP connection loss + UDP PING timeout → triggers suspect detection (see PBFT section)

**Note:** Health monitoring uses **both** transports: UDP PING/PONG for fast stateless checks, TCP connection status for reliable detection. A Nodus is SUSPECT only when both UDP PING timeout (30s) and TCP connection is lost.

---

## 11. Module Structure

```
nodus/
├── include/nodus/
│   ├── nodus.h                 // Public client API (DHT + channels)
│   ├── nodus_server.h          // Server API
│   └── nodus_types.h           // Shared types
│
├── src/
│   ├── core/
│   │   ├── nodus_routing.c     // Kademlia routing table (k-buckets, XOR)
│   │   ├── nodus_storage.c     // SQLite DHT value storage + cleanup
│   │   └── nodus_value.c       // Value create/verify/serialize
│   │
│   ├── protocol/
│   │   ├── nodus_wire.c        // Frame encode/decode (7-byte header)
│   │   ├── nodus_cbor.c        // Minimal CBOR encoder/decoder (~500 lines)
│   │   ├── nodus_tier1.c       // Nodus↔Nodus: Kademlia + pub/sub + replication + consensus
│   │   └── nodus_tier2.c       // Client↔Nodus: DHT ops + channel ops
│   │
│   ├── transport/
│   │   ├── nodus_tcp.c         // TCP socket + connection pool + mesh management (port 4001)
│   │   └── nodus_udp.c         // UDP socket for Kademlia routing (port 4000)
│   │
│   ├── crypto/
│   │   ├── nodus_sign.c        // Dilithium5 sign/verify wrapper
│   │   └── nodus_identity.c    // Key generation, import/export
│   │
│   ├── channel/
│   │   ├── nodus_hashring.c    // Consistent hash ring (SHA3-512)
│   │   ├── nodus_channel_store.c  // Per-channel SQLite tables + retention
│   │   ├── nodus_replication.c // Async replication + hinted handoff
│   │   └── nodus_channel_ops.c // Channel CRUD + subscribe + POST_NOTIFY
│   │
│   ├── consensus/
│   │   └── nodus_pbft.c        // PBFT state machine + ring membership
│   │
│   ├── client/
│   │   ├── nodus_client.c      // Client SDK (connect, auth, put, get, listen, channel ops)
│   │   ├── nodus_singleton.c   // Global singleton for DNA engine
│   │   └── nodus_compat.c      // DHT API backward compat shim
│   │
│   └── server/
│       ├── nodus_server.c      // Server main loop + event dispatch
│       ├── nodus_discovery.c   // Peer discovery (Nodus registry via DHT)
│       └── nodus_auth.c        // Dilithium5 auth handshake (client + nodus)
│
├── tools/
│   └── nodus-server.c          // Server binary entry point
│
├── tests/
│   ├── test_cbor.c
│   ├── test_value.c
│   ├── test_routing.c
│   ├── test_storage.c
│   ├── test_hashring.c
│   ├── test_channel_store.c
│   └── test_integration.c
│
└── CMakeLists.txt
```

### Estimated Size

| Module | Lines (est.) | Description |
|--------|-------------|-------------|
| core/ | ~2,000 | Routing table, DHT storage, value types |
| protocol/ | ~2,000 | Wire, CBOR, Tier 1/2 messages (DHT + channel) |
| transport/ | ~1,000 | TCP (mesh + pool) + UDP (Kademlia routing) |
| crypto/ | ~500 | Dilithium5 sign/verify wrapper |
| channel/ | ~2,000 | Hash ring, channel storage, replication, ops |
| consensus/ | ~1,000 | PBFT state machine |
| client/ | ~1,200 | Client SDK (DHT + channels) + singleton + compat |
| server/ | ~1,200 | Server, discovery, auth |
| **Total** | **~10,900** | **vs OpenDHT 37,968 + bridge 2,124 + chunked 2,000** |

---

## 12. Test Strategy (Hybrid Bottom-Up)

Development and testing follow a **5-phase bottom-up** approach. Each phase builds on the previous, with CLI testing at every step. No phase is "Nodus-only" or "client-only" — the CLI client validates each layer as it's built.

### Phase 1: Foundation (No process needed)

Unit tests — compile and run, no server required.

| Test | What it validates |
|------|-------------------|
| `test_cbor` | CBOR encode/decode for all message types |
| `test_wire` | 7-byte frame header encode/decode, size limits |
| `test_value` | NodusValue create, serialize, sign, verify |
| `test_routing` | K-bucket insert, XOR distance, find_closest |
| `test_storage` | SQLite nodus_values CRUD, expiry sweep, multi-writer PK |
| `test_hashring` | Consistent hash ring: position, clockwise walk, rebalance |

```bash
cd build && ctest --output-on-failure
```

### Phase 2: Single Nodus + CLI Client

One Nodus server process + CLI as client. **No routing, no replication** — single-node mode.

| Test | CLI command | What it validates |
|------|-------------|-------------------|
| TCP connect | `nodus-cli connect <ip>:4001` | TCP connection, frame exchange |
| Auth handshake | `nodus-cli auth` | Dilithium5 challenge-response, session token |
| PUT/GET | `nodus-cli put <key> <value>` / `nodus-cli get <key>` | DHT store + retrieve (local, no forwarding) |
| LISTEN | `nodus-cli listen <key>` | Subscribe, then PUT from another session → push received |
| Multi-writer | Two CLIs with different identities PUT to same key | GET_ALL returns both values |
| Tombstone | `nodus-cli put <key> --delete` | Empty data overwrites, treated as tombstone |
| Channel create | `nodus-cli ch-create <name>` | Channel table created in SQLite |
| Channel post | `nodus-cli ch-post <uuid> "hello"` | Post stored, seq_id assigned |
| Channel subscribe | `nodus-cli ch-subscribe <uuid>` | Real-time push on new post |
| Channel sync | `nodus-cli ch-get-posts <uuid> --since 0` | Fetch all posts |

```bash
# Terminal 1: start single nodus
./nodus-server --config test-single.conf

# Terminal 2: CLI tests
./nodus-cli -d /tmp/test-identity connect 127.0.0.1:4001
./nodus-cli put "test:key" "hello world"
./nodus-cli get "test:key"
```

### Phase 3: Two Nodus (Peer Discovery + Replication)

Two Nodus servers, each other as seed. Tests routing and replication.

| Test | What it validates |
|------|-------------------|
| Peer discovery | N1 and N2 find each other via UDP FIND_NODE |
| Mutual auth | TCP mesh connection with Dilithium5 |
| STORE forwarding | PUT to N1 → STORE to N2 (r=2 with 2 nodes) |
| GET routing | GET from N1 for key closer to N2 → forwarded, response proxied |
| LISTEN across nodes | Client LISTENs on N1, PUT arrives at N2 → NOTIFY → VALUE_CHANGED |
| DHT replication | Value stored on both nodes (r=min(3, node_count)) |

```bash
# Two Nodus on localhost with different ports
./nodus-server --config test-n1.conf   # UDP 4000, TCP 4001
./nodus-server --config test-n2.conf   # UDP 4002, TCP 4003

# CLI connects to N1, puts data, verify on N2
./nodus-cli connect 127.0.0.1:4001
./nodus-cli put "test:key" "replicated?"
./nodus-cli connect 127.0.0.1:4003
./nodus-cli get "test:key"   # should find it
```

### Phase 4: Three Nodus (PBFT + Channel Hosting)

Three Nodus = minimum for PBFT (f=0, quorum=2) and hash ring sharding.

| Test | What it validates |
|------|-------------------|
| PBFT bootstrap | 3 nodes form ring via auto-propose |
| Ring computation | All 3 compute same ring for same channel UUID |
| Channel sharding | Channel assigned to correct [Primary, B1, B2] |
| Channel replication | Post on Primary → ch_rep to B1, B2 |
| Primary failover | Kill Primary → client connects to B1, posts continue |
| Hinted handoff | Kill B2, post, restart B2 → hinted posts delivered |
| Graceful shutdown | N3 self-removes → channels transferred → ring updated |
| New node join | Start N4 → auto-propose → ring rebalance → channel data sync |

```bash
# Three Nodus
./nodus-server --config test-n1.conf
./nodus-server --config test-n2.conf
./nodus-server --config test-n3.conf

# Create channel, verify ring assignment
./nodus-cli connect 127.0.0.1:4001
./nodus-cli ch-create "test-channel"
./nodus-cli ch-post <uuid> "post 1"

# Kill primary, test failover
kill <n1_pid>
./nodus-cli connect 127.0.0.1:4003   # backup
./nodus-cli ch-get-posts <uuid> --since 0   # should have post 1
```

### Phase 5: Full Integration (CLI + Engine)

Engine integration — `dna_engine` uses `nodus_client` instead of OpenDHT.

| Test | What it validates |
|------|-------------------|
| Engine PUT/GET | `dna-messenger-cli send <name> "msg"` works via Nodus |
| Engine LISTEN | `dna-messenger-cli listen` receives messages via Nodus push |
| Profile publish | `dna-messenger-cli profile` publishes to Nodus DHT |
| Offline messages | Send while recipient offline → `check-offline` retrieves |
| Channel via engine | `dna-messenger-cli` channel commands use TCP hosting |
| Backward compat | Existing CLI commands work unchanged (engine API stable) |

```bash
# Use existing dna-messenger-cli against Nodus (instead of OpenDHT bootstrap)
# Engine config points to Nodus seed nodes instead of OpenDHT bootstrap
./dna-messenger-cli -d /tmp/test-id send nox "hello from nodus"
./dna-messenger-cli check-offline
```

### Test Configuration Files

```json
// test-single.conf — Phase 2 (single node, no seeds)
{
  "udp_port": 4000,
  "tcp_port": 4001,
  "seed_nodes": [],
  "persistence_path": "/tmp/nodus-test/n1",
  "identity_path": "/tmp/nodus-test/n1/identity"
}

// test-n1.conf — Phase 3+ (multi-node)
{
  "udp_port": 4000, "tcp_port": 4001,
  "seed_nodes": ["127.0.0.1"],
  "seed_udp_port": 4002, "seed_tcp_port": 4003,
  "persistence_path": "/tmp/nodus-test/n1",
  "identity_path": "/tmp/nodus-test/n1/identity"
}
```

### Test Infrastructure

**Nodus Servers (3 machines, 1 instance each):**

| Role | Hostname | IP | User | OS | CPU | RAM | Disk | UDP | TCP |
|------|----------|-----|------|----|-----|-----|------|-----|-----|
| Nodus-T1 | nehir-01 | 161.97.85.25 | root | Debian 13 | 6 cores | 11 GB | 90 GB free | 4000 | 4001 |
| Nodus-T2 | TBD | TBD | TBD | — | — | — | — | 4000 | 4001 |
| Nodus-T3 | TBD | TBD | TBD | — | — | — | — | 4000 | 4001 |

Each Nodus uses standard ports (UDP 4000, TCP 4001) since they're on separate machines.

**Persistence paths (all Nodus):**
```
/var/lib/nodus/data          # SQLite databases
/var/lib/nodus/identity      # Dilithium5 keypair
```

**Firewall (all Nodus machines):**
```bash
ufw allow 4000/udp
ufw allow 4001/tcp
```

**Client Machines (2):**

| Role | Hostname | IP | User | OS | CPU | RAM | Note |
|------|----------|-----|------|----|-----|-----|------|
| Client #1 | dev machine | — | nocdem | Debian 12 | — | — | Primary dev + CLI testing |
| Client #2 | chat1 | 192.168.0.195 | nocdem | Debian 12 | 4 cores | 15 GB | LAN, second client for multi-client tests |

**Local-only testing (Phase 1-4 early dev):**
Before Nodus-T2 and T3 are ready, Phase 1-4 can run entirely on nehir-01 with 3 instances on different ports (5000/5001, 5002/5003, 5004/5005) for rapid iteration.

**Phase 5 deployment (production):** After test validation, deploy to existing production servers:

| Server | IP | UDP | TCP |
|--------|-----|-----|-----|
| US-1 | 154.38.182.161 | 4000 | 4001 |
| EU-1 | 164.68.105.227 | 4000 | 4001 |
| EU-2 | 164.68.116.180 | 4000 | 4001 |

**Note:** During Phase 5 transition, production servers run old dna-nodus (port 4000) alongside new Nodus (port 5000/5001) for parallel testing. Clean switch when ready.

---

## 13. DNA Messenger Integration

### What Changes

```
BEFORE:
  dna_engine → dht_context.cpp (C++) → OpenDHT DhtRunner (C++)
                  2,124 lines              37,968 lines
               + dht_chunked.c (C)
                  ~2,000 lines
               + channel_cache.c → DHT daily buckets

  Total: ~42,000 lines C++ / C dependency

AFTER:
  dna_engine → nodus_client.c (Pure C)  →  Nodus Server (Pure C)
                    ~1,200 lines                 ~10,900 lines
                    (TCP 4001)                    (UDP 4000 + TCP 4001)

  DHT operations: PUT/GET/LISTEN via Nodus client (TCP 4001)
  Channel operations: ch_post/ch_subscribe via same client (TCP 4001)
  No C++ anywhere in the dependency chain
```

### Files Removed

- `vendor/opendht-pq/` — entire directory (37,968 lines C++)
- `dht/core/dht_context.cpp` — C++ bridge (2,124 lines)
- `dht/core/dht_listen.cpp` — C++ listen wrapper (569 lines)
- `dht/core/dht_stats.cpp` — C++ stats (81 lines)
- `dht/client/dht_identity.cpp` — C++ identity (256 lines)
- `dht/shared/dht_value_storage.cpp` — C++ storage (971 lines)
- `dht/shared/dht_chunked.c` — chunking no longer needed (1,999 lines)
- `dht/shared/dht_chunked.h` — (339 lines)

### Files Preserved (with API changes)

- `dht/shared/dht_offline_queue.c` — same logic, API rename dht_* → nodus_*
- `dht/client/` domain modules — API rename via compat shim
- `dht/client/dna_channels.c` — channel metadata stays on DHT; post operations redirect to TCP
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

## 14. Platform Considerations

### TCP Client (C Library — All Platforms)

#### Linux
- I/O multiplexing: `epoll` for async TCP
- Threads: `pthreads` (already used)
- No new dependencies

#### Windows
- I/O multiplexing: `select()` for simplicity
- Socket init: `WSAStartup()` before any socket ops
- Include order: `winsock2.h` before `windows.h`
- Format specifiers: `%llu` with casts for `uint64_t`

#### Android
- Background TCP: via `ForegroundService` (existing pattern)
- Battery: keepalive interval > 60 seconds
- Network changes: reconnect on WiFi↔cellular transition
- Lifecycle: engine PAUSED → close TCP; ACTIVE → reconnect

### Nodus Server (Linux Only)

- **TCP 4001:** `epoll` for hundreds of concurrent client + mesh connections
- **UDP 4000:** Single socket, non-blocking `recvfrom`/`sendto` in event loop
- Thread model: acceptor thread + worker pool (`threadpool.h`)
- Single process, multi-threaded
- **Firewall:** `ufw allow 4000/udp && ufw allow 4001/tcp`

### Flutter Integration

- No new FFI bindings needed for basic operations — existing `dna_engine_channel_*` reused
- New event types: `DNA_EVENT_TCP_CONNECTED`, `DNA_EVENT_TCP_DISCONNECTED`
- New provider for nodus connection state in UI

---

## 15. Nodus Server Configuration

```json
{
  "udp_port": 4000,
  "tcp_port": 4001,
  "seed_nodes": [
    "154.38.182.161",
    "164.68.105.227",
    "164.68.116.180"
  ],
  "seed_udp_port": 4000,
  "seed_tcp_port": 4001,
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

## 16. Migration Strategy

1. **Clean break** — no backward compatibility (beta project, acceptable)
2. **Client local data safe** — `dnac.db` is the source of truth (contacts, keys, identity preserved)
3. **DHT data republished** — after upgrade, clients republish profiles/contacts/keys from local DB
4. **Channels:** Old DHT-based channels are gone. Users create new TCP-hosted channels. Channel metadata stays on DHT for discovery; post data lives on TCP/SQLite only.
5. **Nodus operators** — must upgrade to new nodus-server binary
6. **Rollout:** ship new client + new nodus-server simultaneously

---

## 17. Summary of Decisions

| # | Decision | Choice |
|---|----------|--------|
| 1 | Language | Pure C99 (no C++ dependency) |
| 2 | Wire format | CBOR (RFC 8949), unified for DHT + channels |
| 3 | Frame header | 7 bytes: Magic (ND) + Version + Length (LE32) |
| 4 | Transport | UDP 4000 (Kademlia routing) + TCP 4001 (data, clients, channels) |
| 5 | DHT routing | Kademlia (k=8, r=3, 512-bit key space) |
| 6 | DHT value types | 2: EPHEMERAL (7d TTL), PERMANENT (∞) |
| 7 | Channel sharding | Consistent hash ring (SHA3-512) |
| 8 | Channel replication | Factor 3 (1 Primary + 2 Backup), async |
| 9 | Channel failover | Client-driven, ring order (P → B1 → B2) |
| 10 | Membership consensus | PBFT (swappable via interface) |
| 11 | Authentication | 3-way Dilithium5 challenge-response, mandatory |
| 12 | Nodus identity | Dilithium5 keypair, nodus_id = SHA3-512(pubkey) = fingerprint |
| 13 | Channel storage | SQLite, per-channel table, 7-day retention |
| 14 | Post ordering | Sequential ID (uint32, per-channel) |
| 15 | Post conflict | Immutable append-only, dedup by post_uuid |
| 16 | Channel discovery | DHT metadata + TCP data |
| 17 | Nodus discovery | DHT registry (7d TTL) |
| 18 | Pub/sub (LISTEN) | Distributed: SUBSCRIBE/NOTIFY between Nodus |
| 19 | Max frame (TCP) | 4 MB |
| 19b | Max datagram (UDP) | 1400 bytes (safe MTU) |
| 20 | Channel post max | 4000 chars body |
| 21 | Hinted handoff | Max 1000 per target, 30s retry |
| 22 | Nodus mesh | Full persistent TCP mesh |
| 23 | Dependencies | SQLite3, OpenSSL, json-c only (7 removed) |
| 24 | Hashing | SHA3-512 everywhere (identity, keys, ring). One hash function. |
| 25 | Test strategy | Hybrid bottom-up: unit → single Nodus+CLI → 2 Nodus → 3 Nodus+PBFT → engine integration |

---

## 18. Open / Deferred

- [ ] Rate limiting / DoS protection beyond basic per-identity limits
- [ ] Channel moderation / admin controls
- [ ] Post permissions (owner-only, whitelist)
- [ ] Encryption of channel data at rest on Nodus
- [ ] Maximum channels per Nodus capacity planning
- [ ] Nodus incentive model (why run a Nodus?)
- [ ] TLS encryption for TCP connections (optional — all data already signed)
- [ ] Client connection pooling (one TCP per Nodus vs per channel)
- [ ] Nodus load balancing for popular channels
- [ ] NAT traversal (future: Phase 16)
- [ ] WebSocket transport (future: Phase 15)
- [ ] Sybil protection (reputation, PoW, or staking)
- [ ] Batch channel subscribe (`ch_batch_subscribe`) for reconnect efficiency
- [ ] Inactive channel cleanup (empty tables after 30d → drop)
- [ ] Storage capacity management (disk full → reject PUTs)
- [ ] Channel post body validation (max 4000 chars, UTF-8 check) on Nodus side

**Known v1 limitations:**
- 3 Nodus = replication factor 3 = every Nodus stores every channel (no sharding benefit). Sharding activates at 4+ Nodus.
- PBFT proposer: lowest `nodus_id` among nodes that independently detect the same event. Concurrent proposals with same target are deduplicated by PBFT seq number.

---

## 19. Codebase References

### Existing Code (Reusable)

| Concept | Code | File |
|---------|------|------|
| Channel metadata struct | `dna_channel_info_t` | `include/dna/dna_engine.h` |
| Channel post struct | `dna_channel_post_info_t` | `include/dna/dna_engine.h` |
| Channel engine module | 9 task handlers | `src/api/engine/dna_engine_channels.c` |
| Channel DHT operations | `dna_channel_create()` | `dht/client/dna_channels.c` |
| Channel cache DB | `channel_cache_put_posts()` | `database/channel_cache.c` |
| Channel subscriptions | `channel_subscriptions_db_subscribe()` | `database/channel_subscriptions_db.c` |
| Dilithium5 sign | `qgp_dsa87_sign()` | `crypto/utils/qgp_dilithium.h` |
| Dilithium5 verify | `qgp_dsa87_verify()` | `crypto/utils/qgp_dilithium.h` |
| SHA3-512 fingerprint | `qgp_sha3_512_fingerprint()` | `crypto/utils/qgp_sha3.h` |
| SHA3-512 hash | `qgp_sha3_512()` | `crypto/utils/qgp_sha3.h` |
| Secure random | `qgp_platform_random()` | `crypto/utils/qgp_platform.h` |
| Platform abstraction | Socket helpers | `crypto/utils/qgp_platform.h` |
| Thread pool | `threadpool_create()` | `crypto/utils/threadpool.h` |
| Engine task system | `dna_submit_task()` | `src/api/dna_engine_internal.h` |
| Engine module pattern | `engine_includes.h` | `src/api/engine/engine_includes.h` |
| Struct packing | `PACK_STRUCT_BEGIN/END` | `crypto/utils/qgp_compiler.h` |
| Transport layer | `transport_init()` | `transport/transport.h` |
| Offline queue | `dht_offline_message_t` | `dht/shared/dht_offline_queue.h` |
| Cache manager | `cache_manager_init()` | `database/cache_manager.h` |

### Current Channel Task Types (Engine)

```c
TASK_CHANNEL_CREATE           → dna_handle_channel_create()
TASK_CHANNEL_GET              → dna_handle_channel_get()
TASK_CHANNEL_DELETE           → dna_handle_channel_delete()
TASK_CHANNEL_DISCOVER         → dna_handle_channel_discover()
TASK_CHANNEL_POST             → dna_handle_channel_post()
TASK_CHANNEL_GET_POSTS        → dna_handle_channel_get_posts()
TASK_CHANNEL_GET_SUBSCRIPTIONS → dna_handle_channel_get_subscriptions()
TASK_CHANNEL_SYNC_SUBS_TO_DHT → dna_handle_channel_sync_subs_to_dht()
TASK_CHANNEL_SYNC_SUBS_FROM_DHT → dna_handle_channel_sync_subs_from_dht()
```

### Current DHT Key Derivation

```c
// Channel metadata — stays on DHT
dna_channel_make_meta_key()  → SHA256("dna:channels:meta:" + uuid)
dna_channel_make_posts_key() → SHA256("dna:channels:posts:" + uuid + ":" + YYYYMMDD)

// After migration: posts move from DHT daily buckets to TCP/SQLite
// Metadata + index remain on DHT (discovery)
```
