# Nodus v5 — Architecture Documentation

**Version:** 0.5.0 | **Language:** C (pure) | **License:** Proprietary

---

## 1. Overview & Motivation

Nodus v5 is a complete rewrite of the DNA Messenger's DHT (Distributed Hash Table) layer. It
replaces OpenDHT-PQ — a C++ library with post-quantum patches — with a pure C implementation
built from the ground up for post-quantum security.

**Why replace OpenDHT-PQ:**

- **C++ dependency** — the only C++ component in an otherwise pure-C codebase, requiring
  `libstdc++` and complicating cross-compilation (Android NDK, Windows MinGW)
- **ASAN memory leaks** — OpenDHT's internal allocations created persistent leak reports
  that could not be resolved without upstream changes
- **No native post-quantum** — Dilithium5 support was bolted on via patches to OpenDHT's
  crypto layer rather than being a first-class design choice
- **Opaque failure modes** — debugging C++ template errors across OpenDHT internals was
  impractical for a small team

**What Nodus v5 provides:**

- Pure C implementation — zero C++ dependencies, compiles with any C11 compiler
- Kademlia DHT with 512-bit key space (SHA3-512)
- Dilithium5 (ML-DSA-87) authentication and value signing throughout
- CBOR wire protocol with custom encoder/decoder (no external CBOR library)
- PBFT-inspired cluster consensus for channel placement
- Consistent hash ring for channel-to-node assignment
- Client SDK with auto-reconnect, multi-server failover, and real-time push
- SQLite persistent storage with TTL-based expiry

**Scale:** ~11,200 lines of C (6,500 source + 530 headers + 4,200 tests) across 21 source
files and 13 test files with 139 test functions. External dependencies: OpenSSL (random
bytes), SQLite (storage), and json-c (server config parsing).

---

## 2. System Architecture

### High-Level Design

Nodus uses a two-tier protocol architecture:

```
┌──────────────────────────────────────────────────────────────┐
│                        CLIENTS                               │
│   ┌─────────┐  ┌─────────┐  ┌─────────┐                     │
│   │ Android │  │  Linux  │  │ Windows │                      │
│   │   App   │  │   App   │  │   App   │                      │
│   └────┬────┘  └────┬────┘  └────┬────┘                      │
│        │            │            │     Tier 2 (TCP)           │
│        │    Dilithium5 Auth      │     PUT/GET/LISTEN         │
│        ▼            ▼            ▼     Channels               │
├──────────────────────────────────────────────────────────────┤
│                     NODUS CLUSTER                            │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│   │ nodus-01 │◄─┤ nodus-02 │◄─┤ nodus-03 │                  │
│   │  (US-1)  │─►│  (EU-1)  │─►│  (EU-2)  │                  │
│   └──────────┘  └──────────┘  └──────────┘                   │
│        Tier 1: UDP (Kademlia) + TCP (replication)            │
│        PBFT consensus + hash ring + value replication        │
└──────────────────────────────────────────────────────────────┘
```

- **Tier 1 (T1)** — Server-to-server: Kademlia routing (UDP), value replication (TCP),
  PBFT heartbeats (UDP)
- **Tier 2 (T2)** — Client-to-server: authentication, DHT operations, channel messaging,
  real-time push notifications (all TCP)

### Directory Structure

```
nodus/
├── include/nodus/
│   ├── nodus_types.h          # All types, constants, enums
│   └── nodus.h                # Public client SDK API
├── src/
│   ├── core/
│   │   ├── nodus_value.c      # DHT value create/sign/verify/serialize
│   │   ├── nodus_routing.c    # Kademlia routing table (512 buckets × k=8)
│   │   └── nodus_storage.c    # SQLite persistent value storage
│   ├── protocol/
│   │   ├── nodus_cbor.c       # Custom CBOR encoder/decoder
│   │   ├── nodus_wire.c       # Wire frame format ("ND" + version + length)
│   │   ├── nodus_tier1.c      # T1 encode/decode (server ↔ server)
│   │   └── nodus_tier2.c      # T2 encode/decode (client ↔ server)
│   ├── transport/
│   │   ├── nodus_tcp.c        # TCP transport (epoll, framing, connections)
│   │   └── nodus_udp.c        # UDP transport (non-blocking recvfrom)
│   ├── crypto/
│   │   ├── nodus_sign.c       # Dilithium5 sign/verify/hash wrappers
│   │   └── nodus_identity.c   # Identity generation, save/load, seed derivation
│   ├── channel/
│   │   ├── nodus_channel_store.c  # SQLite channel + post storage
│   │   ├── nodus_hashring.c       # Consistent hash ring
│   │   └── nodus_replication.c    # Cross-node channel replication + hinted handoff
│   ├── consensus/
│   │   └── nodus_pbft.c       # PBFT cluster membership + leader election
│   ├── server/
│   │   ├── nodus_server.c     # Server event loop + message dispatch
│   │   └── nodus_auth.c       # Dilithium5 challenge-response auth
│   └── client/
│       ├── nodus_client.c     # Client SDK (connect, auth, DHT, channels)
│       ├── nodus_singleton.c  # Thread-safe global client instance
│       └── nodus_republish.c  # Migration republish helper
├── tests/
│   ├── test_wire.c            # Wire frame tests
│   ├── test_cbor.c            # CBOR encoder/decoder tests
│   ├── test_tier1.c           # T1 protocol tests
│   ├── test_tier2.c           # T2 protocol tests
│   ├── test_value.c           # Value create/sign/verify tests
│   ├── test_routing.c         # Routing table tests
│   ├── test_storage.c         # SQLite storage tests
│   ├── test_identity.c        # Identity generation tests
│   ├── test_hashring.c        # Hash ring tests
│   ├── test_channel_store.c   # Channel storage tests
│   ├── test_tcp.c             # TCP transport tests
│   ├── test_client.c          # Client SDK tests
│   ├── test_server.c          # Server integration tests
│   └── integration_test.sh    # E2E integration test suite
├── CMakeLists.txt             # Build system
└── docs/
    └── ARCHITECTURE.md        # This file
```

### Build System

Nodus uses CMake and builds in two modes:

**Standalone** (server binary + tests):
```bash
cd nodus/build && cmake .. && make -j$(nproc)
```

**Messenger integration** (linked into `libdna_lib.so`):
```bash
cd messenger/build && cmake .. && make -j$(nproc)
```

The messenger CMake includes Nodus client sources directly — the server is not linked into
the messenger library. Shared crypto code lives in `shared/crypto/` and is resolved via
`-I /opt/dna/shared` include paths.

---

## 3. Wire Protocol

All Nodus communication uses a framed binary protocol. Every message — whether over TCP or
UDP — is wrapped in a wire frame containing a CBOR payload.

### Frame Format

```
Offset  Size   Field        Description
──────  ────   ─────        ───────────
0       2      Magic        0x4E44 ("ND") — big-endian
2       1      Version      0x01
3       4      Length       Payload length — little-endian uint32
7       N      Payload      CBOR-encoded message
```

Total header: 7 bytes. Maximum payload: 4 MB (TCP) or 1400 bytes (UDP, safe MTU).

**Encoding** (`nodus_wire.c:nodus_frame_encode`):
```c
buf[0] = 0x4E;  // 'N'
buf[1] = 0x44;  // 'D'
buf[2] = 0x01;  // version
buf[3..6] = payload_len (LE32)
buf[7..] = payload
```

**Decoding** (`nodus_wire.c:nodus_frame_decode`): Returns 0 if incomplete (need more
data), -1 on invalid magic, or the total frame length on success. This allows incremental
parsing of TCP streams.

### CBOR Encoding

Nodus implements a custom CBOR encoder/decoder (`nodus_cbor.c`) — no external library
dependency. Supported types:

| CBOR Type | C API | Usage |
|-----------|-------|-------|
| Unsigned int | `cbor_encode_uint` | txn IDs, timestamps, seq numbers |
| Byte string | `cbor_encode_bstr` | keys, signatures, data payloads |
| Text string | `cbor_encode_cstr` / `cbor_encode_tstr` | method names, map keys |
| Array | `cbor_encode_array` | peer lists, value arrays |
| Map | `cbor_encode_map` | message envelope, arguments |
| Boolean | `cbor_encode_bool` | flags (major type 7, values 20/21) |
| Null | `cbor_encode_null` | absent values (major type 7, value 22) |

### Message Envelope

All messages share a common CBOR map structure:

```
{
    "t":   <uint32>     # Transaction ID
    "y":   <string>     # Type: "q" (query), "r" (response), "e" (error)
    "q":   <string>     # Method name
    "a":   {…}          # Arguments (queries)
    "r":   {…}          # Results (responses)
    "tok": <bytes[32]>  # Session token (T2 authenticated requests)
}
```

---

## 4. Tier 1 Protocol — Server-to-Server

Tier 1 handles inter-node communication for Kademlia routing and value replication.

### Transport

- **UDP** — Kademlia discovery (PING/PONG, FIND_NODE). Limited to 1400 bytes (safe MTU).
- **TCP** — Value operations (STORE, FIND_VALUE). Required because a single serialized
  `NodusValue` is ~7.3 KB (Dilithium5 public key 2592B + signature 4627B + data + metadata),
  which exceeds UDP MTU.

### Message Types

| Method | Type | Transport | Description |
|--------|------|-----------|-------------|
| `ping` | query | UDP | Heartbeat — includes sender's node_id |
| `pong` | response | UDP | Heartbeat response — includes responder's node_id |
| `fn` | query | UDP | FIND_NODE — find k closest nodes to target |
| `fn_r` | response | UDP | NODES_FOUND — returns array of peer info |
| `sv` | query | UDP/TCP | STORE_VALUE — replicate a signed value |
| `sv_ack` | response | UDP | STORE acknowledgement |
| `fv` | query | UDP | FIND_VALUE — retrieve value by key |
| `fv_r` | response | UDP | VALUE_FOUND — returns value or closest nodes |
| `sub` | query | TCP | SUBSCRIBE — watch a key for changes (*) |
| `unsub` | query | TCP | UNSUBSCRIBE — stop watching a key (*) |
| `ntf` | query | TCP | NOTIFY — push value change to subscriber (*) |

(*) `sub`, `unsub`, and `ntf` are defined in the T1 protocol layer (`nodus_tier1.c`) but
are not yet dispatched in the server. Inter-node value subscriptions currently use T2
`listen`/`value_changed` via TCP replication.

### CBOR Field Reference

**PING** (`"q": "ping"`):
```
{"t": txn, "y": "q", "q": "ping", "a": {"id": <bytes[64]>}}
```

**PONG** (`"q": "pong"`):
```
{"t": txn, "y": "r", "q": "pong", "r": {"id": <bytes[64]>}}
```

**FIND_NODE** (`"q": "fn"`):
```
{"t": txn, "y": "q", "q": "fn", "a": {"target": <bytes[64]>}}
```

**NODES_FOUND** (`"q": "fn_r"`):
```
{"t": txn, "y": "r", "q": "fn_r", "r": {"nodes": [
    {"id": <bytes[64]>, "ip": "1.2.3.4", "up": 4000, "tp": 4001}, …
]}}
```

**STORE_VALUE** (`"q": "sv"`):
```
{"t": txn, "y": "q", "q": "sv", "a": {"val": <bytes(serialized NodusValue)>}}
```

The `val` field contains a CBOR-serialized `NodusValue` (see Section 6).

### Kademlia Routing

- **Key space:** 512 bits (SHA3-512)
- **Buckets:** 512 (one per bit of key space)
- **Bucket size (k):** 8 nodes
- **Parallel lookups (α):** 3
- **Replication factor (R):** 3
- **Distance metric:** XOR of 64-byte node IDs

**Bucket index** = count of leading zero bits in `XOR(self_id, peer_id)`. Peers with a
longer common prefix (closer in key space) go into higher-numbered buckets.

**Eviction policy:** LRU — when a bucket is full, the least-recently-seen entry is replaced
by the new peer.

### Node Discovery Flow

1. Server starts with seed nodes configured in `/etc/nodus-v5.conf`
2. Sends UDP PING to each seed node
3. On PONG, learns the seed's real node_id (replaces IP-hash placeholder)
4. Inserts seed into routing table
5. Sends FIND_NODE(self_id) to discover nearby peers
6. Iteratively queries returned peers until no closer nodes are found

---

## 5. Tier 2 Protocol — Client-to-Server

Tier 2 handles all client-facing operations over TCP. Every T2 session begins with a
Dilithium5 challenge-response authentication handshake.

### Authentication Handshake

```
Client                              Server
  │                                    │
  │─── HELLO(pk, fp) ────────────────►│  1. Client sends Dilithium5 public key
  │                                    │     and fingerprint (SHA3-512 of pk)
  │                                    │     Server verifies fp == SHA3-512(pk)
  │◄── CHALLENGE(nonce) ──────────────│  2. Server generates 32-byte random nonce
  │                                    │
  │─── AUTH(SIGN(nonce, sk)) ─────────►│  3. Client signs nonce with secret key
  │                                    │     Server verifies signature with pk
  │◄── AUTH_OK(token) ────────────────│  4. Server returns 32-byte session token
  │                                    │     All subsequent requests include token
```

**HELLO** (`"q": "hello"`):
```
{"t": txn, "y": "q", "q": "hello", "a": {"pk": <bytes[2592]>, "fp": <bytes[64]>}}
```

**CHALLENGE** (`"q": "challenge"`):
```
{"t": txn, "y": "r", "q": "challenge", "r": {"nonce": <bytes[32]>}}
```

**AUTH** (`"q": "auth"`):
```
{"t": txn, "y": "q", "q": "auth", "a": {"sig": <bytes[4627]>}}
```

**AUTH_OK** (`"q": "auth_ok"`):
```
{"t": txn, "y": "r", "q": "auth_ok", "r": {"tok": <bytes[32]>}}
```

### Authenticated DHT Operations

All operations below require a valid session token (`"tok"` field).

| Method | Direction | Description |
|--------|-----------|-------------|
| `put` | C→S | Store a signed value |
| `get` | C→S | Retrieve latest value by key |
| `get_all` | C→S | Retrieve all values for a key (all writers) |
| `listen` | C→S | Subscribe to value changes on a key |
| `unlisten` | C→S | Unsubscribe from a key |
| `ping` | C→S | Keepalive |
| `servers` | C→S | Get list of cluster nodes |
| `put_ok` | S→C | PUT acknowledgement |
| `result` | S→C | GET result (single value) |
| `result` (multi) | S→C | GET_ALL result (value array) |
| `listen_ok` | S→C | LISTEN acknowledgement |
| `pong` | S→C | Keepalive response |
| `value_changed` | S→C | Push notification: watched key updated |
| `error` | S→C | Error response with code and message |

**PUT** (`"q": "put"`):
```
{"t": txn, "y": "q", "q": "put", "tok": <bytes[32]>, "a": {
    "k": <bytes[64]>,        # SHA3-512 key hash
    "d": <bytes>,            # Data payload
    "type": <uint>,          # 1=ephemeral, 2=permanent
    "ttl": <uint>,           # Seconds (0=permanent)
    "vid": <uint64>,         # Value ID
    "seq": <uint64>,         # Sequence number
    "sig": <bytes[4627]>     # Dilithium5 signature
}}
```

**GET** (`"q": "get"`):
```
{"t": txn, "y": "q", "q": "get", "tok": <bytes[32]>, "a": {"k": <bytes[64]>}}
```

**VALUE_CHANGED** (push, `"q": "value_changed"`):
```
{"t": 0, "y": "q", "q": "value_changed", "a": {
    "k": <bytes[64]>,
    "val": <bytes(serialized NodusValue)>
}}
```

**ERROR** (`"y": "e"`):
```
{"t": txn, "y": "e", "r": {"code": <uint>, "msg": <string>}}
```

### Channel Operations

| Method | Direction | Description |
|--------|-----------|-------------|
| `ch_create` | C→S | Create a new channel (UUID v4) |
| `ch_post` | C→S | Post a message to a channel |
| `ch_get` | C→S | Get posts from a channel (since seq) |
| `ch_sub` | C→S | Subscribe to channel notifications |
| `ch_unsub` | C→S | Unsubscribe from a channel |
| `ch_ntf` | S→C | Push: new post in subscribed channel |
| `ch_rep` | S→S | Inter-node channel post replication |

**CH_POST** (`"q": "ch_post"`):
```
{"t": txn, "y": "q", "q": "ch_post", "tok": <bytes[32]>, "a": {
    "ch": <bytes[16]>,       # Channel UUID
    "pid": <bytes[16]>,      # Post UUID
    "d": <bytes>,            # Post body (UTF-8, max 4000 chars)
    "ts": <uint64>,          # Author's timestamp
    "sig": <bytes[4627]>     # Dilithium5 signature
}}
```

### Pre-Auth Dispatch

The server allows certain messages without authentication:

- `hello` / `auth` — the handshake itself
- `sv` — inter-node DHT value replication (verified by value signature)
- `ch_rep` — inter-node channel post replication

All other methods return `NODUS_ERR_NOT_AUTHENTICATED` (code 1) if the session is not
authenticated.

---

## 6. Core Data Structures

### NodusValue

The fundamental unit of DHT storage. Every value is cryptographically signed by its owner.

```c
typedef struct {
    nodus_key_t     key_hash;       // SHA3-512 of the logical key (64 bytes)
    uint64_t        value_id;       // Writer-specific identifier
    uint8_t        *data;           // Payload (up to 1 MB)
    size_t          data_len;
    nodus_value_type_t type;        // EPHEMERAL (0x01) or PERMANENT (0x02)
    uint32_t        ttl;            // Seconds until expiry (0 = permanent)
    uint64_t        created_at;     // Unix timestamp
    uint64_t        expires_at;     // 0 if permanent
    uint64_t        seq;            // Sequence number for updates
    nodus_pubkey_t  owner_pk;       // Dilithium5 public key (2592 bytes)
    nodus_key_t     owner_fp;       // SHA3-512(owner_pk) (64 bytes)
    nodus_sig_t     signature;      // Dilithium5 signature (4627 bytes)
} nodus_value_t;
```

**Signature payload** (concatenation, signed with Dilithium5):
```
key_hash    (64 bytes)
data        (variable)
type        (1 byte)
ttl         (4 bytes, LE)
value_id    (8 bytes, LE)
seq         (8 bytes, LE)
```

**CBOR serialization** (10-field map):
```
{"key": <bytes[64]>, "vid": <uint64>, "data": <bytes>, "type": <uint>,
 "ttl": <uint>, "created": <uint64>, "seq": <uint64>, "owner": <bytes[2592]>,
 "owner_fp": <bytes[64]>, "sig": <bytes[4627]>}
```

A typical serialized value is ~7.3 KB due to Dilithium5 key/signature sizes.

### nodus_identity_t

A node's cryptographic identity — derived from a Dilithium5 keypair.

```c
typedef struct {
    nodus_pubkey_t pk;                          // 2592 bytes
    nodus_seckey_t sk;                          // 4896 bytes
    nodus_key_t    node_id;                     // SHA3-512(pk) = 64 bytes
    char           fingerprint[129];            // Hex representation of node_id
} nodus_identity_t;
```

Total size: 7,681 bytes. Identities can be generated randomly, derived deterministically
from a 32-byte seed (BIP39 compatible), or loaded from files (`nodus.pk` + `nodus.sk`).

### nodus_key_t

The universal 512-bit key used throughout the system:

```c
typedef struct {
    uint8_t bytes[64];  // SHA3-512 = 64 bytes
} nodus_key_t;
```

Used for: node IDs, DHT key hashes, fingerprints, XOR distance calculations.

### Routing Table

```c
typedef struct {
    nodus_key_t    self_id;
    nodus_bucket_t buckets[512];    // 512 buckets
} nodus_routing_t;

typedef struct {
    struct { nodus_peer_t peer; bool active; } entries[8];  // k=8
    int count;
} nodus_bucket_t;
```

### Channel Post

```c
typedef struct {
    uint8_t     channel_uuid[16];   // UUID v4
    uint32_t    seq_id;             // Assigned by primary node
    uint8_t     post_uuid[16];      // UUID v4
    nodus_key_t author_fp;          // SHA3-512(author_pk)
    uint64_t    timestamp;          // Author's claimed time
    uint64_t    received_at;        // Server receive time
    char       *body;               // UTF-8, max 4000 chars
    size_t      body_len;
    nodus_sig_t signature;          // Dilithium5 signature
} nodus_channel_post_t;
```

### Error Codes

| Code | Name | Description |
|------|------|-------------|
| 1 | `NOT_AUTHENTICATED` | No valid session or token |
| 2 | `NOT_FOUND` | Key not found in DHT |
| 3 | `INVALID_SIGNATURE` | Dilithium5 verification failed |
| 4 | `RATE_LIMITED` | Too many operations (60 puts/min) |
| 5 | `TOO_LARGE` | Value exceeds 1 MB or post exceeds 4000 chars |
| 6 | `TIMEOUT` | Operation timed out |
| 7 | `PROTOCOL_ERROR` | Unknown method or malformed message |
| 8 | `INTERNAL_ERROR` | Server-side failure |
| 10 | `CHANNEL_NOT_FOUND` | Channel UUID not registered |
| 11 | `NOT_RESPONSIBLE` | Node not in responsible set for channel |
| 12 | `RING_MISMATCH` | Hash ring version conflict |

---

## 7. Cryptography

All cryptographic operations use post-quantum algorithms from the `shared/crypto/` library.

### Dilithium5 (ML-DSA-87)

NIST Category 5 post-quantum digital signature scheme. Used for:

- **Value signing** — every DHT value carries a Dilithium5 signature that proves ownership
- **Client authentication** — 3-step challenge-response handshake
- **Channel post signing** — authors sign their posts

| Parameter | Size |
|-----------|------|
| Public key | 2,592 bytes |
| Secret key | 4,896 bytes |
| Signature | 4,627 bytes |
| Seed | 32 bytes |

**API** (`nodus_sign.c`):
```c
int nodus_sign(nodus_sig_t *sig, const uint8_t *data, size_t len, const nodus_seckey_t *sk);
int nodus_verify(const nodus_sig_t *sig, const uint8_t *data, size_t len, const nodus_pubkey_t *pk);
```

Wraps `qgp_dsa87_sign()` / `qgp_dsa87_verify()` from `shared/crypto/`.

### SHA3-512

Used for all hashing throughout the system:

- **Node IDs** — `node_id = SHA3-512(public_key)`
- **Fingerprints** — human-readable hex of node_id (128 hex chars)
- **DHT key hashes** — `key_hash = SHA3-512(raw_key)` before storage/lookup
- **Hash ring positions** — `SHA3-512(channel_uuid)` for ring placement

```c
int nodus_hash(const uint8_t *data, size_t len, nodus_key_t *hash_out);
int nodus_fingerprint(const nodus_pubkey_t *pk, nodus_key_t *fp_out);
```

### Identity Generation

Two modes:

1. **Random** — `qgp_dsa87_keypair()` generates a fresh random keypair
2. **Seed-based** — `qgp_dsa87_keypair_derand(pk, sk, seed)` produces a deterministic
   keypair from a 32-byte seed. Compatible with BIP39 mnemonic derivation. Produces
   identical keys to OpenDHT-PQ's `pqcrystals_dilithium5_ref_keypair_from_seed()`.

Identity files on disk:
- `nodus.pk` — public key (2,592 bytes, binary)
- `nodus.sk` — secret key (4,896 bytes, binary)
- `nodus.fp` — fingerprint (128 hex chars + newline)

---

## 8. Consensus — PBFT

Nodus uses a simplified PBFT (Practical Byzantine Fault Tolerance) implementation for
cluster membership management and leader election.

### Purpose

- **Cluster membership** — track which nodes are alive, suspect, or dead
- **Leader election** — deterministic: lowest alive node_id is leader
- **Hash ring sync** — add/remove nodes from the consistent hash ring as their state changes

### Node States

```c
typedef enum {
    NODUS_NODE_ALIVE   = 0,   // Responding to heartbeats
    NODUS_NODE_SUSPECT = 1,   // No response for 30s
    NODUS_NODE_DEAD    = 2    // No response for 60s
} nodus_node_state_t;
```

### Heartbeat Protocol

1. Every **10 seconds** (`NODUS_PBFT_HEARTBEAT_SEC`), each node sends UDP PING to all
   non-dead peers
2. On PONG, the peer's `last_seen` timestamp is updated
3. On each tick, peer health is evaluated:
   - `< 30s` since last seen → **ALIVE**
   - `30-60s` since last seen → **SUSPECT**
   - `> 60s` since last seen → **DEAD** (removed from hash ring, no more pings)

### Leader Election

Leader = lowest `node_id` (lexicographic comparison of 64-byte keys) among all ALIVE nodes
plus self. Re-elected whenever a peer's state changes. The leader's `view` number increments
on each leadership change.

### Seed Node Discovery

Seed nodes are configured by IP:port. On startup, their node_ids are unknown — a placeholder
`SHA3-512(ip_string)` is used. When the seed responds to PING with its real node_id in the
PONG, the PBFT module:

1. Finds the peer by IP + port match
2. Replaces the placeholder node_id with the real one
3. Updates the hash ring (remove old, add new)

---

## 9. Channels & Replication

### Channel Model

Channels provide ordered, multi-writer messaging with server-assigned sequence numbers.

**Operations:**
- **Create** — register a UUID v4 channel on the server
- **Post** — submit a signed message (max 4,000 UTF-8 chars), server assigns `seq_id`
- **Get Posts** — paginated retrieval (`since_seq`, `max_count`)
- **Subscribe** — real-time push notifications for new posts

### Storage

Channel data is stored in a separate SQLite database (`channels.db`):

- **Per-channel tables** — each channel gets its own table named `channel_<uuid_hex>` with
  columns: `seq_id`, `post_uuid`, `author_fp`, `timestamp`, `body`, `signature`, `received_at`
- **hinted_handoff** — replication queue for failed cross-node deliveries (target_fp,
  channel_uuid, post data, retry_count, created_at)

Posts are deduplicated by a unique index on `post_uuid` per channel table — replicated
posts from peers are stored idempotently.

### Hash Ring Placement

Channel-to-node assignment uses consistent hashing:

1. `ring_position = SHA3-512(channel_uuid)`
2. Binary search the sorted ring for the first member with `node_id >= ring_position`
3. Collect R (=3) consecutive members clockwise (wrapping around)
4. These R nodes are the **responsible set** for the channel

```c
int nodus_hashring_responsible(const nodus_hashring_t *ring,
                                const uint8_t *channel_uuid,
                                nodus_responsible_set_t *result);
```

### Cross-Node Replication

When a node receives a channel post:

1. Stores it locally and assigns a `seq_id`
2. Notifies all locally subscribed clients (`ch_ntf`)
3. Serializes the post as a `ch_rep` message
4. Sends it via short-lived TCP connections to each node in the responsible set (except self)
5. If a send fails, the post is queued in **hinted handoff** (SQLite, 24h TTL)

**Hinted handoff retry** runs every 30 seconds (`NODUS_HINTED_RETRY_SEC`), attempting to
deliver queued posts to recovered peers. Successfully delivered entries are deleted; failed
entries have their retry count incremented.

---

## 10. Server Architecture

### Event Loop

The server uses a single-threaded, event-driven architecture based on Linux `epoll`
(edge-triggered):

```c
while (srv->running) {
    nodus_tcp_poll(&srv->tcp, 100);     // TCP events (100ms timeout)
    nodus_udp_poll(&srv->udp);          // UDP datagrams (non-blocking)
    nodus_pbft_tick(&srv->pbft);        // Heartbeats + health checks
    nodus_replication_retry(&srv->replication);  // Hinted handoff retry
}
```

### Session Management

Each TCP connection is assigned a **session** (`nodus_session_t`) with:

- Authentication state (nonce, public key, fingerprint, token)
- Active DHT LISTEN subscriptions (up to 128 keys per session)
- Active channel subscriptions (up to 32 channels per session)
- Rate limiting state (60 puts per minute window)

Sessions are cleared on disconnect. The server supports up to `NODUS_MAX_SESSIONS`
concurrent clients.

### Message Dispatch

TCP frames are dispatched through `dispatch_t2()`:

1. **Decode** the CBOR payload as a T2 message
2. **Pre-auth check**: if session is not authenticated, only `hello`, `auth`, `sv`
   (inter-node store), and `ch_rep` (channel replication) are allowed
3. **Token verification**: authenticated requests must carry a valid session token
4. **Handler dispatch**: method name → handler function (`handle_t2_put`, `handle_t2_get`, etc.)

If T2 decode fails, a fallback T1 decode is attempted for inter-node `sv` (STORE_VALUE)
messages that arrive on the TCP port.

### Configuration

Server configuration via JSON file (default: `/etc/nodus-v5.conf`):

```json
{
    "bind_ip": "0.0.0.0",
    "udp_port": 4000,
    "tcp_port": 4001,
    "identity_path": "/var/lib/nodus",
    "data_path": "/var/lib/nodus",
    "seed_nodes": ["161.97.85.25", "156.67.24.125", "156.67.25.251"],
    "seed_ports": [4000, 4000, 4000]
}
```

Data is stored in:
- `<data_path>/nodus.db` — DHT value storage (SQLite)
- `<data_path>/channels.db` — Channel post storage (SQLite)
- `<identity_path>/nodus.pk`, `nodus.sk`, `nodus.fp` — Node identity

---

## 11. Client SDK

### Public API

The client SDK (`nodus/nodus.h`) provides a complete API for applications:

```c
// Lifecycle
int  nodus_client_init(nodus_client_t *client, const nodus_client_config_t *config,
                        const nodus_identity_t *identity);
int  nodus_client_connect(nodus_client_t *client);
int  nodus_client_poll(nodus_client_t *client, int timeout_ms);
bool nodus_client_is_ready(const nodus_client_t *client);
void nodus_client_close(nodus_client_t *client);

// DHT
int nodus_client_put(…);           // Store a signed value
int nodus_client_get(…);           // Retrieve latest value
int nodus_client_get_all(…);       // Retrieve all values for key
int nodus_client_listen(…);        // Subscribe to value changes
int nodus_client_unlisten(…);      // Unsubscribe
int nodus_client_get_servers(…);   // Get cluster node list

// Channels
int nodus_client_ch_create(…);     // Create channel
int nodus_client_ch_post(…);       // Post to channel
int nodus_client_ch_get_posts(…);  // Get posts (paginated)
int nodus_client_ch_subscribe(…);  // Subscribe to channel
int nodus_client_ch_unsubscribe(…);// Unsubscribe
```

### Connection States

```
DISCONNECTED → CONNECTING → AUTHENTICATING → READY
                                                │
                                                ▼ (on disconnect)
                                          RECONNECTING ──► CONNECTING
                                                ▲                │
                                                └────────────────┘
                                              (exponential backoff)
```

### Auto-Reconnect

When enabled (`config.auto_reconnect = true`), the client automatically reconnects on
disconnection:

1. Tries the next server in the configured list (round-robin failover)
2. Uses exponential backoff: 1s → 2s → 4s → … → 30s max
3. On successful reconnect, automatically re-subscribes all active LISTEN keys and
   channel subscriptions

### Callbacks

Three callback types for asynchronous events:

```c
// DHT value change (from LISTEN)
typedef void (*nodus_on_value_changed_fn)(const nodus_key_t *key,
                                           const nodus_value_t *val, void *user_data);
// Channel post notification
typedef void (*nodus_on_ch_post_fn)(const uint8_t channel_uuid[16],
                                     const nodus_channel_post_t *post, void *user_data);
// Connection state change
typedef void (*nodus_on_state_change_fn)(nodus_client_state_t old_state,
                                          nodus_client_state_t new_state, void *user_data);
```

### Singleton Pattern

For applications that need a single global client (e.g., the DNA Messenger), the singleton
module (`nodus_singleton.c`) provides thread-safe access:

```c
int  nodus_singleton_init(const nodus_client_config_t *config, const nodus_identity_t *id);
int  nodus_singleton_connect(void);
nodus_client_t *nodus_singleton_get(void);
bool nodus_singleton_is_ready(void);
int  nodus_singleton_poll(int timeout_ms);
void nodus_singleton_close(void);
void nodus_singleton_lock(void);    // pthread_mutex_lock
void nodus_singleton_unlock(void);  // pthread_mutex_unlock
```

### Protocol Buffer

The client uses a 256 KB static buffer (`g_proto_buf`) for building protocol messages.
This is sufficient for the maximum value payload (1 MB) plus CBOR encoding and Dilithium5
signature overhead.

---

## 12. Messenger Integration

The DNA Messenger integrates Nodus v5 through two convenience layers that bridge the
messenger's application-level concepts to the raw client SDK.

### nodus_ops — Operations Layer

**Source:** `messenger/dht/shared/nodus_ops.c`

Provides a simplified API that handles key hashing, value creation, signing, and listener
dispatch. All operations are serialized via `nodus_singleton_lock/unlock`.

**Key functions:**

| Function | Description |
|----------|-------------|
| `nodus_ops_put(key, len, data, len, ttl, vid)` | Hash key → create value → sign → PUT |
| `nodus_ops_put_str(str_key, data, len, ttl, vid)` | String key variant |
| `nodus_ops_put_permanent(key, len, data, len, vid)` | Permanent (TTL=0) variant |
| `nodus_ops_get(key, len, &data, &len)` | Hash key → GET → extract data payload |
| `nodus_ops_get_str(str_key, &data, &len)` | String key variant |
| `nodus_ops_get_all(key, len, &vals, &lens, &count)` | GET_ALL → extract all payloads |
| `nodus_ops_get_all_str(str_key, &vals, &lens, &count)` | String key GET_ALL variant |
| `nodus_ops_get_all_with_ids(key, len, &vals, &lens, &vids, &count)` | GET_ALL with value IDs |
| `nodus_ops_get_all_str_with_ids(str_key, &vals, &lens, &vids, &count)` | String key variant with IDs |
| `nodus_ops_listen(key, len, callback, user_data, cleanup)` | Register LISTEN + local callback |
| `nodus_ops_cancel_listen(token)` | Cancel by token |
| `nodus_ops_cancel_all()` | Cancel all listeners |
| `nodus_ops_listen_count()` | Number of active listeners |
| `nodus_ops_is_listener_active(token)` | Check if listener is still active |
| `nodus_ops_is_ready()` | Check singleton connection state |
| `nodus_ops_value_id()` | Get current identity's value ID |
| `nodus_ops_fingerprint()` | Get current identity's fingerprint string |

**Listener dispatch:** The `nodus_ops_dispatch()` function is registered as the singleton's
`on_value_changed` callback. When a value change notification arrives, it iterates through
up to 1024 registered listener slots, matching by key hash and invoking the application
callback. Callbacks return `true` to stay subscribed or `false` to auto-cancel.

### nodus_init — Lifecycle Layer

**Source:** `messenger/dht/shared/nodus_init.c`

Manages the complete lifecycle of the Nodus client within the messenger:

| Function | Description |
|----------|-------------|
| `nodus_messenger_init(identity)` | Load config → resolve bootstrap nodes → singleton init → connect |
| `nodus_messenger_close()` | Cancel listeners → close singleton → clear identity |
| `nodus_messenger_reinit()` | Save identity → close → re-init (network change recovery) |
| `nodus_messenger_is_ready()` | Check connection state (initialized + connected) |
| `nodus_messenger_is_initialized()` | Check if init was called (regardless of connection) |
| `nodus_messenger_set_status_callback(cb, data)` | Register connection status callback |
| `nodus_messenger_wait_for_ready(timeout_ms)` | Blocking wait for connection |

**Bootstrap resolution:**
1. Try cached bootstrap nodes from SQLite reliability database (best 3 by success rate)
2. Fall back to hardcoded nodes from `dna_config.c`
3. Parse `IP:port` format, default port = 4001

**Identity storage:** The identity is stored as a stack-allocated value type (not
heap-allocated) to prevent ASAN leak reports — one of the motivations for the rewrite.

### Bootstrap Cache

**Source:** `messenger/dht/client/bootstrap_cache.c`

SQLite database tracking bootstrap node reliability. Records success/failure counts and
latency for each server endpoint. The `bootstrap_cache_get_best()` function returns the
top N nodes sorted by success rate, enabling faster reconnection to known-good servers.

### Migration

On first connect to the v5 network, the messenger performs a one-time republish of local
DHT data (profiles, name registrations, etc.) to the new Nodus cluster. This is controlled
by a flag file and runs in the engine's stabilization thread.

---

## 13. Deployment

### Test Cluster

Three dedicated servers running Nodus v5:

| Node | IP | Specs |
|------|-----|-------|
| nodus-01 | 161.97.85.25 | 6c/11GB/99GB, Debian 13 |
| nodus-02 | 156.67.24.125 | 4c/8GB/74GB, Debian 13 |
| nodus-03 | 156.67.25.251 | 4c/8GB/74GB, Debian 13 |

### Systemd Service

```ini
[Unit]
Description=Nodus v5 DHT Server
After=network.target

[Service]
ExecStart=/usr/local/bin/nodus-v5 --config /etc/nodus-v5.conf
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 4000 | UDP | Kademlia discovery (T1 PING/PONG/FIND_NODE) |
| 4001 | TCP | Client connections (T2) + value replication (T1 STORE) |

### Identity Management

On first start, if no identity exists at `identity_path`, the server generates a random
Dilithium5 keypair and saves it. The identity persists across restarts — the node_id
(SHA3-512 of the public key) is the node's permanent identifier in the DHT.

### Redeploy

Each server has a `/tmp/nodus-redeploy.sh` script that pulls latest code, rebuilds, installs
to `/usr/local/bin/`, and restarts the systemd service.

---

## 14. Testing

### Test Suite

13 test files with **139 test functions** covering all modules:

| Test File | Module Tested | Test Count |
|-----------|---------------|------------|
| `test_wire.c` | Wire frame encode/decode | ~10 |
| `test_cbor.c` | CBOR encoder/decoder | ~15 |
| `test_tier1.c` | T1 protocol encode/decode | ~12 |
| `test_tier2.c` | T2 protocol encode/decode | ~18 |
| `test_value.c` | Value create/sign/verify/serialize | ~12 |
| `test_routing.c` | Kademlia routing table | ~14 |
| `test_storage.c` | SQLite DHT storage | ~10 |
| `test_identity.c` | Identity generation/save/load | ~8 |
| `test_hashring.c` | Consistent hash ring | ~10 |
| `test_channel_store.c` | Channel storage | ~10 |
| `test_tcp.c` | TCP transport | ~5 |
| `test_client.c` | Client SDK | ~8 |
| `test_server.c` | Server integration | ~7 |

### Integration Tests

`integration_test.sh` runs end-to-end scenarios:
- Start a server, connect a client, authenticate
- PUT/GET round-trip
- LISTEN + value change notification
- Channel create/post/get
- Multi-server replication

### Build & Run

```bash
cd nodus/build
cmake ..
make -j$(nproc)

# Run all tests
ctest --output-on-failure

# Run individual test
./test_wire
./test_tier2
```
