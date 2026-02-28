# TCP Channel Hosting Design

**Date:** 2026-02-26
**Status:** Draft (Detailed)
**Phase:** Post-v1 Infrastructure

---

## Overview

Migrate channel data hosting from pure DHT to a **TCP-based architecture** where Nodus servers actively host channel data. Channels are sharded across Nodus servers using consistent hashing, with a replication factor of 3 (1 Primary + 2 Backup). Users connect via TCP for real-time channel operations. BFT consensus (PBFT) governs ring membership changes.

**Key Decisions:**
- Consistent hash ring for channel → nodus sharding
- Replication factor 3 (1 Primary + 2 Backup), async replication
- Client-side hash computation for discovery (no redirect hop)
- Nodus registry via DHT (no hardcoded list)
- BFT consensus (PBFT) for ring membership only (swappable via interface)
- Binary wire protocol, 10-byte header, 100KB max frame
- 3-way Dilithium5 challenge-response authentication (mandatory)
- SQLite storage, per-channel table, 7-day retention
- DHT retains channel metadata/discovery role; TCP handles post data
- Sequential post numbering for sync (not timestamps)
- Nodus TCP port: 4001 (adjacent to DHT UDP 4000)
- Posts are immutable, append-only (CRDT-like conflict-free merge)
- Inter-nodus persistent TCP mesh for replication + consensus

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CONSENSUS LAYER                          │
│          PBFT membership — ring change decisions             │
│          Quorum: 2f+1 where f < n/3 Byzantine faults         │
│          Output: versioned ring (single source of truth)     │
│          Interface: swappable (PBFT → HotStuff if needed)    │
└──────────────────────────┬──────────────────────────────────┘
                           │ Ring v1, v2, v3...
┌──────────────────────────▼──────────────────────────────────┐
│                      NODUS CLUSTER                           │
│                                                              │
│  N1  N2  N3  N4  N5  N6  N7  N8  (currently 8, scalable)   │
│                                                              │
│  Each nodus:                                                 │
│   - Registers on DHT ("I'm here" — 7-day TTL)              │
│   - TCP server on port 4001 for client connections           │
│   - Inter-nodus TCP mesh for replication + consensus         │
│   - PBFT consensus participant                               │
│   - Dilithium5 certificate (nodus identity)                  │
│   - SQLite storage for assigned channels                     │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                      DATA LAYER                              │
│                                                              │
│  Channel X → SHA3(uuid) → ring position → [N3, N7, N1]     │
│                                             P    B1   B2     │
│                                                              │
│  POST       → Primary accepts → ACK to client → async       │
│               replicate to B1, B2                            │
│  GET_POSTS  → read from any of the 3                        │
│  SUBSCRIBE  → TCP push (real-time notification)             │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                       CLIENT                                 │
│                                                              │
│  1. Nodus list: GET from DHT (cache locally)                │
│  2. Ring version: received on first connection               │
│  3. Hash: SHA3(channel_uuid) → find 3 nodus                │
│  4. TCP connect: Primary → fail? → B1 → fail? → B2         │
│  5. Ring changed? → nodus tells client → recalculate        │
│  6. Local SQLite cache for received posts                    │
└─────────────────────────────────────────────────────────────┘
```

---

## DHT vs TCP Role Separation

| Concern | Layer | Rationale |
|---------|-------|-----------|
| Channel metadata (name, description, UUID) | DHT | Discovery, search, browse |
| Channel post data | TCP (Nodus) | Real-time, persistent, ordered |
| Nodus registry ("I'm alive") | DHT | Decentralized, 7-day TTL |
| Ring membership decisions | PBFT Consensus | Deterministic, BFT-safe |
| User authentication | TCP (Dilithium5) | Per-connection challenge-response |

**Design principle:** DHT = phone book (metadata, discovery). TCP = real conversation (data, real-time). Having a number in the phone book doesn't mean the other side will answer — TCP connectivity is the real liveness check.

---

## Nodus TCP Port

**Decision: Port 4001 (TCP)**

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| DHT | 4000 | UDP | Existing DHT network (unchanged) |
| Channel TCP | 4001 | TCP | Client connections + inter-nodus mesh |

**Rationale:**
- Adjacent to existing DHT port — easy firewall rules (`4000-4001`)
- No conflict with well-known services
- Single TCP port for both client-facing and inter-nodus traffic (distinguished by authentication: client key vs nodus key)
- Nodus config (`/etc/dna-nodus.conf`) extended with `"tcp_port": 4001`

**Firewall rules (per nodus server):**
```bash
# Existing
ufw allow 4000/udp   # DHT
# New
ufw allow 4001/tcp   # Channel hosting
```

---

## Sharding: Consistent Hash Ring

### Algorithm
1. Each nodus has a position on the ring: `SHA3-256(nodus_ip + ":" + nodus_port)`
2. Each channel has a position: `SHA3-256(channel_uuid)`
3. Walk clockwise from channel position → first 3 distinct nodus = [Primary, Backup1, Backup2]

### Determinism Requirement
**Every participant (client + all nodus) MUST compute the same ring from the same input.**
- Same hash function: SHA3-256 (already in project via `qgp_sha3.h`)
- Same nodus list: from DHT registry, sorted by nodus_id
- Same algorithm: clockwise walk, first 3 distinct nodes
- Nodus does NOT decide which channels to host — the hash function decides

### Ring Versioning
- Every ring change produces a new version number (uint32)
- Ring version is included in every TCP frame header
- Nodus detects stale client ring → sends RING_UPDATE
- Client recalculates and reconnects if needed

---

## Nodus Discovery (DHT Registry)

```
DHT Key:   SHA3-512("dna:system:nodus:registry")
Value:     { nodus_id, ip, tcp_port, public_key_fingerprint, timestamp, signature }
TTL:       7 days (standard DHT TTL)
```

- Each nodus publishes its registry entry on startup
- Nodus re-publishes periodically (before TTL expiry)
- Clients fetch and cache the nodus list
- Stale entries (nodus that disappeared) expire naturally via DHT TTL
- TCP connectivity is the real liveness check, not DHT presence

### Registry Value Format (Binary)

```
┌──────────────────────────────────────────────────────┐
│  nodus_id        32 bytes   SHA3-256(ip + ":" + port)│
│  ip_len          1 byte     Length of IP string       │
│  ip              N bytes    IP address (ASCII)        │
│  tcp_port        2 bytes    uint16, big-endian        │
│  fingerprint     64 bytes   SHA3-512(nodus_pubkey)    │
│  timestamp       8 bytes    uint64, big-endian        │
│  signature_len   2 bytes    uint16                    │
│  signature       M bytes    Dilithium5 (≤4627 bytes)  │
└──────────────────────────────────────────────────────┘
```

Signature covers: `nodus_id + ip + tcp_port + fingerprint + timestamp`

---

## Membership Consensus (PBFT)

### Purpose
Consensus decides ONE thing: **who is in the ring**.

Posts, subscriptions, and data operations do NOT go through consensus.

### Quorum Mathematics

```
n = total nodus count
f = max Byzantine faults tolerated
Constraint: n ≥ 3f + 1

For 8 nodus:  f = 2, quorum = 2f + 1 = 6 out of 8
For 12 nodus: f = 3, quorum = 2f + 1 = 7 out of 12
For 20 nodus: f = 6, quorum = 2f + 1 = 13 out of 20
```

### Failure Detection (Feeds into PBFT)

Before PBFT proposals, nodus failures must be detected. Detection uses a heartbeat/suspect/dead state machine:

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

**Detection flow:**
1. Each nodus sends PING to all peers every 10 seconds via inter-nodus TCP mesh
2. No PONG for 30 seconds → mark peer as SUSPECT
3. When `ceil(n/2)` nodus independently mark same peer as SUSPECT → trigger PBFT proposal to remove
4. PBFT proposal: "remove N3 from ring" → requires 2f+1 votes
5. If nodus comes back: new PBFT proposal "add N3 to ring"

### When Triggered
- Nodus joins the network (detected via DHT registry + TCP handshake)
- Nodus leaves/crashes (detected via TCP connection loss → suspect → dead)
- Network partition recovery

### Split Brain Prevention
```
8 nodus, partition into [N1-N4] and [N5-N8]:
  - Each side has 4 nodus
  - PBFT quorum requires 2f+1 = 6 (for f=2)
  - Neither side reaches quorum
  - Ring does NOT change → no split brain
  - Both sides continue serving existing channel data
  - No new ring changes until partition heals
```

### PBFT Protocol Phases

```
Proposer (detects failure/join) → all nodus:

Phase 1: PRE-PREPARE
  Proposer → all: "I propose removing N3 (view=V, seq=S)"
  Includes: proposed new ring, evidence (suspect votes)

Phase 2: PREPARE
  Each nodus that agrees → all: "I accept this proposal (view=V, seq=S)"
  Wait for 2f+1 PREPARE messages (including own)

Phase 3: COMMIT
  Each nodus that received 2f+1 PREPAREs → all: "I commit (view=V, seq=S)"
  Wait for 2f+1 COMMIT messages

Result: New ring version applied by all committed nodus
```

**View Change:** If the proposer (leader) fails during consensus, PBFT view change elects a new leader. View number increments, preventing stuck proposals.

### CONSENSUS_MSG Payload Format (0x34)

```
┌──────────────────────────────────────────────────────┐
│  consensus_phase   1 byte    1=PRE_PREPARE           │
│                              2=PREPARE               │
│                              3=COMMIT                │
│                              4=VIEW_CHANGE           │
│  view_number       4 bytes   uint32, big-endian      │
│  sequence_number   4 bytes   uint32, big-endian      │
│  proposer_fp       64 bytes  Proposer's fingerprint  │
│  change_type       1 byte    1=ADD_NODUS             │
│                              2=REMOVE_NODUS          │
│  target_nodus_id   32 bytes  SHA3-256 of target nodus│
│  new_ring_version  4 bytes   uint32, proposed version│
│  nodus_count       1 byte    Nodus in proposed ring  │
│  nodus_list[]      N bytes   32 bytes × nodus_count  │
│  evidence_len      2 bytes   Length of evidence data  │
│  evidence          M bytes   Suspect votes / proof    │
│  signature_len     2 bytes   uint16                  │
│  signature         S bytes   Dilithium5 (≤4627)      │
└──────────────────────────────────────────────────────┘
```

Signature covers all fields except signature_len and signature itself.

### Interface (Swappable)
```c
// Consensus interface — implementation can be PBFT, HotStuff, etc.
typedef struct {
    int (*propose_ring_change)(ring_change_t *change);
    ring_t* (*get_current_ring)(void);
    uint32_t (*get_ring_version)(void);
    int (*on_consensus_msg)(const uint8_t *data, size_t len, const char *sender_fp);
} consensus_interface_t;
```

### Scalability

| Nodus Count | Messages Per Round | Practical? |
|-------------|-------------------|------------|
| 8 | 64 (8²) | Yes — target deployment |
| 20 | 400 (20²) | Yes — manageable |
| 50 | 2,500 (50²) | Borderline — consider swap |
| 100 | 10,000 (100²) | No — swap to HotStuff O(n) |

Future scaling: if nodus count exceeds ~50, swap PBFT (O(n²)) for HotStuff (O(n)) behind the same interface. The consensus_interface_t abstraction makes this a drop-in replacement.

---

## Wire Protocol

### Frame Format (Binary)

```
┌──────────┬──────────┬──────────┬──────────┬─────────────────────┐
│ 4 bytes  │ 1 byte   │ 4 bytes  │ 1 byte   │ N bytes             │
│ length   │ proto_ver│ ring_ver │ msg_type │ payload             │
└──────────┴──────────┴──────────┴──────────┴─────────────────────┘
```

| Field | Size | Description |
|-------|------|-------------|
| `length` | 4 bytes (uint32, big-endian) | Byte count of everything after length field |
| `proto_ver` | 1 byte | Wire protocol version (starts at 0x01) |
| `ring_ver` | 4 bytes (uint32, big-endian) | Sender's current ring version |
| `msg_type` | 1 byte | Message type code |
| `payload` | N bytes | Message-specific data |

- **Header:** 10 bytes total (fixed)
- **Max frame size:** 100KB (102,400 bytes)
- **Byte order:** Big-endian (network byte order)
- `length` = proto_ver(1) + ring_ver(4) + msg_type(1) + payload(N) = 6 + payload_len

### Message Types

**Authentication (pre-auth):**

| Code | Type | Direction | Description |
|------|------|-----------|-------------|
| 0x01 | HELLO | C→N | fingerprint + public_key |
| 0x02 | CHALLENGE | N→C | 32-byte random nonce |
| 0x03 | AUTH_RESPONSE | C→N | SIGN(nonce, private_key) |
| 0x04 | AUTH_OK | N→C | Session authenticated |
| 0x05 | AUTH_FAIL | N→C | Authentication failed |

**Channel operations (post-auth):**

| Code | Type | Direction | Description |
|------|------|-----------|-------------|
| 0x10 | SUBSCRIBE | C→N | Subscribe to channel (channel_uuid) |
| 0x11 | UNSUBSCRIBE | C→N | Unsubscribe from channel |
| 0x12 | POST | C→N | New post (channel_uuid + payload + signature) |
| 0x13 | GET_POSTS | C→N | Request posts (channel_uuid + since_seq_id) |
| 0x14 | PING | C→N | Keepalive |
| 0x15 | CREATE_CHANNEL | C→N | Create new channel on this nodus |

**Server responses:**

| Code | Type | Direction | Description |
|------|------|-----------|-------------|
| 0x20 | POST_NOTIFY | N→C | Push: new post arrived |
| 0x21 | POSTS_RESPONSE | N→C | Response to GET_POSTS |
| 0x22 | RING_UPDATE | N→C | New ring version + nodus list |
| 0x23 | PONG | N→C | Keepalive response |
| 0x24 | ERROR | N→C | Error response (code + message) |
| 0x25 | CHANNEL_CREATED | N→C | Channel creation confirmed |

**Inter-nodus (nodus ↔ nodus):**

| Code | Type | Direction | Description |
|------|------|-----------|-------------|
| 0x30 | REPLICATE_POST | N→N | Forward post to backup |
| 0x31 | REPLICATE_ACK | N→N | Backup confirms receipt |
| 0x32 | SYNC_REQUEST | N→N | Request full channel sync |
| 0x33 | SYNC_DATA | N→N | Channel table dump (chunked) |
| 0x34 | CONSENSUS_MSG | N→N | PBFT protocol messages |

### Detailed Payload Formats

All multi-byte integers are **big-endian** (network byte order). UUIDs are stored as 16-byte binary (not string). Fingerprints are 64-byte binary SHA3-512 (not hex).

#### Authentication Messages

**HELLO (0x01) — Client → Nodus**
```
┌──────────────────────────────────────┐
│  fingerprint     64 bytes            │  SHA3-512(public_key), binary
│  public_key      2592 bytes          │  Dilithium5 (ML-DSA-87)
└──────────────────────────────────────┘
Total payload: 2656 bytes (fixed)
```

**CHALLENGE (0x02) — Nodus → Client**
```
┌──────────────────────────────────────┐
│  nonce           32 bytes            │  Cryptographically random
└──────────────────────────────────────┘
Total payload: 32 bytes (fixed)
```

**AUTH_RESPONSE (0x03) — Client → Nodus**
```
┌──────────────────────────────────────┐
│  signature_len   2 bytes             │  uint16 (actual sig length, ≤4627)
│  signature       S bytes             │  SIGN(nonce, private_key)
└──────────────────────────────────────┘
Total payload: 2 + S bytes (S ≤ 4627)
```

**AUTH_OK (0x04) — Nodus → Client**
```
┌──────────────────────────────────────┐
│  (empty payload)                     │
└──────────────────────────────────────┘
Total payload: 0 bytes
```

**AUTH_FAIL (0x05) — Nodus → Client**
```
┌──────────────────────────────────────┐
│  error_code      1 byte              │  1=bad_fingerprint, 2=bad_signature,
│                                      │  3=banned, 4=server_error
│  message_len     2 bytes             │  uint16
│  message         N bytes             │  UTF-8 human-readable reason
└──────────────────────────────────────┘
Total payload: 3 + N bytes
```

#### Channel Operations

**SUBSCRIBE (0x10) — Client → Nodus**
```
┌──────────────────────────────────────┐
│  channel_uuid    16 bytes            │  Binary UUID
└──────────────────────────────────────┘
Total payload: 16 bytes (fixed)
```

**UNSUBSCRIBE (0x11) — Client → Nodus**
```
┌──────────────────────────────────────┐
│  channel_uuid    16 bytes            │  Binary UUID
└──────────────────────────────────────┘
Total payload: 16 bytes (fixed)
```

**POST (0x12) — Client → Nodus**
```
┌──────────────────────────────────────┐
│  channel_uuid    16 bytes            │  Binary UUID
│  post_uuid       16 bytes            │  Client-generated UUID v4
│  timestamp       8 bytes             │  uint64, author's local time
│  body_len        2 bytes             │  uint16 (max 4000)
│  body            B bytes             │  UTF-8 post content
│  signature_len   2 bytes             │  uint16 (≤4627)
│  signature       S bytes             │  Dilithium5 SIGN(channel_uuid
│                                      │    + post_uuid + timestamp + body)
└──────────────────────────────────────┘
Total payload: 44 + B + S bytes
```

**GET_POSTS (0x13) — Client → Nodus**
```
┌──────────────────────────────────────┐
│  channel_uuid    16 bytes            │  Binary UUID
│  since_seq_id    4 bytes             │  uint32 (0 = from beginning)
│  max_count       2 bytes             │  uint16 (0 = all available)
└──────────────────────────────────────┘
Total payload: 22 bytes (fixed)
```

**PING (0x14) — Client → Nodus**
```
┌──────────────────────────────────────┐
│  (empty payload)                     │
└──────────────────────────────────────┘
Total payload: 0 bytes
```

**CREATE_CHANNEL (0x15) — Client → Nodus**
```
┌──────────────────────────────────────┐
│  channel_uuid    16 bytes            │  Client-generated UUID v4
│  name_len        1 byte              │  uint8 (max 100)
│  name            N bytes             │  UTF-8 channel name
│  desc_len        2 bytes             │  uint16 (max 500)
│  description     D bytes             │  UTF-8 channel description
│  is_public       1 byte              │  0=private, 1=public
└──────────────────────────────────────┘
Total payload: 20 + N + D bytes
```

#### Server Responses

**POST_NOTIFY (0x20) — Nodus → Client**
```
┌──────────────────────────────────────┐
│  channel_uuid    16 bytes            │  Binary UUID
│  seq_id          4 bytes             │  uint32, assigned by primary
│  post_uuid       16 bytes            │  Binary UUID
│  author_fp       64 bytes            │  SHA3-512 binary
│  timestamp       8 bytes             │  uint64, author's timestamp
│  body_len        2 bytes             │  uint16
│  body            B bytes             │  UTF-8 post content
│  signature_len   2 bytes             │  uint16
│  signature       S bytes             │  Dilithium5 (≤4627)
└──────────────────────────────────────┘
Total payload: 112 + B + S bytes
```

**POSTS_RESPONSE (0x21) — Nodus → Client**
```
┌──────────────────────────────────────┐
│  channel_uuid    16 bytes            │  Binary UUID
│  post_count      2 bytes             │  uint16
│  posts[]:                            │  Repeated post_count times:
│    seq_id        4 bytes             │    uint32
│    post_uuid     16 bytes            │    Binary UUID
│    author_fp     64 bytes            │    SHA3-512 binary
│    timestamp     8 bytes             │    uint64
│    body_len      2 bytes             │    uint16
│    body          B bytes             │    UTF-8
│    signature_len 2 bytes             │    uint16
│    signature     S bytes             │    Dilithium5 (≤4627)
└──────────────────────────────────────┘
Total payload: 18 + sum(96 + B + S per post) bytes
```

**RING_UPDATE (0x22) — Nodus → Client**
```
┌──────────────────────────────────────┐
│  ring_version    4 bytes             │  uint32, new version
│  nodus_count     1 byte              │  Number of nodus in ring
│  nodus_list[]:                       │  Repeated nodus_count times:
│    nodus_id      32 bytes            │    SHA3-256(ip:port)
│    ip_len        1 byte              │    uint8
│    ip            N bytes             │    ASCII IP address
│    tcp_port      2 bytes             │    uint16
│    fingerprint   64 bytes            │    SHA3-512(nodus_pubkey)
└──────────────────────────────────────┘
Total payload: 5 + sum(99 + N per nodus) bytes
```

**PONG (0x23) — Nodus → Client**
```
┌──────────────────────────────────────┐
│  (empty payload)                     │
└──────────────────────────────────────┘
Total payload: 0 bytes
```

**ERROR (0x24) — Nodus → Client**
```
┌──────────────────────────────────────┐
│  error_code      2 bytes             │  uint16 (see error codes below)
│  ref_msg_type    1 byte              │  Which message caused the error
│  message_len     2 bytes             │  uint16
│  message         N bytes             │  UTF-8 human-readable error
└──────────────────────────────────────┘
Total payload: 5 + N bytes
```

Error codes:
| Code | Meaning |
|------|---------|
| 0x0001 | NOT_AUTHENTICATED — operation requires auth |
| 0x0002 | CHANNEL_NOT_FOUND — unknown channel UUID |
| 0x0003 | NOT_RESPONSIBLE — wrong nodus for this channel |
| 0x0004 | RING_MISMATCH — client ring is stale |
| 0x0005 | RATE_LIMITED — too many requests |
| 0x0006 | PAYLOAD_TOO_LARGE — exceeds 100KB |
| 0x0007 | INVALID_SIGNATURE — post signature verification failed |
| 0x0008 | INTERNAL_ERROR — nodus internal failure |

**CHANNEL_CREATED (0x25) — Nodus → Client**
```
┌──────────────────────────────────────┐
│  channel_uuid    16 bytes            │  Binary UUID (echo back)
│  seq_id_start    4 bytes             │  uint32 (initial seq_id, 0)
└──────────────────────────────────────┘
Total payload: 20 bytes (fixed)
```

#### Inter-Nodus Messages

**REPLICATE_POST (0x30) — Primary → Backup**
```
┌──────────────────────────────────────┐
│  channel_uuid    16 bytes            │  Binary UUID
│  seq_id          4 bytes             │  uint32, assigned by primary
│  post_uuid       16 bytes            │  Binary UUID
│  author_fp       64 bytes            │  SHA3-512 binary
│  timestamp       8 bytes             │  uint64, author's timestamp
│  body_len        2 bytes             │  uint16
│  body            B bytes             │  UTF-8 post content
│  signature_len   2 bytes             │  uint16
│  signature       S bytes             │  Dilithium5 (≤4627)
└──────────────────────────────────────┘
Total payload: 112 + B + S bytes (same layout as POST_NOTIFY)
```

Backup verifies `author_fp` matches `signature` over `(channel_uuid + post_uuid + timestamp + body)` before storing. This is BFT protection — even a malicious primary cannot inject fake posts.

**REPLICATE_ACK (0x31) — Backup → Primary**
```
┌──────────────────────────────────────┐
│  channel_uuid    16 bytes            │  Binary UUID
│  seq_id          4 bytes             │  uint32, confirming receipt
└──────────────────────────────────────┘
Total payload: 20 bytes (fixed)
```

**SYNC_REQUEST (0x32) — Nodus → Nodus**
```
┌──────────────────────────────────────┐
│  channel_uuid    16 bytes            │  Binary UUID
│  since_seq_id    4 bytes             │  uint32 (0 = full sync)
└──────────────────────────────────────┘
Total payload: 20 bytes (fixed)
```

**SYNC_DATA (0x33) — Nodus → Nodus (chunked)**
```
┌──────────────────────────────────────┐
│  channel_uuid    16 bytes            │  Binary UUID
│  total_posts     4 bytes             │  uint32, total across all chunks
│  chunk_index     2 bytes             │  uint16, 0-based
│  chunk_total     2 bytes             │  uint16, total chunks
│  post_count      2 bytes             │  uint16, posts in THIS chunk
│  posts[]:                            │  Same format as POSTS_RESPONSE
│    seq_id        4 bytes             │
│    post_uuid     16 bytes            │
│    author_fp     64 bytes            │
│    timestamp     8 bytes             │
│    body_len      2 bytes             │
│    body          B bytes             │
│    signature_len 2 bytes             │
│    signature     S bytes             │
└──────────────────────────────────────┘
Total payload: 26 + post data bytes
```

Chunked to stay within 100KB max frame. Each chunk is independently processable. Receiver assembles full table from all chunks.

**CONSENSUS_MSG (0x34) — Nodus → Nodus**

See [PBFT Protocol Phases](#pbft-protocol-phases) section for detailed format.

---

## Authentication

### 3-Way Handshake (Dilithium5)

```
Client → Nodus:  HELLO { fingerprint(64B), public_key(2592B) }
Nodus:           verify: fingerprint == SHA3-512(public_key)
Nodus → Client:  CHALLENGE { nonce(32B) }
Client → Nodus:  AUTH_RESPONSE { signature(≤4627B) = SIGN(nonce, private_key) }
Nodus:           VERIFY(signature, nonce, public_key)
                 ✓ → AUTH_OK, session authenticated
                 ✗ → AUTH_FAIL, disconnect
```

- Authentication is **mandatory** for all operations (reads and writes)
- Post-auth: TCP session is trusted, no per-message signing required
- Client sends public_key in HELLO to avoid DHT lookup delay — nodus verifies fingerprint match locally
- Even users who haven't registered a DHT profile can connect (key-only identity)

### Nodus Identity
- Every nodus has its own Dilithium5 keypair (nodus certificate)
- Used for inter-nodus authentication (same 3-way handshake, nodus-to-nodus)
- Used for signing PBFT consensus messages
- Nodus public key published in DHT registry
- Generated on first nodus startup, stored in nodus data directory

### Crypto Functions Used

| Operation | Function | Header |
|-----------|----------|--------|
| Sign nonce | `qgp_dsa87_sign()` | `crypto/utils/qgp_dilithium.h` |
| Verify signature | `qgp_dsa87_verify()` | `crypto/utils/qgp_dilithium.h` |
| Compute fingerprint | `qgp_sha3_512_fingerprint()` | `crypto/utils/qgp_sha3.h` |
| Generate nonce | `qgp_platform_random()` | `crypto/utils/qgp_platform.h` |

---

## Replication

### Async Model

```
Client ──POST──► Primary Nodus
                    │
                    ├─► store locally (SQLite) → assign seq_id → ACK to client
                    │
                    └─► background: TCP forward to Backup1, Backup2
                          ├─► Backup1: store → REPLICATE_ACK
                          └─► Backup2: store → REPLICATE_ACK

                    REPLICATE_ACK failure → hinted handoff queue
```

**Async tradeoff:** Primary ACKs immediately without waiting for backup confirmation. This means if primary crashes between ACK and replication, the last few posts may be lost. For channel posts (not banking transactions), this is an acceptable tradeoff for low latency.

### Data Per Replication Message

```
REPLICATE_POST payload:
  channel_uuid:     16 bytes
  seq_id:           4 bytes
  post_uuid:        16 bytes
  author_fp:        64 bytes  (SHA3-512)
  timestamp:        8 bytes
  payload:          max ~4KB
  author_signature: 4627 bytes (Dilithium5)
  ─────────────────────────────
  Total:            ~9KB per post
```

- Full data replication: backup can independently verify post authenticity
- Backup verifies author_signature before storing (BFT protection)
- Load estimate: 100 posts/sec × 9KB × 2 backups = ~1.8 MB/s bandwidth

### Hinted Handoff (Temporary Failures)

When a backup is temporarily unreachable during replication:

```
Primary receives POST:
  1. Store locally → assign seq_id → ACK to client
  2. Forward to Backup1 → success → REPLICATE_ACK
  3. Forward to Backup2 → TCP timeout → Backup2 is temporarily down
  4. Store in hinted_handoff queue: { target: Backup2, post_data }
  5. Retry periodically (every 30 seconds)
  6. Backup2 comes back → flush all hinted posts → REPLICATE_ACK
  7. Clear hint from queue
```

**Distinct from SYNC_DATA:** Hinted handoff covers brief outages (minutes). If a nodus is declared DEAD by PBFT and a new ring is computed, full channel transfer via SYNC_DATA is used instead.

**Queue limits:** Max 1000 hinted posts per target nodus. If exceeded, oldest hints are dropped (the full SYNC_DATA path will catch up later).

---

## Conflict Resolution

### Immutable Append-Only Posts (CRDT-Like)

Posts are **immutable** — once created, they are never modified or deleted (within retention window). This fundamental constraint eliminates write conflicts:

```
Scenario: Primary N3 is down, client writes to Backup N7:
  - N7 accepts post, assigns seq_id from its own counter
  - N3 comes back, has different posts from before the failure
  - Merge: union of all posts, deduplicate by post_uuid
  - Re-sequence: assign new seq_ids in received_at order
  - No conflicts because posts are never updated, only appended
```

**Rules:**
- Each post has a globally unique `post_uuid` (UUID v4, client-generated)
- Duplicate detection: if `post_uuid` already exists, discard the duplicate
- After ring change with data merge: re-assign seq_ids by `received_at` order
- Clients may see seq_id gaps during transitions — gaps are normal and expected

---

## Inter-Nodus TCP Mesh

All nodus maintain **persistent TCP connections** to every other nodus:

```
8 nodus → each has 7 outbound connections = 28 total connections
  N1 ←→ N2, N3, N4, N5, N6, N7, N8
  N2 ←→ N3, N4, N5, N6, N7, N8
  ... (full mesh)
```

**Used for:**
1. **Replication** — REPLICATE_POST / REPLICATE_ACK
2. **Health monitoring** — periodic PING/PONG (10-second interval)
3. **PBFT consensus** — CONSENSUS_MSG messages
4. **Channel transfer** — SYNC_REQUEST / SYNC_DATA

**Connection management:**
- Same wire protocol (10-byte header + payload)
- Same authentication (3-way Dilithium5 with nodus keys)
- Auto-reconnect on disconnect with exponential backoff (1s, 2s, 4s, max 30s)
- Connection loss triggers suspect detection (see PBFT section)

---

## Storage

### Nodus-Side (SQLite)

```sql
-- Created dynamically when channel is assigned to this nodus
CREATE TABLE channel_<uuid_hex> (
    seq_id       INTEGER NOT NULL,       -- per-channel sequential, 4 bytes
    post_uuid    BLOB NOT NULL,
    author_fp    BLOB NOT NULL,          -- 64 bytes
    timestamp    INTEGER NOT NULL,       -- author's timestamp (for UX display)
    payload      BLOB NOT NULL,
    signature    BLOB NOT NULL,          -- Dilithium5, 4627 bytes
    received_at  INTEGER NOT NULL,       -- nodus receive time (for system ops)
    PRIMARY KEY (seq_id)
);

CREATE INDEX idx_<uuid_hex>_recv ON channel_<uuid_hex>(received_at);
CREATE UNIQUE INDEX idx_<uuid_hex>_uuid ON channel_<uuid_hex>(post_uuid);

-- 7-day retention cleanup (periodic, every hour)
DELETE FROM channel_<uuid_hex> WHERE received_at < strftime('%s','now') - 604800;

-- Hinted handoff queue (per nodus, not per channel)
CREATE TABLE hinted_handoff (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_fp    BLOB NOT NULL,          -- Target nodus fingerprint
    channel_uuid BLOB NOT NULL,
    post_data    BLOB NOT NULL,          -- Full serialized post
    created_at   INTEGER NOT NULL,
    retry_count  INTEGER DEFAULT 0
);

CREATE INDEX idx_hinted_target ON hinted_handoff(target_fp);
```

**Two timestamps, two purposes:**
- `timestamp` — author's claimed time → displayed in UI
- `received_at` — nodus receive time → used for retention, sync, ordering

Why not trust author timestamp for retention? A malicious user could set their clock to 2030 — the post would never expire. `received_at` prevents this.

**Sequence ID:**
- Assigned by Primary nodus on receipt
- Monotonically increasing per channel
- On primary failover: new primary continues from MAX(seq_id)
- Client uses seq_id for sync: "give me posts after seq_id X"
- Gap detection: if client sees seq_id jump from 344 to 347, seq_ids 345-346 are missing

### Client-Side Cache (SQLite)

```sql
-- Local cache on client device (extends existing channel_cache.db)
CREATE TABLE tcp_channel_posts (
    channel_uuid TEXT NOT NULL,
    seq_id       INTEGER NOT NULL,
    post_uuid    BLOB NOT NULL,
    author_fp    TEXT NOT NULL,          -- 128 hex chars (matches existing convention)
    timestamp    INTEGER NOT NULL,
    body         TEXT NOT NULL,
    received_at  INTEGER NOT NULL,
    PRIMARY KEY (channel_uuid, seq_id)
);

-- Track sync state per channel
CREATE TABLE tcp_channel_sync_state (
    channel_uuid TEXT PRIMARY KEY,
    last_seq_id  INTEGER NOT NULL,      -- highest seq_id received
    last_sync    INTEGER NOT NULL,       -- timestamp of last sync
    nodus_ip     TEXT,                   -- last connected nodus
    nodus_port   INTEGER                 -- for reconnection hint
);
```

---

## Failover Scenarios

### Client-Driven Failover (Normal Operation)

```
Channel X → ring says [N3, N7, N1]

Client:
  TCP connect N3 (Primary)  → timeout/refused → N3 is down
  TCP connect N7 (Backup1)  → success → use N7
  TCP connect N1 (Backup2)  → last resort
  All 3 fail                → error to user
```

No coordination needed. Client knows the ring, tries in order.

### Nodus Failure — Replication Factor Drop

```
Channel X → [N3, N7, N1], N3 and N7 down:

N1 (sole survivor):
  - Detects N3, N7 TCP connections lost
  - Continues serving clients
  - Triggers PBFT proposal: "remove N3, N7 from ring"
  - If quorum reached → new ring version
  - New ring: Channel X → [N1, N5, N2]
  - N1 replicates channel data to N5, N2 (via SYNC_DATA)
  - Replication factor restored to 3
```

### Nodus Recovery

```
N3 comes back online:
  - Publishes to DHT registry
  - Connects to peer nodus via TCP (joins mesh)
  - PBFT proposal: "add N3 to ring"
  - If quorum → new ring version
  - Ring recalculated: some channels shift back to N3
  - N3 receives channel data via SYNC_DATA from current owners
```

### Channel Transfer (Ring Change)

```
Ring v2 → v3: Channel X moves from [N1, N5, N2] back to [N3, N7, N1]

N1 (has data, stays in set):
  - Sends SYNC_DATA to N3 (new primary, just rejoined)
  - N3 receives full channel table dump (chunked)
  - N7 receives full channel table dump (chunked)
  - Transfer complete, N3 is new primary
  - N5, N2 drop Channel X table (no longer responsible)
```

---

## Channel Lifecycle

### Channel Creation

```
1. User generates channel UUID (client-side, UUID v4)
2. User publishes channel metadata to DHT:
   - Key: SHA3-512("dna:channel:" + uuid)
   - Value: { uuid, name, description, creator_fp, created_at }
   - Purpose: discovery, search, browse
3. Client computes: SHA3-256(uuid) → ring → [Primary, B1, B2]
4. Client TCP connects to Primary (port 4001)
5. Sends CREATE_CHANNEL { uuid, name, description, is_public }
6. Primary creates SQLite table → replicates to B1, B2
7. Primary responds CHANNEL_CREATED { uuid, seq_id_start: 0 }
8. Channel is live
```

### Channel Discovery (Unchanged)
- DHT stores channel metadata (same as current system)
- Users browse/search channels via DHT
- Subscribing/reading posts → TCP connection to responsible nodus

### Posting

```
1. Client computes channel's nodus: SHA3-256(uuid) → [Primary, B1, B2]
2. TCP connect to Primary (or next available in failover order)
3. Send POST { channel_uuid, post_uuid, timestamp, body, signature }
   - signature = SIGN(channel_uuid + post_uuid + timestamp + body, private_key)
4. Nodus verifies signature using client's authenticated public_key
5. Nodus assigns seq_id, stores in SQLite, ACKs
6. Nodus pushes POST_NOTIFY to all subscribed TCP clients
7. Nodus async replicates to backups (REPLICATE_POST)
```

### Subscribing / Real-Time

```
1. Client sends SUBSCRIBE { channel_uuid }
2. Nodus registers client in subscriber list (in-memory hash map)
3. When new post arrives → POST_NOTIFY pushed to all subscribers
4. Client sends UNSUBSCRIBE or TCP disconnects → removed from list
```

### Reconnection / Sync

```
1. Client reconnects after disconnect
2. Authenticates (3-way handshake)
3. Sends GET_POSTS { channel_uuid, since_seq_id: last_known }
4. Nodus returns all posts with seq_id > since_seq_id
5. Client merges into local SQLite cache
6. Client re-sends SUBSCRIBE for real-time push
```

---

## Codebase References

### Existing Code (Reusable)

| Design Concept | Existing Code | File Path |
|----------------|---------------|-----------|
| Channel metadata struct | `dna_channel_info_t` | `include/dna/dna_engine.h` |
| Channel post struct | `dna_channel_post_info_t` | `include/dna/dna_engine.h` |
| Channel subscription struct | `dna_channel_subscription_info_t` | `include/dna/dna_engine.h` |
| Channel callbacks | `dna_channel_cb`, `dna_channel_posts_cb` | `include/dna/dna_engine.h` |
| Channel engine module | 9 task handlers, 1140 lines | `src/api/engine/dna_engine_channels.c` |
| Channel DHT operations | `dna_channel_create()`, `dna_channel_post_create()` | `dht/client/dna_channels.c` |
| Channel DHT header | Structs + key derivation functions | `dht/client/dna_channels.h` |
| Channel cache DB | `channel_cache_put_posts()`, `channel_cache_get_posts()` | `database/channel_cache.c` |
| Channel subscriptions DB | `channel_subscriptions_db_subscribe()` | `database/channel_subscriptions_db.c` |
| DHT subscription sync | `dht_channel_subscriptions_sync_to_dht()` | `dht/shared/dht_channel_subscriptions.c` |
| Dilithium5 sign | `qgp_dsa87_sign(sig, siglen, msg, mlen, sk)` | `crypto/utils/qgp_dilithium.h` |
| Dilithium5 verify | `qgp_dsa87_verify(sig, siglen, msg, mlen, pk)` | `crypto/utils/qgp_dilithium.h` |
| SHA3-512 hash | `qgp_sha3_512(data, len, hash_out)` | `crypto/utils/qgp_sha3.h` |
| SHA3-512 fingerprint | `qgp_sha3_512_fingerprint(pubkey, len, fp_out)` | `crypto/utils/qgp_sha3.h` |
| Secure random | `qgp_platform_random(buf, len)` | `crypto/utils/qgp_platform.h` |
| Platform abstraction | Socket helpers, file I/O, paths | `crypto/utils/qgp_platform.h` |
| Struct packing | `PACK_STRUCT_BEGIN` / `PACK_STRUCT_END` | `crypto/utils/qgp_compiler.h` |
| Thread pool | `threadpool_create()`, `threadpool_submit()` | `crypto/utils/threadpool.h` |
| Engine task system | `dna_submit_task()`, `dna_task_queue_t` | `src/api/dna_engine_internal.h` |
| Engine module pattern | `engine_includes.h` + `#define DNA_ENGINE_XXX_IMPL` | `src/api/engine/engine_includes.h` |
| Nodus config | `NodusConfig` struct | `vendor/opendht-pq/tools/nodus_config.h` |
| Nodus main | `dhtcnode.c` (DHT bootstrap server) | `vendor/opendht-pq/tools/dhtcnode.c` |
| Transport layer | `transport_init()`, `transport_start()` | `transport/transport.h` |
| Offline queue format | `dht_offline_message_t`, magic "DNA " | `dht/shared/dht_offline_queue.h` |
| Cache manager | `cache_manager_init()`, `cache_manager_cleanup()` | `database/cache_manager.h` |

### Existing Crypto Constants

| Constant | Value | Header |
|----------|-------|--------|
| `QGP_DSA87_PUBLICKEYBYTES` | 2592 | `crypto/utils/qgp_dilithium.h` |
| `QGP_DSA87_SECRETKEYBYTES` | 4896 | `crypto/utils/qgp_dilithium.h` |
| `QGP_DSA87_SIGNATURE_BYTES` | 4627 | `crypto/utils/qgp_dilithium.h` |
| `QGP_SHA3_512_DIGEST_LENGTH` | 64 | `crypto/utils/qgp_sha3.h` |
| `QGP_SHA3_512_HEX_LENGTH` | 129 | `crypto/utils/qgp_sha3.h` |
| `QGP_FINGERPRINT_HEX_SIZE` | 129 | `crypto/utils/qgp_types.h` |

### Current Channel Task Types (Engine)

```c
// From src/api/dna_engine_internal.h — these will be extended for TCP
TASK_CHANNEL_CREATE          → dna_handle_channel_create()
TASK_CHANNEL_GET             → dna_handle_channel_get()
TASK_CHANNEL_DELETE           → dna_handle_channel_delete()
TASK_CHANNEL_DISCOVER         → dna_handle_channel_discover()
TASK_CHANNEL_POST            → dna_handle_channel_post()
TASK_CHANNEL_GET_POSTS       → dna_handle_channel_get_posts()
TASK_CHANNEL_GET_SUBSCRIPTIONS → dna_handle_channel_get_subscriptions()
TASK_CHANNEL_SYNC_SUBS_TO_DHT → dna_handle_channel_sync_subs_to_dht()
TASK_CHANNEL_SYNC_SUBS_FROM_DHT → dna_handle_channel_sync_subs_from_dht()
```

### Current DHT Key Derivation

```c
// From dht/client/dna_channels.c — metadata stays on DHT
dna_channel_make_meta_key()  → SHA256("dna:channels:meta:" + uuid)
dna_channel_make_posts_key() → SHA256("dna:channels:posts:" + uuid + ":" + YYYYMMDD)
dna_channel_make_index_key() → SHA256("dna:channels:idx:" + YYYYMMDD)

// New (TCP system):
// Posts move from DHT daily buckets to TCP/SQLite
// Metadata + index remain on DHT (discovery)
```

### What Must Be Built (New Code)

| Component | Description | Suggested Location |
|-----------|-------------|-------------------|
| TCP server (nodus) | Accept client + nodus connections | `vendor/opendht-pq/tools/tcp_server.c` |
| TCP client (library) | Connect to nodus from C library | `transport/tcp_client.c`, `transport/tcp_client.h` |
| Wire protocol | Frame parsing, serialization | `transport/tcp_protocol.c`, `transport/tcp_protocol.h` |
| Auth handshake | 3-way Dilithium5 (client + nodus) | `transport/tcp_auth.c` |
| Consistent hash ring | SHA3-256 ring computation | `dht/shared/consistent_hash.c` |
| PBFT consensus | Ring membership consensus | `vendor/opendht-pq/tools/pbft_consensus.c` |
| Nodus channel storage | Per-channel SQLite tables | `vendor/opendht-pq/tools/channel_storage.c` |
| Replication manager | Async replication + hinted handoff | `vendor/opendht-pq/tools/replication.c` |
| Client TCP cache | Local SQLite mirror + sync state | `database/tcp_channel_cache.c` |
| Engine TCP module | New task handlers for TCP channels | `src/api/engine/dna_engine_tcp_channels.c` |
| Nodus mesh manager | Inter-nodus connection pool | `vendor/opendht-pq/tools/nodus_mesh.c` |

---

## Platform Considerations

### TCP Client (C Library — All Platforms)

The TCP client runs inside the DNA library, which targets Linux, Windows, and Android.

#### Linux
- **I/O multiplexing:** `epoll` for async TCP (most efficient on Linux)
- **Threads:** `pthreads` (already used throughout codebase)
- **DNS:** Standard `getaddrinfo()` for nodus IP resolution
- **No new dependencies** — standard POSIX sockets

#### Windows
- **I/O multiplexing:** `select()` for simplicity (IOCP is more performant but complex)
- **Socket init:** Must call `WSAStartup()` before any socket operations
- **Include order:** `winsock2.h` MUST come before `windows.h` (existing pattern)
- **Platform abstraction:** Extend `qgp_platform_windows.c` with socket helpers
- **Format specifiers:** Use `%llu` with casts for `uint64_t` timestamps (Windows `long` is 32-bit)

#### Android
- **Background TCP:** Managed via Android `ForegroundService` (existing pattern in DNA)
- **Battery:** TCP keepalive interval must be > 60 seconds to avoid excessive wake-ups
- **Network changes:** Use `qgp_platform_network_state()` callback to detect WiFi↔cellular transitions — reconnect on change
- **Lifecycle:** Engine `PAUSED` state → close TCP connections. `ACTIVE` → reconnect.
- **Existing pattern:** `dna_engine_lifecycle.c` already handles pause/resume for DHT listeners

#### Platform Abstraction Extensions

New functions needed in `crypto/utils/qgp_platform.h`:

```c
// TCP socket abstraction (new)
typedef int qgp_socket_t;  // SOCKET on Windows, int on POSIX

qgp_socket_t qgp_tcp_connect(const char *host, uint16_t port, int timeout_ms);
int qgp_tcp_send(qgp_socket_t sock, const uint8_t *data, size_t len);
int qgp_tcp_recv(qgp_socket_t sock, uint8_t *buf, size_t buf_len, int timeout_ms);
void qgp_tcp_close(qgp_socket_t sock);
int qgp_tcp_set_keepalive(qgp_socket_t sock, int interval_sec);
```

Implementations in `qgp_platform_linux.c`, `qgp_platform_windows.c`, `qgp_platform_android.c`.

### TCP Server (Nodus — Linux Only)

The nodus server currently runs only on Linux (production bootstrap servers). The TCP server addition targets Linux only.

- **I/O multiplexing:** `epoll` for handling hundreds of concurrent client connections
- **Thread model:** One acceptor thread + worker thread pool (reuse `threadpool.h` pattern)
- **Existing nodus:** C++ codebase (`vendor/opendht-pq/tools/`), new TCP code integrates alongside existing DHT server
- **Process model:** Single process, multi-threaded (consistent with current nodus design)

### Flutter Integration

The Flutter app communicates with the C library via FFI. TCP operations are invisible to Flutter — they happen inside the C engine.

- **No new FFI bindings needed** for basic TCP channel operations — existing `dna_engine_channel_*` functions are reused
- **New event types:** `DNA_EVENT_TCP_CONNECTED`, `DNA_EVENT_TCP_DISCONNECTED` → propagated to Flutter via existing event callback
- **Connection status:** New provider in Flutter to show nodus connection state in UI

---

## Implementation Phases

### Phase 1: TCP Foundation

**Goal:** Nodus accepts TCP connections, clients can authenticate.

**What exists:**
- Dilithium5 sign/verify: `qgp_dsa87_sign()` / `qgp_dsa87_verify()` — ready
- SHA3-512 fingerprints: `qgp_sha3_512_fingerprint()` — ready
- Secure random: `qgp_platform_random()` — ready (all platforms)
- Struct packing: `PACK_STRUCT_BEGIN/END` — ready
- Nodus process: `dhtcnode.c` — running on 3 servers

**What must be built:**
- [ ] Wire protocol frame parser (10-byte header, length-prefixed)
- [ ] TCP server in nodus (epoll, port 4001)
- [ ] 3-way Dilithium5 authentication (server side)
- [ ] TCP client in C library (cross-platform socket abstraction)
- [ ] 3-way Dilithium5 authentication (client side)
- [ ] Platform socket helpers in `qgp_platform_*.c`

**Deliverable:** Client can TCP connect to nodus and authenticate. PING/PONG keepalive works.

### Phase 2: Channel Operations over TCP

**Goal:** Basic channel CRUD and post operations work over TCP.

**What exists:**
- Channel data structures: `dna_channel_info_t`, `dna_channel_post_info_t` — ready
- Channel engine module: `dna_engine_channels.c` — 9 task handlers (DHT-based)
- Channel subscriptions DB: `channel_subscriptions_db.c` — ready
- Engine task system: `dna_submit_task()` — ready

**What must be built:**
- [ ] CREATE_CHANNEL handler on nodus (creates SQLite table)
- [ ] POST handler on nodus (assign seq_id, store, ACK)
- [ ] GET_POSTS handler on nodus (query by since_seq_id)
- [ ] SUBSCRIBE / UNSUBSCRIBE + in-memory subscriber list
- [ ] POST_NOTIFY push to subscribed clients
- [ ] Client-side SQLite cache for TCP posts (`tcp_channel_cache.c`)
- [ ] New engine module: `dna_engine_tcp_channels.c` (or extend existing)
- [ ] Consistent hash ring computation

**Deliverable:** Single nodus serves channel posts over TCP. No replication yet (single point of failure).

### Phase 3: Replication and Failover

**Goal:** Channel data replicated across 3 nodus. Client-driven failover works.

**What exists:**
- Thread pool: `threadpool.h` — ready for async replication
- SQLite patterns: Multiple DB files per identity — established

**What must be built:**
- [ ] Inter-nodus TCP mesh (persistent connections)
- [ ] Nodus-to-nodus authentication (Dilithium5 keys)
- [ ] REPLICATE_POST / REPLICATE_ACK handlers
- [ ] Hinted handoff queue (SQLite table)
- [ ] SYNC_REQUEST / SYNC_DATA for full channel transfer
- [ ] Client-side failover: try Primary → B1 → B2
- [ ] Nodus DHT registry publishing

**Deliverable:** 3-way replication works. Client survives single nodus failure.

### Phase 4: PBFT Consensus

**Goal:** Ring membership changes are BFT-safe. No split brain.

**What must be built:**
- [ ] PBFT state machine (PRE-PREPARE, PREPARE, COMMIT, VIEW_CHANGE)
- [ ] CONSENSUS_MSG handler
- [ ] Heartbeat/suspect/dead detection state machine
- [ ] Ring versioning and RING_UPDATE distribution to clients
- [ ] Channel transfer on ring change (automatic rebalancing)
- [ ] Consensus interface abstraction (`consensus_interface_t`)

**Deliverable:** Nodus join/leave is consensus-driven. Split brain impossible.

### Phase 5: Migration from DHT-Only Channels

**Goal:** Smooth transition from current DHT channel system.

**What exists:**
- DHT channels: Fully working daily-bucket system
- Channel metadata on DHT: discovery, browsing — stays unchanged

**Migration strategy:**
- [ ] Dual-mode period: DHT channels continue working alongside TCP channels
- [ ] New channels default to TCP hosting
- [ ] Existing channels: read from both DHT and TCP, prefer TCP if available
- [ ] Migration tool: bulk-import DHT channel posts to TCP (one-time)
- [ ] Deprecation: after migration period, DHT post storage removed
- [ ] Channel metadata (name, description, discovery) remains on DHT permanently

**Deliverable:** All channels served via TCP. DHT used only for metadata/discovery.

---

## Summary of Decisions

| # | Decision | Choice |
|---|----------|--------|
| 1 | Sharding | Consistent hash ring (SHA3-256) |
| 2 | Replication | Factor 3 (1 Primary + 2 Backup), async |
| 3 | Discovery | Client-side hash computation |
| 4 | Nodus registry | DHT ("I'm here", 7-day TTL) |
| 5 | Failover | Client-driven, ring order |
| 6 | Membership consensus | PBFT (interface-abstracted, swappable) |
| 7 | Wire format | Binary, 10-byte header |
| 8 | Max frame | 100KB |
| 9 | Protocol version | 1 byte (starts 0x01) |
| 10 | Ring version | 4 bytes (uint32) |
| 11 | Authentication | 3-way Dilithium5 challenge-response, mandatory |
| 12 | Nodus identity | Dilithium5 keypair per nodus |
| 13 | Replication data | Full post + metadata + signature |
| 14 | Storage | SQLite, per-channel table |
| 15 | Retention | 7 days (based on received_at) |
| 16 | Timestamps | Two: author timestamp (UX) + received_at (system) |
| 17 | Post ordering | Sequential ID (uint32, per-channel) |
| 18 | Client sync | GET_POSTS since last seq_id |
| 19 | Client cache | Local SQLite mirror |
| 20 | Channel transfer | SQLite table dump (chunked SYNC_DATA) |
| 21 | Channel creation | Anyone can create |
| 22 | Post permissions | Anyone can post (no enforcement in v1) |
| 23 | Channel metadata | DHT (discovery), TCP (data) |

---

## Open / Deferred

**Resolved in this document:**
- [x] Detailed PBFT message format for ring consensus (see CONSENSUS_MSG payload)
- [x] Nodus TCP port number → **4001** (adjacent to DHT UDP 4000)

**Still open:**
- [ ] Rate limiting / DoS protection on nodus TCP (beyond 100KB max frame)
- [ ] Channel moderation / admin controls
- [ ] Post permissions (owner-only, whitelist)
- [ ] Encryption of channel data at rest on nodus
- [ ] Maximum channels per nodus capacity planning
- [ ] Nodus incentive model (why run a nodus?)
- [ ] Migration timeline from current DHT-only channels
- [ ] TLS encryption for TCP connections (optional — posts are already signed)
- [ ] Client connection pooling (one TCP connection per nodus vs per channel)
- [ ] Nodus load balancing for popular channels
