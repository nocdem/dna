# Nodus v5 - Comprehensive Audit Documentation

**Version:** 0.5.0
**Language:** Pure C (C11 standard)
**Audit Date:** 2026-03-01
**Audit Depth:** Exhaustive (all source files verified)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Structure](#2-project-structure)
3. [Public API](#3-public-api)
4. [Server Architecture](#4-server-architecture)
5. [Client SDK](#5-client-sdk)
6. [Protocol Details](#6-protocol-details)
7. [Build System](#7-build-system)
8. [Tests](#8-tests)
9. [Security](#9-security)
10. [Configuration & Deployment](#10-configuration--deployment)
11. [Known Issues & Limitations](#11-known-issues--limitations)

---

## 1. Executive Summary

Nodus v5 is a complete, production-deployed DHT (Distributed Hash Table) implementation in pure C. It replaces OpenDHT-PQ (C++ library) with a lightweight, post-quantum-first design using Dilithium5 (ML-DSA-87) for authentication and SHA3-512 for addressing.

| Metric | Value |
|--------|-------|
| Total source lines | 14,717 |
| Public header lines | 751 |
| Core modules | 9 |
| Test binaries | 14 |
| Test functions | 100+ |
| Status | Stable, ASAN-clean, production-deployed |

---

## 2. Project Structure

```
/opt/dna/nodus/
├── include/nodus/
│   ├── nodus.h                    [406 lines] Public client SDK API
│   └── nodus_types.h              [345 lines] All types, constants, enums
├── src/
│   ├── core/
│   │   ├── nodus_value.c/h        DHT value creation, signing, serialization
│   │   ├── nodus_routing.c/h      Kademlia routing table (512 k-buckets)
│   │   └── nodus_storage.c/h      SQLite persistent storage with TTL
│   ├── protocol/
│   │   ├── nodus_cbor.c/h         Custom minimal CBOR encoder/decoder
│   │   ├── nodus_wire.c/h         Wire frame: 7-byte header ("ND" + len)
│   │   ├── nodus_tier1.c/h        Nodus-Nodus protocol (Kademlia ops)
│   │   ├── nodus_tier2.c/h        Client-Nodus protocol (DHT + channels)
│   │   └── nodus_tier3.c/h        Witness BFT protocol (CBOR encoding)
│   ├── transport/
│   │   ├── nodus_tcp.c/h          Non-blocking TCP (epoll, frame buffering)
│   │   └── nodus_udp.c/h          UDP (Kademlia heartbeats)
│   ├── crypto/
│   │   ├── nodus_identity.c/h     Dilithium5 keypair generation & loading
│   │   └── nodus_sign.c/h         Sign/verify/hash wrappers
│   ├── channel/
│   │   ├── nodus_hashring.c/h     Consistent hash ring for sharding
│   │   ├── nodus_channel_store.c/h SQLite per-channel storage
│   │   └── nodus_replication.c/h  Cross-node replication + hinted handoff
│   ├── consensus/
│   │   └── nodus_pbft.c/h         PBFT cluster membership & leader election
│   ├── server/
│   │   ├── nodus_server.c         [986 lines] Main event loop, routing
│   │   └── nodus_auth.c           Challenge-response authentication
│   ├── witness/
│   │   ├── nodus_witness.c        [314 lines] Witness lifecycle
│   │   ├── nodus_witness_bft.c    [1046 lines] BFT consensus state machine
│   │   ├── nodus_witness_db.c     [666 lines] Witness-specific SQLite ops
│   │   ├── nodus_witness_handlers.c [914 lines] DNAC client handlers
│   │   └── nodus_witness_peer.c   [765 lines] Witness peer connections
│   ├── client/
│   │   ├── nodus_client.c         [1354 lines] Client SDK
│   │   ├── nodus_singleton.c      Global client instance
│   │   └── nodus_republish.c      Value republish on expiry
│   └── nodus_log_shim.c           Logging wrapper (standalone only)
├── tests/                         14 test binaries
├── tools/
│   ├── nodus-cli.c                [349 lines] CLI tool
│   └── nodus-server.c             [300 lines] Server entry point
├── deploy/                        systemd, config, build script
├── docs/                          Architecture documentation
└── CMakeLists.txt                 [231 lines] Build configuration
```

### Line Count by Module

| Module | Source Lines | Headers | Total | Purpose |
|--------|-------------|---------|-------|---------|
| core | 687 | 503 | 1,190 | DHT storage, routing, values |
| protocol | 2,868 | 525 | 3,393 | CBOR, wire, Tier 1/2/3 messages |
| transport | 678 | 227 | 905 | TCP (epoll), UDP |
| crypto | 342 | 130 | 472 | Dilithium5, SHA3-512 |
| channel | 824 | 360 | 1,184 | Hash ring, channels, replication |
| consensus | 229 | 133 | 362 | PBFT membership |
| server | 1,242 | 151 | 1,393 | Event loop, session mgmt |
| witness | 3,705 | 678 | 4,383 | DNAC BFT consensus |
| client | 1,536 | 22 | 1,558 | Client SDK |
| **Total** | **12,153** | **2,729** | **14,882** | |

---

## 3. Public API

### nodus.h: Client SDK (406 lines, 37 public functions)

#### Lifecycle (5 functions)

```c
int nodus_client_init(nodus_client_t *client,
                      const nodus_client_config_t *config,
                      const nodus_identity_t *identity);
int nodus_client_connect(nodus_client_t *client);
void nodus_client_close(nodus_client_t *client);
int nodus_client_poll(nodus_client_t *client, int timeout_ms);
bool nodus_client_is_ready(nodus_client_t *client);
nodus_client_state_t nodus_client_state(nodus_client_t *client);
```

#### DHT Operations (7 functions)

```c
int nodus_client_put(nodus_client_t *client, const nodus_key_t *key,
                     const uint8_t *data, size_t len,
                     nodus_value_type_t type, uint32_t ttl,
                     uint64_t vid, uint64_t seq, const nodus_sig_t *sig);
int nodus_client_get(nodus_client_t *client, const nodus_key_t *key,
                     nodus_value_t *val_out);
int nodus_client_get_all(nodus_client_t *client, const nodus_key_t *key,
                         nodus_value_t **vals_out, int *count_out);
int nodus_client_listen(nodus_client_t *client, const nodus_key_t *key);
int nodus_client_unlisten(nodus_client_t *client, const nodus_key_t *key);
int nodus_client_get_servers(nodus_client_t *client,
                             nodus_server_endpoint_t *endpoints,
                             int max, int *count);
const char *nodus_client_fingerprint(nodus_client_t *client);
```

#### Channel Operations (8 functions)

```c
int nodus_client_ch_create(nodus_client_t *client, const uint8_t uuid[16]);
int nodus_client_ch_post(nodus_client_t *client, const uint8_t ch_uuid[16],
                         const uint8_t post_uuid[16], const char *body,
                         uint64_t timestamp, const nodus_sig_t *sig,
                         uint32_t *seq_out);
int nodus_client_ch_get_posts(nodus_client_t *client, const uint8_t uuid[16],
                              uint32_t since_seq, int max_count,
                              nodus_channel_post_t **posts_out, int *count_out);
int nodus_client_ch_subscribe(nodus_client_t *client, const uint8_t uuid[16]);
int nodus_client_ch_unsubscribe(nodus_client_t *client, const uint8_t uuid[16]);
void nodus_client_free_posts(nodus_channel_post_t *posts, int count);
```

#### DNAC Operations (7 functions)

```c
int nodus_client_dnac_spend(nodus_client_t *client,
                            const uint8_t tx_hash[64],
                            const uint8_t *tx_data, size_t tx_len,
                            const nodus_pubkey_t *pk, const nodus_sig_t *sig,
                            uint64_t fee, nodus_dnac_result_t *result);
int nodus_client_dnac_nullifier(nodus_client_t *client,
                                const uint8_t nullifier[64],
                                nodus_dnac_result_t *result);
int nodus_client_dnac_ledger(nodus_client_t *client,
                             const uint8_t tx_hash[64],
                             nodus_dnac_result_t *result);
int nodus_client_dnac_supply(nodus_client_t *client,
                             nodus_dnac_result_t *result);
int nodus_client_dnac_utxo(nodus_client_t *client,
                           const uint8_t *owner, int max_results,
                           nodus_dnac_result_t *result);
int nodus_client_dnac_ledger_range(nodus_client_t *client,
                                    uint64_t from_seq, uint64_t to_seq,
                                    nodus_dnac_result_t *result);
int nodus_client_dnac_roster(nodus_client_t *client,
                             nodus_dnac_result_t *result);
```

#### Callbacks (3 types)

```c
typedef void (*nodus_on_value_changed_fn)(const nodus_key_t *key,
                                           const nodus_value_t *val,
                                           void *user_data);
typedef void (*nodus_on_ch_post_fn)(const uint8_t uuid[16],
                                     const nodus_channel_post_t *post,
                                     void *user_data);
typedef void (*nodus_on_state_change_fn)(nodus_client_state_t old,
                                          nodus_client_state_t new,
                                          void *user_data);
```

### nodus_types.h: Constants and Types (345 lines)

#### Protocol Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| NODUS_VERSION_MAJOR | 0 | Protocol version |
| NODUS_VERSION_MINOR | 5 | Protocol version |
| NODUS_VERSION_PATCH | 0 | Protocol version |
| NODUS_FRAME_MAGIC | 0x4E44 ("ND") | Wire frame magic |
| NODUS_KEY_BYTES | 64 | SHA3-512 key size |
| NODUS_KEYSPACE_BITS | 512 | Kademlia key space |
| NODUS_K | 8 | Bucket size (Kademlia) |
| NODUS_R | 3 | Replication factor |
| NODUS_BUCKETS | 512 | Routing table buckets |
| NODUS_ALPHA | 3 | Parallel lookups |
| NODUS_PK_BYTES | 2592 | Dilithium5 public key |
| NODUS_SK_BYTES | 4896 | Dilithium5 secret key |
| NODUS_SIG_BYTES | 4627 | Dilithium5 signature |
| NODUS_DEFAULT_TTL | 604800 | 7 days (seconds) |
| NODUS_MAX_VALUE_SIZE | 1 MB | Per-value payload |
| NODUS_MAX_POST_BODY | 4000 | Channel post body |
| NODUS_CHANNEL_RETENTION | 604800 | 7 days |
| NODUS_PBFT_HEARTBEAT_SEC | 10 | Cluster heartbeat |
| NODUS_PBFT_SUSPECT_SEC | 30 | Node suspect timeout |

#### Core Types

```c
typedef struct { uint8_t bytes[64]; } nodus_key_t;         // 512-bit SHA3-512 key
typedef struct { uint8_t bytes[2592]; } nodus_pubkey_t;    // Dilithium5 public key
typedef struct { uint8_t bytes[4896]; } nodus_seckey_t;    // Dilithium5 secret key
typedef struct { uint8_t bytes[4627]; } nodus_sig_t;       // Dilithium5 signature

typedef struct {
    nodus_pubkey_t pk;
    nodus_seckey_t sk;
    nodus_key_t node_id;        // SHA3-512(pk)
    char fingerprint[129];      // Hex string
} nodus_identity_t;

typedef struct {
    nodus_key_t key_hash;
    uint64_t value_id;
    uint8_t *data;              // Heap-allocated payload
    size_t data_len;
    nodus_value_type_t type;    // EPHEMERAL or PERMANENT
    uint32_t ttl;
    uint64_t created_at, expires_at, seq;
    nodus_pubkey_t owner_pk;
    nodus_key_t owner_fp;
    nodus_sig_t signature;
} nodus_value_t;

typedef struct {
    nodus_key_t node_id;
    char ip[64];
    uint16_t udp_port, tcp_port;
    uint64_t last_seen;
} nodus_peer_t;

typedef struct {
    uint8_t channel_uuid[16];
    uint32_t seq_id;
    uint8_t post_uuid[16];
    nodus_key_t author_fp;
    uint64_t timestamp, received_at;
    char *body;
    size_t body_len;
    nodus_sig_t signature;
} nodus_channel_post_t;
```

#### Enums

| Enum | Values | Purpose |
|------|--------|---------|
| nodus_client_state_t | DISCONNECTED, CONNECTING, AUTHENTICATING, READY, RECONNECTING | Client FSM |
| nodus_value_type_t | EPHEMERAL (0x01), PERMANENT (0x02) | Value expiry |
| nodus_msg_type_t | QUERY ('q'), RESPONSE ('r'), ERROR ('e') | Message kind |
| nodus_error_t | 1-13 codes | Error conditions |
| nodus_pbft_phase_t | PRE_PREPARE, PREPARE, COMMIT, VIEW_CHANGE | PBFT phases |
| nodus_dnac_status_t | APPROVED, REJECTED, ERROR | Witness verdict |

---

## 4. Server Architecture

### Event Loop (nodus_server.c, 986 lines)

Single-threaded epoll-based event loop handling UDP + TCP simultaneously.

**Session State (per connection, 1000 max):**
```c
typedef struct {
    nodus_tcp_conn_t *conn;
    nodus_key_t client_fp;          // Client fingerprint (64 bytes)
    nodus_pubkey_t client_pk;       // Client public key (2592 bytes)
    uint8_t token[32];              // Session token
    bool authenticated;
    bool is_nodus;                  // true=peer, false=client
    uint8_t nonce[32];              // Auth challenge
    nodus_key_t listen_keys[128];   // Subscriptions
    int listen_count;
    uint8_t ch_subs[32][16];        // Channel subscriptions
    int ch_sub_count;
    uint64_t rate_window_start;
    int puts_in_window;             // Rate limiting (60 per minute)
} nodus_session_t;
```

**Request Handlers:**

| Handler | Protocol | Purpose |
|---------|----------|---------|
| HELLO | T2 | Client sends identity, server returns challenge nonce |
| AUTH | T2 | Client signs nonce, server validates, creates session token |
| PUT | T2 | Store value, verify signature, rate limit, replicate to backup |
| GET | T2 | Retrieve best value (highest seq) |
| GET_ALL | T2 | Return all versions by owner |
| LISTEN | T2 | Add key to session's subscription list |
| UNLISTEN | T2 | Remove subscription |
| PING/PONG | T1 UDP | Kademlia heartbeat for PBFT health |
| FIND_NODE | T1 UDP | Kademlia peer discovery |
| STORE_VALUE | T1 TCP | Receive replicated value from peer |
| CH_CREATE | T2 | Create channel table |
| CH_POST | T2 | Insert post, assign seq_id, replicate |
| CH_GET_POSTS | T2 | Fetch posts after seq_id |
| CH_SUBSCRIBE | T2 | Add channel to subscriptions |
| DNAC_SPEND | T2 | BFT consensus for transaction |
| DNAC_NULLIFIER/LEDGER/SUPPLY/UTXO/ROSTER | T2 | Query witness DB |

### Kademlia DHT Implementation

**Routing Table:**
- 512 k-buckets (one per bit of 512-bit key space)
- k=8 (max 8 peers per bucket, LRU replacement)
- Bucket index = leading zero bits in XOR(self_id, peer_id)

**Functions (nodus_routing.c, 371 lines):**
```c
void nodus_routing_init(routing_t *rt, const nodus_key_t *self_id);
int nodus_routing_insert(routing_t *rt, const nodus_peer_t *peer);
int nodus_routing_remove(routing_t *rt, const nodus_key_t *peer_id);
int nodus_routing_find_closest(const routing_t *rt, const nodus_key_t *target,
                                nodus_peer_t *results, int max_results);
int nodus_routing_lookup(const routing_t *rt, const nodus_key_t *peer_id,
                         nodus_peer_t *peer_out);
int nodus_routing_count(const routing_t *rt);
int nodus_routing_touch(routing_t *rt, const nodus_key_t *peer_id);
```

### Storage Layer (nodus_storage.c, 316 lines)

SQLite 3 persistent storage with prepared statements and TTL cleanup.

```sql
CREATE TABLE nodus_values (
    key_hash BLOB,           -- 64 bytes (SHA3-512)
    owner_fp BLOB,           -- 64 bytes (owner fingerprint)
    value_id INTEGER,
    data BLOB,               -- Payload (up to 1 MB)
    type INTEGER,            -- EPHEMERAL=1, PERMANENT=2
    ttl INTEGER,
    created_at INTEGER,
    expires_at INTEGER,
    seq INTEGER,
    owner_pk BLOB,           -- 2592 bytes
    signature BLOB,          -- 4627 bytes
    PRIMARY KEY(key_hash, owner_fp, value_id)
);
```

### Consistent Hash Ring (nodus_hashring.c, 152 lines)

Ring positions via SHA3-512. Responsible set = first 3 distinct nodes clockwise:
- Primary (0): Handles writes, assigns seq_id
- Backup 1 (1): Receives replications
- Backup 2 (2): Receives replications

### PBFT Consensus (nodus_pbft.c, 229 lines)

Simplified PBFT for 3-node clusters:
- Leader election: Deterministic (lowest node_id)
- Heartbeat: PING every 10s over UDP
- Failure detection: SUSPECT after 30s, DEAD after 60s
- View change: Automatic on leader failure

---

## 5. Client SDK

### nodus_client.c (1,354 lines)

**State Machine:**
```
DISCONNECTED -> CONNECTING -> AUTHENTICATING -> READY
    ^                                           |
    +--------- RECONNECTING <-------------------+
```

**Reconnect Strategy:**
- Initial timeout: 5s (configurable)
- Backoff: 1s to 30s (exponential, capped)
- Server failover: Try next server on failure
- Auto re-subscribe all listeners on reconnect

**Authentication Flow:**
1. Send HELLO(identity.pk, identity.fingerprint)
2. Receive CHALLENGE(nonce)
3. Send AUTH(signature over nonce)
4. Receive AUTH_OK(session_token)
5. State -> READY

**Configuration:**
```c
typedef struct {
    nodus_server_endpoint_t servers[8];     // Up to 8 servers
    int server_count;
    int connect_timeout_ms;                 // Default 5000
    int request_timeout_ms;                 // Default 10000
    bool auto_reconnect;                    // Default true
    int reconnect_min_ms;                   // Default 1000
    int reconnect_max_ms;                   // Default 30000
    nodus_on_value_changed_fn on_value_changed;
    nodus_on_ch_post_fn on_ch_post;
    nodus_on_state_change_fn on_state_change;
    void *callback_data;
} nodus_client_config_t;
```

---

## 6. Protocol Details

### Wire Frame Format (7-byte header)

```
+----------+---------+--------------------+
| Magic(2) | Ver(1)  | Payload Len(4 LE)  |
| "ND"     | 0x01    | uint32_t           |
+----------+---------+--------------------+
| CBOR Payload (variable)                 |
+-----------------------------------------+
```

- Max payload: 1,400 bytes (UDP safe MTU), 4 MB (TCP)

### Custom CBOR Codec (623 lines)

Minimal RFC 8949 subset: unsigned ints, byte strings, text strings, arrays, maps, bools, null. No floats, tags, or indefinite-length.

### Tier 1: Nodus-Nodus Protocol (382 lines)

| Message | Transport | Purpose |
|---------|-----------|---------|
| ping/pong | UDP | Kademlia heartbeat |
| find_node/nodes_found | UDP | Peer discovery |
| store_value/store_ack | TCP | Replication |
| find_value/value_found | TCP | Remote lookup |
| subscribe/unsubscribe | TCP | Inter-node listen |
| notify | TCP | Push value changes |

### Tier 2: Client-Nodus Protocol (922 lines)

Authentication: hello -> challenge -> auth -> auth_ok

DHT Operations: put, get, get_all, listen, unlisten, ping/pong

Channel Operations: ch_create, ch_post, ch_get_posts, ch_subscribe, ch_unsubscribe

Push: value_changed (async), ch_ntf (async)

Server Gossip: servers -> servers_result

### Tier 3: Witness BFT Protocol (1,131 lines)

BFT Phases: IDLE -> PROPOSE -> PREVOTE -> PRECOMMIT -> COMMIT

Messages: w_ident, w_propose, w_prevote, w_precommit, w_commit, w_viewchg

DNAC queries: dnac_nullifier, dnac_ledger, dnac_supply, dnac_utxo, dnac_ledger_range, dnac_roster

---

## 7. Build System

### CMakeLists.txt (231 lines)

```cmake
cmake_minimum_required(VERSION 3.16)
project(nodus VERSION 0.5.0 LANGUAGES C)
set(CMAKE_C_STANDARD 11)
```

**Dependencies:** OpenSSL, SQLite3, json-c (optional), shared/crypto (DSA, KEM)

**Compiler Flags:** `-Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2`

**Targets:**
- nodus_lib (STATIC)
- 14 test binaries (test_cbor, test_wire, test_value, etc.)
- nodus-cli (CLI tool)
- nodus-server (server binary)

**Build Modes:**
- Release (default): Optimized
- Debug: ASAN enabled

**Build Commands:**
```bash
cd nodus/build && cmake .. && make -j$(nproc)
# Tests:
ctest
```

---

## 8. Tests

### 14 Test Binaries (4,646 test lines)

| Test | Lines | Coverage |
|------|-------|----------|
| test_cbor | 406 | CBOR encoder/decoder, edge cases |
| test_wire | 173 | Frame header parsing |
| test_value | 248 | Create, sign, verify, serialize |
| test_identity | 266 | Seed derivation, save/load |
| test_routing | 224 | Insert, remove, find_closest |
| test_storage | 262 | Put, get, get_all, cleanup |
| test_hashring | 212 | Add, remove, responsible_set |
| test_tcp | 234 | Connect, disconnect, frame I/O |
| test_tier1 | 193 | Encode/decode all T1 messages |
| test_tier2 | 246 | Encode/decode auth + DHT |
| test_tier3 | 709 | BFT consensus state machine |
| test_channel_store | 233 | Channel post, seq_id, retention |
| test_server | 714 | 3-node cluster, auth, PUT/GET |
| test_client | 426 | Connect, auth, sync/async ops |

### Integration Test (integration_test.sh)

10 scenarios on 3-node production cluster:
1. Bootstrap & Service Health
2. Local Ping
3. Local PUT/GET
4. PBFT Ring Formation
5. Cross-Node Replication
6. Bi-directional Replication
7. Multi-Writer (same key)
8. Large Value (4KB)
9. Failover
10. Rejoin

---

## 9. Security

### Cryptography

| Purpose | Algorithm | Key Size |
|---------|-----------|----------|
| Authentication | Dilithium5 (ML-DSA-87) | pk=2592B, sk=4896B, sig=4627B |
| Hashing | SHA3-512 | 64 bytes |
| Session tokens | Random | 32 bytes |

### Rate Limiting

- PUTs: 60 per minute per session
- Listeners: 128 per session
- Channel subscriptions: 32 per session
- Max connections: 1,000 per server

### Error Codes

| Code | Name | Meaning |
|------|------|---------|
| 1 | NOT_AUTHENTICATED | No valid session token |
| 2 | NOT_FOUND | Key not in storage |
| 3 | INVALID_SIGNATURE | Signature verification failed |
| 4 | RATE_LIMITED | Too many PUTs |
| 5 | TOO_LARGE | Value > 1 MB |
| 6 | TIMEOUT | Request timed out |
| 7 | PROTOCOL_ERROR | Invalid message format |
| 8 | INTERNAL_ERROR | Server error |
| 9 | ALREADY_EXISTS | Duplicate channel/post |
| 10 | CHANNEL_NOT_FOUND | No such channel |
| 11 | NOT_RESPONSIBLE | Wrong node for key |
| 12 | RING_MISMATCH | Hash ring changed |
| 13 | DOUBLE_SPEND | DNAC nullifier already spent |

### Memory Safety

- All 14 unit tests pass under ASAN
- Heap-use-after-free fixed (commit 78c0989b)
- All heap allocations have corresponding free calls
- SQLite prepared statements closed on db_close

### Deployment Hardening (systemd)

```ini
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/nodus
```

---

## 10. Configuration & Deployment

### Server Config (JSON)

```json
{
    "bind_ip": "0.0.0.0",
    "udp_port": 4000,
    "tcp_port": 4001,
    "identity_path": "/var/lib/nodus/identity",
    "data_path": "/var/lib/nodus/data",
    "seed_nodes": [
        "161.97.85.25:4000",
        "156.67.24.125:4000",
        "156.67.25.251:4000"
    ]
}
```

### Test Cluster (Running v0.5.0)

| Node | IP | UDP | TCP |
|------|-----|-----|-----|
| nodus-01 | 161.97.85.25 | 4000 | 4001 |
| nodus-02 | 156.67.24.125 | 4000 | 4001 |
| nodus-03 | 156.67.25.251 | 4000 | 4001 |

---

## 11. Known Issues & Limitations

### Intentional Limitations

- **IPv6:** Not supported (IPv4 only)
- **TLS/encryption:** Not implemented (relies on post-quantum signatures for auth)
- **Access control:** No ACLs (DHT is open; clients authenticate only)
- **Sharding keyspace:** Not implemented (all values stored on all nodes)

### Quality Assessment

| Aspect | Rating | Evidence |
|--------|--------|---------|
| Stability | EXCELLENT | ASAN-clean, 14 test binaries pass |
| Protocol | COMPLETE | 3 protocol tiers fully implemented |
| Security | STRONG | Post-quantum auth, rate limiting |
| Documentation | GOOD | Architecture doc + inline comments |
| Deployment | PRODUCTION | Running 3-node cluster |
