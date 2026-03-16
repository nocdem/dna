# Channel System Rewrite — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Rewrite the Nodus channel subsystem so all channel traffic (client + replication) runs over TCP 4003 with PRIMARY/BACKUP roles, replacing the broken cross-node replication.

**Architecture:** Each channel has 3 responsible nodes (hashring). Node [0] is PRIMARY (accepts clients, replicates to backups). Nodes [1-2] are BACKUPs (store replicated data). Dead detection via TCP 4003 heartbeat, not PBFT. Hashring is always authoritative.

**Tech Stack:** C (pure, no C++), SQLite, CBOR wire protocol, Dilithium5 signatures, epoll TCP

**Design Doc:** `/opt/dna/nodus/docs/CHANNEL_REWRITE_DESIGN.md`

---

## Critical Rules

1. **PBFT has NOTHING to do with channels** — never reference PBFT for dead detection
2. **Hashring always wins** — deterministic, no election
3. **Push first, replicate after** — user experience before data safety
4. **No DHT PUT/GET for posts** — all post traffic over TCP 4003
5. **Metadata stays on DHT** — channel name/description/creator/is_public
6. **Node discovery stays on DHT** — `dna:channel:nodes:<uuid>` with ordered list

## Key Files Reference

**Keep unchanged:**
- `nodus/src/channel/nodus_channel_store.c/h` — SQLite per-channel tables (465/159 lines)
- `nodus/src/channel/nodus_hashring.c/h` — Consistent hashring (153/110 lines)

**Delete entirely:**
- `nodus/src/channel/nodus_replication.c/h` — Old 4002 replication (212/73 lines)
- `nodus/src/channel/nodus_ring_mgmt.c/h` — Old PBFT-based ring mgmt (530/97 lines)

**Create new:**
- `nodus/src/channel/nodus_channel_server.c/h` — TCP 4003 event loop, sessions, auth
- `nodus/src/channel/nodus_channel_primary.c/h` — PRIMARY role logic
- `nodus/src/channel/nodus_channel_replication.c/h` — Replication + hinted handoff + sync
- `nodus/src/channel/nodus_channel_ring.c/h` — Ring management via heartbeat

**Modify:**
- `nodus/src/server/nodus_server.c` — Remove old channel handlers, integrate new modules
- `nodus/src/protocol/nodus_tier2.c/h` — Add new protocol messages
- `nodus/CMakeLists.txt` — Update source list
- `messenger/dht/shared/nodus_ops.c` — Update connection strategy

## Existing Types (reuse as-is)

```c
// nodus_types.h — keep these
nodus_channel_post_t    // post_uuid, author_fp, timestamp, received_at, body, signature
nodus_key_t             // 64-byte SHA3-512
nodus_sig_t             // 4627-byte Dilithium5
nodus_pubkey_t          // 2592-byte Dilithium5

// nodus_hashring.h — keep these
nodus_ring_member_t     // node_id, ip, tcp_port
nodus_responsible_set_t // nodes[3], count
nodus_hashring_t        // members[], count, version, sorted

// nodus_channel_store.h — keep these
nodus_channel_store_t   // SQLite db + prepared statements
nodus_hinted_entry_t    // target_fp, channel_uuid, post_data, retry_count, expires_at
```

## Existing Test Pattern

Tests use this pattern (from `nodus/tests/test_channel_store.c`):
```c
static int tests_run = 0;
static int tests_passed = 0;
#define TEST(name) do { tests_run++; printf("  [%d] %-45s ", tests_run, name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while (0)

int main(void) {
    // run tests...
    printf("\n  %d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
```

---

## Task 1: Add New Protocol Messages to Tier 2

**Files:**
- Modify: `nodus/include/nodus/nodus_tier2.h`
- Modify: `nodus/src/protocol/nodus_tier2.c`
- Test: `nodus/tests/test_channel_protocol.c` (create)

**Context:** The tier2 protocol layer already has channel messages (ch_post, ch_get, ch_replicate, ring_check, ring_ack, ring_evict, ch_ring_changed). We need to add new messages for the rewrite: `ch_node_hello`, `ch_node_auth`, `ch_heartbeat`, `ch_sync_request`, `ch_sync_response`, `ch_ring_rejoin`. Keep all existing messages that still apply.

**Step 1: Write failing test for new protocol encode/decode**

Create `nodus/tests/test_channel_protocol.c`:
```c
/**
 * Nodus — Channel Protocol Message Tests
 *
 * Tests encode/decode round-trip for new channel protocol messages.
 */
#include "protocol/nodus_tier2.h"
#include "nodus/nodus_types.h"
#include <stdio.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;
#define TEST(name) do { tests_run++; printf("  [%d] %-45s ", tests_run, name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while (0)

static void test_ch_node_hello_encode(void) {
    TEST("ch_node_hello encode");
    uint8_t buf[8192];
    size_t len = 0;
    nodus_pubkey_t pk;
    nodus_key_t fp;
    memset(pk.bytes, 0xAA, NODUS_PK_BYTES);
    memset(fp.bytes, 0xBB, NODUS_KEY_BYTES);
    uint32_t ring_version = 5;

    int rc = nodus_t2_ch_node_hello(1, &pk, &fp, ring_version, buf, sizeof(buf), &len);
    if (rc != 0 || len == 0) { FAIL("encode failed"); return; }
    PASS();
}

static void test_ch_heartbeat_encode(void) {
    TEST("ch_heartbeat encode");
    uint8_t buf[1024];
    size_t len = 0;
    int rc = nodus_t2_ch_heartbeat(1, buf, sizeof(buf), &len);
    if (rc != 0 || len == 0) { FAIL("encode failed"); return; }
    PASS();
}

static void test_ch_sync_request_encode(void) {
    TEST("ch_sync_request encode");
    uint8_t buf[1024];
    size_t len = 0;
    uint8_t uuid[16];
    memset(uuid, 0x11, 16);
    uint64_t since = 1709000000000ULL;  /* 24h ago in ms */
    int rc = nodus_t2_ch_sync_request(1, uuid, since, buf, sizeof(buf), &len);
    if (rc != 0 || len == 0) { FAIL("encode failed"); return; }
    PASS();
}

static void test_ch_ring_rejoin_encode(void) {
    TEST("ch_ring_rejoin encode");
    uint8_t buf[8192];
    size_t len = 0;
    nodus_key_t fp;
    memset(fp.bytes, 0xCC, NODUS_KEY_BYTES);
    int rc = nodus_t2_ch_ring_rejoin(1, &fp, 3, buf, sizeof(buf), &len);
    if (rc != 0 || len == 0) { FAIL("encode failed"); return; }
    PASS();
}

int main(void) {
    printf("test_channel_protocol: Channel protocol message tests\n");
    test_ch_node_hello_encode();
    test_ch_heartbeat_encode();
    test_ch_sync_request_encode();
    test_ch_ring_rejoin_encode();
    printf("\n  %d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
```

**Step 2: Run test to verify it fails**

```bash
cd nodus/build && cmake .. && make -j$(nproc) 2>&1
```
Expected: Compile error — `nodus_t2_ch_node_hello` not declared.

**Step 3: Add protocol function declarations to nodus_tier2.h**

Add after existing channel protocol declarations (around line 178):
```c
/* --- Channel rewrite: node-to-node protocol --- */

/* Node hello (peer auth with ring_version) */
int nodus_t2_ch_node_hello(uint32_t txn,
                            const nodus_pubkey_t *pk,
                            const nodus_key_t *fp,
                            uint32_t ring_version,
                            uint8_t *buf, size_t cap, size_t *out_len);

/* Node auth OK response (includes current ring state) */
int nodus_t2_ch_node_auth_ok(uint32_t txn,
                              const uint8_t *token, size_t token_len,
                              uint32_t current_ring_version,
                              const nodus_ring_member_t *ring_members, int ring_count,
                              uint8_t *buf, size_t cap, size_t *out_len);

/* Heartbeat (periodic liveness) */
int nodus_t2_ch_heartbeat(uint32_t txn,
                           uint8_t *buf, size_t cap, size_t *out_len);

/* Heartbeat ACK */
int nodus_t2_ch_heartbeat_ack(uint32_t txn,
                               uint8_t *buf, size_t cap, size_t *out_len);

/* Sync request (new node asks PRIMARY for recent posts) */
int nodus_t2_ch_sync_request(uint32_t txn,
                              const uint8_t ch_uuid[NODUS_UUID_BYTES],
                              uint64_t since_ms,
                              uint8_t *buf, size_t cap, size_t *out_len);

/* Sync response (PRIMARY sends batch of posts) */
int nodus_t2_ch_sync_response(uint32_t txn,
                               const uint8_t ch_uuid[NODUS_UUID_BYTES],
                               const nodus_channel_post_t *posts, size_t count,
                               uint8_t *buf, size_t cap, size_t *out_len);

/* Ring rejoin (returning node announces itself) */
int nodus_t2_ch_ring_rejoin(uint32_t txn,
                             const nodus_key_t *node_id,
                             uint32_t my_ring_version,
                             uint8_t *buf, size_t cap, size_t *out_len);
```

**Step 4: Implement encode functions in nodus_tier2.c**

Add implementations following the existing CBOR encode pattern used by `nodus_t2_ch_replicate` and others. Each function:
1. Create CBOR encoder
2. Open map
3. Add "method" string
4. Add "txn" uint
5. Add message-specific fields
6. Close map
7. Return encoded length

**Step 5: Run test to verify it passes**

```bash
cd nodus/build && cmake .. && make -j$(nproc) && ./test_channel_protocol
```
Expected: All 4 tests PASS.

**Step 6: Add test to CMakeLists.txt**

Add `test_channel_protocol` following pattern of existing `test_channel_store`.

**Step 7: Run full test suite**

```bash
cd nodus/build && ctest --output-on-failure
```
Expected: All tests pass (existing + new).

**Step 8: Commit**

```bash
git add nodus/src/protocol/nodus_tier2.c nodus/include/nodus/nodus_tier2.h \
       nodus/tests/test_channel_protocol.c nodus/CMakeLists.txt
git commit -m "feat(nodus): Add channel rewrite protocol messages (Nodus vX.Y.Z)"
```

---

## Task 2: Create nodus_channel_server.c/h — TCP 4003 Session Management

**Files:**
- Create: `nodus/src/channel/nodus_channel_server.h`
- Create: `nodus/src/channel/nodus_channel_server.c`
- Test: `nodus/tests/test_channel_server.c` (create)

**Context:** This module owns the TCP 4003 listener, epoll event loop, session management, and auth flow. It replaces the channel handler code currently embedded in `nodus_server.c` (lines 1944-2298). Two session types: client sessions and node sessions.

**Step 1: Write the header file**

Create `nodus/src/channel/nodus_channel_server.h`:
```c
/**
 * Nodus — Channel Server (TCP 4003)
 *
 * Owns the TCP 4003 listener, session management, and auth for both
 * client connections (users) and node connections (inter-node replication).
 */
#ifndef NODUS_CHANNEL_SERVER_H
#define NODUS_CHANNEL_SERVER_H

#include "nodus/nodus_types.h"
#include "transport/nodus_tcp.h"
#include "channel/nodus_channel_store.h"
#include "channel/nodus_hashring.h"

#include <stdbool.h>
#include <stdint.h>

/* --- Constants --- */
#define NODUS_CH_MAX_CLIENT_SESSIONS   1024
#define NODUS_CH_MAX_NODE_SESSIONS     32
#define NODUS_CH_MAX_SUBS_PER_CLIENT   32
#define NODUS_CH_RATE_POSTS_PER_MIN    60
#define NODUS_CH_HEARTBEAT_INTERVAL_SEC 15
#define NODUS_CH_HEARTBEAT_TIMEOUT_SEC  45
#define NODUS_CH_SESSION_TOKEN_LEN     32
#define NODUS_CH_NONCE_LEN             32

/* --- Session Types --- */

typedef enum {
    NODUS_CH_SESS_CLIENT,   /* User connection */
    NODUS_CH_SESS_NODE      /* Inter-node connection */
} nodus_ch_session_type_t;

/* Client session (user → PRIMARY) */
typedef struct {
    nodus_tcp_conn_t       *conn;
    nodus_key_t             client_fp;
    nodus_pubkey_t          client_pk;
    uint8_t                 token[NODUS_CH_SESSION_TOKEN_LEN];
    bool                    authenticated;
    uint8_t                 nonce[NODUS_CH_NONCE_LEN];
    bool                    nonce_pending;

    /* Channel subscriptions */
    uint8_t                 ch_subs[NODUS_CH_MAX_SUBS_PER_CLIENT][NODUS_UUID_BYTES];
    int                     ch_sub_count;

    /* Rate limiting */
    uint32_t                posts_this_minute;
    uint64_t                rate_window_start;
} nodus_ch_client_session_t;

/* Node session (inter-node replication + ring mgmt) */
typedef struct {
    nodus_tcp_conn_t       *conn;
    nodus_key_t             node_id;
    nodus_pubkey_t          node_pk;
    uint8_t                 token[NODUS_CH_SESSION_TOKEN_LEN];
    bool                    authenticated;
    uint8_t                 nonce[NODUS_CH_NONCE_LEN];
    bool                    nonce_pending;
    uint32_t                ring_version;    /* Peer's ring version at hello */

    /* Heartbeat tracking */
    uint64_t                last_heartbeat_recv;
    uint64_t                last_heartbeat_sent;
} nodus_ch_node_session_t;

/* --- Channel Server --- */

typedef struct nodus_channel_server nodus_channel_server_t;

struct nodus_channel_server {
    /* TCP transport (port 4003) */
    nodus_tcp_t             tcp;
    uint16_t                port;

    /* Sessions */
    nodus_ch_client_session_t  clients[NODUS_CH_MAX_CLIENT_SESSIONS];
    nodus_ch_node_session_t    nodes[NODUS_CH_MAX_NODE_SESSIONS];

    /* Shared state (pointers to server-owned objects) */
    nodus_channel_store_t  *ch_store;
    nodus_hashring_t       *ring;
    nodus_key_t            *self_id;        /* This node's identity */
    nodus_pubkey_t         *self_pk;
    void                   *self_sk;        /* For signing */
    char                    self_ip[64];

    /* Callbacks to parent server for DHT operations */
    int (*dht_put)(const uint8_t *key, size_t key_len,
                   const uint8_t *val, size_t val_len,
                   uint32_t ttl, void *ctx);
    int (*dht_get)(const uint8_t *key, size_t key_len,
                   uint8_t **val, size_t *val_len, void *ctx);
    void *dht_ctx;
};

/* --- Public API --- */

/**
 * Initialize channel server. Does NOT start listening yet.
 * ch_store, ring, self_id must be valid for lifetime of server.
 */
int nodus_channel_server_init(nodus_channel_server_t *cs,
                               nodus_channel_store_t *ch_store,
                               nodus_hashring_t *ring,
                               nodus_key_t *self_id,
                               nodus_pubkey_t *self_pk,
                               void *self_sk,
                               const char *bind_ip);

/**
 * Start listening on TCP 4003.
 */
int nodus_channel_server_listen(nodus_channel_server_t *cs, uint16_t port);

/**
 * Poll for TCP events. Call from main loop.
 * timeout_ms: epoll wait timeout.
 */
void nodus_channel_server_poll(nodus_channel_server_t *cs, int timeout_ms);

/**
 * Periodic tick. Call from main loop (e.g. every 1s).
 * Handles: heartbeat send/check, hinted handoff retry.
 */
void nodus_channel_server_tick(nodus_channel_server_t *cs);

/**
 * Shutdown: disconnect all sessions, close listener.
 */
void nodus_channel_server_close(nodus_channel_server_t *cs);

/* --- Session helpers --- */

nodus_ch_client_session_t *nodus_ch_find_client(nodus_channel_server_t *cs,
                                                 nodus_tcp_conn_t *conn);

nodus_ch_node_session_t *nodus_ch_find_node(nodus_channel_server_t *cs,
                                             nodus_tcp_conn_t *conn);

/**
 * Notify all client sessions subscribed to channel_uuid of a new post.
 */
void nodus_ch_notify_subscribers(nodus_channel_server_t *cs,
                                  const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                  const nodus_channel_post_t *post);

/**
 * Send ch_ring_changed to all client sessions subscribed to channel_uuid.
 */
void nodus_ch_notify_ring_changed(nodus_channel_server_t *cs,
                                   const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                   uint32_t new_version);

#endif /* NODUS_CHANNEL_SERVER_H */
```

**Step 2: Write the implementation**

Create `nodus/src/channel/nodus_channel_server.c` implementing:

1. `nodus_channel_server_init` — Zero-init sessions, store pointers
2. `nodus_channel_server_listen` — Init TCP transport, set callbacks, bind
3. `nodus_channel_server_poll` — Wrapper around `nodus_tcp_poll`
4. `on_ch_accept` callback — Find empty session slot
5. `on_ch_disconnect` callback — Clear session, remove presence
6. `on_ch_frame` callback — Decode tier2 message, dispatch:
   - `"hello"` → `handle_client_hello` (verify fp=SHA3(pk), generate nonce)
   - `"auth"` → `handle_client_auth` (verify sig, create token)
   - `"node_hello"` → `handle_node_hello` (verify fp, generate nonce, compare ring_version)
   - `"node_auth"` → `handle_node_auth` (verify sig, send auth_ok with ring state)
   - Authenticated client messages: `ch_create`, `ch_post`, `ch_get`, `ch_sub`, `ch_unsub`
   - Authenticated node messages: `ch_replicate`, `ch_heartbeat`, `ch_sync_request`, `ch_ring_check`, `ch_ring_ack`, `ch_ring_evict`, `ch_ring_rejoin`
7. `nodus_ch_find_client` / `nodus_ch_find_node` — Linear scan by conn pointer
8. `nodus_ch_notify_subscribers` — Iterate client sessions, send ch_post_notify
9. `nodus_ch_notify_ring_changed` — Iterate client sessions, send ch_ring_changed

**Key difference from old code:** `on_ch_frame` detects session type by checking if conn matches a client or node session. First message (`hello` vs `node_hello`) determines type. A connection cannot be both.

**Step 3: Write test**

Create `nodus/tests/test_channel_server.c` — Unit tests for session management:
- Test client session allocation and lookup
- Test node session allocation and lookup
- Test session cleanup on disconnect
- Test subscriber notification targeting

**Step 4: Update CMakeLists.txt**

Add `src/channel/nodus_channel_server.c` to server sources.
Add `test_channel_server` to test list.

**Step 5: Build and run tests**

```bash
cd nodus/build && cmake .. && make -j$(nproc) && ctest --output-on-failure
```

**Step 6: Commit**

```bash
git add nodus/src/channel/nodus_channel_server.c nodus/src/channel/nodus_channel_server.h \
       nodus/tests/test_channel_server.c nodus/CMakeLists.txt
git commit -m "feat(nodus): Add channel server module — TCP 4003 sessions (Nodus vX.Y.Z)"
```

---

## Task 3: Create nodus_channel_primary.c/h — PRIMARY Role Logic

**Files:**
- Create: `nodus/src/channel/nodus_channel_primary.h`
- Create: `nodus/src/channel/nodus_channel_primary.c`
- Test: `nodus/tests/test_channel_primary.c` (create)

**Context:** This module handles all PRIMARY-specific logic: accepting posts, pushing to subscribers, triggering replication, and announcing to DHT. It gets called from channel_server when the message is a client operation.

**Step 1: Write the header file**

```c
#ifndef NODUS_CHANNEL_PRIMARY_H
#define NODUS_CHANNEL_PRIMARY_H

#include "channel/nodus_channel_server.h"

/**
 * Handle ch_post from client.
 * 1. Verify signature
 * 2. Store in SQLite
 * 3. Push to subscribed clients (ch_post_notify)
 * 4. Queue replication to BACKUPs (async)
 */
int nodus_ch_primary_handle_post(nodus_channel_server_t *cs,
                                  nodus_ch_client_session_t *sess,
                                  const nodus_tier2_msg_t *msg);

/**
 * Handle ch_get from client.
 * Return posts since received_at.
 */
int nodus_ch_primary_handle_get(nodus_channel_server_t *cs,
                                 nodus_ch_client_session_t *sess,
                                 const nodus_tier2_msg_t *msg);

/**
 * Handle ch_create from client.
 * Create channel table, track in ring, announce to DHT.
 */
int nodus_ch_primary_handle_create(nodus_channel_server_t *cs,
                                    nodus_ch_client_session_t *sess,
                                    const nodus_tier2_msg_t *msg);

/**
 * Handle ch_sub from client.
 */
int nodus_ch_primary_handle_subscribe(nodus_channel_server_t *cs,
                                       nodus_ch_client_session_t *sess,
                                       const nodus_tier2_msg_t *msg);

/**
 * Handle ch_unsub from client.
 */
int nodus_ch_primary_handle_unsubscribe(nodus_channel_server_t *cs,
                                         nodus_ch_client_session_t *sess,
                                         const nodus_tier2_msg_t *msg);

/**
 * Announce channel's responsible set to DHT (ordered list).
 * Called on ch_create and ring changes.
 * DHT key: SHA3-512("dna:channel:nodes:" + channel_uuid)
 * Value: CBOR {version, nodes: [{ip, port, nid}, ...]} signed
 * Order: [PRIMARY, BACKUP-1, BACKUP-2] (hashring deterministic)
 */
int nodus_ch_primary_announce_to_dht(nodus_channel_server_t *cs,
                                      const uint8_t channel_uuid[NODUS_UUID_BYTES]);

/**
 * Ensure channel table exists locally. Create if we're responsible.
 * Returns true if channel ready, false if not responsible.
 */
bool nodus_ch_primary_ensure_channel(nodus_channel_server_t *cs,
                                      const uint8_t channel_uuid[NODUS_UUID_BYTES]);

#endif /* NODUS_CHANNEL_PRIMARY_H */
```

**Step 2: Implement**

Port logic from existing `nodus_server.c` handlers:
- `handle_ch_t2_ch_post` (line 2069-2147) → `nodus_ch_primary_handle_post`
- `handle_ch_t2_ch_create` (line 2049-2067) → `nodus_ch_primary_handle_create`
- `handle_ch_t2_ch_get_posts` (line 2149-2179) → `nodus_ch_primary_handle_get`
- `handle_ch_t2_ch_subscribe` (line 2181-2209) → `nodus_ch_primary_handle_subscribe`
- `handle_ch_t2_ch_unsubscribe` (line 2211-2222) → `nodus_ch_primary_handle_unsubscribe`
- `nodus_ring_announce_to_dht` (ring_mgmt.c:427-529) → `nodus_ch_primary_announce_to_dht`

**Key change in handle_post:**
```c
int nodus_ch_primary_handle_post(...) {
    // 1. Rate limit check
    // 2. Ensure channel exists
    // 3. Parse post fields from msg
    // 4. Verify Dilithium5 signature
    // 5. Store in SQLite
    // 6. Send ch_post_ok to client
    // 7. Push to ALL subscribed clients (ch_post_notify) ← FIRST
    // 8. Queue replication to BACKUPs ← AFTER (via replication module)
}
```

**Key change in announce_to_dht:**
The node list is written in **hashring order** (deterministic). Position [0] = PRIMARY, [1] = BACKUP-1, [2] = BACKUP-2.

**Step 3: Write test**

Test `nodus_ch_primary_ensure_channel` — channel creation when responsible vs not responsible.
Test DHT announce encodes ordered list correctly.

**Step 4: Build and test**

```bash
cd nodus/build && cmake .. && make -j$(nproc) && ctest --output-on-failure
```

**Step 5: Commit**

```bash
git add nodus/src/channel/nodus_channel_primary.c nodus/src/channel/nodus_channel_primary.h \
       nodus/tests/test_channel_primary.c nodus/CMakeLists.txt
git commit -m "feat(nodus): Add channel PRIMARY role module (Nodus vX.Y.Z)"
```

---

## Task 4: Create nodus_channel_replication.c/h — Replication + Hinted Handoff + Sync

**Files:**
- Create: `nodus/src/channel/nodus_channel_replication.h`
- Create: `nodus/src/channel/nodus_channel_replication.c`
- Test: existing `test_channel_store.c` already tests hinted handoff SQLite; add `nodus/tests/test_channel_replication.c`

**Context:** Replaces old `nodus_replication.c`. All replication over TCP 4003 (not 4002). PRIMARY sends to BACKUP node sessions. Failed sends go to hinted handoff. New nodes do incremental sync (last 1 day).

**Step 1: Write the header**

```c
#ifndef NODUS_CHANNEL_REPLICATION_H
#define NODUS_CHANNEL_REPLICATION_H

#include "channel/nodus_channel_server.h"

/* --- Replication Context --- */
typedef struct {
    nodus_channel_server_t *cs;
    uint64_t                last_retry_ms;
} nodus_ch_replication_t;

/**
 * Initialize replication module.
 */
void nodus_ch_replication_init(nodus_ch_replication_t *rep,
                                nodus_channel_server_t *cs);

/**
 * Replicate a post to BACKUP nodes.
 * Called by PRIMARY after storing post locally and pushing to clients.
 * Sends ch_replicate over TCP 4003 to each BACKUP node session.
 * On failure: queues to hinted handoff.
 */
int nodus_ch_replication_send(nodus_ch_replication_t *rep,
                               const uint8_t channel_uuid[NODUS_UUID_BYTES],
                               const nodus_channel_post_t *post,
                               const nodus_pubkey_t *author_pk);

/**
 * Handle incoming ch_replicate on BACKUP node.
 * Store post locally (dedup by post_uuid).
 * Also notifies local subscribers (BACKUPs don't have clients normally,
 * but may during failover transition).
 */
int nodus_ch_replication_receive(nodus_ch_replication_t *rep,
                                  const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                  const nodus_channel_post_t *post);

/**
 * Retry hinted handoff entries. Call periodically (every 30s).
 */
void nodus_ch_replication_retry(nodus_ch_replication_t *rep);

/**
 * Handle ch_sync_request from new node.
 * Send last 1 day of posts for channel.
 */
int nodus_ch_replication_handle_sync_request(nodus_ch_replication_t *rep,
                                              nodus_ch_node_session_t *sess,
                                              const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                              uint64_t since_ms);

/**
 * Handle ch_sync_response on new node.
 * Store received posts locally.
 */
int nodus_ch_replication_handle_sync_response(nodus_ch_replication_t *rep,
                                               const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                               const nodus_channel_post_t *posts,
                                               size_t count);

#endif /* NODUS_CHANNEL_REPLICATION_H */
```

**Step 2: Implement**

Key differences from old `nodus_replication.c`:
1. **Send via TCP 4003 node sessions** — Find BACKUP node sessions in `cs->nodes[]`, send `ch_replicate` directly. Old code used `send_to_peer()` over TCP 4002.
2. **Hinted handoff unchanged** — Same SQLite table, same 30s retry, 24h TTL. Uses `nodus_channel_store.c` functions (these are kept).
3. **New: sync request/response** — `handle_sync_request` calls `nodus_channel_get_posts(since_ms)` and sends batch via `nodus_t2_ch_sync_response`. `handle_sync_response` calls `nodus_channel_post()` for each (INSERT OR IGNORE).

**Step 3: Write test**

Test replication_receive stores posts correctly (use channel_store directly).
Test sync_response stores batch correctly.
Test hinted handoff integration.

**Step 4: Build and test**

```bash
cd nodus/build && cmake .. && make -j$(nproc) && ctest --output-on-failure
```

**Step 5: Commit**

```bash
git add nodus/src/channel/nodus_channel_replication.c nodus/src/channel/nodus_channel_replication.h \
       nodus/tests/test_channel_replication.c nodus/CMakeLists.txt
git commit -m "feat(nodus): Add channel replication module — TCP 4003 (Nodus vX.Y.Z)"
```

---

## Task 5: Create nodus_channel_ring.c/h — Ring Management via Heartbeat

**Files:**
- Create: `nodus/src/channel/nodus_channel_ring.h`
- Create: `nodus/src/channel/nodus_channel_ring.c`
- Test: `nodus/tests/test_channel_ring.c` (create)

**Context:** Replaces old `nodus_ring_mgmt.c` which used PBFT for dead detection. New module uses TCP 4003 heartbeat between the 3 responsible nodes. NO PBFT dependency anywhere.

**Step 1: Write the header**

```c
#ifndef NODUS_CHANNEL_RING_H
#define NODUS_CHANNEL_RING_H

#include "channel/nodus_channel_server.h"

#define NODUS_CH_RING_MAX_TRACKED    256
#define NODUS_CH_RING_CHECK_TIMEOUT  10   /* seconds */

/* Tracked channel with ring state */
typedef struct {
    uint8_t     channel_uuid[NODUS_UUID_BYTES];
    uint32_t    ring_version;
    bool        active;

    /* Dead detection state */
    bool        check_pending;
    nodus_key_t check_node_id;
    uint64_t    check_sent_at;
} nodus_ch_ring_channel_t;

typedef struct {
    nodus_channel_server_t     *cs;
    nodus_ch_ring_channel_t     channels[NODUS_CH_RING_MAX_TRACKED];
    int                         channel_count;
    uint64_t                    last_tick_ms;
} nodus_ch_ring_t;

/**
 * Initialize ring management.
 */
void nodus_ch_ring_init(nodus_ch_ring_t *rm, nodus_channel_server_t *cs);

/**
 * Track a channel this node is responsible for.
 */
int nodus_ch_ring_track(nodus_ch_ring_t *rm,
                         const uint8_t channel_uuid[NODUS_UUID_BYTES],
                         uint32_t ring_version);

/**
 * Untrack a channel.
 */
void nodus_ch_ring_untrack(nodus_ch_ring_t *rm,
                            const uint8_t channel_uuid[NODUS_UUID_BYTES]);

/**
 * Periodic tick (call every ~5s from main loop).
 * - Check heartbeat timeouts on node sessions
 * - If node session dead for >HEARTBEAT_TIMEOUT:
 *   send ring_check to other responsible node
 * - Handle check timeouts
 */
void nodus_ch_ring_tick(nodus_ch_ring_t *rm);

/**
 * Handle ring_check from peer: "Is node X dead?"
 * Checks own heartbeat state for node X.
 * Responds with ring_ack(agree=true/false).
 */
int nodus_ch_ring_handle_check(nodus_ch_ring_t *rm,
                                nodus_ch_node_session_t *from,
                                const nodus_key_t *node_id,
                                const uint8_t channel_uuid[NODUS_UUID_BYTES]);

/**
 * Handle ring_ack from peer.
 * If agree=true: remove dead node, recalculate hashring, announce to DHT.
 */
int nodus_ch_ring_handle_ack(nodus_ch_ring_t *rm,
                              const uint8_t channel_uuid[NODUS_UUID_BYTES],
                              bool agree);

/**
 * Handle ring_evict: this node is removed from channel.
 * Notify subscribed clients (ch_ring_changed), untrack channel.
 */
int nodus_ch_ring_handle_evict(nodus_ch_ring_t *rm,
                                const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                uint32_t new_version);

/**
 * Handle ring_rejoin: a returning node wants back in.
 * Recalculate hashring with returning node included.
 * If 4 nodes → evict lowest priority.
 * Hashring always wins.
 */
int nodus_ch_ring_handle_rejoin(nodus_ch_ring_t *rm,
                                 nodus_ch_node_session_t *from,
                                 const nodus_key_t *rejoining_node_id,
                                 uint32_t their_ring_version);

#endif /* NODUS_CHANNEL_RING_H */
```

**Step 2: Implement**

Key logic in `nodus_ch_ring_tick`:
```c
void nodus_ch_ring_tick(nodus_ch_ring_t *rm) {
    uint64_t now = nodus_now_ms();
    if (now - rm->last_tick_ms < 5000) return;
    rm->last_tick_ms = now;

    // For each node session:
    //   If last_heartbeat_recv > HEARTBEAT_TIMEOUT_SEC ago:
    //     Node is suspected dead
    //     For each tracked channel where this node is responsible:
    //       Initiate ring_check with other responsible node

    // For each pending ring_check:
    //   If check_sent_at > CHECK_TIMEOUT ago and no ack:
    //     Timeout — assume dead, proceed with eviction
}
```

Key logic in `nodus_ch_ring_handle_rejoin`:
```c
int nodus_ch_ring_handle_rejoin(...) {
    // 1. Add rejoining node to hashring
    // 2. Recalculate responsible set for each tracked channel
    // 3. If 4 nodes in responsible set → evict 4th (lowest hashring priority)
    // 4. ring_version++
    // 5. Announce new ring to DHT
    // 6. If evicted node has client sessions → send ch_ring_changed
    // 7. New PRIMARY (hashring [0]) takes over
    // 8. Trigger incremental sync for returning node
}
```

**Step 3: Write test**

Test track/untrack channels.
Test heartbeat timeout detection.
Test ring_check/ring_ack flow.
Test rejoin with hashring recalculation.

**Step 4: Build and test**

```bash
cd nodus/build && cmake .. && make -j$(nproc) && ctest --output-on-failure
```

**Step 5: Commit**

```bash
git add nodus/src/channel/nodus_channel_ring.c nodus/src/channel/nodus_channel_ring.h \
       nodus/tests/test_channel_ring.c nodus/CMakeLists.txt
git commit -m "feat(nodus): Add channel ring management — heartbeat dead detection (Nodus vX.Y.Z)"
```

---

## Task 6: Integrate New Modules into nodus_server.c

**Files:**
- Modify: `nodus/src/server/nodus_server.c`
- Modify: `nodus/src/server/nodus_server.h`
- Modify: `nodus/CMakeLists.txt`

**Context:** Remove old channel handlers from nodus_server.c, replace with new modular system. The server struct gets new fields, main loop calls new tick functions.

**Step 1: Update nodus_server.h**

Replace old channel fields:
```c
// REMOVE these:
//   nodus_ch_session_t      ch_sessions[NODUS_MAX_CH_SESSIONS];
//   nodus_replication_t     replication;
//   nodus_ring_mgmt_t       ring_mgmt;

// ADD these:
#include "channel/nodus_channel_server.h"
#include "channel/nodus_channel_replication.h"
#include "channel/nodus_channel_ring.h"

typedef struct nodus_server {
    // ... existing fields ...

    /* Channel system (new modular) */
    nodus_channel_server_t  ch_server;
    nodus_ch_replication_t  ch_replication;
    nodus_ch_ring_t         ch_ring;

    // ... keep ring, ch_store ...
} nodus_server_t;
```

**Step 2: Update nodus_server.c initialization**

In `nodus_server_init` (around line 2420):
```c
// REMOVE: old ch_tcp init, old callback setup
// REMOVE: nodus_replication_init
// REMOVE: nodus_ring_mgmt_init

// ADD:
nodus_channel_server_init(&srv->ch_server, &srv->ch_store, &srv->ring,
                           &srv->self_id, &srv->self_pk, srv->self_sk,
                           config->bind_ip);
nodus_channel_server_listen(&srv->ch_server, ch_port);
nodus_ch_replication_init(&srv->ch_replication, &srv->ch_server);
nodus_ch_ring_init(&srv->ch_ring, &srv->ch_server);
```

**Step 3: Update main loop**

Replace old poll/tick calls:
```c
// REMOVE:
//   nodus_tcp_poll(&srv->ch_tcp, 50);
//   nodus_replication_retry(&srv->replication);
//   nodus_ring_mgmt_tick(&srv->ring_mgmt);

// ADD:
nodus_channel_server_poll(&srv->ch_server, 50);
nodus_channel_server_tick(&srv->ch_server);
nodus_ch_replication_retry(&srv->ch_replication);
nodus_ch_ring_tick(&srv->ch_ring);
```

**Step 4: Remove old channel handler functions**

Remove from nodus_server.c (lines 1944-2298):
- `handle_ch_hello`
- `handle_ch_auth`
- `handle_ch_t2_ch_create`
- `handle_ch_t2_ch_post`
- `handle_ch_t2_ch_get_posts`
- `handle_ch_t2_ch_subscribe`
- `handle_ch_t2_ch_unsubscribe`
- `ch_session_find_4003`
- `ch_session_add_sub_4003`
- `ch_session_remove_sub_4003`
- `notify_ch_subscribers_4003`
- `ch_ensure_channel`
- `on_ch_accept`, `on_ch_disconnect`, `on_ch_frame`

**Step 5: Remove old 4002 channel handlers**

Remove from nodus_server.c any `ch_replicate`, `ring_check`, `ring_ack`, `ring_evict` handlers on the inter-node TCP 4002 dispatch.

**Step 6: Update CMakeLists.txt**

```cmake
# REMOVE:
#   src/channel/nodus_replication.c
#   src/channel/nodus_ring_mgmt.c

# ADD:
src/channel/nodus_channel_server.c
src/channel/nodus_channel_primary.c
src/channel/nodus_channel_replication.c
src/channel/nodus_channel_ring.c
```

**Step 7: Delete old files**

```bash
rm nodus/src/channel/nodus_replication.c nodus/src/channel/nodus_replication.h
rm nodus/src/channel/nodus_ring_mgmt.c nodus/src/channel/nodus_ring_mgmt.h
```

**Step 8: Build**

```bash
cd nodus/build && cmake .. && make -j$(nproc)
```

Fix all compilation errors. There may be references to old types/functions in other files.

**Step 9: Run tests**

```bash
cd nodus/build && ctest --output-on-failure
```

All tests must pass.

**Step 10: Commit**

```bash
git add -A nodus/
git commit -m "feat(nodus): Integrate new channel modules, remove old replication/ring_mgmt (Nodus vX.Y.Z)"
```

---

## Task 7: Update Client — Connection Strategy in nodus_ops.c

**Files:**
- Modify: `messenger/dht/shared/nodus_ops.c` (lines 744-872, ch_pool functions)

**Context:** Client now connects to PRIMARY (first in ordered list from DHT). On `ch_ring_changed`: disconnect, re-query DHT, reconnect. On reconnect: catch-up with `ch_get(since_last_received_at)`.

**Step 1: Update ch_pool_connect (line 744-825)**

Current: tries all DHT nodes, connects to first available.
New: DHT returns ordered list. **Always try in order** (PRIMARY first).

```c
static nodus_ch_conn_t *ch_pool_connect(const uint8_t channel_uuid[NODUS_UUID_BYTES]) {
    // 1. Build DHT key: "dna:channel:nodes:" + uuid
    // 2. GET from DHT
    // 3. Parse ordered node list (nodes[0]=PRIMARY, nodes[1]=BACKUP1, nodes[2]=BACKUP2)
    // 4. Try nodes[0] first (PRIMARY)
    // 5. If fails → try nodes[1] → try nodes[2]
    // 6. If ALL fail → fallback to current server:4003 (existing behavior)
    // 7. On connect: auth + subscribe
}
```

This is mostly the same as current code — the order from DHT is already the connection order. Just ensure we don't randomize or sort it differently.

**Step 2: Add ch_ring_changed handler**

Currently the client SDK doesn't handle `ch_ring_changed` push messages. Add handling in the read thread callback:

In `nodus_ops.c`, in the `ch_pool_on_post` callback area (line 633), add:
```c
static void ch_pool_on_ring_changed(const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                     uint32_t new_version, void *user_data) {
    // 1. Find pool entry for channel_uuid
    // 2. Disconnect existing connection
    // 3. Remove from pool (set active=false)
    // Next operation on this channel will trigger ch_pool_get_or_connect
    // which calls ch_pool_connect → gets new PRIMARY from DHT
}
```

**Step 3: Add reconnect catch-up**

In `ch_pool_get_or_connect` (line 831), when a new connection is established for an existing channel (reconnect case), call `ch_get(since=last_received_at)` to catch up missed posts.

Track `last_received_at` per pool entry:
```c
typedef struct {
    uint8_t           channel_uuid[NODUS_UUID_BYTES];
    nodus_ch_conn_t  *conn;
    bool              active;
    uint64_t          last_received_at;  /* NEW: for catch-up on reconnect */
} nodus_ops_ch_entry_t;
```

**Step 4: Build messenger**

```bash
cd messenger/build && cmake .. && make -j$(nproc)
```

**Step 5: Build nodus**

```bash
cd nodus/build && cmake .. && make -j$(nproc)
```

**Step 6: Run all tests**

```bash
cd nodus/build && ctest --output-on-failure
cd messenger/build && ctest --output-on-failure
```

**Step 7: Commit**

```bash
git add messenger/dht/shared/nodus_ops.c messenger/dht/shared/nodus_ops.h
git commit -m "feat(messenger): Update channel client — ordered PRIMARY connection + reconnect catch-up (vX.Y.Z)"
```

---

## Task 8: Integration Test — Cross-Node Replication

**Files:**
- No new files — use existing nodus-server binaries and CLI tool

**Context:** Deploy to test cluster, verify cross-node replication actually works.

**Step 1: Build and deploy to all 6 nodes**

```bash
# Build locally
cd nodus/build && cmake .. && make -j$(nproc)

# Deploy to each node
for IP in 154.38.182.161 164.68.105.227 164.68.116.180 161.97.85.25 156.67.24.125 156.67.25.251; do
  ssh root@$IP "git -C /opt/dna pull && systemctl stop nodus && make -C /opt/dna/nodus/build -j4 && cp /opt/dna/nodus/build/nodus-server /usr/local/bin/nodus-server && systemctl start nodus"
done
```

**Step 2: Verify cluster health**

Check all 6 nodes are running and forming hashring:
```bash
for IP in 154.38.182.161 164.68.105.227 164.68.116.180 161.97.85.25 156.67.24.125 156.67.25.251; do
  echo "=== $IP ===" && ssh root@$IP "systemctl status nodus | head -5"
done
```

**Step 3: Test cross-node post delivery**

Using CLI tool (`dna-messenger-cli`):
1. From ai machine (chip identity): create a channel
2. Post to channel
3. From chat1 machine (punk identity): subscribe to same channel
4. Verify punk sees chip's post
5. Punk posts to channel
6. Verify chip sees punk's post

```bash
# On ai (chip):
/opt/dna/messenger/build/cli/dna-messenger-cli channel create "test-replication"
/opt/dna/messenger/build/cli/dna-messenger-cli channel post <uuid> "Hello from chip"

# On chat1 (punk):
ssh nocdem@192.168.0.195 "/opt/dna/messenger/build/cli/dna-messenger-cli channel get <uuid>"
```

**Step 4: Verify replication on server side**

Check that all 3 responsible nodes have the posts:
```bash
# Identify responsible nodes from DHT
/opt/dna/messenger/build/cli/dna-messenger-cli channel nodes <uuid>

# Check each node's channel database
ssh root@<node_ip> "sqlite3 /var/lib/nodus/channels.db 'SELECT count(*) FROM channel_<uuid_hex>'"
```

**Step 5: Commit version bump**

After successful integration test, bump nodus version and commit.

---

## Task 9: Documentation Update

**Files:**
- Modify: `nodus/docs/ARCHITECTURE.md`
- Modify: `messenger/docs/DNA_NODUS.md` (if exists)

**Step 1: Update architecture docs**

Document the new channel architecture:
- PRIMARY/BACKUP roles
- TCP 4003 protocol messages (complete list)
- Replication flow
- Failover flow
- Ring rejoin flow
- Dead detection via heartbeat (NOT PBFT)

**Step 2: Commit**

```bash
git add nodus/docs/ messenger/docs/
git commit -m "docs: Update channel system architecture documentation"
```

---

## Execution Order

```
Task 1: Protocol messages ──┐
                             ├→ Task 6: Integration into nodus_server.c
Task 2: Channel server ─────┤
                             │
Task 3: PRIMARY module ──────┤
                             │
Task 4: Replication module ──┤
                             │
Task 5: Ring management ─────┘
                                 → Task 7: Client update (nodus_ops.c)
                                 → Task 8: Integration test (deploy + verify)
                                 → Task 9: Documentation
```

Tasks 1-5 can be developed in parallel (independent modules with well-defined interfaces). Task 6 depends on all of them. Tasks 7-9 depend on Task 6.

---

## Version Bumps

- **Nodus**: Bump in final commit (Task 8). This is a MINOR bump — significant architectural change.
- **Messenger C lib**: Bump when client changes committed (Task 7). PATCH bump.
- **Flutter**: No changes needed.
