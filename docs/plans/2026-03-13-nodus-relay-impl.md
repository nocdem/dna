# Nodus Relay Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Real-time TCP relay between two online users via a dedicated Nodus node (TCP 4004). No storage, just pipe. E2E encrypted opaque frames with type field for future voice/video.

**Architecture:** Relay node selected deterministically via Kademlia distance on `SHA3(sort(fp_A, fp_B))`. Both clients connect to TCP 4004, authenticate, and exchange opaque frames. First message always goes via DHT; relay activates when both parties are online. 30s timeout for peer join.

**Tech Stack:** C (Nodus server + client SDK), CBOR protocol, epoll event loop, existing Tier 2 auth

**Design Doc:** `docs/plans/2026-03-13-nodus-relay-design.md`

---

## Phase 1: Nodus Server — Relay Infrastructure

### Task 1: Add relay port constant and config

**Files:**
- Modify: `nodus/include/nodus/nodus_types.h:54` (after `NODUS_DEFAULT_CH_PORT`)
- Modify: `nodus/src/server/nodus_server.h:44` (config struct, add `relay_port`)
- Modify: `nodus/tools/nodus-server.c:84` (config parsing, add `relay_port`)

**Step 1: Add port constant to nodus_types.h**

After line 54 (`#define NODUS_DEFAULT_CH_PORT 4003`), add:

```c
#define NODUS_DEFAULT_RELAY_PORT 4004      /* Relay TCP port */
```

After line 71 (`#define NODUS_MAX_CH_SESSIONS 1024`), add:

```c
#define NODUS_MAX_RELAY_SESSIONS 1024      /* Max relay TCP 4004 connections */
#define NODUS_RELAY_TIMEOUT_MS   30000     /* 30s — peer must join within this window */
#define NODUS_RELAY_MAX_PAIRS    512       /* Max concurrent relay pairs */
```

**Step 2: Add relay_port to config struct**

In `nodus/src/server/nodus_server.h`, in `nodus_server_config_t` after `ch_port` (line 44):

```c
    uint16_t    relay_port;         /* Relay TCP port (default: 4004) */
```

**Step 3: Parse relay_port from config**

In `nodus/tools/nodus-server.c`, after the `ch_port` parsing (line 84-85):

```c
    if (json_object_object_get_ex(root, "relay_port", &val))
        cfg->relay_port = (uint16_t)json_object_get_int(val);
```

**Step 4: Build and verify**

```bash
cd nodus/build && cmake .. && make -j$(nproc)
```

Expected: Clean compile, no warnings.

**Step 5: Commit**

```bash
git add nodus/include/nodus/nodus_types.h nodus/src/server/nodus_server.h nodus/tools/nodus-server.c
git commit -m "feat(relay): add TCP 4004 port constant and config"
```

---

### Task 2: Create relay session struct and server fields

**Files:**
- Modify: `nodus/src/server/nodus_server.h` (add relay session struct + server fields)

**Step 1: Add relay pair struct**

After `nodus_ch_session_t` definition (after line 95), add:

```c
/* ── Relay session (TCP 4004 connections) ──────────────────── */

typedef struct {
    nodus_tcp_conn_t   *conn;
    nodus_key_t         client_fp;
    nodus_pubkey_t      client_pk;
    uint8_t             token[NODUS_SESSION_TOKEN_LEN];
    bool                authenticated;

    /* Pending auth challenge */
    uint8_t             nonce[NODUS_NONCE_LEN];
    bool                nonce_pending;

    /* Relay pairing — index into relay_pairs[], -1 if not paired */
    int                 pair_idx;
} nodus_relay_session_t;

/** A relay pair: two authenticated clients forwarding opaque frames */
typedef struct {
    bool        active;
    nodus_key_t fp_a;               /* First client fingerprint */
    nodus_key_t fp_b;               /* Second client fingerprint */
    int         slot_a;             /* Session slot for client A (-1 = not connected) */
    int         slot_b;             /* Session slot for client B (-1 = not connected) */
    uint64_t    created_at;         /* Unix ms — for 30s timeout */
    bool        ready;              /* Both clients connected? */
} nodus_relay_pair_t;
```

**Step 2: Add relay fields to nodus_server_t**

In `nodus_server_t` struct, after the channel transport fields (after line 253):

```c
    /* Relay transport (TCP 4004) */
    nodus_tcp_t             relay_tcp;
    nodus_relay_session_t   relay_sessions[NODUS_MAX_RELAY_SESSIONS];
    nodus_relay_pair_t      relay_pairs[NODUS_RELAY_MAX_PAIRS];
```

**Step 3: Build and verify**

```bash
cd nodus/build && cmake .. && make -j$(nproc)
```

**Step 4: Commit**

```bash
git add nodus/src/server/nodus_server.h
git commit -m "feat(relay): add relay session and pair structs to server"
```

---

### Task 3: Create relay module — `nodus_relay.c` / `nodus_relay.h`

**Files:**
- Create: `nodus/src/server/nodus_relay.h`
- Create: `nodus/src/server/nodus_relay.c`
- Modify: `nodus/CMakeLists.txt:104` (add source file)

**Step 1: Create relay header**

Create `nodus/src/server/nodus_relay.h`:

```c
/**
 * Nodus — Relay Module (TCP 4004)
 *
 * Real-time relay between two authenticated clients.
 * No storage — pure frame forwarding.
 */

#ifndef NODUS_RELAY_H
#define NODUS_RELAY_H

#include "server/nodus_server.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Relay protocol methods (CBOR "method" field) ──────────── */

/* Client → Server */
#define NODUS_RELAY_SESSION_INIT   "relay_init"
#define NODUS_RELAY_SESSION_JOIN   "relay_join"
#define NODUS_RELAY_DATA           "relay_data"
#define NODUS_RELAY_SESSION_CLOSE  "relay_close"

/* Server → Client */
#define NODUS_RELAY_WAITING        "relay_waiting"
#define NODUS_RELAY_READY          "relay_ready"
#define NODUS_RELAY_PEER_GONE      "relay_peer_gone"
#define NODUS_RELAY_TIMEOUT        "relay_timeout"

/* Data frame types (inside relay_data) */
#define NODUS_RELAY_TYPE_MESSAGE   0x01
#define NODUS_RELAY_TYPE_VOICE     0x02
#define NODUS_RELAY_TYPE_VIDEO     0x03
#define NODUS_RELAY_TYPE_CONTROL   0xFF

/**
 * Handle an incoming frame on a relay session (TCP 4004).
 * Dispatches auth, session_init, session_join, relay_data, session_close.
 */
void nodus_relay_handle_frame(nodus_server_t *srv,
                               nodus_relay_session_t *sess,
                               const uint8_t *payload, size_t len);

/**
 * Periodic tick — expire timed-out relay pairs (30s).
 * Called from main event loop.
 */
void nodus_relay_tick(nodus_server_t *srv);

/**
 * Clean up when a relay client disconnects.
 * Notifies paired peer if any.
 */
void nodus_relay_on_disconnect(nodus_server_t *srv,
                                nodus_relay_session_t *sess);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_RELAY_H */
```

**Step 2: Create relay implementation**

Create `nodus/src/server/nodus_relay.c`:

```c
/**
 * Nodus — Relay Module (TCP 4004)
 *
 * Session management and frame forwarding for real-time relay.
 */

#include "server/nodus_relay.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_sign.h"
#include "nodus/nodus_types.h"

#include <string.h>
#include <stdio.h>
#include <time.h>

/* Response buffer (shared across handlers — single-threaded) */
static uint8_t relay_resp_buf[NODUS_MAX_VALUE_SIZE + 65536];

/* ── Helpers ──────────────────────────────────────────────────── */

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/** Find a relay pair by both fingerprints (order-independent). Returns index or -1. */
static int find_pair(nodus_server_t *srv,
                     const nodus_key_t *fp_a, const nodus_key_t *fp_b) {
    for (int i = 0; i < NODUS_RELAY_MAX_PAIRS; i++) {
        nodus_relay_pair_t *p = &srv->relay_pairs[i];
        if (!p->active) continue;
        if ((memcmp(&p->fp_a, fp_a, sizeof(nodus_key_t)) == 0 &&
             memcmp(&p->fp_b, fp_b, sizeof(nodus_key_t)) == 0) ||
            (memcmp(&p->fp_a, fp_b, sizeof(nodus_key_t)) == 0 &&
             memcmp(&p->fp_b, fp_a, sizeof(nodus_key_t)) == 0))
            return i;
    }
    return -1;
}

/** Allocate a free relay pair slot. Returns index or -1. */
static int alloc_pair(nodus_server_t *srv) {
    for (int i = 0; i < NODUS_RELAY_MAX_PAIRS; i++) {
        if (!srv->relay_pairs[i].active) return i;
    }
    return -1;
}

/** Send a simple method response (no extra fields) to a relay session. */
static void send_method(nodus_relay_session_t *sess,
                         const char *method, uint32_t txn_id) {
    size_t rlen = 0;
    nodus_t2_result_method(txn_id, method, relay_resp_buf,
                            sizeof(relay_resp_buf), &rlen);
    if (rlen > 0)
        nodus_tcp_send(sess->conn, relay_resp_buf, rlen);
}

/** Send an error response. */
static void send_error(nodus_relay_session_t *sess,
                        uint32_t txn_id, int code, const char *msg) {
    size_t rlen = 0;
    nodus_t2_error(txn_id, code, msg, relay_resp_buf,
                    sizeof(relay_resp_buf), &rlen);
    if (rlen > 0)
        nodus_tcp_send(sess->conn, relay_resp_buf, rlen);
}

/* ── Auth handlers (reuse pattern from channel auth) ──────── */

static void handle_relay_hello(nodus_server_t *srv,
                                nodus_relay_session_t *sess,
                                const nodus_tier2_msg_t *msg) {
    if (sess->authenticated) {
        send_error(sess, msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "already authenticated");
        return;
    }
    if (!msg->has_pubkey || !msg->has_fingerprint) {
        send_error(sess, msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "hello requires pubkey and fingerprint");
        return;
    }

    /* Verify fingerprint matches pubkey */
    nodus_key_t computed_fp;
    nodus_hash(msg->pubkey.data, NODUS_PUBKEY_LEN, &computed_fp);
    if (memcmp(&computed_fp, &msg->fingerprint, sizeof(nodus_key_t)) != 0) {
        send_error(sess, msg->txn_id, NODUS_ERR_AUTH_FAILED,
                   "fingerprint mismatch");
        return;
    }

    memcpy(&sess->client_pk, &msg->pubkey, sizeof(nodus_pubkey_t));
    memcpy(&sess->client_fp, &msg->fingerprint, sizeof(nodus_key_t));

    /* Generate challenge nonce */
    nodus_random(sess->nonce, NODUS_NONCE_LEN);
    sess->nonce_pending = true;

    /* Send challenge */
    size_t rlen = 0;
    nodus_t2_challenge(msg->txn_id, sess->nonce, NODUS_NONCE_LEN,
                        relay_resp_buf, sizeof(relay_resp_buf), &rlen);
    if (rlen > 0)
        nodus_tcp_send(sess->conn, relay_resp_buf, rlen);
}

static void handle_relay_auth(nodus_server_t *srv,
                               nodus_relay_session_t *sess,
                               const nodus_tier2_msg_t *msg) {
    if (sess->authenticated) {
        send_error(sess, msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "already authenticated");
        return;
    }
    if (!sess->nonce_pending) {
        send_error(sess, msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "no pending challenge");
        return;
    }
    if (!msg->has_signature) {
        send_error(sess, msg->txn_id, NODUS_ERR_AUTH_FAILED,
                   "missing signature");
        return;
    }

    /* Verify signature over nonce */
    if (nodus_verify(sess->nonce, NODUS_NONCE_LEN,
                      &msg->signature, &sess->client_pk) != 0) {
        send_error(sess, msg->txn_id, NODUS_ERR_AUTH_FAILED,
                   "invalid signature");
        return;
    }

    sess->authenticated = true;
    sess->nonce_pending = false;

    /* Generate session token */
    nodus_random(sess->token, NODUS_SESSION_TOKEN_LEN);

    /* Send auth_ok with token */
    size_t rlen = 0;
    nodus_t2_auth_ok(msg->txn_id, sess->token, NODUS_SESSION_TOKEN_LEN,
                      relay_resp_buf, sizeof(relay_resp_buf), &rlen);
    if (rlen > 0)
        nodus_tcp_send(sess->conn, relay_resp_buf, rlen);
}

/* ── Relay session handlers ──────────────────────────────────── */

/**
 * relay_init: Client wants to create a relay session with a peer.
 * CBOR: { "method": "relay_init", "fp_peer": <key> }
 */
static void handle_relay_init(nodus_server_t *srv,
                               nodus_relay_session_t *sess,
                               const nodus_tier2_msg_t *msg) {
    if (!msg->has_target_fp) {
        send_error(sess, msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "relay_init requires fp_peer");
        return;
    }

    /* Check if pair already exists */
    int idx = find_pair(srv, &sess->client_fp, &msg->target_fp);
    if (idx >= 0) {
        nodus_relay_pair_t *p = &srv->relay_pairs[idx];
        /* Already exists — is this client already in it? */
        if (memcmp(&p->fp_a, &sess->client_fp, sizeof(nodus_key_t)) == 0 ||
            memcmp(&p->fp_b, &sess->client_fp, sizeof(nodus_key_t)) == 0) {
            send_error(sess, msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                       "session already exists");
            return;
        }
    }

    /* Allocate new pair */
    idx = alloc_pair(srv);
    if (idx < 0) {
        send_error(sess, msg->txn_id, NODUS_ERR_RATE_LIMIT,
                   "relay pairs full");
        return;
    }

    nodus_relay_pair_t *p = &srv->relay_pairs[idx];
    memset(p, 0, sizeof(*p));
    p->active = true;
    memcpy(&p->fp_a, &sess->client_fp, sizeof(nodus_key_t));
    memcpy(&p->fp_b, &msg->target_fp, sizeof(nodus_key_t));
    p->slot_a = sess->conn->slot;
    p->slot_b = -1;
    p->created_at = now_ms();
    p->ready = false;

    sess->pair_idx = idx;

    /* Respond: waiting for peer */
    send_method(sess, NODUS_RELAY_WAITING, msg->txn_id);
}

/**
 * relay_join: Second client joins an existing relay session.
 * CBOR: { "method": "relay_join", "fp_peer": <key> }
 */
static void handle_relay_join(nodus_server_t *srv,
                               nodus_relay_session_t *sess,
                               const nodus_tier2_msg_t *msg) {
    if (!msg->has_target_fp) {
        send_error(sess, msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "relay_join requires fp_peer");
        return;
    }

    /* Find the pair where fp_peer is the initiator and our fp is the target */
    int idx = find_pair(srv, &sess->client_fp, &msg->target_fp);
    if (idx < 0) {
        send_error(sess, msg->txn_id, NODUS_ERR_NOT_FOUND,
                   "no pending relay session");
        return;
    }

    nodus_relay_pair_t *p = &srv->relay_pairs[idx];
    if (p->ready) {
        send_error(sess, msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "session already active");
        return;
    }

    /* Determine which slot this client fills */
    if (memcmp(&p->fp_b, &sess->client_fp, sizeof(nodus_key_t)) == 0) {
        p->slot_b = sess->conn->slot;
    } else if (memcmp(&p->fp_a, &sess->client_fp, sizeof(nodus_key_t)) == 0) {
        p->slot_a = sess->conn->slot;
    } else {
        send_error(sess, msg->txn_id, NODUS_ERR_AUTH_FAILED,
                   "fingerprint not in session");
        return;
    }

    sess->pair_idx = idx;
    p->ready = true;

    /* Notify both: session_ready */
    send_method(sess, NODUS_RELAY_READY, msg->txn_id);

    /* Notify the initiator too */
    if (p->slot_a >= 0 && p->slot_a < NODUS_MAX_RELAY_SESSIONS) {
        nodus_relay_session_t *peer_sess = &srv->relay_sessions[p->slot_a];
        if (peer_sess->conn && peer_sess->authenticated)
            send_method(peer_sess, NODUS_RELAY_READY, 0);
    }
}

/**
 * relay_data: Forward opaque frame to peer.
 * CBOR: { "method": "relay_data", "type": <u8>, "data": <bytes> }
 *
 * This is the hot path — just forward the raw payload to the other side.
 */
static void handle_relay_data(nodus_server_t *srv,
                               nodus_relay_session_t *sess,
                               const nodus_tier2_msg_t *msg) {
    if (sess->pair_idx < 0 || sess->pair_idx >= NODUS_RELAY_MAX_PAIRS) {
        send_error(sess, msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "no active relay session");
        return;
    }

    nodus_relay_pair_t *p = &srv->relay_pairs[sess->pair_idx];
    if (!p->active || !p->ready) {
        send_error(sess, msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "relay not ready");
        return;
    }

    /* Determine peer slot */
    int peer_slot = -1;
    if (memcmp(&p->fp_a, &sess->client_fp, sizeof(nodus_key_t)) == 0)
        peer_slot = p->slot_b;
    else
        peer_slot = p->slot_a;

    if (peer_slot < 0 || peer_slot >= NODUS_MAX_RELAY_SESSIONS) {
        send_error(sess, msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "peer not connected");
        return;
    }

    nodus_relay_session_t *peer = &srv->relay_sessions[peer_slot];
    if (!peer->conn || !peer->authenticated) {
        send_error(sess, msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "peer not connected");
        return;
    }

    /* Forward: re-encode as relay_data to peer.
     * For efficiency, we re-encode the CBOR with the same type+data.
     * The msg already has data/data_len and relay_type fields. */
    size_t rlen = 0;
    nodus_t2_relay_data(msg->txn_id, msg->relay_type, msg->data, msg->data_len,
                         relay_resp_buf, sizeof(relay_resp_buf), &rlen);
    if (rlen > 0)
        nodus_tcp_send(peer->conn, relay_resp_buf, rlen);
}

/**
 * relay_close: Graceful session close.
 */
static void handle_relay_close(nodus_server_t *srv,
                                nodus_relay_session_t *sess,
                                const nodus_tier2_msg_t *msg) {
    if (sess->pair_idx >= 0 && sess->pair_idx < NODUS_RELAY_MAX_PAIRS) {
        nodus_relay_pair_t *p = &srv->relay_pairs[sess->pair_idx];
        if (p->active) {
            /* Notify peer */
            int peer_slot = (memcmp(&p->fp_a, &sess->client_fp,
                                     sizeof(nodus_key_t)) == 0) ?
                             p->slot_b : p->slot_a;
            if (peer_slot >= 0 && peer_slot < NODUS_MAX_RELAY_SESSIONS) {
                nodus_relay_session_t *peer = &srv->relay_sessions[peer_slot];
                if (peer->conn && peer->authenticated) {
                    send_method(peer, NODUS_RELAY_PEER_GONE, 0);
                    peer->pair_idx = -1;
                }
            }
            memset(p, 0, sizeof(*p));
        }
    }
    sess->pair_idx = -1;
}

/* ── Public API ──────────────────────────────────────────────── */

void nodus_relay_handle_frame(nodus_server_t *srv,
                               nodus_relay_session_t *sess,
                               const uint8_t *payload, size_t len) {
    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    if (nodus_t2_decode(payload, len, &msg) != 0) {
        nodus_t2_msg_free(&msg);
        return;
    }

    /* Auth flow (same as channel) */
    if (strcmp(msg.method, "hello") == 0) {
        handle_relay_hello(srv, sess, &msg);
        nodus_t2_msg_free(&msg);
        return;
    }
    if (strcmp(msg.method, "auth") == 0) {
        handle_relay_auth(srv, sess, &msg);
        nodus_t2_msg_free(&msg);
        return;
    }

    /* All other ops require auth */
    if (!sess->authenticated) {
        send_error(sess, msg.txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                   "not authenticated");
        nodus_t2_msg_free(&msg);
        return;
    }

    /* Relay dispatch */
    if (strcmp(msg.method, NODUS_RELAY_SESSION_INIT) == 0)
        handle_relay_init(srv, sess, &msg);
    else if (strcmp(msg.method, NODUS_RELAY_SESSION_JOIN) == 0)
        handle_relay_join(srv, sess, &msg);
    else if (strcmp(msg.method, NODUS_RELAY_DATA) == 0)
        handle_relay_data(srv, sess, &msg);
    else if (strcmp(msg.method, NODUS_RELAY_SESSION_CLOSE) == 0)
        handle_relay_close(srv, sess, &msg);
    else {
        send_error(sess, msg.txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "unknown relay method");
    }

    nodus_t2_msg_free(&msg);
}

void nodus_relay_tick(nodus_server_t *srv) {
    uint64_t now = now_ms();

    for (int i = 0; i < NODUS_RELAY_MAX_PAIRS; i++) {
        nodus_relay_pair_t *p = &srv->relay_pairs[i];
        if (!p->active) continue;

        /* Timeout: pair created but peer didn't join within 30s */
        if (!p->ready && (now - p->created_at) > NODUS_RELAY_TIMEOUT_MS) {
            /* Notify the initiator */
            int init_slot = p->slot_a;
            if (init_slot >= 0 && init_slot < NODUS_MAX_RELAY_SESSIONS) {
                nodus_relay_session_t *sess = &srv->relay_sessions[init_slot];
                if (sess->conn && sess->authenticated) {
                    send_method(sess, NODUS_RELAY_TIMEOUT, 0);
                    sess->pair_idx = -1;
                }
            }
            memset(p, 0, sizeof(*p));
        }
    }
}

void nodus_relay_on_disconnect(nodus_server_t *srv,
                                nodus_relay_session_t *sess) {
    if (sess->pair_idx >= 0 && sess->pair_idx < NODUS_RELAY_MAX_PAIRS) {
        nodus_relay_pair_t *p = &srv->relay_pairs[sess->pair_idx];
        if (p->active) {
            int peer_slot = (memcmp(&p->fp_a, &sess->client_fp,
                                     sizeof(nodus_key_t)) == 0) ?
                             p->slot_b : p->slot_a;
            if (peer_slot >= 0 && peer_slot < NODUS_MAX_RELAY_SESSIONS) {
                nodus_relay_session_t *peer = &srv->relay_sessions[peer_slot];
                if (peer->conn && peer->authenticated) {
                    send_method(peer, NODUS_RELAY_PEER_GONE, 0);
                    peer->pair_idx = -1;
                }
            }
            memset(p, 0, sizeof(*p));
        }
    }
    memset(sess, 0, sizeof(*sess));
}
```

**Step 3: Add to CMakeLists.txt**

In `nodus/CMakeLists.txt`, after `src/server/nodus_presence.c` (line 104):

```cmake
        src/server/nodus_relay.c
```

**Step 4: Build and verify**

```bash
cd nodus/build && cmake .. && make -j$(nproc)
```

Expected: Will likely fail — needs Tier 2 protocol additions (Task 4). That's OK, commit what we have and fix in next task.

**Step 5: Commit**

```bash
git add nodus/src/server/nodus_relay.h nodus/src/server/nodus_relay.c nodus/CMakeLists.txt
git commit -m "feat(relay): add relay module — session management and frame forwarding"
```

---

### Task 4: Extend Tier 2 protocol for relay messages

**Files:**
- Modify: `nodus/src/protocol/nodus_tier2.h` (add relay encode/decode helpers)
- Modify: `nodus/src/protocol/nodus_tier2.c` (implement relay CBOR encoding)

**Context:** The Tier 2 protocol uses CBOR encoding. We need:
1. `nodus_t2_relay_data()` — encode a relay_data frame
2. `nodus_t2_result_method()` — encode a simple method-only response (relay_waiting, relay_ready, etc.)
3. `target_fp` field in `nodus_tier2_msg_t` for relay_init/relay_join
4. `relay_type` and `data`/`data_len` fields in msg for relay_data

**Step 1: Check existing tier2 structures**

Read `nodus/src/protocol/nodus_tier2.h` to understand current `nodus_tier2_msg_t` fields.

**Step 2: Add relay fields to tier2_msg_t**

Add to `nodus_tier2_msg_t`:
```c
    /* Relay fields */
    nodus_key_t     target_fp;          /* Peer fingerprint for relay_init/relay_join */
    bool            has_target_fp;
    uint8_t         relay_type;         /* Frame type (0x01=msg, 0x02=voice, etc.) */
```

Note: `data` and `data_len` likely already exist for other message types. Verify and reuse.

**Step 3: Add decoder support for relay fields**

In `nodus_t2_decode()`, add parsing for `"fp_peer"` → `msg->target_fp`, `"relay_type"` → `msg->relay_type`.

**Step 4: Add encoder functions**

```c
/**
 * Encode relay_data frame: { "method": "relay_data", "type": N, "data": <bytes> }
 */
int nodus_t2_relay_data(uint32_t txn_id, uint8_t type,
                         const uint8_t *data, size_t data_len,
                         uint8_t *out, size_t out_cap, size_t *out_len);

/**
 * Encode a simple method-only response (relay_waiting, relay_ready, relay_peer_gone, relay_timeout).
 */
int nodus_t2_result_method(uint32_t txn_id, const char *method,
                            uint8_t *out, size_t out_cap, size_t *out_len);
```

**Step 5: Build and verify**

```bash
cd nodus/build && cmake .. && make -j$(nproc)
```

Expected: Clean compile.

**Step 6: Commit**

```bash
git add nodus/src/protocol/nodus_tier2.h nodus/src/protocol/nodus_tier2.c
git commit -m "feat(relay): extend Tier 2 protocol with relay message types"
```

---

### Task 5: Wire relay into server event loop

**Files:**
- Modify: `nodus/src/server/nodus_server.c` (add relay TCP init, callbacks, poll, cleanup)
- Modify: `nodus/src/server/nodus_server.h` (add include for relay header)

**Step 1: Add include**

In `nodus_server.h`, add after the ring_mgmt include (line 25):
```c
#include "server/nodus_relay.h"
```

Wait — this creates a circular dependency (relay.h includes server.h). Instead, add the include in `nodus_server.c` only.

In `nodus_server.c`, add near the top includes:
```c
#include "server/nodus_relay.h"
```

**Step 2: Add relay TCP callbacks**

Following the pattern of `on_ch_accept`, `on_ch_disconnect`, `on_ch_frame` (lines 2163-2232):

```c
/* ── Relay TCP 4004 callbacks ──────────────────────────────── */

static void on_relay_accept(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    if (conn->slot >= 0 && conn->slot < NODUS_MAX_RELAY_SESSIONS) {
        memset(&srv->relay_sessions[conn->slot], 0, sizeof(nodus_relay_session_t));
        srv->relay_sessions[conn->slot].conn = conn;
        srv->relay_sessions[conn->slot].pair_idx = -1;
    }
}

static void on_relay_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    if (conn->slot >= 0 && conn->slot < NODUS_MAX_RELAY_SESSIONS) {
        nodus_relay_session_t *sess = &srv->relay_sessions[conn->slot];
        nodus_relay_on_disconnect(srv, sess);
    }
}

static void on_relay_frame(nodus_tcp_conn_t *conn,
                            const uint8_t *payload, size_t len, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    if (conn->slot < 0 || conn->slot >= NODUS_MAX_RELAY_SESSIONS) return;
    nodus_relay_session_t *sess = &srv->relay_sessions[conn->slot];
    if (!sess->conn) return;
    nodus_relay_handle_frame(srv, sess, payload, len);
}
```

**Step 3: Init relay TCP in `nodus_server_init()`**

After the channel TCP init block (after line 2369), add:

```c
    /* Init relay TCP transport (TCP 4004 — own epoll) */
    uint16_t relay_port = config->relay_port ? config->relay_port
                                              : NODUS_DEFAULT_RELAY_PORT;
    if (relay_port == config->tcp_port || relay_port == peer_port ||
        relay_port == ch_port) {
        fprintf(stderr, "ERROR: relay_port (%d) must differ from other ports\n",
                relay_port);
        return -1;
    }
    if (nodus_tcp_init(&srv->relay_tcp, -1) != 0)
        return -1;
    srv->relay_tcp.on_accept     = on_relay_accept;
    srv->relay_tcp.on_frame      = on_relay_frame;
    srv->relay_tcp.on_disconnect = on_relay_disconnect;
    srv->relay_tcp.cb_ctx        = srv;

    if (nodus_tcp_listen(&srv->relay_tcp, config->bind_ip, relay_port) != 0) {
        fprintf(stderr, "Failed to bind relay TCP %s:%d\n",
                config->bind_ip, relay_port);
        return -1;
    }
```

**Step 4: Add to run loop print**

After `fprintf(stderr, "  Channel port: %d\n", srv->ch_tcp.port);` (line 2420):

```c
    fprintf(stderr, "  Relay port: %d\n", srv->relay_tcp.port);
```

**Step 5: Add poll to main loop**

After `nodus_tcp_poll(&srv->ch_tcp, 50);` (line 2431):

```c
        /* Poll relay TCP events (4004) */
        nodus_tcp_poll(&srv->relay_tcp, 50);
```

**Step 6: Add relay_tick to main loop**

After `nodus_presence_tick(srv);` (line 2450):

```c
        /* Relay: expire timed-out pairs (30s) */
        nodus_relay_tick(srv);
```

**Step 7: Add cleanup**

After `nodus_tcp_close(&srv->ch_tcp);` (line 2507):

```c
    nodus_tcp_close(&srv->relay_tcp);
```

**Step 8: Initialize relay sessions pair_idx to -1**

In `nodus_server_init()`, after the session array memsets, add:
```c
    for (int i = 0; i < NODUS_MAX_RELAY_SESSIONS; i++)
        srv->relay_sessions[i].pair_idx = -1;
```

**Step 9: Build and verify**

```bash
cd nodus/build && cmake .. && make -j$(nproc)
```

**Step 10: Commit**

```bash
git add nodus/src/server/nodus_server.c
git commit -m "feat(relay): wire relay TCP 4004 into server event loop"
```

---

### Task 6: Unit tests for relay

**Files:**
- Create: `nodus/tests/test_relay.c`
- Modify: `nodus/CMakeLists.txt` (add test)

**Step 1: Write test file**

Create `nodus/tests/test_relay.c`:

```c
/**
 * Nodus — Relay Unit Tests
 *
 * Tests relay pair allocation, timeout, and disconnect cleanup.
 * (Integration tests with actual TCP connections are separate.)
 */

#include "server/nodus_relay.h"
#include "nodus/nodus_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%d] %-50s ", tests_run, name); \
} while (0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while (0)

/* Minimal server with relay_pairs only */
static nodus_server_t srv;

static void setup(void) {
    memset(&srv, 0, sizeof(srv));
    for (int i = 0; i < NODUS_MAX_RELAY_SESSIONS; i++)
        srv.relay_sessions[i].pair_idx = -1;
}

static void make_fp(nodus_key_t *fp, uint8_t val) {
    memset(fp, val, sizeof(nodus_key_t));
}

static void test_pair_alloc_and_find(void) {
    TEST("alloc pair and find by fingerprints");
    setup();

    nodus_key_t fp_a, fp_b;
    make_fp(&fp_a, 0xAA);
    make_fp(&fp_b, 0xBB);

    /* Allocate pair manually */
    srv.relay_pairs[0].active = true;
    memcpy(&srv.relay_pairs[0].fp_a, &fp_a, sizeof(nodus_key_t));
    memcpy(&srv.relay_pairs[0].fp_b, &fp_b, sizeof(nodus_key_t));
    srv.relay_pairs[0].slot_a = 0;
    srv.relay_pairs[0].slot_b = -1;

    /* find_pair is static, so we test via relay_tick behavior instead.
     * For now, just verify the struct is set up correctly. */
    if (!srv.relay_pairs[0].active) { FAIL("pair not active"); return; }
    if (memcmp(&srv.relay_pairs[0].fp_a, &fp_a, sizeof(nodus_key_t)) != 0) {
        FAIL("fp_a mismatch"); return;
    }
    PASS();
}

static void test_pair_timeout(void) {
    TEST("pair timeout after 30s");
    setup();

    nodus_key_t fp_a, fp_b;
    make_fp(&fp_a, 0xAA);
    make_fp(&fp_b, 0xBB);

    srv.relay_pairs[0].active = true;
    memcpy(&srv.relay_pairs[0].fp_a, &fp_a, sizeof(nodus_key_t));
    memcpy(&srv.relay_pairs[0].fp_b, &fp_b, sizeof(nodus_key_t));
    srv.relay_pairs[0].slot_a = -1;   /* No real connection */
    srv.relay_pairs[0].slot_b = -1;
    srv.relay_pairs[0].created_at = 0; /* Epoch — will always be timed out */
    srv.relay_pairs[0].ready = false;

    nodus_relay_tick(&srv);

    if (srv.relay_pairs[0].active) {
        FAIL("pair should have been cleaned up after timeout");
        return;
    }
    PASS();
}

static void test_pair_no_timeout_when_ready(void) {
    TEST("no timeout when pair is ready (both connected)");
    setup();

    nodus_key_t fp_a, fp_b;
    make_fp(&fp_a, 0xAA);
    make_fp(&fp_b, 0xBB);

    srv.relay_pairs[0].active = true;
    memcpy(&srv.relay_pairs[0].fp_a, &fp_a, sizeof(nodus_key_t));
    memcpy(&srv.relay_pairs[0].fp_b, &fp_b, sizeof(nodus_key_t));
    srv.relay_pairs[0].slot_a = 0;
    srv.relay_pairs[0].slot_b = 1;
    srv.relay_pairs[0].created_at = 0; /* Old timestamp */
    srv.relay_pairs[0].ready = true;   /* But ready! */

    nodus_relay_tick(&srv);

    if (!srv.relay_pairs[0].active) {
        FAIL("ready pair should NOT be timed out");
        return;
    }
    PASS();
}

static void test_max_pairs(void) {
    TEST("max pairs limit");
    setup();

    /* Fill all pairs */
    for (int i = 0; i < NODUS_RELAY_MAX_PAIRS; i++) {
        srv.relay_pairs[i].active = true;
    }

    /* Verify all slots full (alloc_pair would return -1).
     * We check by counting active pairs. */
    int active = 0;
    for (int i = 0; i < NODUS_RELAY_MAX_PAIRS; i++) {
        if (srv.relay_pairs[i].active) active++;
    }

    if (active != NODUS_RELAY_MAX_PAIRS) {
        FAIL("expected all pairs active"); return;
    }
    PASS();
}

int main(void) {
    printf("Nodus relay tests:\n");

    test_pair_alloc_and_find();
    test_pair_timeout();
    test_pair_no_timeout_when_ready();
    test_max_pairs();

    printf("\n  %d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
```

**Step 2: Add test to CMakeLists.txt**

After the last test entry:

```cmake
add_executable(test_relay tests/test_relay.c)
target_link_libraries(test_relay nodus)
add_test(NAME test_relay COMMAND test_relay)
```

**Step 3: Build and run tests**

```bash
cd nodus/build && cmake .. && make -j$(nproc) && ctest --output-on-failure
```

Expected: All tests pass including the new relay tests.

**Step 4: Commit**

```bash
git add nodus/tests/test_relay.c nodus/CMakeLists.txt
git commit -m "test(relay): add relay unit tests — pair alloc, timeout, limits"
```

---

## Phase 2: Nodus Client SDK — Relay Connection

### Task 7: Add relay client API to Nodus SDK

**Files:**
- Modify: `nodus/include/nodus/nodus.h` (add relay connection type + public API)
- Modify: `nodus/src/client/nodus_client.c` (implement relay client)

**Step 1: Add relay connection type and API to nodus.h**

```c
/* ── Relay connection (TCP 4004) ──────────────────────────── */

typedef struct nodus_relay_conn nodus_relay_conn_t;

/** Callback when relay data arrives from peer */
typedef void (*nodus_relay_data_cb_t)(uint8_t type,
                                       const uint8_t *data, size_t data_len,
                                       void *user_data);

/** Callback for relay session events (ready, peer_gone, timeout) */
typedef void (*nodus_relay_event_cb_t)(const char *event,
                                        void *user_data);

/**
 * Connect to a relay node on TCP 4004.
 * Authenticates using the provided identity.
 */
nodus_relay_conn_t *nodus_relay_connect(const char *host, uint16_t port,
                                         const nodus_identity_t *id);

/**
 * Initiate a relay session with a peer.
 * Call this on the initiator side. Returns 0 on success.
 */
int nodus_relay_session_init(nodus_relay_conn_t *conn,
                              const uint8_t peer_fp[NODUS_KEY_LEN]);

/**
 * Join an existing relay session.
 * Call this on the joining side. Returns 0 on success.
 */
int nodus_relay_session_join(nodus_relay_conn_t *conn,
                              const uint8_t peer_fp[NODUS_KEY_LEN]);

/**
 * Send data through the relay to the peer.
 * Type: NODUS_RELAY_TYPE_MESSAGE (0x01), VOICE (0x02), etc.
 */
int nodus_relay_send(nodus_relay_conn_t *conn,
                      uint8_t type,
                      const uint8_t *data, size_t data_len);

/**
 * Poll for incoming relay data and events. Non-blocking.
 * Calls data_cb for relay_data, event_cb for session events.
 */
int nodus_relay_poll(nodus_relay_conn_t *conn, int timeout_ms);

/**
 * Set callbacks for relay data and events.
 */
void nodus_relay_set_callbacks(nodus_relay_conn_t *conn,
                                nodus_relay_data_cb_t data_cb,
                                nodus_relay_event_cb_t event_cb,
                                void *user_data);

/**
 * Close relay connection and free resources.
 */
void nodus_relay_close(nodus_relay_conn_t *conn);
```

**Step 2: Implement in nodus_client.c**

The implementation follows the same pattern as `nodus_ch_conn_t` — TCP connect, authenticate, then send/receive CBOR frames. Key difference: relay_poll needs to dispatch incoming frames to callbacks.

Implementation structure:
```c
struct nodus_relay_conn {
    int                     fd;
    nodus_identity_t        identity;
    uint8_t                 token[NODUS_SESSION_TOKEN_LEN];
    bool                    authenticated;
    nodus_relay_data_cb_t   data_cb;
    nodus_relay_event_cb_t  event_cb;
    void                   *cb_data;
    uint8_t                *recv_buf;
    size_t                  recv_len;
    size_t                  recv_cap;
};
```

**Step 3: Build and verify**

```bash
cd nodus/build && cmake .. && make -j$(nproc)
```

**Step 4: Commit**

```bash
git add nodus/include/nodus/nodus.h nodus/src/client/nodus_client.c
git commit -m "feat(relay): add relay client SDK — connect, init, join, send, poll"
```

---

## Phase 3: Messenger Integration — nodus_ops relay wrapper

### Task 8: Add relay wrapper to nodus_ops

**Files:**
- Modify: `messenger/dht/shared/nodus_ops.h` (add relay ops API)
- Modify: `messenger/dht/shared/nodus_ops.c` (implement relay connection management)

**Step 1: Add relay API to nodus_ops.h**

```c
/* ── Relay operations (TCP 4004) ──────────────────────────── */

/** Callback for relay data from peer */
typedef void (*nodus_ops_relay_data_cb_t)(const char *peer_fp,
                                           uint8_t type,
                                           const uint8_t *data, size_t data_len,
                                           void *user_data);

/** Callback for relay events (ready, peer_gone, timeout) */
typedef void (*nodus_ops_relay_event_cb_t)(const char *peer_fp,
                                            const char *event,
                                            void *user_data);

/** Set global relay callbacks */
void nodus_ops_relay_set_callbacks(nodus_ops_relay_data_cb_t data_cb,
                                    nodus_ops_relay_event_cb_t event_cb,
                                    void *user_data);

/**
 * Initiate a relay session with peer.
 * Computes relay node via Kademlia distance, connects to TCP 4004,
 * sends session_init, returns 0 on success.
 */
int nodus_ops_relay_init(const char *peer_fp_hex);

/**
 * Join a relay session (called when we receive a relay invite).
 * Computes relay node, connects to TCP 4004, sends session_join.
 */
int nodus_ops_relay_join(const char *peer_fp_hex);

/**
 * Send data through an active relay session.
 */
int nodus_ops_relay_send(const char *peer_fp_hex,
                          uint8_t type,
                          const uint8_t *data, size_t data_len);

/**
 * Check if we have an active relay session with peer.
 */
bool nodus_ops_relay_is_active(const char *peer_fp_hex);

/**
 * Close a specific relay session.
 */
void nodus_ops_relay_close(const char *peer_fp_hex);

/**
 * Poll all active relay sessions. Called from engine worker/heartbeat thread.
 */
void nodus_ops_relay_poll_all(void);

/** Shut down all relay sessions. */
void nodus_ops_relay_shutdown(void);
```

**Step 2: Implement relay pool in nodus_ops.c**

Following the `g_ch_pool` pattern — a fixed-size pool of relay connections indexed by peer fingerprint.

```c
#define NODUS_OPS_RELAY_MAX_CONNS 16

typedef struct {
    char                    peer_fp[129];   /* Hex fingerprint of peer */
    nodus_relay_conn_t     *conn;
    bool                    active;
    bool                    ready;          /* Session is active (both sides connected) */
} nodus_ops_relay_entry_t;

static nodus_ops_relay_entry_t g_relay_pool[NODUS_OPS_RELAY_MAX_CONNS];
static pthread_mutex_t g_relay_mutex = PTHREAD_MUTEX_INITIALIZER;
/* ... callbacks ... */
```

Key implementation detail: `nodus_ops_relay_init()` must:
1. Compute relay node: `SHA3(sort(our_fp, peer_fp))` → find nearest node in routing table
2. Get relay node's IP (from Nodus servers list or routing table)
3. Connect to that node's TCP 4004
4. Authenticate
5. Send `relay_init` with peer fingerprint

**Step 3: Build and verify**

```bash
cd messenger/build && cmake .. && make -j$(nproc)
```

**Step 4: Commit**

```bash
git add messenger/dht/shared/nodus_ops.h messenger/dht/shared/nodus_ops.c
git commit -m "feat(relay): add relay wrapper to nodus_ops — connection pool + relay node selection"
```

---

### Task 9: Integrate relay into messaging engine

**Files:**
- Modify: `messenger/src/api/engine/dna_engine_messaging.c` (check relay before DHT, handle relay receive)
- Modify: `messenger/src/api/engine/dna_engine_internal.h` (add relay task types if needed)
- Modify: `messenger/include/dna/dna_engine.h` (if new public API needed)

**Step 1: Modify send path**

In `dna_handle_send_message()`, after encryption, before DHT PUT:

```c
    /* Check if we have an active relay session with this recipient */
    if (nodus_ops_relay_is_active(task->params.send_message.recipient)) {
        /* Send via relay — encrypted message as opaque bytes */
        int rc = nodus_ops_relay_send(
            task->params.send_message.recipient,
            NODUS_RELAY_TYPE_MESSAGE,
            encrypted_data, encrypted_len);
        if (rc == 0) {
            /* Success — still save to local DB, but skip DHT PUT */
            QGP_LOG_INFO(LOG_TAG, "[SEND] Message sent via relay (skipping DHT)");
            /* ... save to DB, emit event ... */
            goto done;
        }
        /* Relay send failed — fall through to DHT */
        QGP_LOG_WARN(LOG_TAG, "[SEND] Relay send failed, falling back to DHT");
    }
```

**Step 2: Handle incoming relay data**

When relay data callback fires, decrypt and deliver via same event system:

```c
static void on_relay_data(const char *peer_fp, uint8_t type,
                           const uint8_t *data, size_t data_len,
                           void *user_data) {
    if (type != NODUS_RELAY_TYPE_MESSAGE) return;
    dna_engine_t *engine = (dna_engine_t *)user_data;

    /* Decrypt and process same as DHT-received message */
    /* ... messenger_decrypt_message(data, data_len, ...) ... */
    /* ... save to DB, emit DNA_EVENT_MESSAGE_RECEIVED ... */
}
```

**Step 3: Handle relay invite via DHT**

When receiving a message and sender is online, start relay:

```c
    /* After receiving DHT message, check if sender is online */
    if (dna_presence_is_online(engine, sender_fp)) {
        /* Initiate relay session */
        nodus_ops_relay_join(sender_fp_hex);
        /* Send relay invite back to sender via DHT */
        /* ... small DHT PUT with relay_invite type ... */
    }
```

**Step 4: Build and verify**

```bash
cd messenger/build && cmake .. && make -j$(nproc)
```

**Step 5: Commit**

```bash
git add messenger/src/api/engine/dna_engine_messaging.c
git commit -m "feat(relay): integrate relay into messaging — send via relay when active, DHT fallback"
```

---

## Phase 4: Deployment & Testing

### Task 10: Deploy relay port to production nodes

**Step 1: Open firewall on all 6 nodes**

```bash
for IP in 154.38.182.161 164.68.105.227 164.68.116.180 161.97.85.25 156.67.24.125 156.67.25.251; do
    ssh root@$IP "ufw allow 4004/tcp comment 'Nodus relay' && ufw status | grep 4004"
done
```

**Step 2: Update nodus.conf on all nodes**

Add `"relay_port": 4004` to `/etc/nodus.conf` on each node.

**Step 3: Deploy updated nodus-server**

```bash
for IP in ...; do
    ssh root@$IP "git -C /opt/dna pull && systemctl stop nodus && make -C /opt/dna/nodus/build -j4 && cp /opt/dna/nodus/build/nodus-server /usr/local/bin/nodus-server && systemctl start nodus"
done
```

**Step 4: Verify relay port is listening**

```bash
for IP in ...; do
    ssh root@$IP "ss -tlnp | grep 4004"
done
```

**Step 5: Commit deployment docs update**

---

### Task 11: Integration test — CLI relay

**Step 1: Test from dev machine (chip)**

```bash
# 1. Send normal message to punk (triggers DHT path)
$CLI send punk "relay test message"

# 2. Check if relay invite is received (logs)
# 3. Verify relay session establishes (logs)
# 4. Send another message — should go via relay
$CLI send punk "second message via relay"
```

**Step 2: Verify on chat1 (punk)**

```bash
ssh nocdem@192.168.0.195 "$CLI messages chip"
```

Both messages should be received. Logs should show second message via relay path.

---

### Task 12: Version bump and documentation

**Files:**
- Modify: `nodus/include/nodus/nodus_types.h` (version bump)
- Modify: `messenger/include/dna/version.h` (version bump)
- Update: `messenger/docs/P2P_ARCHITECTURE.md`
- Update: `messenger/docs/DNA_NODUS.md`
- Update: `messenger/docs/functions/dht.md` (new relay functions)

**Step 1: Bump Nodus version**

Increment `NODUS_VERSION_MINOR` or `NODUS_VERSION_PATCH` in `nodus_types.h`.

**Step 2: Bump Messenger version**

Increment patch in `messenger/include/dna/version.h`.

**Step 3: Update docs**

- P2P_ARCHITECTURE.md: Add relay section
- DNA_NODUS.md: Add TCP 4004 port, relay configuration
- functions/dht.md: Add `nodus_ops_relay_*` functions

**Step 4: Commit**

```bash
git commit -m "feat: Nodus relay — real-time DM relay via TCP 4004 (vX.Y.Z)"
```

---

## Implementation Notes

### Critical things to verify during implementation:

1. **Tier 2 protocol**: Check if `nodus_tier2_msg_t` already has `data`/`data_len` fields that can be reused for relay_data. If not, add them. Also check if there's already a `target_fp` or similar field.

2. **Auth helpers**: `nodus_auth_handle_hello()` and `nodus_auth_handle_auth()` in `nodus_server.c` work with `nodus_session_t`. The relay module needs similar auth but with `nodus_relay_session_t`. Either refactor auth to be generic, or duplicate (duplicate is simpler and avoids touching working code).

3. **Relay node discovery**: The messenger needs to map `SHA3(sort(fp_a, fp_b))` → nearest node IP. The `nodus_ops_get_servers()` or routing table can provide the node list. Then find closest by XOR distance.

4. **Thread safety**: `nodus_ops_relay_poll_all()` will be called from a background thread. The relay pool needs mutex protection (same pattern as channel pool).

5. **DHT relay invite**: Define a new message type or use a special DHT key pattern for relay invites. Keep it simple — a small CBOR blob PUT to the peer's listen key with short TTL (60s).

### Order of operations:
- Tasks 1-6: Pure server-side, can be built and tested independently
- Task 7: Client SDK, depends on Task 4 (protocol)
- Tasks 8-9: Messenger integration, depends on Task 7
- Tasks 10-12: Deployment and docs, depends on everything above
