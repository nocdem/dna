# Dedicated Channel Port (TCP 4003) — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a dedicated TCP 4003 listener for channel operations, migrate from seq_id to received_at ordering, and implement multi-primary replication with ring management.

**Architecture:** A third `nodus_tcp_t` instance (`ch_tcp`) listens on TCP 4003 with its own session pool (`nodus_ch_session_t`). Channel ops are dispatched from this listener using the same auth mechanism as TCP 4001. The `seq_id` column/logic is removed from channel storage in favor of `received_at` timestamp ordering with `post_uuid` dedup. Ring management uses `ring_check`/`ring_ack`/`ring_evict` messages over TCP 4002. Clients discover responsible nodes via DHT self-announcement.

**Tech Stack:** C (POSIX), SQLite, CBOR, epoll, Dilithium5

**Design Doc:** `docs/plans/2026-03-13-dedicated-channel-port-design.md`

---

## Phase 1 (Faz 1): TCP 4003 Infrastructure

### Task 1.1: Add `NODUS_DEFAULT_CH_PORT` constant and config field

**Files:**
- Modify: `nodus/include/nodus/nodus_types.h` — add `NODUS_DEFAULT_CH_PORT 4003`
- Modify: `nodus/src/server/nodus_server.h` — add `uint16_t ch_port` to `nodus_server_config_t`, add `nodus_tcp_t ch_tcp` to `nodus_server_t`, add `nodus_ch_session_t` struct and `ch_sessions[]` array
- Modify: `nodus/tools/nodus-server.c` — add `-C` flag for channel port, parse `ch_port` from JSON config

**Step 1: Add constant to nodus_types.h**

After `NODUS_DEFAULT_PEER_PORT 4002`:
```c
#define NODUS_DEFAULT_CH_PORT   4003        /* Channel client TCP port */
```

Also add channel session limits:
```c
#define NODUS_MAX_CH_SESSIONS   256         /* Max channel TCP connections */
#define NODUS_MAX_CH_SUBS_PER_SESSION 32    /* Per channel-session subscriptions */
```

**Step 2: Add ch_session struct and config field to nodus_server.h**

Add to `nodus_server_config_t` after `peer_port`:
```c
uint16_t    ch_port;            /* Channel client TCP port (default: 4003) */
```

Add new channel session struct (separate from `nodus_session_t`):
```c
/* ── Channel session (TCP 4003 connections) ──────────────────── */

typedef struct {
    nodus_tcp_conn_t   *conn;
    nodus_key_t         client_fp;
    nodus_pubkey_t      client_pk;
    uint8_t             token[NODUS_SESSION_TOKEN_LEN];
    bool                authenticated;

    /* Pending auth challenge */
    uint8_t             nonce[NODUS_NONCE_LEN];
    bool                nonce_pending;

    /* Channel subscriptions */
    uint8_t             ch_subs[NODUS_MAX_CH_SUBS_PER_SESSION][NODUS_UUID_BYTES];
    int                 ch_sub_count;

    /* Rate limiting */
    uint32_t            posts_this_minute;
    time_t              rate_window_start;
} nodus_ch_session_t;
```

Add to `nodus_server_t` struct after `inter_sessions[]`:
```c
/* Channel transport (TCP 4003) */
nodus_tcp_t             ch_tcp;
nodus_ch_session_t      ch_sessions[NODUS_MAX_CH_SESSIONS];
```

**Step 3: Update nodus-server.c**

In `usage()`, add:
```c
fprintf(stderr, "  -C <ch_port>      Channel TCP port (default: %d)\n", NODUS_DEFAULT_CH_PORT);
```

In config defaults, add:
```c
config.ch_port = NODUS_DEFAULT_CH_PORT;
```

In `load_config_json()`, add:
```c
if (json_object_object_get_ex(root, "ch_port", &val))
    cfg->ch_port = (uint16_t)json_object_get_int(val);
```

In getopt string, change `"c:b:u:t:p:i:d:s:h"` to `"c:b:u:t:p:C:i:d:s:h"` and add:
```c
case 'C': config.ch_port = (uint16_t)atoi(optarg); break;
```

(Same in the CLI re-parse block.)

**Step 4: Build and run tests**

```bash
cd /opt/dna/nodus/build && cmake .. && make -j$(nproc)
cd /opt/dna/nodus/build && ctest --output-on-failure
```

Expected: All 16 tests pass. Build clean (zero warnings).

**Step 5: Commit**

```bash
git add nodus/include/nodus/nodus_types.h nodus/src/server/nodus_server.h nodus/tools/nodus-server.c
git commit -m "feat(nodus): add channel port config and ch_session struct"
```

---

### Task 1.2: Initialize TCP 4003 listener in server

**Files:**
- Modify: `nodus/src/server/nodus_server.c` — add ch_tcp init, callbacks, listen, poll, close

**Step 1: Add channel TCP callback forward declarations**

Near the existing `on_tcp_accept`/`on_tcp_frame`/`on_tcp_disconnect` declarations (around line 240), add:
```c
/* TCP 4003 channel callbacks */
static void on_ch_accept(nodus_tcp_conn_t *conn, void *ctx);
static void on_ch_frame(nodus_tcp_conn_t *conn, const uint8_t *payload, size_t len, void *ctx);
static void on_ch_disconnect(nodus_tcp_conn_t *conn, void *ctx);
```

**Step 2: Add channel session helper functions**

Add these helpers (mirror the existing session helpers but for ch_sessions):
```c
/* ── Channel session helpers (TCP 4003) ─────────────────────── */

static nodus_ch_session_t *ch_session_find(nodus_server_t *srv, nodus_tcp_conn_t *conn) {
    if (!conn || conn->slot < 0 || conn->slot >= NODUS_MAX_CH_SESSIONS)
        return NULL;
    nodus_ch_session_t *s = &srv->ch_sessions[conn->slot];
    return (s->conn == conn) ? s : NULL;
}

static int ch_session_add_ch_sub(nodus_ch_session_t *sess, const uint8_t *uuid) {
    if (sess->ch_sub_count >= NODUS_MAX_CH_SUBS_PER_SESSION) return -1;
    /* Check duplicate */
    for (int i = 0; i < sess->ch_sub_count; i++) {
        if (memcmp(sess->ch_subs[i], uuid, NODUS_UUID_BYTES) == 0)
            return 0;  /* Already subscribed */
    }
    memcpy(sess->ch_subs[sess->ch_sub_count], uuid, NODUS_UUID_BYTES);
    sess->ch_sub_count++;
    return 0;
}

static void ch_session_remove_ch_sub(nodus_ch_session_t *sess, const uint8_t *uuid) {
    for (int i = 0; i < sess->ch_sub_count; i++) {
        if (memcmp(sess->ch_subs[i], uuid, NODUS_UUID_BYTES) == 0) {
            memcpy(sess->ch_subs[i],
                   sess->ch_subs[--sess->ch_sub_count], NODUS_UUID_BYTES);
            return;
        }
    }
}
```

**Step 3: Implement channel TCP callbacks**

```c
static void on_ch_accept(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    if (conn->slot >= 0 && conn->slot < NODUS_MAX_CH_SESSIONS) {
        memset(&srv->ch_sessions[conn->slot], 0, sizeof(nodus_ch_session_t));
        srv->ch_sessions[conn->slot].conn = conn;
    }
}

static void on_ch_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    if (conn->slot >= 0 && conn->slot < NODUS_MAX_CH_SESSIONS) {
        memset(&srv->ch_sessions[conn->slot], 0, sizeof(nodus_ch_session_t));
    }
}
```

For `on_ch_frame`, implement the channel dispatch. This reuses the existing auth flow (hello/auth) and dispatches channel-specific methods:
```c
static void on_ch_frame(nodus_tcp_conn_t *conn,
                         const uint8_t *payload, size_t len, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    nodus_ch_session_t *sess = ch_session_find(srv, conn);
    if (!sess) return;

    nodus_tier2_msg_t msg;
    if (nodus_t2_decode(payload, len, &msg) != 0) return;

    /* Auth flow (same as 4001 but uses ch_session) */
    if (strcmp(msg.method, "hello") == 0) {
        handle_ch_hello(srv, sess, &msg);
        nodus_t2_msg_free(&msg);
        return;
    }
    if (strcmp(msg.method, "auth") == 0) {
        handle_ch_auth(srv, sess, &msg);
        nodus_t2_msg_free(&msg);
        return;
    }

    /* All other ops require auth */
    if (!sess->authenticated) {
        size_t rlen = 0;
        nodus_t2_error(msg.txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                        "not authenticated", resp_buf, sizeof(resp_buf), &rlen);
        nodus_tcp_send(sess->conn, resp_buf, rlen);
        nodus_t2_msg_free(&msg);
        return;
    }

    /* Channel-only dispatch */
    if (strcmp(msg.method, "ch_create") == 0)
        handle_ch_t2_ch_create(srv, sess, &msg);
    else if (strcmp(msg.method, "ch_post") == 0)
        handle_ch_t2_ch_post(srv, sess, &msg);
    else if (strcmp(msg.method, "ch_get") == 0)
        handle_ch_t2_ch_get_posts(srv, sess, &msg);
    else if (strcmp(msg.method, "ch_sub") == 0)
        handle_ch_t2_ch_subscribe(srv, sess, &msg);
    else if (strcmp(msg.method, "ch_unsub") == 0)
        handle_ch_t2_ch_unsubscribe(srv, sess, &msg);
    else {
        size_t rlen = 0;
        nodus_t2_error(msg.txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "unknown channel method", resp_buf, sizeof(resp_buf), &rlen);
        nodus_tcp_send(sess->conn, resp_buf, rlen);
    }

    nodus_t2_msg_free(&msg);
}
```

**Step 4: Implement channel auth handlers**

These mirror `nodus_auth_handle_hello`/`nodus_auth_handle_auth` but operate on `nodus_ch_session_t`:
```c
static void handle_ch_hello(nodus_server_t *srv, nodus_ch_session_t *sess,
                              nodus_tier2_msg_t *msg) {
    /* Verify fingerprint matches pubkey */
    nodus_key_t expected_fp;
    nodus_hash(msg->pk.bytes, NODUS_PK_BYTES, &expected_fp);
    if (nodus_key_cmp(&expected_fp, &msg->fp) != 0) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INVALID_SIGNATURE,
                        "fingerprint mismatch", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    sess->client_pk = msg->pk;
    sess->client_fp = msg->fp;

    /* Generate challenge nonce */
    nodus_random(sess->nonce, NODUS_NONCE_LEN);
    sess->nonce_pending = true;

    size_t len = 0;
    nodus_t2_challenge(msg->txn_id, sess->nonce, resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);
}

static void handle_ch_auth(nodus_server_t *srv, nodus_ch_session_t *sess,
                              nodus_tier2_msg_t *msg) {
    if (!sess->nonce_pending) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "no pending challenge", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    /* Verify signature over nonce */
    if (nodus_verify(sess->nonce, NODUS_NONCE_LEN,
                      &msg->sig, &sess->client_pk) != 0) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INVALID_SIGNATURE,
                        "invalid signature", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    sess->authenticated = true;
    sess->nonce_pending = false;
    nodus_random(sess->token, NODUS_SESSION_TOKEN_LEN);

    /* Register in presence table */
    nodus_presence_register(&srv->presence, &sess->client_fp);

    size_t len = 0;
    nodus_t2_auth_ok(msg->txn_id, sess->token, resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);
}
```

**Step 5: Implement channel-specific message handlers for TCP 4003**

These are nearly identical to the existing `handle_t2_ch_*` functions but take `nodus_ch_session_t*` instead of `nodus_session_t*`. The key difference: `notify_ch_subscribers` must also broadcast to 4003 ch_sessions.

Add a new notify function that broadcasts to ch_sessions:
```c
/** Notify channel subscribers on TCP 4003 connections */
static void notify_ch_subscribers_4003(nodus_server_t *srv,
                                         const uint8_t uuid[NODUS_UUID_BYTES],
                                         const nodus_channel_post_t *post) {
    for (int i = 0; i < NODUS_MAX_CH_SESSIONS; i++) {
        nodus_ch_session_t *s = &srv->ch_sessions[i];
        if (!s->conn || !s->authenticated) continue;

        for (int j = 0; j < s->ch_sub_count; j++) {
            if (memcmp(s->ch_subs[j], uuid, NODUS_UUID_BYTES) == 0) {
                size_t len = 0;
                if (nodus_t2_ch_post_notify(0, uuid, post,
                        resp_buf, sizeof(resp_buf), &len) == 0) {
                    nodus_tcp_send(s->conn, resp_buf, len);
                }
                break;
            }
        }
    }
}
```

Update the existing `notify_ch_subscribers` (TCP 4001) to also call `notify_ch_subscribers_4003`. During the transition (Phase 1), both 4001 and 4003 receive notifications. In Phase 3, 4001 notifications will be removed.

The `handle_ch_t2_ch_post` handler should call BOTH notify functions:
```c
/* After storing post and replicate: */
if (rc == 0) {
    notify_ch_subscribers(srv, msg->channel_uuid, &post);      /* 4001 legacy */
    notify_ch_subscribers_4003(srv, msg->channel_uuid, &post); /* 4003 new */
    nodus_replication_send(&srv->replication, msg->channel_uuid, &post, &sess->client_pk);
}
```

**Step 6: Wire up ch_tcp in nodus_server_init()**

In `nodus_server_init()`, after the inter_tcp init block (line ~2167):
```c
/* Init channel TCP transport (TCP 4003 — own epoll) */
uint16_t ch_port = config->ch_port ? config->ch_port : NODUS_DEFAULT_CH_PORT;
if (ch_port == config->tcp_port || ch_port == peer_port) {
    fprintf(stderr, "ERROR: ch_port (%d) must differ from tcp_port (%d) and peer_port (%d)\n",
            ch_port, config->tcp_port, peer_port);
    return -1;
}
if (nodus_tcp_init(&srv->ch_tcp, -1) != 0)
    return -1;
srv->ch_tcp.on_accept     = on_ch_accept;
srv->ch_tcp.on_frame      = on_ch_frame;
srv->ch_tcp.on_disconnect = on_ch_disconnect;
srv->ch_tcp.cb_ctx        = srv;

if (nodus_tcp_listen(&srv->ch_tcp, config->bind_ip, ch_port) != 0) {
    fprintf(stderr, "Failed to listen on channel TCP %s:%d\n",
            config->bind_ip, ch_port);
    return -1;
}
```

**Step 7: Add ch_tcp poll to main loop**

In `nodus_server_run()`, after `nodus_tcp_poll(&srv->inter_tcp, 50)`:
```c
/* Poll channel TCP events (4003) */
nodus_tcp_poll(&srv->ch_tcp, 50);
```

**Step 8: Add ch_tcp to startup log**

In `nodus_server_run()` startup print:
```c
fprintf(stderr, "  Channel port: %d\n", srv->ch_tcp.port);
```

**Step 9: Close ch_tcp in nodus_server_close()**

In `nodus_server_close()`, add before `nodus_tcp_close(&srv->tcp)`:
```c
nodus_tcp_close(&srv->ch_tcp);
```

**Step 10: Build and run tests**

```bash
cd /opt/dna/nodus/build && cmake .. && make -j$(nproc)
cd /opt/dna/nodus/build && ctest --output-on-failure
```

Expected: All 16 tests pass. Zero warnings. Server now listens on 3 TCP ports.

**Step 11: Commit**

```bash
git add nodus/src/server/nodus_server.c
git commit -m "feat(nodus): TCP 4003 channel listener with auth and dispatch"
```

---

### Task 1.3: Remove seq_id — migrate to received_at ordering

**Files:**
- Modify: `nodus/include/nodus/nodus_types.h` — remove `seq_id` from `nodus_channel_post_t`
- Modify: `nodus/src/channel/nodus_channel_store.h` — change `nodus_channel_get_posts` to use `uint64_t since_timestamp`; remove `nodus_channel_max_seq`
- Modify: `nodus/src/channel/nodus_channel_store.c` — new schema without seq_id PK, received_at-based queries
- Modify: `nodus/src/protocol/nodus_tier2.h` — change `nodus_t2_ch_post_ok` (no seq_id), change `nodus_t2_ch_get_posts` (since_timestamp), remove seq from ch_ntf and ch_posts and ch_rep encoding
- Modify: `nodus/src/protocol/nodus_tier2.c` — update encode/decode
- Modify: `nodus/src/server/nodus_server.c` — update handler calls
- Modify: `nodus/src/client/nodus_client.c` — update `nodus_client_ch_post` (no seq_out), `nodus_client_ch_get_posts` (uint64_t since_timestamp)
- Modify: `nodus/include/nodus/nodus.h` — update public API signatures
- Modify: `nodus/tests/test_channel_store.c` — update tests for new schema

**This is a breaking change** — existing channel data will need table recreation. Since channels are public ephemeral data (7-day retention), this is acceptable: old tables are dropped and recreated on first access.

**Step 1: Remove seq_id from nodus_channel_post_t**

In `nodus/include/nodus/nodus_types.h`, change `nodus_channel_post_t`:
```c
/** Channel post (stored per-channel, ordered by received_at) */
typedef struct {
    uint8_t     channel_uuid[NODUS_UUID_BYTES];
    uint8_t     post_uuid[NODUS_UUID_BYTES];
    nodus_key_t author_fp;      /* SHA3-512(author_pk) */
    uint64_t    timestamp;      /* Author's claimed time */
    uint64_t    received_at;    /* Nodus receive time (ms) — ordering key */
    char       *body;           /* UTF-8, max 4000 chars */
    size_t      body_len;
    nodus_sig_t signature;      /* SIGN(ch + id + ts + body) */
} nodus_channel_post_t;
```

**Step 2: Update channel store header**

In `nodus_channel_store.h`:
- Change `nodus_channel_get_posts` signature:
```c
int nodus_channel_get_posts(nodus_channel_store_t *store,
                             const uint8_t uuid[NODUS_UUID_BYTES],
                             uint64_t since_timestamp, int max_count,
                             nodus_channel_post_t **posts_out,
                             size_t *count_out);
```
- Remove `nodus_channel_max_seq` declaration entirely.

**Step 3: Update channel store implementation**

In `nodus_channel_store.c`:

`nodus_channel_create()` — new schema:
```c
snprintf(sql, sizeof(sql),
    "CREATE TABLE IF NOT EXISTS channel_%s ("
    "post_uuid BLOB NOT NULL PRIMARY KEY,"
    "author_fp BLOB NOT NULL,"
    "timestamp INTEGER NOT NULL,"
    "body BLOB NOT NULL,"
    "signature BLOB NOT NULL,"
    "received_at INTEGER NOT NULL)", hex);
```

Keep the `received_at` index:
```c
snprintf(sql, sizeof(sql),
    "CREATE INDEX IF NOT EXISTS idx_%s_recv ON channel_%s(received_at)",
    hex, hex);
```

Remove the `post_uuid` unique index (it's now the PRIMARY KEY).

`nodus_channel_post()` — no seq_id assignment:
```c
int nodus_channel_post(nodus_channel_store_t *store,
                        nodus_channel_post_t *post) {
    if (!store || !store->db || !post) return -1;

    char hex[33];
    uuid_to_hex(post->channel_uuid, hex);
    if (!uuid_hex_valid(hex)) return -1;

    /* Assign received_at if not already set (replication preserves original) */
    if (post->received_at == 0)
        post->received_at = nodus_time_now_ms();

    /* Check duplicate post_uuid */
    char sql[256];
    snprintf(sql, sizeof(sql),
        "SELECT 1 FROM channel_%s WHERE post_uuid = ?", hex);
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(store->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(stmt, 1, post->post_uuid, NODUS_UUID_BYTES, SQLITE_STATIC);
    bool duplicate = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    if (duplicate) return 1;

    /* Insert */
    snprintf(sql, sizeof(sql),
        "INSERT INTO channel_%s (post_uuid, author_fp, timestamp, body, signature, received_at) "
        "VALUES (?, ?, ?, ?, ?, ?)", hex);

    if (sqlite3_prepare_v2(store->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    sqlite3_bind_blob(stmt, 1, post->post_uuid, NODUS_UUID_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, post->author_fp.bytes, NODUS_KEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (int64_t)post->timestamp);
    sqlite3_bind_blob(stmt, 4, post->body, (int)post->body_len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, post->signature.bytes, NODUS_SIG_BYTES, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, (int64_t)post->received_at);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}
```

`nodus_channel_get_posts()` — received_at based:
```c
int nodus_channel_get_posts(nodus_channel_store_t *store,
                             const uint8_t uuid[NODUS_UUID_BYTES],
                             uint64_t since_timestamp, int max_count,
                             nodus_channel_post_t **posts_out,
                             size_t *count_out) {
    /* ... null checks same as before ... */

    char sql[256];
    snprintf(sql, sizeof(sql),
        "SELECT post_uuid, author_fp, timestamp, body, signature, received_at "
        "FROM channel_%s WHERE received_at > ? ORDER BY received_at ASC, author_fp ASC LIMIT ?", hex);

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(store->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)since_timestamp);
    sqlite3_bind_int(stmt, 2, max_count > 0 ? max_count : 1000);

    /* ... rest of loop identical but reads 6 columns instead of 7, no seq_id ... */
}
```

Remove `nodus_channel_max_seq()` entirely.

**Step 4: Schema migration — handle old tables**

Add a migration function to detect old-format tables (with seq_id column) and drop+recreate them. Channel data is ephemeral (7-day retention) so data loss is acceptable:

```c
/** Check if channel table uses old schema (has seq_id column) and migrate */
static void migrate_channel_table(nodus_channel_store_t *store,
                                    const uint8_t uuid[NODUS_UUID_BYTES]) {
    char hex[33];
    uuid_to_hex(uuid, hex);
    if (!uuid_hex_valid(hex)) return;

    /* Check if seq_id column exists */
    char sql[256];
    snprintf(sql, sizeof(sql),
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='channel_%s'", hex);
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(store->db, sql, -1, &stmt, NULL) != SQLITE_OK) return;

    bool has_seq_id = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *table_sql = (const char *)sqlite3_column_text(stmt, 0);
        if (table_sql && strstr(table_sql, "seq_id"))
            has_seq_id = true;
    }
    sqlite3_finalize(stmt);

    if (has_seq_id) {
        fprintf(stderr, "NODUS_CH: migrating channel_%s from seq_id to received_at schema\n", hex);
        nodus_channel_drop(store, uuid);
        nodus_channel_create(store, uuid);
    }
}
```

Call this from `nodus_channel_create()` before the `CREATE TABLE IF NOT EXISTS`:
```c
/* Migrate old schema if needed */
migrate_channel_table(store, uuid);
```

**Step 5: Update protocol layer — remove seq_id from wire format**

In `nodus_tier2.h`:
- Change `nodus_t2_ch_post_ok` signature (remove `seq_id` param):
```c
int nodus_t2_ch_post_ok(uint32_t txn,
                         uint8_t *buf, size_t cap, size_t *out_len);
```
- Change `nodus_t2_ch_get_posts` to use `uint64_t since_timestamp`:
```c
int nodus_t2_ch_get_posts(uint32_t txn, const uint8_t *token,
                           const uint8_t uuid[NODUS_UUID_BYTES],
                           uint64_t since_timestamp, int max_count,
                           uint8_t *buf, size_t cap, size_t *out_len);
```
- Remove `ch_seq_id` from `nodus_tier2_msg_t` struct, add `ch_since_timestamp`:
```c
uint64_t        ch_since_timestamp;  /* ch_get_posts: since_timestamp */
```

In `nodus_tier2.c`:
- `nodus_t2_ch_post_ok` — empty result map (no seq):
```c
int nodus_t2_ch_post_ok(uint32_t txn,
                         uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "ch_post_ok");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 0);
    return finish(&enc, out_len);
}
```
- `nodus_t2_ch_posts` — remove "seq" field, encode 6 fields per post instead of 7
- `nodus_t2_ch_post_notify` — remove "seq" field, encode 6 fields instead of 7
- `nodus_t2_ch_replicate` — remove "seq" field, reduce map count
- `nodus_t2_ch_get_posts` — encode `since_timestamp` as uint64 instead of seq uint32
- Decode: remove "seq" parsing from post maps, change `ch_get_posts` since field to uint64

**Step 6: Update server handlers**

In `nodus_server.c`:
- `handle_t2_ch_post` / `handle_ch_t2_ch_post`: call `nodus_t2_ch_post_ok(msg->txn_id, ...)` without seq_id
- `handle_t2_ch_get_posts` / `handle_ch_t2_ch_get_posts`: use `msg->ch_since_timestamp` instead of `msg->seq`
- `nodus_replication_receive`: no longer assigns seq_id; preserve original `received_at`

**Step 7: Update client SDK**

In `nodus/include/nodus/nodus.h`:
- `nodus_client_ch_post`: remove `uint32_t *seq_out` param
- `nodus_client_ch_get_posts`: change `uint32_t since_seq` to `uint64_t since_timestamp`

In `nodus/src/client/nodus_client.c`:
- `nodus_client_ch_post`: remove `seq_out` handling
- `nodus_client_ch_get_posts`: pass `since_timestamp` instead of `since_seq`

**Step 8: Update replication — preserve received_at**

In `nodus_server.c`, the `handle_t2_ch_post` handler currently calls `nodus_channel_post()` which sets `received_at` internally. Verify this still works: the receiving nodus assigns `received_at`, replication preserves it.

In `nodus_replication.c`, `nodus_replication_receive()` calls `nodus_channel_post()` which will now set `received_at` only if it's 0. The replicated post already has `received_at` set by the originating nodus, so it will be preserved. **This is correct by design.**

**Step 9: Update test_channel_store.c**

Update all tests that reference `seq_id` or `nodus_channel_max_seq`. Key changes:
- Post structs no longer set/check `seq_id`
- `nodus_channel_get_posts` uses `since_timestamp` (uint64_t ms) instead of `since_seq`
- Remove test for `nodus_channel_max_seq`

**Step 10: Build and run tests**

```bash
cd /opt/dna/nodus/build && cmake .. && make -j$(nproc)
cd /opt/dna/nodus/build && ctest --output-on-failure
```

Expected: All tests pass. Zero warnings. No seq_id references remain.

**Step 11: Verify no seq_id references remain**

```bash
grep -rn "seq_id\|since_seq\|max_seq\|ch_seq" nodus/ --include="*.c" --include="*.h" | grep -v ".git"
```

Expected: Zero matches (except possibly comments referencing the migration).

**Step 12: Commit**

```bash
git add nodus/
git commit -m "feat(nodus): remove seq_id, use received_at timestamp ordering"
```

---

### Task 1.4: Update nodus_t2_ch_post_notify to use received_at

**Files:**
- Modify: `nodus/src/protocol/nodus_tier2.h` — add `received_at` to ch_post_notify
- Modify: `nodus/src/protocol/nodus_tier2.c` — encode `ra` field in ch_ntf

**Step 1: Add received_at to ch_post_notify**

The notification should include `received_at` so clients can use it as their sync cursor. Update `nodus_t2_ch_post_notify` to encode 7 fields (was 7 with seq, now 7 with ra):

In `nodus_tier2.c`, `nodus_t2_ch_post_notify`:
```c
cbor_encode_map(&enc, 7);
cbor_encode_cstr(&enc, "ch");
cbor_encode_bstr(&enc, ch_uuid, NODUS_UUID_BYTES);
cbor_encode_cstr(&enc, "pid");
cbor_encode_bstr(&enc, post->post_uuid, NODUS_UUID_BYTES);
cbor_encode_cstr(&enc, "afp");
cbor_encode_bstr(&enc, post->author_fp.bytes, NODUS_KEY_BYTES);
cbor_encode_cstr(&enc, "ts");
cbor_encode_uint(&enc, post->timestamp);
cbor_encode_cstr(&enc, "d");
cbor_encode_bstr(&enc, (const uint8_t *)post->body, post->body_len);
cbor_encode_cstr(&enc, "sig");
cbor_encode_bstr(&enc, post->signature.bytes, NODUS_SIG_BYTES);
cbor_encode_cstr(&enc, "ra");
cbor_encode_uint(&enc, post->received_at);
```

**Step 2: Build and test**

```bash
cd /opt/dna/nodus/build && cmake .. && make -j$(nproc)
cd /opt/dna/nodus/build && ctest --output-on-failure
```

**Step 3: Commit**

```bash
git add nodus/src/protocol/nodus_tier2.c nodus/src/protocol/nodus_tier2.h
git commit -m "feat(nodus): include received_at in ch_post_notify"
```

---

## Phase 2 (Faz 2): Ring Management

### Task 2.1: Add ring_check / ring_ack / ring_evict protocol messages

**Files:**
- Modify: `nodus/src/protocol/nodus_tier2.h` — add encode/decode for ring_check, ring_ack, ring_evict
- Modify: `nodus/src/protocol/nodus_tier2.c` — implement encode/decode

**Step 1: Add encode functions**

```c
/* Ring management (Nodus → Nodus, TCP 4002) */
int nodus_t2_ring_check(uint32_t txn,
                          const nodus_key_t *node_id,
                          const uint8_t ch_uuid[NODUS_UUID_BYTES],
                          const char *status,  /* "dead" or "alive" */
                          uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ring_ack(uint32_t txn,
                        const uint8_t ch_uuid[NODUS_UUID_BYTES],
                        bool agree,
                        uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ring_evict(uint32_t txn,
                          const uint8_t ch_uuid[NODUS_UUID_BYTES],
                          uint32_t version,
                          uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_ring_changed(uint32_t txn,
                               const uint8_t ch_uuid[NODUS_UUID_BYTES],
                               uint32_t version,
                               uint8_t *buf, size_t cap, size_t *out_len);
```

**Step 2: Implement, build, test, commit**

---

### Task 2.2: Implement ring management logic in server

**Files:**
- Create: `nodus/src/channel/nodus_ring_mgmt.h` — ring management API
- Create: `nodus/src/channel/nodus_ring_mgmt.c` — ring_check initiation, ring_ack handling, ring_evict
- Modify: `nodus/src/server/nodus_server.c` — dispatch ring_check/ring_ack/ring_evict on inter_tcp
- Modify: `nodus/src/server/nodus_server.h` — include ring management header

**Key logic:**
- On PBFT tick: if a node goes DEAD → initiate ring_check to peer for all channels where that node is responsible
- On ring_ack(agree=true) → update hashring, write new responsible set to DHT, send ring_evict to replacement node
- On ring_ack(agree=false) → no change, retry on next tick

---

### Task 2.3: DHT self-announcement for channel discovery

**Files:**
- Modify: `nodus/src/channel/nodus_ring_mgmt.c` — add `ring_announce_to_dht()` function
- Modify: `nodus/src/server/nodus_server.c` — call announcement on channel create and ring change

**Key logic:**
- DHT key = `SHA3-512("dna:channel:nodes:" + channel_uuid)`
- Value = CBOR `{"version": N, "nodes": [{ip, port, node_id}, ...]}`
- Written on channel create and on every ring version change
- Uses nodus's own DHT PUT (server is also a DHT node)

---

### Task 2.4: ch_ring_changed client notification

**Files:**
- Modify: `nodus/src/server/nodus_server.c` — send ch_ring_changed to connected 4003 clients when this node loses responsibility

**Key logic:**
- When this node receives ring_evict → iterate ch_sessions, send ch_ring_changed to subscribers of that channel
- Client SDK should handle this notification in its read thread

---

## Phase 3 (Faz 3): Testing & Stabilization

### Task 3.1: Add unit tests for TCP 4003 channel operations

**Files:**
- Create: `nodus/tests/test_channel_port.c` — tests for channel auth, post, subscribe, notify over TCP 4003
- Modify: `nodus/CMakeLists.txt` — add test target

### Task 3.2: Add unit tests for ring management

**Files:**
- Create: `nodus/tests/test_ring_mgmt.c` — tests for ring_check/ring_ack flow, ring_evict, DHT announcement
- Modify: `nodus/CMakeLists.txt` — add test target

### Task 3.3: Integration test — multi-node channel replication

**Step 1:** Start 3 nodus instances locally with different ports
**Step 2:** Create channel on node 1 via CLI
**Step 3:** Post via node 1, verify replication to nodes 2+3
**Step 4:** Subscribe on node 2, post on node 1, verify notification arrives on node 2

### Task 3.4: Verify hinted handoff works with new schema

**Step 1:** Post with one backup down
**Step 2:** Bring backup up
**Step 3:** Verify hinted handoff delivers the missed post within 30s

### Task 3.5: Deploy to production cluster

Deploy updated nodus to all 6 production nodes:
```bash
# For each node:
ssh root@<IP> "git -C /opt/dna pull && systemctl stop nodus && make -C /opt/dna/nodus/build -j4 && cp /opt/dna/nodus/build/nodus-server /usr/local/bin/nodus-server && systemctl start nodus"
```

Open TCP 4003 in firewall on all 6 nodes.

---

## Phase 4 (Faz 4): Messenger Migration

### Task 4.1: Add channel connection API to nodus client SDK

**Files:**
- Modify: `nodus/include/nodus/nodus.h` — add `nodus_ch_conn_t`, `nodus_channel_connect/disconnect`
- Modify: `nodus/src/client/nodus_client.c` — implement channel connection (separate TCP 4003 connection)

**Key design:** `nodus_ch_conn_t` is a lightweight connection struct that wraps a single TCP 4003 connection with auth. Multiple channel subscriptions can share one connection to the same nodus.

### Task 4.2: Add multi-connection management to nodus_ops

**Files:**
- Modify: `messenger/dht/shared/nodus_ops.h` — add channel connection pool API
- Modify: `messenger/dht/shared/nodus_ops.c` — connection pool: channel_uuid → nodus_ch_conn_t mapping

### Task 4.3: Migrate dna_engine_channels.c from DHT to native channels

**Files:**
- Modify: `messenger/src/api/engine/dna_engine_channels.c` — switch from `dna_channel_*` (DHT) to `nodus_ops` channel connection API

**Key change:** Replace DHT PUT/GET based channel operations with direct TCP 4003 calls via nodus_ops wrappers. This means:
- `dna_channel_create` → `nodus_ops_ch_create` (TCP 4003)
- `dna_channel_post_create` → `nodus_ops_ch_post` (TCP 4003)
- `dna_channel_posts_get` → `nodus_ops_ch_get_posts` (TCP 4003, with since_timestamp)
- Subscribe/unsubscribe → `nodus_ops_ch_subscribe/unsubscribe` (TCP 4003)

### Task 4.4: Update Flutter channel provider

**Files:**
- Modify: `messenger/dna_messenger_flutter/lib/providers/channel_provider.dart` — update to use received_at for sync cursor instead of seq_id

### Task 4.5: Remove channel ops from TCP 4001 dispatch (Phase 3 of design)

**Files:**
- Modify: `nodus/src/server/nodus_server.c` — remove ch_create, ch_post, ch_get, ch_sub, ch_unsub from 4001 dispatch
- Modify: `nodus/src/server/nodus_server.h` — remove ch_subs from `nodus_session_t`

**WARNING:** This is a breaking change. Only do this AFTER all clients have migrated to TCP 4003.

---

## Version Bumps

After Phase 1 completion:
- Nodus: bump PATCH in `nodus/include/nodus/nodus_types.h`

After Phase 4 completion:
- Messenger C lib: bump PATCH in `messenger/include/dna/version.h`
- Flutter app: bump PATCH in `messenger/dna_messenger_flutter/pubspec.yaml`

---

## Documentation Updates (Checkpoint 7)

After each phase, update:
- `nodus/docs/` — deployment docs with port 4003
- `messenger/docs/DNA_NODUS.md` — new port, channel connection model
- `messenger/docs/P2P_ARCHITECTURE.md` — channel connection topology
- `messenger/docs/functions/dht.md` — updated channel function signatures
