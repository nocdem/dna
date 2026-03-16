# Separate Inter-Node TCP Port Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add TCP port 4002 for inter-node traffic, making port 4001 client-only. Fixes CRIT-1, HIGH-1, HIGH-2, HIGH-10.

**Architecture:** Second `nodus_tcp_t` instance shares the same epoll fd. Inter-node port gets its own dispatch function and lightweight session array (rate limiting only). The entire pre-auth inter-node block is removed from `dispatch_t2()`.

**Tech Stack:** C, epoll, CBOR, Nodus wire protocol

---

### Task 1: Add `NODUS_DEFAULT_PEER_PORT` and Config Field

**Files:**
- Modify: `nodus/include/nodus/nodus_types.h:52`
- Modify: `nodus/src/server/nodus_server.h:37-50`

**Step 1: Add constant to nodus_types.h**

After line 52 (`NODUS_DEFAULT_TCP_PORT`), add:

```c
#define NODUS_DEFAULT_PEER_PORT 4002
```

**Step 2: Add `peer_port` to config struct in nodus_server.h**

In `nodus_server_config_t` (line 37-50), after `tcp_port` (line 41), add:

```c
    uint16_t    peer_port;          /* Inter-node TCP port (default: 4002) */
```

**Step 3: Commit**

```bash
git add nodus/include/nodus/nodus_types.h nodus/src/server/nodus_server.h
git commit -m "feat(nodus): add NODUS_DEFAULT_PEER_PORT constant and config field"
```

---

### Task 2: Add Inter-Node Session Struct and Server Fields

**Files:**
- Modify: `nodus/src/server/nodus_server.h:54-83` (session), `181-224` (server)

**Step 1: Add lightweight inter-node session struct**

Before `nodus_session_t` (line 54), add:

```c
/* Inter-node session (lightweight — rate limiting only, no auth) */
typedef struct {
    nodus_tcp_conn_t   *conn;

    /* Per-session rate limiting */
    uint64_t            sv_window_start;
    int                 sv_count;
    uint64_t            fv_window_start;
    int                 fv_count;
    uint64_t            ps_window_start;
    int                 ps_count;
    uint64_t            cr_window_start;
    int                 cr_count;
} nodus_inter_session_t;

#define NODUS_MAX_INTER_SESSIONS  NODUS_TCP_MAX_CONNS
```

**Step 2: Add inter-node TCP + sessions to server struct**

In `nodus_server_t` (line 181-224), after `nodus_tcp_t tcp;` (line 189), add:

```c
    nodus_tcp_t             inter_tcp;      /* Inter-node TCP transport (port 4002) */
```

After `nodus_session_t sessions[NODUS_MAX_SESSIONS];` (line 209), add:

```c
    nodus_inter_session_t   inter_sessions[NODUS_MAX_INTER_SESSIONS];
```

**Step 3: Commit**

```bash
git add nodus/src/server/nodus_server.h
git commit -m "feat(nodus): add inter-node session struct and server fields"
```

---

### Task 3: Add `dispatch_inter()` and Inter-Node TCP Callbacks

**Files:**
- Modify: `nodus/src/server/nodus_server.c`

**Step 1: Add inter-node session helper**

After `session_for_conn()` (line 166-171), add:

```c
static nodus_inter_session_t *inter_session_for_conn(nodus_server_t *srv,
                                                      nodus_tcp_conn_t *conn) {
    if (!conn || conn->slot < 0 || conn->slot >= NODUS_MAX_INTER_SESSIONS)
        return NULL;
    return &srv->inter_sessions[conn->slot];
}

static void inter_session_clear(nodus_inter_session_t *sess) {
    memset(sess, 0, sizeof(*sess));
}
```

**Step 2: Add `dispatch_inter()` function**

Before `dispatch_t2()` (line 1582), add the new inter-node dispatch function. This contains the inter-node message handling logic currently in the pre-auth block of `dispatch_t2()`, but with per-session rate limiting:

```c
/* ── Inter-node frame dispatch (peer port) ──────────────────────── */

static void dispatch_inter(nodus_server_t *srv, nodus_inter_session_t *sess,
                            const uint8_t *payload, size_t len) {
    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    /* Try T2 decode first (p_sync, ch_rep, fv, w_*) */
    if (nodus_t2_decode(payload, len, &msg) == 0) {

        /* Tier 3: Witness BFT messages */
        if (strncmp(msg.method, "w_", 2) == 0 && srv->witness) {
            nodus_witness_dispatch_t3(srv->witness, sess->conn, payload, len);
            nodus_t2_msg_free(&msg);
            return;
        }

        if (strcmp(msg.method, "fv") == 0) {
            /* Inter-node FIND_VALUE (per-session rate limit) */
            uint64_t fv_now = nodus_time_now();
            if (fv_now != sess->fv_window_start) { sess->fv_window_start = fv_now; sess->fv_count = 0; }
            if (++sess->fv_count > NODUS_FV_MAX_PER_SEC) {
                nodus_t2_msg_free(&msg);
                return;
            }

            nodus_tier1_msg_t t1msg;
            memset(&t1msg, 0, sizeof(t1msg));
            if (nodus_t1_decode(payload, len, &t1msg) == 0) {
                nodus_value_t *val = NULL;
                int rc = nodus_storage_get(&srv->storage, &t1msg.target, &val);

                size_t rlen = 0;
                if (rc == 0 && val) {
                    nodus_t1_value_found(t1msg.txn_id, val,
                                          resp_buf, sizeof(resp_buf), &rlen);
                    nodus_value_free(val);
                } else {
                    nodus_peer_t results[NODUS_K];
                    int found = nodus_routing_find_closest(&srv->routing, &t1msg.target,
                                                            results, NODUS_K);
                    nodus_t1_value_not_found(t1msg.txn_id, results, found,
                                              resp_buf, sizeof(resp_buf), &rlen);
                }
                if (rlen > 0)
                    nodus_tcp_send(sess->conn, resp_buf, rlen);
            }
            nodus_t1_msg_free(&t1msg);
            nodus_t2_msg_free(&msg);
            return;

        } else if (strcmp(msg.method, "p_sync") == 0) {
            /* Inter-node presence sync (per-session rate limit) */
            uint64_t ps_now = nodus_time_now();
            if (ps_now != sess->ps_window_start) { sess->ps_window_start = ps_now; sess->ps_count = 0; }
            if (++sess->ps_count > 10) {
                nodus_t2_msg_free(&msg);
                return;
            }

            if (msg.pq_fps && msg.pq_count > 0 && sess->conn) {
                uint32_t h = 5381;
                for (const char *c = sess->conn->ip; *c; c++)
                    h = h * 33 + (uint8_t)*c;
                uint8_t pi = (uint8_t)(h % 254 + 1);
                nodus_presence_merge_remote(srv, msg.pq_fps, msg.pq_count, pi);
            }
            nodus_t2_msg_free(&msg);
            return;

        } else if (strcmp(msg.method, "ch_rep") == 0) {
            /* Inter-node channel replication (per-session rate limit) */
            uint64_t cr_now = nodus_time_now();
            if (cr_now != sess->cr_window_start) { sess->cr_window_start = cr_now; sess->cr_count = 0; }
            if (++sess->cr_count > NODUS_SV_MAX_PER_SEC) {
                nodus_t2_msg_free(&msg);
                return;
            }

            /* Verify ch_rep carries author public key (SECURITY: CRIT-01) */
            if (!msg.has_author_pk) {
                fprintf(stderr, "NODUS_SRV: ch_rep rejected — missing author pubkey\n");
                size_t rlen = 0;
                nodus_t2_error(msg.txn_id, NODUS_ERR_INVALID_SIGNATURE,
                                "missing author pubkey",
                                resp_buf, sizeof(resp_buf), &rlen);
                nodus_tcp_send(sess->conn, resp_buf, rlen);
                nodus_t2_msg_free(&msg);
                return;
            }

            nodus_key_t computed_fp;
            nodus_fingerprint(&msg.author_pk, &computed_fp);
            if (nodus_key_cmp(&computed_fp, &msg.fp) != 0) {
                fprintf(stderr, "NODUS_SRV: ch_rep rejected — pubkey/fingerprint mismatch\n");
                size_t rlen = 0;
                nodus_t2_error(msg.txn_id, NODUS_ERR_INVALID_SIGNATURE,
                                "pubkey fingerprint mismatch",
                                resp_buf, sizeof(resp_buf), &rlen);
                nodus_tcp_send(sess->conn, resp_buf, rlen);
                nodus_t2_msg_free(&msg);
                return;
            }

            nodus_channel_post_t post;
            memset(&post, 0, sizeof(post));
            memcpy(post.channel_uuid, msg.channel_uuid, NODUS_UUID_BYTES);
            post.seq_id = (uint32_t)msg.seq;
            memcpy(post.post_uuid, msg.post_uuid_ch, NODUS_UUID_BYTES);
            memcpy(post.author_fp.bytes, msg.fp.bytes, NODUS_KEY_BYTES);
            post.timestamp = msg.ch_timestamp;
            post.body = (char *)msg.data;
            post.body_len = msg.data_len;
            memcpy(post.signature.bytes, msg.sig.bytes, NODUS_SIG_BYTES);
            post.received_at = nodus_time_now();

            if (verify_channel_post_sig(&post, &msg.author_pk) != 0) {
                fprintf(stderr, "NODUS_SRV: ch_rep rejected — invalid post signature\n");
                post.body = NULL;
                size_t rlen = 0;
                nodus_t2_error(msg.txn_id, NODUS_ERR_INVALID_SIGNATURE,
                                "invalid post signature",
                                resp_buf, sizeof(resp_buf), &rlen);
                nodus_tcp_send(sess->conn, resp_buf, rlen);
                nodus_t2_msg_free(&msg);
                return;
            }

            int rc = nodus_replication_receive(&srv->ch_store, &post);
            post.body = NULL;

            size_t rlen = 0;
            if (rc >= 0) {
                nodus_t2_ch_rep_ok(msg.txn_id, resp_buf, sizeof(resp_buf), &rlen);
            } else {
                nodus_t2_error(msg.txn_id, NODUS_ERR_INTERNAL_ERROR,
                                "replication store failed",
                                resp_buf, sizeof(resp_buf), &rlen);
            }
            nodus_tcp_send(sess->conn, resp_buf, rlen);
            nodus_t2_msg_free(&msg);
            return;
        }

        /* Unknown T2 method on inter-node port — ignore */
        nodus_t2_msg_free(&msg);
        return;
    }
    nodus_t2_msg_free(&msg);

    /* Try T1 decode for STORE_VALUE replication */
    nodus_tier1_msg_t t1msg;
    memset(&t1msg, 0, sizeof(t1msg));
    if (nodus_t1_decode(payload, len, &t1msg) == 0 &&
        strcmp(t1msg.method, "sv") == 0 && t1msg.value) {

        /* Per-session rate limit */
        uint64_t sv_now = nodus_time_now();
        if (sv_now != sess->sv_window_start) { sess->sv_window_start = sv_now; sess->sv_count = 0; }
        if (++sess->sv_count > NODUS_SV_MAX_PER_SEC) {
            nodus_t1_msg_free(&t1msg);
            return;
        }

        if (nodus_value_verify(t1msg.value) == 0) {
            int put_rc = nodus_storage_put_if_newer(&srv->storage, t1msg.value);
            if (put_rc == 0) {
                notify_listeners(srv, &t1msg.value->key_hash, t1msg.value);
                fprintf(stderr, "REPL-RX: stored replicated value\n");
            } else if (put_rc == 1) {
                fprintf(stderr, "REPL-RX: skipped (existing seq >= incoming)\n");
            }
        }
    }
    nodus_t1_msg_free(&t1msg);
}
```

**Step 3: Add inter-node TCP callbacks**

After the existing `on_tcp_disconnect()` (around line 2015), add:

```c
/* ── Inter-node TCP callbacks ───────────────────────────────────── */

static void on_inter_accept(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    nodus_inter_session_t *sess = inter_session_for_conn(srv, conn);
    if (sess) {
        inter_session_clear(sess);
        sess->conn = conn;
    }
    conn->is_nodus = true;  /* All connections on peer port are inter-node */
}

static void on_inter_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                             size_t len, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    nodus_inter_session_t *sess = inter_session_for_conn(srv, conn);
    if (!sess) return;
    dispatch_inter(srv, sess, payload, len);
}

static void on_inter_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    nodus_inter_session_t *sess = inter_session_for_conn(srv, conn);
    if (sess) {
        inter_session_clear(sess);
    }
}
```

**Step 4: Commit**

```bash
git add nodus/src/server/nodus_server.c
git commit -m "feat(nodus): add dispatch_inter() and inter-node TCP callbacks"
```

---

### Task 4: Strip Pre-Auth Inter-Node Block from `dispatch_t2()`

**Files:**
- Modify: `nodus/src/server/nodus_server.c:1582-1779`

**Step 1: Replace the entire pre-auth block**

Replace lines 1587-1779 (the `if (nodus_t2_decode...) ... if (!sess->authenticated)` block) with this simplified version:

```c
    if (nodus_t2_decode(payload, len, &msg) != 0) {
        nodus_t2_msg_free(&msg);
        /* No T1 fallback on client port (SECURITY: CRIT-1 fix) */
        return;
    }

    /* Pre-auth: ONLY hello and auth allowed on client port */
    if (!sess->authenticated) {
        if (strcmp(msg.method, "hello") == 0) {
            nodus_auth_handle_hello(srv, sess, &msg.pk, &msg.fp, msg.txn_id);
        } else if (strcmp(msg.method, "auth") == 0) {
            nodus_auth_handle_auth(srv, sess, &msg.sig, msg.txn_id);
        } else {
            size_t rlen = 0;
            nodus_t2_error(msg.txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                            "authenticate first", resp_buf, sizeof(resp_buf), &rlen);
            nodus_tcp_send(sess->conn, resp_buf, rlen);
        }
        nodus_t2_msg_free(&msg);
        return;
    }
```

This deletes:
- The T1 fallback path (lines 1590-1602) — **fixes CRIT-1**
- The `sv` handler with global static rate limit (lines 1619-1644) — **fixes HIGH-2 for sv**
- The `fv` handler with global static rate limit (lines 1645-1679) — **fixes HIGH-2 for fv**
- The `p_sync` handler (lines 1680-1699) — **fixes HIGH-1 for p_sync**
- The `ch_rep` handler (lines 1700-1770) — **fixes HIGH-1 for ch_rep**
- The `w_*` handler (lines 1609-1612) — moved to `dispatch_inter()`

**Step 2: Build to verify compilation**

```bash
cd /opt/dna/nodus/build && cmake .. && make -j$(nproc)
```

Expected: Build succeeds. Some warnings about unused `static` vars `sv_window_start`/`sv_count`/`fv_window_start`/`fv_count` may appear if they were defined elsewhere — verify they were only in the deleted block.

**Step 3: Commit**

```bash
git add nodus/src/server/nodus_server.c
git commit -m "security(nodus): remove pre-auth inter-node block from client dispatch (CRIT-1, HIGH-1, HIGH-2)"
```

---

### Task 5: Initialize Inter-Node TCP in Server Init/Run/Close

**Files:**
- Modify: `nodus/src/server/nodus_server.c:2022-2238` (init, run, close)

**Step 1: Add inter-node TCP init in `nodus_server_init()`**

After the existing TCP init block (lines 2089-2095), add:

```c
    /* Init inter-node TCP transport (shares main TCP's epoll) */
    uint16_t peer_port = config->peer_port ? config->peer_port : NODUS_DEFAULT_PEER_PORT;
    if (nodus_tcp_init(&srv->inter_tcp, nodus_tcp_epoll_fd(&srv->tcp)) != 0)
        return -1;
    srv->inter_tcp.on_accept     = on_inter_accept;
    srv->inter_tcp.on_frame      = on_inter_frame;
    srv->inter_tcp.on_disconnect = on_inter_disconnect;
    srv->inter_tcp.cb_ctx        = srv;

    if (nodus_tcp_listen(&srv->inter_tcp, config->bind_ip, peer_port) != 0) {
        fprintf(stderr, "Failed to listen on inter-node TCP %s:%d\n",
                config->bind_ip, peer_port);
        return -1;
    }
```

**Step 2: Add peer port to startup log in `nodus_server_run()`**

After the existing TCP port log line (line 2155), add:

```c
    fprintf(stderr, "  Peer port: %d\n", srv->inter_tcp.port);
```

**Step 3: Add inter-node TCP close in `nodus_server_close()`**

After `nodus_tcp_close(&srv->tcp);` (line 2233), add:

```c
    nodus_tcp_close(&srv->inter_tcp);
```

**Step 4: Update presence sync to use inter_tcp for outbound connections**

In `nodus/src/server/nodus_presence.c`, the p_sync outbound connections (lines 253-268) currently use `srv->tcp`. Change to use `srv->inter_tcp`:

Replace all 4 occurrences of `&srv->tcp` in the p_sync send/cleanup loop (lines 254, 264, 278, 291) with `&srv->inter_tcp`:

- Line 254: `nodus_tcp_find_by_addr((nodus_tcp_t *)&srv->inter_tcp, ...)`
- Line 264: `nodus_tcp_connect((nodus_tcp_t *)&srv->inter_tcp, ...)`
- Line 278: `srv->inter_tcp.pool[i]`
- Line 291: `nodus_tcp_disconnect((nodus_tcp_t *)&srv->inter_tcp, c);`

**Step 5: Update `handle_t2_servers()` — keep returning client port**

The `handle_t2_servers()` function (line 1305-1336) returns `srv->config.tcp_port` and `srv->pbft.peers[i].tcp_port` to clients. Currently `pbft.peers[i].tcp_port` stores the peer's inter-node port. Clients need the CLIENT port.

For now, the PBFT peer struct's `tcp_port` will store the PEER port (4002). For the `servers` response, we assume client port = peer_port - 1 (convention: 4001 = 4002 - 1). Alternatively, keep reporting `srv->config.tcp_port` for self and for peers use the same `tcp_port - 1` convention. The cleaner approach is:

Change line 1328 from:
```c
        infos[count].tcp_port = srv->pbft.peers[i].tcp_port;
```
to:
```c
        infos[count].tcp_port = srv->pbft.peers[i].tcp_port - 1;  /* Client port = peer port - 1 */
```

This matches the existing convention at line 2128: `config->seed_ports[i] + 1` (TCP = UDP + 1), so: UDP=4000, client TCP=4001, peer TCP=4002.

**Step 6: Build and test**

```bash
cd /opt/dna/nodus/build && cmake .. && make -j$(nproc)
cd /opt/dna/nodus/build && ctest --output-on-failure
```

Expected: Build succeeds, 16/16 tests pass.

**Step 7: Commit**

```bash
git add nodus/src/server/nodus_server.c nodus/src/server/nodus_presence.c
git commit -m "feat(nodus): init inter-node TCP on peer_port, move p_sync to inter_tcp"
```

---

### Task 6: Update Config Parsing and nodus-server Main

**Files:**
- Modify: `nodus/tools/nodus-server.c`

**Step 1: Add `peer_port` to JSON config parsing**

In `load_config_json()` (line 62-114), after the `tcp_port` parsing (line 78-79), add:

```c
    if (json_object_object_get_ex(root, "peer_port", &val))
        cfg->peer_port = (uint16_t)json_object_get_int(val);
```

**Step 2: Add `-p` CLI flag for peer port**

Update `usage()` (line 32-43) — add line:
```c
    fprintf(stderr, "  -p <peer_port>    Inter-node TCP port (default: %d)\n", NODUS_DEFAULT_PEER_PORT);
```

Update `getopt` string from `"c:b:u:t:i:d:s:h"` to `"c:b:u:t:p:i:d:s:h"` in both getopt loops (lines 130, 173).

Add case in both switch blocks:
```c
            case 'p': config.peer_port = (uint16_t)atoi(optarg); break;
```

**Step 3: Set default peer_port**

After `config.tcp_port = NODUS_DEFAULT_TCP_PORT;` (line 124), add:
```c
    config.peer_port = NODUS_DEFAULT_PEER_PORT;
```

Same for the `file_cfg` defaults (line 161), add:
```c
        file_cfg.peer_port = NODUS_DEFAULT_PEER_PORT;
```

**Step 4: Update seed node TCP port convention**

In `nodus_server_init()` line 2128, the seed node TCP port is computed as `seed_ports[i] + 1`. Now the peer port should be `seed_ports[i] + 2`:

Change line 2128 from:
```c
                              config->seed_ports[i] + 1);  /* TCP = UDP + 1 */
```
to:
```c
                              config->seed_ports[i] + 2);  /* Peer TCP = UDP + 2 */
```

**Step 5: Build**

```bash
cd /opt/dna/nodus/build && cmake .. && make -j$(nproc)
```

**Step 6: Commit**

```bash
git add nodus/tools/nodus-server.c nodus/src/server/nodus_server.c
git commit -m "feat(nodus): add peer_port config parsing and CLI flag"
```

---

### Task 7: Update Production Config Files

**Files:**
- Modify: `/etc/nodus.conf` on all 6 production nodes (via SSH)

**Step 1: Add `peer_port` to each node's config**

Add this field to each node's `/etc/nodus.conf`:
```json
    "peer_port": 4002,
```

The config file on each node should look like:
```json
{
    "bind_ip": "0.0.0.0",
    "udp_port": 4000,
    "tcp_port": 4001,
    "peer_port": 4002,
    ...
}
```

**Step 2: Deploy updated binary to all 6 nodes**

Use the standard deploy pattern for each node:
```bash
ssh root@<IP> "git -C /opt/dna pull && systemctl stop nodus && make -C /opt/dna/nodus/build -j4 && cp /opt/dna/nodus/build/nodus-server /usr/local/bin/nodus-server && systemctl start nodus"
```

Nodes (deploy in order):
1. US-1: 154.38.182.161
2. EU-1: 164.68.105.227
3. EU-2: 164.68.116.180
4. EU-3: 161.97.85.25
5. EU-4: 156.67.24.125
6. EU-5: 156.67.25.251

**Step 3: Verify each node starts correctly**

```bash
ssh root@<IP> "journalctl -u nodus --no-pager -n 10"
```

Expected output includes:
```
Nodus v0.6.9 running
  Identity: ...
  TCP port: 4001
  Peer port: 4002
  UDP port: 4000
```

**Step 4: After all 6 nodes deployed, add firewall rules**

On each node, restrict peer port to only accept connections from the other 5 nodes:

```bash
# Allow peer port from cluster IPs only
iptables -A INPUT -p tcp --dport 4002 -s 154.38.182.161 -j ACCEPT
iptables -A INPUT -p tcp --dport 4002 -s 164.68.105.227 -j ACCEPT
iptables -A INPUT -p tcp --dport 4002 -s 164.68.116.180 -j ACCEPT
iptables -A INPUT -p tcp --dport 4002 -s 161.97.85.25 -j ACCEPT
iptables -A INPUT -p tcp --dport 4002 -s 156.67.24.125 -j ACCEPT
iptables -A INPUT -p tcp --dport 4002 -s 156.67.25.251 -j ACCEPT
iptables -A INPUT -p tcp --dport 4002 -j DROP
```

---

### Task 8: Version Bump and Final Build Verification

**Files:**
- Modify: `nodus/include/nodus/nodus_types.h:23-26`

**Step 1: Bump version**

Change:
```c
#define NODUS_VERSION_MINOR  6
#define NODUS_VERSION_PATCH  8
#define NODUS_VERSION_STRING "0.6.8"
```
to:
```c
#define NODUS_VERSION_MINOR  6
#define NODUS_VERSION_PATCH  9
#define NODUS_VERSION_STRING "0.6.9"
```

**Step 2: Full build**

```bash
cd /opt/dna/nodus/build && cmake .. && make -j$(nproc)
```

**Step 3: Run all tests**

```bash
cd /opt/dna/nodus/build && ctest --output-on-failure
```

Expected: 16/16 tests pass, zero warnings, zero errors.

**Step 4: Commit**

```bash
git add nodus/include/nodus/nodus_types.h
git commit -m "security: separate inter-node TCP port 4002, client-only port 4001 (CRIT-1, HIGH-1, HIGH-2) (v0.6.9)"
```

---

### Task 9: Update Documentation

**Files:**
- Modify: `nodus/docs/` (relevant docs)
- Modify: `docs/SECURITY_AUDIT_2026-03-12.md` (mark findings as fixed)

**Step 1: Update security audit report**

In the cross-reference table, add:
```
| CRIT-1 (T1 fallback auth bypass) | Fixed in v0.6.9 | Deleted T1 fallback from client port |
| HIGH-1 (no inter-node TCP auth) | Fixed in v0.6.9 | Separate peer port, firewalled |
| HIGH-2 (global sv/fv rate limits) | Fixed in v0.6.9 | Per-session rate limits in dispatch_inter |
| HIGH-10 (unauth Dilithium5 CPU) | Mitigated in v0.6.9 | Only reachable on firewalled peer port |
```

**Step 2: Commit**

```bash
git add docs/SECURITY_AUDIT_2026-03-12.md
git commit -m "docs: update security audit with v0.6.9 fixes"
```

---

### Task 10: Post-Deploy Verification

**Step 1: Send test messages**

From `chip` (this machine) and `punk` (chat1), send test messages to `nocdem` (phone) to verify messaging still works through the updated nodes.

```bash
# From this machine (chip):
/opt/dna/messenger/build/cli/dna-messenger-cli send nocdem "peer port test from chip"

# From chat1 (punk):
ssh nocdem@192.168.0.195 "/opt/dna/messenger/build/cli/dna-messenger-cli send nocdem 'peer port test from punk'"
```

**Step 2: Verify inter-node replication**

Check that p_sync is working on the new peer port:
```bash
ssh root@154.38.182.161 "journalctl -u nodus --no-pager -n 50 | grep P_SYNC"
```

Expected: `P_SYNC: broadcast ... to .../... routing peers` lines showing successful presence sync.

**Step 3: Verify no connections on port 4002 from non-peers**

```bash
ssh root@154.38.182.161 "ss -tn sport = :4002"
```

Expected: Only connections from the other 5 cluster IPs.
