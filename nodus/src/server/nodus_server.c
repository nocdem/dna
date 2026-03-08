/**
 * Nodus v5 — Server Core Implementation
 *
 * Dual-transport event loop: UDP (Kademlia) + TCP (data + clients).
 * Handles: auth, PUT, GET, GET_ALL, LISTEN, PING, and Kademlia routing.
 */

#include "server/nodus_server.h"
#include "channel/nodus_replication.h"
#include "consensus/nodus_pbft.h"
#include "protocol/nodus_tier1.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_sign.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

/* Response buffer (shared, single-threaded).
 * Must accommodate max value (1MB data) + Dilithium5 pk(2592) + sig(4627) + CBOR.
 * Previous 64KB was too small — values >55KB data caused silent GET failures. */
#define RESP_BUF_SIZE (NODUS_MAX_VALUE_SIZE + 65536)
static uint8_t resp_buf[RESP_BUF_SIZE];

/* ── Session management ──────────────────────────────────────────── */

static nodus_session_t *session_for_conn(nodus_server_t *srv,
                                          nodus_tcp_conn_t *conn) {
    if (!conn || conn->slot < 0 || conn->slot >= NODUS_MAX_SESSIONS)
        return NULL;
    return &srv->sessions[conn->slot];
}

static void session_clear(nodus_session_t *sess) {
    memset(sess, 0, sizeof(*sess));
}

static bool session_check_token(nodus_session_t *sess, const uint8_t *token) {
    if (!sess->authenticated || !token) return false;
    return memcmp(sess->token, token, NODUS_SESSION_TOKEN_LEN) == 0;
}

/* ── Rate limiting ───────────────────────────────────────────────── */

static bool rate_check_put(nodus_session_t *sess) {
    uint64_t now = nodus_time_now();
    if (now - sess->rate_window_start >= 60) {
        sess->rate_window_start = now;
        sess->puts_in_window = 0;
    }
    if (sess->puts_in_window >= NODUS_RATE_PUTS_PER_MIN)
        return false;
    sess->puts_in_window++;
    return true;
}

/* ── LISTEN subscription management ─────────────────────────────── */

static int session_add_listen(nodus_session_t *sess, const nodus_key_t *key) {
    /* Check duplicate */
    for (int i = 0; i < sess->listen_count; i++) {
        if (nodus_key_cmp(&sess->listen_keys[i], key) == 0)
            return 0;  /* Already listening */
    }
    if (sess->listen_count >= NODUS_MAX_LISTEN_KEYS)
        return -1;
    sess->listen_keys[sess->listen_count++] = *key;
    return 0;
}

static void session_remove_listen(nodus_session_t *sess, const nodus_key_t *key) {
    for (int i = 0; i < sess->listen_count; i++) {
        if (nodus_key_cmp(&sess->listen_keys[i], key) == 0) {
            sess->listen_keys[i] = sess->listen_keys[--sess->listen_count];
            return;
        }
    }
}

/** Notify all sessions listening on this key */
static void notify_listeners(nodus_server_t *srv, const nodus_key_t *key,
                              const nodus_value_t *val) {
    for (int i = 0; i < NODUS_MAX_SESSIONS; i++) {
        nodus_session_t *s = &srv->sessions[i];
        if (!s->conn || !s->authenticated) continue;

        for (int j = 0; j < s->listen_count; j++) {
            if (nodus_key_cmp(&s->listen_keys[j], key) == 0) {
                size_t len = 0;
                if (nodus_t2_value_changed(0, key, val,
                        resp_buf, sizeof(resp_buf), &len) == 0) {
                    nodus_tcp_send(s->conn, resp_buf, len);
                }
                break;
            }
        }
    }
}

/* ── Channel subscription management ─────────────────────────────── */

static int ch_session_add_sub(nodus_session_t *sess,
                               const uint8_t uuid[NODUS_UUID_BYTES]) {
    for (int i = 0; i < sess->ch_sub_count; i++) {
        if (memcmp(sess->ch_subs[i], uuid, NODUS_UUID_BYTES) == 0)
            return 0;  /* Already subscribed */
    }
    if (sess->ch_sub_count >= NODUS_MAX_CH_SUBS)
        return -1;
    memcpy(sess->ch_subs[sess->ch_sub_count++], uuid, NODUS_UUID_BYTES);
    return 0;
}

static void ch_session_remove_sub(nodus_session_t *sess,
                                    const uint8_t uuid[NODUS_UUID_BYTES]) {
    for (int i = 0; i < sess->ch_sub_count; i++) {
        if (memcmp(sess->ch_subs[i], uuid, NODUS_UUID_BYTES) == 0) {
            memcpy(sess->ch_subs[i],
                   sess->ch_subs[--sess->ch_sub_count], NODUS_UUID_BYTES);
            return;
        }
    }
}

/** Notify all sessions subscribed to a channel about a new post */
static void notify_ch_subscribers(nodus_server_t *srv,
                                    const uint8_t uuid[NODUS_UUID_BYTES],
                                    const nodus_channel_post_t *post) {
    for (int i = 0; i < NODUS_MAX_SESSIONS; i++) {
        nodus_session_t *s = &srv->sessions[i];
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

/* ── Server-to-server TCP STORE (with hinted handoff on failure) ── */

/**
 * Send a pre-encoded wire frame to a peer. Returns 0 on success, -1 on failure.
 */
static int send_frame_to_peer(const char *peer_ip, uint16_t peer_tcp_port,
                               const uint8_t *frame, size_t flen) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        fprintf(stderr, "DHT-REPL: socket() failed for %s:%d: %s\n",
                peer_ip, peer_tcp_port, strerror(errno));
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(peer_tcp_port);
    inet_pton(AF_INET, peer_ip, &addr.sin_addr);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        fprintf(stderr, "DHT-REPL: connect %s:%d failed: %s\n",
                peer_ip, peer_tcp_port, strerror(errno));
        close(fd);
        return -1;
    }

    /* Wait for connect (2s timeout) — use poll() instead of select()
     * because select() crashes when fd >= FD_SETSIZE (1024) */
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    rc = poll(&pfd, 1, 2000);
    if (rc <= 0) {
        fprintf(stderr, "DHT-REPL: connect timeout %s:%d\n", peer_ip, peer_tcp_port);
        close(fd);
        return -1;
    }

    int err = 0;
    socklen_t errlen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
    if (err != 0) {
        fprintf(stderr, "DHT-REPL: connect error %s:%d: %s\n",
                peer_ip, peer_tcp_port, strerror(err));
        close(fd);
        return -1;
    }

    /* Blocking send with 2s timeout */
    int flags_save = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags_save & ~O_NONBLOCK);
    struct timeval stv = { .tv_sec = 2 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &stv, sizeof(stv));

    ssize_t sent = send(fd, frame, flen, MSG_NOSIGNAL);
    close(fd);

    if (sent < 0 || (size_t)sent != flen) {
        fprintf(stderr, "DHT-REPL: send failed %s:%d: sent=%zd/%zu: %s\n",
                peer_ip, peer_tcp_port, sent, flen, strerror(errno));
        return -1;
    }

    return 0;
}

static void replicate_value(nodus_server_t *srv, const nodus_value_t *val) {
    /* Encode T1 STORE_VALUE once for all peers */
    uint8_t *cbor_buf = malloc(RESP_BUF_SIZE);
    if (!cbor_buf) return;
    size_t clen = 0;
    if (nodus_t1_store_value(0, val, cbor_buf, RESP_BUF_SIZE, &clen) != 0) {
        free(cbor_buf);
        return;
    }

    /* Wire-frame it */
    uint8_t *frame = malloc(clen + 16);
    if (!frame) { free(cbor_buf); return; }
    size_t flen = nodus_frame_encode(frame, clen + 16, cbor_buf, (uint32_t)clen);
    free(cbor_buf);
    if (flen == 0) { free(frame); return; }

    /* Replicate to K-closest nodes via Kademlia routing table */
    nodus_peer_t closest[NODUS_K];
    int count = nodus_routing_find_closest(&srv->routing, &val->key_hash,
                                            closest, NODUS_K);

    for (int i = 0; i < count; i++) {
        /* Skip self */
        if (nodus_key_cmp(&closest[i].node_id, &srv->identity.node_id) == 0)
            continue;

        int rc = send_frame_to_peer(closest[i].ip, closest[i].tcp_port, frame, flen);
        if (rc != 0) {
            /* Queue to hinted handoff for retry (keyed by node_id) */
            nodus_storage_hinted_insert(&srv->storage,
                                         &closest[i].node_id,
                                         closest[i].ip, closest[i].tcp_port,
                                         frame, flen);
        }
    }

    free(frame);
}

/**
 * Retry DHT hinted handoff entries every NODUS_HINTED_RETRY_SEC seconds.
 * For each ALIVE PBFT peer, query pending hints, attempt send, delete on success.
 */
static void dht_hinted_retry(nodus_server_t *srv) {
    static uint64_t last_retry = 0;
    uint64_t now = nodus_time_now();

    if (now - last_retry < NODUS_HINTED_RETRY_SEC)
        return;
    last_retry = now;

    /* Cleanup expired entries first */
    nodus_storage_hinted_cleanup(&srv->storage);

    /* Query distinct node_ids with pending hints */
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(srv->storage.db,
            "SELECT DISTINCT node_id FROM dht_hinted_handoff WHERE expires_at > ?",
            -1, &stmt, NULL) != SQLITE_OK)
        return;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(stmt, 0);
        int blob_len = sqlite3_column_bytes(stmt, 0);
        if (!blob || blob_len != NODUS_KEY_BYTES) continue;

        nodus_key_t node_id;
        memcpy(node_id.bytes, blob, NODUS_KEY_BYTES);

        /* Look up current IP:Port in routing table (node may have migrated) */
        nodus_peer_t peer;
        const char *ip;
        uint16_t tcp_port;
        if (nodus_routing_lookup(&srv->routing, &node_id, &peer) == 0) {
            ip = peer.ip;
            tcp_port = peer.tcp_port;
        } else {
            /* Not in routing table — skip until rediscovered */
            continue;
        }

        nodus_dht_hint_t *entries = NULL;
        size_t count = 0;
        if (nodus_storage_hinted_get(&srv->storage, &node_id,
                                       100, &entries, &count) != 0 || count == 0)
            continue;

        for (size_t j = 0; j < count; j++) {
            int rc = send_frame_to_peer(ip, tcp_port,
                                         entries[j].frame_data,
                                         entries[j].frame_len);
            if (rc == 0) {
                nodus_storage_hinted_delete(&srv->storage, entries[j].id);
            }
        }

        nodus_storage_hinted_free(entries, count);
    }

    sqlite3_finalize(stmt);
}

/* ── Kademlia bucket refresh ──────────────────────────────────────── */

static void dht_bucket_refresh(nodus_server_t *srv) {
    static uint64_t last_refresh = 0;
    uint64_t now = nodus_time_now();
    if (now - last_refresh < NODUS_BUCKET_REFRESH_SEC) return;
    last_refresh = now;

    for (int b = 0; b < NODUS_BUCKETS; b++) {
        const nodus_bucket_t *bucket = &srv->routing.buckets[b];
        if (bucket->count == 0) continue;

        /* Skip recently active buckets */
        bool fresh = false;
        for (int e = 0; e < bucket->count && !fresh; e++) {
            if (bucket->entries[e].active &&
                bucket->entries[e].peer.last_seen > 0 &&
                now - bucket->entries[e].peer.last_seen < NODUS_BUCKET_REFRESH_SEC)
                fresh = true;
        }
        if (fresh) continue;

        /* Find first active entry to query */
        const nodus_peer_t *target = NULL;
        for (int e = 0; e < bucket->count; e++) {
            if (bucket->entries[e].active) {
                target = &bucket->entries[e].peer;
                break;
            }
        }
        if (!target) continue;

        /* Generate random key in this bucket's range and send FIND_NODE */
        nodus_key_t random_key;
        nodus_key_random_in_bucket(&random_key, &srv->identity.node_id, b);

        uint8_t buf[512];
        size_t len = 0;
        nodus_t1_find_node(0, &random_key, buf, sizeof(buf), &len);
        uint8_t frame[512 + 16];
        size_t flen = nodus_frame_encode(frame, sizeof(frame), buf, (uint32_t)len);
        if (flen > 0)
            nodus_udp_send(&srv->udp, frame, flen, target->ip, target->udp_port);
    }
}

/* ── Storage cleanup timer ───────────────────────────────────────── */

static void dht_storage_cleanup(nodus_server_t *srv) {
    static uint64_t last_cleanup = 0;
    uint64_t now = nodus_time_now();
    if (now - last_cleanup < NODUS_CLEANUP_SEC) return;
    last_cleanup = now;

    int cleaned = nodus_storage_cleanup(&srv->storage);
    if (cleaned > 0)
        fprintf(stderr, "DHT-CLEANUP: removed %d expired values\n", cleaned);
}

/* ── Periodic republish (non-blocking) ───────────────────────────── */

/** Clean up a single republish connection */
static void rp_conn_cleanup(nodus_server_t *srv, dht_republish_conn_t *rc) {
    if (!rc->active) return;
    if (rc->fd >= 0) {
        epoll_ctl(srv->rp_epoll_fd, EPOLL_CTL_DEL, rc->fd, NULL);
        close(rc->fd);
        rc->fd = -1;
    }
    free(rc->frame);
    rc->frame = NULL;
    rc->active = false;
    srv->republish.pending_fds--;
}

/** Handle epoll events for republish connections */
static void dht_republish_handle_events(nodus_server_t *srv) {
    if (srv->rp_epoll_fd < 0) return;

    struct epoll_event events[32];
    int n = epoll_wait(srv->rp_epoll_fd, events, 32, 0);

    for (int i = 0; i < n; i++) {
        int fd = events[i].data.fd;
        /* Find the connection entry */
        dht_republish_conn_t *rc = NULL;
        for (int j = 0; j < NODUS_REPUBLISH_MAX_FDS; j++) {
            if (srv->republish.conns[j].active && srv->republish.conns[j].fd == fd) {
                rc = &srv->republish.conns[j];
                break;
            }
        }
        if (!rc) continue;

        if (events[i].events & (EPOLLERR | EPOLLHUP)) {
            rp_conn_cleanup(srv, rc);
            continue;
        }

        if (events[i].events & EPOLLOUT) {
            if (!rc->connected) {
                /* Check connect result */
                int err = 0;
                socklen_t elen = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
                if (err != 0) {
                    rp_conn_cleanup(srv, rc);
                    continue;
                }
                rc->connected = true;
            }

            /* Send remaining data */
            while (rc->send_pos < rc->frame_len) {
                ssize_t sent = send(fd, rc->frame + rc->send_pos,
                                     rc->frame_len - rc->send_pos, MSG_NOSIGNAL);
                if (sent < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    rp_conn_cleanup(srv, rc);
                    goto next_event;
                }
                rc->send_pos += (size_t)sent;
            }

            if (rc->send_pos >= rc->frame_len) {
                /* Send complete — fire and forget */
                rp_conn_cleanup(srv, rc);
            }
        }
        next_event:;
    }
}

/** Check for timed-out republish connections (2s timeout) */
static void dht_republish_timeout_check(nodus_server_t *srv) {
    uint64_t now_ms = nodus_time_now_ms();
    for (int i = 0; i < NODUS_REPUBLISH_MAX_FDS; i++) {
        dht_republish_conn_t *rc = &srv->republish.conns[i];
        if (rc->active && now_ms - rc->started_at > 2000)
            rp_conn_cleanup(srv, rc);
    }
}

/** Start a non-blocking fire-and-forget send to a peer */
static void dht_republish_send_async(nodus_server_t *srv, const char *ip,
                                       uint16_t port, const uint8_t *frame,
                                       size_t flen) {
    /* Find free connection slot */
    dht_republish_conn_t *rc = NULL;
    for (int i = 0; i < NODUS_REPUBLISH_MAX_FDS; i++) {
        if (!srv->republish.conns[i].active) {
            rc = &srv->republish.conns[i];
            break;
        }
    }
    if (!rc) return;  /* All slots full */

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == 0) {
        /* Immediate connect (localhost) — send and close */
        send(fd, frame, flen, MSG_NOSIGNAL);
        close(fd);
        return;
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return;
    }

    /* Set up connection tracking */
    memset(rc, 0, sizeof(*rc));
    rc->fd = fd;
    rc->frame = malloc(flen);
    if (!rc->frame) { close(fd); return; }
    memcpy(rc->frame, frame, flen);
    rc->frame_len = flen;
    rc->send_pos = 0;
    rc->started_at = nodus_time_now_ms();
    rc->active = true;
    rc->connected = false;
    srv->republish.pending_fds++;

    /* Register with republish epoll */
    struct epoll_event ev;
    ev.events = EPOLLOUT | EPOLLET;
    ev.data.fd = fd;
    epoll_ctl(srv->rp_epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}

/** Main republish tick — fetch batch, send to K-closest, manage connections */
static void dht_republish(nodus_server_t *srv) {
    dht_republish_state_t *rs = &srv->republish;
    uint64_t now = nodus_time_now();

    /* Handle in-flight connections */
    dht_republish_handle_events(srv);
    dht_republish_timeout_check(srv);

    if (!rs->active) {
        /* Start new cycle every NODUS_REPUBLISH_SEC */
        if (now - rs->cycle_start < NODUS_REPUBLISH_SEC) return;
        memset(&rs->last_key, 0, sizeof(rs->last_key));
        rs->active = true;
        rs->first_batch = true;
        rs->cycle_start = now;
    }

    /* Don't fetch more if too many sends in flight */
    if (rs->pending_fds >= NODUS_REPUBLISH_MAX_FDS) return;

    /* Fetch BATCH values using bookmark pagination */
    nodus_value_t *batch[NODUS_REPUBLISH_BATCH];
    int fetched = nodus_storage_fetch_batch(&srv->storage,
                                             rs->first_batch ? NULL : &rs->last_key,
                                             batch, NODUS_REPUBLISH_BATCH);
    rs->first_batch = false;

    for (int i = 0; i < fetched; i++) {
        nodus_value_t *val = batch[i];

        /* Encode frame once for all peers */
        uint8_t *cbor_buf = malloc(RESP_BUF_SIZE);
        if (!cbor_buf) { nodus_value_free(val); continue; }
        size_t clen = 0;
        if (nodus_t1_store_value(0, val, cbor_buf, RESP_BUF_SIZE, &clen) != 0) {
            free(cbor_buf); nodus_value_free(val); continue;
        }
        uint8_t *frame = malloc(clen + 16);
        if (!frame) { free(cbor_buf); nodus_value_free(val); continue; }
        size_t flen = nodus_frame_encode(frame, clen + 16, cbor_buf, (uint32_t)clen);
        free(cbor_buf);

        if (flen == 0) { free(frame); nodus_value_free(val); continue; }

        nodus_peer_t closest[NODUS_K];
        int n = nodus_routing_find_closest(&srv->routing, &val->key_hash, closest, NODUS_K);

        for (int j = 0; j < n; j++) {
            if (nodus_key_cmp(&closest[j].node_id, &srv->identity.node_id) == 0) continue;
            if (rs->pending_fds >= NODUS_REPUBLISH_MAX_FDS) break;
            dht_republish_send_async(srv, closest[j].ip, closest[j].tcp_port, frame, flen);
        }

        rs->last_key = val->key_hash;
        free(frame);
        nodus_value_free(val);
    }

    /* Cycle complete if fewer rows than batch size */
    if (fetched < NODUS_REPUBLISH_BATCH) {
        rs->active = false;
        rs->cycle_start = nodus_time_now();
    }
}

/* ── Tier 2 message handlers (Client -> Nodus) ──────────────────── */

static void handle_t2_put(nodus_server_t *srv, nodus_session_t *sess,
                           nodus_tier2_msg_t *msg) {
    if (!rate_check_put(sess)) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_RATE_LIMITED,
                        "too many puts", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    /* Create value from message fields + authenticated session identity */
    nodus_value_t *val = NULL;
    int rc = nodus_value_create(&msg->key, msg->data, msg->data_len,
                                 msg->val_type, msg->ttl,
                                 msg->vid, msg->seq,
                                 &sess->client_pk, &val);
    if (rc != 0 || !val) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "value creation failed", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    /* Apply the client-provided signature */
    memcpy(val->signature.bytes, msg->sig.bytes, NODUS_SIG_BYTES);

    /* Verify signature */
    if (nodus_value_verify(val) != 0) {
        nodus_value_free(val);
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INVALID_SIGNATURE,
                        "value signature invalid", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    /* Store (seq check — skip if existing value has higher seq) */
    rc = nodus_storage_put_if_newer(&srv->storage, val);
    if (rc < 0) {
        nodus_value_free(val);
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "storage error", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    /* Notify listeners */
    notify_listeners(srv, &msg->key, val);

    /* Replicate to alive PBFT peers via TCP STORE */
    replicate_value(srv, val);

    /* Respond OK */
    size_t len = 0;
    nodus_t2_put_ok(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);

    nodus_value_free(val);
}

/* ── FIND_VALUE async state machine ──────────────────────────────── */

/** Check if a node_id has already been visited in this lookup */
static bool fv_is_visited(dht_fv_lookup_t *lookup, const nodus_key_t *node_id) {
    for (int i = 0; i < lookup->visited_count; i++) {
        if (nodus_key_cmp(&lookup->visited[i], node_id) == 0)
            return true;
    }
    return false;
}

/** Add a node_id to the visited set */
static void fv_mark_visited(dht_fv_lookup_t *lookup, const nodus_key_t *node_id) {
    if (lookup->visited_count < NODUS_K * 4)
        lookup->visited[lookup->visited_count++] = *node_id;
}

/** Clean up a single FV query: close fd, free buffers, clear fd table */
static void fv_query_cleanup(nodus_server_t *srv, dht_fv_lookup_t *lookup, int qi) {
    dht_fv_query_t *q = &lookup->queries[qi];
    if (q->fd >= 0) {
        epoll_ctl(srv->fv_epoll_fd, EPOLL_CTL_DEL, q->fd, NULL);
        close(q->fd);
        if (q->fd < NODUS_FV_FD_TABLE_SIZE) {
            srv->fv_fd_table[q->fd].lookup_idx = -1;
            srv->fv_fd_table[q->fd].query_idx = -1;
        }
        q->fd = -1;
    }
    free(q->send_buf);
    q->send_buf = NULL;
    free(q->recv_buf);
    q->recv_buf = NULL;
}

/** Clean up an entire FV lookup */
static void fv_lookup_cleanup(nodus_server_t *srv, dht_fv_lookup_t *lookup) {
    for (int q = 0; q < NODUS_ALPHA; q++)
        fv_query_cleanup(srv, lookup, q);
    free(lookup->result_buf);
    lookup->result_buf = NULL;
    lookup->active = false;
}

/** Send the FV lookup result (or empty) back to the client */
static void fv_send_result(nodus_server_t *srv, dht_fv_lookup_t *lookup) {
    nodus_session_t *sess = &srv->sessions[lookup->session_slot];
    if (!sess->conn) return;  /* Client disconnected */

    if (lookup->found && lookup->result_buf && lookup->result_len > 0) {
        nodus_tcp_send(sess->conn, lookup->result_buf, lookup->result_len);
    } else {
        size_t len = 0;
        nodus_t2_result_empty(lookup->txn_id, resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
    }
}

/** Start a single outgoing FV query to a peer */
static int fv_query_start(nodus_server_t *srv, dht_fv_lookup_t *lookup,
                           int qi, const nodus_peer_t *peer) {
    dht_fv_query_t *q = &lookup->queries[qi];
    memset(q, 0, sizeof(*q));
    q->fd = -1;

    /* Create non-blocking socket */
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    if (fd >= NODUS_FV_FD_TABLE_SIZE) {
        close(fd);
        return -1;
    }

    /* Build fv request frame */
    uint8_t cbor_buf[256];
    size_t cbor_len = 0;
    if (nodus_t1_find_value(0, &lookup->key_hash, cbor_buf, sizeof(cbor_buf), &cbor_len) != 0) {
        close(fd);
        return -1;
    }

    uint8_t frame_buf[256 + 16];
    size_t flen = nodus_frame_encode(frame_buf, sizeof(frame_buf),
                                      cbor_buf, (uint32_t)cbor_len);
    if (flen == 0) {
        close(fd);
        return -1;
    }

    q->send_buf = malloc(flen);
    if (!q->send_buf) { close(fd); return -1; }
    memcpy(q->send_buf, frame_buf, flen);
    q->send_len = flen;
    q->send_pos = 0;

    q->recv_cap = NODUS_MAX_VALUE_SIZE + 65536;
    q->recv_buf = malloc(q->recv_cap);
    if (!q->recv_buf) { free(q->send_buf); q->send_buf = NULL; close(fd); return -1; }
    q->recv_len = 0;

    /* Connect (non-blocking) */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(peer->tcp_port);
    inet_pton(AF_INET, peer->ip, &addr.sin_addr);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        free(q->send_buf); q->send_buf = NULL;
        free(q->recv_buf); q->recv_buf = NULL;
        close(fd);
        return -1;
    }

    q->fd = fd;
    q->state = FV_QUERY_CONNECTING;
    q->node_id = peer->node_id;
    snprintf(q->ip, sizeof(q->ip), "%s", peer->ip);
    q->tcp_port = peer->tcp_port;
    q->started_at = nodus_time_now_ms();

    /* Register with FV epoll */
    struct epoll_event ev;
    ev.events = EPOLLOUT | EPOLLET;
    ev.data.fd = fd;
    epoll_ctl(srv->fv_epoll_fd, EPOLL_CTL_ADD, fd, &ev);

    /* Register in fd table */
    int li = (int)(lookup - srv->fv_state.lookups);
    srv->fv_fd_table[fd].lookup_idx = li;
    srv->fv_fd_table[fd].query_idx = qi;

    /* Mark visited */
    fv_mark_visited(lookup, &peer->node_id);

    lookup->queries_pending++;
    return 0;
}

/** Start up to NODUS_ALPHA queries for the current round */
static void fv_start_round(nodus_server_t *srv, dht_fv_lookup_t *lookup) {
    int started = 0;
    for (int c = 0; c < lookup->candidate_count && started < NODUS_ALPHA; c++) {
        if (fv_is_visited(lookup, &lookup->candidates[c].node_id))
            continue;

        /* Find free query slot */
        int qi = -1;
        for (int q = 0; q < NODUS_ALPHA; q++) {
            if (lookup->queries[q].fd < 0 &&
                lookup->queries[q].state == FV_QUERY_DONE) {
                qi = q;
                break;
            }
        }
        /* Try uninitialized slots (fd == 0 from memset but state == 0 == CONNECTING) */
        if (qi < 0) {
            for (int q = 0; q < NODUS_ALPHA; q++) {
                if (lookup->queries[q].fd <= 0 && lookup->queries[q].send_buf == NULL) {
                    qi = q;
                    break;
                }
            }
        }
        if (qi < 0) break;

        if (fv_query_start(srv, lookup, qi, &lookup->candidates[c]) == 0)
            started++;
    }
}

/**
 * Start a FIND_VALUE lookup for a key not found locally.
 * Returns 0 if lookup started, -1 if no slots available.
 */
static int dht_find_value_start(nodus_server_t *srv, nodus_session_t *sess,
                                 uint32_t txn_id, const nodus_key_t *key) {
    /* Find free slot */
    int slot = -1;
    for (int i = 0; i < NODUS_FV_MAX_INFLIGHT; i++) {
        if (!srv->fv_state.lookups[i].active) {
            slot = i;
            break;
        }
    }
    if (slot < 0) return -1;

    dht_fv_lookup_t *lookup = &srv->fv_state.lookups[slot];
    memset(lookup, 0, sizeof(*lookup));
    lookup->active = true;
    lookup->key_hash = *key;
    lookup->txn_id = txn_id;
    lookup->session_slot = (int)(sess - srv->sessions);
    lookup->started_at = nodus_time_now_ms();
    lookup->round = 0;

    /* Initialize query fds to -1 */
    for (int q = 0; q < NODUS_ALPHA; q++)
        lookup->queries[q].fd = -1;

    /* Seed candidates from routing table */
    lookup->candidate_count = nodus_routing_find_closest(
        &srv->routing, key, lookup->candidates, NODUS_K * 4);

    if (lookup->candidate_count == 0) {
        lookup->active = false;
        return -1;  /* No peers known */
    }

    /* Start first round of queries */
    fv_start_round(srv, lookup);

    if (lookup->queries_pending == 0) {
        lookup->active = false;
        return -1;  /* No queries could be started */
    }

    return 0;
}

/** Handle epoll events for FV query fds */
static void dht_find_value_handle_event(nodus_server_t *srv, int fd, uint32_t events) {
    if (fd < 0 || fd >= NODUS_FV_FD_TABLE_SIZE) return;
    int li = srv->fv_fd_table[fd].lookup_idx;
    int qi = srv->fv_fd_table[fd].query_idx;
    if (li < 0 || li >= NODUS_FV_MAX_INFLIGHT) return;
    if (qi < 0 || qi >= NODUS_ALPHA) return;

    dht_fv_lookup_t *lookup = &srv->fv_state.lookups[li];
    if (!lookup->active) return;
    dht_fv_query_t *q = &lookup->queries[qi];

    if (events & (EPOLLERR | EPOLLHUP)) {
        q->state = FV_QUERY_DONE;
        fv_query_cleanup(srv, lookup, qi);
        lookup->queries_pending--;
        return;
    }

    if (events & EPOLLOUT) {
        if (q->state == FV_QUERY_CONNECTING) {
            /* Check connect result */
            int err = 0;
            socklen_t len = sizeof(err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err != 0) {
                q->state = FV_QUERY_DONE;
                fv_query_cleanup(srv, lookup, qi);
                lookup->queries_pending--;
                return;
            }
            q->state = FV_QUERY_SENDING;
        }

        if (q->state == FV_QUERY_SENDING) {
            while (q->send_pos < q->send_len) {
                ssize_t sent = send(fd, q->send_buf + q->send_pos,
                                     q->send_len - q->send_pos, MSG_NOSIGNAL);
                if (sent < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    q->state = FV_QUERY_DONE;
                    fv_query_cleanup(srv, lookup, qi);
                    lookup->queries_pending--;
                    return;
                }
                q->send_pos += (size_t)sent;
            }

            if (q->send_pos >= q->send_len) {
                /* Sending complete, switch to receiving */
                q->state = FV_QUERY_RECEIVING;
                struct epoll_event ev;
                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = fd;
                epoll_ctl(srv->fv_epoll_fd, EPOLL_CTL_MOD, fd, &ev);
            }
        }
    }

    if (events & EPOLLIN) {
        if (q->state == FV_QUERY_RECEIVING) {
            while (q->recv_len < q->recv_cap) {
                ssize_t got = recv(fd, q->recv_buf + q->recv_len,
                                    q->recv_cap - q->recv_len, 0);
                if (got < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    q->state = FV_QUERY_DONE;
                    fv_query_cleanup(srv, lookup, qi);
                    lookup->queries_pending--;
                    return;
                }
                if (got == 0) break;  /* Peer closed */
                q->recv_len += (size_t)got;
            }

            /* Try to decode a frame */
            nodus_frame_t frame;
            int frc = nodus_frame_decode(q->recv_buf, q->recv_len, &frame);
            if (frc > 0) {
                /* Got complete frame — decode T1 response */
                nodus_tier1_msg_t t1msg;
                memset(&t1msg, 0, sizeof(t1msg));
                if (nodus_t1_decode(frame.payload, frame.payload_len, &t1msg) == 0) {
                    if (t1msg.has_value && t1msg.value) {
                        /* Value found! Encode T2 result for client */
                        lookup->found = true;
                        lookup->result_buf = malloc(RESP_BUF_SIZE);
                        if (lookup->result_buf) {
                            size_t rlen = 0;
                            if (nodus_t2_result(lookup->txn_id, t1msg.value,
                                                 lookup->result_buf, RESP_BUF_SIZE, &rlen) == 0) {
                                lookup->result_len = rlen;
                            } else {
                                lookup->found = false;
                                free(lookup->result_buf);
                                lookup->result_buf = NULL;
                            }
                        }
                        /* Cache locally */
                        if (t1msg.value)
                            nodus_storage_put_if_newer(&srv->storage, t1msg.value);
                    } else {
                        /* No value — add returned closer nodes to candidates */
                        for (int p = 0; p < t1msg.peer_count; p++) {
                            if (fv_is_visited(lookup, &t1msg.peers[p].node_id))
                                continue;
                            if (lookup->candidate_count < NODUS_K * 4)
                                lookup->candidates[lookup->candidate_count++] = t1msg.peers[p];
                        }
                    }
                }
                nodus_t1_msg_free(&t1msg);

                q->state = FV_QUERY_DONE;
                fv_query_cleanup(srv, lookup, qi);
                lookup->queries_pending--;
            }
        }
    }
}

/** Poll FV epoll and advance state machines (called from main loop) */
static void dht_find_value_tick(nodus_server_t *srv) {
    if (srv->fv_epoll_fd < 0) return;

    /* Poll FV epoll with 0 timeout (non-blocking) */
    struct epoll_event events[32];
    int n = epoll_wait(srv->fv_epoll_fd, events, 32, 0);
    for (int i = 0; i < n; i++)
        dht_find_value_handle_event(srv, events[i].data.fd, events[i].events);

    uint64_t now_ms = nodus_time_now_ms();

    /* Check all active lookups */
    for (int li = 0; li < NODUS_FV_MAX_INFLIGHT; li++) {
        dht_fv_lookup_t *lookup = &srv->fv_state.lookups[li];
        if (!lookup->active) continue;

        /* Check client disconnect */
        nodus_session_t *sess = &srv->sessions[lookup->session_slot];
        if (!sess->conn) {
            fv_lookup_cleanup(srv, lookup);
            continue;
        }

        /* Overall timeout */
        if (now_ms - lookup->started_at > NODUS_FV_TIMEOUT_MS) {
            fv_send_result(srv, lookup);
            fv_lookup_cleanup(srv, lookup);
            continue;
        }

        /* Per-query timeouts */
        for (int qi = 0; qi < NODUS_ALPHA; qi++) {
            dht_fv_query_t *q = &lookup->queries[qi];
            if (q->fd >= 0 && q->state != FV_QUERY_DONE) {
                if (now_ms - q->started_at > NODUS_FV_QUERY_TIMEOUT_MS) {
                    q->state = FV_QUERY_DONE;
                    fv_query_cleanup(srv, lookup, qi);
                    lookup->queries_pending--;
                }
            }
        }

        /* Check if value found */
        if (lookup->found) {
            fv_send_result(srv, lookup);
            fv_lookup_cleanup(srv, lookup);
            continue;
        }

        /* If all queries done, try next round */
        if (lookup->queries_pending == 0) {
            lookup->round++;
            if (lookup->round < 3) {
                fv_start_round(srv, lookup);
                if (lookup->queries_pending > 0)
                    continue;  /* New round started */
            }

            /* Exhausted — send empty */
            fv_send_result(srv, lookup);
            fv_lookup_cleanup(srv, lookup);
        }
    }
}

static void handle_t2_get(nodus_server_t *srv, nodus_session_t *sess,
                           nodus_tier2_msg_t *msg) {
    nodus_value_t *val = NULL;
    int rc = nodus_storage_get(&srv->storage, &msg->key, &val);

    if (rc == 0 && val) {
        size_t len = 0;
        if (nodus_t2_result(msg->txn_id, val, resp_buf, sizeof(resp_buf), &len) == 0) {
            nodus_tcp_send(sess->conn, resp_buf, len);
        } else {
            fprintf(stderr, "NODUS_SRV: GET result encode failed (value too large?)\n");
            nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                            "value encode failed", resp_buf, sizeof(resp_buf), &len);
            nodus_tcp_send(sess->conn, resp_buf, len);
        }
        nodus_value_free(val);
    } else {
        /* Value not found locally — start async FIND_VALUE lookup */
        if (dht_find_value_start(srv, sess, msg->txn_id, &msg->key) != 0) {
            /* No slots or no peers — return empty immediately */
            size_t len = 0;
            nodus_t2_result_empty(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
            nodus_tcp_send(sess->conn, resp_buf, len);
        }
        /* Response sent later by dht_find_value_tick() */
    }
}

static void handle_t2_get_all(nodus_server_t *srv, nodus_session_t *sess,
                               nodus_tier2_msg_t *msg) {
    nodus_value_t **vals = NULL;
    size_t count = 0;
    int rc = nodus_storage_get_all(&srv->storage, &msg->key, &vals, &count);

    if (rc == 0 && count > 0) {
        size_t len = 0;
        if (nodus_t2_result_multi(msg->txn_id, vals, count,
                                   resp_buf, sizeof(resp_buf), &len) == 0) {
            nodus_tcp_send(sess->conn, resp_buf, len);
        } else {
            fprintf(stderr, "NODUS_SRV: GET_ALL result encode failed (values too large?)\n");
            nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                            "value encode failed", resp_buf, sizeof(resp_buf), &len);
            nodus_tcp_send(sess->conn, resp_buf, len);
        }

        for (size_t i = 0; i < count; i++)
            nodus_value_free(vals[i]);
        free(vals);
    } else {
        size_t len = 0;
        nodus_t2_result_empty(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
    }
}

static void handle_t2_listen(nodus_server_t *srv, nodus_session_t *sess,
                              nodus_tier2_msg_t *msg) {
    if (session_add_listen(sess, &msg->key) != 0) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_RATE_LIMITED,
                        "too many listeners", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    size_t len = 0;
    nodus_t2_listen_ok(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);
}

static void handle_t2_unlisten(nodus_server_t *srv, nodus_session_t *sess,
                                nodus_tier2_msg_t *msg) {
    (void)srv;
    session_remove_listen(sess, &msg->key);

    uint8_t resp_buf[256];
    size_t len = 0;
    nodus_t2_listen_ok(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);
}

static void handle_t2_ping(nodus_server_t *srv, nodus_session_t *sess,
                            nodus_tier2_msg_t *msg) {
    (void)srv;
    size_t len = 0;
    nodus_t2_pong(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);
}

static void handle_t2_servers(nodus_server_t *srv, nodus_session_t *sess,
                                nodus_tier2_msg_t *msg) {
    /* Build server info list: self + alive PBFT peers */
    nodus_t2_server_info_t infos[NODUS_PBFT_MAX_PEERS + 1];
    int count = 0;

    /* Self first */
    memset(&infos[count], 0, sizeof(infos[0]));
    snprintf(infos[count].ip, sizeof(infos[0].ip), "%s",
             srv->config.bind_ip[0] ? srv->config.bind_ip : "0.0.0.0");
    infos[count].tcp_port = srv->config.tcp_port;
    count++;

    /* Alive peers */
    for (int i = 0; i < srv->pbft.peer_count && count < NODUS_PBFT_MAX_PEERS + 1; i++) {
        if (srv->pbft.peers[i].state != NODUS_NODE_ALIVE) continue;
        memset(&infos[count], 0, sizeof(infos[0]));
        snprintf(infos[count].ip, sizeof(infos[0].ip), "%s", srv->pbft.peers[i].ip);
        infos[count].tcp_port = srv->pbft.peers[i].tcp_port;
        count++;
    }

    size_t len = 0;
    nodus_t2_servers_result(msg->txn_id, infos, count,
                             resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);
}

/* ── Channel handlers ────────────────────────────────────────────── */

static void handle_t2_ch_create(nodus_server_t *srv, nodus_session_t *sess,
                                  nodus_tier2_msg_t *msg) {
    int rc = nodus_channel_create(&srv->ch_store, msg->channel_uuid);
    if (rc != 0) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "channel create failed", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    size_t len = 0;
    nodus_t2_ch_create_ok(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);
}

static void handle_t2_ch_post(nodus_server_t *srv, nodus_session_t *sess,
                                nodus_tier2_msg_t *msg) {
    /* Rate limit channel posts (same window as DHT puts) */
    if (!rate_check_put(sess)) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_RATE_LIMITED,
                        "too many posts", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    /* Verify channel exists */
    if (!nodus_channel_exists(&srv->ch_store, msg->channel_uuid)) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_CHANNEL_NOT_FOUND,
                        "channel not found", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    /* Check body size */
    if (msg->data_len > NODUS_MAX_POST_BODY) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_TOO_LARGE,
                        "post body too large", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    /* Build post */
    nodus_channel_post_t post;
    memset(&post, 0, sizeof(post));
    memcpy(post.channel_uuid, msg->channel_uuid, NODUS_UUID_BYTES);
    memcpy(post.post_uuid, msg->post_uuid_ch, NODUS_UUID_BYTES);
    post.author_fp = sess->client_fp;
    post.timestamp = msg->ch_timestamp;
    post.body = (char *)msg->data;  /* Borrowed, not freed here */
    post.body_len = msg->data_len;
    memcpy(post.signature.bytes, msg->sig.bytes, NODUS_SIG_BYTES);

    int rc = nodus_channel_post(&srv->ch_store, &post);

    if (rc < 0) {
        post.body = NULL;  /* msg owns the data */
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "post failed", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    /* rc=1 means duplicate — still respond with OK (idempotent) */
    size_t len = 0;
    nodus_t2_ch_post_ok(msg->txn_id, post.seq_id,
                          resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);

    /* Notify subscribers and replicate (only for new posts, not duplicates) */
    if (rc == 0) {
        notify_ch_subscribers(srv, msg->channel_uuid, &post);
        nodus_replication_send(&srv->replication, msg->channel_uuid, &post);
    }

    post.body = NULL;  /* msg owns the data — prevent double-free */
}

static void handle_t2_ch_get_posts(nodus_server_t *srv, nodus_session_t *sess,
                                     nodus_tier2_msg_t *msg) {
    if (!nodus_channel_exists(&srv->ch_store, msg->channel_uuid)) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_CHANNEL_NOT_FOUND,
                        "channel not found", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    nodus_channel_post_t *posts = NULL;
    size_t count = 0;
    uint32_t since = (uint32_t)msg->seq;
    int max = msg->ch_max_count > 0 ? msg->ch_max_count : 100;

    int rc = nodus_channel_get_posts(&srv->ch_store, msg->channel_uuid,
                                       since, max, &posts, &count);
    if (rc != 0) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "get posts failed", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    size_t len = 0;
    nodus_t2_ch_posts(msg->txn_id, posts, count,
                       resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);
    nodus_channel_posts_free(posts, count);
}

static void handle_t2_ch_subscribe(nodus_server_t *srv, nodus_session_t *sess,
                                     nodus_tier2_msg_t *msg) {
    if (!nodus_channel_exists(&srv->ch_store, msg->channel_uuid)) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_CHANNEL_NOT_FOUND,
                        "channel not found", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    if (ch_session_add_sub(sess, msg->channel_uuid) != 0) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_RATE_LIMITED,
                        "too many channel subscriptions",
                        resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    size_t len = 0;
    nodus_t2_ch_sub_ok(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);
}

static void handle_t2_ch_unsubscribe(nodus_server_t *srv, nodus_session_t *sess,
                                       nodus_tier2_msg_t *msg) {
    (void)srv;
    ch_session_remove_sub(sess, msg->channel_uuid);

    uint8_t resp_buf[256];
    size_t len = 0;
    nodus_t2_ch_sub_ok(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);
}

/* ── TCP frame dispatch ──────────────────────────────────────────── */

static void dispatch_t2(nodus_server_t *srv, nodus_session_t *sess,
                          const uint8_t *payload, size_t len) {
    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    if (nodus_t2_decode(payload, len, &msg) != 0) {
        nodus_t2_msg_free(&msg);

        /* Fallback: try T1 decode for inter-node messages (STORE, etc.) */
        nodus_tier1_msg_t t1msg;
        memset(&t1msg, 0, sizeof(t1msg));
        if (nodus_t1_decode(payload, len, &t1msg) == 0 &&
            strcmp(t1msg.method, "sv") == 0 && t1msg.value) {
            if (nodus_value_verify(t1msg.value) == 0) {
                if (nodus_storage_put_if_newer(&srv->storage, t1msg.value) == 0)
                    notify_listeners(srv, &t1msg.value->key_hash, t1msg.value);
            }
        }
        nodus_t1_msg_free(&t1msg);
        return;
    }

    /* Pre-auth: hello, auth, w_* (witness BFT), and inter-nodus ch_rep allowed */
    if (!sess->authenticated) {
        /* Tier 3: Witness BFT messages (self-authenticated via wsig) */
        if (strncmp(msg.method, "w_", 2) == 0 && srv->witness) {
            nodus_witness_dispatch_t3(srv->witness, sess->conn, payload, len);
            nodus_t2_msg_free(&msg);
            return;
        }

        if (strcmp(msg.method, "hello") == 0) {
            nodus_auth_handle_hello(srv, sess, &msg.pk, &msg.fp, msg.txn_id);
        } else if (strcmp(msg.method, "auth") == 0) {
            nodus_auth_handle_auth(srv, sess, &msg.sig, msg.txn_id);
        } else if (strcmp(msg.method, "sv") == 0) {
            /* Inter-nodus DHT value replication (no auth required, rate-limited) */
            static uint64_t sv_window_start = 0;
            static int sv_count = 0;
            uint64_t sv_now = nodus_time_now();
            if (sv_now != sv_window_start) { sv_window_start = sv_now; sv_count = 0; }
            if (++sv_count > NODUS_SV_MAX_PER_SEC) {
                nodus_t2_msg_free(&msg);
                return;  /* Drop — rate limited */
            }

            nodus_tier1_msg_t t1msg;
            memset(&t1msg, 0, sizeof(t1msg));
            if (nodus_t1_decode(payload, len, &t1msg) == 0 &&
                t1msg.value && nodus_value_verify(t1msg.value) == 0) {
                int put_rc = nodus_storage_put_if_newer(&srv->storage, t1msg.value);
                if (put_rc == 0) {
                    notify_listeners(srv, &t1msg.value->key_hash, t1msg.value);
                    fprintf(stderr, "REPL-RX: stored replicated value\n");
                } else if (put_rc == 1) {
                    fprintf(stderr, "REPL-RX: skipped (existing seq >= incoming)\n");
                }
            }
            nodus_t1_msg_free(&t1msg);
            nodus_t2_msg_free(&msg);
            return;
        } else if (strcmp(msg.method, "fv") == 0) {
            /* Inter-nodus FIND_VALUE (no auth required, rate-limited) */
            static uint64_t fv_window_start = 0;
            static int fv_count = 0;
            uint64_t fv_now = nodus_time_now();
            if (fv_now != fv_window_start) { fv_window_start = fv_now; fv_count = 0; }
            if (++fv_count > NODUS_FV_MAX_PER_SEC) {
                nodus_t2_msg_free(&msg);
                return;  /* Drop — rate limited */
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
            /* Inter-nodus presence sync (no auth required) */
            if (msg.pq_fps && msg.pq_count > 0) {
                /* Determine peer_index from source IP */
                uint8_t pi = 0;
                if (sess->conn) {
                    for (int p = 0; p < srv->pbft.peer_count; p++) {
                        if (strcmp(srv->pbft.peers[p].ip, sess->conn->ip) == 0) {
                            pi = (uint8_t)(p + 1);
                            break;
                        }
                    }
                }
                if (pi > 0)
                    nodus_presence_merge_remote(srv, msg.pq_fps, msg.pq_count, pi);
            }
            nodus_t2_msg_free(&msg);
            return;
        } else if (strcmp(msg.method, "ch_rep") == 0) {
            /* Inter-nodus channel replication (no auth required) */
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
            /* received_at decoded as ch_timestamp if present, or use now */
            post.received_at = nodus_time_now();

            int rc = nodus_replication_receive(&srv->ch_store, &post);
            post.body = NULL;  /* msg owns data */

            size_t rlen = 0;
            if (rc >= 0) {
                nodus_t2_ch_rep_ok(msg.txn_id, resp_buf, sizeof(resp_buf), &rlen);
            } else {
                nodus_t2_error(msg.txn_id, NODUS_ERR_INTERNAL_ERROR,
                                "replication store failed",
                                resp_buf, sizeof(resp_buf), &rlen);
            }
            nodus_tcp_send(sess->conn, resp_buf, rlen);
        } else {
            size_t rlen = 0;
            nodus_t2_error(msg.txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                            "authenticate first", resp_buf, sizeof(resp_buf), &rlen);
            nodus_tcp_send(sess->conn, resp_buf, rlen);
        }
        nodus_t2_msg_free(&msg);
        return;
    }

    /* Post-auth: verify session token */
    if (msg.has_token && !session_check_token(sess, msg.token)) {
        size_t rlen = 0;
        nodus_t2_error(msg.txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                        "invalid token", resp_buf, sizeof(resp_buf), &rlen);
        nodus_tcp_send(sess->conn, resp_buf, rlen);
        nodus_t2_msg_free(&msg);
        return;
    }

    /* Witness BFT messages in post-auth path (peer may have authenticated) */
    if (strncmp(msg.method, "w_", 2) == 0 && srv->witness) {
        nodus_witness_dispatch_t3(srv->witness, sess->conn, payload, len);
        nodus_t2_msg_free(&msg);
        return;
    }

    /* DNAC client methods (post-auth, requires witness module) */
    if (strncmp(msg.method, "dnac_", 5) == 0) {
        if (srv->witness) {
            nodus_witness_dispatch_dnac(srv->witness, sess->conn,
                                         payload, len,
                                         msg.method, msg.txn_id);
        } else {
            size_t rlen = 0;
            nodus_t2_error(msg.txn_id, NODUS_ERR_PROTOCOL_ERROR,
                            "witness module not enabled",
                            resp_buf, sizeof(resp_buf), &rlen);
            nodus_tcp_send(sess->conn, resp_buf, rlen);
        }
        nodus_t2_msg_free(&msg);
        return;
    }

    /* Presence query (post-auth) */
    if (strcmp(msg.method, "pq") == 0) {
        if (msg.pq_fps && msg.pq_count > 0) {
            bool *online = calloc((size_t)msg.pq_count, sizeof(bool));
            uint8_t *peers = calloc((size_t)msg.pq_count, sizeof(uint8_t));
            uint64_t *last_seen = calloc((size_t)msg.pq_count, sizeof(uint64_t));
            if (online && peers && last_seen) {
                int pq_online = nodus_presence_query_batch(srv, msg.pq_fps, msg.pq_count,
                                                             online, peers, last_seen);
                fprintf(stderr, "PQ: queried %d fps, %d online (table has %d entries)\n",
                        msg.pq_count, pq_online, srv->presence.count);
                size_t rlen = 0;
                nodus_t2_presence_result(msg.txn_id, msg.pq_fps, online, peers, last_seen,
                                           msg.pq_count, resp_buf, sizeof(resp_buf), &rlen);
                nodus_tcp_send(sess->conn, resp_buf, rlen);
            }
            free(online);
            free(peers);
            free(last_seen);
        } else {
            /* Empty query → empty result */
            size_t rlen = 0;
            nodus_t2_presence_result(msg.txn_id, NULL, NULL, NULL, NULL, 0,
                                       resp_buf, sizeof(resp_buf), &rlen);
            nodus_tcp_send(sess->conn, resp_buf, rlen);
        }
        nodus_t2_msg_free(&msg);
        return;
    }

    /* Dispatch to handler */
    if (strcmp(msg.method, "put") == 0)
        handle_t2_put(srv, sess, &msg);
    else if (strcmp(msg.method, "get") == 0)
        handle_t2_get(srv, sess, &msg);
    else if (strcmp(msg.method, "get_all") == 0)
        handle_t2_get_all(srv, sess, &msg);
    else if (strcmp(msg.method, "listen") == 0)
        handle_t2_listen(srv, sess, &msg);
    else if (strcmp(msg.method, "unlisten") == 0)
        handle_t2_unlisten(srv, sess, &msg);
    else if (strcmp(msg.method, "ping") == 0)
        handle_t2_ping(srv, sess, &msg);
    else if (strcmp(msg.method, "servers") == 0)
        handle_t2_servers(srv, sess, &msg);
    else if (strcmp(msg.method, "ch_create") == 0)
        handle_t2_ch_create(srv, sess, &msg);
    else if (strcmp(msg.method, "ch_post") == 0)
        handle_t2_ch_post(srv, sess, &msg);
    else if (strcmp(msg.method, "ch_get") == 0)
        handle_t2_ch_get_posts(srv, sess, &msg);
    else if (strcmp(msg.method, "ch_sub") == 0)
        handle_t2_ch_subscribe(srv, sess, &msg);
    else if (strcmp(msg.method, "ch_unsub") == 0)
        handle_t2_ch_unsubscribe(srv, sess, &msg);
    else {
        size_t rlen = 0;
        nodus_t2_error(msg.txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "unknown method", resp_buf, sizeof(resp_buf), &rlen);
        nodus_tcp_send(sess->conn, resp_buf, rlen);
    }

    nodus_t2_msg_free(&msg);
}

/* ── Tier 1 UDP handler (Kademlia routing) ───────────────────────── */

static void handle_udp_message(const uint8_t *payload, size_t len,
                                const char *from_ip, uint16_t from_port,
                                void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;

    nodus_tier1_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    if (nodus_t1_decode(payload, len, &msg) != 0) {
        nodus_t1_msg_free(&msg);
        return;
    }

    if (strcmp(msg.method, "ping") == 0) {
        /* Respond with PONG */
        size_t rlen = 0;
        nodus_t1_pong(msg.txn_id, &srv->identity.node_id,
                       resp_buf, sizeof(resp_buf), &rlen);
        nodus_udp_send(&srv->udp, resp_buf, rlen, from_ip, from_port);

        /* Update routing table */
        nodus_peer_t peer;
        memset(&peer, 0, sizeof(peer));
        peer.node_id = msg.node_id;
        strncpy(peer.ip, from_ip, sizeof(peer.ip) - 1);
        peer.udp_port = from_port;
        peer.tcp_port = from_port + 1;  /* Convention: TCP = UDP + 1 */
        peer.last_seen = nodus_time_now();
        nodus_routing_insert(&srv->routing, &peer);

        /* FIX 0c: A received PING proves the peer is alive (same as PONG).
         * Without this, DEAD peers can never recover — permanent deadlock. */
        nodus_pbft_on_pong(&srv->pbft, &msg.node_id, from_ip, from_port);

    } else if (strcmp(msg.method, "pong") == 0) {
        /* Update routing table + PBFT health (IP-aware for seed discovery) */
        nodus_routing_touch(&srv->routing, &msg.node_id);
        nodus_pbft_on_pong(&srv->pbft, &msg.node_id, from_ip, from_port);

        /* Also insert into routing table if new */
        nodus_peer_t rpeer;
        memset(&rpeer, 0, sizeof(rpeer));
        rpeer.node_id = msg.node_id;
        strncpy(rpeer.ip, from_ip, sizeof(rpeer.ip) - 1);
        rpeer.udp_port = from_port;
        rpeer.tcp_port = from_port + 1;
        rpeer.last_seen = nodus_time_now();
        nodus_routing_insert(&srv->routing, &rpeer);

    } else if (strcmp(msg.method, "fn") == 0) {
        /* FIND_NODE: return k closest nodes */
        nodus_peer_t results[NODUS_K];
        int found = nodus_routing_find_closest(&srv->routing, &msg.target,
                                                results, NODUS_K);
        size_t rlen = 0;
        nodus_t1_nodes_found(msg.txn_id, results, found,
                              resp_buf, sizeof(resp_buf), &rlen);
        nodus_udp_send(&srv->udp, resp_buf, rlen, from_ip, from_port);

    } else if (strcmp(msg.method, "fn_r") == 0) {
        /* NODES_FOUND: add discovered peers to routing table */
        for (int i = 0; i < msg.peer_count; i++) {
            msg.peers[i].last_seen = nodus_time_now();
            nodus_routing_insert(&srv->routing, &msg.peers[i]);
        }

    } else if (strcmp(msg.method, "sv") == 0) {
        /* STORE_VALUE: inter-node replication */
        if (msg.value) {
            if (nodus_value_verify(msg.value) == 0) {
                if (nodus_storage_put_if_newer(&srv->storage, msg.value) == 0)
                    notify_listeners(srv, &msg.value->key_hash, msg.value);
            }
            /* Send ACK */
            size_t rlen = 0;
            nodus_t1_store_ack(msg.txn_id, resp_buf, sizeof(resp_buf), &rlen);
            nodus_udp_send(&srv->udp, resp_buf, rlen, from_ip, from_port);
        }

    } else if (strcmp(msg.method, "fv") == 0) {
        /* FIND_VALUE: respond with value or closest nodes */
        nodus_value_t *val = NULL;
        int rc = nodus_storage_get(&srv->storage, &msg.target, &val);

        size_t rlen = 0;
        if (rc == 0 && val) {
            nodus_t1_value_found(msg.txn_id, val, resp_buf, sizeof(resp_buf), &rlen);
            nodus_value_free(val);
        } else {
            nodus_peer_t results[NODUS_K];
            int found = nodus_routing_find_closest(&srv->routing, &msg.target,
                                                    results, NODUS_K);
            nodus_t1_value_not_found(msg.txn_id, results, found,
                                      resp_buf, sizeof(resp_buf), &rlen);
        }
        nodus_udp_send(&srv->udp, resp_buf, rlen, from_ip, from_port);
    }

    nodus_t1_msg_free(&msg);
}

/* ── TCP callbacks ───────────────────────────────────────────────── */

static void on_tcp_accept(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    nodus_session_t *sess = session_for_conn(srv, conn);
    if (sess) {
        session_clear(sess);
        sess->conn = conn;
    }
}

static void on_tcp_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                           size_t len, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    nodus_session_t *sess = session_for_conn(srv, conn);
    if (!sess) return;

    dispatch_t2(srv, sess, payload, len);
}

static void on_tcp_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    nodus_session_t *sess = session_for_conn(srv, conn);
    if (sess) {
        if (sess->authenticated)
            nodus_presence_remove_local(srv, &sess->client_fp);
        session_clear(sess);
    }

    /* Clear any witness peer references before conn is freed */
    if (srv->witness)
        nodus_witness_peer_conn_closed(srv->witness, conn);
}

/* ── Public API ──────────────────────────────────────────────────── */

int nodus_server_init(nodus_server_t *srv, const nodus_server_config_t *config) {
    if (!srv || !config) return -1;
    memset(srv, 0, sizeof(*srv));
    srv->config = *config;

    /* Initialize FV fd mapping table (all entries invalid) */
    for (int i = 0; i < NODUS_FV_FD_TABLE_SIZE; i++) {
        srv->fv_fd_table[i].lookup_idx = -1;
        srv->fv_fd_table[i].query_idx = -1;
    }

    /* Create FV epoll fd for FIND_VALUE async state machine */
    srv->fv_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (srv->fv_epoll_fd < 0) {
        fprintf(stderr, "Failed to create FV epoll fd\n");
        return -1;
    }

    /* Create republish epoll fd for non-blocking sends */
    srv->rp_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (srv->rp_epoll_fd < 0) {
        fprintf(stderr, "Failed to create republish epoll fd\n");
        return -1;
    }

    /* Load or generate identity */
    if (config->identity_path[0]) {
        if (nodus_identity_load(config->identity_path, &srv->identity) != 0) {
            fprintf(stderr, "Identity not found at %s, generating new\n",
                    config->identity_path);
            nodus_identity_generate(&srv->identity);
            nodus_identity_save(&srv->identity, config->identity_path);
        }
    } else {
        nodus_identity_generate(&srv->identity);
    }

    /* Open DHT storage */
    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/nodus.db",
             config->data_path[0] ? config->data_path : "/tmp");
    if (nodus_storage_open(db_path, &srv->storage) != 0) {
        fprintf(stderr, "Failed to open storage: %s\n", db_path);
        return -1;
    }

    /* Open channel storage */
    char ch_db_path[512];
    snprintf(ch_db_path, sizeof(ch_db_path), "%s/channels.db",
             config->data_path[0] ? config->data_path : "/tmp");
    if (nodus_channel_store_open(ch_db_path, &srv->ch_store) != 0) {
        fprintf(stderr, "Failed to open channel store: %s\n", ch_db_path);
        return -1;
    }

    /* Init routing table */
    nodus_routing_init(&srv->routing, &srv->identity.node_id);

    /* Init replication */
    nodus_replication_init(&srv->replication, srv);

    /* Init hash ring */
    nodus_hashring_init(&srv->ring);

    /* Init PBFT consensus (adds self to ring) */
    nodus_pbft_init(&srv->pbft, srv);

    /* Init TCP transport (own epoll) */
    if (nodus_tcp_init(&srv->tcp, -1) != 0)
        return -1;
    srv->tcp.on_accept = on_tcp_accept;
    srv->tcp.on_frame = on_tcp_frame;
    srv->tcp.on_disconnect = on_tcp_disconnect;
    srv->tcp.cb_ctx = srv;

    /* Init UDP transport (own epoll — udp_poll uses non-blocking recvfrom) */
    if (nodus_udp_init(&srv->udp, -1) != 0)
        return -1;
    srv->udp.on_recv = handle_udp_message;
    srv->udp.cb_ctx = srv;

    /* Bind TCP */
    if (nodus_tcp_listen(&srv->tcp, config->bind_ip, config->tcp_port) != 0) {
        fprintf(stderr, "Failed to listen on TCP %s:%d\n",
                config->bind_ip, config->tcp_port);
        return -1;
    }

    /* Bind UDP */
    if (nodus_udp_bind(&srv->udp, config->bind_ip, config->udp_port) != 0) {
        fprintf(stderr, "Failed to bind UDP %s:%d\n",
                config->bind_ip, config->udp_port);
        return -1;
    }

    /* Add seed nodes to PBFT cluster.
     * Seeds don't have node_ids yet — they'll be discovered via PING/PONG.
     * For now, create placeholder node_ids from IP hash. The real node_id
     * will be learned when the seed responds to our PING. */
    for (int i = 0; i < config->seed_count; i++) {
        nodus_key_t seed_id;
        nodus_hash((const uint8_t *)config->seed_nodes[i],
                    strlen(config->seed_nodes[i]), &seed_id);
        nodus_pbft_add_peer(&srv->pbft, &seed_id,
                              config->seed_nodes[i],
                              config->seed_ports[i],
                              config->seed_ports[i] + 1);  /* TCP = UDP + 1 */
    }

    /* Initialize witness module if enabled */
    if (config->witness.enabled) {
        srv->witness = calloc(1, sizeof(nodus_witness_t));
        if (!srv->witness) {
            fprintf(stderr, "Failed to allocate witness context\n");
            return -1;
        }
        if (nodus_witness_init(srv->witness, srv, &config->witness) != 0) {
            fprintf(stderr, "Witness module init failed\n");
            free(srv->witness);
            srv->witness = NULL;
            return -1;
        }
    }

    return 0;
}

int nodus_server_run(nodus_server_t *srv) {
    if (!srv) return -1;
    srv->running = true;

    fprintf(stderr, "Nodus v%s running\n", NODUS_VERSION_STRING);
    fprintf(stderr, "  Identity: %s\n", srv->identity.fingerprint);
    fprintf(stderr, "  TCP port: %d\n", srv->tcp.port);
    fprintf(stderr, "  UDP port: %d\n", srv->udp.port);

    while (srv->running) {
        /* Poll TCP events (which uses the shared epoll) */
        nodus_tcp_poll(&srv->tcp, 100);

        /* Process any pending UDP datagrams */
        nodus_udp_poll(&srv->udp);

        /* PBFT: send heartbeats, check peer health */
        nodus_pbft_tick(&srv->pbft);

        /* Witness BFT: timeout checks, peer reconnection */
        if (srv->witness)
            nodus_witness_tick(srv->witness);

        /* Retry hinted handoff (runs at most every NODUS_HINTED_RETRY_SEC) */
        nodus_replication_retry(&srv->replication);

        /* Presence: expire stale entries + broadcast local list to peers */
        nodus_presence_tick(srv);

        /* Retry DHT hinted handoff (failed replication, every 30s) */
        dht_hinted_retry(srv);

        /* FIND_VALUE async state machine tick */
        dht_find_value_tick(srv);

        /* Kademlia bucket refresh (every 15 min) */
        dht_bucket_refresh(srv);

        /* Storage cleanup — remove expired values (every 1 hour) */
        dht_storage_cleanup(srv);

        /* Periodic republish — send stored values to K-closest (every 1 hour) */
        dht_republish(srv);
    }

    return 0;
}

void nodus_server_stop(nodus_server_t *srv) {
    if (srv) srv->running = false;
}

void nodus_server_close(nodus_server_t *srv) {
    if (!srv) return;

    /* Clean up all active FV lookups */
    for (int i = 0; i < NODUS_FV_MAX_INFLIGHT; i++) {
        if (srv->fv_state.lookups[i].active)
            fv_lookup_cleanup(srv, &srv->fv_state.lookups[i]);
    }
    if (srv->fv_epoll_fd >= 0) {
        close(srv->fv_epoll_fd);
        srv->fv_epoll_fd = -1;
    }

    /* Clean up republish connections */
    for (int i = 0; i < NODUS_REPUBLISH_MAX_FDS; i++) {
        if (srv->republish.conns[i].active)
            rp_conn_cleanup(srv, &srv->republish.conns[i]);
    }
    if (srv->rp_epoll_fd >= 0) {
        close(srv->rp_epoll_fd);
        srv->rp_epoll_fd = -1;
    }

    if (srv->witness) {
        nodus_witness_close(srv->witness);
        free(srv->witness);
        srv->witness = NULL;
    }

    nodus_tcp_close(&srv->tcp);
    nodus_udp_close(&srv->udp);
    nodus_storage_close(&srv->storage);
    nodus_channel_store_close(&srv->ch_store);
    nodus_identity_clear(&srv->identity);
}
