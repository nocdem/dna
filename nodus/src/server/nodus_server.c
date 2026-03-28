/**
 * Nodus — Server Core Implementation
 *
 * Dual-transport event loop: UDP (Kademlia) + TCP (data + clients).
 * Handles: auth, PUT, GET, GET_ALL, LISTEN, PING, and Kademlia routing.
 */

#include "server/nodus_server.h"
#include "channel/nodus_channel_server.h"
#include "channel/nodus_channel_replication.h"
#include "channel/nodus_channel_ring.h"
#include "consensus/nodus_cluster.h"
#include "protocol/nodus_tier1.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_sign.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
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

/* Channel post signature verification is now in nodus_channel_primary.c */

/* Forward declaration for async send (used in replicate_value and hinted_retry) */
static void dht_republish_send_async(nodus_server_t *srv, const char *ip,
                                       uint16_t port, const uint8_t *frame,
                                       size_t flen);

/* ── Session management ──────────────────────────────────────────── */

static nodus_session_t *session_for_conn(nodus_server_t *srv,
                                          nodus_tcp_conn_t *conn) {
    if (!conn || conn->slot < 0 || conn->slot >= NODUS_MAX_SESSIONS)
        return NULL;
    return &srv->sessions[conn->slot];
}

static nodus_inter_session_t *inter_session_for_conn(nodus_server_t *srv,
                                                      nodus_tcp_conn_t *conn) {
    if (!conn || conn->slot < 0 || conn->slot >= NODUS_MAX_INTER_SESSIONS)
        return NULL;
    return &srv->inter_sessions[conn->slot];
}

static void inter_session_clear(nodus_inter_session_t *sess) {
    memset(sess, 0, sizeof(*sess));
}

static void session_clear(nodus_session_t *sess) {
    memset(sess, 0, sizeof(*sess));
}

static bool session_check_token(nodus_session_t *sess, const uint8_t *token) {
    if (!sess->authenticated || !token) return false;
    /* Constant-time comparison to prevent timing side-channel (HIGH-11) */
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < NODUS_SESSION_TOKEN_LEN; i++)
        diff |= sess->token[i] ^ token[i];
    return diff == 0;
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
    /* HIGH-5 fix: use per-operation heap buffer instead of shared static resp_buf
     * to avoid reentrancy risk when iterating sessions */
    uint8_t *notify_buf = malloc(RESP_BUF_SIZE);
    if (!notify_buf) return;

    for (int i = 0; i < NODUS_MAX_SESSIONS; i++) {
        nodus_session_t *s = &srv->sessions[i];
        if (!s->conn || !s->authenticated) continue;

        for (int j = 0; j < s->listen_count; j++) {
            if (nodus_key_cmp(&s->listen_keys[j], key) == 0) {
                size_t len = 0;
                if (nodus_t2_value_changed(0, key, val,
                        notify_buf, RESP_BUF_SIZE, &len) == 0) {
                    nodus_tcp_send(s->conn, notify_buf, len);
                }
                break;
            }
        }
    }

    free(notify_buf);
}

/* Channel session helpers are now in nodus_channel_server.c */

/* Forward declaration for async replication */
static void dht_republish_send_async(nodus_server_t *srv, const char *ip,
                                      uint16_t port, const uint8_t *frame,
                                      size_t flen);

/* ── Server-to-server TCP STORE (with hinted handoff on failure) ── */

/**
 * Send a pre-encoded wire frame to a peer. Returns 0 on success, -1 on failure.
 */
/* HIGH-13: Blocking send replaced by dht_republish_send_async() in all callers.
 * Kept for potential future use (e.g., synchronous fallback paths). */
static int __attribute__((unused)) send_frame_to_peer(const char *peer_ip, uint16_t peer_tcp_port,
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

void nodus_server_replicate_value(nodus_server_t *srv, const nodus_value_t *val) {
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

        /* HIGH-13 fix: use non-blocking async send instead of blocking TCP.
         * Falls back to hinted handoff if all async slots are full. */
        if (srv->republish.pending_fds < NODUS_REPUBLISH_MAX_FDS) {
            dht_republish_send_async(srv, closest[i].ip, closest[i].tcp_port, frame, flen);
        } else {
            /* All async slots full — queue for later retry */
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
 * For each ALIVE cluster peer, query pending hints, attempt send, delete on success.
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
            /* HIGH-13 fix: use async send for hinted handoff retry too */
            if (srv->republish.pending_fds >= NODUS_REPUBLISH_MAX_FDS)
                break;  /* Async slots full — try remaining next cycle */
            dht_republish_send_async(srv, ip, tcp_port,
                                      entries[j].frame_data,
                                      entries[j].frame_len);
            /* Delete hint optimistically — async send will either succeed
             * or the value will be re-queued on next replication cycle */
            nodus_storage_hinted_delete(&srv->storage, entries[j].id);
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

    /* Reject oversized values before doing any work (SECURITY: HIGH-7) */
    if (msg->data_len > NODUS_MAX_VALUE_SIZE) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_TOO_LARGE,
                        "value exceeds max size", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    /* Check storage quotas (global count, global bytes, per-owner count) */
    if (nodus_storage_check_quota(&srv->storage, &sess->client_fp) != 0) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_QUOTA_EXCEEDED,
                        "storage quota exceeded", resp_buf, sizeof(resp_buf), &len);
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
        char kh[17], fp_hex[17];
        for (int i = 0; i < 8; i++) {
            sprintf(kh + i*2, "%02x", val->key_hash.bytes[i]);
            sprintf(fp_hex + i*2, "%02x", sess->client_fp.bytes[i]);
        }
        kh[16] = '\0'; fp_hex[16] = '\0';
        fprintf(stderr, "T2_PUT: verify FAILED key=%s... client=%s... vid=%llu seq=%llu\n",
                kh, fp_hex, (unsigned long long)val->value_id, (unsigned long long)val->seq);
        nodus_value_free(val);
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INVALID_SIGNATURE,
                        "value signature invalid", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    /* Store — client owns this key (signature verified), always overwrite.
     * put_if_newer is only for inter-node replication paths. */
    rc = nodus_storage_put(&srv->storage, val);
    if (rc != 0) {
        nodus_value_free(val);
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "storage error", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    /* Notify listeners */
    notify_listeners(srv, &msg->key, val);

    /* Replicate to alive cluster peers via TCP STORE */
    nodus_server_replicate_value(srv, val);

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
                        /* Cache locally — HIGH-12 fix: verify before caching */
                        if (t1msg.value) {
                            if (nodus_value_verify(t1msg.value) == 0) {
                                nodus_storage_put_if_newer(&srv->storage, t1msg.value);
                            } else {
                                char kh[17];
                                for (int i = 0; i < 8; i++)
                                    sprintf(kh + i*2, "%02x", t1msg.value->key_hash.bytes[i]);
                                kh[16] = '\0';
                                fprintf(stderr, "FV_CACHE: verify FAILED for key=%s... — not cached\n", kh);
                            }
                        }
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

/* ── Batch Forward (BF) ─── get_batch miss → forward to closest peer ── */

static void bf_conn_cleanup(nodus_server_t *srv, dht_bf_conn_t *c) {
    if (c->fd >= 0) {
        epoll_ctl(srv->bf_state.bf_epoll_fd, EPOLL_CTL_DEL, c->fd, NULL);
        if (c->fd < NODUS_BF_FD_TABLE_SIZE) {
            srv->bf_fd_table[c->fd].batch_idx = -1;
            srv->bf_fd_table[c->fd].forward_idx = -1;
        }
        close(c->fd);
    }
    c->fd = -1;
    free(c->send_buf); c->send_buf = NULL;
    free(c->recv_buf); c->recv_buf = NULL;
    free(c->key_indices); c->key_indices = NULL;
    free(c->batch_keys); c->batch_keys = NULL;
    c->state = BF_DONE;
}

static void bf_batch_cleanup(nodus_server_t *srv, dht_bf_batch_t *b) {
    for (int i = 0; i < NODUS_BF_MAX_FORWARDS; i++) {
        if (b->forwards[i].fd >= 0) bf_conn_cleanup(srv, &b->forwards[i]);
    }
    if (b->vals_per_key) {
        for (int i = 0; i < b->key_count; i++) {
            if (b->vals_per_key[i]) {
                for (size_t j = 0; j < b->counts_per_key[i]; j++)
                    nodus_value_free(b->vals_per_key[i][j]);
                free(b->vals_per_key[i]);
            }
        }
        free(b->vals_per_key);
    }
    free(b->counts_per_key);
    free(b->keys);
    memset(b, 0, sizeof(*b));
}

/** Send batch response to client and clean up */
static void bf_send_result(nodus_server_t *srv, dht_bf_batch_t *b) {
    nodus_session_t *sess = &srv->sessions[b->session_slot];
    if (!sess->conn) { bf_batch_cleanup(srv, b); return; }

    size_t buf_cap = RESP_BUF_SIZE;
    uint8_t *buf = malloc(buf_cap);
    if (buf) {
        size_t len = 0;
        if (nodus_t2_result_get_batch(b->txn_id, b->keys, b->key_count,
                                       b->vals_per_key, b->counts_per_key,
                                       buf, buf_cap, &len) == 0)
            nodus_tcp_send(sess->conn, buf, len);
        free(buf);
    }
    bf_batch_cleanup(srv, b);
}

/** Build a framed CBOR message into malloc'd buffer. Returns 0 on success. */
static int bf_build_frame(uint8_t **buf_out, size_t *len_out,
                            const uint8_t *cbor, size_t cbor_len);

/** Try to receive a complete nodus frame. Returns 1 if complete, 0 if need more, -1 on error. */
static int bf_recv_frame(dht_bf_conn_t *c, int fd) {
    ssize_t n = recv(fd, c->recv_buf + c->recv_len,
                     c->recv_cap - c->recv_len, 0);
    if (n <= 0) return -1;  /* closed or error */
    c->recv_len += (size_t)n;

    if (c->recv_len < 7) return 0;  /* need more */
    if (c->recv_buf[0] != 0x4E || c->recv_buf[1] != 0x44) return -1;  /* bad magic */

    uint32_t frame_len = (uint32_t)c->recv_buf[3] << 24 |
                         (uint32_t)c->recv_buf[4] << 16 |
                         (uint32_t)c->recv_buf[5] << 8 |
                         (uint32_t)c->recv_buf[6];
    return (c->recv_len >= 7 + frame_len) ? 1 : 0;
}

/** Reset send/recv buffers for next round-trip */
static void bf_reset_buffers(dht_bf_conn_t *c) {
    free(c->send_buf); c->send_buf = NULL;
    c->send_len = 0; c->send_pos = 0;
    c->recv_len = 0;  /* keep recv_buf allocated */
}

/** Switch epoll to EPOLLOUT for sending */
static void bf_switch_to_send(nodus_server_t *srv, dht_bf_conn_t *c) {
    struct epoll_event ev = { .events = EPOLLOUT | EPOLLERR | EPOLLHUP, .data.fd = c->fd };
    epoll_ctl(srv->bf_state.bf_epoll_fd, EPOLL_CTL_MOD, c->fd, &ev);
}

/** Switch epoll to EPOLLIN for receiving */
static void bf_switch_to_recv(nodus_server_t *srv, dht_bf_conn_t *c) {
    struct epoll_event ev = { .events = EPOLLIN | EPOLLERR | EPOLLHUP, .data.fd = c->fd };
    epoll_ctl(srv->bf_state.bf_epoll_fd, EPOLL_CTL_MOD, c->fd, &ev);
}

/** Forward error → cleanup + check batch completion */
static void bf_forward_fail(nodus_server_t *srv, dht_bf_batch_t *b, dht_bf_conn_t *c) {
    bf_conn_cleanup(srv, c);
    if (--b->pending_forwards <= 0) bf_send_result(srv, b);
}

/** Handle epoll events for batch forward fds — full auth state machine */
static void bf_handle_event(nodus_server_t *srv, int fd, uint32_t events) {
    if (fd < 0 || fd >= NODUS_BF_FD_TABLE_SIZE) return;
    int bi = srv->bf_fd_table[fd].batch_idx;
    int fi = srv->bf_fd_table[fd].forward_idx;
    if (bi < 0 || bi >= NODUS_BF_MAX_BATCHES) return;
    if (fi < 0 || fi >= NODUS_BF_MAX_FORWARDS) return;
    dht_bf_batch_t *b = &srv->bf_state.batches[bi];
    if (!b->active) return;
    dht_bf_conn_t *c = &b->forwards[fi];
    if (c->fd < 0) return;

    if (events & (EPOLLERR | EPOLLHUP)) {
        bf_forward_fail(srv, b, c);
        return;
    }

    /* ── State 0: Connecting → send HELLO ── */
    if (c->state == BF_CONNECTING && (events & EPOLLOUT)) {
        c->state = BF_SEND_HELLO;
        /* send_buf already has HELLO frame from bf_start_forward */
    }

    /* ── Send states (HELLO / AUTH / BATCH) ── */
    if ((c->state == BF_SEND_HELLO || c->state == BF_SEND_AUTH ||
         c->state == BF_SEND_BATCH) && (events & EPOLLOUT)) {
        if (!c->send_buf) { bf_forward_fail(srv, b, c); return; }
        ssize_t n = send(fd, c->send_buf + c->send_pos,
                         c->send_len - c->send_pos, MSG_NOSIGNAL);
        if (n < 0) { bf_forward_fail(srv, b, c); return; }
        if (n > 0) c->send_pos += (size_t)n;
        if (c->send_pos >= c->send_len) {
            /* Send complete → switch to recv for response */
            if (c->state == BF_SEND_HELLO)  c->state = BF_RECV_CHALL;
            else if (c->state == BF_SEND_AUTH) c->state = BF_RECV_AUTHOK;
            else if (c->state == BF_SEND_BATCH) c->state = BF_RECV_RESULT;
            bf_reset_buffers(c);
            bf_switch_to_recv(srv, c);
        }
        return;
    }

    /* ── State 2: Recv CHALLENGE → sign nonce → send AUTH ── */
    if (c->state == BF_RECV_CHALL && (events & EPOLLIN)) {
        int rc = bf_recv_frame(c, fd);
        if (rc < 0) { bf_forward_fail(srv, b, c); return; }
        if (rc == 0) return;  /* need more data */

        /* Parse challenge nonce */
        nodus_tier2_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        if (nodus_t2_decode(c->recv_buf + 7, c->recv_len - 7, &msg) != 0) {
            nodus_t2_msg_free(&msg);
            bf_forward_fail(srv, b, c); return;
        }

        /* Sign nonce with our secret key */
        nodus_sig_t sig;
        if (nodus_sign(&sig, msg.nonce, NODUS_NONCE_LEN, &srv->identity.sk) != 0) {
            nodus_t2_msg_free(&msg);
            bf_forward_fail(srv, b, c); return;
        }
        nodus_t2_msg_free(&msg);

        /* Build AUTH frame */
        uint8_t cbor[8192];
        size_t clen = 0;
        if (nodus_t2_auth(2, &sig, cbor, sizeof(cbor), &clen) != 0 ||
            bf_build_frame(&c->send_buf, &c->send_len, cbor, clen) != 0) {
            bf_forward_fail(srv, b, c); return;
        }
        c->send_pos = 0;
        c->recv_len = 0;
        c->state = BF_SEND_AUTH;
        bf_switch_to_send(srv, c);
        return;
    }

    /* ── State 4: Recv AUTH_OK → extract token → send get_batch ── */
    if (c->state == BF_RECV_AUTHOK && (events & EPOLLIN)) {
        int rc = bf_recv_frame(c, fd);
        if (rc < 0) { bf_forward_fail(srv, b, c); return; }
        if (rc == 0) return;

        /* Parse auth_ok → get token */
        nodus_tier2_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        if (nodus_t2_decode(c->recv_buf + 7, c->recv_len - 7, &msg) != 0 ||
            msg.type == 'e') {
            nodus_t2_msg_free(&msg);
            bf_forward_fail(srv, b, c); return;
        }
        memcpy(c->token, msg.token, NODUS_SESSION_TOKEN_LEN);
        nodus_t2_msg_free(&msg);

        /* Build get_batch frame WITH token */
        uint8_t cbor[4096];
        size_t clen = 0;
        if (nodus_t2_get_batch(3, c->token, c->batch_keys, c->batch_key_count,
                                cbor, sizeof(cbor), &clen) != 0 ||
            bf_build_frame(&c->send_buf, &c->send_len, cbor, clen) != 0) {
            bf_forward_fail(srv, b, c); return;
        }
        c->send_pos = 0;
        c->recv_len = 0;
        c->state = BF_SEND_BATCH;
        bf_switch_to_send(srv, c);
        return;
    }

    /* ── State 6: Recv batch result → merge → done ── */
    if (c->state == BF_RECV_RESULT && (events & EPOLLIN)) {
        int rc = bf_recv_frame(c, fd);
        if (rc < 0) goto merge_and_done;
        if (rc == 0) return;

    merge_and_done:
        /* Parse batch response from peer */
        if (c->recv_len > 7) {
            nodus_tier2_msg_t resp;
            memset(&resp, 0, sizeof(resp));
            if (nodus_t2_decode(c->recv_buf + 7, c->recv_len - 7, &resp) == 0 &&
                resp.batch_keys && resp.batch_key_count > 0) {
                for (int r = 0; r < resp.batch_key_count && r < c->key_count; r++) {
                    int ki = c->key_indices[r];
                    if (ki < 0 || ki >= b->key_count) continue;
                    if (b->counts_per_key[ki] > 0) continue;
                    b->vals_per_key[ki] = resp.batch_vals ? resp.batch_vals[r] : NULL;
                    b->counts_per_key[ki] = resp.batch_val_counts ? resp.batch_val_counts[r] : 0;
                    if (resp.batch_vals) resp.batch_vals[r] = NULL;
                    if (resp.batch_val_counts) resp.batch_val_counts[r] = 0;
                }
                nodus_t2_msg_free(&resp);
            }
        }
        bf_conn_cleanup(srv, c);
        if (--b->pending_forwards <= 0) bf_send_result(srv, b);
    }
}

/** Tick: advance all batch forwards (called from main event loop) */
static void bf_tick(nodus_server_t *srv) {
    if (srv->bf_state.bf_epoll_fd < 0) return;

    struct epoll_event events[32];
    int n = epoll_wait(srv->bf_state.bf_epoll_fd, events, 32, 0);
    for (int i = 0; i < n; i++)
        bf_handle_event(srv, events[i].data.fd, events[i].events);

    /* Check timeouts */
    uint64_t now = nodus_time_now_ms();
    for (int bi = 0; bi < NODUS_BF_MAX_BATCHES; bi++) {
        dht_bf_batch_t *b = &srv->bf_state.batches[bi];
        if (!b->active) continue;

        /* Check client disconnect */
        nodus_session_t *sess = &srv->sessions[b->session_slot];
        if (!sess->conn) { bf_batch_cleanup(srv, b); continue; }

        /* Overall batch timeout */
        if (now - b->started_at > NODUS_BF_TIMEOUT_MS) {
            /* Timeout: clean up remaining forwards, send what we have */
            for (int fi = 0; fi < NODUS_BF_MAX_FORWARDS; fi++) {
                if (b->forwards[fi].fd >= 0) {
                    bf_conn_cleanup(srv, &b->forwards[fi]);
                }
            }
            bf_send_result(srv, b);
        }
    }
}

/** Build a framed CBOR message into malloc'd buffer. Returns 0 on success. */
static int bf_build_frame(uint8_t **buf_out, size_t *len_out,
                            const uint8_t *cbor, size_t cbor_len) {
    uint8_t tmp[8192];
    size_t flen = nodus_frame_encode(tmp, sizeof(tmp), cbor, (uint32_t)cbor_len);
    if (flen == 0) return -1;
    *buf_out = malloc(flen);
    if (!*buf_out) return -1;
    memcpy(*buf_out, tmp, flen);
    *len_out = flen;
    return 0;
}

/** Start a batch forward to a peer node */
static int bf_start_forward(nodus_server_t *srv, dht_bf_batch_t *b,
                              int fi, const nodus_peer_t *peer,
                              const nodus_key_t *keys, const int *key_indices,
                              int key_count) {
    dht_bf_conn_t *c = &b->forwards[fi];
    memset(c, 0, sizeof(*c));
    c->fd = -1;

    /* Copy key indices */
    c->key_indices = malloc((size_t)key_count * sizeof(int));
    if (!c->key_indices) return -1;
    memcpy(c->key_indices, key_indices, (size_t)key_count * sizeof(int));
    c->key_count = key_count;

    /* Store batch keys for later (sent after auth completes) */
    c->batch_keys = malloc((size_t)key_count * sizeof(nodus_key_t));
    if (!c->batch_keys) goto fail;
    memcpy(c->batch_keys, keys, (size_t)key_count * sizeof(nodus_key_t));
    c->batch_key_count = key_count;

    /* Build HELLO frame (first message in auth handshake) */
    uint8_t cbor_buf[4096];
    size_t cbor_len = 0;
    if (nodus_t2_hello(1, &srv->identity.pk, &srv->identity.node_id,
                        cbor_buf, sizeof(cbor_buf), &cbor_len) != 0)
        goto fail;

    if (bf_build_frame(&c->send_buf, &c->send_len, cbor_buf, cbor_len) != 0)
        goto fail;

    c->recv_cap = RESP_BUF_SIZE;
    c->recv_buf = malloc(c->recv_cap);
    if (!c->recv_buf) goto fail;

    /* Non-blocking connect to peer's INTER-NODE port (4002) */
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) goto fail;
    if (fd >= NODUS_BF_FD_TABLE_SIZE) { close(fd); goto fail; }

    /* Inter-node port = UDP port + 2 (convention: 4000→4002) */
    uint16_t inter_port = peer->udp_port ? (peer->udp_port + 2) : 4002;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(inter_port);
    inet_pton(AF_INET, peer->ip, &addr.sin_addr);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) { close(fd); goto fail; }

    c->fd = fd;
    c->state = BF_CONNECTING;
    c->started_at = nodus_time_now_ms();
    snprintf(c->ip, sizeof(c->ip), "%s", peer->ip);
    c->port = inter_port;

    /* Register with batch forward epoll */
    int bi = (int)(b - srv->bf_state.batches);
    srv->bf_fd_table[fd].batch_idx = bi;
    srv->bf_fd_table[fd].forward_idx = fi;

    struct epoll_event ev = { .events = EPOLLOUT | EPOLLERR | EPOLLHUP, .data.fd = fd };
    epoll_ctl(srv->bf_state.bf_epoll_fd, EPOLL_CTL_ADD, fd, &ev);

    return 0;

fail:
    free(c->key_indices); c->key_indices = NULL;
    free(c->send_buf); c->send_buf = NULL;
    free(c->recv_buf); c->recv_buf = NULL;
    free(c->batch_keys); c->batch_keys = NULL;
    return -1;
}

static void handle_t2_get_batch(nodus_server_t *srv, nodus_session_t *sess,
                                 nodus_tier2_msg_t *msg) {
    if (msg->batch_key_count < 1 || msg->batch_key_count > NODUS_MAX_BATCH_KEYS) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "invalid batch key count", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    int n = msg->batch_key_count;
    nodus_value_t ***vals_per_key = calloc((size_t)n, sizeof(nodus_value_t **));
    size_t *counts_per_key = calloc((size_t)n, sizeof(size_t));
    if (!vals_per_key || !counts_per_key) {
        free(vals_per_key);
        free(counts_per_key);
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "alloc failed", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    /* Phase 1: local storage lookup for all keys */
    int miss_count = 0;
    int miss_indices[NODUS_MAX_BATCH_KEYS];

    for (int i = 0; i < n; i++) {
        nodus_storage_get_all(&srv->storage, &msg->batch_keys[i],
                               &vals_per_key[i], &counts_per_key[i]);
        if (counts_per_key[i] == 0) {
            miss_indices[miss_count++] = i;
        }
    }

    /* Phase 2: if all found locally → respond immediately (fast path) */
    if (miss_count == 0) {
        goto send_response;
    }

    /* Phase 3: group misses by closest peer and start batch forwards */
    {
        /* Find a free batch slot */
        int bi = -1;
        for (int i = 0; i < NODUS_BF_MAX_BATCHES; i++) {
            if (!srv->bf_state.batches[i].active) { bi = i; break; }
        }

        if (bi < 0) {
            /* No batch slots available — send local-only results */
            goto send_response;
        }

        /* Group misses by closest peer */
        typedef struct { nodus_peer_t peer; int key_idx[NODUS_MAX_BATCH_KEYS]; int count; } peer_group_t;
        peer_group_t groups[NODUS_BF_MAX_FORWARDS];
        int group_count = 0;

        for (int m = 0; m < miss_count; m++) {
            int ki = miss_indices[m];
            nodus_peer_t closest[1];
            int found = nodus_routing_find_closest(&srv->routing, &msg->batch_keys[ki],
                                                     closest, 1);
            if (found == 0) continue; /* No peers known — skip */

            /* Skip self */
            if (nodus_key_cmp(&closest[0].node_id, &srv->identity.node_id) == 0) {
                /* We ARE the closest — no point forwarding */
                continue;
            }

            /* Find existing group for this peer or create new */
            int gi = -1;
            for (int g = 0; g < group_count; g++) {
                if (strcmp(groups[g].peer.ip, closest[0].ip) == 0 &&
                    groups[g].peer.tcp_port == closest[0].tcp_port) {
                    gi = g;
                    break;
                }
            }
            if (gi < 0 && group_count < NODUS_BF_MAX_FORWARDS) {
                gi = group_count++;
                groups[gi].peer = closest[0];
                groups[gi].count = 0;
            }
            if (gi >= 0 && groups[gi].count < NODUS_MAX_BATCH_KEYS) {
                groups[gi].key_idx[groups[gi].count++] = ki;
            }
        }

        if (group_count == 0) {
            /* No peers to forward to — send local-only results */
            goto send_response;
        }

        /* Set up batch context — transfer ownership of results */
        dht_bf_batch_t *b = &srv->bf_state.batches[bi];
        memset(b, 0, sizeof(*b));
        b->active = true;
        b->txn_id = msg->txn_id;
        b->session_slot = (int)(sess - srv->sessions);
        b->started_at = nodus_time_now_ms();
        b->key_count = n;
        b->keys = malloc((size_t)n * sizeof(nodus_key_t));
        if (!b->keys) {
            b->active = false;
            goto send_response;
        }
        memcpy(b->keys, msg->batch_keys, (size_t)n * sizeof(nodus_key_t));
        b->vals_per_key = vals_per_key;   /* Transfer ownership */
        b->counts_per_key = counts_per_key;
        b->pending_forwards = 0;

        /* Start forwards */
        for (int g = 0; g < group_count; g++) {
            /* Build key array for this group */
            nodus_key_t *fwd_keys = malloc((size_t)groups[g].count * sizeof(nodus_key_t));
            if (!fwd_keys) continue;
            for (int k = 0; k < groups[g].count; k++)
                fwd_keys[k] = msg->batch_keys[groups[g].key_idx[k]];

            if (bf_start_forward(srv, b, g, &groups[g].peer,
                                  fwd_keys, groups[g].key_idx,
                                  groups[g].count) == 0) {
                b->pending_forwards++;
            }
            free(fwd_keys);
        }

        if (b->pending_forwards > 0) {
            /* Response deferred — bf_tick will send when all forwards complete */
            return;
        }

        /* All forwards failed to start — send local results and clean up */
        /* Take back ownership before cleanup */
        b->vals_per_key = NULL;
        b->counts_per_key = NULL;
        bf_batch_cleanup(srv, b);
        goto send_response;
    }

send_response:
    {
        size_t buf_cap = RESP_BUF_SIZE;
        uint8_t *buf = malloc(buf_cap);
        if (buf) {
            size_t len = 0;
            int rc = nodus_t2_result_get_batch(msg->txn_id, msg->batch_keys, n,
                                                vals_per_key, counts_per_key,
                                                buf, buf_cap, &len);
            if (rc == 0) {
                nodus_tcp_send(sess->conn, buf, len);
            } else {
                size_t elen = 0;
                nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                                "batch encode failed", resp_buf, sizeof(resp_buf), &elen);
                nodus_tcp_send(sess->conn, resp_buf, elen);
            }
            free(buf);
        }

        for (int i = 0; i < n; i++) {
            if (vals_per_key[i]) {
                for (size_t j = 0; j < counts_per_key[i]; j++)
                    nodus_value_free(vals_per_key[i][j]);
                free(vals_per_key[i]);
            }
        }
        free(vals_per_key);
        free(counts_per_key);
    }
}

static void handle_t2_count_batch(nodus_server_t *srv, nodus_session_t *sess,
                                    nodus_tier2_msg_t *msg) {
    if (msg->batch_key_count < 1 || msg->batch_key_count > NODUS_MAX_BATCH_KEYS) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "invalid batch key count", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    int n = msg->batch_key_count;
    size_t *counts = calloc((size_t)n, sizeof(size_t));
    bool *has_mine = calloc((size_t)n, sizeof(bool));
    if (!counts || !has_mine) {
        free(counts);
        free(has_mine);
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "alloc failed", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }

    /* Use session's fingerprint (from auth) as caller_fp.
     * msg->fp is set if client sent "fp" in args, otherwise fall back to session. */
    nodus_key_t caller_fp;
    bool has_caller = false;
    if (memcmp(msg->fp.bytes, "\0\0\0\0\0\0\0\0", 8) != 0) {
        memcpy(&caller_fp, &msg->fp, sizeof(nodus_key_t));
        has_caller = true;
    } else if (memcmp(sess->client_fp.bytes, "\0\0\0\0\0\0\0\0", 8) != 0) {
        memcpy(&caller_fp, &sess->client_fp, sizeof(nodus_key_t));
        has_caller = true;
    }

    for (int i = 0; i < n; i++) {
        int c = nodus_storage_count_key(&srv->storage, &msg->batch_keys[i]);
        counts[i] = c >= 0 ? (size_t)c : 0;
        if (has_caller) {
            int ho = nodus_storage_has_owner(&srv->storage,
                                              &msg->batch_keys[i], &caller_fp);
            has_mine[i] = (ho == 1);
        }
    }

    size_t len = 0;
    if (nodus_t2_result_count_batch(msg->txn_id, msg->batch_keys, n,
                                     counts, has_mine,
                                     resp_buf, sizeof(resp_buf), &len) == 0) {
        nodus_tcp_send(sess->conn, resp_buf, len);
    } else {
        size_t elen = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "count batch encode failed", resp_buf, sizeof(resp_buf), &elen);
        nodus_tcp_send(sess->conn, resp_buf, elen);
    }

    free(counts);
    free(has_mine);
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

/* ── Channel discovery on TCP 4001 ────────────────────────────────── */

static void handle_t2_ch_list(nodus_server_t *srv, nodus_session_t *sess,
                                nodus_tier2_msg_t *msg) {
    nodus_channel_meta_t *metas = NULL;
    size_t count = 0;
    int rc = nodus_channel_store_list_public(&srv->ch_store,
                                              msg->ch_offset, msg->ch_limit,
                                              &metas, &count);
    if (rc != 0) {
        uint8_t buf[256];
        size_t len = 0;
        nodus_t2_error(msg->txn_id, 500, "internal error", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return;
    }

    uint8_t *buf = malloc(65536);
    if (!buf) { free(metas); return; }
    size_t len = 0;
    nodus_t2_ch_list_ok(msg->txn_id, metas, count, buf, 65536, &len);
    nodus_tcp_send(sess->conn, buf, len);
    free(buf);
    free(metas);
}

static void handle_t2_ch_search(nodus_server_t *srv, nodus_session_t *sess,
                                  nodus_tier2_msg_t *msg) {
    const char *query = msg->ch_query;
    if (!query || query[0] == '\0') {
        handle_t2_ch_list(srv, sess, msg);
        return;
    }

    nodus_channel_meta_t *metas = NULL;
    size_t count = 0;
    int rc = nodus_channel_store_search(&srv->ch_store, query,
                                         msg->ch_offset, msg->ch_limit,
                                         &metas, &count);
    if (rc != 0) {
        uint8_t buf[256];
        size_t len = 0;
        nodus_t2_error(msg->txn_id, 500, "internal error", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return;
    }

    uint8_t *buf = malloc(65536);
    if (!buf) { free(metas); return; }
    size_t len = 0;
    nodus_t2_ch_list_ok(msg->txn_id, metas, count, buf, 65536, &len);
    nodus_tcp_send(sess->conn, buf, len);
    free(buf);
    free(metas);
}

static void handle_t2_ch_get(nodus_server_t *srv, nodus_session_t *sess,
                               nodus_tier2_msg_t *msg) {
    nodus_channel_meta_t meta;
    int rc = nodus_channel_load_meta(&srv->ch_store, msg->channel_uuid, &meta);
    if (rc != 0) {
        uint8_t buf[256];
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_NOT_FOUND, "channel not found",
                       buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return;
    }

    /* Reuse ch_list_ok with count=1 */
    uint8_t *buf = malloc(4096);
    if (!buf) return;
    size_t len = 0;
    nodus_t2_ch_list_ok(msg->txn_id, &meta, 1, buf, 4096, &len);
    nodus_tcp_send(sess->conn, buf, len);
    free(buf);
}

static void handle_t2_servers(nodus_server_t *srv, nodus_session_t *sess,
                                nodus_tier2_msg_t *msg) {
    /* Build server info list: self + alive cluster peers */
    nodus_t2_server_info_t infos[NODUS_CLUSTER_MAX_PEERS + 1];
    int count = 0;

    /* Self first — use external_ip if configured, otherwise bind_ip.
     * Skip self if resolved IP is 0.0.0.0 (not routable). */
    const char *self_ip = srv->config.external_ip[0] ? srv->config.external_ip
                        : srv->config.bind_ip[0]     ? srv->config.bind_ip
                        : NULL;
    if (self_ip && strcmp(self_ip, "0.0.0.0") != 0) {
        memset(&infos[count], 0, sizeof(infos[0]));
        snprintf(infos[count].ip, sizeof(infos[0].ip), "%s", self_ip);
        infos[count].tcp_port = srv->config.tcp_port;
        count++;
    }

    /* Alive peers */
    for (int i = 0; i < srv->cluster.peer_count && count < NODUS_CLUSTER_MAX_PEERS + 1; i++) {
        if (srv->cluster.peers[i].state != NODUS_NODE_ALIVE) continue;
        memset(&infos[count], 0, sizeof(infos[0]));
        snprintf(infos[count].ip, sizeof(infos[0].ip), "%s", srv->cluster.peers[i].ip);
        /* Client port = peer port - 1 (convention: UDP, UDP+1=client, UDP+2=peer).
         * NOTE: breaks if non-standard port gaps are configured. */
        infos[count].tcp_port = srv->cluster.peers[i].tcp_port - 1;
        count++;
    }

    size_t len = 0;
    nodus_t2_servers_result(msg->txn_id, infos, count,
                             resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);
}

/* ── Ping-before-evict helpers ───────────────────────────────────── */

/**
 * Try to insert a peer into the routing table. If the bucket is full,
 * send a UDP PING to the LRU candidate and queue the eviction.
 * The main loop sweep handles timeout-based eviction.
 */
static void routing_insert_or_ping(nodus_server_t *srv, const nodus_peer_t *peer) {
    nodus_peer_t lru;
    memset(&lru, 0, sizeof(lru));
    int rc = nodus_routing_try_insert(&srv->routing, peer, &lru);

    /* Sync hashring with routing table on insert/update */
    if (rc == 0 || rc == 1) {
        nodus_hashring_add(&srv->ring, &peer->node_id,
                           peer->ip, peer->tcp_port);
    }

    if (rc != 2) return;  /* 0=inserted, 1=updated, -1=error — all done */

    /* Bucket full — check if we already have a pending eviction for this LRU */
    for (int i = 0; i < NODUS_MAX_PENDING_EVICTIONS; i++) {
        if (srv->pending_evictions[i].active &&
            nodus_key_cmp(&srv->pending_evictions[i].lru_peer.node_id,
                          &lru.node_id) == 0)
            return;  /* Already pinging this LRU, discard new peer */
    }

    /* Find a free slot */
    for (int i = 0; i < NODUS_MAX_PENDING_EVICTIONS; i++) {
        if (!srv->pending_evictions[i].active) {
            srv->pending_evictions[i].active = true;
            srv->pending_evictions[i].new_peer = *peer;
            srv->pending_evictions[i].lru_peer = lru;
            srv->pending_evictions[i].ping_sent_at = nodus_time_now();

            /* Send UDP PING to the LRU candidate */
            uint8_t ping_buf[256];
            size_t plen = 0;
            nodus_t1_ping(0, &srv->identity.node_id,
                           ping_buf, sizeof(ping_buf), &plen);
            nodus_udp_send(&srv->udp, ping_buf, plen,
                            lru.ip, lru.udp_port);
            return;
        }
    }
    /* No free slot — discard the new peer (conservative, favors existing) */
}

/**
 * Called from the PONG handler: if the responding peer is an LRU candidate
 * in a pending eviction, cancel the eviction (keep existing peer).
 */
static void eviction_on_pong(nodus_server_t *srv, const nodus_key_t *node_id) {
    for (int i = 0; i < NODUS_MAX_PENDING_EVICTIONS; i++) {
        if (srv->pending_evictions[i].active &&
            nodus_key_cmp(&srv->pending_evictions[i].lru_peer.node_id,
                          node_id) == 0) {
            /* LRU responded — keep it, discard new peer */
            srv->pending_evictions[i].active = false;
            nodus_routing_touch(&srv->routing, node_id);
        }
    }
}

/**
 * Periodic sweep: evict LRU peers that didn't respond to PING within timeout.
 * Called from the main event loop.
 */
static void eviction_sweep(nodus_server_t *srv) {
    uint64_t now = nodus_time_now();
    for (int i = 0; i < NODUS_MAX_PENDING_EVICTIONS; i++) {
        if (!srv->pending_evictions[i].active) continue;
        if (now - srv->pending_evictions[i].ping_sent_at < NODUS_EVICT_PING_TIMEOUT)
            continue;

        /* Timeout — evict LRU and insert new peer */
        nodus_routing_remove(&srv->routing,
                              &srv->pending_evictions[i].lru_peer.node_id);
        nodus_hashring_remove(&srv->ring,
                               &srv->pending_evictions[i].lru_peer.node_id);
        nodus_routing_insert(&srv->routing,
                              &srv->pending_evictions[i].new_peer);
        nodus_hashring_add(&srv->ring,
                           &srv->pending_evictions[i].new_peer.node_id,
                           srv->pending_evictions[i].new_peer.ip,
                           srv->pending_evictions[i].new_peer.tcp_port);
        srv->pending_evictions[i].active = false;
    }
}

/* ── CRIT-4: TCP idle timeout sweep ──────────────────────────────── */

#define IDLE_SWEEP_INTERVAL   30   /* seconds between sweeps */
#define IDLE_TIMEOUT_AUTH     60   /* seconds for authenticated connections */
#define IDLE_TIMEOUT_UNAUTH   15   /* seconds for unauthenticated connections */

static void idle_timeout_sweep(nodus_server_t *srv) {
    uint64_t now = nodus_time_now();
    if (now - srv->last_idle_sweep < IDLE_SWEEP_INTERVAL)
        return;
    srv->last_idle_sweep = now;

    /* Sweep client TCP pool */
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = srv->tcp.pool[i];
        if (!c || c->state != NODUS_CONN_CONNECTED) continue;
        uint64_t idle = now - c->last_activity;
        bool authed = srv->sessions[c->slot].authenticated;
        uint64_t timeout = authed ? IDLE_TIMEOUT_AUTH : IDLE_TIMEOUT_UNAUTH;
        if (idle > timeout) {
            char fp_hex[33] = {0};
            if (authed)
                for (int j = 0; j < 16; j++)
                    sprintf(fp_hex + j*2, "%02x", srv->sessions[c->slot].client_fp.bytes[j]);
            fprintf(stderr, "IDLE_SWEEP: slot=%d ip=%s idle=%lus timeout=%lus auth=%s fp=%s\n",
                    c->slot, c->ip,
                    (unsigned long)idle, (unsigned long)timeout,
                    authed ? "yes" : "no", fp_hex);
            nodus_tcp_disconnect(&srv->tcp, c);
        }
    }

    /* Sweep inter-node TCP pool */
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = srv->inter_tcp.pool[i];
        if (!c || c->state != NODUS_CONN_CONNECTED) continue;
        if (now - c->last_activity > IDLE_TIMEOUT_AUTH)
            nodus_tcp_disconnect(&srv->inter_tcp, c);
    }
}

/* ── Inter-node frame dispatch (peer port) ──────────────────────── */

static void dispatch_inter(nodus_server_t *srv, nodus_inter_session_t *sess,
                            const uint8_t *payload, size_t len) {
    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    /* C-01: Dilithium5 authentication on inter-node port.
     * Pre-auth: only hello and auth messages allowed.
     * Enforcement controlled by require_peer_auth config flag. */
    if (nodus_t2_decode(payload, len, &msg) == 0) {
        if (srv->config.require_peer_auth && !sess->authenticated) {
            if (strcmp(msg.method, "hello") == 0) {
                /* Reuse client auth handler — same Dilithium5 challenge-response.
                 * We cast to nodus_session_t-compatible struct for auth fields. */
                nodus_key_t computed_fp;
                nodus_fingerprint(&msg.pk, &computed_fp);
                if (nodus_key_cmp(&computed_fp, &msg.fp) != 0) {
                    size_t rlen = 0;
                    nodus_t2_error(msg.txn_id, NODUS_ERR_INVALID_SIGNATURE,
                                    "fingerprint mismatch", resp_buf, sizeof(resp_buf), &rlen);
                    nodus_tcp_send(sess->conn, resp_buf, rlen);
                } else {
                    sess->client_pk = msg.pk;
                    sess->client_fp = msg.fp;
                    nodus_random(sess->nonce, NODUS_NONCE_LEN);
                    sess->nonce_pending = true;
                    size_t rlen = 0;
                    nodus_t2_challenge(msg.txn_id, sess->nonce,
                                        resp_buf, sizeof(resp_buf), &rlen);
                    nodus_tcp_send(sess->conn, resp_buf, rlen);
                }
            } else if (strcmp(msg.method, "auth") == 0 && sess->nonce_pending) {
                int rc = nodus_verify(&msg.sig, sess->nonce, NODUS_NONCE_LEN, &sess->client_pk);
                if (rc != 0) {
                    size_t rlen = 0;
                    nodus_t2_error(msg.txn_id, NODUS_ERR_INVALID_SIGNATURE,
                                    "auth failed", resp_buf, sizeof(resp_buf), &rlen);
                    nodus_tcp_send(sess->conn, resp_buf, rlen);
                } else {
                    sess->authenticated = true;
                    sess->nonce_pending = false;
                    sess->conn->peer_id = sess->client_fp;
                    sess->conn->peer_pk = sess->client_pk;
                    sess->conn->peer_id_set = true;
                    uint8_t token[NODUS_SESSION_TOKEN_LEN];
                    nodus_random(token, NODUS_SESSION_TOKEN_LEN);
                    size_t rlen = 0;
                    nodus_t2_auth_ok(msg.txn_id, token,
                                      resp_buf, sizeof(resp_buf), &rlen);
                    nodus_tcp_send(sess->conn, resp_buf, rlen);
                    char fp_hex[33];
                    for (int k = 0; k < 16; k++)
                        sprintf(fp_hex + k*2, "%02x", sess->client_fp.bytes[k]);
                    fp_hex[32] = '\0';
                    fprintf(stderr, "INTER_AUTH_OK: node %s... authenticated on port 4002\n", fp_hex);
                }
            } else {
                size_t rlen = 0;
                nodus_t2_error(msg.txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                                "authenticate first", resp_buf, sizeof(resp_buf), &rlen);
                nodus_tcp_send(sess->conn, resp_buf, rlen);
            }
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

        }

        if (strcmp(msg.method, "get_batch") == 0) {
            /* Inter-node forwarded get_batch — local-only, no re-forward */
            if (msg.batch_key_count > 0 && msg.batch_key_count <= NODUS_MAX_BATCH_KEYS &&
                msg.batch_keys) {
                int n = msg.batch_key_count;
                nodus_value_t ***vals = calloc((size_t)n, sizeof(nodus_value_t **));
                size_t *counts = calloc((size_t)n, sizeof(size_t));
                if (vals && counts) {
                    for (int i = 0; i < n; i++)
                        nodus_storage_get_all(&srv->storage, &msg.batch_keys[i],
                                               &vals[i], &counts[i]);

                    size_t buf_cap = RESP_BUF_SIZE;
                    uint8_t *buf = malloc(buf_cap);
                    if (buf) {
                        size_t rlen = 0;
                        if (nodus_t2_result_get_batch(msg.txn_id, msg.batch_keys, n,
                                                       vals, counts, buf, buf_cap, &rlen) == 0)
                            nodus_tcp_send(sess->conn, buf, rlen);
                        free(buf);
                    }

                    for (int i = 0; i < n; i++) {
                        if (vals[i]) {
                            for (size_t j = 0; j < counts[i]; j++)
                                nodus_value_free(vals[i][j]);
                            free(vals[i]);
                        }
                    }
                }
                free(vals);
                free(counts);
            }
            nodus_t2_msg_free(&msg);
            return;
        }

        /* ch_rep, ring_check, ring_ack, ring_evict now go via TCP 4003 (channel server) */

        /* T2 decode succeeded but method is not a known T2 inter-node method.
         * Fall through to T1 decode — sv payloads can parse as valid T2 CBOR. */
        nodus_t2_msg_free(&msg);
    }

    /* Try T1 decode for STORE_VALUE replication */
    nodus_tier1_msg_t t1msg;
    memset(&t1msg, 0, sizeof(t1msg));
    if (nodus_t1_decode(payload, len, &t1msg) == 0 &&
        strcmp(t1msg.method, "sv") == 0 && t1msg.value) {

        /* Per-session rate limit */
        uint64_t sv_now = nodus_time_now();
        if (sv_now != sess->sv_window_start) { sess->sv_window_start = sv_now; sess->sv_count = 0; }
        if (++sess->sv_count > NODUS_SV_MAX_PER_SEC) {
            fprintf(stderr, "REPL_TCP: sv rate limit hit (%d/s), slot=%d\n",
                    sess->sv_count, sess->conn ? sess->conn->slot : -1);
            nodus_t1_msg_free(&t1msg);
            return;
        }

        if (nodus_value_verify(t1msg.value) == 0) {
            int put_rc = nodus_storage_put_if_newer(&srv->storage, t1msg.value);
            if (put_rc == 0) {
                notify_listeners(srv, &t1msg.value->key_hash, t1msg.value);
            }
        } else {
            char kh[17];
            for (int i = 0; i < 8; i++)
                sprintf(kh + i*2, "%02x", t1msg.value->key_hash.bytes[i]);
            kh[16] = '\0';
            fprintf(stderr, "REPL_TCP: verify FAILED for key=%s... vid=%llu seq=%llu — value DROPPED\n",
                    kh, (unsigned long long)t1msg.value->value_id,
                    (unsigned long long)t1msg.value->seq);
        }
    } else if (nodus_t1_decode(payload, len, &t1msg) != 0) {
        /* T1 decode also failed — unknown frame on inter-node port */
        fprintf(stderr, "REPL_TCP: T1 decode failed (len=%zu), slot=%d\n",
                len, sess->conn ? sess->conn->slot : -1);
    }
    nodus_t1_msg_free(&t1msg);
}

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

    /* Notify witness module so it can clear peer references */
    if (srv->witness)
        nodus_witness_peer_conn_closed(srv->witness, conn);
}

/* ── Witness TCP callbacks (dedicated port 4004) ─────────────────── */

static void on_witness_accept(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    conn->is_nodus = true;  /* All witness port connections are inter-node */
}

static void on_witness_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                              size_t len, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    if (!srv->witness) return;

    /* C-02: Dilithium5 authentication on witness port.
     * Pre-auth: only hello and auth messages allowed.
     * Enforcement controlled by require_peer_auth config flag. */
    if (srv->config.require_peer_auth && !conn->authenticated) {
        nodus_tier2_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        if (nodus_t2_decode(payload, len, &msg) != 0) {
            nodus_t2_msg_free(&msg);
            return;
        }
        if (strcmp(msg.method, "hello") == 0) {
            nodus_key_t computed_fp;
            nodus_fingerprint(&msg.pk, &computed_fp);
            if (nodus_key_cmp(&computed_fp, &msg.fp) != 0) {
                size_t rlen = 0;
                nodus_t2_error(msg.txn_id, NODUS_ERR_INVALID_SIGNATURE,
                                "fingerprint mismatch", resp_buf, sizeof(resp_buf), &rlen);
                nodus_tcp_send(conn, resp_buf, rlen);
            } else {
                conn->peer_pk = msg.pk;
                conn->peer_id = msg.fp;
                nodus_random(conn->auth_nonce, NODUS_NONCE_LEN);
                conn->auth_nonce_pending = true;
                size_t rlen = 0;
                nodus_t2_challenge(msg.txn_id, conn->auth_nonce,
                                    resp_buf, sizeof(resp_buf), &rlen);
                nodus_tcp_send(conn, resp_buf, rlen);
            }
        } else if (strcmp(msg.method, "auth") == 0 && conn->auth_nonce_pending) {
            int rc = nodus_verify(&msg.sig, conn->auth_nonce, NODUS_NONCE_LEN, &conn->peer_pk);
            if (rc != 0) {
                size_t rlen = 0;
                nodus_t2_error(msg.txn_id, NODUS_ERR_INVALID_SIGNATURE,
                                "auth failed", resp_buf, sizeof(resp_buf), &rlen);
                nodus_tcp_send(conn, resp_buf, rlen);
            } else {
                conn->authenticated = true;
                conn->auth_nonce_pending = false;
                conn->peer_id_set = true;
                uint8_t token[NODUS_SESSION_TOKEN_LEN];
                nodus_random(token, NODUS_SESSION_TOKEN_LEN);
                size_t rlen = 0;
                nodus_t2_auth_ok(msg.txn_id, token,
                                  resp_buf, sizeof(resp_buf), &rlen);
                nodus_tcp_send(conn, resp_buf, rlen);
                fprintf(stderr, "WITNESS_AUTH_OK: peer authenticated on port 4004\n");
            }
        } else {
            size_t rlen = 0;
            nodus_t2_error(msg.txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                            "authenticate first", resp_buf, sizeof(resp_buf), &rlen);
            nodus_tcp_send(conn, resp_buf, rlen);
        }
        nodus_t2_msg_free(&msg);
        return;
    }

    /* C-02: Handle auth responses for OUTGOING connections (client-side auth).
     * When we connect to another witness, we send hello and receive challenge/auth_ok.
     * These are T2 messages that arrive on the witness port. */
    {
        nodus_tier2_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        if (nodus_t2_decode(payload, len, &msg) == 0) {
            if (strcmp(msg.method, "challenge") == 0) {
                /* Sign the nonce and send auth response */
                nodus_sig_t sig;
                nodus_sign(&sig, msg.nonce, NODUS_NONCE_LEN, &srv->identity.sk);
                uint8_t buf[8192];
                size_t rlen = 0;
                nodus_t2_auth(msg.txn_id, &sig, buf, sizeof(buf), &rlen);
                nodus_tcp_send(conn, buf, rlen);
                nodus_t2_msg_free(&msg);
                return;
            } else if (strcmp(msg.method, "auth_ok") == 0) {
                /* Auth succeeded — mark peer as authenticated */
                conn->authenticated = true;
                conn->peer_id_set = true;
                /* Find and update peer auth_state */
                if (srv->witness) {
                    for (int i = 0; i < srv->witness->peer_count; i++) {
                        if (srv->witness->peers[i].conn == conn) {
                            srv->witness->peers[i].auth_state = PEER_AUTH_OK;
                            break;
                        }
                    }
                }
                nodus_t2_msg_free(&msg);
                return;
            } else if (strcmp(msg.method, "error") == 0) {
                /* Auth or other error from peer */
                nodus_t2_msg_free(&msg);
                return;
            }
            nodus_t2_msg_free(&msg);
        }
    }

    /* All other frames on witness port are T3 BFT messages — dispatch directly */
    nodus_witness_dispatch_t3(srv->witness, conn, payload, len);
}

static void on_witness_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;

    /* Notify witness module so it can clear peer references */
    if (srv->witness)
        nodus_witness_peer_conn_closed(srv->witness, conn);
}

/* ── TCP frame dispatch ──────────────────────────────────────────── */

static void dispatch_t2(nodus_server_t *srv, nodus_session_t *sess,
                          const uint8_t *payload, size_t len) {
    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));

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

    /* Post-auth: verify session token */
    if (!msg.has_token || !session_check_token(sess, msg.token)) {
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
    else if (strcmp(msg.method, "get_batch") == 0)
        handle_t2_get_batch(srv, sess, &msg);
    else if (strcmp(msg.method, "cnt_batch") == 0)
        handle_t2_count_batch(srv, sess, &msg);
    else if (strcmp(msg.method, "listen") == 0)
        handle_t2_listen(srv, sess, &msg);
    else if (strcmp(msg.method, "unlisten") == 0)
        handle_t2_unlisten(srv, sess, &msg);
    else if (strcmp(msg.method, "ping") == 0)
        handle_t2_ping(srv, sess, &msg);
    else if (strcmp(msg.method, "servers") == 0)
        handle_t2_servers(srv, sess, &msg);
    else if (strcmp(msg.method, "ch_list") == 0)
        handle_t2_ch_list(srv, sess, &msg);
    else if (strcmp(msg.method, "ch_search") == 0)
        handle_t2_ch_search(srv, sess, &msg);
    else if (strcmp(msg.method, "ch_get") == 0)
        handle_t2_ch_get(srv, sess, &msg);
    else {
        size_t rlen = 0;
        nodus_t2_error(msg.txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "unknown method", resp_buf, sizeof(resp_buf), &rlen);
        nodus_tcp_send(sess->conn, resp_buf, rlen);
    }

    nodus_t2_msg_free(&msg);
}

/* ── Per-IP UDP rate limiter (HIGH-9 amplification mitigation) ──── */

#define UDP_RATE_MAX_ENTRIES  64   /* Fixed-size table — plenty for 6 nodes */
#define UDP_RATE_MAX_PER_SEC  10   /* Max fn/fv responses per IP per second */
#define UDP_RATE_WINDOW_SEC    1   /* 1-second sliding window */
#define UDP_RATE_EXPIRE_SEC   10   /* Evict stale entries after 10s */

typedef struct {
    char     ip[46];    /* IPv4 or IPv6 string */
    uint64_t window;    /* Window start (epoch seconds) */
    int      count;     /* Requests in current window */
} udp_rate_entry_t;

static udp_rate_entry_t udp_rate_table[UDP_RATE_MAX_ENTRIES];
static int              udp_rate_count = 0;

/**
 * Check if an IP is within rate limit for fn/fv.
 * Returns 0 if allowed, -1 if rate exceeded (drop).
 */
static int udp_rate_check(const char *ip) {
    uint64_t now = (uint64_t)time(NULL);

    /* Search for existing entry */
    for (int i = 0; i < udp_rate_count; i++) {
        if (strcmp(udp_rate_table[i].ip, ip) == 0) {
            if (now - udp_rate_table[i].window >= UDP_RATE_WINDOW_SEC) {
                /* New window — reset */
                udp_rate_table[i].window = now;
                udp_rate_table[i].count = 1;
                return 0;
            }
            udp_rate_table[i].count++;
            if (udp_rate_table[i].count > UDP_RATE_MAX_PER_SEC)
                return -1;  /* Rate exceeded */
            return 0;
        }
    }

    /* New IP — evict stale entries first if table is full */
    if (udp_rate_count >= UDP_RATE_MAX_ENTRIES) {
        int j = 0;
        for (int i = 0; i < udp_rate_count; i++) {
            if (now - udp_rate_table[i].window < UDP_RATE_EXPIRE_SEC) {
                if (j != i)
                    udp_rate_table[j] = udp_rate_table[i];
                j++;
            }
        }
        udp_rate_count = j;

        /* Still full — overwrite oldest */
        if (udp_rate_count >= UDP_RATE_MAX_ENTRIES) {
            int oldest = 0;
            for (int i = 1; i < udp_rate_count; i++) {
                if (udp_rate_table[i].window < udp_rate_table[oldest].window)
                    oldest = i;
            }
            strncpy(udp_rate_table[oldest].ip, ip, sizeof(udp_rate_table[oldest].ip) - 1);
            udp_rate_table[oldest].ip[sizeof(udp_rate_table[oldest].ip) - 1] = '\0';
            udp_rate_table[oldest].window = now;
            udp_rate_table[oldest].count = 1;
            return 0;
        }
    }

    /* Insert new entry */
    strncpy(udp_rate_table[udp_rate_count].ip, ip, sizeof(udp_rate_table[udp_rate_count].ip) - 1);
    udp_rate_table[udp_rate_count].ip[sizeof(udp_rate_table[udp_rate_count].ip) - 1] = '\0';
    udp_rate_table[udp_rate_count].window = now;
    udp_rate_table[udp_rate_count].count = 1;
    udp_rate_count++;
    return 0;
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

        /* Update routing table (ping-before-evict if bucket full) */
        nodus_peer_t peer;
        memset(&peer, 0, sizeof(peer));
        peer.node_id = msg.node_id;
        strncpy(peer.ip, from_ip, sizeof(peer.ip) - 1);
        peer.udp_port = from_port;
        peer.tcp_port = from_port + 2;  /* Peer TCP = UDP + 2 */
        peer.last_seen = nodus_time_now();
        routing_insert_or_ping(srv, &peer);

        /* A received PING proves the peer is alive (same as PONG).
         * Cancel any pending eviction for this peer. */
        eviction_on_pong(srv, &msg.node_id);
        nodus_cluster_on_pong(&srv->cluster, &msg.node_id, from_ip, from_port);

    } else if (strcmp(msg.method, "pong") == 0) {
        /* Update routing table + cluster health (IP-aware for seed discovery) */
        nodus_routing_touch(&srv->routing, &msg.node_id);
        nodus_cluster_on_pong(&srv->cluster, &msg.node_id, from_ip, from_port);

        /* Cancel pending evictions for this peer (it responded) */
        eviction_on_pong(srv, &msg.node_id);

        /* Also insert into routing table if new */
        nodus_peer_t rpeer;
        memset(&rpeer, 0, sizeof(rpeer));
        rpeer.node_id = msg.node_id;
        strncpy(rpeer.ip, from_ip, sizeof(rpeer.ip) - 1);
        rpeer.udp_port = from_port;
        rpeer.tcp_port = from_port + 2;  /* Peer TCP = UDP + 2 */
        rpeer.last_seen = nodus_time_now();
        routing_insert_or_ping(srv, &rpeer);

    } else if (strcmp(msg.method, "fn") == 0) {
        /* FIND_NODE: rate-limit to mitigate UDP amplification (HIGH-9) */
        if (udp_rate_check(from_ip) != 0) {
            nodus_t1_msg_free(&msg);
            return;
        }
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
            routing_insert_or_ping(srv, &msg.peers[i]);
        }

    } else if (strcmp(msg.method, "sv") == 0) {
        /* STORE_VALUE: rate-limit to mitigate UDP abuse (H-05) */
        if (udp_rate_check(from_ip) != 0) {
            fprintf(stderr, "REPL_UDP: sv rate limited from %s:%d\n", from_ip, from_port);
            nodus_t1_msg_free(&msg);
            return;
        }
        /* STORE_VALUE: inter-node replication */
        if (msg.value) {
            if (nodus_value_verify(msg.value) == 0) {
                if (nodus_storage_put_if_newer(&srv->storage, msg.value) == 0)
                    notify_listeners(srv, &msg.value->key_hash, msg.value);
            } else {
                char kh[17];
                for (int i = 0; i < 8; i++)
                    sprintf(kh + i*2, "%02x", msg.value->key_hash.bytes[i]);
                kh[16] = '\0';
                fprintf(stderr, "REPL_UDP: verify FAILED for key=%s... from %s:%d — value DROPPED\n",
                        kh, from_ip, from_port);
            }
            /* Send ACK */
            size_t rlen = 0;
            nodus_t1_store_ack(msg.txn_id, resp_buf, sizeof(resp_buf), &rlen);
            nodus_udp_send(&srv->udp, resp_buf, rlen, from_ip, from_port);
        }

    } else if (strcmp(msg.method, "fv") == 0) {
        /* FIND_VALUE: rate-limit to mitigate UDP amplification (HIGH-9) */
        if (udp_rate_check(from_ip) != 0) {
            nodus_t1_msg_free(&msg);
            return;
        }
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
        char fp_hex[33] = {0};
        if (sess->authenticated) {
            for (int i = 0; i < 16; i++)
                sprintf(fp_hex + i*2, "%02x", sess->client_fp.bytes[i]);
            fprintf(stderr, "CLIENT_DISCONNECT: %s slot=%d ip=%s auth=yes idle=%lus reason=",
                    fp_hex, conn->slot, conn->ip,
                    (unsigned long)(nodus_time_now() - conn->last_activity));
            /* Detect reason */
            int err = 0;
            socklen_t elen = sizeof(err);
            if (conn->fd >= 0) getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &elen);
            if (err) fprintf(stderr, "socket_error(%d)\n", err);
            else fprintf(stderr, "clean_close_or_sweep\n");
            nodus_presence_remove_local(srv, &sess->client_fp);
        } else {
            fprintf(stderr, "CLIENT_DISCONNECT: unauth slot=%d ip=%s idle=%lus\n",
                    conn->slot, conn->ip,
                    (unsigned long)(nodus_time_now() - conn->last_activity));
        }
        session_clear(sess);
    }

    /* Clear any witness peer references before conn is freed */
    if (srv->witness)
        nodus_witness_peer_conn_closed(srv->witness, conn);
}

/* ── Channel post replication callback ────────────────────────── */

/** Callback: PRIMARY stored a post, replicate to BACKUPs */
static void ch_on_post_callback(nodus_channel_server_t *cs,
                                  const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                  const nodus_channel_post_t *post,
                                  const nodus_pubkey_t *author_pk) {
    nodus_server_t *srv = (nodus_server_t *)cs->cb_ctx;
    nodus_ch_replication_send(&srv->ch_replication, channel_uuid, post, author_pk);
}

/** Callback: channel server needs to PUT a signed value into DHT (e.g. node announcements) */
static int ch_dht_put_signed(const uint8_t *key_hash, size_t key_len,
                              const uint8_t *val_data, size_t val_len,
                              uint32_t ttl, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    if (!srv || key_len != NODUS_KEY_BYTES) return -1;

    nodus_key_t key;
    memcpy(key.bytes, key_hash, NODUS_KEY_BYTES);

    /* Create a value owned by this server's identity */
    nodus_value_t *val = NULL;
    int rc = nodus_value_create(&key, val_data, val_len,
                                 NODUS_VALUE_EPHEMERAL,
                                 ttl ? ttl : NODUS_DEFAULT_TTL,
                                 0, 1,
                                 &srv->identity.pk, &val);
    if (rc != 0 || !val) return -1;

    /* Sign with server's secret key */
    rc = nodus_value_sign(val, &srv->identity.sk);
    if (rc != 0) { nodus_value_free(val); return -1; }

    /* Store locally */
    rc = nodus_storage_put(&srv->storage, val);
    if (rc != 0) { nodus_value_free(val); return -1; }

    /* Replicate to K-closest peers */
    nodus_server_replicate_value(srv, val);
    nodus_value_free(val);
    return 0;
}

/* ── Identity publish to DHT ──────────────────────────────────────
 * Every nodus server publishes its pubkey to a well-known DHT key.
 * Witness module reads all entries to build the roster.
 * TTL = 10 min, refreshed every 60s. Dead nodes expire automatically. */

#define NODUS_PK_REGISTRY_TTL  600   /* 10 minutes */

static int nodus_server_publish_identity(nodus_server_t *srv) {
    /* Derive DHT key: SHA3-512("nodus:pk") */
    static const char key_str[] = "nodus:pk";
    nodus_key_t key;
    nodus_hash((const uint8_t *)key_str, sizeof(key_str) - 1, &key);

    /* Encode payload: CBOR { "id": node_id, "pk": pubkey, "ip": ip, "port": port } */
    uint8_t payload[4096];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, payload, sizeof(payload));
    cbor_encode_map(&enc, 4);

    cbor_encode_cstr(&enc, "id");
    cbor_encode_bstr(&enc, srv->identity.node_id.bytes, NODUS_KEY_BYTES);

    cbor_encode_cstr(&enc, "pk");
    cbor_encode_bstr(&enc, srv->identity.pk.bytes, NODUS_PK_BYTES);

    cbor_encode_cstr(&enc, "ip");
    const char *ip = srv->config.external_ip[0]
                   ? srv->config.external_ip
                   : srv->config.bind_ip;
    cbor_encode_cstr(&enc, ip);

    cbor_encode_cstr(&enc, "port");
    uint16_t pub_wport = srv->config.witness_port
                       ? srv->config.witness_port
                       : NODUS_DEFAULT_WITNESS_PORT;
    cbor_encode_uint(&enc, pub_wport);

    size_t payload_len = cbor_encoder_len(&enc);
    if (payload_len == 0) return -1;

    /* Create DHT value */
    nodus_value_t *val = NULL;
    int rc = nodus_value_create(&key, payload, payload_len,
                                 NODUS_VALUE_EPHEMERAL,
                                 NODUS_PK_REGISTRY_TTL,
                                 0, (uint64_t)time(NULL),
                                 &srv->identity.pk, &val);
    if (rc != 0 || !val) return -1;

    rc = nodus_value_sign(val, &srv->identity.sk);
    if (rc != 0) { nodus_value_free(val); return -1; }

    rc = nodus_storage_put(&srv->storage, val);
    if (rc != 0) { nodus_value_free(val); return -1; }

    nodus_server_replicate_value(srv, val);
    nodus_value_free(val);
    return 0;
}

/* ── Channel startup rejoin ───────────────────────────────────────
 * Called once from the main loop after hashring has ≥2 members.
 * 1. Scan channels.db for existing channel tables
 * 2. Re-track channels this node is responsible for
 * 3. Send ring_rejoin to authenticated peer sessions
 * 4. Send ch_sync_request to PRIMARY for each tracked channel
 */
static void ch_startup_rejoin(nodus_server_t *srv)
{
    /* 1. List all channels in local store */
    uint8_t *uuids = NULL;
    size_t count = 0;
    if (nodus_channel_store_list_all(&srv->ch_store, &uuids, &count) != 0 || count == 0) {
        fprintf(stderr, "CH_STARTUP: No existing channels in store, skipping rejoin\n");
        free(uuids);
        return;
    }

    fprintf(stderr, "CH_STARTUP: Found %zu channel(s) in store, checking responsibility\n", count);

    /* 2. Re-track channels this node is responsible for */
    int tracked = 0;
    for (size_t i = 0; i < count; i++) {
        const uint8_t *uuid = uuids + i * NODUS_UUID_BYTES;
        nodus_responsible_set_t rset;
        if (nodus_hashring_responsible(&srv->ring, uuid, &rset) != 0)
            continue;

        bool self_responsible = false;
        for (int r = 0; r < rset.count; r++) {
            if (nodus_key_cmp(&rset.nodes[r].node_id,
                               &srv->identity.node_id) == 0) {
                self_responsible = true;
                break;
            }
        }
        if (!self_responsible)
            continue;

        /* Re-track this channel */
        nodus_ch_ring_track(&srv->ch_ring, uuid, srv->ring.version);

        /* Ensure table exists (idempotent) */
        nodus_channel_create(&srv->ch_store, uuid, false, NULL, NULL, false);

        tracked++;
    }

    fprintf(stderr, "CH_STARTUP: Re-tracked %d/%zu channel(s)\n", tracked, count);

    /* 3. Send ring_rejoin to all authenticated node sessions */
    for (int i = 0; i < NODUS_CH_MAX_NODE_SESSIONS; i++) {
        nodus_ch_node_session_t *ns = &srv->ch_server.nodes[i];
        if (!ns->conn || !ns->authenticated)
            continue;

        uint8_t buf[256];
        size_t len = 0;
        if (nodus_t2_ch_ring_rejoin(0, &srv->identity.node_id,
                                     srv->ring.version,
                                     buf, sizeof(buf), &len) == 0) {
            nodus_tcp_send(ns->conn, buf, len);
            fprintf(stderr, "CH_STARTUP: Sent ring_rejoin to %s:%u\n",
                    ns->conn->ip, (unsigned)ns->conn->port);
        }
    }

    /* 4. Send ch_sync_request to PRIMARY for each tracked channel */
    for (size_t i = 0; i < count; i++) {
        const uint8_t *uuid = uuids + i * NODUS_UUID_BYTES;

        /* Only sync channels we're tracking */
        if (!nodus_ch_ring_is_tracked(&srv->ch_ring, uuid))
            continue;

        nodus_responsible_set_t rset;
        if (nodus_hashring_responsible(&srv->ring, uuid, &rset) != 0)
            continue;

        /* Find PRIMARY (first in responsible set that isn't us) */
        for (int r = 0; r < rset.count; r++) {
            if (nodus_key_cmp(&rset.nodes[r].node_id,
                               &srv->identity.node_id) == 0)
                continue;

            /* Find authenticated session for this node */
            nodus_ch_node_session_t *ns = NULL;
            for (int j = 0; j < NODUS_CH_MAX_NODE_SESSIONS; j++) {
                nodus_ch_node_session_t *c = &srv->ch_server.nodes[j];
                if (c->conn && c->authenticated &&
                    nodus_key_cmp(&c->node_id, &rset.nodes[r].node_id) == 0) {
                    ns = c;
                    break;
                }
            }
            if (!ns) {
                /* Connect to PRIMARY for sync */
                nodus_ch_server_connect_to_peer(&srv->ch_server,
                                                  rset.nodes[r].ip,
                                                  srv->ch_server.port,
                                                  &rset.nodes[r].node_id);
                break;  /* Connection is async; hinted handoff retry will handle sync later */
            }

            /* Send sync request (since=0 to get all posts) */
            uint8_t buf[256];
            size_t len = 0;
            if (nodus_t2_ch_sync_request(0, uuid, 0,
                                          buf, sizeof(buf), &len) == 0) {
                nodus_tcp_send(ns->conn, buf, len);
                fprintf(stderr, "CH_STARTUP: Sent ch_sync_request to %s:%u\n",
                        ns->conn->ip, (unsigned)ns->conn->port);
            }
            break;  /* Only need one sync source */
        }
    }

    free(uuids);
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

    /* Create batch forward epoll fd */
    srv->bf_state.bf_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (srv->bf_state.bf_epoll_fd < 0) {
        fprintf(stderr, "Failed to create BF epoll fd\n");
        return -1;
    }
    for (int i = 0; i < NODUS_BF_FD_TABLE_SIZE; i++) {
        srv->bf_fd_table[i].batch_idx = -1;
        srv->bf_fd_table[i].forward_idx = -1;
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

    /* Register default channels (idempotent) */
    nodus_channel_store_register_defaults(&srv->ch_store);

    /* Init routing table */
    nodus_routing_init(&srv->routing, &srv->identity.node_id);

    /* Init hash ring (populated by Kademlia routing, NOT cluster peers) */
    nodus_hashring_init(&srv->ring);

    /* Add self to hash ring */
    uint16_t self_peer_port = config->peer_port ? config->peer_port : NODUS_DEFAULT_PEER_PORT;
    const char *self_ip = config->external_ip[0] ? config->external_ip : config->bind_ip;
    nodus_hashring_add(&srv->ring, &srv->identity.node_id,
                        self_ip, self_peer_port);

    /* Init cluster membership (heartbeat, leader election) */
    nodus_cluster_init(&srv->cluster, srv);

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

    /* Init inter-node TCP transport (own epoll — shared epoll not possible
     * because listen socket uses NULL data.ptr as marker) */
    uint16_t peer_port = config->peer_port ? config->peer_port : NODUS_DEFAULT_PEER_PORT;
    if (peer_port == config->tcp_port) {
        fprintf(stderr, "ERROR: peer_port (%d) must differ from tcp_port (%d)\n",
                peer_port, config->tcp_port);
        return -1;
    }
    if (nodus_tcp_init(&srv->inter_tcp, -1) != 0)
        return -1;
    srv->inter_tcp.on_accept     = on_inter_accept;
    srv->inter_tcp.on_frame      = on_inter_frame;
    srv->inter_tcp.on_disconnect = on_inter_disconnect;
    srv->inter_tcp.cb_ctx        = srv;

    /* Bind TCP (client port) */
    if (nodus_tcp_listen(&srv->tcp, config->bind_ip, config->tcp_port) != 0) {
        fprintf(stderr, "Failed to listen on TCP %s:%d\n",
                config->bind_ip, config->tcp_port);
        return -1;
    }

    /* Bind inter-node TCP (peer port) */
    if (nodus_tcp_listen(&srv->inter_tcp, config->bind_ip, peer_port) != 0) {
        fprintf(stderr, "Failed to listen on inter-node TCP %s:%d\n",
                config->bind_ip, peer_port);
        return -1;
    }

    /* Init new channel server (TCP 4003) */
    if (nodus_channel_server_init(&srv->ch_server) != 0)
        return -1;

    srv->ch_server.ch_store = &srv->ch_store;
    srv->ch_server.ring = &srv->ring;
    srv->ch_server.identity = &srv->identity;
    const char *ch_self_ip = config->external_ip[0] ? config->external_ip : config->bind_ip;
    snprintf(srv->ch_server.self_ip, sizeof(srv->ch_server.self_ip), "%s", ch_self_ip);

    uint16_t ch_port = config->ch_port ? config->ch_port : NODUS_DEFAULT_CH_PORT;
    if (ch_port == config->tcp_port || ch_port == peer_port) {
        fprintf(stderr, "ERROR: ch_port (%d) must differ from tcp_port (%d) and peer_port (%d)\n",
                ch_port, config->tcp_port, peer_port);
        return -1;
    }
    if (nodus_channel_server_listen(&srv->ch_server, config->bind_ip, ch_port) != 0) {
        fprintf(stderr, "Failed to listen on channel TCP %s:%d\n",
                config->bind_ip, ch_port);
        return -1;
    }

    /* Init channel replication */
    nodus_ch_replication_init(&srv->ch_replication, &srv->ch_server);

    /* Init channel ring management */
    nodus_ch_ring_init(&srv->ch_ring, &srv->ch_server);

    /* Wire replication callback: PRIMARY -> after post stored, trigger replicate to BACKUPs */
    srv->ch_server.on_post = ch_on_post_callback;
    srv->ch_server.cb_ctx = srv;

    /* Wire DHT put callback: channel server announces node list to DHT */
    srv->ch_server.dht_put_signed = ch_dht_put_signed;
    srv->ch_server.dht_ctx = srv;

    /* Wire cross-module pointers so dispatch handlers can call real implementations */
    srv->ch_server.ch_ring_ptr = &srv->ch_ring;
    srv->ch_server.ch_replication_ptr = &srv->ch_replication;

    /* Init witness BFT TCP transport (dedicated port 4004) */
    uint16_t witness_port = config->witness_port ? config->witness_port : NODUS_DEFAULT_WITNESS_PORT;
    if (witness_port == config->tcp_port || witness_port == peer_port || witness_port == ch_port) {
        fprintf(stderr, "ERROR: witness_port (%d) must differ from tcp_port (%d), "
                "peer_port (%d), and ch_port (%d)\n",
                witness_port, config->tcp_port, peer_port, ch_port);
        return -1;
    }
    if (nodus_tcp_init(&srv->witness_tcp, -1) != 0)
        return -1;
    srv->witness_tcp.on_accept     = on_witness_accept;
    srv->witness_tcp.on_frame      = on_witness_frame;
    srv->witness_tcp.on_disconnect = on_witness_disconnect;
    srv->witness_tcp.cb_ctx        = srv;

    if (nodus_tcp_listen(&srv->witness_tcp, config->bind_ip, witness_port) != 0) {
        fprintf(stderr, "Failed to listen on witness TCP %s:%d\n",
                config->bind_ip, witness_port);
        return -1;
    }

    /* Bind UDP */
    if (nodus_udp_bind(&srv->udp, config->bind_ip, config->udp_port) != 0) {
        fprintf(stderr, "Failed to bind UDP %s:%d\n",
                config->bind_ip, config->udp_port);
        return -1;
    }

    /* Add seed nodes to cluster.
     * Seeds don't have node_ids yet — they'll be discovered via PING/PONG.
     * For now, create placeholder node_ids from IP hash. The real node_id
     * will be learned when the seed responds to our PING. */
    for (int i = 0; i < config->seed_count; i++) {
        nodus_key_t seed_id;
        nodus_hash((const uint8_t *)config->seed_nodes[i],
                    strlen(config->seed_nodes[i]), &seed_id);
        nodus_cluster_add_peer(&srv->cluster, &seed_id,
                              config->seed_nodes[i],
                              config->seed_ports[i],
                              config->seed_ports[i] + 2);  /* Peer TCP = UDP + 2 */
    }

    /* Initialize witness module (all nodes are automatic witnesses) */
    srv->witness = calloc(1, sizeof(nodus_witness_t));
    if (!srv->witness) {
        fprintf(stderr, "Failed to allocate witness context\n");
        return -1;
    }
    srv->witness->tcp = &srv->witness_tcp;  /* Set before init (preserved across memset) */
    if (nodus_witness_init(srv->witness, srv, &config->witness) != 0) {
        fprintf(stderr, "Witness module init failed\n");
        free(srv->witness);
        srv->witness = NULL;
        /* Non-fatal — server can run without witness */
        fprintf(stderr, "WARNING: running without witness module\n");
    }

    /* Publish identity to DHT for witness discovery */
    nodus_server_publish_identity(srv);

    return 0;
}

int nodus_server_run(nodus_server_t *srv) {
    if (!srv) return -1;
    srv->running = true;

    fprintf(stderr, "Nodus v%s running\n", NODUS_VERSION_STRING);
    fprintf(stderr, "  Identity: %s\n", srv->identity.fingerprint);
    fprintf(stderr, "  TCP port: %d\n", srv->tcp.port);
    fprintf(stderr, "  Peer port: %d\n", srv->inter_tcp.port);
    fprintf(stderr, "  Witness port: %d\n", srv->witness_tcp.port);
    fprintf(stderr, "  Channel port: %d\n", srv->ch_server.port);
    fprintf(stderr, "  UDP port: %d\n", srv->udp.port);

    while (srv->running) {
        /* Poll client TCP events */
        nodus_tcp_poll(&srv->tcp, 50);

        /* Poll inter-node TCP events */
        nodus_tcp_poll(&srv->inter_tcp, 50);

        /* Witness BFT TCP (port 4004) is polled inside nodus_witness_tick() */

        /* Poll new channel server (TCP 4003) */
        nodus_channel_server_poll(&srv->ch_server, 50);

        /* Process any pending UDP datagrams */
        nodus_udp_poll(&srv->udp);

        /* Cluster: send heartbeats, check peer health */
        nodus_cluster_tick(&srv->cluster);

        /* Ping-before-evict: evict LRU peers that didn't respond */
        eviction_sweep(srv);

        /* CRIT-4: Disconnect idle TCP connections */
        idle_timeout_sweep(srv);

        /* Refresh identity in DHT (every 60s) */
        {
            static uint64_t last_pk_publish = 0;
            uint64_t pk_now = nodus_time_now();
            if (pk_now - last_pk_publish >= 60) {
                last_pk_publish = pk_now;
                nodus_server_publish_identity(srv);
            }
        }

        /* Witness BFT: timeout checks, peer reconnection */
        if (srv->witness)
            nodus_witness_tick(srv->witness);

        /* Channel server tick: heartbeat send/check */
        {
            uint64_t now_ms = nodus_time_now_ms();
            nodus_channel_server_tick(&srv->ch_server, now_ms);

            /* Channel replication: retry hinted handoff (every 30s) */
            nodus_ch_replication_retry(&srv->ch_replication, now_ms);

            /* Channel ring management: check heartbeat timeouts (every 5s) */
            nodus_ch_ring_tick(&srv->ch_ring, now_ms);

            /* One-shot channel startup rejoin: scan channels.db, re-track,
             * send ring_rejoin to peers once hashring has ≥2 members */
            if (!srv->ch_startup_done && srv->ring.count >= 2) {
                srv->ch_startup_done = true;
                ch_startup_rejoin(srv);
            }
        }

        /* Presence: expire stale entries + broadcast local list to peers */
        nodus_presence_tick(srv);

        /* Retry DHT hinted handoff (failed replication, every 30s) */
        dht_hinted_retry(srv);

        /* FIND_VALUE async state machine tick */
        dht_find_value_tick(srv);

        /* Batch forward async tick */
        bf_tick(srv);

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

    /* Clean up batch forward state */
    for (int i = 0; i < NODUS_BF_MAX_BATCHES; i++) {
        if (srv->bf_state.batches[i].active)
            bf_batch_cleanup(srv, &srv->bf_state.batches[i]);
    }
    if (srv->bf_state.bf_epoll_fd >= 0) {
        close(srv->bf_state.bf_epoll_fd);
        srv->bf_state.bf_epoll_fd = -1;
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

    nodus_channel_server_close(&srv->ch_server);
    nodus_tcp_close(&srv->tcp);
    nodus_tcp_close(&srv->inter_tcp);
    nodus_tcp_close(&srv->witness_tcp);
    nodus_udp_close(&srv->udp);
    nodus_storage_close(&srv->storage);
    nodus_channel_store_close(&srv->ch_store);
    nodus_identity_clear(&srv->identity);
}
