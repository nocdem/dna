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

    /* Wait for connect (2s timeout) */
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    rc = select(fd + 1, NULL, &wfds, NULL, &tv);
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

    for (int i = 0; i < srv->pbft.peer_count; i++) {
        nodus_cluster_peer_t *peer = &srv->pbft.peers[i];
        if (peer->state != NODUS_NODE_ALIVE)
            continue;

        int rc = send_frame_to_peer(peer->ip, peer->tcp_port, frame, flen);
        if (rc != 0) {
            /* Queue to hinted handoff for retry */
            nodus_storage_hinted_insert(&srv->storage,
                                         peer->ip, peer->tcp_port,
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

    /* Try to deliver pending hints to each ALIVE peer */
    for (int i = 0; i < srv->pbft.peer_count; i++) {
        nodus_cluster_peer_t *peer = &srv->pbft.peers[i];
        if (peer->state != NODUS_NODE_ALIVE)
            continue;

        nodus_dht_hint_t *entries = NULL;
        size_t count = 0;
        if (nodus_storage_hinted_get(&srv->storage,
                                       peer->ip, peer->tcp_port,
                                       100, &entries, &count) != 0 || count == 0)
            continue;

        for (size_t j = 0; j < count; j++) {
            int rc = send_frame_to_peer(peer->ip, peer->tcp_port,
                                         entries[j].frame_data,
                                         entries[j].frame_len);
            if (rc == 0) {
                nodus_storage_hinted_delete(&srv->storage, entries[j].id);
            }
        }

        nodus_storage_hinted_free(entries, count);
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

    /* Store */
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

    /* Replicate to alive PBFT peers via TCP STORE */
    replicate_value(srv, val);

    /* Respond OK */
    size_t len = 0;
    nodus_t2_put_ok(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);

    nodus_value_free(val);
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
        size_t len = 0;
        nodus_t2_result_empty(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
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
                nodus_storage_put(&srv->storage, t1msg.value);
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
            /* Inter-nodus DHT value replication (no auth required) */
            nodus_tier1_msg_t t1msg;
            memset(&t1msg, 0, sizeof(t1msg));
            if (nodus_t1_decode(payload, len, &t1msg) == 0 &&
                t1msg.value && nodus_value_verify(t1msg.value) == 0) {
                nodus_storage_put(&srv->storage, t1msg.value);
                notify_listeners(srv, &t1msg.value->key_hash, t1msg.value);
                fprintf(stderr, "REPL-RX: stored replicated value\n");
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
                nodus_storage_put(&srv->storage, msg.value);
                /* Notify local listeners */
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
    }

    return 0;
}

void nodus_server_stop(nodus_server_t *srv) {
    if (srv) srv->running = false;
}

void nodus_server_close(nodus_server_t *srv) {
    if (!srv) return;

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
