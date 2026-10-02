/**
 * Nodus — DHT / storage half of the server (component split S4)
 *
 * The DHT handlers and periodic work, moved out of nodus_server.c
 * unchanged (decision docs/plans/decisions/2026-10-01-nodus-component-
 * split.md items 2-4, 16, 17): the client DHT methods (put, get, get_all,
 * get_batch, cnt_batch, listen, unlisten, ch_*; media in
 * nodus_dht_media.c), the 4002 DHT frames (fv, get_batch, m_sv, T1 sv /
 * sub / unsub / ntf), the UDP 4000 Kademlia queries other than ping / pong
 * (fn, fn_r, sv, fv), the iterative lookup engine, batch forward,
 * replication, republish, hinted handoff, listen subscriptions, ping-
 * before-evict, storage cleanup, WAL checkpoint and vacuum.
 *
 * Reaches core only through its host view (dht/nodus_dht.h,
 * nodus_dht_host_t); includes no server header, so a storage binary can
 * link it without core (test_dht_linked). Log lines keep the "NODUS_SRV"
 * tag they had, so what operators and the harness grep is unchanged.
 *
 * @file nodus_dht_server.c
 */

#include "dht/nodus_dht.h"
#include "dht/nodus_dht_media.h"
#include "protocol/nodus_tier1.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_channel_crypto.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/qgp_mlkem.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "NODUS_SRV"

extern void qgp_secure_memzero(void *ptr, size_t len);

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

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* Response buffer (shared, single-threaded).
 * Must accommodate max value (1MB data) + Dilithium5 pk(2592) + sig(4627) + CBOR.
 * Previous 64KB was too small — values >55KB data caused silent GET failures.
 * The DHT's own; core keeps its own for its replies (split S4). */
#define RESP_BUF_SIZE (NODUS_MAX_VALUE_SIZE + 65536)
static uint8_t resp_buf[RESP_BUF_SIZE];

/* ── DHT → core: the host view's sends (nodus_dht_host_t) ────────── */

/* HOT: a reply / push frame to the session in `origin`'s slot. */
static int dht_send_origin(nodus_dht_t *dht, nodus_dht_origin_t origin,
                           const uint8_t *frame, size_t len) {
    return dht->host.send_to_origin(dht->host.ctx, origin, frame, len);
}

static int dht_send_client(nodus_dht_t *dht, int slot,
                           const uint8_t *frame, size_t len) {
    nodus_dht_origin_t o = { NODUS_DHT_ORIGIN_CLIENT, slot };
    return dht_send_origin(dht, o, frame, len);
}

static int dht_send_inter(nodus_dht_t *dht, int slot,
                          const uint8_t *frame, size_t len) {
    nodus_dht_origin_t o = { NODUS_DHT_ORIGIN_INTER, slot };
    return dht_send_origin(dht, o, frame, len);
}

/* A T1 datagram from UDP 4000 (raw CBOR; the transport frames it). */
static int dht_udp_send(nodus_dht_t *dht, const uint8_t *payload, size_t len,
                        const char *ip, uint16_t port) {
    return dht->host.udp_send(dht->host.ctx, payload, len, ip, port);
}

/* A pre-framed frame to a peer's 4002 over core's inter-node pool;
 * 0 / -1, synchronous (the hinted-handoff decision reads it). */
static int dht_inter_send(nodus_dht_t *dht, const char *ip, uint16_t port,
                          const nodus_key_t *expected_node_id,
                          const uint8_t *frame, size_t flen) {
    return dht->host.inter_send(dht->host.ctx, ip, port, expected_node_id,
                                frame, flen);
}

/* A failed send to `node_id` is worth a hint (cluster member, recently
 * seen — core's cluster). */
static bool dht_hint_wanted(nodus_dht_t *dht, const nodus_key_t *node_id) {
    return dht->host.hint_wanted(dht->host.ctx, node_id);
}

/* Forward declaration: iterative lookup engine (defined later in file).
 * Used by replicate_value / replicate_media_chunk for large-cluster PUT
 * discovery of true K-closest nodes. */
static int iterative_lookup_start(nodus_dht_t *dht,
                                   const nodus_key_t *target,
                                   int session_slot,
                                   uint32_t client_txn_id,
                                   void (*on_complete)(struct nodus_dht *,
                                                       nodus_peer_t *, int,
                                                       void *),
                                   void *cb_data,
                                   void (*cb_data_free)(void *));

/* ── PUT replication callback context (iterative store for large clusters) ── */

typedef struct {
    uint8_t    *frame;      /* heap-allocated replication frame (owned) */
    size_t      flen;
    nodus_key_t key_hash;   /* for logging */
} put_repl_ctx_t;

static void put_repl_ctx_free(void *p) {
    put_repl_ctx_t *ctx = (put_repl_ctx_t *)p;
    if (!ctx) return;
    free(ctx->frame);
    free(ctx);
}

typedef struct {
    uint8_t    *frame;      /* heap-allocated media replication frame (owned) */
    size_t      flen;
    nodus_key_t media_key;  /* content_hash mapped to nodus_key_t */
    uint32_t    chunk_index;/* for logging */
} put_media_ctx_t;

static void put_media_ctx_free(void *p) {
    put_media_ctx_t *ctx = (put_media_ctx_t *)p;
    if (!ctx) return;
    free(ctx->frame);
    free(ctx);
}

static void put_replication_complete(nodus_dht_t *dht,
                                      nodus_peer_t *closest, int count,
                                      void *user_data);
static void media_replication_complete(nodus_dht_t *dht,
                                        nodus_peer_t *closest, int count,
                                        void *user_data);

/* ── Rate limiting ───────────────────────────────────────────────── */

static bool rate_check_put(nodus_dht_session_t *sess) {
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

static int session_add_listen(nodus_dht_session_t *sess, const nodus_key_t *key) {
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

static void session_remove_listen(nodus_dht_session_t *sess, const nodus_key_t *key) {
    for (int i = 0; i < sess->listen_count; i++) {
        if (nodus_key_cmp(&sess->listen_keys[i], key) == 0) {
            sess->listen_keys[i] = sess->listen_keys[--sess->listen_count];
            return;
        }
    }
}

/** Notify all sessions listening on this key */
static void notify_listeners(nodus_dht_t *dht, const nodus_key_t *key,
                              const nodus_value_t *val) {
    /* HIGH-5 fix: use per-operation heap buffer instead of shared static resp_buf
     * to avoid reentrancy risk when iterating sessions */
    uint8_t *notify_buf = malloc(RESP_BUF_SIZE);
    if (!notify_buf) return;

    for (int i = 0; i < NODUS_MAX_SESSIONS; i++) {
        nodus_dht_session_t *s = &dht->sessions[i];
        /* open == conn && authenticated for a session with listen keys
         * (nodus_dht_session_t) */
        if (!s->open) continue;

        for (int j = 0; j < s->listen_count; j++) {
            if (nodus_key_cmp(&s->listen_keys[j], key) == 0) {
                size_t len = 0;
                if (nodus_t2_value_changed(0, key, val,
                        notify_buf, RESP_BUF_SIZE, &len) == 0) {
                    dht_send_client(dht, i, notify_buf, len);
                }
                break;
            }
        }
    }

    free(notify_buf);
}

/* ── Listen Forwarding (Scribe pattern) subscription table ──────── */

/**
 * Add or refresh a subscription entry. Returns 0 on success, -1 if full.
 * If an entry with the same (key, subscriber_node_id) already exists,
 * its TTL is refreshed and IP/port updated.
 */
static int subscription_add(nodus_subscription_table_t *table,
                             const nodus_key_t *key,
                             const nodus_key_t *subscriber_id,
                             const char *ip, uint16_t port) {
    if (!table || !key || !subscriber_id) return -1;
    uint64_t now = nodus_time_now();
    uint64_t expires = now + NODUS_SUBSCRIPTION_TTL;

    /* Refresh duplicate */
    for (int i = 0; i < table->count; i++) {
        nodus_subscription_t *e = &table->entries[i];
        if (!e->active) continue;
        if (nodus_key_cmp(&e->key, key) == 0 &&
            nodus_key_cmp(&e->subscriber_node_id, subscriber_id) == 0) {
            e->expires_at = expires;
            if (ip && ip[0]) {
                snprintf(e->subscriber_ip, sizeof(e->subscriber_ip), "%s", ip);
            }
            if (port) e->subscriber_port = port;
            return 0;
        }
    }

    /* Find empty slot — prefer inactive slots in [0..count) */
    int slot = -1;
    for (int i = 0; i < table->count; i++) {
        if (!table->entries[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        if (table->count >= NODUS_MAX_SUBSCRIPTIONS) return -1;
        slot = table->count++;
    }

    nodus_subscription_t *e = &table->entries[slot];
    memset(e, 0, sizeof(*e));
    e->active = true;
    e->key = *key;
    e->subscriber_node_id = *subscriber_id;
    if (ip) {
        snprintf(e->subscriber_ip, sizeof(e->subscriber_ip), "%s", ip);
    }
    e->subscriber_port = port ? port : NODUS_DEFAULT_PEER_PORT;
    e->expires_at = expires;
    return 0;
}

/** Mark matching subscription inactive. */
static void subscription_remove(nodus_subscription_table_t *table,
                                 const nodus_key_t *key,
                                 const nodus_key_t *subscriber_id) {
    if (!table || !key || !subscriber_id) return;
    for (int i = 0; i < table->count; i++) {
        nodus_subscription_t *e = &table->entries[i];
        if (!e->active) continue;
        if (nodus_key_cmp(&e->key, key) == 0 &&
            nodus_key_cmp(&e->subscriber_node_id, subscriber_id) == 0) {
            e->active = false;
            return;
        }
    }
}

/** Remove all expired subscriptions. Called periodically. */
static void subscription_cleanup_expired(nodus_subscription_table_t *table) {
    if (!table) return;
    uint64_t now = nodus_time_now();
    int removed = 0;
    for (int i = 0; i < table->count; i++) {
        nodus_subscription_t *e = &table->entries[i];
        if (!e->active) continue;
        if (e->expires_at && e->expires_at <= now) {
            e->active = false;
            removed++;
        }
    }
    /* Compact trailing inactive slots to keep count accurate */
    while (table->count > 0 && !table->entries[table->count - 1].active) {
        table->count--;
    }
    if (removed > 0) {
        QGP_LOG_DEBUG(LOG_TAG, "SUB_CLEANUP: removed %d expired subscriptions (count=%d)",
                       removed, table->count);
    }
}

#define NODUS_SUB_RENEWAL_PER_TICK  5   /* Max listens to renew per event loop tick */

/* Forward decl — defined later in file */
static void listen_fwd_complete(nodus_dht_t *dht,
                                 nodus_peer_t *closest, int count,
                                 void *user_data);

/** Periodic subscription renewal: re-forward local client LISTEN keys to
 *  current responsible nodes. Rate-limited to prevent bursts.
 *
 *  Walks through all sessions and their listen_keys, starting a new
 *  iterative FIND_NODE lookup for each. Processes up to
 *  NODUS_SUB_RENEWAL_PER_TICK keys per call, saving progress in
 *  dht->sub_renewal bookmark to resume next tick.
 *
 *  A full renewal cycle starts every NODUS_SUBSCRIPTION_TTL/2 (7.5 min).
 */
static void subscription_renew_tick(nodus_dht_t *dht) {
    if (!dht) return;

    /* Start a new renewal cycle every NODUS_SUBSCRIPTION_TTL / 2 */
    uint64_t now = nodus_time_now();
    if (now - dht->sub_renewal.last_renewal < NODUS_SUBSCRIPTION_TTL / 2) {
        /* Not time yet — but if we're mid-cycle, continue processing */
        if (dht->sub_renewal.session_idx == 0 && dht->sub_renewal.key_idx == 0) {
            return;
        }
    } else if (dht->sub_renewal.session_idx == 0 && dht->sub_renewal.key_idx == 0) {
        /* Start new cycle */
        dht->sub_renewal.last_renewal = now;
    }

    int processed = 0;
    while (processed < NODUS_SUB_RENEWAL_PER_TICK &&
           dht->sub_renewal.session_idx < NODUS_MAX_SESSIONS) {

        nodus_dht_session_t *s = &dht->sessions[dht->sub_renewal.session_idx];

        if (!s->open) {
            /* Skip disconnected sessions (an unauthenticated one has no
             * listen keys — the branch below skips it the same way) */
            dht->sub_renewal.session_idx++;
            dht->sub_renewal.key_idx = 0;
            continue;
        }

        if (dht->sub_renewal.key_idx >= s->listen_count) {
            /* Done with this session */
            dht->sub_renewal.session_idx++;
            dht->sub_renewal.key_idx = 0;
            continue;
        }

        /* Process this listen key: re-forward subscription */
        nodus_key_t *key_copy = malloc(sizeof(nodus_key_t));
        if (key_copy) {
            *key_copy = s->listen_keys[dht->sub_renewal.key_idx];
            if (iterative_lookup_start(dht, key_copy, -1, 0,
                                        listen_fwd_complete, key_copy, free) != 0) {
                /* No slots — fallback (synchronous) */
                nodus_peer_t closest[NODUS_R];
                int count = nodus_routing_find_closest(&dht->routing, key_copy,
                                                         closest, NODUS_R);
                listen_fwd_complete(dht, closest, count, key_copy);
            }
        }

        dht->sub_renewal.key_idx++;
        processed++;
    }

    /* If we walked past all sessions, reset for next cycle */
    if (dht->sub_renewal.session_idx >= NODUS_MAX_SESSIONS) {
        dht->sub_renewal.session_idx = 0;
        dht->sub_renewal.key_idx = 0;
        QGP_LOG_DEBUG(LOG_TAG, "SUB_RENEWAL: cycle complete");
    }
}

/** Send a T1 notify to every remote subscriber interested in key. */
static void subscription_notify(nodus_dht_t *dht, const nodus_key_t *key,
                                 const nodus_value_t *val) {
    if (!dht || !key || !val) return;
    nodus_subscription_table_t *table = &dht->subscriptions;
    if (table->count == 0) return;

    /* Encode once, reuse for all subscribers. */
    uint8_t *cbor_buf = malloc(RESP_BUF_SIZE);
    if (!cbor_buf) return;
    size_t clen = 0;
    if (nodus_t1_notify(0, key, val, cbor_buf, RESP_BUF_SIZE, &clen) != 0) {
        free(cbor_buf);
        return;
    }
    uint8_t *frame = malloc(clen + 16);
    if (!frame) { free(cbor_buf); return; }
    size_t flen = nodus_frame_encode(frame, clen + 16, cbor_buf, (uint32_t)clen);
    free(cbor_buf);
    if (flen == 0) { free(frame); return; }

    uint64_t now = nodus_time_now();
    int sent = 0;
    for (int i = 0; i < table->count; i++) {
        nodus_subscription_t *e = &table->entries[i];
        if (!e->active) continue;
        if (e->expires_at && e->expires_at <= now) continue;
        if (nodus_key_cmp(&e->key, key) != 0) continue;
        /* Skip sending to self */
        if (nodus_key_cmp(&e->subscriber_node_id, &dht->host.identity->node_id) == 0) continue;
        if (!e->subscriber_ip[0]) continue;
        if (dht_inter_send(dht, e->subscriber_ip, e->subscriber_port,
                           &e->subscriber_node_id, frame, flen) == 0) {
            sent++;
        }
    }

    if (sent > 0) {
        char kh[17];
        for (int i = 0; i < 8; i++) snprintf(kh + i*2, sizeof(kh) - i*2, "%02x", key->bytes[i]);
        kh[16] = '\0';
        QGP_LOG_DEBUG(LOG_TAG, "SUB_NOTIFY: key=%s... forwarded to %d subscribers",
                       kh, sent);
    }

    free(frame);
}

/* Channel session helpers are now in nodus_channel_server.c */

/* ── Server-to-server TCP STORE (with hinted handoff on failure) ── */

/**
 * Send a pre-encoded wire frame to a peer. Returns 0 on success, -1 on failure.
 */
/* Legacy blocking send — kept for potential future use (e.g., synchronous fallback paths). */
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

/**
 * Replicate a pre-encoded STORE frame to the given peers.
 * Shared by small-cluster fast path and large-cluster fallback path.
 * Performs hinted-handoff bookkeeping on transient failures.
 */
static void do_replicate_store_frame(nodus_dht_t *dht,
                                      const nodus_key_t *key_hash,
                                      const uint8_t *frame, size_t flen,
                                      nodus_peer_t *closest, int count,
                                      const char *log_prefix,
                                      const char *kh) {
    int sent = 0, skipped_self = 0, failed = 0, hinted = 0;
    int fail_indices[NODUS_K];
    bool is_media = (strncmp(log_prefix, "MEDIA", 5) == 0);
    for (int i = 0; i < count; i++) {
        /* Skip self */
        if (nodus_key_cmp(&closest[i].node_id, &dht->host.identity->node_id) == 0) {
            skipped_self++;
            continue;
        }

        int send_rc = dht_inter_send(dht, closest[i].ip, closest[i].tcp_port,
                                     &closest[i].node_id, frame, flen);
        if (is_media) {
            fprintf(stderr,
                    "MEDIA-REPL-SEND: hash=%s peer=%s:%d rc=%d flen=%zu\n",
                    kh, closest[i].ip, closest[i].tcp_port, send_rc, flen);
        }
        if (send_rc != 0) {
            if (failed < NODUS_K) fail_indices[failed] = i;
            failed++;
            QGP_LOG_DEBUG(LOG_TAG, "%s: key=%s... SEND_FAIL to %s:%d",
                          log_prefix, kh, closest[i].ip, closest[i].tcp_port);
        } else {
            sent++;
        }
    }

    int peers_tried = count - skipped_self;
    if (sent < NODUS_REPLICATION_MIN && peers_tried >= NODUS_REPLICATION_MIN && failed > 0) {
        for (int f = 0; f < failed && f < NODUS_K; f++) {
            int i = fail_indices[f];
            /* Item 9: hints only for cluster members (routing ids of
             * unknown nodes are not hinted; republish covers them) seen
             * less than NODUS_HINT_OFFLINE_SKIP_SEC ago (core's cluster). */
            if (!dht_hint_wanted(dht, &closest[i].node_id)) continue;
            /* F4: a refused hint (cap reached, -3, logged by storage)
             * is not counted as queued. */
            if (nodus_storage_hinted_insert(&dht->storage,
                                             &closest[i].node_id,
                                             closest[i].ip, closest[i].tcp_port,
                                             frame, flen) == 0)
                hinted++;
        }
    }

    if (is_media) {
        fprintf(stderr,
                "MEDIA-REPL-DONE: hash=%s sent=%d self=%d fail=%d hint=%d peers=%d\n",
                kh, sent, skipped_self, failed, hinted, peers_tried);
    }
    QGP_LOG_DEBUG(LOG_TAG,
                  "%s: key=%s... done sent=%d self=%d fail=%d hint=%d peers=%d",
                  log_prefix, kh, sent, skipped_self, failed, hinted, peers_tried);
    (void)key_hash;  /* reserved for future */
}

void nodus_dht_replicate_value(nodus_dht_t *dht, const nodus_value_t *val) {
    /* Key hash prefix for logging */
    char rpl_kh[17];
    for (int kk = 0; kk < 8; kk++) snprintf(rpl_kh + kk*2, sizeof(rpl_kh) - kk*2, "%02x", val->key_hash.bytes[kk]);
    rpl_kh[16] = '\0';

    /* Encode T1 STORE_VALUE once for all peers */
    uint8_t *cbor_buf = malloc(RESP_BUF_SIZE);
    if (!cbor_buf) return;
    size_t clen = 0;
    if (nodus_t1_store_value(0, val, cbor_buf, RESP_BUF_SIZE, &clen) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "REPL: key=%s... encode FAILED", rpl_kh);
        free(cbor_buf);
        return;
    }

    /* Wire-frame it */
    uint8_t *frame = malloc(clen + 16);
    if (!frame) { free(cbor_buf); return; }
    size_t flen = nodus_frame_encode(frame, clen + 16, cbor_buf, (uint32_t)clen);
    free(cbor_buf);
    if (flen == 0) { free(frame); return; }

    int known = nodus_routing_count(&dht->routing);

    if (known <= NODUS_R * 4) {
        /* Small cluster fast path — routing table IS the network. */
        nodus_peer_t closest[NODUS_R];
        int count = nodus_routing_find_closest(&dht->routing, &val->key_hash,
                                                closest, NODUS_R);
        QGP_LOG_DEBUG(LOG_TAG, "REPL: key=%s... vid=%llu fast_path found=%d (R=%d)",
                      rpl_kh, (unsigned long long)val->value_id, count, NODUS_R);
        do_replicate_store_frame(dht, &val->key_hash, frame, flen,
                                 closest, count, "REPL", rpl_kh);
        free(frame);
        return;
    }

    /* Large cluster: iterative FIND_NODE, then STORE from callback.
     * Frame ownership transfers to the ctx; the callback (or cb_data_free
     * on abandonment) frees both the ctx and the frame. */
    put_repl_ctx_t *ctx = malloc(sizeof(put_repl_ctx_t));
    if (!ctx) { free(frame); return; }
    ctx->frame = frame;
    ctx->flen = flen;
    ctx->key_hash = val->key_hash;

    QGP_LOG_DEBUG(LOG_TAG, "REPL: key=%s... vid=%llu iter_path known=%d",
                  rpl_kh, (unsigned long long)val->value_id, known);

    if (iterative_lookup_start(dht, &val->key_hash, -1, 0,
                                put_replication_complete, ctx,
                                put_repl_ctx_free) != 0) {
        /* No lookup slots — fallback to routing table fast path. */
        nodus_peer_t closest[NODUS_R];
        int count = nodus_routing_find_closest(&dht->routing, &val->key_hash,
                                                closest, NODUS_R);
        QGP_LOG_DEBUG(LOG_TAG, "REPL: key=%s... iter FALLBACK found=%d",
                      rpl_kh, count);
        do_replicate_store_frame(dht, &val->key_hash, frame, flen,
                                 closest, count, "REPL-FB", rpl_kh);
        put_repl_ctx_free(ctx);
    }
}

static void put_replication_complete(nodus_dht_t *dht,
                                      nodus_peer_t *closest, int count,
                                      void *user_data) {
    put_repl_ctx_t *ctx = (put_repl_ctx_t *)user_data;
    if (!ctx) return;

    /* Log key prefix */
    char kh[17];
    for (int i = 0; i < 8; i++) snprintf(kh + i*2, sizeof(kh) - i*2, "%02x", ctx->key_hash.bytes[i]);
    kh[16] = '\0';

    int sent = 0, failed = 0;
    int fail_indices[NODUS_K];
    for (int i = 0; i < count; i++) {
        if (nodus_key_cmp(&closest[i].node_id, &dht->host.identity->node_id) == 0) continue;
        if (dht_inter_send(dht, closest[i].ip, closest[i].tcp_port,
                           &closest[i].node_id,
                           ctx->frame, ctx->flen) == 0) {
            sent++;
        } else {
            if (failed < NODUS_K) fail_indices[failed] = i;
            failed++;
        }
    }

    /* Hinted handoff for failures when we got enough peers but not enough sends */
    if (sent < NODUS_REPLICATION_MIN && failed > 0) {
        for (int f = 0; f < failed && f < NODUS_K; f++) {
            int i = fail_indices[f];
            /* item 9: cluster members seen recently only */
            if (!dht_hint_wanted(dht, &closest[i].node_id)) continue;
            nodus_storage_hinted_insert(&dht->storage, &closest[i].node_id,
                                         closest[i].ip, closest[i].tcp_port,
                                         ctx->frame, ctx->flen);
        }
    }

    QGP_LOG_DEBUG(LOG_TAG,
                  "REPL_ITER: key=%s... iterative store sent=%d failed=%d closest=%d",
                  kh, sent, failed, count);

    /* on_complete owns cb_data cleanup on normal completion. */
    put_repl_ctx_free(ctx);
}

void nodus_dht_replicate_media_chunk(nodus_dht_t *dht,
                                     const nodus_media_meta_t *meta,
                                     uint32_t chunk_index,
                                     const uint8_t *data, size_t data_len) {
    if (!dht || !meta || !data || data_len == 0) return;

    /* Encode m_sv message with meta + chunk */
    uint8_t *cbor_buf = malloc(RESP_BUF_SIZE);
    if (!cbor_buf) return;
    size_t clen = 0;
    if (nodus_t2_media_store_value(0, meta, chunk_index,
                                    data, data_len,
                                    cbor_buf, RESP_BUF_SIZE, &clen) != 0) {
        free(cbor_buf);
        return;
    }

    /* Wire-frame it */
    uint8_t *frame = malloc(clen + 16);
    if (!frame) { free(cbor_buf); return; }
    size_t flen = nodus_frame_encode(frame, clen + 16, cbor_buf, (uint32_t)clen);
    free(cbor_buf);
    if (flen == 0) { free(frame); return; }

    /* Map content_hash[64] to nodus_key_t for routing lookup */
    nodus_key_t media_key;
    memcpy(media_key.bytes, meta->content_hash, NODUS_KEY_BYTES);

    /* Hex prefix for logging */
    char mkh[17];
    for (int x = 0; x < 8; x++) snprintf(mkh + x*2, sizeof(mkh) - x*2, "%02x", meta->content_hash[x]);
    mkh[16] = '\0';

    int known = nodus_routing_count(&dht->routing);

    fprintf(stderr,
            "MEDIA-REPL-CALL: hash=%s chunk=%u routing=%d path=%s\n",
            mkh, chunk_index, known,
            (known <= NODUS_R * 4) ? "fast" : "iter");

    if (known <= NODUS_R * 4) {
        /* Small cluster fast path — routing table is the network */
        nodus_peer_t closest[NODUS_R];
        int count = nodus_routing_find_closest(&dht->routing, &media_key,
                                                closest, NODUS_R);
        fprintf(stderr,
                "MEDIA-REPL-FAST: hash=%s chunk=%u found=%d (target_R=%d)\n",
                mkh, chunk_index, count, NODUS_R);
        do_replicate_store_frame(dht, &media_key, frame, flen,
                                 closest, count, "MEDIA-REPL", mkh);
        free(frame);
        return;
    }

    /* Large cluster: iterative FIND_NODE then STORE from callback.
     * Frame ownership transfers to the ctx. */
    put_media_ctx_t *ctx = malloc(sizeof(put_media_ctx_t));
    if (!ctx) { free(frame); return; }
    ctx->frame = frame;
    ctx->flen = flen;
    ctx->media_key = media_key;
    ctx->chunk_index = chunk_index;

    fprintf(stderr,
            "MEDIA-REPL-ITER: hash=%s chunk=%u routing=%d (large cluster)\n",
            mkh, chunk_index, known);

    if (iterative_lookup_start(dht, &media_key, -1, 0,
                                media_replication_complete, ctx,
                                put_media_ctx_free) != 0) {
        /* No lookup slots — fallback to routing table fast path. */
        nodus_peer_t closest[NODUS_R];
        int count = nodus_routing_find_closest(&dht->routing, &media_key,
                                                closest, NODUS_R);
        fprintf(stderr,
                "MEDIA-REPL-ITER-FB: hash=%s chunk=%u found=%d (no lookup slots)\n",
                mkh, chunk_index, count);
        do_replicate_store_frame(dht, &media_key, frame, flen,
                                 closest, count, "MEDIA-REPL-FB", mkh);
        put_media_ctx_free(ctx);
    }
}

static void media_replication_complete(nodus_dht_t *dht,
                                        nodus_peer_t *closest, int count,
                                        void *user_data) {
    put_media_ctx_t *ctx = (put_media_ctx_t *)user_data;
    if (!ctx) return;

    char mkh[17];
    for (int i = 0; i < 8; i++) snprintf(mkh + i*2, sizeof(mkh) - i*2, "%02x", ctx->media_key.bytes[i]);
    mkh[16] = '\0';

    int sent = 0, failed = 0;
    int fail_indices[NODUS_K];
    for (int i = 0; i < count; i++) {
        if (nodus_key_cmp(&closest[i].node_id, &dht->host.identity->node_id) == 0) continue;
        if (dht_inter_send(dht, closest[i].ip, closest[i].tcp_port,
                           &closest[i].node_id,
                           ctx->frame, ctx->flen) == 0) {
            sent++;
        } else {
            if (failed < NODUS_K) fail_indices[failed] = i;
            failed++;
        }
    }

    if (sent < NODUS_REPLICATION_MIN && failed > 0) {
        for (int f = 0; f < failed && f < NODUS_K; f++) {
            int i = fail_indices[f];
            /* item 9: cluster members seen recently only */
            if (!dht_hint_wanted(dht, &closest[i].node_id)) continue;
            nodus_storage_hinted_insert(&dht->storage, &closest[i].node_id,
                                         closest[i].ip, closest[i].tcp_port,
                                         ctx->frame, ctx->flen);
        }
    }

    QGP_LOG_DEBUG(LOG_TAG,
                  "MEDIA-REPL_ITER: hash=%s... chunk=%u iterative store sent=%d failed=%d closest=%d",
                  mkh, ctx->chunk_index, sent, failed, count);

    put_media_ctx_free(ctx);
}

/**
 * Retry DHT hinted handoff entries every NODUS_HINTED_RETRY_SEC seconds.
 * For each ALIVE cluster peer, query pending hints, attempt send, delete on success.
 */
static void dht_hinted_retry(nodus_dht_t *dht) {
    static uint64_t last_retry = 0;
    uint64_t now = nodus_time_now();

    if (now - last_retry < NODUS_HINTED_RETRY_SEC)
        return;
    last_retry = now;

    /* Cleanup expired entries first */
    int cleaned = nodus_storage_hinted_cleanup(&dht->storage);
    int total_hints = nodus_storage_hinted_count(&dht->storage);
    if (total_hints > 0 || cleaned > 0)
        fprintf(stderr, "HINT-RETRY: tick start — %d pending, %d expired-cleaned\n",
                total_hints, cleaned > 0 ? cleaned : 0);

    /* Query distinct node_ids with pending hints */
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(dht->storage.db,
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

        /* Fetch entries first — we need them either way, and they carry the
         * peer_ip/peer_port that was current at hint creation time. */
        nodus_dht_hint_t *entries = NULL;
        size_t count = 0;
        if (nodus_storage_hinted_get(&dht->storage, &node_id,
                                       100, &entries, &count) != 0 || count == 0)
            continue;

        /* Phase 3.2f FIX: previously this used routing_lookup as the only
         * source of truth and `continue` if routing was sparse. Result:
         * hints accumulated forever when routing rebuilt slowly after a
         * restart (observed: 343 MB stuck on EU-2 post-deploy). The hint
         * table already records peer_ip/peer_port from insert time; fall
         * back to those when routing is empty for this node_id. */
        nodus_peer_t peer;
        const char *ip;
        uint16_t tcp_port;
        if (nodus_routing_lookup(&dht->routing, &node_id, &peer) == 0) {
            ip = peer.ip;
            tcp_port = peer.tcp_port;
        } else {
            ip = entries[0].peer_ip;
            tcp_port = entries[0].peer_port;
        }

        int h_sent = 0, h_bumped = 0, h_expired = 0;
        for (size_t j = 0; j < count; j++) {
            if (dht_inter_send(dht, ip, tcp_port,
                               &node_id,
                               entries[j].frame_data,
                               entries[j].frame_len) == 0) {
                nodus_storage_hinted_delete(&dht->storage, entries[j].id);
                h_sent++;
            } else {
                /* Send failed — TCP buffer likely full. Bump retry count,
                 * delete if max retries reached, then STOP trying this
                 * peer to avoid flooding the buffer. */
                int retries = nodus_storage_hinted_bump_retry(
                    &dht->storage, entries[j].id);
                if (retries >= NODUS_HINT_MAX_RETRIES) {
                    nodus_storage_hinted_delete(&dht->storage, entries[j].id);
                    h_expired++;
                } else {
                    h_bumped++;
                }
                break;  /* Back off — don't flood this peer's TCP buffer */
            }
        }
        fprintf(stderr, "HINT-RETRY: peer=%s:%d batch=%zu delivered=%d bumped=%d maxretry=%d\n",
                ip, tcp_port, count, h_sent, h_bumped, h_expired);

        nodus_storage_hinted_free(entries, count);
    }

    sqlite3_finalize(stmt);
}

/* ── Kademlia bucket refresh ──────────────────────────────────────── */

static void dht_bucket_refresh(nodus_dht_t *dht) {
    static uint64_t last_refresh = 0;
    uint64_t now = nodus_time_now();
    if (now - last_refresh < NODUS_BUCKET_REFRESH_SEC) return;
    last_refresh = now;

    for (int b = 0; b < NODUS_BUCKETS; b++) {
        const nodus_bucket_t *bucket = &dht->routing.buckets[b];
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
        nodus_key_random_in_bucket(&random_key, &dht->host.identity->node_id, b);

        /* FIX-L2: pass raw CBOR to nodus_udp_send() — it applies the
         * wire frame internally. Previously we framed twice, producing
         * a nested 7-byte-header frame that peers couldn't decode. */
        uint8_t buf[512];
        size_t len = 0;
        if (nodus_t1_find_node(0, &random_key, buf, sizeof(buf), &len) == 0 && len > 0)
            dht_udp_send(dht, buf, len, target->ip, target->udp_port);
    }
}

/* ── Storage cleanup timer ───────────────────────────────────────── */

static void dht_storage_cleanup(nodus_dht_t *dht) {
    static uint64_t last_cleanup = 0;
    uint64_t now = nodus_time_now();
    if (now - last_cleanup < NODUS_CLEANUP_SEC) return;
    last_cleanup = now;

    int cleaned = nodus_storage_cleanup(&dht->storage);
    if (cleaned > 0)
        fprintf(stderr, "DHT-CLEANUP: removed %d expired values\n", cleaned);

    nodus_media_cleanup(&dht->media_storage);
}

/* ── WAL checkpoint + incremental vacuum ─────────────────────────── */

static void dht_wal_checkpoint(nodus_dht_t *dht) {
    uint64_t now = nodus_time_now();
    if (now - dht->last_wal_checkpoint < NODUS_WAL_CHECKPOINT_SEC) return;
    dht->last_wal_checkpoint = now;

    /* Reset all prepared statements to release read snapshots.
     * Without this, stepped-but-not-reset cursors hold implicit
     * read transactions that block WAL checkpoint. */
    sqlite3_stmt *stmts[] = {
        dht->storage.stmt_put, dht->storage.stmt_get,
        dht->storage.stmt_get_all, dht->storage.stmt_delete,
        dht->storage.stmt_cleanup, dht->storage.stmt_count,
        dht->storage.stmt_put_if_newer, dht->storage.stmt_fetch_batch,
        dht->storage.stmt_exclusive_owner,
        dht->storage.stmt_hint_insert, dht->storage.stmt_hint_get,
        dht->storage.stmt_hint_delete, dht->storage.stmt_hint_cleanup,
        dht->storage.stmt_hint_count,
        dht->media_storage.stmt_put_meta, dht->media_storage.stmt_put_chunk,
        dht->media_storage.stmt_get_meta, dht->media_storage.stmt_get_chunk,
        dht->media_storage.stmt_exists, dht->media_storage.stmt_mark_complete,
        dht->media_storage.stmt_count_chunks,
        dht->media_storage.stmt_cleanup_expired,
        dht->media_storage.stmt_cleanup_incomplete,
        dht->media_storage.stmt_cleanup_orphan_chunks,
        dht->media_storage.stmt_count_per_owner,
        dht->media_storage.stmt_fetch_batch,
    };
    for (size_t i = 0; i < sizeof(stmts)/sizeof(stmts[0]); i++) {
        if (stmts[i]) sqlite3_reset(stmts[i]);
    }

    int nlog = 0, nckpt = 0;
    int rc = sqlite3_wal_checkpoint_v2(dht->storage.db, NULL,
                                        SQLITE_CHECKPOINT_TRUNCATE, &nlog, &nckpt);
    if (rc == SQLITE_OK && nlog > 0)
        fprintf(stderr, "WAL-CKPT: nodus.db truncated (%d frames)\n", nckpt);
    else if (rc == SQLITE_BUSY && nlog > 0)
        fprintf(stderr, "WAL-CKPT: nodus.db BUSY (%d/%d frames), retrying PASSIVE\n", nckpt, nlog);
    if (rc == SQLITE_BUSY)
        sqlite3_wal_checkpoint_v2(dht->storage.db, NULL,
                                   SQLITE_CHECKPOINT_PASSIVE, NULL, NULL);

#ifndef NODUS_CHANNELS_DISABLED
    /* channels.db has its own DB handle. Only the channel server (4003)
     * attaches it (ch_server.ch_store = &ch_store, nodus_server_init); with
     * the channel server compiled out it was never checkpointed here, and
     * still is not. */
    if (dht->ch_store.db) {
        sqlite3_wal_checkpoint_v2(dht->ch_store.db, NULL,
                                   SQLITE_CHECKPOINT_TRUNCATE, NULL, NULL);
    }
#endif
}

static void dht_incremental_vacuum(nodus_dht_t *dht) {
    uint64_t now = nodus_time_now();
    if (now - dht->last_vacuum < NODUS_VACUUM_SEC) return;
    dht->last_vacuum = now;

    sqlite3_exec(dht->storage.db, "PRAGMA incremental_vacuum(10000)",
                 NULL, NULL, NULL);
#ifndef NODUS_CHANNELS_DISABLED
    /* channels.db — only with the channel server (see dht_wal_checkpoint) */
    if (dht->ch_store.db) {
        sqlite3_exec(dht->ch_store.db, "PRAGMA incremental_vacuum(10000)",
                     NULL, NULL, NULL);
    }
#endif
    fprintf(stderr, "VACUUM: incremental vacuum completed\n");
}

/* ── Periodic republish (via the host's inter-node send) ─────────── */

/** Main republish tick — fetch batch, send to K-closest, manage connections */
static void dht_republish(nodus_dht_t *dht) {
    dht_republish_state_t *rs = &dht->republish;
    uint64_t now = nodus_time_now();

    if (!rs->active) {
        /* Start new cycle every NODUS_REPUBLISH_SEC */
        if (now - rs->cycle_start < NODUS_REPUBLISH_SEC) return;
        /* Wait for routing table to have enough peers */
        if (nodus_routing_count(&dht->routing) < NODUS_REPLICATION_MIN) return;
        memset(&rs->last_key, 0, sizeof(rs->last_key));
        memset(&rs->last_owner, 0, sizeof(rs->last_owner));
        rs->last_vid = 0;
        rs->active = true;
        rs->first_batch = true;
        rs->cycle_start = now;
    }

    /* Fetch BATCH values using composite (key_hash, owner_fp, value_id)
     * bookmark — required because nodus_values PRIMARY KEY is composite,
     * and bookmarking only on key_hash skipped tied rows at batch
     * boundaries (~15% loss per cycle on multi-row keys). */
    nodus_value_t *batch[NODUS_REPUBLISH_BATCH];
    int fetched = nodus_storage_fetch_batch(&dht->storage,
                                             rs->first_batch ? NULL : &rs->last_key,
                                             rs->first_batch ? NULL : &rs->last_owner,
                                             rs->first_batch ? 0 : rs->last_vid,
                                             batch, NODUS_REPUBLISH_BATCH);
    rs->first_batch = false;

    for (int i = 0; i < fetched; i++) {
        nodus_value_t *val = batch[i];

        /* A row already expired (the rows nodus_storage_cleanup deletes) is
         * not sent: every peer would refuse it as expired on arrival
         * (NODUS_STORAGE_RC_EXPIRED). The bookmark still moves past it. */
        if (val->expires_at > 0 && val->expires_at <= now) {
            rs->last_key = val->key_hash;
            rs->last_owner = val->owner_fp;
            rs->last_vid = val->value_id;
            nodus_value_free(val);
            continue;
        }

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

        nodus_peer_t closest[NODUS_R];
        int n = nodus_routing_find_closest(&dht->routing, &val->key_hash, closest, NODUS_R);

        /* DBG: log per-value republish targets (v0.18.1) */
        {
            char dbg_kh[17];
            for (int x = 0; x < 8; x++)
                snprintf(dbg_kh + x*2, sizeof(dbg_kh) - x*2,
                         "%02x", val->key_hash.bytes[x]);
            dbg_kh[16] = '\0';
            fprintf(stderr, "DBG_REPUB_PEERS: key=%s vid=%llu n=%d",
                    dbg_kh, (unsigned long long)val->value_id, n);
            for (int j = 0; j < n; j++) {
                fprintf(stderr, " %s", closest[j].ip);
            }
            fprintf(stderr, "\n");
        }

        /* Republish is a best-effort periodic maintenance operation.
         * Failures queue into the hinted handoff table; the dedup index
         * (node_id, frame_hash) keys on SHA3-512 of frame_data, so
         * the same frame to the same peer collapses to one row even if
         * many cycles fail. */
        for (int j = 0; j < n; j++) {
            if (nodus_key_cmp(&closest[j].node_id, &dht->host.identity->node_id) == 0) continue;
            int rc = dht_inter_send(dht, closest[j].ip, closest[j].tcp_port,
                                    &closest[j].node_id, frame, flen);
            /* Item 9: hints only for cluster members (seen recently); the
             * next republish cycle covers any other peer. */
            if (rc != 0 && dht_hint_wanted(dht, &closest[j].node_id)) {
                nodus_storage_hinted_insert(&dht->storage,
                                             &closest[j].node_id,
                                             closest[j].ip, closest[j].tcp_port,
                                             frame, flen);
            }
        }

        rs->last_key = val->key_hash;
        rs->last_owner = val->owner_fp;
        rs->last_vid = val->value_id;
        free(frame);
        nodus_value_free(val);
    }

    /* Cycle complete if fewer rows than batch size */
    if (fetched < NODUS_REPUBLISH_BATCH) {
        rs->active = false;
        rs->cycle_start = nodus_time_now();
    }
}

/** Periodic media republish — paced one chunk per tick.
 *
 * Why per-tick pacing: a single media entry can have 100+ chunks of ~512KB
 * each. Replicating to 6 peers in one tick = 300+ MB queued synchronously
 * onto inter_tcp wbufs (5 MB cap each) → pending queue overflow → frames
 * shunted to hint table with synth IDs → never delivered. By processing
 * exactly one chunk per tick we let the event loop drain wbufs between
 * chunks, so pending stays well under cap.
 */
static void dht_media_republish(nodus_dht_t *dht) {
    dht_media_republish_state_t *mrs = &dht->media_republish;
    uint64_t now = nodus_time_now();

    /* Cycle activation gate */
    if (!mrs->active) {
        if (now - mrs->cycle_start < NODUS_MEDIA_REPUBLISH_SEC) return;
        if (nodus_routing_count(&dht->routing) < NODUS_REPLICATION_MIN) {
            fprintf(stderr,
                    "MEDIA-REPUB-SKIP: routing sparse (%d < %d)\n",
                    nodus_routing_count(&dht->routing), NODUS_REPLICATION_MIN);
            return;
        }
        fprintf(stderr,
                "MEDIA-REPUB-CYCLE: start cycle, routing=%d\n",
                nodus_routing_count(&dht->routing));
        memset(mrs->last_hash, 0, sizeof(mrs->last_hash));
        mrs->active = true;
        mrs->first_batch = true;
        mrs->has_current = false;
        mrs->chunk_cursor = 0;
        mrs->cycle_start = now;
    }

    /* Need a current entry? Fetch the next one (size 1 — pacing). */
    if (!mrs->has_current) {
        nodus_media_meta_t one[1];
        int fetched = nodus_media_fetch_batch(&dht->media_storage,
                                               mrs->first_batch ? NULL : mrs->last_hash,
                                               one, 1);
        mrs->first_batch = false;
        if (fetched == 0) {
            fprintf(stderr, "MEDIA-REPUB-DONE: cycle complete\n");
            mrs->active = false;
            mrs->cycle_start = nodus_time_now();
            return;
        }
        mrs->current_meta = one[0];
        mrs->chunk_cursor = 0;
        mrs->has_current = true;

        char hpfx[17];
        for (int x = 0; x < 8; x++)
            snprintf(hpfx + x*2, 3, "%02x", mrs->current_meta.content_hash[x]);
        hpfx[16] = '\0';
        fprintf(stderr,
                "MEDIA-REPUB-ENTRY: hash=%s chunks=%u total_size=%llu complete=%d\n",
                hpfx, mrs->current_meta.chunk_count,
                (unsigned long long)mrs->current_meta.total_size,
                mrs->current_meta.complete);
    }

    /* Send exactly ONE chunk per tick — drain wbufs between sends */
    if (mrs->chunk_cursor < mrs->current_meta.chunk_count) {
        uint8_t *chunk_data = NULL;
        size_t chunk_len = 0;
        if (nodus_media_get_chunk(&dht->media_storage,
                                   mrs->current_meta.content_hash,
                                   mrs->chunk_cursor,
                                   &chunk_data, &chunk_len) == 0) {
            nodus_dht_replicate_media_chunk(dht, &mrs->current_meta,
                                            mrs->chunk_cursor,
                                            chunk_data, chunk_len);
            free(chunk_data);
        } else {
            char hpfx[17];
            for (int x = 0; x < 8; x++)
                snprintf(hpfx + x*2, 3, "%02x", mrs->current_meta.content_hash[x]);
            hpfx[16] = '\0';
            fprintf(stderr,
                    "MEDIA-REPUB-CHUNK-MISS: hash=%s chunk_idx=%u get_chunk_failed\n",
                    hpfx, mrs->chunk_cursor);
        }
        mrs->chunk_cursor++;
    }

    /* Entry done — advance bookmark, fetch next entry on next tick */
    if (mrs->chunk_cursor >= mrs->current_meta.chunk_count) {
        memcpy(mrs->last_hash, mrs->current_meta.content_hash, 64);
        mrs->has_current = false;
    }
}

/* ── Tier 2 message handlers (Client -> Nodus) ──────────────────── */

static void handle_t2_put(nodus_dht_t *dht, int slot,
                           const nodus_key_t *client_fp,
                           const nodus_pubkey_t *client_pk,
                           nodus_tier2_msg_t *msg) {
    if (!rate_check_put(&dht->sessions[slot])) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_RATE_LIMITED,
                        "too many puts", resp_buf, sizeof(resp_buf), &len);
        dht_send_client(dht, slot, resp_buf, len);
        return;
    }

    /* Reject oversized values before doing any work (SECURITY: HIGH-7) */
    if (msg->data_len > NODUS_MAX_VALUE_SIZE) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_TOO_LARGE,
                        "value exceeds max size", resp_buf, sizeof(resp_buf), &len);
        dht_send_client(dht, slot, resp_buf, len);
        return;
    }

    /* Storage caps (owner rows / owner bytes / global rows / global bytes)
     * are applied by nodus_storage_put itself with the growth-only rule:
     * a replace of a live (key, owner, value_id) row that does not grow is
     * never refused. The former nodus_storage_check_quota pre-call counted
     * every row and refused such a replace once the owner was at the cap
     * (DHT Package A rev 2, storage contract nodus_storage.h). */

    /* Create value from message fields + authenticated session identity */
    nodus_value_t *val = NULL;
    int rc = nodus_value_create(&msg->key, msg->data, msg->data_len,
                                 msg->val_type, msg->ttl,
                                 msg->vid, msg->seq,
                                 client_pk, &val);
    if (rc != 0 || !val) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "value creation failed", resp_buf, sizeof(resp_buf), &len);
        dht_send_client(dht, slot, resp_buf, len);
        return;
    }

    /* Apply the client-provided signature */
    memcpy(val->signature.bytes, msg->sig.bytes, NODUS_SIG_BYTES);

    /* Verify signature */
    if (nodus_value_verify(val) != 0) {
        char kh[17], fp_hex[17];
        for (int i = 0; i < 8; i++) {
            snprintf(kh + i*2, sizeof(kh) - i*2, "%02x", val->key_hash.bytes[i]);
            snprintf(fp_hex + i*2, sizeof(fp_hex) - i*2, "%02x", client_fp->bytes[i]);
        }
        kh[16] = '\0'; fp_hex[16] = '\0';
        fprintf(stderr, "T2_PUT: verify FAILED key=%s... client=%s... vid=%llu seq=%llu\n",
                kh, fp_hex, (unsigned long long)val->value_id, (unsigned long long)val->seq);
        nodus_value_free(val);
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INVALID_SIGNATURE,
                        "value signature invalid", resp_buf, sizeof(resp_buf), &len);
        dht_send_client(dht, slot, resp_buf, len);
        return;
    }

    /* Store — with EXCLUSIVE ownership enforcement.
     * put_if_newer is only for inter-node replication paths. */
    rc = nodus_storage_put(&dht->storage, val);
    if (rc == -2) {
        /* EXCLUSIVE key owned by different identity */
        nodus_value_free(val);
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_KEY_OWNED,
                        "key owned by different identity", resp_buf, sizeof(resp_buf), &len);
        dht_send_client(dht, slot, resp_buf, len);
        return;
    }
    if (rc == NODUS_STORAGE_RC_QUOTA || rc == NODUS_STORAGE_RC_STALE) {
        /* F5: a storage cap on this node would be exceeded — the owner's
         * row or byte quota, or the node-wide row or byte cap.
         * F7: a stored row of the same (key, owner, value_id) has a higher
         * seq — an older value never replaces a newer one. */
        nodus_value_free(val);
        size_t len = 0;
        if (rc == NODUS_STORAGE_RC_QUOTA)
            nodus_t2_error(msg->txn_id, NODUS_ERR_QUOTA_EXCEEDED,
                            "storage quota exceeded", resp_buf, sizeof(resp_buf), &len);
        else
            nodus_t2_error(msg->txn_id, NODUS_ERR_STALE,
                            "stored value has a higher seq", resp_buf, sizeof(resp_buf), &len);
        dht_send_client(dht, slot, resp_buf, len);
        return;
    }
    if (rc != 0) {
        nodus_value_free(val);
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "storage error", resp_buf, sizeof(resp_buf), &len);
        dht_send_client(dht, slot, resp_buf, len);
        return;
    }

    /* Notify listeners */
    notify_listeners(dht, &msg->key, val);
    /* Forward to remote subscribers (Scribe pattern) */
    subscription_notify(dht, &msg->key, val);

    /* Replicate to alive cluster peers via TCP STORE */
    nodus_dht_replicate_value(dht, val);

    /* Respond OK */
    size_t len = 0;
    nodus_t2_put_ok(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
    dht_send_client(dht, slot, resp_buf, len);

    nodus_value_free(val);
}

/* ── Iterative Kademlia FIND_NODE Lookup (UDP-based) ──────────────── */
/*
 * Replaces the old TCP FIND_VALUE state machine. Standard Kademlia
 * iterative lookup with convergence detection. Used by GET (value fetched
 * separately via BF/TCP), PUT (STORE to discovered closest), and LISTEN
 * (Scribe forwarding).
 *
 * Values are NOT returned via UDP — Nodus values are 1.5-6KB+ which
 * exceed NODUS_MAX_FRAME_UDP (1400 bytes). FIND_NODE responses are small
 * and always fit UDP.
 */

/* Forward declarations — BF infrastructure is defined further down */
static void bf_send_result(nodus_dht_t *dht, dht_bf_batch_t *b);
static void bf_batch_cleanup(nodus_dht_t *dht, dht_bf_batch_t *b);
static int bf_start_forward(nodus_dht_t *dht, dht_bf_batch_t *b,
                              int fi, const nodus_peer_t *peer,
                              const nodus_key_t *keys, const int *key_indices,
                              int key_count);

/** Check if a node_id has been queried in this lookup */
static bool lookup_is_queried(const iterative_lookup_t *l,
                                const nodus_key_t *node_id) {
    for (int i = 0; i < l->queried_count; i++)
        if (nodus_key_cmp(&l->queried[i], node_id) == 0) return true;
    return false;
}

static void lookup_mark_queried(iterative_lookup_t *l,
                                  const nodus_key_t *node_id) {
    if (l->queried_count < NODUS_LOOKUP_MAX_QUERIED)
        l->queried[l->queried_count++] = *node_id;
}

/** FIX-C2: Compare two node_ids by XOR distance to target.
 *  Returns <0 if a is closer to target, >0 if b is closer, 0 if equal. */
static int xor_distance_cmp(const nodus_key_t *target,
                             const nodus_key_t *a,
                             const nodus_key_t *b) {
    nodus_key_t da, db;
    nodus_key_xor(&da, target, a);
    nodus_key_xor(&db, target, b);
    return nodus_key_cmp(&da, &db);
}

/** Sort shortlist by XOR distance to target (insertion sort, small N) */
static void lookup_sort_shortlist(iterative_lookup_t *l) {
    for (int i = 1; i < l->shortlist_count; i++) {
        nodus_peer_t tmp = l->shortlist[i];
        int j = i - 1;
        while (j >= 0 && xor_distance_cmp(&l->target_key, &tmp.node_id,
                                            &l->shortlist[j].node_id) < 0) {
            l->shortlist[j + 1] = l->shortlist[j];
            j--;
        }
        l->shortlist[j + 1] = tmp;
    }
}

/** Check convergence: did closest_k change from prev round? */
static bool lookup_check_convergence(const iterative_lookup_t *l) {
    if (l->closest_k_count == 0) return false;
    for (int i = 0; i < l->closest_k_count && i < NODUS_K; i++) {
        if (nodus_key_cmp(&l->closest_k[i].node_id,
                           &l->prev_closest_k[i].node_id) != 0) {
            return false;
        }
    }
    return true;
}

/** Update closest_k from sorted shortlist */
static void lookup_update_closest_k(iterative_lookup_t *l) {
    memcpy(l->prev_closest_k, l->closest_k, sizeof(l->closest_k));
    lookup_sort_shortlist(l);
    int n = l->shortlist_count < NODUS_K ? l->shortlist_count : NODUS_K;
    memcpy(l->closest_k, l->shortlist, (size_t)n * sizeof(nodus_peer_t));
    l->closest_k_count = n;
}

/** Send a FIND_NODE query to a peer via UDP */
static int lookup_send_query(nodus_dht_t *dht, iterative_lookup_t *l,
                              int qi, const nodus_peer_t *peer) {
    lookup_query_t *q = &l->queries[qi];

    uint32_t txn = dht->lookup_state.next_txn++;

    /* Encode T1 FIND_NODE. Always FIND_NODE, never FIND_VALUE. */
    uint8_t buf[256];
    size_t len = 0;
    if (nodus_t1_find_node(txn, &l->target_key, buf, sizeof(buf), &len) != 0)
        return -1;

    /* FIX-C1: send RAW CBOR — nodus_udp_send() applies the wire frame
     * internally. Calling nodus_frame_encode() here would double-frame. */
    if (dht_udp_send(dht, buf, len, peer->ip, peer->udp_port) != 0)
        return -1;

    q->state = LOOKUP_QUERY_SENT;
    q->node_id = peer->node_id;
    snprintf(q->ip, sizeof(q->ip), "%s", peer->ip);
    q->udp_port = peer->udp_port;
    q->txn = txn;
    q->sent_at = nodus_time_now_ms();
    q->retries = 0;

    lookup_mark_queried(l, &peer->node_id);
    l->queries_pending++;
    return 0;
}

/** Send queries to up to ALPHA unqueried closest peers */
static void lookup_send_round(nodus_dht_t *dht, iterative_lookup_t *l) {
    int sent = 0;
    lookup_sort_shortlist(l);

    for (int i = 0; i < l->shortlist_count && sent < NODUS_ALPHA; i++) {
        nodus_peer_t *p = &l->shortlist[i];

        if (lookup_is_queried(l, &p->node_id)) continue;

        /* Skip self */
        if (nodus_key_cmp(&p->node_id, &dht->host.identity->node_id) == 0) {
            lookup_mark_queried(l, &p->node_id);
            continue;
        }

        /* Find free query slot */
        int qi = -1;
        for (int q = 0; q < NODUS_ALPHA; q++) {
            if (l->queries[q].state != LOOKUP_QUERY_SENT) { qi = q; break; }
        }
        if (qi < 0) break;

        if (lookup_send_query(dht, l, qi, p) == 0)
            sent++;
    }

    QGP_LOG_DEBUG(LOG_TAG,
        "lookup_round stable=%d shortlist=%d queries_sent=%d pending=%d",
        l->stable_rounds, l->shortlist_count, sent, l->queries_pending);
}

/**
 * Start an iterative FIND_NODE lookup.
 *
 * Discovers K-closest nodes to target_key via UDP FIND_NODE queries.
 * On completion, calls on_complete(dht, closest_nodes, count, cb_data).
 *
 * CONTRACT: cb_data ownership transfers to the lookup engine.
 *   - Normal completion: on_complete() is called with cb_data; the callback
 *     MUST free cb_data itself.
 *   - Abandonment (client disconnect, server shutdown, lookup slot exhaustion):
 *     cb_data_free() is called if non-NULL. If cb_data_free is NULL and the
 *     lookup is abandoned, cb_data leaks — always provide cb_data_free unless
 *     cb_data is stack-allocated or static.
 *
 * @param session_slot  Client session (-1 for internal/async operations)
 * @param client_txn_id Client's T2 txn ID (unused for internal lookups)
 * @param on_complete   Called when lookup converges (REQUIRED)
 * @param cb_data       Passed to on_complete
 * @param cb_data_free  Called to free cb_data on abandonment (can be NULL;
 *                      see CONTRACT above)
 * @return 0 on success (lookup started), -1 on failure (no slots / no peers)
 */
static int iterative_lookup_start(nodus_dht_t *dht,
                                   const nodus_key_t *target,
                                   int session_slot,
                                   uint32_t client_txn_id,
                                   void (*on_complete)(struct nodus_dht *,
                                                       nodus_peer_t *, int,
                                                       void *),
                                   void *cb_data,
                                   void (*cb_data_free)(void *)) {
    int slot = -1;
    for (int i = 0; i < NODUS_LOOKUP_MAX_INFLIGHT; i++) {
        if (!dht->lookup_state.lookups[i].active) { slot = i; break; }
    }
    if (slot < 0) return -1;

    iterative_lookup_t *l = &dht->lookup_state.lookups[slot];
    memset(l, 0, sizeof(*l));
    l->active = true;
    l->target_key = *target;
    l->client_txn_id = client_txn_id;
    l->session_slot = session_slot;
    l->started_at = nodus_time_now_ms();
    l->on_complete = on_complete;
    l->cb_data = cb_data;
    l->cb_data_free = cb_data_free;

    /* Bootstrap: seed shortlist from local routing table */
    nodus_peer_t seeds[NODUS_K * 2];
    int seed_count = nodus_routing_find_closest(&dht->routing, target,
                                                 seeds, NODUS_K * 2);
    for (int i = 0; i < seed_count && l->shortlist_count < NODUS_LOOKUP_MAX_CANDIDATES; i++)
        l->shortlist[l->shortlist_count++] = seeds[i];

    QGP_LOG_DEBUG(LOG_TAG,
        "lookup_start slot=%d target=%02x%02x%02x%02x%02x%02x%02x%02x seeds=%d",
        slot,
        target->bytes[0], target->bytes[1], target->bytes[2], target->bytes[3],
        target->bytes[4], target->bytes[5], target->bytes[6], target->bytes[7],
        seed_count);

    if (l->shortlist_count == 0) {
        l->active = false;
        return -1;
    }

    lookup_update_closest_k(l);

    lookup_send_round(dht, l);

    if (l->queries_pending == 0) {
        l->active = false;
        return -1;
    }

    return 0;
}

/**
 * Handle a FIND_NODE response (fn_r / nodes_found) for active lookups.
 * Called from handle_udp_message() when fn_r is received.
 *
 * SECURITY: from_ip/from_port are the sender of the UDP datagram. We verify
 * they match the peer we originally queried to prevent a malicious node from
 * forging fn_r responses (guessing txn) and polluting our shortlist.
 */
static void iterative_lookup_handle_response(nodus_dht_t *dht,
                                              uint32_t txn,
                                              const nodus_tier1_msg_t *msg,
                                              const char *from_ip,
                                              uint16_t from_port) {
    for (int li = 0; li < NODUS_LOOKUP_MAX_INFLIGHT; li++) {
        iterative_lookup_t *l = &dht->lookup_state.lookups[li];
        if (!l->active) continue;

        for (int qi = 0; qi < NODUS_ALPHA; qi++) {
            lookup_query_t *q = &l->queries[qi];
            if (q->state != LOOKUP_QUERY_SENT || q->txn != txn) continue;

            /* SECURITY: verify response source matches the queried peer.
             * Prevents forged fn_r from polluting our shortlist. Do NOT
             * mark the query done — the genuine peer may still reply. */
            if (strcmp(q->ip, from_ip) != 0 || q->udp_port != from_port) {
                QGP_LOG_WARN(LOG_TAG,
                    "lookup_resp spoof? txn=%u expected=%s:%u got=%s:%u",
                    txn, q->ip, q->udp_port, from_ip, from_port);
                return;
            }

            /* Match! Add newly discovered peers to the shortlist. */
            q->state = LOOKUP_QUERY_DONE;
            l->queries_pending--;

            for (int p = 0; p < msg->peer_count; p++) {
                const nodus_peer_t *np = &msg->peers[p];
                if (nodus_key_cmp(&np->node_id, &dht->host.identity->node_id) == 0)
                    continue;
                bool dup = false;
                for (int s = 0; s < l->shortlist_count; s++) {
                    if (nodus_key_cmp(&l->shortlist[s].node_id,
                                       &np->node_id) == 0) {
                        dup = true; break;
                    }
                }
                if (!dup && l->shortlist_count < NODUS_LOOKUP_MAX_CANDIDATES)
                    l->shortlist[l->shortlist_count++] = *np;
            }
            return;
        }
    }
    /* No match — stale/duplicate response, ignore */
}

/** Finalize lookup: invoke callback with K-closest nodes found.
 *
 * Reentrancy-safe: snapshots callback state and clears the slot BEFORE
 * invoking on_complete, so the callback is free to start another lookup
 * or iterate the lookup table without observing a half-released slot.
 *
 * Ownership: on_complete is responsible for freeing cb_data (normal
 * completion path). cb_data_free is only called on abandonment paths
 * (iterative_lookup_tick disconnect, nodus_dht_stop shutdown).
 */
static void lookup_finalize(nodus_dht_t *dht, iterative_lookup_t *l) {
    /* Populate result_nodes from closest_k if not already set */
    if (l->result_node_count == 0 && l->closest_k_count > 0) {
        memcpy(l->result_nodes, l->closest_k,
               (size_t)l->closest_k_count * sizeof(nodus_peer_t));
        l->result_node_count = l->closest_k_count;
    }

    /* Snapshot callback + result into locals BEFORE clearing the slot.
     * This makes it safe for on_complete to re-enter the engine. */
    void (*cb)(struct nodus_dht *, nodus_peer_t *, int, void *) = l->on_complete;
    void *cb_data = l->cb_data;
    nodus_peer_t result_nodes[NODUS_K];
    int result_count = l->result_node_count;
    if (result_count > 0) {
        if (result_count > NODUS_K) result_count = NODUS_K;
        memcpy(result_nodes, l->result_nodes,
               (size_t)result_count * sizeof(nodus_peer_t));
    }

    QGP_LOG_DEBUG(LOG_TAG,
        "lookup_finalize stable=%d results=%d shortlist=%d queried=%d",
        l->stable_rounds, result_count, l->shortlist_count, l->queried_count);

    /* Clear slot first — the callback sees an inactive lookup. */
    l->on_complete = NULL;
    l->cb_data = NULL;
    l->cb_data_free = NULL;
    l->active = false;

    /* Invoke callback with local copies — safe to re-enter the engine.
     * The callback is responsible for freeing cb_data. */
    if (cb) cb(dht, result_nodes, result_count, cb_data);
}

/**
 * Tick: advance all active lookups.
 * Called from main event loop every iteration.
 */
static void iterative_lookup_tick(nodus_dht_t *dht) {
    uint64_t now = nodus_time_now_ms();

    for (int li = 0; li < NODUS_LOOKUP_MAX_INFLIGHT; li++) {
        iterative_lookup_t *l = &dht->lookup_state.lookups[li];
        if (!l->active) continue;

        /* Overall timeout — finalize with best-effort closest_k */
        if (now - l->started_at > NODUS_LOOKUP_TIMEOUT_MS) {
            QGP_LOG_DEBUG(LOG_TAG,
                "lookup_timeout after %llu ms (overall), finalizing",
                (unsigned long long)(now - l->started_at));
            lookup_finalize(dht, l);
            continue;
        }

        /* Client disconnect check */
        if (l->session_slot >= 0) {
            if (!dht->sessions[l->session_slot].open) {
                if (l->cb_data && l->cb_data_free) l->cb_data_free(l->cb_data);
                l->cb_data = NULL;
                l->cb_data_free = NULL;
                l->active = false;
                continue;
            }
        }

        /* Per-query timeouts with retry (FIX-N1: UDP unreliable) */
        for (int qi = 0; qi < NODUS_ALPHA; qi++) {
            lookup_query_t *q = &l->queries[qi];
            if (q->state == LOOKUP_QUERY_SENT &&
                now - q->sent_at > NODUS_LOOKUP_QUERY_TIMEOUT_MS) {
                if (q->retries < 1) {
                    q->retries++;
                    uint8_t buf[256];
                    size_t len = 0;
                    if (nodus_t1_find_node(q->txn, &l->target_key,
                                            buf, sizeof(buf), &len) == 0 && len > 0) {
                        dht_udp_send(dht, buf, len, q->ip, q->udp_port);
                    }
                    q->sent_at = now;
                } else {
                    q->state = LOOKUP_QUERY_DONE;
                    l->queries_pending--;
                }
            }
        }

        /* All queries done — check convergence and maybe start next round */
        if (l->queries_pending == 0) {
            lookup_update_closest_k(l);

            if (lookup_check_convergence(l)) {
                l->stable_rounds++;
            } else {
                l->stable_rounds = 0;
            }

            if (l->stable_rounds >= NODUS_LOOKUP_CONVERGE_ROUNDS) {
                /* CONVERGED — query any remaining unqueried closest_k */
                bool has_unqueried = false;
                for (int i = 0; i < l->closest_k_count; i++) {
                    if (!lookup_is_queried(l, &l->closest_k[i].node_id)) {
                        has_unqueried = true;
                        break;
                    }
                }

                if (has_unqueried) {
                    /* Count free query slots so we can stop iterating
                     * closest_k as soon as all slots are full. */
                    int free_slots = 0;
                    for (int qi = 0; qi < NODUS_ALPHA; qi++)
                        if (l->queries[qi].state != LOOKUP_QUERY_SENT) free_slots++;

                    for (int i = 0;
                         i < l->closest_k_count && free_slots > 0; i++) {
                        if (lookup_is_queried(l, &l->closest_k[i].node_id)) continue;
                        if (nodus_key_cmp(&l->closest_k[i].node_id,
                                           &dht->host.identity->node_id) == 0) continue;
                        for (int qi = 0; qi < NODUS_ALPHA; qi++) {
                            if (l->queries[qi].state != LOOKUP_QUERY_SENT) {
                                if (lookup_send_query(dht, l, qi,
                                                       &l->closest_k[i]) == 0)
                                    free_slots--;
                                break;
                            }
                        }
                    }
                    if (l->queries_pending > 0) continue;
                }

                lookup_finalize(dht, l);
            } else {
                /* Not converged — send another round */
                lookup_send_round(dht, l);

                if (l->queries_pending == 0) {
                    /* No more peers to query — done */
                    lookup_finalize(dht, l);
                }
            }
        }
    }
}

/* ── DHT Package A: forwarded-read candidate sets (S1, F6, S3, S6) ──
 *
 * Pure functions of the rows they are given — no clock, no I/O, no global
 * state. Every distinct row is kept as a candidate until the read resolves
 * and the resolution is a function of the candidate multiset, ranked by a
 * total order, so the same rows give the same reply whatever order the
 * sources answered in (D2). Exception, stated: unpaged replies list rows
 * in the order their PK first arrived (the pre-Package-A order), and the
 * verify budget (NODUS_DHT_VERIFY_CAP) and the per-source discard (rev 3
 * R-b, which depends on which row the PK-ordered walk verifies first) can
 * only change WHICH forwarded rows an adversarial source leaves out, never
 * admit an unverified one nor drop a local row.
 * Declared in dht/nodus_dht.h for the unit tests. */

int nodus_dht_pk_cmp(const nodus_key_t *a_owner, uint64_t a_vid,
                     const nodus_key_t *b_owner, uint64_t b_vid) {
    int c = memcmp(a_owner->bytes, b_owner->bytes, NODUS_KEY_BYTES);
    if (c != 0) return c;
    /* value_id is a SQLite INTEGER: signed int64 order, like the PK. */
    int64_t a = (int64_t)a_vid;
    int64_t b = (int64_t)b_vid;
    return (a > b) - (a < b);
}

static int dht_value_pk_cmp(const nodus_value_t *a, const nodus_value_t *b) {
    return nodus_dht_pk_cmp(&a->owner_fp, a->value_id, &b->owner_fp, b->value_id);
}

/* SHA3-256(data) exactly as nodus_storage stores data_hash (empty → zeros). */
static void dht_data_hash(const nodus_value_t *v, uint8_t out[32]) {
    if (!v->data || v->data_len == 0 ||
        qgp_sha3_256(v->data, v->data_len, out) != 0)
        memset(out, 0, 32);
}

/* The replica predicate on (seq, data hash): >0 when a is newer than b,
 * <0 when older, 0 when both are equal. seq is a SQLite INTEGER (signed). */
static int dht_newer_cmp(uint64_t a_seq, const uint8_t a_hash[32],
                         uint64_t b_seq, const uint8_t b_hash[32]) {
    int64_t sa = (int64_t)a_seq;
    int64_t sb = (int64_t)b_seq;
    if (sa != sb) return (sa > sb) ? 1 : -1;
    return memcmp(a_hash, b_hash, 32);
}

int nodus_dht_value_newer(const nodus_value_t *in, const nodus_value_t *ex) {
    uint8_t hi[32], he[32];
    dht_data_hash(in, hi);
    dht_data_hash(ex, he);
    return dht_newer_cmp(in->seq, hi, ex->seq, he) > 0;
}

/* Key / owner / cursor filter shared by the merge and the single pick. */
static bool dht_row_passes(const nodus_value_t *v, const nodus_key_t *key,
                           const nodus_key_t *own, const nodus_t2_cursor_t *after,
                           nodus_dht_merge_stats_t *st) {
    if (nodus_key_cmp(&v->key_hash, key) != 0 ||
        (own && nodus_key_cmp(&v->owner_fp, own) != 0)) {
        st->bad++;
        return false;
    }
    if (after && nodus_dht_pk_cmp(&v->owner_fp, v->value_id,
                                  &after->owner, after->vid) <= 0) {
        st->below_cursor++;
        return false;
    }
    return true;
}

static void dht_note_last(nodus_dht_merge_stats_t *st, const nodus_value_t *v) {
    if (!st->has_last ||
        nodus_dht_pk_cmp(&v->owner_fp, v->value_id,
                         &st->last.owner, st->last.vid) > 0) {
        st->last.owner = v->owner_fp;
        st->last.vid = v->value_id;
        st->has_last = true;
    }
}

/* Rev 3 R-e: the unpaged per-source row bound is what one forward reply
 * buffer can carry of rows that hold an owner pk and a signature. */
_Static_assert(NODUS_DHT_SRC_MAX_ROWS ==
               (size_t)RESP_BUF_SIZE / (size_t)(NODUS_PK_BYTES + NODUS_SIG_BYTES),
               "NODUS_DHT_SRC_MAX_ROWS must follow RESP_BUF_SIZE");
_Static_assert(NODUS_DHT_MAX_SOURCES <= 16, "source bitmask is uint16_t");

static bool dht_all_zero(const uint8_t *p, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* Rank of two candidates of the SAME PK: <0 when a ranks first. seq DESC,
 * data hash DESC (the replica predicate), then a total tiebreak over every
 * field nodus_value_verify reads (key_hash is filtered equal, value_id and
 * owner_fp are the PK), so 0 means the two are EXACT copies: verify cannot
 * tell them apart. created_at / expires_at are not signed and not compared
 * (R-f picks which copy's stand, dht_copy_stands). */
static int dht_cand_rank_cmp(const nodus_dht_cand_t *a, const nodus_dht_cand_t *b) {
    int n = dht_newer_cmp(a->v->seq, a->hash, b->v->seq, b->hash);
    if (n != 0) return -n;
    if (a->v->type != b->v->type) return (a->v->type < b->v->type) ? -1 : 1;
    if (a->v->ttl != b->v->ttl) return (a->v->ttl < b->v->ttl) ? -1 : 1;
    int s = memcmp(a->v->signature.bytes, b->v->signature.bytes, NODUS_SIG_BYTES);
    if (s != 0) return s;
    return memcmp(a->v->owner_pk.bytes, b->v->owner_pk.bytes, NODUS_PK_BYTES);
}

/* The keyset order: PK ASC, then rank. 0 = exact copies. */
static int dht_cand_cmp(const nodus_dht_cand_t *a, const nodus_dht_cand_t *b) {
    int c = dht_value_pk_cmp(a->v, b->v);
    if (c != 0) return c;
    return dht_cand_rank_cmp(a, b);
}

/* R-f: of two exact copies, true when b's object (created_at / expires_at)
 * should stand instead of a's: a trusted copy (the local store) beats an
 * untrusted one; otherwise the smaller created_at. A function of the two
 * copies only — the same whatever order they arrived in. */
static bool dht_copy_stands(const nodus_dht_cand_t *a, const nodus_dht_cand_t *b) {
    if (a->trusted != b->trusted) return b->trusted;
    return b->v->created_at < a->v->created_at;
}

/* One row of the source being added (its index in the caller's array). */
typedef struct {
    nodus_dht_cand_t c;
    size_t           idx;
} dht_in_t;

/* R-e cut: PK ASC, then arrival. */
static int dht_qsort_in_pk(const void *pa, const void *pb) {
    const dht_in_t *a = (const dht_in_t *)pa;
    const dht_in_t *b = (const dht_in_t *)pb;
    int c = dht_value_pk_cmp(a->c.v, b->c.v);
    if (c != 0) return c;
    return (a->idx > b->idx) - (a->idx < b->idx);
}

/* Keyset order, then arrival (exact copies adjacent, earliest first). */
static int dht_qsort_in_full(const void *pa, const void *pb) {
    const dht_in_t *a = (const dht_in_t *)pa;
    const dht_in_t *b = (const dht_in_t *)pb;
    int c = dht_cand_cmp(&a->c, &b->c);
    if (c != 0) return c;
    return (a->idx > b->idx) - (a->idx < b->idx);
}

void nodus_dht_keyset_clear(nodus_dht_keyset_t *ks) {
    if (!ks) return;
    for (size_t i = 0; i < ks->n; i++) nodus_value_free(ks->c[i].v);
    free(ks->c);
    ks->c = NULL;
    ks->n = 0;
    ks->cap = 0;
}

int nodus_dht_keyset_add_ex(nodus_dht_keyset_t *ks,
                            nodus_value_t **src, size_t src_count,
                            const nodus_key_t *key, const nodus_key_t *own,
                            const nodus_t2_cursor_t *after, bool trusted,
                            size_t max_rows,
                            const nodus_storage_data_hash_t *hashes,
                            nodus_dht_merge_stats_t *stats) {
    nodus_dht_merge_stats_t scratch;
    if (!stats) stats = &scratch;
    memset(stats, 0, sizeof(*stats));
    stats->src = -1;
    if (!ks || !key) return -1;
    if (ks->nsrc >= NODUS_DHT_MAX_SOURCES) {
        QGP_LOG_WARN(LOG_TAG, "DHT merge: more than %d sources for one key — "
                     "rows refused", NODUS_DHT_MAX_SOURCES);
        return -1;
    }
    int s = ks->nsrc;
    if (!src) src_count = 0;

    /* This source's rows that pass the filters (key / owner / cursor, then
     * R-c for an untrusted source). */
    dht_in_t *in = NULL;
    size_t m = 0;
    if (src_count > 0) {
        in = calloc(src_count, sizeof(dht_in_t));
        if (!in) return -1;
    }
    for (size_t i = 0; i < src_count; i++) {
        nodus_value_t *v = src[i];
        if (!v) continue;
        if (!dht_row_passes(v, key, own, after, stats)) continue;
        /* R-c: nodus_value_deserialize leaves owner_pk / signature zeroed
         * when "owner" / "sig" is absent; such a row can never verify and
         * would only spend verify budget. Local rows were verified at put. */
        if (!trusted &&
            (dht_all_zero(v->owner_pk.bytes, NODUS_PK_BYTES) ||
             dht_all_zero(v->signature.bytes, NODUS_SIG_BYTES))) {
            stats->refused++;
            continue;
        }
        in[m].c.v = v;
        in[m].idx = i;
        m++;
    }

    /* R-e: at most max_rows from one source — the smallest PKs (a page is
     * filled from the low end; the rest come back on a later page). */
    if (max_rows > 0 && m > max_rows) {
        qsort(in, m, sizeof(dht_in_t), dht_qsort_in_pk);
        stats->over_cap = m - max_rows;
        stats->truncated = true;
        m = max_rows;
    }

    for (size_t k = 0; k < m; k++) {
        nodus_dht_cand_t *c = &in[k].c;
        stats->est_bytes += NODUS_VALUE_SERIALIZED_EST(c->v->data_len);
        dht_note_last(stats, c->v);
        if (hashes && hashes[in[k].idx].present)
            memcpy(c->hash, hashes[in[k].idx].bytes, 32);   /* R-g: stored hash */
        else
            dht_data_hash(c->v, c->hash);
        c->vstate = trusted ? NODUS_DHT_V_OK : NODUS_DHT_V_UNKNOWN;
        c->trusted = trusted;
        c->srcs = (uint16_t)(1u << s);
        c->order = ks->next_order + (uint32_t)in[k].idx;
    }

    /* Sort this source's rows into keyset order; collapse its own exact
     * copies (R-f: the copy that stands keeps its object; the other stays
     * in src for the caller to free). */
    if (m > 1) qsort(in, m, sizeof(dht_in_t), dht_qsort_in_full);
    size_t u = 0;
    for (size_t k = 0; k < m; k++) {
        if (u > 0 && dht_cand_cmp(&in[u - 1].c, &in[k].c) == 0) {
            stats->dup++;
            if (dht_copy_stands(&in[u - 1].c, &in[k].c)) {
                uint32_t first = in[u - 1].c.order;   /* earliest arrival stays */
                in[u - 1].c.v = in[k].c.v;
                in[u - 1].idx = in[k].idx;
                in[u - 1].c.order = first;
            }
            continue;
        }
        in[u++] = in[k];
    }
    m = u;

    /* Merge into the sorted candidates: O(n + m). An incoming exact copy
     * of a present candidate is collapsed into it. */
    size_t need = ks->n + m;
    if (need > 0 && m > 0) {
        nodus_dht_cand_t *out = malloc(need * sizeof(nodus_dht_cand_t));
        if (!out) { free(in); return -1; }
        size_t i = 0, j = 0, o = 0;
        while (i < ks->n || j < m) {
            int r = (j == m) ? -1 : (i == ks->n) ? 1 : dht_cand_cmp(&ks->c[i], &in[j].c);
            if (r < 0) {
                out[o++] = ks->c[i++];
            } else if (r > 0) {
                out[o++] = in[j].c;
                src[in[j].idx] = NULL;          /* taken */
                stats->added++;
                j++;
            } else {
                nodus_dht_cand_t e = ks->c[i++];
                e.srcs |= in[j].c.srcs;
                /* A trusted copy (local row) vouches for the candidate. */
                if (in[j].c.trusted) e.vstate = NODUS_DHT_V_OK;
                if (dht_copy_stands(&e, &in[j].c)) {
                    nodus_value_t *old = e.v;
                    e.v = in[j].c.v;
                    src[in[j].idx] = old;       /* replaced object back to the caller */
                }
                e.trusted = e.trusted || in[j].c.trusted;
                if (in[j].c.order < e.order) e.order = in[j].c.order;
                out[o++] = e;
                stats->dup++;
                j++;
            }
        }
        free(ks->c);
        ks->c = out;
        ks->n = o;
        ks->cap = need;
    }
    free(in);

    ks->next_order += (uint32_t)src_count;
    memset(&ks->src[s], 0, sizeof(ks->src[s]));
    ks->src[s].trusted = trusted;
    ks->nsrc = s + 1;
    stats->src = s;
    return 0;
}

int nodus_dht_keyset_add(nodus_dht_keyset_t *ks,
                         nodus_value_t **src, size_t src_count,
                         const nodus_key_t *key, const nodus_key_t *own,
                         const nodus_t2_cursor_t *after, bool trusted,
                         nodus_dht_merge_stats_t *stats) {
    return nodus_dht_keyset_add_ex(ks, src, src_count, key, own, after, trusted,
                                   trusted ? 0 : NODUS_DHT_SRC_MAX_ROWS, NULL, stats);
}

void nodus_dht_keyset_note_page(nodus_dht_keyset_t *ks, bool more, bool trusted,
                                size_t responder_budget, const uint64_t *nx,
                                const nodus_dht_merge_stats_t *stats) {
    if (!ks || !stats || stats->src < 0 || stats->src >= ks->nsrc) return;
    nodus_dht_src_page_t *sp = &ks->src[stats->src];
    sp->noted = true;
    /* R-e: a source cut by its row cap has rows past its last kept PK. */
    sp->more = more || stats->truncated;
    if (stats->has_last) {
        sp->has_last = true;
        sp->last = stats->last;
    }
    /* Rev 2 item 12 + rev 3 R-d: only a source whose rows filled its page
     * may bound ours. With nx the responder's own stop rule is replayed
     * (its next row did not fit); without it (older peer) no row is
     * smaller than NODUS_VALUE_SERIALIZED_EST(0). */
    size_t next_est = NODUS_VALUE_SERIALIZED_EST(0);
    if (nx) next_est = (*nx > (uint64_t)SIZE_MAX) ? SIZE_MAX : (size_t)*nx;
    bool filled = stats->truncated ||
                  stats->est_bytes > responder_budget ||
                  next_est > responder_budget - stats->est_bytes;
    sp->bounds = sp->more && sp->has_last && (trusted || sp->trusted || filled);
}

/* Settle one candidate: 1 = valid, 0 = invalid, -1 = verify budget gone.
 * R-b: a candidate whose every sender was discarded is invalid without a
 * verify; a failed verify discards every source that sent the row. */
static int dht_cand_check(nodus_dht_keyset_t *ks, nodus_dht_cand_t *c,
                          int *verify_left) {
    if (c->vstate == NODUS_DHT_V_OK) return 1;
    if (c->vstate == NODUS_DHT_V_BAD) return 0;
    if ((c->srcs & (uint16_t)~ks->tainted) == 0) {
        c->vstate = NODUS_DHT_V_BAD;
        return 0;
    }
    if (!verify_left || *verify_left <= 0) return -1;
    (*verify_left)--;
    if (nodus_value_verify(c->v) == 0) {
        c->vstate = NODUS_DHT_V_OK;
        return 1;
    }
    c->vstate = NODUS_DHT_V_BAD;
    if (c->srcs & (uint16_t)~ks->tainted) {
        char kh[17];
        for (int i = 0; i < 8; i++) snprintf(kh + i * 2, 3, "%02x", c->v->key_hash.bytes[i]);
        kh[16] = '\0';
        QGP_LOG_WARN(LOG_TAG, "DHT merge: key=%s... a forwarded row failed "
                     "verification — its source(s) 0x%03x discarded for this read",
                     kh, (unsigned)(c->srcs & (uint16_t)~ks->tainted));
    }
    ks->tainted |= c->srcs;
    return 0;
}

/* Resolve the PK group c[g..end) (sorted by rank): index of the first
 * valid candidate. R-a: a candidate the budget cannot decide is passed
 * over and a lower-ranked one already valid is taken. -1 when none is
 * valid and none undecided, -2 when none is valid and one is undecided.
 * *end_out = one past the group. */
static long dht_group_pick(nodus_dht_keyset_t *ks, size_t g, int *verify_left,
                           size_t *end_out) {
    nodus_dht_cand_t *c = ks->c;
    size_t n = ks->n;
    size_t end = g + 1;
    while (end < n && dht_value_pk_cmp(c[end].v, c[g].v) == 0) end++;
    *end_out = end;
    bool undecided = false;
    for (size_t i = g; i < end; i++) {
        int r = dht_cand_check(ks, &c[i], verify_left);
        if (r == 1) return (long)i;
        if (r < 0) undecided = true;
    }
    return undecided ? -2 : -1;
}

/* Group start index holding PK (owner, vid), or n when absent. */
static size_t dht_group_find(const nodus_dht_cand_t *c, size_t n,
                             const nodus_t2_cursor_t *pk) {
    for (size_t i = 0; i < n; i++) {
        int k = nodus_dht_pk_cmp(&c[i].v->owner_fp, c[i].v->value_id,
                                 &pk->owner, pk->vid);
        if (k == 0) return i;
        if (k > 0) break;
    }
    return n;
}

/* Paged bound: the smallest last PK of a noted, bounding source that is
 * not discarded (R-b) and whose PK group resolves to a VALID row. A bound
 * PK with no valid row is discarded (unverified rows never set it) and the
 * next smallest is tried; a source discarded while its own PK was checked
 * is skipped. R-a exception: a bound PK the budget leaves undecided is
 * kept as the bound (*capped set) — a smaller page, never a skipped row.
 * @return the source index of the bound, -1 when there is none. */
static int dht_pick_bound(nodus_dht_keyset_t *ks, int *verify_left,
                          nodus_t2_cursor_t *bound, bool *capped) {
    bool tried[NODUS_DHT_MAX_SOURCES];
    memset(tried, 0, sizeof(tried));
    for (;;) {
        int best = -1;
        for (int s = 0; s < ks->nsrc; s++) {
            const nodus_dht_src_page_t *sp = &ks->src[s];
            if (tried[s] || !sp->noted || !sp->bounds ||
                (ks->tainted & (uint16_t)(1u << s)))
                continue;
            if (best < 0 ||
                nodus_dht_pk_cmp(&sp->last.owner, sp->last.vid,
                                 &ks->src[best].last.owner, ks->src[best].last.vid) < 0)
                best = s;
        }
        if (best < 0) return -1;
        tried[best] = true;
        size_t g = dht_group_find(ks->c, ks->n, &ks->src[best].last);
        if (g == ks->n) continue;          /* filtered out entirely: no row there */
        size_t end;
        long pick = dht_group_pick(ks, g, verify_left, &end);
        if (ks->tainted & (uint16_t)(1u << best)) continue;   /* discarded meanwhile */
        if (pick == -1) continue;          /* nothing valid at that PK */
        if (pick == -2) *capped = true;    /* undecided: kept, conservatively */
        *bound = ks->src[best].last;
        return best;
    }
}

/* A kept row and the arrival order of its PK group (unpaged output order). */
typedef struct { nodus_value_t *v; uint32_t order; } dht_kept_t;

static int dht_qsort_kept(const void *pa, const void *pb) {
    const dht_kept_t *a = (const dht_kept_t *)pa;
    const dht_kept_t *b = (const dht_kept_t *)pb;
    return (a->order > b->order) - (a->order < b->order);
}

int nodus_dht_keyset_resolve(nodus_dht_keyset_t *ks, bool paged, size_t budget,
                             int *verify_left,
                             nodus_value_t ***rows_out, size_t *count_out,
                             nodus_t2_page_info_t *page_out, bool *capped_out) {
    nodus_t2_page_info_t page;
    memset(&page, 0, sizeof(page));
    if (rows_out) *rows_out = NULL;
    if (count_out) *count_out = 0;
    if (capped_out) *capped_out = false;
    if (page_out) *page_out = page;
    if (!ks || !rows_out || !count_out) return -1;

    size_t n = ks->n;
    nodus_dht_cand_t *c = ks->c;   /* sorted (PK, rank) by nodus_dht_keyset_add_ex */
    if (n == 0) { nodus_dht_keyset_clear(ks); return 0; }

    dht_kept_t *kept = calloc(n, sizeof(dht_kept_t));
    if (!kept) { nodus_dht_keyset_clear(ks); return -1; }
    size_t nk = 0;

    /* Paged: the bound = the smallest last PK of a bounding, not discarded
     * source whose group resolves to a VALID row (dht_pick_bound). */
    bool has_bound = false, any_more = false, capped = false;
    nodus_t2_cursor_t bound;
    memset(&bound, 0, sizeof(bound));
    int bsrc = -1;
    if (paged) {
        bsrc = dht_pick_bound(ks, verify_left, &bound, &capped);
        has_bound = (bsrc >= 0);
    }

    size_t used = 0;
    bool cut = false;
    for (size_t g = 0; g < n; ) {
        if (paged && has_bound &&
            nodus_dht_pk_cmp(&c[g].v->owner_fp, c[g].v->value_id,
                             &bound.owner, bound.vid) > 0) {
            cut = true;
            break;
        }
        size_t end;
        uint16_t tainted_before = ks->tainted;
        long pick = dht_group_pick(ks, g, verify_left, &end);
        if (paged && has_bound && ks->tainted != tainted_before &&
            (ks->tainted & (uint16_t)(1u << bsrc))) {
            /* R-b: the bounding source was just discarded — its note no
             * longer counts. The bound can only move up (fewer sources), so
             * every row kept so far stays inside it. */
            bsrc = dht_pick_bound(ks, verify_left, &bound, &capped);
            has_bound = (bsrc >= 0);
        }
        if (pick == -2) {
            /* R-a: no row of this PK is settled valid and one could not be
             * checked. Unpaged: skip it, the walk goes on (rows already
             * valid — local rows included — are still returned). Paged:
             * close the page here — a cursor past this PK would hide a row
             * nobody checked; it comes back first on the next page. */
            capped = true;
            if (paged) { cut = true; break; }
            g = end;
            continue;
        }
        if (pick >= 0) {
            if (paged) {
                size_t est = NODUS_VALUE_SERIALIZED_EST(c[pick].v->data_len);
                if (nk > 0 && used + est > budget) { cut = true; break; }
                used += est;
            }
            uint32_t first = c[g].order;
            for (size_t i = g + 1; i < end; i++)
                if (c[i].order < first) first = c[i].order;
            kept[nk].v = c[pick].v;
            kept[nk].order = first;
            nk++;
            c[pick].v = NULL;              /* moved out */
        }
        g = end;
    }

    if (capped_out) *capped_out = capped;

    if (!paged && nk > 1) qsort(kept, nk, sizeof(dht_kept_t), dht_qsort_kept);

    nodus_value_t **rows = NULL;
    if (nk > 0) {
        rows = calloc(nk, sizeof(nodus_value_t *));
        if (!rows) {
            for (size_t i = 0; i < nk; i++) nodus_value_free(kept[i].v);
            free(kept);
            nodus_dht_keyset_clear(ks);
            return -1;
        }
        for (size_t i = 0; i < nk; i++) rows[i] = kept[i].v;
    }
    free(kept);
    nodus_dht_keyset_clear(ks);   /* frees every candidate not moved out */

    if (paged) {
        /* R-b: a discarded source's "more" no longer counts. */
        for (int s = 0; s < ks->nsrc; s++)
            if (ks->src[s].noted && ks->src[s].more &&
                !(ks->tainted & (uint16_t)(1u << s)))
                any_more = true;
    }
    if (paged && nk > 0) {
        page.more = cut || capped || any_more;
        if (page.more) {
            page.has_next = true;
            page.next.owner = rows[nk - 1]->owner_fp;
            page.next.vid = rows[nk - 1]->value_id;
        }
    }
    *rows_out = rows;
    *count_out = nk;
    if (page_out) *page_out = page;
    return 0;
}

/* Single-GET order of two rows with their data hashes: <0 when a ranks
 * first. (exclusive_first: EXCLUSIVE first), seq DESC, hash DESC, PK ASC,
 * then type, ttl, signature, owner_pk — total over what verify reads. */
static int dht_single_cmp(const nodus_value_t *a, const uint8_t ha[32],
                          const nodus_value_t *b, const uint8_t hb[32],
                          bool exclusive_first) {
    if (exclusive_first) {
        bool ae = a->type == NODUS_VALUE_EXCLUSIVE;
        bool be = b->type == NODUS_VALUE_EXCLUSIVE;
        if (ae != be) return ae ? -1 : 1;
    }
    int n = dht_newer_cmp(a->seq, ha, b->seq, hb);
    if (n != 0) return -n;
    int p = dht_value_pk_cmp(a, b);
    if (p != 0) return p;
    if (a->type != b->type) return (a->type < b->type) ? -1 : 1;
    if (a->ttl != b->ttl) return (a->ttl < b->ttl) ? -1 : 1;
    int s = memcmp(a->signature.bytes, b->signature.bytes, NODUS_SIG_BYTES);
    if (s != 0) return s;
    return memcmp(a->owner_pk.bytes, b->owner_pk.bytes, NODUS_PK_BYTES);
}

int nodus_dht_single_better(const nodus_value_t *cand, const nodus_value_t *best,
                            bool exclusive_first) {
    if (!cand) return 0;
    if (!best) return 1;
    uint8_t hc[32], hb[32];
    dht_data_hash(cand, hc);
    dht_data_hash(best, hb);
    return dht_single_cmp(cand, hc, best, hb, exclusive_first) < 0;
}

nodus_value_t *nodus_dht_keyset_pick_best(nodus_dht_keyset_t *ks,
                                          bool exclusive_first, int *verify_left,
                                          bool *capped_out) {
    if (capped_out) *capped_out = false;
    if (!ks) return NULL;
    nodus_value_t *best = NULL;
    bool budget_gone = false;
    /* Candidates are tried best-first; each pass picks the best not yet
     * rejected (one key's rows: bounded by the per-source row cap), so
     * only rows that would become the answer are ever verified. */
    for (;;) {
        long bi = -1;
        for (size_t i = 0; i < ks->n; i++) {
            nodus_dht_cand_t *c = &ks->c[i];
            if (!c->v || c->vstate == NODUS_DHT_V_BAD) continue;
            if (budget_gone && c->vstate == NODUS_DHT_V_UNKNOWN) {
                /* R-a: passed over — unless every sender was discarded
                 * (then it is simply invalid, R-b). */
                if ((c->srcs & (uint16_t)~ks->tainted) == 0)
                    c->vstate = NODUS_DHT_V_BAD;
                else if (capped_out)
                    *capped_out = true;
                continue;
            }
            if (bi < 0 || dht_single_cmp(c->v, c->hash,
                                         ks->c[bi].v, ks->c[bi].hash,
                                         exclusive_first) < 0)
                bi = (long)i;
        }
        if (bi < 0) break;
        int r = dht_cand_check(ks, &ks->c[bi], verify_left);
        if (r < 0) {
            /* R-a: verify budget gone — keep looking among the candidates
             * already settled valid (the local row among them). */
            budget_gone = true;
            if (capped_out) *capped_out = true;
            continue;
        }
        if (r == 1) {
            best = ks->c[bi].v;
            ks->c[bi].v = NULL;            /* moved out */
            break;
        }
    }
    nodus_dht_keyset_clear(ks);
    return best;
}

nodus_dht_read_outcome_t nodus_dht_read_outcome(size_t rows, int peers,
                                                int answered, bool local_fault) {
    if (rows > 0) return NODUS_DHT_READ_ROWS;
    if (answered > 0) return NODUS_DHT_READ_EMPTY;
    if (peers <= 0 && !local_fault) return NODUS_DHT_READ_EMPTY;
    return NODUS_DHT_READ_UNAVAILABLE;
}

/* S6: tell the client this node could not look (not "not found"). */
static void dht_send_unavailable(nodus_dht_t *dht, int slot, uint32_t txn,
                                 const char *why) {
    if (!dht->sessions[slot].open) return;
    size_t len = 0;
    if (nodus_t2_error(txn, NODUS_ERR_UNAVAILABLE, why,
                       resp_buf, sizeof(resp_buf), &len) == 0)
        dht_send_client(dht, slot, resp_buf, len);
}

static void dht_free_rows(nodus_value_t **vals, size_t count) {
    if (!vals) return;
    for (size_t i = 0; i < count; i++) nodus_value_free(vals[i]);
    free(vals);
}

static void dht_key_prefix(const nodus_key_t *k, char out[17]) {
    for (int i = 0; i < 8; i++) snprintf(out + i * 2, 3, "%02x", k->bytes[i]);
    out[16] = '\0';
}

/* ── Read replies from a resolved keyset (single GET / get_all / batch) ─
 *
 * One encoder per reply shape, used by the forward completion
 * (nodus_dht_bf_encode_result) AND by every path that answers without
 * forwarding (no peer, no slot, alloc failure), so both answer alike. */

typedef enum {
    DHT_REPLY_SINGLE = 0,   /* get: result / result_empty */
    DHT_REPLY_GET_ALL = 1   /* get_all: result_multi / result_empty / result_page */
} dht_reply_kind_t;

static int dht_encode_unavailable(uint32_t txn, const char *why,
                                  uint8_t *buf, size_t cap, size_t *len) {
    return nodus_t2_error(txn, NODUS_ERR_UNAVAILABLE, why, buf, cap, len);
}

/* Consumes ks (its rows are moved out or freed). */
static int dht_encode_key_reply(dht_reply_kind_t kind, uint32_t txn,
                                nodus_dht_keyset_t *ks, bool has_own, bool paged,
                                int *verify_left,
                                uint8_t *buf, size_t cap, size_t *len) {
    char kh[17] = "?";
    if (ks->n > 0) dht_key_prefix(&ks->c[0].v->key_hash, kh);

    if (kind == DHT_REPLY_SINGLE) {
        /* Without an owner filter the local read (nodus_storage_get)
         * prefers an EXCLUSIVE row; with one, the owner's newest row. */
        bool capped = false;
        nodus_value_t *best = nodus_dht_keyset_pick_best(ks, !has_own, verify_left,
                                                         &capped);
        /* The verify budget ran out before any candidate qualified: the
         * read could not decide — UNAVAILABLE, never "not found". */
        if ((capped && !best) ||
            nodus_dht_read_outcome(best ? 1 : 0, ks->peers, ks->answered,
                                   ks->local_fault) == NODUS_DHT_READ_UNAVAILABLE) {
            QGP_LOG_WARN(LOG_TAG, "GET: txn=%u could not look (peers=%d answered=%d "
                         "local_fault=%d capped=%d)", (unsigned)txn, ks->peers,
                         ks->answered, ks->local_fault ? 1 : 0, capped ? 1 : 0);
            nodus_value_free(best);
            return dht_encode_unavailable(txn, "could not look", buf, cap, len);
        }
        int rc;
        if (best) {
            rc = nodus_t2_result(txn, best, buf, cap, len);
            if (rc != 0)
                rc = nodus_t2_error(txn, NODUS_ERR_INTERNAL_ERROR,
                                    "value encode failed", buf, cap, len);
        } else {
            rc = nodus_t2_result_empty(txn, buf, cap, len);
        }
        nodus_value_free(best);
        return rc;
    }

    nodus_value_t **rows = NULL;
    size_t count = 0;
    nodus_t2_page_info_t page;
    bool capped = false;
    if (nodus_dht_keyset_resolve(ks, paged, NODUS_GET_ALL_PAGE_MAX_BYTES,
                                 verify_left, &rows, &count, &page, &capped) != 0)
        return nodus_t2_error(txn, NODUS_ERR_INTERNAL_ERROR, "get_all alloc failed",
                              buf, cap, len);
    if (capped)
        QGP_LOG_WARN(LOG_TAG, "GET_ALL: key=%s... verify budget (%d) spent — %zu "
                     "row(s) returned, the rest %s", kh, NODUS_DHT_VERIFY_CAP, count,
                     paged ? "left for the next page" : "dropped");
    if ((capped && count == 0) ||
        nodus_dht_read_outcome(count, ks->peers, ks->answered, ks->local_fault) ==
            NODUS_DHT_READ_UNAVAILABLE) {
        dht_free_rows(rows, count);
        QGP_LOG_WARN(LOG_TAG, "GET_ALL: key=%s... txn=%u could not look (peers=%d "
                     "answered=%d local_fault=%d capped=%d)", kh, (unsigned)txn,
                     ks->peers, ks->answered, ks->local_fault ? 1 : 0, capped ? 1 : 0);
        return dht_encode_unavailable(txn, "could not look", buf, cap, len);
    }
    int rc;
    if (paged)
        rc = nodus_t2_result_page(txn, rows, count, &page, buf, cap, len);
    else if (count > 0)
        rc = nodus_t2_result_multi(txn, rows, count, buf, cap, len);
    else
        rc = nodus_t2_result_empty(txn, buf, cap, len);
    if (rc != 0)
        rc = nodus_t2_error(txn, NODUS_ERR_INTERNAL_ERROR, "get_all encode failed",
                            buf, cap, len);
    dht_free_rows(rows, count);
    return rc;
}

/* Client get_batch reply over n keysets (consumed). A key that could not
 * be looked up gets "u": true (rev 2 item 15); when NO key has a row and
 * every key could not be looked up, the whole reply is UNAVAILABLE. */
static int dht_encode_batch_reply(uint32_t txn, const nodus_key_t *keys, int n,
                                  nodus_dht_keyset_t *sets, int *verify_left,
                                  uint8_t *buf, size_t cap, size_t *len) {
    nodus_value_t ***vals = calloc((size_t)n, sizeof(nodus_value_t **));
    size_t *counts = calloc((size_t)n, sizeof(size_t));
    bool *unavail = calloc((size_t)n, sizeof(bool));
    int rc;
    if (!vals || !counts || !unavail) {
        for (int i = 0; i < n; i++) nodus_dht_keyset_clear(&sets[i]);
        rc = nodus_t2_error(txn, NODUS_ERR_INTERNAL_ERROR, "alloc failed", buf, cap, len);
        goto out;
    }
    size_t rows = 0;
    int n_unavail = 0;
    for (int i = 0; i < n; i++) {
        bool capped = false;
        if (nodus_dht_keyset_resolve(&sets[i], false, 0, verify_left,
                                     &vals[i], &counts[i], NULL, &capped) != 0) {
            unavail[i] = true;     /* could not build the answer for this key */
            n_unavail++;
            continue;
        }
        if (capped) {
            char kh[17];
            dht_key_prefix(&keys[i], kh);
            QGP_LOG_WARN(LOG_TAG, "GET_BATCH: key=%s... verify budget (%d) spent — "
                         "%zu row(s) kept, the rest dropped", kh,
                         NODUS_DHT_VERIFY_CAP, counts[i]);
        }
        rows += counts[i];
        if ((capped && counts[i] == 0) ||
            nodus_dht_read_outcome(counts[i], sets[i].peers, sets[i].answered,
                                   sets[i].local_fault) == NODUS_DHT_READ_UNAVAILABLE) {
            unavail[i] = true;
            n_unavail++;
        }
    }
    if (rows == 0 && n_unavail == n) {
        QGP_LOG_WARN(LOG_TAG, "GET_BATCH: txn=%u %d key(s), none could be looked up "
                     "— UNAVAILABLE", (unsigned)txn, n);
        rc = dht_encode_unavailable(txn, "could not look", buf, cap, len);
        goto out;
    }
    if (n_unavail > 0)
        QGP_LOG_INFO(LOG_TAG, "GET_BATCH: txn=%u %d of %d key(s) marked could-not-look",
                     (unsigned)txn, n_unavail, n);
    rc = nodus_t2_result_get_batch_ex(txn, keys, n, vals, counts, NULL,
                                      n_unavail > 0 ? unavail : NULL, buf, cap, len);
    if (rc != 0)
        rc = nodus_t2_error(txn, NODUS_ERR_INTERNAL_ERROR, "batch encode failed",
                            buf, cap, len);
out:
    if (vals) {
        for (int i = 0; i < n; i++) dht_free_rows(vals[i], counts ? counts[i] : 0);
        free(vals);
    }
    free(counts);
    free(unavail);
    return rc;
}

/* Encode with a heap buffer and send; UNAVAILABLE when even that fails. */
static void dht_send_key_reply(nodus_dht_t *dht, int slot, dht_reply_kind_t kind,
                               uint32_t txn, nodus_dht_keyset_t *ks, bool has_own,
                               bool paged) {
    int verify_left = NODUS_DHT_VERIFY_CAP;
    uint8_t *buf = malloc(RESP_BUF_SIZE);
    size_t len = 0;
    if (!buf) {
        nodus_dht_keyset_clear(ks);
        dht_send_unavailable(dht, slot, txn, "reply alloc failed");
        return;
    }
    if (dht_encode_key_reply(kind, txn, ks, has_own, paged, &verify_left,
                             buf, RESP_BUF_SIZE, &len) == 0 && dht->sessions[slot].open)
        dht_send_client(dht, slot, buf, len);
    free(buf);
}

/* ── handle_t2_get — FIND_NODE + BF forward (TCP) ────────────────── */

/**
 * Per-GET context passed through the iterative lookup callback.
 * Always heap-allocated. `get_lookup_complete` frees it.
 */
typedef struct {
    uint32_t       txn_id;
    int            session_slot;
    nodus_key_t    key;
    bool           has_own;     /* S2: "own" owner filter */
    nodus_key_t    own;
    nodus_value_t *local;       /* item 14: the owner's local row (own only) */
    bool           local_fault; /* the local read faulted (rev 2 item 13) */
} get_lookup_ctx_t;

static void get_lookup_ctx_free(void *p) {
    get_lookup_ctx_t *ctx = (get_lookup_ctx_t *)p;
    if (!ctx) return;
    nodus_value_free(ctx->local);
    free(ctx);
}

/**
 * Callback: iterative FIND_NODE completed for a GET request.
 * Now BF forward to K-closest nodes to fetch the value via TCP. The local
 * row (own) is a trusted candidate of the same pick.
 */
static void get_lookup_complete(nodus_dht_t *dht,
                                 nodus_peer_t *closest, int count,
                                 void *user_data) {
    get_lookup_ctx_t *ctx = (get_lookup_ctx_t *)user_data;
    if (!ctx) return;

    /* Client disconnected */
    if (!dht->sessions[ctx->session_slot].open) { get_lookup_ctx_free(ctx); return; }

    /* Filter out self */
    int fwd_count = 0;
    nodus_peer_t fwd_peers[NODUS_K];
    for (int i = 0; i < count && fwd_count < NODUS_K; i++) {
        if (nodus_key_cmp(&closest[i].node_id, &dht->host.identity->node_id) != 0)
            fwd_peers[fwd_count++] = closest[i];
    }
    const nodus_key_t *own = ctx->has_own ? &ctx->own : NULL;

    /* Find a free BF batch slot */
    int bi = -1;
    if (fwd_count > 0) {
        for (int i = 0; i < NODUS_BF_MAX_BATCHES; i++) {
            if (!dht->bf_state.batches[i].active) { bi = i; break; }
        }
    }
    dht_bf_batch_t *b = (bi >= 0) ? &dht->bf_state.batches[bi] : NULL;
    if (b && nodus_dht_bf_batch_setup(b, &ctx->key, 1) != 0) {
        QGP_LOG_WARN(LOG_TAG, "GET: forward alloc failed");
        b = NULL;
    }
    if (!b) {
        /* No forward: no peer (a truthful empty, unless the local read
         * faulted), or (S6) no slot / alloc failure — could not look
         * unless the local row answers. */
        if (fwd_count > 0)
            QGP_LOG_WARN(LOG_TAG, "GET: txn=%u no forward slot", (unsigned)ctx->txn_id);
        nodus_dht_keyset_t ks;
        memset(&ks, 0, sizeof(ks));
        ks.peers = fwd_count;
        ks.local_fault = ctx->local_fault;
        if (ctx->local)
            (void)nodus_dht_keyset_add(&ks, &ctx->local, 1, &ctx->key, own, NULL,
                                       true, NULL);
        dht_send_key_reply(dht, ctx->session_slot, DHT_REPLY_SINGLE, ctx->txn_id, &ks,
                           ctx->has_own, false);
        get_lookup_ctx_free(ctx);
        return;
    }

    b->is_get_all = false;
    b->is_single_get = true;
    b->has_own = ctx->has_own;
    b->own = ctx->own;
    b->txn_id = ctx->txn_id;
    b->session_slot = ctx->session_slot;
    b->started_at = nodus_time_now_ms();
    b->sets[0].peers = fwd_count;
    b->sets[0].local_fault = ctx->local_fault;
    if (ctx->local)
        (void)nodus_dht_keyset_add(&b->sets[0], &ctx->local, 1, &ctx->key, own,
                                   NULL, true, NULL);

    /* Start forwards to K-closest peers */
    b->pending_forwards = 0;
    int key_idx = 0;
    int fwd_limit = fwd_count < NODUS_BF_MAX_FORWARDS ? fwd_count : NODUS_BF_MAX_FORWARDS;
    for (int f = 0; f < fwd_limit; f++) {
        if (bf_start_forward(dht, b, f, &fwd_peers[f], &ctx->key, &key_idx, 1) == 0)
            b->pending_forwards++;
    }

    /* Every forward failed to start → answer now from what is there (the
     * local row, or S6 UNAVAILABLE). Else bf_tick answers. */
    if (b->pending_forwards == 0)
        bf_send_result(dht, b);

    get_lookup_ctx_free(ctx);
}

static void handle_t2_get(nodus_dht_t *dht, int slot,
                           nodus_tier2_msg_t *msg) {
    /* Local read. S2: with "own", that owner's newest row
     * (nodus_storage_get_owner) instead of the key's best row. */
    nodus_value_t *val = NULL;
    int rc = msg->has_own
        ? nodus_storage_get_owner(&dht->storage, &msg->key, &msg->own_fp, &val)
        : nodus_storage_get(&dht->storage, &msg->key, &val);
    bool local_fault = (rc == NODUS_STORAGE_RC_FAULT);
    if (local_fault)
        QGP_LOG_WARN(LOG_TAG, "GET: txn=%u local storage read fault — asking peers",
                     (unsigned)msg->txn_id);

    /* Without "own": a local hit answers at once (unchanged fast path).
     * Rev 2 item 14: with "own" the owner's row on this node may be older
     * than on its replicas — always forward and pick the newest verified
     * row among the local one and the forwarded ones (S1). */
    if (!msg->has_own && rc == 0 && val) {
        size_t len = 0;
        if (nodus_t2_result(msg->txn_id, val, resp_buf, sizeof(resp_buf), &len) == 0) {
            dht_send_client(dht, slot, resp_buf, len);
        } else {
            fprintf(stderr, "NODUS_SRV: GET result encode failed (value too large?)\n");
            nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                            "value encode failed", resp_buf, sizeof(resp_buf), &len);
            dht_send_client(dht, slot, resp_buf, len);
        }
        nodus_value_free(val);
        return;
    }

    /*   Small cluster: routing table covers most nodes — BF forward directly.
     *   Large cluster: iterative FIND_NODE first, then BF forward to K-closest. */
    int known = nodus_routing_count(&dht->routing);

    get_lookup_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        /* S6: forward-context alloc failure — could not look */
        nodus_value_free(val);
        dht_send_unavailable(dht, slot, msg->txn_id, "forward alloc failed");
        return;
    }
    ctx->txn_id = msg->txn_id;
    ctx->session_slot = slot;
    ctx->key = msg->key;
    ctx->has_own = msg->has_own;
    if (msg->has_own) ctx->own = msg->own_fp;
    ctx->local = (rc == 0) ? val : NULL;   /* own only — the fast path took the rest */
    if (!ctx->local) nodus_value_free(val);
    ctx->local_fault = local_fault;

    if (known <= NODUS_R * 4) {
        /* Small cluster: skip iterative FIND_NODE — use routing table */
        nodus_peer_t closest[NODUS_K];
        int peer_count = nodus_routing_find_closest(&dht->routing, &msg->key,
                                                      closest, NODUS_K);
        get_lookup_complete(dht, closest, peer_count, ctx);
        return;
    }

    /* Large cluster: iterative FIND_NODE to discover true K-closest */
    if (iterative_lookup_start(dht, &msg->key,
                                slot,
                                msg->txn_id,
                                get_lookup_complete, ctx, get_lookup_ctx_free) != 0) {
        /* No lookup slots — fall back to routing table + BF */
        nodus_peer_t closest[NODUS_K];
        int peer_count = nodus_routing_find_closest(&dht->routing, &msg->key,
                                                      closest, NODUS_K);
        get_lookup_complete(dht, closest, peer_count, ctx);
    }
}

static void handle_t2_get_all(nodus_dht_t *dht, int slot,
                               nodus_tier2_msg_t *msg) {
    /* S3: paging is OPT-IN ("pg" or "after"); S2: "own" filters by owner.
     * Without any of them this is the pre-Package-A read: nodus_storage_get_all
     * (seq DESC, owner_fp ASC, 10000 rows / 16 MB). */
    bool paged = msg->page || msg->has_after;
    const nodus_key_t *own = msg->has_own ? &msg->own_fp : NULL;
    const nodus_t2_cursor_t *after = msg->has_after ? &msg->after : NULL;

    nodus_value_t **vals = NULL;
    nodus_storage_data_hash_t *hashes = NULL;   /* R-g: stored data_hash per row */
    size_t count = 0;
    int local_more = 0;
    int rc;
    if (paged || own) {
        /* PK order; an owner-filtered unpaged read keeps the legacy reply
         * shape and the legacy byte cap (truncation is logged below). */
        rc = nodus_storage_get_all_page_hashed(&dht->storage, &msg->key, own,
                                               after ? &after->owner : NULL,
                                               after ? after->vid : 0,
                                               paged ? (size_t)NODUS_GET_ALL_PAGE_MAX_BYTES
                                                     : (size_t)NODUS_GET_ALL_MAX_BYTES,
                                               &vals, &hashes, &count, &local_more);
    } else {
        /* The legacy read returns no stored hashes: these rows are hashed
         * by the merge (R-g covers the paged / owner read only). */
        rc = nodus_storage_get_all(&dht->storage, &msg->key, &vals, &count);
    }
    /* Rev 2 item 13: a FAULT of the paged / owner read is "could not look"
     * (nodus_storage_get_all returns -1 for both "none" and a SQLite error,
     * so the legacy read cannot tell — it stays "no local row"). */
    bool local_fault = (rc == NODUS_STORAGE_RC_FAULT);
    if (rc != 0) {
        dht_free_rows(vals, count);
        vals = NULL;
        free(hashes);
        hashes = NULL;
        count = 0;
        local_more = 0;
    }

    /* Key hash prefix for logging */
    char ga_kh[17];
    dht_key_prefix(&msg->key, ga_kh);
    if (local_fault)
        QGP_LOG_WARN(LOG_TAG, "GET_ALL: key=%s... local storage read fault", ga_kh);

    if (!paged && local_more)
        fprintf(stderr, "GET_ALL: key=%s... owner-filtered read truncated at "
                "%zu local rows (unpaged; use pg/after)\n", ga_kh, count);

    /* The local rows are one TRUSTED source (verified at put): their page
     * outcome always bounds (S3), their order leads an unpaged reply. */
    nodus_dht_keyset_t local;
    memset(&local, 0, sizeof(local));
    local.local_fault = local_fault;
    {
        nodus_dht_merge_stats_t lst;
        int arc = nodus_dht_keyset_add_ex(&local, vals, count, &msg->key, own, after,
                                          true, 0, hashes, &lst);
        free(hashes);
        hashes = NULL;
        if (arc != 0) {
            dht_free_rows(vals, count);
            nodus_dht_keyset_clear(&local);
            dht_send_unavailable(dht, slot, msg->txn_id, "local alloc failed");
            return;
        }
        if (paged)
            nodus_dht_keyset_note_page(&local, local_more != 0, true,
                                       NODUS_GET_ALL_PAGE_MAX_BYTES, NULL, &lst);
        dht_free_rows(vals, count);   /* rows not taken (filtered): none expected */
        vals = NULL;
    }

    /* Find R closest peers for potential forwarding (needed even on local hit
     * because multi-owner keys may have different value_ids on different nodes) */
    nodus_peer_t closest[NODUS_R];
    int peer_count = nodus_routing_find_closest(&dht->routing, &msg->key,
                                                  closest, NODUS_R);

    /* Filter out self */
    int fwd_count = 0;
    nodus_peer_t fwd_peers[NODUS_R];
    for (int i = 0; i < peer_count; i++) {
        if (nodus_key_cmp(&closest[i].node_id, &dht->host.identity->node_id) != 0) {
            fwd_peers[fwd_count++] = closest[i];
        }
    }
    local.peers = fwd_count;

    /* No peers to forward to: the local rows are the whole answer (no local
     * row → a truthful empty; single-node truth — unless the read faulted). */
    if (fwd_count == 0) {
        fprintf(stderr, "GET_ALL: key=%s... local=%zu, no peers to forward\n",
                ga_kh, count);
        dht_send_key_reply(dht, slot, DHT_REPLY_GET_ALL, msg->txn_id, &local,
                           own != NULL, paged);
        return;
    }

    /* We have peers to forward to — use BF infrastructure to gather all value_ids
     * from multiple nodes and merge with local data */
    fprintf(stderr, "GET_ALL: key=%s... local=%zu values, forwarding to %d peers\n",
            ga_kh, count, fwd_count);

    /* Find a free BF batch slot */
    int bi = -1;
    for (int i = 0; i < NODUS_BF_MAX_BATCHES; i++) {
        if (!dht->bf_state.batches[i].active) { bi = i; break; }
    }
    dht_bf_batch_t *b = (bi >= 0) ? &dht->bf_state.batches[bi] : NULL;
    if (!b) {
        fprintf(stderr, "GET_ALL: key=%s... no BF slots\n", ga_kh);
    } else if (nodus_dht_bf_batch_setup(b, &msg->key, 1) != 0) {
        fprintf(stderr, "GET_ALL: key=%s... forward alloc failed\n", ga_kh);
        b = NULL;
    }
    if (!b) {
        /* Could not forward. Local rows are still an answer; with none,
         * S6: could not look → UNAVAILABLE (peers > 0, none answered). */
        dht_send_key_reply(dht, slot, DHT_REPLY_GET_ALL, msg->txn_id, &local,
                           own != NULL, paged);
        return;
    }
    b->is_get_all = true;
    b->paged = paged;
    b->has_own = (own != NULL);
    if (own) b->own = *own;
    b->has_after = (after != NULL);
    if (after) b->after = *after;
    b->txn_id = msg->txn_id;
    b->session_slot = slot;
    b->started_at = nodus_time_now_ms();
    b->sets[0] = local;   /* ownership of the local candidates moves to the batch */

    /* Start forwards to up to R closest peers */
    b->pending_forwards = 0;
    int key_idx = 0;
    int fwd_limit = fwd_count < NODUS_BF_MAX_FORWARDS ? fwd_count : NODUS_BF_MAX_FORWARDS;
    for (int f = 0; f < fwd_limit; f++) {
        if (bf_start_forward(dht, b, f, &fwd_peers[f], &msg->key, &key_idx, 1) == 0) {
            b->pending_forwards++;
        } else {
            fprintf(stderr, "GET_ALL: key=%s... forward START_FAILED to %s:%d\n",
                    ga_kh, fwd_peers[f].ip, fwd_peers[f].tcp_port);
        }
    }

    if (b->pending_forwards > 0) {
        return;  /* Response deferred — bf_tick will send when all forwards complete */
    }

    /* All forwards failed to start — answer from what we have: local rows,
     * or (S6, no source answered) UNAVAILABLE. */
    bf_send_result(dht, b);
}

/* ── Batch Forward (BF) ─── get_batch miss → forward to closest peer ── */

static void bf_conn_cleanup(nodus_dht_t *dht, dht_bf_conn_t *c) {
    if (c->fd >= 0) {
        /* Phase 3.2e: log BF close so we can correlate close(fd) → recycle. */
        fprintf(stderr, "BF_CLOSE: fd=%d state=%d encrypted=%d\n",
                c->fd, (int)c->state, c->encrypted ? 1 : 0);
        epoll_ctl(dht->bf_state.bf_epoll_fd, EPOLL_CTL_DEL, c->fd, NULL);
        if (c->fd < NODUS_BF_FD_TABLE_SIZE) {
            dht->bf_fd_table[c->fd].batch_idx = -1;
            dht->bf_fd_table[c->fd].forward_idx = -1;
        }
        close(c->fd);
    }
    c->fd = -1;
    free(c->send_buf); c->send_buf = NULL;
    free(c->recv_buf); c->recv_buf = NULL;
    free(c->key_indices); c->key_indices = NULL;
    free(c->batch_keys); c->batch_keys = NULL;
    if (c->encrypted) nodus_channel_crypto_clear(&c->crypto);
    c->encrypted = false;
    qgp_secure_memzero(c->pending_ss, sizeof(c->pending_ss));
    qgp_secure_memzero(c->pending_nc, sizeof(c->pending_nc));
    c->state = BF_DONE;
}

static void bf_batch_cleanup(nodus_dht_t *dht, dht_bf_batch_t *b) {
    for (int i = 0; i < NODUS_BF_MAX_FORWARDS; i++) {
        /* Phase 3.2e FIX: was `fd >= 0` which treated zero-initialized
         * uninitialized forwards (.bss start, or post-memset state below)
         * as valid fds, calling close(0) on each batch cleanup pass and
         * stomping stdin. Use `> 0` so only real socket fds (>= 3 in
         * practice) are cleaned. */
        if (b->forwards[i].fd > 0) bf_conn_cleanup(dht, &b->forwards[i]);
    }
    if (b->sets) {
        for (int i = 0; i < b->key_count; i++) nodus_dht_keyset_clear(&b->sets[i]);
        free(b->sets);
    }
    free(b->keys);
    memset(b, 0, sizeof(*b));
    /* Phase 3.2e FIX: after memset all forwards' fd are 0 — re-init to -1
     * so any later cleanup pass treats them as inactive, not as stdin. */
    for (int i = 0; i < NODUS_BF_MAX_FORWARDS; i++) b->forwards[i].fd = -1;
}

void nodus_dht_bf_batch_cleanup(nodus_dht_t *dht, dht_bf_batch_t *b) {
    if (b) bf_batch_cleanup(dht, b);
}

int nodus_dht_bf_batch_setup(dht_bf_batch_t *b, const nodus_key_t *keys, int n) {
    if (!b || !keys || n < 1) return -1;
    memset(b, 0, sizeof(*b));
    for (int i = 0; i < NODUS_BF_MAX_FORWARDS; i++) b->forwards[i].fd = -1;
    b->keys = malloc((size_t)n * sizeof(nodus_key_t));
    b->sets = calloc((size_t)n, sizeof(nodus_dht_keyset_t));
    if (!b->keys || !b->sets) {
        free(b->keys);
        free(b->sets);
        memset(b, 0, sizeof(*b));
        for (int i = 0; i < NODUS_BF_MAX_FORWARDS; i++) b->forwards[i].fd = -1;
        return -1;
    }
    memcpy(b->keys, keys, (size_t)n * sizeof(nodus_key_t));
    b->key_count = n;
    b->verify_left = NODUS_DHT_VERIFY_CAP;
    b->active = true;
    return 0;
}

int nodus_dht_bf_encode_result(dht_bf_batch_t *b, uint8_t *buf, size_t cap,
                               size_t *len_out) {
    if (!b || !b->sets || !buf || !len_out) return -1;
    if (b->is_single_get && b->key_count == 1)
        return dht_encode_key_reply(DHT_REPLY_SINGLE, b->txn_id, &b->sets[0],
                                    b->has_own, false, &b->verify_left,
                                    buf, cap, len_out);
    if (b->is_get_all && b->key_count == 1)
        return dht_encode_key_reply(DHT_REPLY_GET_ALL, b->txn_id, &b->sets[0],
                                    b->has_own, b->paged, &b->verify_left,
                                    buf, cap, len_out);
    return dht_encode_batch_reply(b->txn_id, b->keys, b->key_count, b->sets,
                                  &b->verify_left, buf, cap, len_out);
}

/** Send batch response to client and clean up */
static void bf_send_result(nodus_dht_t *dht, dht_bf_batch_t *b) {
    if (!dht->sessions[b->session_slot].open) { bf_batch_cleanup(dht, b); return; }

    if (b->is_get_all && b->key_count == 1) {
        char bfkh[17];
        dht_key_prefix(&b->keys[0], bfkh);
        fprintf(stderr, "GET_ALL: key=%s... forward done: %zu candidate(s), "
                "%d source(s) answered%s\n", bfkh, b->sets[0].n, b->sets[0].answered,
                b->paged ? " (paged)" : "");
    }

    /* S6 / rev 2 item 13: the encoder answers UNAVAILABLE (whole reply) or
     * "u" (per batch key) where nothing could be looked up. */
    uint8_t *buf = malloc(RESP_BUF_SIZE);
    size_t len = 0;
    if (!buf) {
        dht_send_unavailable(dht, b->session_slot, b->txn_id, "reply alloc failed");
    } else {
        if (nodus_dht_bf_encode_result(b, buf, RESP_BUF_SIZE, &len) == 0)
            dht_send_client(dht, b->session_slot, buf, len);
        free(buf);
    }
    bf_batch_cleanup(dht, b);
}

int nodus_dht_bf_absorb_reply(dht_bf_batch_t *b, const dht_bf_conn_t *c,
                              const uint8_t *payload, size_t len) {
    if (!b || !c || !payload || !b->sets) return -1;
    nodus_tier2_msg_t resp;
    memset(&resp, 0, sizeof(resp));
    if (nodus_t2_decode(payload, len, &resp) != 0 ||
        !resp.batch_keys || resp.batch_key_count <= 0) {
        nodus_t2_msg_free(&resp);
        return -1;
    }

    const nodus_key_t *own = b->has_own ? &b->own : NULL;
    /* Old peers ignore "after": re-apply the cursor here. */
    const nodus_t2_cursor_t *after = (b->paged && b->has_after) ? &b->after : NULL;
    /* The responder splits its page budget over the keys of ITS batch
     * (the 4002 get_batch handler): the unit a "filled" page is judged in. */
    size_t responder_budget = c->batch_key_count > 0
        ? (size_t)NODUS_GET_ALL_PAGE_MAX_BYTES / (size_t)c->batch_key_count
        : (size_t)NODUS_GET_ALL_PAGE_MAX_BYTES;
    /* R-e: rows taken from one source — paged, what its page budget can
     * hold (no row is smaller than NODUS_VALUE_SERIALIZED_EST(0); the first
     * row always comes); unpaged, what one reply buffer can carry. */
    size_t max_rows = b->paged
        ? responder_budget / NODUS_VALUE_SERIALIZED_EST(0) + 1
        : NODUS_DHT_SRC_MAX_ROWS;

    bool used[NODUS_MAX_BATCH_KEYS];
    memset(used, 0, sizeof(used));
    for (int r = 0; r < resp.batch_key_count; r++) {
        /* F6 + rev 2 item 16: match the entry to a key THIS forward asked
         * for, by key AND position among identical keys — the m-th entry
         * for key K goes to the m-th index of this forward that asks K.
         * An entry no asked index is left for is dropped. */
        int ki = -1;
        for (int j = 0; j < c->key_count && j < NODUS_MAX_BATCH_KEYS; j++) {
            int cand = c->key_indices[j];
            if (used[j] || cand < 0 || cand >= b->key_count) continue;
            if (nodus_key_cmp(&b->keys[cand], &resp.batch_keys[r]) == 0) {
                used[j] = true;
                ki = cand;
                break;
            }
        }
        if (ki < 0) {
            fprintf(stderr, "BF: %s:%u reply entry %d for a key not asked (or "
                    "asked fewer times) — dropped\n", c->ip, (unsigned)c->port, r);
            continue;
        }
        nodus_dht_keyset_t *ks = &b->sets[ki];

        /* Rev 2 items 13/15: "u" = the responder could not look at this key;
         * not an answer, and any rows beside it are ignored. */
        if (resp.batch_unavail && resp.batch_unavail[r]) {
            fprintf(stderr, "BF: %s:%u could not look up reply entry %d\n",
                    c->ip, (unsigned)c->port, r);
            continue;
        }
        ks->answered++;

        size_t new_count = resp.batch_val_counts ? resp.batch_val_counts[r] : 0;
        nodus_value_t **new_vals = resp.batch_vals ? resp.batch_vals[r] : NULL;

        /* F6 + S1 + item 11: rows enter as UNVERIFIED candidates (key /
         * owner / cursor filters applied now); only the rows a reply
         * returns are signature-verified, at resolution. Rows not taken
         * stay in resp and are freed with it. */
        nodus_dht_merge_stats_t st;
        if (nodus_dht_keyset_add_ex(ks, new_vals, new_count, &b->keys[ki], own, after,
                                    false, max_rows, NULL, &st) != 0)
            QGP_LOG_WARN(LOG_TAG, "BF: %s:%u merge failed (alloc / too many "
                         "sources) — rows dropped", c->ip, (unsigned)c->port);
        if (b->paged) {
            /* R-d: "nx" = the size of the row the responder stopped on */
            const nodus_t2_page_info_t *pi = resp.batch_page ? &resp.batch_page[r] : NULL;
            nodus_dht_keyset_note_page(ks, pi ? pi->more : false, false,
                                       responder_budget,
                                       (pi && pi->has_nx) ? &pi->nx : NULL, &st);
        }
        if (st.bad > 0)
            fprintf(stderr, "BF: %s:%u dropped %zu forwarded value(s) "
                    "(wrong key / owner filter)\n", c->ip, (unsigned)c->port, st.bad);
        if (st.refused > 0 || st.over_cap > 0)
            QGP_LOG_WARN(LOG_TAG, "BF: %s:%u dropped %zu forwarded value(s) without "
                         "owner key / signature and %zu past the per-source cap (%zu)",
                         c->ip, (unsigned)c->port, st.refused, st.over_cap, max_rows);
    }
    nodus_t2_msg_free(&resp);
    return 0;
}

/** Build a framed CBOR message into malloc'd buffer. Returns 0 on success. */
static int bf_build_frame(uint8_t **buf_out, size_t *len_out,
                            const uint8_t *cbor, size_t cbor_len);

int nodus_dht_bf_frame_status(const uint8_t *buf, size_t len, size_t cap) {
    if (!buf) return -1;
    if (len < NODUS_FRAME_HEADER_SIZE) return 0;  /* need more */

    /* The transport's own decoder: magic, LITTLE-endian length
     * (nodus_wire.c nodus_frame_encode). It fills version and payload_len
     * whenever the header is present, complete frame or not. */
    nodus_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    int rc = nodus_frame_decode(buf, len, &frame);
    if (rc < 0) return -1;  /* bad magic */

    /* Version and TCP size limit, as the transport checks them — here
     * already at the header, so a frame that can never be accepted is
     * refused now instead of waited for. */
    if (!nodus_frame_validate(&frame, false)) return -1;

    /* A declared length the receive buffer can never hold would otherwise
     * wait until the forward times out. */
    if ((size_t)NODUS_FRAME_HEADER_SIZE + (size_t)frame.payload_len > cap) return -1;

    return rc > 0 ? 1 : 0;
}

/** Try to receive a complete nodus frame. Returns 1 if complete, 0 if need more, -1 on error. */
static int bf_recv_frame(dht_bf_conn_t *c, int fd) {
    ssize_t n = recv(fd, c->recv_buf + c->recv_len,
                     c->recv_cap - c->recv_len, 0);
    if (n <= 0) return -1;  /* closed or error */
    c->recv_len += (size_t)n;

    return nodus_dht_bf_frame_status(c->recv_buf, c->recv_len, c->recv_cap);
}

/** Reset send/recv buffers for next round-trip */
static void bf_reset_buffers(dht_bf_conn_t *c) {
    free(c->send_buf); c->send_buf = NULL;
    c->send_len = 0; c->send_pos = 0;
    c->recv_len = 0;  /* keep recv_buf allocated */
}

/** Switch epoll to EPOLLOUT for sending */
static void bf_switch_to_send(nodus_dht_t *dht, dht_bf_conn_t *c) {
    struct epoll_event ev = { .events = EPOLLOUT | EPOLLERR | EPOLLHUP, .data.fd = c->fd };
    epoll_ctl(dht->bf_state.bf_epoll_fd, EPOLL_CTL_MOD, c->fd, &ev);
}

/** Switch epoll to EPOLLIN for receiving */
static void bf_switch_to_recv(nodus_dht_t *dht, dht_bf_conn_t *c) {
    struct epoll_event ev = { .events = EPOLLIN | EPOLLERR | EPOLLHUP, .data.fd = c->fd };
    epoll_ctl(dht->bf_state.bf_epoll_fd, EPOLL_CTL_MOD, c->fd, &ev);
}

/** Forward error → cleanup + check batch completion */
static void bf_forward_fail(nodus_dht_t *dht, dht_bf_batch_t *b, dht_bf_conn_t *c) {
    bf_conn_cleanup(dht, c);
    if (--b->pending_forwards <= 0) bf_send_result(dht, b);
}

/** Handle epoll events for batch forward fds — full auth state machine */
static void bf_handle_event(nodus_dht_t *dht, int fd, uint32_t events) {
    /* Phase 3.2e: log every BF event with fd. Captures BF subsystem activity
     * we previously had no visibility into. */
    fprintf(stderr, "BF_EVENT: fd=%d events=0x%x\n", fd, events);
    if (fd < 0 || fd >= NODUS_BF_FD_TABLE_SIZE) return;
    int bi = dht->bf_fd_table[fd].batch_idx;
    int fi = dht->bf_fd_table[fd].forward_idx;
    if (bi < 0 || bi >= NODUS_BF_MAX_BATCHES) return;
    if (fi < 0 || fi >= NODUS_BF_MAX_FORWARDS) return;
    dht_bf_batch_t *b = &dht->bf_state.batches[bi];
    if (!b->active) return;
    dht_bf_conn_t *c = &b->forwards[fi];
    if (c->fd < 0) return;

    if (events & (EPOLLERR | EPOLLHUP)) {
        bf_forward_fail(dht, b, c);
        return;
    }

    /* ── State 0: Connecting → send HELLO ── */
    if (c->state == BF_CONNECTING && (events & EPOLLOUT)) {
        c->state = BF_SEND_HELLO;
        /* send_buf already has HELLO frame from bf_start_forward */
    }

    /* ── Send states (HELLO / AUTH / KEY_INIT / BATCH) ── */
    if ((c->state == BF_SEND_HELLO || c->state == BF_SEND_AUTH ||
         c->state == BF_SEND_KEY_INIT || c->state == BF_SEND_BATCH) &&
        (events & EPOLLOUT)) {
        if (!c->send_buf) { bf_forward_fail(dht, b, c); return; }
        /* Phase 3.2e: log BF send target fd + state. If fd ever points at a
         * recycled stale value, this log will reveal the mismatch. */
        fprintf(stderr,
                "BF_SEND: fd=%d c_fd=%d state=%d peer=%s:%u send_pos=%zu "
                "send_len=%zu encrypted=%d bi=%d fi=%d\n",
                fd, c->fd, (int)c->state, c->ip, (unsigned)c->port,
                c->send_pos, c->send_len, c->encrypted ? 1 : 0, bi, fi);
        ssize_t n = send(fd, c->send_buf + c->send_pos,
                         c->send_len - c->send_pos, MSG_NOSIGNAL);
        if (n < 0) { bf_forward_fail(dht, b, c); return; }
        if (n > 0) c->send_pos += (size_t)n;
        if (c->send_pos >= c->send_len) {
            /* Send complete → switch to recv for response */
            if (c->state == BF_SEND_HELLO)      c->state = BF_RECV_CHALL;
            else if (c->state == BF_SEND_AUTH)   c->state = BF_RECV_AUTHOK;
            else if (c->state == BF_SEND_KEY_INIT) c->state = BF_RECV_KEY_ACK;
            else if (c->state == BF_SEND_BATCH)  c->state = BF_RECV_RESULT;
            bf_reset_buffers(c);
            bf_switch_to_recv(dht, c);
        }
        return;
    }

    /* ── State 2: Recv CHALLENGE → sign nonce → send AUTH ── */
    if (c->state == BF_RECV_CHALL && (events & EPOLLIN)) {
        int rc = bf_recv_frame(c, fd);
        if (rc < 0) { bf_forward_fail(dht, b, c); return; }
        if (rc == 0) return;  /* need more data */

        /* Parse challenge nonce */
        nodus_tier2_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        if (nodus_t2_decode(c->recv_buf + 7, c->recv_len - 7, &msg) != 0) {
            nodus_t2_msg_free(&msg);
            bf_forward_fail(dht, b, c); return;
        }

        /* C2 fix: domain-tagged AUTH_CHALLENGE. bf_forward owns its own TCP
         * socket and only runs outbound (we dialed the leader), so no
         * inbound-conn oracle vector exists here — just the domain tag. */
        nodus_sig_t sig;
        /* CRIT-1: retain the challenge nonce so BF_RECV_AUTHOK can verify the
         * peer's kpk_sig over (kyber_pk || nonce). */
        memcpy(c->challenge_nonce, msg.nonce, NODUS_NONCE_LEN);
        c->has_challenge_nonce = true;
        if (nodus_sign_auth_challenge(&sig, msg.nonce, &dht->host.identity->sk) != 0) {
            nodus_t2_msg_free(&msg);
            bf_forward_fail(dht, b, c); return;
        }
        nodus_t2_msg_free(&msg);

        /* Build AUTH frame */
        uint8_t cbor[8192];
        size_t clen = 0;
        if (nodus_t2_auth(2, &sig, cbor, sizeof(cbor), &clen) != 0 ||
            bf_build_frame(&c->send_buf, &c->send_len, cbor, clen) != 0) {
            bf_forward_fail(dht, b, c); return;
        }
        c->send_pos = 0;
        c->recv_len = 0;
        c->state = BF_SEND_AUTH;
        bf_switch_to_send(dht, c);
        return;
    }

    /* ── State 4: Recv AUTH_OK → Kyber key_init → key exchange ── */
    if (c->state == BF_RECV_AUTHOK && (events & EPOLLIN)) {
        int rc = bf_recv_frame(c, fd);
        if (rc < 0) { bf_forward_fail(dht, b, c); return; }
        if (rc == 0) return;

        /* Parse auth_ok → get token + kyber_pk */
        nodus_tier2_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        if (nodus_t2_decode(c->recv_buf + 7, c->recv_len - 7, &msg) != 0 ||
            msg.type == 'e') {
            nodus_t2_msg_free(&msg);
            bf_forward_fail(dht, b, c); return;
        }
        memcpy(c->token, msg.token, NODUS_SESSION_TOKEN_LEN);
        uint32_t authok_txn = msg.txn_id;

        /* CRIT-1: authenticate the peer's Kyber pk BEFORE encapsulating to it —
         * verify kpk_sig over (kyber_pk || our challenge nonce) under server_pk,
         * then pin fingerprint(server_pk) to the FIND_NODE peer we dialed. The
         * signature alone only proves the triple is self-consistent; the pin is
         * what stops an on-path MITM from substituting its own identity. All
         * paths fail closed (bf_forward_fail). */
        if (!msg.has_kyber_pk || !msg.has_kpk_sig || !msg.has_server_pk ||
            !c->has_challenge_nonce || !c->has_expected_node_id) {
            fprintf(stderr,
                    "BF CRIT-1: auth_ok from %s:%u missing kyber_pk/kpk_sig/"
                    "server_pk or local pin state — refusing\n",
                    c->ip, (unsigned)c->port);
            nodus_t2_msg_free(&msg);
            bf_forward_fail(dht, b, c); return;
        }
        {
            uint8_t sign_data[NODUS_KYBER_PK_BYTES + NODUS_NONCE_LEN];
            memcpy(sign_data, msg.kyber_pk, NODUS_KYBER_PK_BYTES);
            memcpy(sign_data + NODUS_KYBER_PK_BYTES,
                   c->challenge_nonce, NODUS_NONCE_LEN);
            nodus_key_t actual_id;
            if (nodus_verify_kyber_bind(&msg.kpk_sig, sign_data,
                                         sizeof(sign_data), &msg.server_pk) != 0) {
                fprintf(stderr,
                        "BF CRIT-1: kyber_pk signature INVALID from %s:%u — "
                        "possible MITM, refusing\n", c->ip, (unsigned)c->port);
                nodus_t2_msg_free(&msg);
                bf_forward_fail(dht, b, c); return;
            }
            if (nodus_fingerprint(&msg.server_pk, &actual_id) != 0 ||
                nodus_key_cmp(&actual_id, &c->expected_node_id) != 0) {
                fprintf(stderr,
                        "BF CRIT-1: identity PIN MISMATCH at %s:%u — server_pk "
                        "fingerprint != dialed node_id, refusing\n",
                        c->ip, (unsigned)c->port);
                nodus_t2_msg_free(&msg);
                bf_forward_fail(dht, b, c); return;
            }
        }

        /* Faz 1 KEM migration (docs/plans/decisions/2026-09-23-kem-mlkem-
         * migration.md): if the peer ALSO advertised a signed ML-KEM-1024
         * pubkey, verify it under MLKEM_BIND against the SAME pinned
         * server_pk (the CRIT-1 block above already proved server_pk is
         * the peer we dialed) and prefer it; otherwise fall back to Kyber
         * round-3 exactly as today. */
        bool use_mlkem = false;
        if (msg.has_mlkem_pk && msg.has_mpk_sig) {
            uint8_t msign_data[NODUS_MLKEM_PK_BYTES + NODUS_NONCE_LEN];
            memcpy(msign_data, msg.mlkem_pk, NODUS_MLKEM_PK_BYTES);
            memcpy(msign_data + NODUS_MLKEM_PK_BYTES,
                   c->challenge_nonce, NODUS_NONCE_LEN);
            if (nodus_verify_mlkem_bind(&msg.mpk_sig, msign_data, sizeof(msign_data),
                                         &msg.server_pk) == 0) {
                use_mlkem = true;
            } else {
                fprintf(stderr,
                        "BF: mlkem_pk signature INVALID from %s:%u — falling "
                        "back to Kyber round-3\n", c->ip, (unsigned)c->port);
            }
        }

        /* KEM encapsulate → shared secret + ciphertext */
        uint8_t ct[NODUS_KYBER_CT_BYTES], ss[NODUS_KYBER_SS_BYTES];
        uint8_t alg = use_mlkem ? 1 : 0;
        int enc_rc = use_mlkem
            ? qgp_mlkem1024_encapsulate(ct, ss, msg.mlkem_pk)
            : qgp_kem1024_encapsulate(ct, ss, msg.kyber_pk);
        if (enc_rc != 0) {
            nodus_t2_msg_free(&msg);
            bf_forward_fail(dht, b, c); return;
        }
        nodus_t2_msg_free(&msg);

        /* Generate local nonce, store pending state */
        uint8_t nc[NODUS_NONCE_LEN];
        nodus_random(nc, NODUS_NONCE_LEN);
        memcpy(c->pending_ss, ss, 32);
        memcpy(c->pending_nc, nc, 32);
        qgp_secure_memzero(ss, sizeof(ss));

        /* Build key_init frame */
        uint8_t ki_buf[4096];
        size_t ki_len = 0;
        if (nodus_t2_key_init(authok_txn, ct, nc, alg, ki_buf, sizeof(ki_buf), &ki_len) != 0 ||
            bf_build_frame(&c->send_buf, &c->send_len, ki_buf, ki_len) != 0) {
            bf_forward_fail(dht, b, c); return;
        }
        c->send_pos = 0;
        c->recv_len = 0;
        c->state = BF_SEND_KEY_INIT;
        bf_switch_to_send(dht, c);
        return;
    }

    /* ── State 5: Send KEY_INIT (handled by generic send block above) ── */

    /* ── State 6: Recv KEY_ACK → init crypto → send encrypted batch ── */
    if (c->state == BF_RECV_KEY_ACK && (events & EPOLLIN)) {
        int rc = bf_recv_frame(c, fd);
        if (rc < 0) { bf_forward_fail(dht, b, c); return; }
        if (rc == 0) return;

        /* Parse key_ack → get server nonce */
        nodus_tier2_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        if (nodus_t2_decode(c->recv_buf + 7, c->recv_len - 7, &msg) != 0 ||
            !msg.has_key_nonce) {
            nodus_t2_msg_free(&msg);
            bf_forward_fail(dht, b, c); return;
        }

        /* Derive AES-256-GCM session key. We DIALED this peer → initiator. */
        nodus_channel_crypto_init(&c->crypto, c->pending_ss,
                                    c->pending_nc, msg.key_nonce,
                                    NODUS_CHANNEL_ROLE_INITIATOR);
        c->encrypted = true;
        qgp_secure_memzero(c->pending_ss, sizeof(c->pending_ss));
        qgp_secure_memzero(c->pending_nc, sizeof(c->pending_nc));
        nodus_t2_msg_free(&msg);

        /* Build get_batch CBOR, encrypt, frame, send. S2/S3: forward the
         * owner filter and paging args (an old peer skips them; the merge
         * re-applies both). No args → the pre-Package-A frame. */
        nodus_t2_read_opts_t fwd_opts = {
            .own   = b->has_own ? &b->own : NULL,
            .page  = b->paged,
            .after = b->has_after ? &b->after : NULL,
        };
        uint8_t cbor[4096];
        size_t clen = 0;
        if (nodus_t2_get_batch_ex(3, c->token, c->batch_keys, c->batch_key_count,
                                   &fwd_opts, cbor, sizeof(cbor), &clen) != 0) {
            bf_forward_fail(dht, b, c); return;
        }
        /* Encrypt the CBOR payload */
        size_t enc_cap = clen + NODUS_CHANNEL_OVERHEAD;
        uint8_t *enc_buf = malloc(enc_cap);
        if (!enc_buf) { bf_forward_fail(dht, b, c); return; }
        size_t enc_len = 0;
        if (nodus_channel_encrypt(&c->crypto, cbor, clen,
                                    enc_buf, enc_cap, &enc_len) != 0) {
            free(enc_buf);
            bf_forward_fail(dht, b, c); return;
        }
        /* Frame the encrypted payload */
        if (bf_build_frame(&c->send_buf, &c->send_len, enc_buf, enc_len) != 0) {
            free(enc_buf);
            bf_forward_fail(dht, b, c); return;
        }
        free(enc_buf);
        c->send_pos = 0;
        c->recv_len = 0;
        c->state = BF_SEND_BATCH;
        bf_switch_to_send(dht, c);
        return;
    }

    /* ── State 8: Recv batch result → decrypt if needed → merge → done ── */
    if (c->state == BF_RECV_RESULT && (events & EPOLLIN)) {
        int rc = bf_recv_frame(c, fd);
        if (rc < 0) goto merge_and_done;
        if (rc == 0) return;

    merge_and_done:
        /* Parse batch response from peer (decrypt if Kyber session active) */
        if (c->recv_len > 7) {
            const uint8_t *payload = c->recv_buf + 7;
            size_t payload_len = c->recv_len - 7;

            /* Decrypt if encrypted */
            uint8_t *dec_buf = NULL;
            if (c->encrypted) {
                size_t dec_cap = payload_len;  /* decrypted is smaller */
                dec_buf = malloc(dec_cap);
                if (!dec_buf) { bf_forward_fail(dht, b, c); return; }
                size_t dec_len = 0;
                if (nodus_channel_decrypt(&c->crypto, payload, payload_len,
                                            dec_buf, dec_cap, &dec_len) != 0) {
                    free(dec_buf);
                    bf_forward_fail(dht, b, c); return;
                }
                payload = dec_buf;
                payload_len = dec_len;
            }

            /* An error frame / garbage absorbs nothing: the keys of this
             * forward stay unanswered (S6). */
            (void)nodus_dht_bf_absorb_reply(b, c, payload, payload_len);
            free(dec_buf);  /* NULL-safe */
        }
        bf_conn_cleanup(dht, c);
        if (--b->pending_forwards <= 0) bf_send_result(dht, b);
    }
}

/** Tick: advance all batch forwards (called from main event loop) */
static void bf_tick(nodus_dht_t *dht) {
    if (dht->bf_state.bf_epoll_fd < 0) return;

    struct epoll_event events[32];
    int n = epoll_wait(dht->bf_state.bf_epoll_fd, events, 32, 0);
    for (int i = 0; i < n; i++)
        bf_handle_event(dht, events[i].data.fd, events[i].events);

    /* Check timeouts */
    uint64_t now = nodus_time_now_ms();
    for (int bi = 0; bi < NODUS_BF_MAX_BATCHES; bi++) {
        dht_bf_batch_t *b = &dht->bf_state.batches[bi];
        if (!b->active) continue;

        /* Check client disconnect */
        if (!dht->sessions[b->session_slot].open) { bf_batch_cleanup(dht, b); continue; }

        /* Overall batch timeout */
        if (now - b->started_at > NODUS_BF_TIMEOUT_MS) {
            /* Timeout: clean up remaining forwards, send what we have.
             * A peer that did not answer leaves the result (or the S3
             * page) incomplete; with no row and no answer at all the
             * reply is UNAVAILABLE (S6, bf_send_result).
             * Phase 3.2e FIX: `> 0` not `>= 0` — see bf_batch_cleanup. */
            fprintf(stderr, "BF: txn=%u timeout — %d forward(s) unanswered%s\n",
                    (unsigned)b->txn_id, b->pending_forwards,
                    b->paged ? " (page may be incomplete)" : "");
            for (int fi = 0; fi < NODUS_BF_MAX_FORWARDS; fi++) {
                if (b->forwards[fi].fd > 0) {
                    bf_conn_cleanup(dht, &b->forwards[fi]);
                }
            }
            bf_send_result(dht, b);
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
static int bf_start_forward(nodus_dht_t *dht, dht_bf_batch_t *b,
                              int fi, const nodus_peer_t *peer,
                              const nodus_key_t *keys, const int *key_indices,
                              int key_count) {
    dht_bf_conn_t *c = &b->forwards[fi];
    memset(c, 0, sizeof(*c));
    c->fd = -1;

    /* CRIT-1: record WHO we are dialing (the FIND_NODE-closest peer, NOT the
     * leader — pinning against a leader_id here would self-partition every
     * non-leader GET). The auth_ok handler pins fingerprint(server_pk) against
     * this before Kyber-encapsulating. */
    if (peer) {
        c->expected_node_id = peer->node_id;
        c->has_expected_node_id = true;
    }

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
    if (nodus_t2_hello(1, &dht->host.identity->pk, &dht->host.identity->node_id,
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
    /* Phase 3.2e: log BF socket allocation. fd value tells us if BF is
     * grabbing low fds (e.g. fd=0 from closed stdin). */
    fprintf(stderr, "BF_SOCK: fd=%d peer=%s\n", fd, peer->ip);
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
    int bi = (int)(b - dht->bf_state.batches);
    dht->bf_fd_table[fd].batch_idx = bi;
    dht->bf_fd_table[fd].forward_idx = fi;

    struct epoll_event ev = { .events = EPOLLOUT | EPOLLERR | EPOLLHUP, .data.fd = fd };
    epoll_ctl(dht->bf_state.bf_epoll_fd, EPOLL_CTL_ADD, fd, &ev);

    return 0;

fail:
    free(c->key_indices); c->key_indices = NULL;
    free(c->send_buf); c->send_buf = NULL;
    free(c->recv_buf); c->recv_buf = NULL;
    free(c->batch_keys); c->batch_keys = NULL;
    return -1;
}

static void handle_t2_get_batch(nodus_dht_t *dht, int slot,
                                 nodus_tier2_msg_t *msg) {
    if (msg->batch_key_count < 1 || msg->batch_key_count > NODUS_MAX_BATCH_KEYS) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "invalid batch key count", resp_buf, sizeof(resp_buf), &len);
        dht_send_client(dht, slot, resp_buf, len);
        return;
    }

    int n = msg->batch_key_count;
    /* One keyset per key (local rows = trusted candidates). Duplicate keys
     * in one batch stay separate entries, answered in request order. */
    nodus_dht_keyset_t *sets = calloc((size_t)n, sizeof(nodus_dht_keyset_t));
    if (!sets) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "alloc failed", resp_buf, sizeof(resp_buf), &len);
        dht_send_client(dht, slot, resp_buf, len);
        return;
    }

    /* Phase 1: local storage lookup for all keys. (nodus_storage_get_all
     * returns -1 for both "no row" and a SQLite error: a local fault is not
     * visible on this legacy read — it reads as a miss and is forwarded.) */
    int miss_count = 0;
    int miss_indices[NODUS_MAX_BATCH_KEYS];

    for (int i = 0; i < n; i++) {
        nodus_value_t **vals = NULL;
        size_t count = 0;
        if (nodus_storage_get_all(&dht->storage, &msg->batch_keys[i],
                                  &vals, &count) != 0) {
            dht_free_rows(vals, count);
            vals = NULL;
            count = 0;
        }
        if (count > 0 &&
            nodus_dht_keyset_add(&sets[i], vals, count, &msg->batch_keys[i],
                                 NULL, NULL, true, NULL) != 0) {
            /* could not hold this key's rows: answered as could-not-look */
            sets[i].local_fault = true;
        }
        dht_free_rows(vals, count);   /* rows not taken */
        if (sets[i].n == 0) {
            miss_indices[miss_count++] = i;
        }
    }

    /* Phase 2: if all found locally → respond immediately (fast path) */
    if (miss_count == 0) {
        goto send_response;
    }

    /* Phase 3: group misses by closest peer and start batch forwards.
     * Rev 2 item 15: the peers are found BEFORE the slot check — a miss
     * with no peer to ask is a truthful empty even when no slot is free. */
    {
        /* Group misses by closest peer */
        typedef struct { nodus_peer_t peer; int key_idx[NODUS_MAX_BATCH_KEYS]; int count; } peer_group_t;
        peer_group_t groups[NODUS_BF_MAX_FORWARDS];
        int group_count = 0;

        for (int m = 0; m < miss_count; m++) {
            int ki = miss_indices[m];
            /* FIX-N4: try up to R closest peers instead of just 1.
             * At R=3 with 100 nodes, the single closest peer might be
             * unreachable or not hold the key. Trying R candidates gives
             * the same reliability as replication factor. */
            nodus_peer_t closest[NODUS_R];
            int found = nodus_routing_find_closest(&dht->routing, &msg->batch_keys[ki],
                                                     closest, NODUS_R);
            if (found == 0) continue; /* No peers known — skip */

            /* Pick the first non-self closest peer */
            int chosen = -1;
            for (int c = 0; c < found; c++) {
                if (nodus_key_cmp(&closest[c].node_id, &dht->host.identity->node_id) != 0) {
                    chosen = c;
                    break;
                }
            }
            if (chosen < 0) continue; /* All candidates are self */
            /* S6: this key has a peer to ask. If it does not make it into a
             * forward below (groups full, no slot, start failure) nobody
             * answers it → "u". */
            sets[ki].peers = 1;

            /* Find existing group for this peer or create new */
            int gi = -1;
            for (int g = 0; g < group_count; g++) {
                if (strcmp(groups[g].peer.ip, closest[chosen].ip) == 0 &&
                    groups[g].peer.tcp_port == closest[chosen].tcp_port) {
                    gi = g;
                    break;
                }
            }
            if (gi < 0 && group_count < NODUS_BF_MAX_FORWARDS) {
                gi = group_count++;
                groups[gi].peer = closest[chosen];
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

        /* Find a free batch slot */
        int bi = -1;
        for (int i = 0; i < NODUS_BF_MAX_BATCHES; i++) {
            if (!dht->bf_state.batches[i].active) { bi = i; break; }
        }
        dht_bf_batch_t *b = (bi >= 0) ? &dht->bf_state.batches[bi] : NULL;
        if (!b || nodus_dht_bf_batch_setup(b, msg->batch_keys, n) != 0) {
            /* No slot / alloc failure — local-only results; the misses
             * that had a peer are "u" (S6). */
            QGP_LOG_WARN(LOG_TAG, "GET_BATCH: txn=%u %s — %d miss(es) not forwarded",
                         (unsigned)msg->txn_id, b ? "forward alloc failed" : "no BF slot",
                         miss_count);
            goto send_response;
        }

        /* Set up batch context — the keysets move into the batch */
        b->txn_id = msg->txn_id;
        b->session_slot = slot;
        b->started_at = nodus_time_now_ms();
        for (int i = 0; i < n; i++) b->sets[i] = sets[i];
        free(sets);
        sets = NULL;
        b->pending_forwards = 0;

        /* Start forwards */
        for (int g = 0; g < group_count; g++) {
            /* Build key array for this group */
            nodus_key_t *fwd_keys = malloc((size_t)groups[g].count * sizeof(nodus_key_t));
            if (!fwd_keys) continue;
            for (int k = 0; k < groups[g].count; k++)
                fwd_keys[k] = msg->batch_keys[groups[g].key_idx[k]];

            if (bf_start_forward(dht, b, g, &groups[g].peer,
                                  fwd_keys, groups[g].key_idx,
                                  groups[g].count) == 0) {
                b->pending_forwards++;
            }
            free(fwd_keys);
        }

        /* Response deferred — bf_tick sends when all forwards complete.
         * With none started, answer now from what is there (local rows;
         * the misses unanswered → "u" / UNAVAILABLE). */
        if (b->pending_forwards == 0)
            bf_send_result(dht, b);
        return;
    }

send_response:
    {
        int verify_left = NODUS_DHT_VERIFY_CAP;
        uint8_t *buf = malloc(RESP_BUF_SIZE);
        size_t len = 0;
        if (!buf) {
            for (int i = 0; i < n; i++) nodus_dht_keyset_clear(&sets[i]);
            dht_send_unavailable(dht, slot, msg->txn_id, "reply alloc failed");
        } else {
            if (dht_encode_batch_reply(msg->txn_id, msg->batch_keys, n, sets,
                                       &verify_left, buf, RESP_BUF_SIZE, &len) == 0)
                dht_send_client(dht, slot, buf, len);
            free(buf);
        }
        free(sets);
    }
}

static void handle_t2_count_batch(nodus_dht_t *dht, int slot,
                                    const nodus_key_t *client_fp,
                                    nodus_tier2_msg_t *msg) {
    if (msg->batch_key_count < 1 || msg->batch_key_count > NODUS_MAX_BATCH_KEYS) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "invalid batch key count", resp_buf, sizeof(resp_buf), &len);
        dht_send_client(dht, slot, resp_buf, len);
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
        dht_send_client(dht, slot, resp_buf, len);
        return;
    }

    /* Use session's fingerprint (from auth) as caller_fp.
     * msg->fp is set if client sent "fp" in args, otherwise fall back to session. */
    nodus_key_t caller_fp;
    bool has_caller = false;
    if (memcmp(msg->fp.bytes, "\0\0\0\0\0\0\0\0", 8) != 0) {
        memcpy(&caller_fp, &msg->fp, sizeof(nodus_key_t));
        has_caller = true;
    } else if (memcmp(client_fp->bytes, "\0\0\0\0\0\0\0\0", 8) != 0) {
        memcpy(&caller_fp, client_fp, sizeof(nodus_key_t));
        has_caller = true;
    }

    for (int i = 0; i < n; i++) {
        int c = nodus_storage_count_key(&dht->storage, &msg->batch_keys[i]);
        counts[i] = c >= 0 ? (size_t)c : 0;
        if (has_caller) {
            int ho = nodus_storage_has_owner(&dht->storage,
                                              &msg->batch_keys[i], &caller_fp);
            has_mine[i] = (ho == 1);
        }
    }

    size_t len = 0;
    if (nodus_t2_result_count_batch(msg->txn_id, msg->batch_keys, n,
                                     counts, has_mine,
                                     resp_buf, sizeof(resp_buf), &len) == 0) {
        dht_send_client(dht, slot, resp_buf, len);
    } else {
        size_t elen = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "count batch encode failed", resp_buf, sizeof(resp_buf), &elen);
        dht_send_client(dht, slot, resp_buf, elen);
    }

    free(counts);
    free(has_mine);
}

/* ── LISTEN (Scribe forwarding) ──────────────────────────────────── */

/**
 * Completion callback for listen forwarding iterative lookup.
 * Sends T1 "sub" frames to the K-closest nodes so they remember to
 * forward NOTIFY messages back to us when a PUT matches.
 *
 * user_data is a heap-allocated nodus_key_t (the listen key),
 * freed here or via cb_data_free on abandonment (see iterative_lookup_start).
 */
static void listen_fwd_complete(nodus_dht_t *dht,
                                 nodus_peer_t *closest, int count,
                                 void *user_data) {
    nodus_key_t *key = (nodus_key_t *)user_data;
    if (!dht || !key) { free(key); return; }

    uint8_t cbor_buf[256];
    size_t clen = 0;
    if (nodus_t1_subscribe(0, key, cbor_buf, sizeof(cbor_buf), &clen) != 0) {
        free(key);
        return;
    }
    uint8_t frame[512];
    size_t flen = nodus_frame_encode(frame, sizeof(frame), cbor_buf, (uint32_t)clen);
    if (flen == 0) { free(key); return; }

    int sent = 0;
    for (int i = 0; i < count; i++) {
        if (nodus_key_cmp(&closest[i].node_id, &dht->host.identity->node_id) == 0) continue;
        if (dht_inter_send(dht, closest[i].ip, closest[i].tcp_port,
                           &closest[i].node_id, frame, flen) == 0) {
            sent++;
        }
    }

    char kh[17];
    for (int i = 0; i < 8; i++) snprintf(kh + i*2, sizeof(kh) - i*2, "%02x", key->bytes[i]);
    kh[16] = '\0';
    QGP_LOG_DEBUG(LOG_TAG,
                   "LISTEN_FWD: key=%s... subscribe sent=%d closest=%d",
                   kh, sent, count);

    free(key);
}

static void handle_t2_listen(nodus_dht_t *dht, int slot,
                              nodus_tier2_msg_t *msg) {
    if (session_add_listen(&dht->sessions[slot], &msg->key) != 0) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_RATE_LIMITED,
                        "too many listeners", resp_buf, sizeof(resp_buf), &len);
        dht_send_client(dht, slot, resp_buf, len);
        return;
    }

    size_t len = 0;
    nodus_t2_listen_ok(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
    dht_send_client(dht, slot, resp_buf, len);

    /* Forward subscription to the key's responsible nodes so that remote
     * PUTs will generate NOTIFY messages back to us (Scribe pattern). */
    nodus_key_t *key_copy = malloc(sizeof(nodus_key_t));
    if (!key_copy) return;
    *key_copy = msg->key;

    if (iterative_lookup_start(dht, &msg->key, -1, 0,
                                listen_fwd_complete, key_copy, free) != 0) {
        /* No lookup slots available — synchronous fallback via routing table */
        nodus_peer_t closest[NODUS_R];
        int count = nodus_routing_find_closest(&dht->routing, &msg->key,
                                                 closest, NODUS_R);
        listen_fwd_complete(dht, closest, count, key_copy);
    }
}

static void handle_t2_unlisten(nodus_dht_t *dht, int slot,
                                nodus_tier2_msg_t *msg) {
    session_remove_listen(&dht->sessions[slot], &msg->key);

    uint8_t resp_buf[256];
    size_t len = 0;
    nodus_t2_listen_ok(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
    dht_send_client(dht, slot, resp_buf, len);
}

/* ── Channel discovery on TCP 4001 ────────────────────────────────── */

static void handle_t2_ch_list(nodus_dht_t *dht, int slot,
                                nodus_tier2_msg_t *msg) {
    nodus_channel_meta_t *metas = NULL;
    size_t count = 0;
    int rc = nodus_channel_store_list_public(&dht->ch_store,
                                              msg->ch_offset, msg->ch_limit,
                                              &metas, &count);
    if (rc != 0) {
        uint8_t buf[256];
        size_t len = 0;
        nodus_t2_error(msg->txn_id, 500, "internal error", buf, sizeof(buf), &len);
        dht_send_client(dht, slot, buf, len);
        return;
    }

    uint8_t *buf = malloc(65536);
    if (!buf) { free(metas); return; }
    size_t len = 0;
    nodus_t2_ch_list_ok(msg->txn_id, metas, count, buf, 65536, &len);
    dht_send_client(dht, slot, buf, len);
    free(buf);
    free(metas);
}

static void handle_t2_ch_search(nodus_dht_t *dht, int slot,
                                  nodus_tier2_msg_t *msg) {
    const char *query = msg->ch_query;
    if (!query || query[0] == '\0') {
        handle_t2_ch_list(dht, slot, msg);
        return;
    }

    nodus_channel_meta_t *metas = NULL;
    size_t count = 0;
    int rc = nodus_channel_store_search(&dht->ch_store, query,
                                         msg->ch_offset, msg->ch_limit,
                                         &metas, &count);
    if (rc != 0) {
        uint8_t buf[256];
        size_t len = 0;
        nodus_t2_error(msg->txn_id, 500, "internal error", buf, sizeof(buf), &len);
        dht_send_client(dht, slot, buf, len);
        return;
    }

    uint8_t *buf = malloc(65536);
    if (!buf) { free(metas); return; }
    size_t len = 0;
    nodus_t2_ch_list_ok(msg->txn_id, metas, count, buf, 65536, &len);
    dht_send_client(dht, slot, buf, len);
    free(buf);
    free(metas);
}

static void handle_t2_ch_get(nodus_dht_t *dht, int slot,
                               nodus_tier2_msg_t *msg) {
    nodus_channel_meta_t meta;
    int rc = nodus_channel_load_meta(&dht->ch_store, msg->channel_uuid, &meta);
    if (rc != 0) {
        uint8_t buf[256];
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_NOT_FOUND, "channel not found",
                       buf, sizeof(buf), &len);
        dht_send_client(dht, slot, buf, len);
        return;
    }

    /* Reuse ch_list_ok with count=1 */
    uint8_t *buf = malloc(4096);
    if (!buf) return;
    size_t len = 0;
    nodus_t2_ch_list_ok(msg->txn_id, &meta, 1, buf, 4096, &len);
    dht_send_client(dht, slot, buf, len);
    free(buf);
}

/* ── Ping-before-evict helpers ───────────────────────────────────── */

/**
 * Try to insert a peer into the routing table. If the bucket is full,
 * send a UDP PING to the LRU candidate and queue the eviction.
 * The main loop sweep handles timeout-based eviction.
 */
static void routing_insert_or_ping(nodus_dht_t *dht, const nodus_peer_t *peer) {
    nodus_peer_t lru;
    memset(&lru, 0, sizeof(lru));
    int rc = nodus_routing_try_insert(&dht->routing, peer, &lru);

    /* Sync hashring with routing table on insert/update */
    if (rc == 0 || rc == 1) {
        nodus_hashring_add(&dht->ring, &peer->node_id,
                           peer->ip, peer->tcp_port);
    }

    if (rc != 2) return;  /* 0=inserted, 1=updated, -1=error — all done */

    /* Bucket full — check if we already have a pending eviction for this LRU */
    for (int i = 0; i < NODUS_MAX_PENDING_EVICTIONS; i++) {
        if (dht->pending_evictions[i].active &&
            nodus_key_cmp(&dht->pending_evictions[i].lru_peer.node_id,
                          &lru.node_id) == 0)
            return;  /* Already pinging this LRU, discard new peer */
    }

    /* Find a free slot */
    for (int i = 0; i < NODUS_MAX_PENDING_EVICTIONS; i++) {
        if (!dht->pending_evictions[i].active) {
            dht->pending_evictions[i].active = true;
            dht->pending_evictions[i].new_peer = *peer;
            dht->pending_evictions[i].lru_peer = lru;
            dht->pending_evictions[i].ping_sent_at = nodus_time_now();

            /* Send UDP PING to the LRU candidate */
            uint8_t ping_buf[256];
            size_t plen = 0;
            nodus_t1_ping(0, &dht->host.identity->node_id,
                           ping_buf, sizeof(ping_buf), &plen);
            dht_udp_send(dht, ping_buf, plen,
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
static void eviction_on_pong(nodus_dht_t *dht, const nodus_key_t *node_id) {
    for (int i = 0; i < NODUS_MAX_PENDING_EVICTIONS; i++) {
        if (dht->pending_evictions[i].active &&
            nodus_key_cmp(&dht->pending_evictions[i].lru_peer.node_id,
                          node_id) == 0) {
            /* LRU responded — keep it, discard new peer */
            dht->pending_evictions[i].active = false;
            nodus_routing_touch(&dht->routing, node_id);
        }
    }
}

/**
 * Periodic sweep: evict LRU peers that didn't respond to PING within timeout.
 * Called from the main event loop.
 */
static void eviction_sweep(nodus_dht_t *dht) {
    uint64_t now = nodus_time_now();
    for (int i = 0; i < NODUS_MAX_PENDING_EVICTIONS; i++) {
        if (!dht->pending_evictions[i].active) continue;
        if (now - dht->pending_evictions[i].ping_sent_at < NODUS_EVICT_PING_TIMEOUT)
            continue;

        /* Timeout — evict LRU and insert new peer */
        nodus_routing_remove(&dht->routing,
                              &dht->pending_evictions[i].lru_peer.node_id);
        nodus_hashring_remove(&dht->ring,
                               &dht->pending_evictions[i].lru_peer.node_id);
        nodus_routing_insert(&dht->routing,
                              &dht->pending_evictions[i].new_peer);
        nodus_hashring_add(&dht->ring,
                           &dht->pending_evictions[i].new_peer.node_id,
                           dht->pending_evictions[i].new_peer.ip,
                           dht->pending_evictions[i].new_peer.tcp_port);
        dht->pending_evictions[i].active = false;
    }
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

/* ── DHT entry points: core → DHT (dht/nodus_dht.h) ──────────────── */

void nodus_dht_session_opened(nodus_dht_t *dht, nodus_dht_origin_t origin) {
    if (!dht || origin.slot < 0) return;
    if (origin.kind == NODUS_DHT_ORIGIN_CLIENT) {
        if (origin.slot >= NODUS_MAX_SESSIONS) return;
        memset(&dht->sessions[origin.slot], 0, sizeof(dht->sessions[0]));
        dht->sessions[origin.slot].open = true;
    } else {
        if (origin.slot >= NODUS_MAX_INTER_SESSIONS) return;
        memset(&dht->inter_sessions[origin.slot], 0, sizeof(dht->inter_sessions[0]));
    }
}

void nodus_dht_session_closed(nodus_dht_t *dht, nodus_dht_origin_t origin) {
    if (!dht || origin.slot < 0) return;
    if (origin.kind == NODUS_DHT_ORIGIN_CLIENT) {
        if (origin.slot >= NODUS_MAX_SESSIONS) return;
        memset(&dht->sessions[origin.slot], 0, sizeof(dht->sessions[0]));
    } else {
        if (origin.slot >= NODUS_MAX_INTER_SESSIONS) return;
        memset(&dht->inter_sessions[origin.slot], 0, sizeof(dht->inter_sessions[0]));
    }
}

void nodus_dht_client_request(nodus_dht_t *dht, int slot,
                              const nodus_key_t *client_fp,
                              const nodus_pubkey_t *client_pk,
                              nodus_tier2_msg_t *msg) {
    if (!dht || !msg || slot < 0 || slot >= NODUS_MAX_SESSIONS) return;

    if (strcmp(msg->method, "put") == 0)
        handle_t2_put(dht, slot, client_fp, client_pk, msg);
    else if (strcmp(msg->method, "get") == 0)
        handle_t2_get(dht, slot, msg);
    else if (strcmp(msg->method, "get_all") == 0)
        handle_t2_get_all(dht, slot, msg);
    else if (strcmp(msg->method, "get_batch") == 0)
        handle_t2_get_batch(dht, slot, msg);
    else if (strcmp(msg->method, "cnt_batch") == 0)
        handle_t2_count_batch(dht, slot, client_fp, msg);
    else if (strcmp(msg->method, "listen") == 0)
        handle_t2_listen(dht, slot, msg);
    else if (strcmp(msg->method, "unlisten") == 0)
        handle_t2_unlisten(dht, slot, msg);
    else if (strcmp(msg->method, "ch_list") == 0)
        handle_t2_ch_list(dht, slot, msg);
    else if (strcmp(msg->method, "ch_search") == 0)
        handle_t2_ch_search(dht, slot, msg);
    else if (strcmp(msg->method, "ch_get") == 0)
        handle_t2_ch_get(dht, slot, msg);
    else if (strcmp(msg->method, "m_put") == 0)
        handle_t2_media_put(dht, slot, client_fp, msg);
    else if (strcmp(msg->method, "m_meta") == 0)
        handle_t2_media_get_meta(dht, slot, msg);
    else if (strcmp(msg->method, "m_chunk") == 0)
        handle_t2_media_get_chunk(dht, slot, msg);
    else {
        /* Not a DHT method (core routes only these here): the answer the
         * client port gives any unknown method. */
        size_t rlen = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "unknown method", resp_buf, sizeof(resp_buf), &rlen);
        dht_send_client(dht, slot, resp_buf, rlen);
    }
}

void nodus_dht_inter_request(nodus_dht_t *dht, int slot,
                             const uint8_t *payload, size_t len,
                             nodus_tier2_msg_t *msg) {
    if (!dht || !msg || slot < 0 || slot >= NODUS_MAX_INTER_SESSIONS) return;
    nodus_dht_inter_session_t *sess = &dht->inter_sessions[slot];

    if (strcmp(msg->method, "fv") == 0) {
        /* Inter-node FIND_VALUE (per-session rate limit) */
        uint64_t fv_now = nodus_time_now();
        if (fv_now != sess->fv_window_start) { sess->fv_window_start = fv_now; sess->fv_count = 0; }
        if (++sess->fv_count > NODUS_FV_MAX_PER_SEC)
            return;

        nodus_tier1_msg_t t1msg;
        memset(&t1msg, 0, sizeof(t1msg));
        if (nodus_t1_decode(payload, len, &t1msg) == 0) {
            nodus_value_t *val = NULL;
            int rc = nodus_storage_get(&dht->storage, &t1msg.target, &val);
            /* A storage fault answers like a miss — "not here, ask
             * these closer nodes" — so the asking node tries others;
             * T1 FIND_VALUE has no "could not look" reply. Logged. */
            if (rc == NODUS_STORAGE_RC_FAULT)
                QGP_LOG_WARN(LOG_TAG, "INTER fv: storage read fault — answered "
                             "as not-found with closest nodes");

            size_t rlen = 0;
            if (rc == 0 && val) {
                nodus_t1_value_found(t1msg.txn_id, val,
                                      resp_buf, sizeof(resp_buf), &rlen);
                nodus_value_free(val);
            } else {
                nodus_peer_t results[NODUS_K];
                int found = nodus_routing_find_closest(&dht->routing, &t1msg.target,
                                                        results, NODUS_K);
                nodus_t1_value_not_found(t1msg.txn_id, results, found,
                                          resp_buf, sizeof(resp_buf), &rlen);
            }
            if (rlen > 0)
                dht_send_inter(dht, slot, resp_buf, rlen);
        }
        nodus_t1_msg_free(&t1msg);
        return;
    }

    if (strcmp(msg->method, "get_batch") == 0) {
        /* Inter-node forwarded get_batch — local-only, no re-forward */
        if (msg->batch_key_count > 0 && msg->batch_key_count <= NODUS_MAX_BATCH_KEYS &&
            msg->batch_keys) {
            int n = msg->batch_key_count;
            nodus_value_t ***vals = calloc((size_t)n, sizeof(nodus_value_t **));
            size_t *counts = calloc((size_t)n, sizeof(size_t));
            /* S2/S3: "own" filters by owner; "pg"/"after" ask for one
             * page per key in PK order (the cursor applies to every
             * key; the forwarding node sends one key). Without them the
             * pre-Package-A read (nodus_storage_get_all) and reply. */
            bool paged = msg->page || msg->has_after;
            const nodus_key_t *own = msg->has_own ? &msg->own_fp : NULL;
            nodus_t2_page_info_t *pages = paged
                ? calloc((size_t)n, sizeof(nodus_t2_page_info_t)) : NULL;
            /* Rev 2 items 13/15: a key whose local read FAULTED is sent
             * with "u" so the forwarding node does not count it as
             * looked at. Only the paged / owner read can tell a fault
             * (nodus_storage_get_all returns -1 for "none" and error). */
            bool *unavail = calloc((size_t)n, sizeof(bool));
            int n_unavail = 0;
            if (vals && counts && unavail && (!paged || pages)) {
                for (int i = 0; i < n; i++) {
                    if (!paged && !own) {
                        nodus_storage_get_all(&dht->storage, &msg->batch_keys[i],
                                               &vals[i], &counts[i]);
                        continue;
                    }
                    int more = 0;
                    size_t budget = paged
                        ? (size_t)NODUS_GET_ALL_PAGE_MAX_BYTES / (size_t)n
                        : (size_t)NODUS_GET_ALL_MAX_BYTES;
                    int prc = nodus_storage_get_all_page(&dht->storage, &msg->batch_keys[i],
                            own, msg->has_after ? &msg->after.owner : NULL,
                            msg->has_after ? msg->after.vid : 0, budget,
                            &vals[i], &counts[i], &more);
                    if (prc != 0) {
                        dht_free_rows(vals[i], counts[i]);
                        vals[i] = NULL;
                        counts[i] = 0;
                        more = 0;
                        if (prc == NODUS_STORAGE_RC_FAULT) {
                            unavail[i] = true;
                            n_unavail++;
                        }
                    }
                    if (paged && more && counts[i] > 0) {
                        const nodus_value_t *lastv = vals[i][counts[i] - 1];
                        pages[i].more = true;
                        pages[i].has_next = true;
                        pages[i].next.owner = lastv->owner_fp;
                        pages[i].next.vid = lastv->value_id;
                        /* Rev 3 R-d: "nx" = the serialized estimate of
                         * the row this page stopped on — the first row
                         * after the last one sent, same filters (a
                         * budget of 0 still returns that one row). The
                         * originator then knows the page was full. A
                         * probe fault leaves "nx" out (old rule). */
                        nodus_value_t **probe = NULL;
                        size_t pn = 0;
                        int pmore = 0;
                        if (nodus_storage_get_all_page(&dht->storage,
                                &msg->batch_keys[i], own, &lastv->owner_fp,
                                lastv->value_id, 0, &probe, &pn, &pmore) == 0 &&
                            pn > 0) {
                            pages[i].has_nx = true;
                            pages[i].nx = (uint64_t)NODUS_VALUE_SERIALIZED_EST(
                                probe[0]->data_len);
                        }
                        dht_free_rows(probe, pn);
                    }
                }

                size_t buf_cap = RESP_BUF_SIZE;
                uint8_t *buf = malloc(buf_cap);
                if (buf) {
                    size_t rlen = 0;
                    if (n_unavail > 0)
                        QGP_LOG_WARN(LOG_TAG, "INTER get_batch: %d of %d key(s) — "
                                     "storage read fault, sent as \"u\"", n_unavail, n);
                    if (nodus_t2_result_get_batch_ex(msg->txn_id, msg->batch_keys, n,
                                                      vals, counts, pages,
                                                      n_unavail > 0 ? unavail : NULL,
                                                      buf, buf_cap, &rlen) == 0) {
                        dht_send_inter(dht, slot, buf, rlen);
                    } else {
                        /* The forwarding peer's BF reader ignores a frame
                         * without batch results and completes the forward
                         * instead of waiting for its timeout. */
                        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                                        "batch encode failed", buf, buf_cap, &rlen);
                        dht_send_inter(dht, slot, buf, rlen);
                    }
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
            free(pages);
            free(unavail);
        }
        return;
    }

    if (strcmp(msg->method, "m_sv") == 0 && msg->has_media) {
        /* Inter-node media replication: store replicated media chunk */

        /* Per-session rate limit (same window as sv) */
        uint64_t msv_now = nodus_time_now();
        if (msv_now != sess->sv_window_start) { sess->sv_window_start = msv_now; sess->sv_count = 0; }
        if (++sess->sv_count > NODUS_SV_MAX_PER_SEC) {
            fprintf(stderr, "MEDIA_REPL: m_sv rate limit hit (%d/s), slot=%d\n",
                    sess->sv_count, slot);
            return;
        }

        /* Validate fields */
        if (msg->data && msg->data_len > 0 &&
            msg->media_chunk_count > 0 && msg->media_chunk_count <= NODUS_MEDIA_MAX_CHUNKS &&
            msg->media_total_size > 0 && msg->media_total_size <= NODUS_MEDIA_MAX_TOTAL_SIZE &&
            msg->data_len <= NODUS_MEDIA_MAX_CHUNK_SIZE) {

            /* Create meta via INSERT OR IGNORE (dedup safe) */
            nodus_media_meta_t meta;
            memset(&meta, 0, sizeof(meta));
            memcpy(meta.content_hash, msg->media_hash, 64);
            memcpy(meta.owner_fp, "replicated", 11);
            meta.media_type  = msg->media_type;
            meta.total_size  = msg->media_total_size;
            meta.chunk_count = msg->media_chunk_count;
            meta.encrypted   = msg->media_encrypted;
            meta.ttl         = msg->ttl;
            meta.created_at  = (uint64_t)time(NULL);
            meta.expires_at  = (meta.ttl > 0) ? meta.created_at + meta.ttl : 0;
            meta.complete    = false;

            /* INSERT OR IGNORE — if meta already exists, this is a no-op */
            nodus_media_put_meta(&dht->media_storage, &meta);

            /* Store chunk data */
            int rc = nodus_media_put_chunk(&dht->media_storage, msg->media_hash,
                                           msg->media_chunk_idx,
                                           msg->data, msg->data_len);
            if (rc == 0) {
                /* Check completeness */
                int chunk_count = nodus_media_count_chunks(&dht->media_storage, msg->media_hash);
                if (chunk_count >= (int)msg->media_chunk_count) {
                    nodus_media_mark_complete(&dht->media_storage, msg->media_hash);
                    fprintf(stderr, "MEDIA_REPL: m_sv replicated media complete (%d/%u chunks)\n",
                            chunk_count, msg->media_chunk_count);
                }
            }
        }
        return;
    }
}

void nodus_dht_inter_t1(nodus_dht_t *dht, int slot,
                        const nodus_key_t *peer_fp, const char *peer_ip,
                        nodus_tier1_msg_t *t1msg) {
    if (!dht || !t1msg || slot < 0 || slot >= NODUS_MAX_INTER_SESSIONS) return;
    nodus_dht_inter_session_t *sess = &dht->inter_sessions[slot];

    if (strcmp(t1msg->method, "sv") == 0 && t1msg->value) {
        /* STORE_VALUE: replication from another node */
        uint64_t sv_now = nodus_time_now();
        if (sv_now != sess->sv_window_start) { sess->sv_window_start = sv_now; sess->sv_count = 0; }
        if (++sess->sv_count > NODUS_SV_MAX_PER_SEC) {
            fprintf(stderr, "REPL_TCP: sv rate limit hit (%d/s), slot=%d\n",
                    sess->sv_count, slot);
            return;
        }

        if (nodus_value_verify(t1msg->value) == 0) {
            int put_rc = nodus_storage_put_if_newer(&dht->storage, t1msg->value);
            /* DBG: log put_rc for replication diagnosis (v0.18.1) */
            if (put_rc != 0) {
                char dbg_kh[17];
                for (int x = 0; x < 8; x++)
                    snprintf(dbg_kh + x*2, sizeof(dbg_kh) - x*2,
                             "%02x", t1msg->value->key_hash.bytes[x]);
                dbg_kh[16] = '\0';
                fprintf(stderr,
                        "DBG_PUT_SKIP: put_rc=%d key=%s vid=%llu seq=%llu type=%d\n",
                        put_rc, dbg_kh,
                        (unsigned long long)t1msg->value->value_id,
                        (unsigned long long)t1msg->value->seq,
                        (int)t1msg->value->type);
            }
            if (put_rc == 0) {
                notify_listeners(dht, &t1msg->value->key_hash, t1msg->value);
                /* Forward to remote subscribers (Scribe pattern) */
                subscription_notify(dht, &t1msg->value->key_hash, t1msg->value);
            }
        } else {
            char kh[17];
            for (int i = 0; i < 8; i++)
                snprintf(kh + i*2, sizeof(kh) - i*2, "%02x", t1msg->value->key_hash.bytes[i]);
            kh[16] = '\0';
            fprintf(stderr, "REPL_TCP: verify FAILED for key=%s... vid=%llu seq=%llu — value DROPPED\n",
                    kh, (unsigned long long)t1msg->value->value_id,
                    (unsigned long long)t1msg->value->seq);
        }

    } else if (strcmp(t1msg->method, "sub") == 0) {
        /* SUBSCRIBE_FWD: remote node subscribing to a key on us.
         * Look up subscriber's TCP 4002 port from routing table. */
        nodus_peer_t peer;
        uint16_t sub_port = NODUS_DEFAULT_PEER_PORT;
        if (nodus_routing_lookup(&dht->routing, peer_fp, &peer) == 0) {
            sub_port = peer.tcp_port ? peer.tcp_port : NODUS_DEFAULT_PEER_PORT;
        }
        subscription_add(&dht->subscriptions, &t1msg->target, peer_fp,
                          peer_ip, sub_port);

    } else if (strcmp(t1msg->method, "unsub") == 0) {
        subscription_remove(&dht->subscriptions, &t1msg->target, peer_fp);

    } else if (strcmp(t1msg->method, "ntf") == 0 && t1msg->value) {
        /* NOTIFY forwarded from a responsible node — we have a local
         * listener that asked for this key. Verify and push to local
         * listeners only. Do NOT store: this node is not necessarily
         * a responsible node for the key, and storing here would bloat
         * non-responsible nodes and break R=3 invariants. Scribe is
         * push-only — the value lives only on responsible nodes. */
        if (nodus_value_verify(t1msg->value) == 0) {
            notify_listeners(dht, &t1msg->value->key_hash, t1msg->value);
        }
    }
}

void nodus_dht_udp_request(nodus_dht_t *dht, const char *from_ip,
                           uint16_t from_port, nodus_tier1_msg_t *msg) {
    if (!dht || !msg) return;

    if (strcmp(msg->method, "fn") == 0) {
        /* FIND_NODE: rate-limit to mitigate UDP amplification (HIGH-9) */
        if (udp_rate_check(from_ip) != 0)
            return;
        /* FIND_NODE: return k closest nodes */
        nodus_peer_t results[NODUS_K];
        int found = nodus_routing_find_closest(&dht->routing, &msg->target,
                                                results, NODUS_K);
        size_t rlen = 0;
        nodus_t1_nodes_found(msg->txn_id, results, found,
                              resp_buf, sizeof(resp_buf), &rlen);
        dht_udp_send(dht, resp_buf, rlen, from_ip, from_port);

    } else if (strcmp(msg->method, "fn_r") == 0) {
        /* NODES_FOUND: feed to iterative lookup engine FIRST (FIX-C3),
         * then update routing table (existing behavior, kept). */
        iterative_lookup_handle_response(dht, msg->txn_id, msg,
                                          from_ip, from_port);
        for (int i = 0; i < msg->peer_count; i++) {
            msg->peers[i].last_seen = nodus_time_now();
            routing_insert_or_ping(dht, &msg->peers[i]);
        }

    } else if (strcmp(msg->method, "sv") == 0) {
        /* STORE_VALUE: rate-limit to mitigate UDP abuse (H-05) */
        if (udp_rate_check(from_ip) != 0) {
            fprintf(stderr, "REPL_UDP: sv rate limited from %s:%d\n", from_ip, from_port);
            return;
        }
        /* STORE_VALUE: inter-node replication */
        if (msg->value) {
            if (nodus_value_verify(msg->value) == 0) {
                if (nodus_storage_put_if_newer(&dht->storage, msg->value) == 0)
                    notify_listeners(dht, &msg->value->key_hash, msg->value);
            } else {
                char kh[17];
                for (int i = 0; i < 8; i++)
                    snprintf(kh + i*2, sizeof(kh) - i*2, "%02x", msg->value->key_hash.bytes[i]);
                kh[16] = '\0';
                fprintf(stderr, "REPL_UDP: verify FAILED for key=%s... from %s:%d — value DROPPED\n",
                        kh, from_ip, from_port);
            }
            /* Send ACK */
            size_t rlen = 0;
            nodus_t1_store_ack(msg->txn_id, resp_buf, sizeof(resp_buf), &rlen);
            dht_udp_send(dht, resp_buf, rlen, from_ip, from_port);
        }

    } else if (strcmp(msg->method, "fv") == 0) {
        /* FIND_VALUE: rate-limit to mitigate UDP amplification (HIGH-9) */
        if (udp_rate_check(from_ip) != 0)
            return;
        /* FIND_VALUE: respond with value or closest nodes */
        nodus_value_t *val = NULL;
        int rc = nodus_storage_get(&dht->storage, &msg->target, &val);
        /* Storage fault → answered like a miss (closest nodes), logged —
         * see the 4002 "fv" handler. */
        if (rc == NODUS_STORAGE_RC_FAULT)
            QGP_LOG_WARN(LOG_TAG, "UDP fv: storage read fault — answered as "
                         "not-found with closest nodes");

        size_t rlen = 0;
        if (rc == 0 && val) {
            nodus_t1_value_found(msg->txn_id, val, resp_buf, sizeof(resp_buf), &rlen);
            nodus_value_free(val);
        } else {
            nodus_peer_t results[NODUS_K];
            int found = nodus_routing_find_closest(&dht->routing, &msg->target,
                                                    results, NODUS_K);
            nodus_t1_value_not_found(msg->txn_id, results, found,
                                      resp_buf, sizeof(resp_buf), &rlen);
        }
        dht_udp_send(dht, resp_buf, rlen, from_ip, from_port);
    }
}

void nodus_dht_peer_seen(nodus_dht_t *dht, nodus_dht_peer_seen_t kind,
                         const nodus_key_t *node_id, const char *ip,
                         uint16_t udp_port, uint16_t tcp_port) {
    if (!dht || !node_id || !ip) return;

    nodus_peer_t peer;
    switch (kind) {
    case NODUS_DHT_PEER_PING:
        /* Update routing table (ping-before-evict if bucket full) */
        memset(&peer, 0, sizeof(peer));
        peer.node_id = *node_id;
        strncpy(peer.ip, ip, sizeof(peer.ip) - 1);
        peer.udp_port = udp_port;
        peer.tcp_port = tcp_port;
        peer.last_seen = nodus_time_now();
        routing_insert_or_ping(dht, &peer);

        /* A received PING proves the peer is alive (same as PONG).
         * Cancel any pending eviction for this peer. */
        eviction_on_pong(dht, node_id);
        break;

    case NODUS_DHT_PEER_PONG_TOUCH:
        /* Update routing table (the cluster health update follows, core) */
        nodus_routing_touch(&dht->routing, node_id);
        break;

    case NODUS_DHT_PEER_PONG:
        /* Cancel pending evictions for this peer (it responded) */
        eviction_on_pong(dht, node_id);

        /* Also insert into routing table if new */
        memset(&peer, 0, sizeof(peer));
        peer.node_id = *node_id;
        strncpy(peer.ip, ip, sizeof(peer.ip) - 1);
        peer.udp_port = udp_port;
        peer.tcp_port = tcp_port;
        peer.last_seen = nodus_time_now();
        routing_insert_or_ping(dht, &peer);
        break;

    case NODUS_DHT_PEER_ALIVE:
        /* Inject into Kademlia routing table so replication can find this
         * peer immediately (otherwise routing table stays empty until UDP
         * discovery completes, causing PUT replication to silently drop
         * data) */
        memset(&peer, 0, sizeof(peer));
        peer.node_id = *node_id;
        snprintf(peer.ip, sizeof(peer.ip), "%s", ip);
        peer.udp_port = udp_port;
        peer.tcp_port = tcp_port;
        peer.last_seen = nodus_time_now();
        nodus_routing_insert(&dht->routing, &peer);
        break;
    }
}

void nodus_dht_peer_dead(nodus_dht_t *dht, const nodus_key_t *node_id) {
    if (!dht || !node_id) return;
    /* Remove dead nodes from routing table to prevent stale replication */
    nodus_routing_remove(&dht->routing, node_id);
}

int nodus_dht_hint_store(nodus_dht_t *dht, const nodus_key_t *node_id,
                         const char *ip, uint16_t port,
                         const uint8_t *frame, size_t len) {
    if (!dht) return -1;
    return nodus_storage_hinted_insert(&dht->storage, node_id, ip, port,
                                       frame, len);
}

int nodus_dht_routing_snapshot(const nodus_dht_t *dht,
                               nodus_dht_peer_addr_t *out, int max) {
    if (!dht || !out || max <= 0) return 0;
    int n = 0;
    for (int b = 0; b < NODUS_BUCKETS && n < max; b++) {
        const nodus_bucket_t *bkt = &dht->routing.buckets[b];
        for (int e = 0; e < bkt->count && n < max; e++) {
            if (bkt->entries[e].active) {
                snprintf(out[n].ip, sizeof(out[n].ip), "%s",
                         bkt->entries[e].peer.ip);
                out[n].tcp_port = bkt->entries[e].peer.tcp_port;
                n++;
            }
        }
    }
    return n;
}

void nodus_dht_evict_tick(nodus_dht_t *dht) {
    if (!dht) return;
    /* Ping-before-evict: evict LRU peers that didn't respond */
    eviction_sweep(dht);
}

void nodus_dht_tick(nodus_dht_t *dht) {
    if (!dht) return;

    /* Retry DHT hinted handoff (failed replication, every 30s) */
    dht_hinted_retry(dht);

    /* Listen-forward subscription cleanup (every 60s) */
    {
        uint64_t now_sec = nodus_time_now();
        if (now_sec - dht->last_sub_cleanup > 60) {
            subscription_cleanup_expired(&dht->subscriptions);
            dht->last_sub_cleanup = now_sec;
        }
    }

    /* Periodic subscription renewal (re-forward local LISTENs to K-closest).
     * Rate-limited internally to NODUS_SUB_RENEWAL_PER_TICK per call. */
    subscription_renew_tick(dht);

    /* Iterative Kademlia FIND_NODE lookup engine tick */
    iterative_lookup_tick(dht);

    /* Batch forward async tick */
    bf_tick(dht);

    /* Kademlia bucket refresh (every 15 min) */
    dht_bucket_refresh(dht);

    /* Storage cleanup — remove expired values (every 1 hour) */
    dht_storage_cleanup(dht);

    /* Periodic republish — send stored values to R-closest (every 1 hour) */
    dht_republish(dht);

    /* Periodic media republish — send stored media to R-closest (every 24 hours) */
    dht_media_republish(dht);

    /* WAL checkpoint — truncate WAL file (every 5 min) */
    dht_wal_checkpoint(dht);

    /* Incremental vacuum — reclaim freelist pages (every 24 hours) */
    dht_incremental_vacuum(dht);
}

/* ── DHT lifecycle (dht/nodus_dht.h) ─────────────────────────────── */

int nodus_dht_init(nodus_dht_t *dht, const nodus_dht_host_t *host) {
    if (!dht || !host) return -1;
    memset(dht, 0, sizeof(*dht));
    dht->host = *host;

    /* Phase 3.2e FIX: bf_state.batches[].forwards[].fd starts at 0 from
     * memset above, but 0 is a VALID stdio fd (stdin). Cleanup paths use
     * fd >= 0 as "active" check, so uninitialized forwards trigger
     * close(0) and stomp stdin. Initialize all forward fds to -1. */
    for (int bi = 0; bi < NODUS_BF_MAX_BATCHES; bi++) {
        for (int fi = 0; fi < NODUS_BF_MAX_FORWARDS; fi++) {
            dht->bf_state.batches[bi].forwards[fi].fd = -1;
        }
    }

    /* Jitter republish start to avoid thundering herd across cluster.
     * Each node delays its first republish cycle by a random offset
     * (0 to REPUBLISH_SEC), spreading replication traffic over time. */
    {
        uint64_t now = nodus_time_now();
        uint32_t jitter_seed;
        nodus_random((uint8_t *)&jitter_seed, sizeof(jitter_seed));
        uint64_t value_jitter = jitter_seed % NODUS_REPUBLISH_SEC;
        uint64_t media_jitter = (jitter_seed >> 16) % NODUS_MEDIA_REPUBLISH_SEC;
        dht->republish.cycle_start = now - NODUS_REPUBLISH_SEC + value_jitter;
        /* Stagger media 60s after value cycle to avoid wbuf contention */
        dht->media_republish.cycle_start = now - NODUS_MEDIA_REPUBLISH_SEC + media_jitter + 60;
    }

    /* Iterative Kademlia lookup engine — no epoll/fd state.
     * All active lookups live in dht->lookup_state (already zeroed by memset). */
    dht->lookup_state.next_txn = 1;

    /* Create batch forward epoll fd */
    dht->bf_state.bf_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (dht->bf_state.bf_epoll_fd < 0) {
        fprintf(stderr, "Failed to create BF epoll fd\n");
        return -1;
    }
    for (int i = 0; i < NODUS_BF_FD_TABLE_SIZE; i++) {
        dht->bf_fd_table[i].batch_idx = -1;
        dht->bf_fd_table[i].forward_idx = -1;
    }
    return 0;
}

int nodus_dht_open(nodus_dht_t *dht, const char *data_path,
                   const char *self_ip, uint16_t self_peer_port) {
    if (!dht || !data_path || !self_ip) return -1;

    /* Open DHT storage */
    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/nodus.db",
             data_path[0] ? data_path : "/tmp");
    if (nodus_storage_open(db_path, &dht->storage) != 0) {
        fprintf(stderr, "Failed to open storage: %s\n", db_path);
        return -1;
    }
    dht->storage_open = true;

    /* Open media storage (shares same DB handle) */
    if (nodus_media_storage_open(dht->storage.db, &dht->media_storage) != 0) {
        fprintf(stderr, "Failed to open media storage\n");
        return -1;
    }
    dht->media_open = true;

    /* Open channel storage */
    char ch_db_path[512];
    snprintf(ch_db_path, sizeof(ch_db_path), "%s/channels.db",
             data_path[0] ? data_path : "/tmp");
    if (nodus_channel_store_open(ch_db_path, &dht->ch_store) != 0) {
        fprintf(stderr, "Failed to open channel store: %s\n", ch_db_path);
        return -1;
    }
    dht->ch_open = true;

    /* Register default channels (idempotent) */
    nodus_channel_store_register_defaults(&dht->ch_store);

    /* Init routing table */
    nodus_routing_init(&dht->routing, &dht->host.identity->node_id);

    /* Init hash ring (populated by Kademlia routing, NOT cluster peers) */
    nodus_hashring_init(&dht->ring);

    /* Add self to hash ring */
    nodus_hashring_add(&dht->ring, &dht->host.identity->node_id,
                        self_ip, self_peer_port);
    return 0;
}

void nodus_dht_stop(nodus_dht_t *dht) {
    if (!dht) return;

    /* Clean up any active iterative lookups (free callback data) */
    for (int i = 0; i < NODUS_LOOKUP_MAX_INFLIGHT; i++) {
        iterative_lookup_t *l = &dht->lookup_state.lookups[i];
        if (!l->active) continue;
        if (l->cb_data && l->cb_data_free) l->cb_data_free(l->cb_data);
        l->cb_data = NULL;
        l->cb_data_free = NULL;
        l->active = false;
    }

    /* Clean up batch forward state */
    for (int i = 0; i < NODUS_BF_MAX_BATCHES; i++) {
        if (dht->bf_state.batches[i].active)
            bf_batch_cleanup(dht, &dht->bf_state.batches[i]);
    }
    if (dht->bf_state.bf_epoll_fd >= 0) {
        close(dht->bf_state.bf_epoll_fd);
        dht->bf_state.bf_epoll_fd = -1;
    }
}

void nodus_dht_close(nodus_dht_t *dht) {
    if (!dht) return;
    if (dht->media_open) nodus_media_storage_close(&dht->media_storage);
    if (dht->storage_open) nodus_storage_close(&dht->storage);
    if (dht->ch_open) nodus_channel_store_close(&dht->ch_store);
    dht->media_open = dht->storage_open = dht->ch_open = false;
    if (dht->bf_state.bf_epoll_fd >= 0) {
        close(dht->bf_state.bf_epoll_fd);
        dht->bf_state.bf_epoll_fd = -1;
    }
}
