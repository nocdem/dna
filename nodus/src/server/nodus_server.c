/**
 * Nodus — Server Core Implementation
 *
 * Dual-transport event loop: UDP (Kademlia) + TCP (data + clients).
 * Handles: auth, PUT, GET, GET_ALL, LISTEN, PING, and Kademlia routing.
 */

#include "server/nodus_server.h"
#include "server/nodus_media_handler.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_p2p.h"      /* the 4004 listen port (log) */
#include "witness/nodus_witness_v2_apply.h"   /* nodus_witness_v2_committed_global_root (W4-H) */
#include "channel/nodus_channel_server.h"
#include "channel/nodus_channel_replication.h"
#include "channel/nodus_channel_ring.h"
#include "consensus/nodus_cluster.h"
#include "protocol/nodus_tier1.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_channel_crypto.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/qgp_mlkem.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"
#include "witness/nodus_witness_v2_gen.h"     /* stored chain id (P2P-PORT F6) */

#define LOG_TAG "NODUS_SRV"

extern void qgp_secure_memzero(void *ptr, size_t len);

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <sqlite3.h>                        /* chain id reader (P2P-PORT F6) */
#ifdef NODUS_HAS_JSONC
#include <json-c/json.h>                    /* the network file (P2P-PORT F6) */
#endif

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* Response buffer (shared, single-threaded).
 * Must accommodate max value (1MB data) + Dilithium5 pk(2592) + sig(4627) + CBOR.
 * Previous 64KB was too small — values >55KB data caused silent GET failures. */
#define RESP_BUF_SIZE (NODUS_MAX_VALUE_SIZE + 65536)
static uint8_t resp_buf[RESP_BUF_SIZE];

/* Channel post signature verification is now in nodus_channel_primary.c */

/* Forward declaration for inter_tcp pool send (used in replicate_value and hinted_retry) */
static int dht_republish_send(nodus_server_t *srv, const char *ip,
                               uint16_t port,
                               const nodus_key_t *expected_node_id,
                               const uint8_t *frame, size_t flen);

/* Forward declaration: iterative lookup engine (defined later in file).
 * Used by replicate_value / replicate_media_chunk for large-cluster PUT
 * discovery of true K-closest nodes. */
static int iterative_lookup_start(nodus_server_t *srv,
                                   const nodus_key_t *target,
                                   int session_slot,
                                   uint32_t client_txn_id,
                                   void (*on_complete)(struct nodus_server *,
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

static void put_replication_complete(nodus_server_t *srv,
                                      nodus_peer_t *closest, int count,
                                      void *user_data);
static void media_replication_complete(nodus_server_t *srv,
                                        nodus_peer_t *closest, int count,
                                        void *user_data);

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

static void inter_session_clear(nodus_inter_session_t *sess,
                                 int slot, const char *caller) {
    /* Phase 3.2c: log every clear so we can correlate session resets with
     * downstream T1 decode failures.
     * B3 fix — channel_crypto storage now lives on the conn struct, not
     * inline in this session. Read counters via sess->conn (NULL-guarded
     * because the conn may already be freed by the time we get here). */
    void *prev_conn = sess->conn;
    int prev_established = 0;
    unsigned long long prev_tx = 0, prev_rx = 0;
    if (sess->conn) {
        prev_established = sess->conn->channel_crypto.established ? 1 : 0;
        prev_tx = (unsigned long long)sess->conn->channel_crypto.tx_counter;
        prev_rx = (unsigned long long)sess->conn->channel_crypto.rx_counter;
    }
    fprintf(stderr,
            "SESS_CLEAR: slot=%d caller=%s prev_conn=%p prev_established=%d "
            "prev_tx=%llu prev_rx=%llu\n",
            slot, caller, prev_conn, prev_established, prev_tx, prev_rx);
    memset(sess, 0, sizeof(*sess));
}

static void session_clear(nodus_session_t *sess) {
    memset(sess, 0, sizeof(*sess));
    nodus_circuit_table_init(&sess->circuits);
}

/* Find an authenticated session by client fingerprint (for local circuit bridge) */
static nodus_session_t *find_session_by_fp(nodus_server_t *srv, const nodus_key_t *fp) {
    for (int i = 0; i < NODUS_MAX_SESSIONS; i++) {
        nodus_session_t *s = &srv->sessions[i];
        if (s->authenticated && s->conn != NULL &&
            nodus_key_cmp(&s->client_fp, fp) == 0) {
            return s;
        }
    }
    return NULL;
}

/* Find a cluster peer by IP-hash peer_idx (inverse of p_sync peer_idx formula).
 * peer_idx is computed as: h=5381; for each char c in ip: h=h*33+c; pi=(h%254)+1
 * Returns NULL if no ALIVE peer matches. */
static nodus_cluster_peer_t *find_cluster_peer_by_idx(nodus_server_t *srv, uint8_t peer_idx) {
    for (int i = 0; i < srv->cluster.peer_count; i++) {
        nodus_cluster_peer_t *p = &srv->cluster.peers[i];
        if (p->state != NODUS_NODE_ALIVE) continue;
        uint32_t h = 5381;
        for (const char *c = p->ip; *c; c++) h = h * 33 + (uint8_t)*c;
        uint8_t pi = (uint8_t)(h % 254 + 1);
        if (pi == peer_idx) return p;
    }
    return NULL;
}

/* DHT Package A rev 2 item 9: is node_id a member of this node's cluster
 * (srv->cluster.peers — the configured seeds, whose placeholder id is
 * replaced by the real one on the first PONG)? Any state counts: a hint is
 * exactly for a member that is down. Hints (replication failures, pending-
 * full frames) are persisted only for members; any other peer relies on
 * the periodic republish. */
static bool cluster_knows_peer(const nodus_server_t *srv, const nodus_key_t *node_id) {
    for (int i = 0; i < srv->cluster.peer_count; i++) {
        if (nodus_key_cmp(&srv->cluster.peers[i].node_id, node_id) == 0)
            return true;
    }
    return false;
}

/* Tear down all circuits owned by this session: notify bridge peers,
 * free peer-side entries. Called before session_clear on disconnect. */
static void session_teardown_circuits(nodus_server_t *srv, nodus_session_t *sess) {
    for (int i = 0; i < NODUS_MAX_CIRCUITS_PER_SESSION; i++) {
        nodus_circuit_t *c = &sess->circuits.entries[i];
        if (!c->in_use) continue;
        if (c->is_local_bridge && c->bridge_peer_sess) {
            nodus_session_t *peer = (nodus_session_t *)c->bridge_peer_sess;
            uint64_t peer_cid = c->bridge_peer_cid;
            /* Send circ_close to peer */
            if (peer->conn) {
                uint8_t buf[256];
                size_t blen = 0;
                if (nodus_t2_circ_close(0, peer->token, peer_cid,
                                         buf, sizeof(buf), &blen) == 0) {
                    nodus_tcp_send(peer->conn, buf, blen);
                }
            }
            /* Free peer's entry (clears back-pointer on peer side) */
            nodus_circuit_free(&peer->circuits, peer_cid);
        } else if (c->inter) {
            /* Cross-nodus — notify peer nodus and free global inter entry */
            if (c->inter->peer_conn) {
                uint8_t buf[256]; size_t blen = 0;
                if (nodus_t2_ri_close(0, c->inter->peer_cid,
                                       buf, sizeof(buf), &blen) == 0) {
                    nodus_tcp_send(c->inter->peer_conn, buf, blen);
                }
            }
            nodus_inter_circuit_free(&srv->inter_circuits, c->inter->our_cid);
        }
    }
}

/* Rev 2 item 8: the client circuit attached to an inter-circuit is found by
 * POINTER identity (c->inter == ic), never by cid — a client-chosen cid may
 * equal a server-generated one in the same table, and a by-cid lookup or
 * free then hits the other circuit. */
static nodus_circuit_t *circuit_for_inter(nodus_circuit_table_t *t,
                                          const nodus_inter_circuit_t *ic) {
    for (int i = 0; i < NODUS_MAX_CIRCUITS_PER_SESSION; i++) {
        if (t->entries[i].in_use && t->entries[i].inter == ic)
            return &t->entries[i];
    }
    return NULL;
}

/* Free exactly this table entry (the by-pointer twin of nodus_circuit_free,
 * which frees the first entry with a matching cid). */
static void circuit_free_entry(nodus_circuit_table_t *t, nodus_circuit_t *c) {
    if (!c || !c->in_use) return;
    memset(c, 0, sizeof(*c));
    t->count--;
}

/* F1 (DHT Package A): release one inter-circuit entry together with the
 * local client circuit attached to it. The client is told first —
 * circ_open_err(open_err_code) while its circ_open is still pending, else
 * circ_close — then its circuit is freed (which drops c->inter), and only
 * then the global entry. Freeing the global entry alone left c->inter
 * pointing at a slot the next circuit reuses. */
static void inter_circuit_release(nodus_server_t *srv, nodus_inter_circuit_t *ic,
                                  int open_err_code) {
    nodus_session_t *client = (nodus_session_t *)ic->local_sess;
    if (client) {
        nodus_circuit_t *c = circuit_for_inter(&client->circuits, ic);
        if (c) {
            if (client->conn) {
                uint8_t buf[256];
                size_t blen = 0;
                int rc = (ic->is_originator && ic->pending_open)
                    ? nodus_t2_circ_open_err(ic->client_txn_id, ic->local_cid,
                                             open_err_code, buf, sizeof(buf), &blen)
                    : nodus_t2_circ_close(0, client->token, ic->local_cid,
                                          buf, sizeof(buf), &blen);
                if (rc == 0) nodus_tcp_send(client->conn, buf, blen);
            }
            circuit_free_entry(&client->circuits, c);
        }
    }
    nodus_inter_circuit_free(&srv->inter_circuits, ic->our_cid);
}

void nodus_server_inter_conn_closed(nodus_server_t *srv,
                                    const nodus_tcp_conn_t *conn) {
    if (!srv || !conn) return;
    int closed = 0;
    for (int i = 0; i < NODUS_INTER_CIRCUITS_MAX; i++) {
        nodus_inter_circuit_t *ic = &srv->inter_circuits.entries[i];
        /* Pointer compare only — the conn is about to be freed. */
        if (!ic->in_use || ic->peer_conn != conn) continue;
        inter_circuit_release(srv, ic, NODUS_ERR_CIRCUIT_CLOSED);
        closed++;
    }
    if (closed > 0)
        fprintf(stderr, "INTER_CIRCUIT: closed %d circuit(s) on 4002 disconnect "
                "of %s:%u\n", closed, conn->ip, (unsigned)conn->port);
}

int nodus_server_inter_sweep_orphans(nodus_server_t *srv, uint64_t now_ms,
                                     uint64_t max_age_ms) {
    if (!srv) return 0;
    int freed = 0;
    for (int i = 0; i < NODUS_INTER_CIRCUITS_MAX; i++) {
        nodus_inter_circuit_t *ic = &srv->inter_circuits.entries[i];
        if (!ic->in_use || !ic->pending_open || ic->created_at_ms == 0) continue;
        if (now_ms - ic->created_at_ms < max_age_ms) continue;
        inter_circuit_release(srv, ic, NODUS_ERR_TIMEOUT);
        freed++;
    }
    /* Same predicate as the table's own sweep: after the loop above it
     * finds nothing; kept so the generic sweep remains the backstop. */
    freed += nodus_inter_circuit_sweep_orphans(&srv->inter_circuits, now_ms, max_age_ms);
    return freed;
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
static void listen_fwd_complete(nodus_server_t *srv,
                                 nodus_peer_t *closest, int count,
                                 void *user_data);

/** Periodic subscription renewal: re-forward local client LISTEN keys to
 *  current responsible nodes. Rate-limited to prevent bursts.
 *
 *  Walks through all sessions and their listen_keys, starting a new
 *  iterative FIND_NODE lookup for each. Processes up to
 *  NODUS_SUB_RENEWAL_PER_TICK keys per call, saving progress in
 *  srv->sub_renewal bookmark to resume next tick.
 *
 *  A full renewal cycle starts every NODUS_SUBSCRIPTION_TTL/2 (7.5 min).
 */
static void subscription_renew_tick(nodus_server_t *srv) {
    if (!srv) return;

    /* Start a new renewal cycle every NODUS_SUBSCRIPTION_TTL / 2 */
    uint64_t now = nodus_time_now();
    if (now - srv->sub_renewal.last_renewal < NODUS_SUBSCRIPTION_TTL / 2) {
        /* Not time yet — but if we're mid-cycle, continue processing */
        if (srv->sub_renewal.session_idx == 0 && srv->sub_renewal.key_idx == 0) {
            return;
        }
    } else if (srv->sub_renewal.session_idx == 0 && srv->sub_renewal.key_idx == 0) {
        /* Start new cycle */
        srv->sub_renewal.last_renewal = now;
    }

    int processed = 0;
    while (processed < NODUS_SUB_RENEWAL_PER_TICK &&
           srv->sub_renewal.session_idx < NODUS_MAX_SESSIONS) {

        nodus_session_t *s = &srv->sessions[srv->sub_renewal.session_idx];

        if (!s->conn || !s->authenticated) {
            /* Skip disconnected/unauthed sessions */
            srv->sub_renewal.session_idx++;
            srv->sub_renewal.key_idx = 0;
            continue;
        }

        if (srv->sub_renewal.key_idx >= s->listen_count) {
            /* Done with this session */
            srv->sub_renewal.session_idx++;
            srv->sub_renewal.key_idx = 0;
            continue;
        }

        /* Process this listen key: re-forward subscription */
        nodus_key_t *key_copy = malloc(sizeof(nodus_key_t));
        if (key_copy) {
            *key_copy = s->listen_keys[srv->sub_renewal.key_idx];
            if (iterative_lookup_start(srv, key_copy, -1, 0,
                                        listen_fwd_complete, key_copy, free) != 0) {
                /* No slots — fallback (synchronous) */
                nodus_peer_t closest[NODUS_R];
                int count = nodus_routing_find_closest(&srv->routing, key_copy,
                                                         closest, NODUS_R);
                listen_fwd_complete(srv, closest, count, key_copy);
            }
        }

        srv->sub_renewal.key_idx++;
        processed++;
    }

    /* If we walked past all sessions, reset for next cycle */
    if (srv->sub_renewal.session_idx >= NODUS_MAX_SESSIONS) {
        srv->sub_renewal.session_idx = 0;
        srv->sub_renewal.key_idx = 0;
        QGP_LOG_DEBUG(LOG_TAG, "SUB_RENEWAL: cycle complete");
    }
}

/** Send a T1 notify to every remote subscriber interested in key. */
static void subscription_notify(nodus_server_t *srv, const nodus_key_t *key,
                                 const nodus_value_t *val) {
    if (!srv || !key || !val) return;
    nodus_subscription_table_t *table = &srv->subscriptions;
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
        if (nodus_key_cmp(&e->subscriber_node_id, &srv->identity.node_id) == 0) continue;
        if (!e->subscriber_ip[0]) continue;
        if (dht_republish_send(srv, e->subscriber_ip, e->subscriber_port,
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

/* Forward declaration for inter_tcp pool replication */
static int dht_republish_send(nodus_server_t *srv, const char *ip,
                               uint16_t port,
                               const nodus_key_t *expected_node_id,
                               const uint8_t *frame, size_t flen);

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
static void do_replicate_store_frame(nodus_server_t *srv,
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
        if (nodus_key_cmp(&closest[i].node_id, &srv->identity.node_id) == 0) {
            skipped_self++;
            continue;
        }

        int send_rc = dht_republish_send(srv, closest[i].ip, closest[i].tcp_port,
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
             * unknown nodes are not hinted; republish covers them). */
            if (!cluster_knows_peer(srv, &closest[i].node_id)) continue;
            uint64_t offline = nodus_cluster_peer_offline_secs(&srv->cluster, &closest[i].node_id);
            if (offline < NODUS_HINT_OFFLINE_SKIP_SEC) {
                /* F4: a refused hint (cap reached, -3, logged by storage)
                 * is not counted as queued. */
                if (nodus_storage_hinted_insert(&srv->storage,
                                                 &closest[i].node_id,
                                                 closest[i].ip, closest[i].tcp_port,
                                                 frame, flen) == 0)
                    hinted++;
            }
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

void nodus_server_replicate_value(nodus_server_t *srv, const nodus_value_t *val) {
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

    int known = nodus_routing_count(&srv->routing);

    if (known <= NODUS_R * 4) {
        /* Small cluster fast path — routing table IS the network. */
        nodus_peer_t closest[NODUS_R];
        int count = nodus_routing_find_closest(&srv->routing, &val->key_hash,
                                                closest, NODUS_R);
        QGP_LOG_DEBUG(LOG_TAG, "REPL: key=%s... vid=%llu fast_path found=%d (R=%d)",
                      rpl_kh, (unsigned long long)val->value_id, count, NODUS_R);
        do_replicate_store_frame(srv, &val->key_hash, frame, flen,
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

    if (iterative_lookup_start(srv, &val->key_hash, -1, 0,
                                put_replication_complete, ctx,
                                put_repl_ctx_free) != 0) {
        /* No lookup slots — fallback to routing table fast path. */
        nodus_peer_t closest[NODUS_R];
        int count = nodus_routing_find_closest(&srv->routing, &val->key_hash,
                                                closest, NODUS_R);
        QGP_LOG_DEBUG(LOG_TAG, "REPL: key=%s... iter FALLBACK found=%d",
                      rpl_kh, count);
        do_replicate_store_frame(srv, &val->key_hash, frame, flen,
                                 closest, count, "REPL-FB", rpl_kh);
        put_repl_ctx_free(ctx);
    }
}

static void put_replication_complete(nodus_server_t *srv,
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
        if (nodus_key_cmp(&closest[i].node_id, &srv->identity.node_id) == 0) continue;
        if (dht_republish_send(srv, closest[i].ip, closest[i].tcp_port,
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
            if (!cluster_knows_peer(srv, &closest[i].node_id)) continue;  /* item 9 */
            uint64_t offline = nodus_cluster_peer_offline_secs(&srv->cluster,
                                                                &closest[i].node_id);
            if (offline < NODUS_HINT_OFFLINE_SKIP_SEC) {
                nodus_storage_hinted_insert(&srv->storage, &closest[i].node_id,
                                             closest[i].ip, closest[i].tcp_port,
                                             ctx->frame, ctx->flen);
            }
        }
    }

    QGP_LOG_DEBUG(LOG_TAG,
                  "REPL_ITER: key=%s... iterative store sent=%d failed=%d closest=%d",
                  kh, sent, failed, count);

    /* on_complete owns cb_data cleanup on normal completion. */
    put_repl_ctx_free(ctx);
}

void nodus_server_replicate_media_chunk(nodus_server_t *srv,
                                         const nodus_media_meta_t *meta,
                                         uint32_t chunk_index,
                                         const uint8_t *data, size_t data_len) {
    if (!srv || !meta || !data || data_len == 0) return;

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

    int known = nodus_routing_count(&srv->routing);

    fprintf(stderr,
            "MEDIA-REPL-CALL: hash=%s chunk=%u routing=%d path=%s\n",
            mkh, chunk_index, known,
            (known <= NODUS_R * 4) ? "fast" : "iter");

    if (known <= NODUS_R * 4) {
        /* Small cluster fast path — routing table is the network */
        nodus_peer_t closest[NODUS_R];
        int count = nodus_routing_find_closest(&srv->routing, &media_key,
                                                closest, NODUS_R);
        fprintf(stderr,
                "MEDIA-REPL-FAST: hash=%s chunk=%u found=%d (target_R=%d)\n",
                mkh, chunk_index, count, NODUS_R);
        do_replicate_store_frame(srv, &media_key, frame, flen,
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

    if (iterative_lookup_start(srv, &media_key, -1, 0,
                                media_replication_complete, ctx,
                                put_media_ctx_free) != 0) {
        /* No lookup slots — fallback to routing table fast path. */
        nodus_peer_t closest[NODUS_R];
        int count = nodus_routing_find_closest(&srv->routing, &media_key,
                                                closest, NODUS_R);
        fprintf(stderr,
                "MEDIA-REPL-ITER-FB: hash=%s chunk=%u found=%d (no lookup slots)\n",
                mkh, chunk_index, count);
        do_replicate_store_frame(srv, &media_key, frame, flen,
                                 closest, count, "MEDIA-REPL-FB", mkh);
        put_media_ctx_free(ctx);
    }
}

static void media_replication_complete(nodus_server_t *srv,
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
        if (nodus_key_cmp(&closest[i].node_id, &srv->identity.node_id) == 0) continue;
        if (dht_republish_send(srv, closest[i].ip, closest[i].tcp_port,
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
            if (!cluster_knows_peer(srv, &closest[i].node_id)) continue;  /* item 9 */
            uint64_t offline = nodus_cluster_peer_offline_secs(&srv->cluster,
                                                                &closest[i].node_id);
            if (offline < NODUS_HINT_OFFLINE_SKIP_SEC) {
                nodus_storage_hinted_insert(&srv->storage, &closest[i].node_id,
                                             closest[i].ip, closest[i].tcp_port,
                                             ctx->frame, ctx->flen);
            }
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
static void dht_hinted_retry(nodus_server_t *srv) {
    static uint64_t last_retry = 0;
    uint64_t now = nodus_time_now();

    if (now - last_retry < NODUS_HINTED_RETRY_SEC)
        return;
    last_retry = now;

    /* Cleanup expired entries first */
    int cleaned = nodus_storage_hinted_cleanup(&srv->storage);
    int total_hints = nodus_storage_hinted_count(&srv->storage);
    if (total_hints > 0 || cleaned > 0)
        fprintf(stderr, "HINT-RETRY: tick start — %d pending, %d expired-cleaned\n",
                total_hints, cleaned > 0 ? cleaned : 0);

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

        /* Fetch entries first — we need them either way, and they carry the
         * peer_ip/peer_port that was current at hint creation time. */
        nodus_dht_hint_t *entries = NULL;
        size_t count = 0;
        if (nodus_storage_hinted_get(&srv->storage, &node_id,
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
        if (nodus_routing_lookup(&srv->routing, &node_id, &peer) == 0) {
            ip = peer.ip;
            tcp_port = peer.tcp_port;
        } else {
            ip = entries[0].peer_ip;
            tcp_port = entries[0].peer_port;
        }

        int h_sent = 0, h_bumped = 0, h_expired = 0;
        for (size_t j = 0; j < count; j++) {
            if (dht_republish_send(srv, ip, tcp_port,
                                    &node_id,
                                    entries[j].frame_data,
                                    entries[j].frame_len) == 0) {
                nodus_storage_hinted_delete(&srv->storage, entries[j].id);
                h_sent++;
            } else {
                /* Send failed — TCP buffer likely full. Bump retry count,
                 * delete if max retries reached, then STOP trying this
                 * peer to avoid flooding the buffer. */
                int retries = nodus_storage_hinted_bump_retry(
                    &srv->storage, entries[j].id);
                if (retries >= NODUS_HINT_MAX_RETRIES) {
                    nodus_storage_hinted_delete(&srv->storage, entries[j].id);
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

        /* FIX-L2: pass raw CBOR to nodus_udp_send() — it applies the
         * wire frame internally. Previously we framed twice, producing
         * a nested 7-byte-header frame that peers couldn't decode. */
        uint8_t buf[512];
        size_t len = 0;
        if (nodus_t1_find_node(0, &random_key, buf, sizeof(buf), &len) == 0 && len > 0)
            nodus_udp_send(&srv->udp, buf, len, target->ip, target->udp_port);
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

    nodus_media_cleanup(&srv->media_storage);
}

/* ── WAL checkpoint + incremental vacuum ─────────────────────────── */

static void dht_wal_checkpoint(nodus_server_t *srv) {
    uint64_t now = nodus_time_now();
    if (now - srv->last_wal_checkpoint < NODUS_WAL_CHECKPOINT_SEC) return;
    srv->last_wal_checkpoint = now;

    /* Reset all prepared statements to release read snapshots.
     * Without this, stepped-but-not-reset cursors hold implicit
     * read transactions that block WAL checkpoint. */
    sqlite3_stmt *stmts[] = {
        srv->storage.stmt_put, srv->storage.stmt_get,
        srv->storage.stmt_get_all, srv->storage.stmt_delete,
        srv->storage.stmt_cleanup, srv->storage.stmt_count,
        srv->storage.stmt_put_if_newer, srv->storage.stmt_fetch_batch,
        srv->storage.stmt_exclusive_owner,
        srv->storage.stmt_hint_insert, srv->storage.stmt_hint_get,
        srv->storage.stmt_hint_delete, srv->storage.stmt_hint_cleanup,
        srv->storage.stmt_hint_count,
        srv->media_storage.stmt_put_meta, srv->media_storage.stmt_put_chunk,
        srv->media_storage.stmt_get_meta, srv->media_storage.stmt_get_chunk,
        srv->media_storage.stmt_exists, srv->media_storage.stmt_mark_complete,
        srv->media_storage.stmt_count_chunks,
        srv->media_storage.stmt_cleanup_expired,
        srv->media_storage.stmt_cleanup_incomplete,
        srv->media_storage.stmt_cleanup_orphan_chunks,
        srv->media_storage.stmt_count_per_owner,
        srv->media_storage.stmt_fetch_batch,
    };
    for (size_t i = 0; i < sizeof(stmts)/sizeof(stmts[0]); i++) {
        if (stmts[i]) sqlite3_reset(stmts[i]);
    }

    int nlog = 0, nckpt = 0;
    int rc = sqlite3_wal_checkpoint_v2(srv->storage.db, NULL,
                                        SQLITE_CHECKPOINT_TRUNCATE, &nlog, &nckpt);
    if (rc == SQLITE_OK && nlog > 0)
        fprintf(stderr, "WAL-CKPT: nodus.db truncated (%d frames)\n", nckpt);
    else if (rc == SQLITE_BUSY && nlog > 0)
        fprintf(stderr, "WAL-CKPT: nodus.db BUSY (%d/%d frames), retrying PASSIVE\n", nckpt, nlog);
    if (rc == SQLITE_BUSY)
        sqlite3_wal_checkpoint_v2(srv->storage.db, NULL,
                                   SQLITE_CHECKPOINT_PASSIVE, NULL, NULL);

    /* channels.db has its own DB handle */
    if (srv->ch_server.ch_store && srv->ch_server.ch_store->db) {
        sqlite3_wal_checkpoint_v2(srv->ch_server.ch_store->db, NULL,
                                   SQLITE_CHECKPOINT_TRUNCATE, NULL, NULL);
    }
}

static void dht_incremental_vacuum(nodus_server_t *srv) {
    uint64_t now = nodus_time_now();
    if (now - srv->last_vacuum < NODUS_VACUUM_SEC) return;
    srv->last_vacuum = now;

    sqlite3_exec(srv->storage.db, "PRAGMA incremental_vacuum(10000)",
                 NULL, NULL, NULL);
    if (srv->ch_server.ch_store && srv->ch_server.ch_store->db) {
        sqlite3_exec(srv->ch_server.ch_store->db, "PRAGMA incremental_vacuum(10000)",
                     NULL, NULL, NULL);
    }
    fprintf(stderr, "VACUUM: incremental vacuum completed\n");
}

/* ── Phase 1: Send diagnostics dump ──────────────────────────────── */
/* Periodic per-peer counter dump so we can correlate buf_ensure failures
 * with throughput and identify slow peers. No behavior change — pure
 * visibility for Phase 1 of the send-path diagnosis. */
static void dht_send_stats_dump(nodus_server_t *srv) {
    uint64_t now = nodus_time_now();
    if (now - srv->last_stats_dump < NODUS_STATS_DUMP_SEC) return;
    srv->last_stats_dump = now;

    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = srv->inter_tcp.pool[i];
        if (!c || c->state != NODUS_CONN_CONNECTED) continue;
        if (c->send_ok_count == 0 && c->send_full_count == 0 &&
            c->pending_enqueued_count == 0 && c->decrypt_skip_count == 0) continue;

        /* Phase 3.2a: crypto state tag for asymmetry diagnosis.
         * B3 fix — read inline channel_crypto field directly. */
        const char *crypto_state = c->channel_crypto.established ? "est" : "none";

        fprintf(stderr,
                "SEND_STATS: peer=%s:%u slot=%d crypto=%s ok=%llu full=%llu "
                "bytes=%llu wlen=%zu wcap=%zu "
                "pending_now=%zu pending_bytes=%zu enq=%llu drain=%llu hint=%llu "
                "decrypt_skip=%llu\n",
                c->ip, (unsigned)c->port, c->slot, crypto_state,
                (unsigned long long)c->send_ok_count,
                (unsigned long long)c->send_full_count,
                (unsigned long long)c->send_bytes_total,
                c->wlen, c->wcap,
                c->pending_count, c->pending_bytes,
                (unsigned long long)c->pending_enqueued_count,
                (unsigned long long)c->pending_drained_count,
                (unsigned long long)c->pending_hint_fallback_count,
                (unsigned long long)c->decrypt_skip_count);
    }
}

/* ── Phase 3: Pending-full hint fallback ─────────────────────────── */
/* Invoked by the TCP layer when a send cannot fit into wbuf AND the
 * per-conn pending queue is also at its cap. We persist the frame to
 * the DHT hinted handoff table so it can be delivered when the peer
 * has drained — same path that periodic republish already uses.
 *
 * Dedup key policy: the authenticated peer identity (peer_id), so
 * retries bucket with the canonical node_id. DHT Package A F4: a conn
 * without an authenticated peer_id persists nothing (the former synthetic
 * SHA3-512("ip:port") fallback is gone); the per-peer and whole-table caps
 * live in nodus_storage_hinted_insert. */
static void server_on_pending_full(nodus_tcp_conn_t *conn,
                                    const uint8_t *payload, size_t len,
                                    void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    if (!srv || !conn || !payload) return;

    /* F4: persist hints ONLY for an authenticated peer identity. peer_id is
     * set after a verified auth on the accepting side and after the
     * identity pin check on the dialing side (dispatch_inter auth_ok). An
     * unauthenticated conn (no peer_id) gets nothing persisted — previously
     * a synthetic SHA3-512("ip:port") id let any unauthenticated conn that
     * stopped reading fill the hint table. */
    if (!conn->peer_id_set) {
        fprintf(stderr,
                "PENDING_FULL: peer=%s:%u len=%zu not authenticated — frame "
                "DROPPED (no hint)\n",
                conn->ip, (unsigned)conn->port, len);
        return;
    }
    /* Rev 2 item 9: and only for a member of this node's cluster. Any
     * authenticated identity (keys are free) could otherwise park frames in
     * the hint table; non-members rely on the periodic republish. */
    if (!cluster_knows_peer(srv, &conn->peer_id)) {
        QGP_LOG_WARN(LOG_TAG, "PENDING_FULL: peer=%s:%u len=%zu not a cluster "
                     "member — frame DROPPED (no hint)",
                     conn->ip, (unsigned)conn->port, len);
        return;
    }
    nodus_key_t dedup_id;
    memcpy(&dedup_id, &conn->peer_id, sizeof(dedup_id));
    const char *id_source = "peer_id";

    /* Build a fully framed wire blob (hint drain resends it as-is). */
    size_t frame_size = NODUS_FRAME_HEADER_SIZE + len;
    uint8_t *framed = malloc(frame_size);
    if (!framed) {
        fprintf(stderr, "PENDING_FULL: malloc failed (peer=%s:%u len=%zu)\n",
                conn->ip, (unsigned)conn->port, len);
        return;
    }
    size_t written = nodus_frame_encode(framed, frame_size, payload, (uint32_t)len);
    if (written != frame_size) {
        fprintf(stderr, "PENDING_FULL: frame_encode failed (peer=%s:%u len=%zu)\n",
                conn->ip, (unsigned)conn->port, len);
        free(framed);
        return;
    }

    int rc = nodus_storage_hinted_insert(&srv->storage,
                                          &dedup_id,
                                          conn->ip, conn->port,
                                          framed, frame_size);
    free(framed);

    if (rc != 0) {
        /* rc -3: a hint cap (per peer / whole table) is reached — the frame
         * is DROPPED; the transport still reports the send as queued
         * (nodus_tcp.c pending-full path), the 10-minute republish repeats
         * replication frames. */
        fprintf(stderr,
                "PENDING_FULL: hint %s (peer=%s:%u len=%zu id=%s rc=%d) — frame DROPPED\n",
                rc == NODUS_STORAGE_RC_QUOTA ? "cap reached" : "insert failed",
                conn->ip, (unsigned)conn->port, len, id_source, rc);
        return;
    }
    fprintf(stderr,
            "PENDING_FULL: peer=%s:%u len=%zu queued to hint table (id=%s)\n",
            conn->ip, (unsigned)conn->port, len, id_source);
}

/* ── Periodic republish (via inter_tcp pool) ────────────────────── */

/** Send a pre-framed replication payload via persistent inter_tcp pool.
 *  Frame is already wire-encoded (nodus_frame_encode already called by caller).
 *  Returns 0 on success, -1 on failure (caller should use hinted handoff). */
static int dht_republish_send(nodus_server_t *srv, const char *ip,
                               uint16_t port,
                               const nodus_key_t *expected_node_id,
                               const uint8_t *frame, size_t flen) {
    nodus_tcp_conn_t *conn = nodus_tcp_find_by_addr(&srv->inter_tcp, ip, port);
    if (!conn) {
        conn = nodus_tcp_connect(&srv->inter_tcp, ip, port);
        if (!conn) return -1;
        conn->is_nodus = true;
        /* CRIT-1: record WHO we believe we are dialing, from the routing/roster
         * entry that produced this ip:port. The auth_ok handler pins
         * fingerprint(server_pk) against it before Kyber-encapsulating, so an
         * on-path attacker cannot substitute its own identity. Stored on the
         * conn (not the session) because on_inter_connect fires later and
         * inter_session_clear() would wipe session state. */
        if (expected_node_id) {
            conn->expected_peer_id = *expected_node_id;
            conn->expected_peer_id_set = true;
        }
        /* on_inter_connect callback handles auth_required + hello */
    }

    /* Auth gate for pre-framed data */
    if (conn->auth_required && conn->auth_state != NODUS_CONN_AUTH_OK) {
        if (conn->auth_state == NODUS_CONN_AUTH_FAILED) return -1;
        /* Queue raw pre-framed bytes in pending buffer */
        if (!conn->pending_buf) {
            conn->pending_cap = NODUS_TCP_BUF_INIT;
            conn->pending_buf = malloc(conn->pending_cap);
            if (!conn->pending_buf) return -1;
            conn->pending_len = 0;
        }
        if (conn->pending_len + flen > NODUS_TCP_PENDING_MAX) return -1;
        if (conn->pending_len + flen > conn->pending_cap) {
            size_t new_cap = conn->pending_cap;
            while (new_cap < conn->pending_len + flen) new_cap *= 2;
            if (new_cap > NODUS_TCP_PENDING_MAX) new_cap = NODUS_TCP_PENDING_MAX;
            uint8_t *nb = realloc(conn->pending_buf, new_cap);
            if (!nb) return -1;
            conn->pending_buf = nb;
            conn->pending_cap = new_cap;
        }
        memcpy(conn->pending_buf + conn->pending_len, frame, flen);
        conn->pending_len += flen;
        return 0;
    }

    /* Auth OK or not required.
     * If crypto is active, we must go through nodus_tcp_send() so the
     * payload gets encrypted. Extract payload from pre-framed data and
     * send via the normal path. */
    if (conn->channel_crypto.established) {
        /* frame = [7-byte header][payload]. Extract payload.
         * B3 fix — read inline channel_crypto. */
        if (flen <= NODUS_FRAME_HEADER_SIZE) return -1;
        const uint8_t *payload = frame + NODUS_FRAME_HEADER_SIZE;
        size_t payload_len = flen - NODUS_FRAME_HEADER_SIZE;
        /* Phase 3.2b-inv2: republish send path visibility. Sample: first 3
         * calls per conn logged via cc->tx_counter check inside send_progress;
         * this log just tags the entry point so we know which caller. */
        {
            nodus_channel_crypto_t *cc = &conn->channel_crypto;
            if (cc->tx_counter < 3) {
                fprintf(stderr,
                        "REPUBLISH_SEND slot=%d peer=%s:%u crypto=%p "
                        "tx_counter=%llu flen=%zu\n",
                        conn->slot, conn->ip, (unsigned)conn->port,
                        (void *)cc,
                        (unsigned long long)cc->tx_counter, flen);
            }
        }
        int rc = nodus_tcp_send_progress(conn, payload, payload_len, NULL, NULL);
        if (rc != 0) {
            /* Send failed (buffer full / slow consumer) — disconnect so
             * next retry opens a fresh connection instead of hammering
             * the same stalled conn with buf_ensure errors. */
            fprintf(stderr, "REPL_SEND: slow consumer %s:%d, disconnecting\n",
                    conn->ip, conn->port);
            nodus_tcp_disconnect(&srv->inter_tcp, conn);
        }
        return rc;
    }

    /* No crypto — write pre-framed data directly to wbuf (fast path) */
    if (conn->wpos > 0) {
        size_t remaining = conn->wlen - conn->wpos;
        if (remaining > 0)
            memmove(conn->wbuf, conn->wbuf + conn->wpos, remaining);
        conn->wlen = remaining;
        conn->wpos = 0;
    }
    size_t needed = conn->wlen + flen;
    const size_t max_wbuf = NODUS_MAX_FRAME_TCP + NODUS_FRAME_HEADER_SIZE + 4096;
    if (needed > max_wbuf) {
        /* Buffer full — slow consumer, disconnect */
        fprintf(stderr, "REPL_SEND: slow consumer %s:%d (wlen=%zu), disconnecting\n",
                conn->ip, conn->port, conn->wlen);
        nodus_tcp_disconnect(&srv->inter_tcp, conn);
        return -1;
    }
    if (needed > conn->wcap) {
        size_t new_cap = conn->wcap;
        while (new_cap < needed) new_cap *= 2;
        if (new_cap > max_wbuf) new_cap = max_wbuf;
        uint8_t *nb = realloc(conn->wbuf, new_cap);
        if (!nb) return -1;
        conn->wbuf = nb;
        conn->wcap = new_cap;
    }
    memcpy(conn->wbuf + conn->wlen, frame, flen);
    conn->wlen += flen;

#ifndef _WIN32
    /* Ensure EPOLLOUT so data gets flushed */
    if (conn->fd >= 0 && srv->inter_tcp.epoll_fd >= 0) {
        uint32_t et = srv->inter_tcp.level_triggered ? 0 : EPOLLET;
        struct epoll_event ev = { .events = EPOLLIN | EPOLLOUT | et, .data.ptr = conn };
        epoll_ctl(srv->inter_tcp.epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
    }
#endif

    return 0;
}

/** Main republish tick — fetch batch, send to K-closest, manage connections */
static void dht_republish(nodus_server_t *srv) {
    dht_republish_state_t *rs = &srv->republish;
    uint64_t now = nodus_time_now();

    if (!rs->active) {
        /* Start new cycle every NODUS_REPUBLISH_SEC */
        if (now - rs->cycle_start < NODUS_REPUBLISH_SEC) return;
        /* Wait for routing table to have enough peers */
        if (nodus_routing_count(&srv->routing) < NODUS_REPLICATION_MIN) return;
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
    int fetched = nodus_storage_fetch_batch(&srv->storage,
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
        int n = nodus_routing_find_closest(&srv->routing, &val->key_hash, closest, NODUS_R);

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
            if (nodus_key_cmp(&closest[j].node_id, &srv->identity.node_id) == 0) continue;
            int rc = dht_republish_send(srv, closest[j].ip, closest[j].tcp_port,
                                         &closest[j].node_id, frame, flen);
            /* Item 9: hints only for cluster members; the next republish
             * cycle covers any other peer. */
            if (rc != 0 && cluster_knows_peer(srv, &closest[j].node_id)) {
                uint64_t offline = nodus_cluster_peer_offline_secs(&srv->cluster,
                                                                    &closest[j].node_id);
                if (offline < NODUS_HINT_OFFLINE_SKIP_SEC) {
                    nodus_storage_hinted_insert(&srv->storage,
                                                 &closest[j].node_id,
                                                 closest[j].ip, closest[j].tcp_port,
                                                 frame, flen);
                }
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
static void dht_media_republish(nodus_server_t *srv) {
    dht_media_republish_state_t *mrs = &srv->media_republish;
    uint64_t now = nodus_time_now();

    /* Cycle activation gate */
    if (!mrs->active) {
        if (now - mrs->cycle_start < NODUS_MEDIA_REPUBLISH_SEC) return;
        if (nodus_routing_count(&srv->routing) < NODUS_REPLICATION_MIN) {
            fprintf(stderr,
                    "MEDIA-REPUB-SKIP: routing sparse (%d < %d)\n",
                    nodus_routing_count(&srv->routing), NODUS_REPLICATION_MIN);
            return;
        }
        fprintf(stderr,
                "MEDIA-REPUB-CYCLE: start cycle, routing=%d\n",
                nodus_routing_count(&srv->routing));
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
        int fetched = nodus_media_fetch_batch(&srv->media_storage,
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
        if (nodus_media_get_chunk(&srv->media_storage,
                                   mrs->current_meta.content_hash,
                                   mrs->chunk_cursor,
                                   &chunk_data, &chunk_len) == 0) {
            nodus_server_replicate_media_chunk(srv, &mrs->current_meta,
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
            snprintf(kh + i*2, sizeof(kh) - i*2, "%02x", val->key_hash.bytes[i]);
            snprintf(fp_hex + i*2, sizeof(fp_hex) - i*2, "%02x", sess->client_fp.bytes[i]);
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

    /* Store — with EXCLUSIVE ownership enforcement.
     * put_if_newer is only for inter-node replication paths. */
    rc = nodus_storage_put(&srv->storage, val);
    if (rc == -2) {
        /* EXCLUSIVE key owned by different identity */
        nodus_value_free(val);
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_KEY_OWNED,
                        "key owned by different identity", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
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
        nodus_tcp_send(sess->conn, resp_buf, len);
        return;
    }
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
    /* Forward to remote subscribers (Scribe pattern) */
    subscription_notify(srv, &msg->key, val);

    /* Replicate to alive cluster peers via TCP STORE */
    nodus_server_replicate_value(srv, val);

    /* Respond OK */
    size_t len = 0;
    nodus_t2_put_ok(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);

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
static void bf_send_result(nodus_server_t *srv, dht_bf_batch_t *b);
static void bf_batch_cleanup(nodus_server_t *srv, dht_bf_batch_t *b);
static int bf_start_forward(nodus_server_t *srv, dht_bf_batch_t *b,
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
static int lookup_send_query(nodus_server_t *srv, iterative_lookup_t *l,
                              int qi, const nodus_peer_t *peer) {
    lookup_query_t *q = &l->queries[qi];

    uint32_t txn = srv->lookup_state.next_txn++;

    /* Encode T1 FIND_NODE. Always FIND_NODE, never FIND_VALUE. */
    uint8_t buf[256];
    size_t len = 0;
    if (nodus_t1_find_node(txn, &l->target_key, buf, sizeof(buf), &len) != 0)
        return -1;

    /* FIX-C1: send RAW CBOR — nodus_udp_send() applies the wire frame
     * internally. Calling nodus_frame_encode() here would double-frame. */
    if (nodus_udp_send(&srv->udp, buf, len, peer->ip, peer->udp_port) != 0)
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
static void lookup_send_round(nodus_server_t *srv, iterative_lookup_t *l) {
    int sent = 0;
    lookup_sort_shortlist(l);

    for (int i = 0; i < l->shortlist_count && sent < NODUS_ALPHA; i++) {
        nodus_peer_t *p = &l->shortlist[i];

        if (lookup_is_queried(l, &p->node_id)) continue;

        /* Skip self */
        if (nodus_key_cmp(&p->node_id, &srv->identity.node_id) == 0) {
            lookup_mark_queried(l, &p->node_id);
            continue;
        }

        /* Find free query slot */
        int qi = -1;
        for (int q = 0; q < NODUS_ALPHA; q++) {
            if (l->queries[q].state != LOOKUP_QUERY_SENT) { qi = q; break; }
        }
        if (qi < 0) break;

        if (lookup_send_query(srv, l, qi, p) == 0)
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
 * On completion, calls on_complete(srv, closest_nodes, count, cb_data).
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
static int iterative_lookup_start(nodus_server_t *srv,
                                   const nodus_key_t *target,
                                   int session_slot,
                                   uint32_t client_txn_id,
                                   void (*on_complete)(struct nodus_server *,
                                                       nodus_peer_t *, int,
                                                       void *),
                                   void *cb_data,
                                   void (*cb_data_free)(void *)) {
    int slot = -1;
    for (int i = 0; i < NODUS_LOOKUP_MAX_INFLIGHT; i++) {
        if (!srv->lookup_state.lookups[i].active) { slot = i; break; }
    }
    if (slot < 0) return -1;

    iterative_lookup_t *l = &srv->lookup_state.lookups[slot];
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
    int seed_count = nodus_routing_find_closest(&srv->routing, target,
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

    lookup_send_round(srv, l);

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
static void iterative_lookup_handle_response(nodus_server_t *srv,
                                              uint32_t txn,
                                              const nodus_tier1_msg_t *msg,
                                              const char *from_ip,
                                              uint16_t from_port) {
    for (int li = 0; li < NODUS_LOOKUP_MAX_INFLIGHT; li++) {
        iterative_lookup_t *l = &srv->lookup_state.lookups[li];
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
                if (nodus_key_cmp(&np->node_id, &srv->identity.node_id) == 0)
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
 * (iterative_lookup_tick disconnect, nodus_server_close shutdown).
 */
static void lookup_finalize(nodus_server_t *srv, iterative_lookup_t *l) {
    /* Populate result_nodes from closest_k if not already set */
    if (l->result_node_count == 0 && l->closest_k_count > 0) {
        memcpy(l->result_nodes, l->closest_k,
               (size_t)l->closest_k_count * sizeof(nodus_peer_t));
        l->result_node_count = l->closest_k_count;
    }

    /* Snapshot callback + result into locals BEFORE clearing the slot.
     * This makes it safe for on_complete to re-enter the engine. */
    void (*cb)(struct nodus_server *, nodus_peer_t *, int, void *) = l->on_complete;
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
    if (cb) cb(srv, result_nodes, result_count, cb_data);
}

/**
 * Tick: advance all active lookups.
 * Called from main event loop every iteration.
 */
static void iterative_lookup_tick(nodus_server_t *srv) {
    uint64_t now = nodus_time_now_ms();

    for (int li = 0; li < NODUS_LOOKUP_MAX_INFLIGHT; li++) {
        iterative_lookup_t *l = &srv->lookup_state.lookups[li];
        if (!l->active) continue;

        /* Overall timeout — finalize with best-effort closest_k */
        if (now - l->started_at > NODUS_LOOKUP_TIMEOUT_MS) {
            QGP_LOG_DEBUG(LOG_TAG,
                "lookup_timeout after %llu ms (overall), finalizing",
                (unsigned long long)(now - l->started_at));
            lookup_finalize(srv, l);
            continue;
        }

        /* Client disconnect check */
        if (l->session_slot >= 0) {
            nodus_session_t *sess = &srv->sessions[l->session_slot];
            if (!sess->conn) {
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
                        nodus_udp_send(&srv->udp, buf, len, q->ip, q->udp_port);
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
                                           &srv->identity.node_id) == 0) continue;
                        for (int qi = 0; qi < NODUS_ALPHA; qi++) {
                            if (l->queries[qi].state != LOOKUP_QUERY_SENT) {
                                if (lookup_send_query(srv, l, qi,
                                                       &l->closest_k[i]) == 0)
                                    free_slots--;
                                break;
                            }
                        }
                    }
                    if (l->queries_pending > 0) continue;
                }

                lookup_finalize(srv, l);
            } else {
                /* Not converged — send another round */
                lookup_send_round(srv, l);

                if (l->queries_pending == 0) {
                    /* No more peers to query — done */
                    lookup_finalize(srv, l);
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
 * Declared in nodus_server.h (internal section) for the unit tests. */

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
static void dht_send_unavailable(nodus_tcp_conn_t *conn, uint32_t txn,
                                 const char *why) {
    if (!conn) return;
    size_t len = 0;
    if (nodus_t2_error(txn, NODUS_ERR_UNAVAILABLE, why,
                       resp_buf, sizeof(resp_buf), &len) == 0)
        nodus_tcp_send(conn, resp_buf, len);
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
 * (nodus_server_bf_encode_result) AND by every path that answers without
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
static void dht_send_key_reply(nodus_tcp_conn_t *conn, dht_reply_kind_t kind,
                               uint32_t txn, nodus_dht_keyset_t *ks, bool has_own,
                               bool paged) {
    int verify_left = NODUS_DHT_VERIFY_CAP;
    uint8_t *buf = malloc(RESP_BUF_SIZE);
    size_t len = 0;
    if (!buf) {
        nodus_dht_keyset_clear(ks);
        dht_send_unavailable(conn, txn, "reply alloc failed");
        return;
    }
    if (dht_encode_key_reply(kind, txn, ks, has_own, paged, &verify_left,
                             buf, RESP_BUF_SIZE, &len) == 0 && conn)
        nodus_tcp_send(conn, buf, len);
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
static void get_lookup_complete(nodus_server_t *srv,
                                 nodus_peer_t *closest, int count,
                                 void *user_data) {
    get_lookup_ctx_t *ctx = (get_lookup_ctx_t *)user_data;
    if (!ctx) return;

    nodus_session_t *sess = &srv->sessions[ctx->session_slot];
    if (!sess->conn) { get_lookup_ctx_free(ctx); return; }  /* Client disconnected */

    /* Filter out self */
    int fwd_count = 0;
    nodus_peer_t fwd_peers[NODUS_K];
    for (int i = 0; i < count && fwd_count < NODUS_K; i++) {
        if (nodus_key_cmp(&closest[i].node_id, &srv->identity.node_id) != 0)
            fwd_peers[fwd_count++] = closest[i];
    }
    const nodus_key_t *own = ctx->has_own ? &ctx->own : NULL;

    /* Find a free BF batch slot */
    int bi = -1;
    if (fwd_count > 0) {
        for (int i = 0; i < NODUS_BF_MAX_BATCHES; i++) {
            if (!srv->bf_state.batches[i].active) { bi = i; break; }
        }
    }
    dht_bf_batch_t *b = (bi >= 0) ? &srv->bf_state.batches[bi] : NULL;
    if (b && nodus_server_bf_batch_setup(b, &ctx->key, 1) != 0) {
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
        dht_send_key_reply(sess->conn, DHT_REPLY_SINGLE, ctx->txn_id, &ks,
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
        if (bf_start_forward(srv, b, f, &fwd_peers[f], &ctx->key, &key_idx, 1) == 0)
            b->pending_forwards++;
    }

    /* Every forward failed to start → answer now from what is there (the
     * local row, or S6 UNAVAILABLE). Else bf_tick answers. */
    if (b->pending_forwards == 0)
        bf_send_result(srv, b);

    get_lookup_ctx_free(ctx);
}

static void handle_t2_get(nodus_server_t *srv, nodus_session_t *sess,
                           nodus_tier2_msg_t *msg) {
    /* Local read. S2: with "own", that owner's newest row
     * (nodus_storage_get_owner) instead of the key's best row. */
    nodus_value_t *val = NULL;
    int rc = msg->has_own
        ? nodus_storage_get_owner(&srv->storage, &msg->key, &msg->own_fp, &val)
        : nodus_storage_get(&srv->storage, &msg->key, &val);
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
            nodus_tcp_send(sess->conn, resp_buf, len);
        } else {
            fprintf(stderr, "NODUS_SRV: GET result encode failed (value too large?)\n");
            nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                            "value encode failed", resp_buf, sizeof(resp_buf), &len);
            nodus_tcp_send(sess->conn, resp_buf, len);
        }
        nodus_value_free(val);
        return;
    }

    /*   Small cluster: routing table covers most nodes — BF forward directly.
     *   Large cluster: iterative FIND_NODE first, then BF forward to K-closest. */
    int known = nodus_routing_count(&srv->routing);

    get_lookup_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        /* S6: forward-context alloc failure — could not look */
        nodus_value_free(val);
        dht_send_unavailable(sess->conn, msg->txn_id, "forward alloc failed");
        return;
    }
    ctx->txn_id = msg->txn_id;
    ctx->session_slot = (int)(sess - srv->sessions);
    ctx->key = msg->key;
    ctx->has_own = msg->has_own;
    if (msg->has_own) ctx->own = msg->own_fp;
    ctx->local = (rc == 0) ? val : NULL;   /* own only — the fast path took the rest */
    if (!ctx->local) nodus_value_free(val);
    ctx->local_fault = local_fault;

    if (known <= NODUS_R * 4) {
        /* Small cluster: skip iterative FIND_NODE — use routing table */
        nodus_peer_t closest[NODUS_K];
        int peer_count = nodus_routing_find_closest(&srv->routing, &msg->key,
                                                      closest, NODUS_K);
        get_lookup_complete(srv, closest, peer_count, ctx);
        return;
    }

    /* Large cluster: iterative FIND_NODE to discover true K-closest */
    if (iterative_lookup_start(srv, &msg->key,
                                (int)(sess - srv->sessions),
                                msg->txn_id,
                                get_lookup_complete, ctx, get_lookup_ctx_free) != 0) {
        /* No lookup slots — fall back to routing table + BF */
        nodus_peer_t closest[NODUS_K];
        int peer_count = nodus_routing_find_closest(&srv->routing, &msg->key,
                                                      closest, NODUS_K);
        get_lookup_complete(srv, closest, peer_count, ctx);
    }
}

static void handle_t2_get_all(nodus_server_t *srv, nodus_session_t *sess,
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
        rc = nodus_storage_get_all_page_hashed(&srv->storage, &msg->key, own,
                                               after ? &after->owner : NULL,
                                               after ? after->vid : 0,
                                               paged ? (size_t)NODUS_GET_ALL_PAGE_MAX_BYTES
                                                     : (size_t)NODUS_GET_ALL_MAX_BYTES,
                                               &vals, &hashes, &count, &local_more);
    } else {
        /* The legacy read returns no stored hashes: these rows are hashed
         * by the merge (R-g covers the paged / owner read only). */
        rc = nodus_storage_get_all(&srv->storage, &msg->key, &vals, &count);
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
            dht_send_unavailable(sess->conn, msg->txn_id, "local alloc failed");
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
    int peer_count = nodus_routing_find_closest(&srv->routing, &msg->key,
                                                  closest, NODUS_R);

    /* Filter out self */
    int fwd_count = 0;
    nodus_peer_t fwd_peers[NODUS_R];
    for (int i = 0; i < peer_count; i++) {
        if (nodus_key_cmp(&closest[i].node_id, &srv->identity.node_id) != 0) {
            fwd_peers[fwd_count++] = closest[i];
        }
    }
    local.peers = fwd_count;

    /* No peers to forward to: the local rows are the whole answer (no local
     * row → a truthful empty; single-node truth — unless the read faulted). */
    if (fwd_count == 0) {
        fprintf(stderr, "GET_ALL: key=%s... local=%zu, no peers to forward\n",
                ga_kh, count);
        dht_send_key_reply(sess->conn, DHT_REPLY_GET_ALL, msg->txn_id, &local,
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
        if (!srv->bf_state.batches[i].active) { bi = i; break; }
    }
    dht_bf_batch_t *b = (bi >= 0) ? &srv->bf_state.batches[bi] : NULL;
    if (!b) {
        fprintf(stderr, "GET_ALL: key=%s... no BF slots\n", ga_kh);
    } else if (nodus_server_bf_batch_setup(b, &msg->key, 1) != 0) {
        fprintf(stderr, "GET_ALL: key=%s... forward alloc failed\n", ga_kh);
        b = NULL;
    }
    if (!b) {
        /* Could not forward. Local rows are still an answer; with none,
         * S6: could not look → UNAVAILABLE (peers > 0, none answered). */
        dht_send_key_reply(sess->conn, DHT_REPLY_GET_ALL, msg->txn_id, &local,
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
    b->session_slot = (int)(sess - srv->sessions);
    b->started_at = nodus_time_now_ms();
    b->sets[0] = local;   /* ownership of the local candidates moves to the batch */

    /* Start forwards to up to R closest peers */
    b->pending_forwards = 0;
    int key_idx = 0;
    int fwd_limit = fwd_count < NODUS_BF_MAX_FORWARDS ? fwd_count : NODUS_BF_MAX_FORWARDS;
    for (int f = 0; f < fwd_limit; f++) {
        if (bf_start_forward(srv, b, f, &fwd_peers[f], &msg->key, &key_idx, 1) == 0) {
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
    bf_send_result(srv, b);
}

/* ── Batch Forward (BF) ─── get_batch miss → forward to closest peer ── */

static void bf_conn_cleanup(nodus_server_t *srv, dht_bf_conn_t *c) {
    if (c->fd >= 0) {
        /* Phase 3.2e: log BF close so we can correlate close(fd) → recycle. */
        fprintf(stderr, "BF_CLOSE: fd=%d state=%d encrypted=%d\n",
                c->fd, (int)c->state, c->encrypted ? 1 : 0);
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
    if (c->encrypted) nodus_channel_crypto_clear(&c->crypto);
    c->encrypted = false;
    qgp_secure_memzero(c->pending_ss, sizeof(c->pending_ss));
    qgp_secure_memzero(c->pending_nc, sizeof(c->pending_nc));
    c->state = BF_DONE;
}

static void bf_batch_cleanup(nodus_server_t *srv, dht_bf_batch_t *b) {
    for (int i = 0; i < NODUS_BF_MAX_FORWARDS; i++) {
        /* Phase 3.2e FIX: was `fd >= 0` which treated zero-initialized
         * uninitialized forwards (.bss start, or post-memset state below)
         * as valid fds, calling close(0) on each batch cleanup pass and
         * stomping stdin. Use `> 0` so only real socket fds (>= 3 in
         * practice) are cleaned. */
        if (b->forwards[i].fd > 0) bf_conn_cleanup(srv, &b->forwards[i]);
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

void nodus_server_bf_batch_cleanup(nodus_server_t *srv, dht_bf_batch_t *b) {
    if (b) bf_batch_cleanup(srv, b);
}

int nodus_server_bf_batch_setup(dht_bf_batch_t *b, const nodus_key_t *keys, int n) {
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

int nodus_server_bf_encode_result(dht_bf_batch_t *b, uint8_t *buf, size_t cap,
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
static void bf_send_result(nodus_server_t *srv, dht_bf_batch_t *b) {
    nodus_session_t *sess = &srv->sessions[b->session_slot];
    if (!sess->conn) { bf_batch_cleanup(srv, b); return; }

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
        dht_send_unavailable(sess->conn, b->txn_id, "reply alloc failed");
    } else {
        if (nodus_server_bf_encode_result(b, buf, RESP_BUF_SIZE, &len) == 0)
            nodus_tcp_send(sess->conn, buf, len);
        free(buf);
    }
    bf_batch_cleanup(srv, b);
}

int nodus_server_bf_absorb_reply(dht_bf_batch_t *b, const dht_bf_conn_t *c,
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

int nodus_server_bf_frame_status(const uint8_t *buf, size_t len, size_t cap) {
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

    return nodus_server_bf_frame_status(c->recv_buf, c->recv_len, c->recv_cap);
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
    /* Phase 3.2e: log every BF event with fd. Captures BF subsystem activity
     * we previously had no visibility into. */
    fprintf(stderr, "BF_EVENT: fd=%d events=0x%x\n", fd, events);
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

    /* ── Send states (HELLO / AUTH / KEY_INIT / BATCH) ── */
    if ((c->state == BF_SEND_HELLO || c->state == BF_SEND_AUTH ||
         c->state == BF_SEND_KEY_INIT || c->state == BF_SEND_BATCH) &&
        (events & EPOLLOUT)) {
        if (!c->send_buf) { bf_forward_fail(srv, b, c); return; }
        /* Phase 3.2e: log BF send target fd + state. If fd ever points at a
         * recycled stale value, this log will reveal the mismatch. */
        fprintf(stderr,
                "BF_SEND: fd=%d c_fd=%d state=%d peer=%s:%u send_pos=%zu "
                "send_len=%zu encrypted=%d bi=%d fi=%d\n",
                fd, c->fd, (int)c->state, c->ip, (unsigned)c->port,
                c->send_pos, c->send_len, c->encrypted ? 1 : 0, bi, fi);
        ssize_t n = send(fd, c->send_buf + c->send_pos,
                         c->send_len - c->send_pos, MSG_NOSIGNAL);
        if (n < 0) { bf_forward_fail(srv, b, c); return; }
        if (n > 0) c->send_pos += (size_t)n;
        if (c->send_pos >= c->send_len) {
            /* Send complete → switch to recv for response */
            if (c->state == BF_SEND_HELLO)      c->state = BF_RECV_CHALL;
            else if (c->state == BF_SEND_AUTH)   c->state = BF_RECV_AUTHOK;
            else if (c->state == BF_SEND_KEY_INIT) c->state = BF_RECV_KEY_ACK;
            else if (c->state == BF_SEND_BATCH)  c->state = BF_RECV_RESULT;
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

        /* C2 fix: domain-tagged AUTH_CHALLENGE. bf_forward owns its own TCP
         * socket and only runs outbound (we dialed the leader), so no
         * inbound-conn oracle vector exists here — just the domain tag. */
        nodus_sig_t sig;
        /* CRIT-1: retain the challenge nonce so BF_RECV_AUTHOK can verify the
         * peer's kpk_sig over (kyber_pk || nonce). */
        memcpy(c->challenge_nonce, msg.nonce, NODUS_NONCE_LEN);
        c->has_challenge_nonce = true;
        if (nodus_sign_auth_challenge(&sig, msg.nonce, &srv->identity.sk) != 0) {
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

    /* ── State 4: Recv AUTH_OK → Kyber key_init → key exchange ── */
    if (c->state == BF_RECV_AUTHOK && (events & EPOLLIN)) {
        int rc = bf_recv_frame(c, fd);
        if (rc < 0) { bf_forward_fail(srv, b, c); return; }
        if (rc == 0) return;

        /* Parse auth_ok → get token + kyber_pk */
        nodus_tier2_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        if (nodus_t2_decode(c->recv_buf + 7, c->recv_len - 7, &msg) != 0 ||
            msg.type == 'e') {
            nodus_t2_msg_free(&msg);
            bf_forward_fail(srv, b, c); return;
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
            bf_forward_fail(srv, b, c); return;
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
                bf_forward_fail(srv, b, c); return;
            }
            if (nodus_fingerprint(&msg.server_pk, &actual_id) != 0 ||
                nodus_key_cmp(&actual_id, &c->expected_node_id) != 0) {
                fprintf(stderr,
                        "BF CRIT-1: identity PIN MISMATCH at %s:%u — server_pk "
                        "fingerprint != dialed node_id, refusing\n",
                        c->ip, (unsigned)c->port);
                nodus_t2_msg_free(&msg);
                bf_forward_fail(srv, b, c); return;
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
            bf_forward_fail(srv, b, c); return;
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
            bf_forward_fail(srv, b, c); return;
        }
        c->send_pos = 0;
        c->recv_len = 0;
        c->state = BF_SEND_KEY_INIT;
        bf_switch_to_send(srv, c);
        return;
    }

    /* ── State 5: Send KEY_INIT (handled by generic send block above) ── */

    /* ── State 6: Recv KEY_ACK → init crypto → send encrypted batch ── */
    if (c->state == BF_RECV_KEY_ACK && (events & EPOLLIN)) {
        int rc = bf_recv_frame(c, fd);
        if (rc < 0) { bf_forward_fail(srv, b, c); return; }
        if (rc == 0) return;

        /* Parse key_ack → get server nonce */
        nodus_tier2_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        if (nodus_t2_decode(c->recv_buf + 7, c->recv_len - 7, &msg) != 0 ||
            !msg.has_key_nonce) {
            nodus_t2_msg_free(&msg);
            bf_forward_fail(srv, b, c); return;
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
            bf_forward_fail(srv, b, c); return;
        }
        /* Encrypt the CBOR payload */
        size_t enc_cap = clen + NODUS_CHANNEL_OVERHEAD;
        uint8_t *enc_buf = malloc(enc_cap);
        if (!enc_buf) { bf_forward_fail(srv, b, c); return; }
        size_t enc_len = 0;
        if (nodus_channel_encrypt(&c->crypto, cbor, clen,
                                    enc_buf, enc_cap, &enc_len) != 0) {
            free(enc_buf);
            bf_forward_fail(srv, b, c); return;
        }
        /* Frame the encrypted payload */
        if (bf_build_frame(&c->send_buf, &c->send_len, enc_buf, enc_len) != 0) {
            free(enc_buf);
            bf_forward_fail(srv, b, c); return;
        }
        free(enc_buf);
        c->send_pos = 0;
        c->recv_len = 0;
        c->state = BF_SEND_BATCH;
        bf_switch_to_send(srv, c);
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
                if (!dec_buf) { bf_forward_fail(srv, b, c); return; }
                size_t dec_len = 0;
                if (nodus_channel_decrypt(&c->crypto, payload, payload_len,
                                            dec_buf, dec_cap, &dec_len) != 0) {
                    free(dec_buf);
                    bf_forward_fail(srv, b, c); return;
                }
                payload = dec_buf;
                payload_len = dec_len;
            }

            /* An error frame / garbage absorbs nothing: the keys of this
             * forward stay unanswered (S6). */
            (void)nodus_server_bf_absorb_reply(b, c, payload, payload_len);
            free(dec_buf);  /* NULL-safe */
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
    /* One keyset per key (local rows = trusted candidates). Duplicate keys
     * in one batch stay separate entries, answered in request order. */
    nodus_dht_keyset_t *sets = calloc((size_t)n, sizeof(nodus_dht_keyset_t));
    if (!sets) {
        size_t len = 0;
        nodus_t2_error(msg->txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "alloc failed", resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
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
        if (nodus_storage_get_all(&srv->storage, &msg->batch_keys[i],
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
            int found = nodus_routing_find_closest(&srv->routing, &msg->batch_keys[ki],
                                                     closest, NODUS_R);
            if (found == 0) continue; /* No peers known — skip */

            /* Pick the first non-self closest peer */
            int chosen = -1;
            for (int c = 0; c < found; c++) {
                if (nodus_key_cmp(&closest[c].node_id, &srv->identity.node_id) != 0) {
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
            if (!srv->bf_state.batches[i].active) { bi = i; break; }
        }
        dht_bf_batch_t *b = (bi >= 0) ? &srv->bf_state.batches[bi] : NULL;
        if (!b || nodus_server_bf_batch_setup(b, msg->batch_keys, n) != 0) {
            /* No slot / alloc failure — local-only results; the misses
             * that had a peer are "u" (S6). */
            QGP_LOG_WARN(LOG_TAG, "GET_BATCH: txn=%u %s — %d miss(es) not forwarded",
                         (unsigned)msg->txn_id, b ? "forward alloc failed" : "no BF slot",
                         miss_count);
            goto send_response;
        }

        /* Set up batch context — the keysets move into the batch */
        b->txn_id = msg->txn_id;
        b->session_slot = (int)(sess - srv->sessions);
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

            if (bf_start_forward(srv, b, g, &groups[g].peer,
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
            bf_send_result(srv, b);
        return;
    }

send_response:
    {
        int verify_left = NODUS_DHT_VERIFY_CAP;
        uint8_t *buf = malloc(RESP_BUF_SIZE);
        size_t len = 0;
        if (!buf) {
            for (int i = 0; i < n; i++) nodus_dht_keyset_clear(&sets[i]);
            dht_send_unavailable(sess->conn, msg->txn_id, "reply alloc failed");
        } else {
            if (dht_encode_batch_reply(msg->txn_id, msg->batch_keys, n, sets,
                                       &verify_left, buf, RESP_BUF_SIZE, &len) == 0)
                nodus_tcp_send(sess->conn, buf, len);
            free(buf);
        }
        free(sets);
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

/* ── Circuit handlers (VPN mesh Faz 1) ────────────────────────────── */

static void handle_t2_circ_open(nodus_server_t *srv, nodus_session_t *sess,
                                 nodus_tier2_msg_t *msg) {
    uint8_t resp[256];
    size_t rlen = 0;

    /* Rev 2 item 8: the client chooses the cid of the circuits it opens,
     * this server generates the cid of the circuits opened TO it (inbound,
     * nodus_circuit_alloc → next_cid_gen) — both live in sess->circuits.
     * Policy: BUMP the generator past a client cid, do not refuse it. The
     * client SDK counts from 1 per process and does not reset on reconnect
     * (nodus_client.c next_client_cid) while a new session's generator
     * restarts at 1, so an honest client's cid is routinely >= the
     * generator; refusing it would break every circuit after a reconnect.
     * After the bump no generated cid can equal a live client cid (the
     * generator only grows past it), and a client cid below the generator
     * that is in use is refused just below. cid 0 (reserved) and cids
     * >= 2^63 (a generator bumped there could wrap) are refused — no
     * honest counter reaches them. */
    if (msg->circ_cid == 0 || msg->circ_cid >= (UINT64_C(1) << 63)) {
        nodus_t2_circ_open_err(msg->txn_id, msg->circ_cid, NODUS_ERR_PROTOCOL_ERROR,
                                resp, sizeof(resp), &rlen);
        nodus_tcp_send(sess->conn, resp, rlen);
        return;
    }

    /* Reject if originator would collide with existing cid in this session */
    if (nodus_circuit_lookup(&sess->circuits, msg->circ_cid) != NULL) {
        nodus_t2_circ_open_err(msg->txn_id, msg->circ_cid, NODUS_ERR_CIRCUIT_LIMIT,
                                resp, sizeof(resp), &rlen);
        nodus_tcp_send(sess->conn, resp, rlen);
        return;
    }
    if (msg->circ_cid >= sess->circuits.next_cid_gen)
        sess->circuits.next_cid_gen = msg->circ_cid + 1;

    /* Check circuit capacity on originator side */
    if (nodus_circuit_count(&sess->circuits) >= NODUS_MAX_CIRCUITS_PER_SESSION) {
        nodus_t2_circ_open_err(msg->txn_id, msg->circ_cid, NODUS_ERR_CIRCUIT_LIMIT,
                                resp, sizeof(resp), &rlen);
        nodus_tcp_send(sess->conn, resp, rlen);
        return;
    }

    /* Presence lookup */
    uint8_t peer_idx = 0;
    bool online = nodus_presence_is_online(srv, &msg->circ_peer_fp, &peer_idx);
    if (!online) {
        nodus_t2_circ_open_err(msg->txn_id, msg->circ_cid, NODUS_ERR_PEER_OFFLINE,
                                resp, sizeof(resp), &rlen);
        nodus_tcp_send(sess->conn, resp, rlen);
        return;
    }

    if (peer_idx != 0) {
        /* Cross-nodus — find peer nodus by peer_idx (IP-hash reverse lookup) */
        nodus_cluster_peer_t *peer_node = find_cluster_peer_by_idx(srv, peer_idx);
        if (!peer_node) {
            nodus_t2_circ_open_err(msg->txn_id, msg->circ_cid, NODUS_ERR_PEER_OFFLINE,
                                    resp, sizeof(resp), &rlen);
            nodus_tcp_send(sess->conn, resp, rlen);
            return;
        }

        /* Check inter-circuit capacity */
        if (nodus_inter_circuit_count(&srv->inter_circuits) >= NODUS_INTER_CIRCUITS_MAX) {
            nodus_t2_circ_open_err(msg->txn_id, msg->circ_cid, NODUS_ERR_CIRCUIT_LIMIT,
                                    resp, sizeof(resp), &rlen);
            nodus_tcp_send(sess->conn, resp, rlen);
            return;
        }

        /* Allocate circuit on originator's session; overwrite with client-provided cid */
        nodus_circuit_t *c = nodus_circuit_alloc(&sess->circuits);
        if (!c) {
            nodus_t2_circ_open_err(msg->txn_id, msg->circ_cid, NODUS_ERR_CIRCUIT_LIMIT,
                                    resp, sizeof(resp), &rlen);
            nodus_tcp_send(sess->conn, resp, rlen);
            return;
        }
        c->local_cid = msg->circ_cid;

        /* Allocate global inter-circuit entry */
        nodus_inter_circuit_t *ic = nodus_inter_circuit_alloc(&srv->inter_circuits);
        if (!ic) {
            nodus_circuit_free(&sess->circuits, c->local_cid);
            nodus_t2_circ_open_err(msg->txn_id, msg->circ_cid, NODUS_ERR_CIRCUIT_LIMIT,
                                    resp, sizeof(resp), &rlen);
            nodus_tcp_send(sess->conn, resp, rlen);
            return;
        }

        /* Open or reuse inter-node TCP 4002 connection to peer nodus */
        nodus_tcp_conn_t *pconn = nodus_tcp_find_by_addr(
            (nodus_tcp_t *)&srv->inter_tcp, peer_node->ip, peer_node->tcp_port);
        if (!pconn) {
            pconn = nodus_tcp_connect(
                (nodus_tcp_t *)&srv->inter_tcp, peer_node->ip, peer_node->tcp_port);
            if (pconn) pconn->is_nodus = true;
        }
        if (!pconn) {
            nodus_inter_circuit_free(&srv->inter_circuits, ic->our_cid);
            nodus_circuit_free(&sess->circuits, c->local_cid);
            nodus_t2_circ_open_err(msg->txn_id, msg->circ_cid, NODUS_ERR_INTERNAL_ERROR,
                                    resp, sizeof(resp), &rlen);
            nodus_tcp_send(sess->conn, resp, rlen);
            return;
        }

        /* Link inter entry <-> local session circuit */
        ic->peer_conn = pconn;
        ic->local_sess = (struct nodus_session *)sess;
        ic->local_cid = c->local_cid;
        ic->is_originator = true;
        ic->pending_open = true;
        ic->client_txn_id = msg->txn_id;
        ic->created_at_ms = nodus_time_now_ms();
        c->is_local_bridge = false;
        c->inter = ic;

        /* Send ri_open to peer nodus (pass e2e_ct opaquely for onion layer) */
        uint8_t obuf[2048]; size_t olen = 0;
        int ri_rc;
        if (msg->has_e2e_ct) {
            /* Faz 1 KEM migration: propagate the originator's e2e_alg
             * opaquely — this server never decapsulates "ect", only relays
             * it and the algorithm tag it was encapsulated under. */
            ri_rc = nodus_t2_ri_open_e2e(msg->txn_id, ic->our_cid, &sess->client_fp,
                                          &msg->circ_peer_fp, msg->e2e_ct, msg->e2e_alg,
                                          obuf, sizeof(obuf), &olen);
        } else {
            ri_rc = nodus_t2_ri_open(msg->txn_id, ic->our_cid, &sess->client_fp,
                                      &msg->circ_peer_fp, obuf, sizeof(obuf), &olen);
        }
        if (ri_rc != 0) {
            nodus_inter_circuit_free(&srv->inter_circuits, ic->our_cid);
            nodus_circuit_free(&sess->circuits, c->local_cid);
            nodus_t2_circ_open_err(msg->txn_id, msg->circ_cid, NODUS_ERR_INTERNAL_ERROR,
                                    resp, sizeof(resp), &rlen);
            nodus_tcp_send(sess->conn, resp, rlen);
            return;
        }
        nodus_tcp_send(pconn, obuf, olen);
        /* Do NOT reply to client yet — wait for ri_open_ok/err */
        return;
    }

    /* Local bridge case — find peer session */
    nodus_session_t *peer_sess = find_session_by_fp(srv, &msg->circ_peer_fp);
    if (!peer_sess) {
        nodus_t2_circ_open_err(msg->txn_id, msg->circ_cid, NODUS_ERR_PEER_OFFLINE,
                                resp, sizeof(resp), &rlen);
        nodus_tcp_send(sess->conn, resp, rlen);
        return;
    }
    if (nodus_circuit_count(&peer_sess->circuits) >= NODUS_MAX_CIRCUITS_PER_SESSION) {
        nodus_t2_circ_open_err(msg->txn_id, msg->circ_cid, NODUS_ERR_CIRCUIT_LIMIT,
                                resp, sizeof(resp), &rlen);
        nodus_tcp_send(sess->conn, resp, rlen);
        return;
    }

    nodus_circuit_t *c_src = nodus_circuit_alloc(&sess->circuits);
    nodus_circuit_t *c_dst = nodus_circuit_alloc(&peer_sess->circuits);
    if (!c_src || !c_dst) {
        if (c_src) nodus_circuit_free(&sess->circuits, c_src->local_cid);
        if (c_dst) nodus_circuit_free(&peer_sess->circuits, c_dst->local_cid);
        nodus_t2_circ_open_err(msg->txn_id, msg->circ_cid, NODUS_ERR_INTERNAL_ERROR,
                                resp, sizeof(resp), &rlen);
        nodus_tcp_send(sess->conn, resp, rlen);
        return;
    }

    /* Originator side: override auto-generated cid with client-provided cid
     * so future circ_data(C1) from originator is looked up by C1. */
    c_src->local_cid = msg->circ_cid;

    /* Link both sides */
    c_src->is_local_bridge = true;
    c_src->bridge_peer_sess = (struct nodus_session *)peer_sess;
    c_src->bridge_peer_cid = c_dst->local_cid;

    c_dst->is_local_bridge = true;
    c_dst->bridge_peer_sess = (struct nodus_session *)sess;
    c_dst->bridge_peer_cid = c_src->local_cid;

    /* Reply to originator: echo their cid */
    nodus_t2_circ_open_ok(msg->txn_id, msg->circ_cid, resp, sizeof(resp), &rlen);
    nodus_tcp_send(sess->conn, resp, rlen);

    /* Push circ_inbound to target with server-assigned cid for target's side.
     * Pass e2e_ct opaquely (onion layer — server cannot decrypt). */
    uint8_t ibuf[2048];
    size_t ilen = 0;
    if (msg->has_e2e_ct) {
        /* Faz 1 KEM migration: propagate e2e_alg opaquely, see the
         * ri_open_e2e comment above. */
        nodus_t2_circ_inbound_e2e(0, c_dst->local_cid, &sess->client_fp,
                                   msg->e2e_ct, msg->e2e_alg, ibuf, sizeof(ibuf), &ilen);
    } else {
        nodus_t2_circ_inbound(0, c_dst->local_cid, &sess->client_fp,
                               ibuf, sizeof(ibuf), &ilen);
    }
    nodus_tcp_send(peer_sess->conn, ibuf, ilen);
}

static void handle_t2_circ_data(nodus_server_t *srv, nodus_session_t *sess,
                                 nodus_tier2_msg_t *msg) {
    (void)srv;
    nodus_circuit_t *c = nodus_circuit_lookup(&sess->circuits, msg->circ_cid);
    if (!c) {
        /* Unknown cid — silently drop */
        return;
    }
    if (c->is_local_bridge && c->bridge_peer_sess) {
        nodus_session_t *peer = (nodus_session_t *)c->bridge_peer_sess;
        if (!peer->conn) return;
        size_t cap = msg->circ_data_len + 256;
        uint8_t *buf = malloc(cap);
        if (!buf) return;
        size_t blen = 0;
        if (nodus_t2_circ_data(0, peer->token, c->bridge_peer_cid,
                                msg->circ_data, msg->circ_data_len,
                                buf, cap, &blen) == 0) {
            nodus_tcp_send(peer->conn, buf, blen);
        }
        free(buf);
    } else if (c->inter && c->inter->peer_conn) {
        /* Cross-nodus — forward to peer nodus via ri_data */
        size_t cap = msg->circ_data_len + 256;
        uint8_t *buf = malloc(cap);
        if (!buf) return;
        size_t blen = 0;
        if (nodus_t2_ri_data(0, c->inter->peer_cid,
                              msg->circ_data, msg->circ_data_len,
                              buf, cap, &blen) == 0) {
            nodus_tcp_send(c->inter->peer_conn, buf, blen);
        }
        free(buf);
    }
}

static void handle_t2_circ_close(nodus_server_t *srv, nodus_session_t *sess,
                                  nodus_tier2_msg_t *msg) {
    nodus_circuit_t *c = nodus_circuit_lookup(&sess->circuits, msg->circ_cid);
    if (!c) return;
    if (c->is_local_bridge && c->bridge_peer_sess) {
        nodus_session_t *peer = (nodus_session_t *)c->bridge_peer_sess;
        uint64_t peer_cid = c->bridge_peer_cid;
        if (peer->conn) {
            uint8_t buf[256];
            size_t blen = 0;
            if (nodus_t2_circ_close(0, peer->token, peer_cid,
                                     buf, sizeof(buf), &blen) == 0) {
                nodus_tcp_send(peer->conn, buf, blen);
            }
        }
        nodus_circuit_free(&peer->circuits, peer_cid);
    } else if (c->inter) {
        /* Cross-nodus — propagate ri_close to peer nodus, free inter entry */
        if (c->inter->peer_conn) {
            uint8_t buf[256]; size_t blen = 0;
            if (nodus_t2_ri_close(0, c->inter->peer_cid,
                                   buf, sizeof(buf), &blen) == 0) {
                nodus_tcp_send(c->inter->peer_conn, buf, blen);
            }
        }
        nodus_inter_circuit_free(&srv->inter_circuits, c->inter->our_cid);
    }
    circuit_free_entry(&sess->circuits, c);   /* the entry looked up above */
}

/* ── Inter-node ri_* handlers (VPN mesh Faz 1) ────────────────────── */

static void handle_inter_ri_open(nodus_server_t *srv, nodus_inter_session_t *sess,
                                  nodus_tier2_msg_t *msg) {
    uint8_t resp[256]; size_t rlen = 0;

    /* Validate dst is locally connected */
    uint8_t peer_idx = 0;
    bool online = nodus_presence_is_online(srv, &msg->ri_dst_fp, &peer_idx);
    if (!online || peer_idx != 0) {
        nodus_t2_ri_open_err(msg->txn_id, msg->ri_ups_cid, NODUS_ERR_PEER_OFFLINE,
                              resp, sizeof(resp), &rlen);
        nodus_tcp_send(sess->conn, resp, rlen);
        return;
    }

    nodus_session_t *target = find_session_by_fp(srv, &msg->ri_dst_fp);
    if (!target) {
        nodus_t2_ri_open_err(msg->txn_id, msg->ri_ups_cid, NODUS_ERR_PEER_OFFLINE,
                              resp, sizeof(resp), &rlen);
        nodus_tcp_send(sess->conn, resp, rlen);
        return;
    }
    if (nodus_circuit_count(&target->circuits) >= NODUS_MAX_CIRCUITS_PER_SESSION) {
        nodus_t2_ri_open_err(msg->txn_id, msg->ri_ups_cid, NODUS_ERR_CIRCUIT_LIMIT,
                              resp, sizeof(resp), &rlen);
        nodus_tcp_send(sess->conn, resp, rlen);
        return;
    }

    /* Allocate global inter-circuit entry */
    nodus_inter_circuit_t *ic = nodus_inter_circuit_alloc(&srv->inter_circuits);
    if (!ic) {
        nodus_t2_ri_open_err(msg->txn_id, msg->ri_ups_cid, NODUS_ERR_INTERNAL_ERROR,
                              resp, sizeof(resp), &rlen);
        nodus_tcp_send(sess->conn, resp, rlen);
        return;
    }
    /* Allocate circuit on target user's session */
    nodus_circuit_t *c = nodus_circuit_alloc(&target->circuits);
    if (!c) {
        nodus_inter_circuit_free(&srv->inter_circuits, ic->our_cid);
        nodus_t2_ri_open_err(msg->txn_id, msg->ri_ups_cid, NODUS_ERR_CIRCUIT_LIMIT,
                              resp, sizeof(resp), &rlen);
        nodus_tcp_send(sess->conn, resp, rlen);
        return;
    }

    /* Link inter entry */
    ic->peer_cid = msg->ri_ups_cid;
    ic->peer_conn = sess->conn;
    ic->local_sess = (struct nodus_session *)target;
    ic->local_cid = c->local_cid;
    ic->is_originator = false;

    /* Link target's session circuit to inter entry */
    c->is_local_bridge = false;
    c->inter = ic;

    /* Reply ri_open_ok */
    nodus_t2_ri_open_ok(msg->txn_id, msg->ri_ups_cid, ic->our_cid,
                         resp, sizeof(resp), &rlen);
    nodus_tcp_send(sess->conn, resp, rlen);

    /* Push circ_inbound to target user (pass e2e_ct opaquely for onion layer) */
    uint8_t ibuf[2048]; size_t ilen = 0;
    if (msg->has_e2e_ct) {
        /* Faz 1 KEM migration: propagate e2e_alg, see the ri_open_e2e
         * comment in handle_t2_circ_open() above. */
        nodus_t2_circ_inbound_e2e(0, c->local_cid, &msg->ri_src_fp,
                                   msg->e2e_ct, msg->e2e_alg, ibuf, sizeof(ibuf), &ilen);
    } else {
        nodus_t2_circ_inbound(0, c->local_cid, &msg->ri_src_fp, ibuf, sizeof(ibuf), &ilen);
    }
    nodus_tcp_send(target->conn, ibuf, ilen);
}

/* F1b: a ri_* frame may only address a circuit routed over the conn it
 * arrived on. Circuit ids are sequential, so without this any peer on
 * 4002 could open/feed/close another link's circuit by guessing its id. */
static nodus_inter_circuit_t *inter_circuit_for_peer(nodus_server_t *srv,
                                                     nodus_inter_session_t *sess,
                                                     uint64_t our_cid) {
    nodus_inter_circuit_t *ic = nodus_inter_circuit_lookup(&srv->inter_circuits, our_cid);
    if (!ic || !sess || !sess->conn || ic->peer_conn != sess->conn) return NULL;
    return ic;
}

static void handle_inter_ri_open_ok(nodus_server_t *srv, nodus_inter_session_t *sess,
                                     nodus_tier2_msg_t *msg) {
    nodus_inter_circuit_t *ic = inter_circuit_for_peer(srv, sess, msg->ri_ups_cid);
    if (!ic || !ic->is_originator || !ic->pending_open || !ic->local_sess) return;
    ic->peer_cid = msg->ri_dns_cid;
    ic->pending_open = false;

    nodus_session_t *client = (nodus_session_t *)ic->local_sess;
    if (!client->conn) return;
    uint8_t buf[256]; size_t blen = 0;
    if (nodus_t2_circ_open_ok(ic->client_txn_id, ic->local_cid,
                                buf, sizeof(buf), &blen) == 0) {
        nodus_tcp_send(client->conn, buf, blen);
    }
}

static void handle_inter_ri_open_err(nodus_server_t *srv, nodus_inter_session_t *sess,
                                      nodus_tier2_msg_t *msg) {
    nodus_inter_circuit_t *ic = inter_circuit_for_peer(srv, sess, msg->ri_ups_cid);
    if (!ic || !ic->is_originator || !ic->local_sess) return;

    /* Item 8: tell the client (circ_open_err with the peer's code while the
     * open is pending, else circ_close), free ITS circuit by pointer, then
     * the inter entry. */
    inter_circuit_release(srv, ic, msg->ri_err_code);
}

static void handle_inter_ri_data(nodus_server_t *srv, nodus_inter_session_t *sess,
                                  nodus_tier2_msg_t *msg) {
    nodus_inter_circuit_t *ic = inter_circuit_for_peer(srv, sess, msg->ri_cid);
    if (!ic || !ic->local_sess) return;  /* Drop silently */

    nodus_session_t *target = (nodus_session_t *)ic->local_sess;
    if (!target->conn) return;
    /* Forward payload to local user via circ_data push */
    size_t cap = msg->ri_data_len + 256;
    uint8_t *buf = malloc(cap);
    if (!buf) return;
    size_t blen = 0;
    if (nodus_t2_circ_data(0, target->token, ic->local_cid,
                            msg->ri_data, msg->ri_data_len,
                            buf, cap, &blen) == 0) {
        nodus_tcp_send(target->conn, buf, blen);
    }
    free(buf);
}

static void handle_inter_ri_close(nodus_server_t *srv, nodus_inter_session_t *sess,
                                   nodus_tier2_msg_t *msg) {
    nodus_inter_circuit_t *ic = inter_circuit_for_peer(srv, sess, msg->ri_cid);
    if (!ic) return;

    /* Item 8: propagate the close to the local user (circ_open_err while an
     * originated open is still pending, else circ_close), free its circuit
     * by pointer identity, then the inter entry. */
    inter_circuit_release(srv, ic, NODUS_ERR_CIRCUIT_CLOSED);
}

/**
 * Completion callback for listen forwarding iterative lookup.
 * Sends T1 "sub" frames to the K-closest nodes so they remember to
 * forward NOTIFY messages back to us when a PUT matches.
 *
 * user_data is a heap-allocated nodus_key_t (the listen key),
 * freed here or via cb_data_free on abandonment (see iterative_lookup_start).
 */
static void listen_fwd_complete(nodus_server_t *srv,
                                 nodus_peer_t *closest, int count,
                                 void *user_data) {
    nodus_key_t *key = (nodus_key_t *)user_data;
    if (!srv || !key) { free(key); return; }

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
        if (nodus_key_cmp(&closest[i].node_id, &srv->identity.node_id) == 0) continue;
        if (dht_republish_send(srv, closest[i].ip, closest[i].tcp_port,
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

    /* Forward subscription to the key's responsible nodes so that remote
     * PUTs will generate NOTIFY messages back to us (Scribe pattern). */
    nodus_key_t *key_copy = malloc(sizeof(nodus_key_t));
    if (!key_copy) return;
    *key_copy = msg->key;

    if (iterative_lookup_start(srv, &msg->key, -1, 0,
                                listen_fwd_complete, key_copy, free) != 0) {
        /* No lookup slots available — synchronous fallback via routing table */
        nodus_peer_t closest[NODUS_R];
        int count = nodus_routing_find_closest(&srv->routing, &msg->key,
                                                 closest, NODUS_R);
        listen_fwd_complete(srv, closest, count, key_copy);
    }
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

/* Cluster-status query handler (Phase 0 / Task 0.2).
 * Reports this nodus-server's own block_height, state_root, chain_id,
 * peer count, uptime and wall clock. All fields are public and
 * authenticated only by the existing tier2 session token. */
static void handle_t2_status(nodus_server_t *srv, nodus_session_t *sess,
                              nodus_tier2_msg_t *msg) {
    nodus_t2_status_info_t info;
    memset(&info, 0, sizeof(info));

    if (srv->witness && srv->witness->db) {
        info.block_height = nodus_witness_block_height(srv->witness);
        if (srv->witness->v2_successor) {
            /* R3 W4 package H: on a version-3 chain the legacy cached
             * state root is never written (the Comet apply lane keeps
             * no `blocks` row), so the column was EMPTY while HEIGHT
             * already reported the `v2_blocks` tip. Report the committed
             * GLOBAL ROOT of that tip instead — the row the engine wrote
             * (`nodus_witness_v2_committed_global_root`: the authority is
             * the stored `v2_blocks.global_root`, never a recompute), the
             * same quantity `stagef_cmt_diff_at_floor` compares across
             * nodes. A chain with no committed row yet leaves it zero. */
            if (nodus_witness_v2_committed_global_root(srv->witness,
                                                       info.state_root) != 0) {
                memset(info.state_root, 0, sizeof(info.state_root));
            }
        }
        /* Root-layout round (K3): the legacy `else` branch that copied
         * `cached_state_root` is deleted with that field (it had no
         * writer); a non-successor witness reports the zeroed
         * state_root from the memset above, as it already did. */
        memcpy(info.chain_id, srv->witness->chain_id, 32);
    }

    /* Inter-node TCP peer connection count = "cluster peers we currently
     * have a TCP socket open to". */
    int connected = 0;
    for (int i = 0; i < srv->cluster.peer_count; i++) {
        if (srv->cluster.peers[i].state == NODUS_NODE_ALIVE) connected++;
    }
    info.peer_count = (uint32_t)connected;

    uint64_t now = (uint64_t)time(NULL);
    info.uptime_sec = srv->start_time ? (now - srv->start_time) : 0;
    info.wall_clock = now;

    /* disk_free_pct via statvfs on the configured data path. 255 means
     * unknown (no data path or statvfs error). Phase 0 / Task 0.12. */
    info.disk_free_pct = 255;
    if (srv->config.data_path[0]) {
        struct statvfs sv;
        if (statvfs(srv->config.data_path, &sv) == 0 && sv.f_blocks > 0) {
            uint64_t avail = (uint64_t)sv.f_bavail * sv.f_frsize;
            uint64_t total = (uint64_t)sv.f_blocks * sv.f_frsize;
            if (total > 0) {
                info.disk_free_pct = (uint8_t)((avail * 100) / total);
            }
        }
    }

    size_t len = 0;
    nodus_t2_status_result(msg->txn_id, &info,
                            resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);
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
        /* Include first 16 bytes of our Dilithium fingerprint */
        memcpy(infos[count].dil_fp, srv->identity.node_id.bytes, 16);
        infos[count].has_dil_fp = true;
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
#define IDLE_TIMEOUT_AUTH    180   /* seconds for authenticated connections (client pings every 60s) */
#define IDLE_TIMEOUT_UNAUTH   15   /* seconds for unauthenticated connections */
#define IDLE_ABSOLUTE_UNAUTH  30   /* absolute bound from connected_at while unauthenticated:
                                    * a slow trickle resets last_activity but not this */

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
        bool abs_expired = !authed &&
                           now - c->connected_at > IDLE_ABSOLUTE_UNAUTH;
        if (idle > timeout || abs_expired) {
            char fp_hex[33] = {0};
            if (authed)
                for (int j = 0; j < 16; j++)
                    snprintf(fp_hex + j*2, sizeof(fp_hex) - j*2, "%02x", srv->sessions[c->slot].client_fp.bytes[j]);
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

    /* Auth timeout: connections stuck in HELLO_SENT for >10s */
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = srv->inter_tcp.pool[i];
        if (!c || c->auth_state != NODUS_CONN_AUTH_HELLO_SENT) continue;
        if (now - c->connected_at > 10) {
            fprintf(stderr, "INTER_AUTH: auth timeout for %s:%d, disconnecting\n",
                    c->ip, c->port);
            c->auth_state = NODUS_CONN_AUTH_FAILED;
            nodus_tcp_disconnect(&srv->inter_tcp, c);
        }
    }

    /* Witness TCP uses T3 w_ident auth — not covered by this sweep. */

    /* Sweep orphaned pending_open inter-circuits (peer nodus never responded).
     * 10s matches NODUS_CIRCUIT_OPEN_TIMEOUT_MS with margin for scheduling.
     * F1: the server-side sweep also unlinks the client circuit (the
     * circuit module cannot see the session layout). */
    nodus_server_inter_sweep_orphans(srv, nodus_time_now_ms(), 10000);
}

/* Faz 1 KEM migration (docs/plans/decisions/2026-09-23-kem-mlkem-
 * migration.md): sign this identity's ML-KEM-1024 pubkey under MLKEM_BIND
 * (N2) — nodus_sign_mlkem_bind() routes through the SAME nodus_sign_tagged()
 * engine kpk_sig uses, but MLKEM_BIND is in the strict set
 * (nodus_sign_purpose_is_strict(), N1 delta 1 D2) so it always signs the
 * NDS1-tagged preimage, never raw — unlike kpk_sig/KYBER_BIND, whose
 * (kyber_pk || nonce) preimage has the same length/shape and would
 * otherwise be swappable with this one. Returns false (leaves
 * *mpk_sig_out untouched) when the identity has no ML-KEM keypair yet, or
 * signing fails — callers then omit mpk from the AUTH_OK they send,
 * falling back to Kyber-only exactly as before this migration. Used by
 * the nodus_t2_auth_ok_kyber sender in dispatch_inter below (the second
 * one, the 4004 T2 auth handler, is deleted with that path, P2P-PORT
 * F5) — nodus_auth.c's client-facing
 * sender (port 4001) has its own copy since it lives in a different
 * translation unit. */
static bool sign_mlkem_bind_for_auth_ok(const nodus_identity_t *identity,
                                          const uint8_t *nonce,
                                          nodus_sig_t *mpk_sig_out) {
    if (!identity->has_mlkem) return false;
    uint8_t sign_data[NODUS_MLKEM_PK_BYTES + NODUS_NONCE_LEN];
    memcpy(sign_data, identity->mlkem_pk, NODUS_MLKEM_PK_BYTES);
    memcpy(sign_data + NODUS_MLKEM_PK_BYTES, nonce, NODUS_NONCE_LEN);
    return nodus_sign_mlkem_bind(mpk_sig_out, sign_data, sizeof(sign_data),
                                  &identity->sk) == 0;
}

/* ── Inter-node frame dispatch (peer port) ──────────────────────── */

/* F3: peer auth is required and this node can encrypt, but the session
 * key of this conn does not exist yet. */
static bool inter_pre_established(const nodus_server_t *srv,
                                  const nodus_inter_session_t *sess) {
    return srv->config.require_peer_auth && srv->identity.has_kyber &&
           !(sess->conn && sess->conn->channel_crypto.established);
}

/* F3: the frames a 4002 handshake consists of (either role). */
static bool inter_handshake_method(const char *method) {
    return strcmp(method, "hello") == 0 || strcmp(method, "challenge") == 0 ||
           strcmp(method, "auth") == 0 || strcmp(method, "auth_ok") == 0 ||
           strcmp(method, "key_init") == 0 || strcmp(method, "key_ack") == 0 ||
           strcmp(method, "error") == 0;
}

/* Rev 2 item 7: which side of a 4002 conn may RECEIVE a handshake frame.
 * The dialing side (conn->auth_initiated_by_us) sends hello / auth /
 * key_init and receives challenge / auth_ok / key_ack; the accepting side
 * the reverse. "error" is valid on both. */
typedef enum {
    INTER_HS_NONE = 0,     /* not a handshake frame */
    INTER_HS_TO_DIALER,    /* challenge, auth_ok, key_ack */
    INTER_HS_TO_ACCEPTOR,  /* hello, auth, key_init */
    INTER_HS_EITHER        /* error */
} inter_hs_role_t;

static inter_hs_role_t inter_handshake_role(const char *method) {
    if (strcmp(method, "challenge") == 0 || strcmp(method, "auth_ok") == 0 ||
        strcmp(method, "key_ack") == 0)
        return INTER_HS_TO_DIALER;
    if (strcmp(method, "hello") == 0 || strcmp(method, "auth") == 0 ||
        strcmp(method, "key_init") == 0)
        return INTER_HS_TO_ACCEPTOR;
    if (strcmp(method, "error") == 0)
        return INTER_HS_EITHER;
    return INTER_HS_NONE;
}

static void dispatch_inter(nodus_server_t *srv, nodus_inter_session_t *sess,
                            const uint8_t *payload, size_t len) {
    /* DBG: trace dispatch entries on encrypted conns (v0.18.1) */
    if (sess->conn && sess->conn->channel_crypto.established) {
        fprintf(stderr, "DBG_DISP_ENC: slot=%d peer=%s:%u len=%zu\n",
                sess->conn->slot, sess->conn->ip,
                (unsigned)sess->conn->port, len);
    }

    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    /* C-01: Dilithium5 authentication on inter-node port.
     * Pre-auth: only hello and auth messages allowed.
     * Enforcement controlled by require_peer_auth config flag. */
    if (nodus_t2_decode(payload, len, &msg) == 0) {
        /* Phase 3.2c: log every t2 method received per (slot, method)
         * one-shot. Tells us which handshake messages are actually arriving
         * vs missing on each conn. Bits: 0=hello 1=challenge 2=auth
         * 3=auth_ok 4=key_init 5=key_ack. */
        if (sess->conn) {
            int bit = -1;
            if      (strcmp(msg.method, "hello")     == 0) bit = 0;
            else if (strcmp(msg.method, "challenge") == 0) bit = 1;
            else if (strcmp(msg.method, "auth")      == 0) bit = 2;
            else if (strcmp(msg.method, "auth_ok")   == 0) bit = 3;
            else if (strcmp(msg.method, "key_init")  == 0) bit = 4;
            else if (strcmp(msg.method, "key_ack")   == 0) bit = 5;
            if (bit >= 0 && !(sess->conn->dispatch_logged_mask & (1u << bit))) {
                sess->conn->dispatch_logged_mask |= (1u << bit);
                fprintf(stderr,
                        "INTER_DISPATCH: slot=%d peer=%s:%u method=%s "
                        "auth_state=%d authed=%d has_crypto=%d\n",
                        sess->conn->slot, sess->conn->ip,
                        (unsigned)sess->conn->port, msg.method,
                        (int)sess->conn->auth_state,
                        sess->conn->authenticated ? 1 : 0,
                        sess->conn->channel_crypto.established ? 1 : 0);
            }
        }

        /* Rev 2 item 7: role split. A handshake frame that only the OTHER
         * side of this conn may receive (an inbound peer sending auth_ok /
         * challenge / key_ack, or the node we dialed sending hello / auth /
         * key_init) is a protocol violation: log and disconnect. Applies
         * whatever require_peer_auth says — before this, an inbound
         * "auth_ok" marked the session authenticated. No honest peer sends
         * one: the dialer's on_inter_connect sends hello and its handlers
         * answer challenge → auth, auth_ok → key_init; the acceptor answers
         * hello → challenge, auth → auth_ok, key_init → key_ack; the batch-
         * forward dialer (bf_handle_event) speaks the dialer's side. */
        if (sess->conn) {
            inter_hs_role_t role = inter_handshake_role(msg.method);
            bool dialer = sess->conn->auth_initiated_by_us;
            if ((role == INTER_HS_TO_DIALER && !dialer) ||
                (role == INTER_HS_TO_ACCEPTOR && dialer)) {
                nodus_tcp_conn_t *bad = sess->conn;
                QGP_LOG_WARN(LOG_TAG, "INTER_ROLE: slot=%d peer=%s:%u sent %s on a "
                             "conn %s — disconnecting",
                             bad->slot, bad->ip, (unsigned)bad->port, msg.method,
                             dialer ? "we dialed" : "we accepted");
                nodus_t2_msg_free(&msg);
                bad->auth_state = NODUS_CONN_AUTH_FAILED;
                /* on_inter_disconnect clears *sess: nothing below may touch it. */
                nodus_tcp_disconnect(&srv->inter_tcp, bad);
                return;
            }
        }

        /* F3 (DHT Package A): role-neutral pre-established gate. While this
         * node requires peer auth and can encrypt (has_kyber) but the
         * session key does not exist yet, only the handshake frames are
         * processed — on BOTH sides: the accepting side between auth and
         * key_init, the dialing side between auth_ok and key_ack. The
         * no-Kyber branch (auth_ok below) never sets `established`; this
         * gate is off for it (has_kyber false). */
        if (inter_pre_established(srv, sess) &&
            !inter_handshake_method(msg.method)) {
            fprintf(stderr,
                    "INTER_GATE: slot=%d peer=%s:%u method=%s before session key "
                    "— dropped (F3)\n",
                    sess->conn ? sess->conn->slot : -1,
                    sess->conn ? sess->conn->ip : "?",
                    sess->conn ? (unsigned)sess->conn->port : 0, msg.method);
            nodus_t2_msg_free(&msg);
            return;
        }

        /* Handle auth RESPONSES for outgoing inter-node connections (this
         * node opened the conn, sent hello, now receives challenge/auth_ok).
         * These must be handled regardless of require_peer_auth — they
         * complete auth initiated by us.
         *
         * C2 fix: enforce outbound-only gate — now the role split above: a
         * challenge on an inbound conn disconnects before this point, so
         * this node never signs a nonce an accepted peer chose (closes the
         * Dilithium5 oracle). One challenge per dialed conn: a repeated one
         * (the nonce is already retained) is not signed again. */
        if (strcmp(msg.method, "challenge") == 0) {
            if (sess->has_challenge_nonce || sess->authenticated) {
                QGP_LOG_WARN(LOG_TAG, "INTER: repeated challenge from %s:%u — "
                             "not signed, dropped",
                             sess->conn->ip, (unsigned)sess->conn->port);
                nodus_t2_msg_free(&msg);
                return;
            }
            nodus_sig_t sig;
            nodus_sign_auth_challenge(&sig, msg.nonce, &srv->identity.sk);
            /* CRIT-1: retain the challenge nonce — the peer signs
             * (kyber_pk || this nonce) as kpk_sig, so auth_ok cannot verify the
             * binding without it. Previously it was signed and discarded. */
            memcpy(sess->challenge_nonce, msg.nonce, NODUS_NONCE_LEN);
            sess->has_challenge_nonce = true;
            uint8_t buf[8192];
            size_t rlen = 0;
            nodus_t2_auth(msg.txn_id, &sig, buf, sizeof(buf), &rlen);
            nodus_tcp_send_raw(sess->conn, buf, rlen);
            nodus_t2_msg_free(&msg);
            return;
        } else if (strcmp(msg.method, "auth_ok") == 0) {
            /* Only on a conn we dialed (role split above), once: a repeated
             * auth_ok would start a second key exchange. */
            if (sess->authenticated || sess->pending_kyber) {
                QGP_LOG_WARN(LOG_TAG, "INTER: repeated auth_ok from %s:%u — dropped",
                             sess->conn->ip, (unsigned)sess->conn->port);
                nodus_t2_msg_free(&msg);
                return;
            }
            sess->conn->authenticated = true;
            sess->authenticated = true;

            /* Inter-node Kyber handshake (connecting side).
             * Keep auth gate CLOSED (auth_state != AUTH_OK) during handshake
             * so no plaintext frames leak through. Open after key_ack. */
            /* CRIT-1: authenticate the peer's Kyber public key BEFORE
             * encapsulating to it. Without this an active MITM on the plaintext
             * handshake substitutes its own self-consistent triple
             * (server_pk', kyber_pk', kpk_sig') and owns the channel key — which
             * makes every downstream nonce/AEAD property moot. Three gates, all
             * fail-closed:
             *   1. downgrade-close: if WE support Kyber, a missing kyber_pk /
             *      kpk_sig / server_pk is refused — never fall through to the
             *      plaintext branch (an attacker could otherwise just strip the
             *      field to force cleartext inter-node traffic).
             *   2. signature: kpk_sig must verify over (kyber_pk || the nonce we
             *      challenged with) under server_pk.
             *   3. identity pin: fingerprint(server_pk) must equal the node_id we
             *      believed we were dialing. Step 2 alone only proves the triple
             *      is SELF-consistent — the attacker signs its own key with its
             *      own identity and passes. The pin is what actually binds the
             *      channel to the intended peer; SHA3-512 preimage resistance
             *      means a MITM cannot produce a pk matching that fingerprint.
             * Trust note: the pin reference is the routing-table node_id
             * (trusted-discovery; adversarial UDP-4000 Kademlia injection is out
             * of scope per the threat model). */
            if (srv->identity.has_kyber) {
                bool bind_ok = false;

                if (!msg.has_kyber_pk || !msg.has_kpk_sig || !msg.has_server_pk) {
                    fprintf(stderr,
                            "INTER CRIT-1: auth_ok missing kyber_pk/kpk_sig/server_pk "
                            "from %s:%u — refusing (downgrade attempt?)\n",
                            sess->conn->ip, (unsigned)sess->conn->port);
                } else if (!sess->has_challenge_nonce) {
                    fprintf(stderr,
                            "INTER CRIT-1: no retained challenge nonce for %s:%u — "
                            "cannot verify kpk_sig, refusing\n",
                            sess->conn->ip, (unsigned)sess->conn->port);
                } else {
                    uint8_t sign_data[NODUS_KYBER_PK_BYTES + NODUS_NONCE_LEN];
                    memcpy(sign_data, msg.kyber_pk, NODUS_KYBER_PK_BYTES);
                    memcpy(sign_data + NODUS_KYBER_PK_BYTES,
                           sess->challenge_nonce, NODUS_NONCE_LEN);

                    if (nodus_verify_kyber_bind(&msg.kpk_sig, sign_data,
                                                 sizeof(sign_data),
                                                 &msg.server_pk) != 0) {
                        fprintf(stderr,
                                "INTER CRIT-1: kyber_pk signature INVALID from %s:%u "
                                "— possible MITM, refusing\n",
                                sess->conn->ip, (unsigned)sess->conn->port);
                    } else if (!sess->conn->expected_peer_id_set) {
                        fprintf(stderr,
                                "INTER CRIT-1: no expected peer identity for %s:%u "
                                "— cannot pin, refusing\n",
                                sess->conn->ip, (unsigned)sess->conn->port);
                    } else {
                        nodus_key_t actual_id;
                        if (nodus_fingerprint(&msg.server_pk, &actual_id) != 0) {
                            fprintf(stderr,
                                    "INTER CRIT-1: fingerprint() failed for %s:%u "
                                    "— refusing\n",
                                    sess->conn->ip, (unsigned)sess->conn->port);
                        } else if (nodus_key_cmp(&actual_id,
                                                 &sess->conn->expected_peer_id) != 0) {
                            /* Fail closed + alarm. Do NOT re-resolve the identity
                             * here: FIND_NODE data is unsigned, so adopting a
                             * fresh node_id at attack time would let the same
                             * adversary both trigger and answer the mismatch.
                             * Recovery is via authenticated discovery refresh. */
                            fprintf(stderr,
                                    "INTER CRIT-1: identity PIN MISMATCH at %s:%u — "
                                    "server_pk fingerprint != dialed node_id. "
                                    "Refusing (MITM or peer identity rotation).\n",
                                    sess->conn->ip, (unsigned)sess->conn->port);
                        } else {
                            bind_ok = true;
                            /* F4: the dialed peer's identity is now proven
                             * (signature + pin) — record it on the conn,
                             * like the accepting side does after auth, so
                             * pending-full hints key on a real identity. */
                            sess->conn->peer_id = actual_id;
                            sess->conn->peer_pk = msg.server_pk;
                            sess->conn->peer_id_set = true;
                        }
                    }
                }

                if (!bind_ok) {
                    sess->conn->auth_state = NODUS_CONN_AUTH_FAILED;
                    nodus_t2_msg_free(&msg);
                    nodus_tcp_disconnect(&srv->inter_tcp, sess->conn);
                    return;
                }

                /* Faz 1 KEM migration (docs/plans/decisions/2026-09-23-kem-
                 * mlkem-migration.md): if the peer ALSO advertised a signed
                 * ML-KEM-1024 pubkey, verify it under MLKEM_BIND against
                 * the SAME pinned server_pk (bind_ok above already proved
                 * it) and prefer it; otherwise fall back to the Kyber kpk
                 * exactly as today. */
                bool use_mlkem = false;
                if (msg.has_mlkem_pk && msg.has_mpk_sig) {
                    uint8_t msign_data[NODUS_MLKEM_PK_BYTES + NODUS_NONCE_LEN];
                    memcpy(msign_data, msg.mlkem_pk, NODUS_MLKEM_PK_BYTES);
                    memcpy(msign_data + NODUS_MLKEM_PK_BYTES,
                           sess->challenge_nonce, NODUS_NONCE_LEN);
                    if (nodus_verify_mlkem_bind(&msg.mpk_sig, msign_data, sizeof(msign_data),
                                                 &msg.server_pk) == 0) {
                        use_mlkem = true;
                    } else {
                        fprintf(stderr,
                                "INTER: mlkem_pk signature INVALID from %s:%u — "
                                "falling back to Kyber round-3\n",
                                sess->conn->ip, (unsigned)sess->conn->port);
                    }
                }

                uint8_t ct[NODUS_KYBER_CT_BYTES], ss_buf[NODUS_KYBER_SS_BYTES];
                uint8_t alg = use_mlkem ? 1 : 0;
                int enc_rc = use_mlkem
                    ? qgp_mlkem1024_encapsulate(ct, ss_buf, msg.mlkem_pk)
                    : qgp_kem1024_encapsulate(ct, ss_buf, msg.kyber_pk);
                if (enc_rc == 0) {
                    uint8_t nc[NODUS_NONCE_LEN];
                    nodus_random(nc, NODUS_NONCE_LEN);
                    uint8_t ki_buf[4096];
                    size_t ki_len = 0;
                    nodus_t2_key_init(msg.txn_id, ct, nc, alg, ki_buf, sizeof(ki_buf), &ki_len);
                    nodus_tcp_send_raw(sess->conn, ki_buf, ki_len);
                    /* Store shared secret + nonce for key_ack */
                    memcpy(sess->pending_ss, ss_buf, 32);
                    memcpy(sess->pending_nc, nc, 32);
                    sess->pending_kyber = true;
                }
                qgp_secure_memzero(ss_buf, sizeof(ss_buf));
            } else {
                /* This node has no Kyber identity — it cannot do channel
                 * encryption at all, so plaintext is the only option and is not
                 * an attacker-induced downgrade. */
                sess->conn->auth_state = NODUS_CONN_AUTH_OK;
                nodus_tcp_pending_flush(sess->conn);
            }

            nodus_t2_msg_free(&msg);
            return;
        } else if (strcmp(msg.method, "key_ack") == 0 && sess->pending_kyber) {
            /* Phase 3.2b-inv: KEY_ACK receive visibility */
            fprintf(stderr,
                    "CRYPTO: KEY_ACK_RX slot=%d peer=%s:%u has_nonce=%d sess=%p\n",
                    sess->conn ? sess->conn->slot : -1,
                    sess->conn ? sess->conn->ip : "?",
                    sess->conn ? (unsigned)sess->conn->port : 0,
                    msg.has_key_nonce ? 1 : 0, (void *)sess);
            /* Complete inter-node Kyber handshake.
             * B3 fix — init the per-conn channel_crypto directly; no
             * separate crypto-pointer alias needed. */
            if (msg.has_key_nonce) {
                /* We DIALED this peer (outgoing inter-node conn) → initiator. */
                nodus_channel_crypto_init(&sess->conn->channel_crypto,
                                           sess->pending_ss, sess->pending_nc, msg.key_nonce,
                                           NODUS_CHANNEL_ROLE_INITIATOR);
                fprintf(stderr,
                        "CRYPTO: SET_OUTGOING slot=%d peer=%s:%u (inter-node encrypted)\n",
                        sess->conn->slot, sess->conn->ip, (unsigned)sess->conn->port);
                qgp_secure_memzero(sess->pending_ss, sizeof(sess->pending_ss));
                qgp_secure_memzero(sess->pending_nc, sizeof(sess->pending_nc));
                sess->pending_kyber = false;
                /* Open auth gate. DISCARD pending queue — it contains
                 * pre-framed plaintext that would bypass encryption.
                 * Inter-node queued frames are periodic (heartbeat/repl)
                 * and will be re-sent on next cycle. */
                sess->conn->auth_state = NODUS_CONN_AUTH_OK;
                if (sess->conn->pending_buf) {
                    free(sess->conn->pending_buf);
                    sess->conn->pending_buf = NULL;
                    sess->conn->pending_len = 0;
                    sess->conn->pending_cap = 0;
                }
                fprintf(stderr, "INTER_CRYPTO: outgoing conn to %s:%d encrypted\n",
                        sess->conn->ip, sess->conn->port);
            }
            nodus_t2_msg_free(&msg);
            return;
        } else if (strcmp(msg.method, "error") == 0) {
            nodus_t2_msg_free(&msg);
            return;
        }

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
                    nodus_tcp_send_raw(sess->conn, resp_buf, rlen);
                } else if (srv->identity.has_kyber && msg.proto_version < 2) {
                    /* C1/G3: inter-node proto_version floor. `proto_version`
                     * arrives in the PLAINTEXT pre-auth hello and is not covered
                     * by any signature (nodus_sign_auth_challenge signs only the
                     * 32-byte nonce), so an active MITM could advertise v<2 to
                     * push this link onto the no-Kyber branch — i.e. force
                     * CLEARTEXT inter-node replication and open frame injection.
                     * Every node hardcodes v=2, so a v<2 peer on 4002 is either
                     * an attacker or a build that predates channel encryption;
                     * refuse it. (4002 is operator-only — unlike the 4001 client
                     * port there is no legacy-app population to preserve.) */
                    fprintf(stderr,
                            "INTER: rejecting peer %s:%u — proto_version=%u < 2 "
                            "(downgrade attempt or pre-encryption build)\n",
                            sess->conn->ip, (unsigned)sess->conn->port,
                            (unsigned)msg.proto_version);
                    size_t rlen = 0;
                    nodus_t2_error(msg.txn_id, NODUS_ERR_PROTOCOL_ERROR,
                                    "inter-node requires proto_version >= 2",
                                    resp_buf, sizeof(resp_buf), &rlen);
                    nodus_tcp_send_raw(sess->conn, resp_buf, rlen);
                    sess->conn->auth_state = NODUS_CONN_AUTH_FAILED;
                } else {
                    sess->client_pk = msg.pk;
                    sess->client_fp = msg.fp;
                    sess->proto_version = msg.proto_version;
                    nodus_random(sess->nonce, NODUS_NONCE_LEN);
                    sess->nonce_pending = true;
                    size_t rlen = 0;
                    nodus_t2_challenge(msg.txn_id, sess->nonce,
                                        resp_buf, sizeof(resp_buf), &rlen);
                    nodus_tcp_send_raw(sess->conn, resp_buf, rlen);
                }
            } else if (strcmp(msg.method, "auth") == 0 && sess->nonce_pending) {
                /* C2: domain-tagged AUTH_CHALLENGE verify */
                int rc = nodus_verify_auth_challenge(&msg.sig, sess->nonce, &sess->client_pk);
                if (rc != 0) {
                    size_t rlen = 0;
                    nodus_t2_error(msg.txn_id, NODUS_ERR_INVALID_SIGNATURE,
                                    "auth failed", resp_buf, sizeof(resp_buf), &rlen);
                    nodus_tcp_send_raw(sess->conn, resp_buf, rlen);
                } else {
                    sess->authenticated = true;
                    /* Rev 2 item 7: with Kyber the send gate stays CLOSED
                     * until key_init has produced the session key (opened
                     * in the key_init branch below) — nodus_tcp_send queues
                     * instead of writing plaintext. The handshake replies
                     * use nodus_tcp_send_raw. Without Kyber no session key
                     * will ever exist: open now, as before. */
                    if (!srv->identity.has_kyber)
                        sess->conn->auth_state = NODUS_CONN_AUTH_OK;
                    sess->nonce_pending = false;
                    sess->conn->peer_id = sess->client_fp;
                    sess->conn->peer_pk = sess->client_pk;
                    sess->conn->peer_id_set = true;
                    uint8_t token[NODUS_SESSION_TOKEN_LEN];
                    nodus_random(token, NODUS_SESSION_TOKEN_LEN);
                    size_t rlen = 0;
                    if (srv->identity.has_kyber && sess->proto_version >= 2) {
                        uint8_t sign_data[NODUS_KYBER_PK_BYTES + NODUS_NONCE_LEN];
                        memcpy(sign_data, srv->identity.kyber_pk, NODUS_KYBER_PK_BYTES);
                        memcpy(sign_data + NODUS_KYBER_PK_BYTES, sess->nonce, NODUS_NONCE_LEN);
                        nodus_sig_t kpk_sig;
                        /* C2: KYBER_BIND domain */
                        if (nodus_sign_kyber_bind(&kpk_sig, sign_data, sizeof(sign_data), &srv->identity.sk) == 0) {
                            /* Faz 1 KEM migration: also bind mlkem_pk, if
                             * this identity has one (N2 MLKEM_BIND). */
                            nodus_sig_t mpk_sig;
                            bool have_mpk = sign_mlkem_bind_for_auth_ok(&srv->identity,
                                                                         sess->nonce, &mpk_sig);
                            nodus_t2_auth_ok_kyber(msg.txn_id, token, srv->identity.kyber_pk,
                                                    &srv->identity.pk, &kpk_sig,
                                                    have_mpk ? srv->identity.mlkem_pk : NULL,
                                                    have_mpk ? &mpk_sig : NULL,
                                                    resp_buf, sizeof(resp_buf), &rlen);
                        } else {
                            nodus_t2_auth_ok(msg.txn_id, token,
                                              resp_buf, sizeof(resp_buf), &rlen);
                        }
                    } else {
                        nodus_t2_auth_ok(msg.txn_id, token,
                                          resp_buf, sizeof(resp_buf), &rlen);
                    }
                    nodus_tcp_send_raw(sess->conn, resp_buf, rlen);
                    char fp_hex[33];
                    for (int k = 0; k < 16; k++)
                        snprintf(fp_hex + k*2, sizeof(fp_hex) - k*2, "%02x", sess->client_fp.bytes[k]);
                    fp_hex[32] = '\0';
                    fprintf(stderr, "INTER_AUTH_OK: node %s... authenticated on port 4002 (v=%u)\n",
                            fp_hex, sess->proto_version);
                }
            } else {
                size_t rlen = 0;
                nodus_t2_error(msg.txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                                "authenticate first", resp_buf, sizeof(resp_buf), &rlen);
                nodus_tcp_send_raw(sess->conn, resp_buf, rlen);
            }
            nodus_t2_msg_free(&msg);
            return;
        }

        /* Inter-node key_init: accepting side KEM handshake. key_alg (Faz
         * 1 KEM migration) selects round-3 (0, default) vs ML-KEM-1024 (1)
         * — set by whichever algorithm the encapsulating side chose above. */
        if (strcmp(msg.method, "key_init") == 0 &&
            sess->conn && sess->conn->channel_crypto.established) {
            /* F3: one key exchange per conn — a second key_init would
             * re-key a live session on the peer's word alone. */
            fprintf(stderr,
                    "INTER_GATE: slot=%d peer=%s:%u key_init on an established "
                    "session — refused (F3)\n",
                    sess->conn->slot, sess->conn->ip, (unsigned)sess->conn->port);
            nodus_t2_msg_free(&msg);
            return;
        }
        if (strcmp(msg.method, "key_init") == 0 && msg.has_kyber_ct && msg.has_key_nonce) {
            bool use_mlkem = (msg.key_alg == 1);
            bool have_key = use_mlkem ? srv->identity.has_mlkem : srv->identity.has_kyber;
            /* Phase 3.2b-inv: KEY_INIT receive visibility */
            fprintf(stderr,
                    "CRYPTO: KEY_INIT_RX slot=%d peer=%s:%u alg=%u have_key=%d "
                    "sess=%p sess_conn=%p\n",
                    sess->conn ? sess->conn->slot : -1,
                    sess->conn ? sess->conn->ip : "?",
                    sess->conn ? (unsigned)sess->conn->port : 0,
                    (unsigned)msg.key_alg, have_key ? 1 : 0,
                    (void *)sess, (void *)(sess->conn));
            if (have_key) {
                uint8_t ss_buf[NODUS_KYBER_SS_BYTES];
                int dec_rc = use_mlkem
                    ? qgp_mlkem1024_decapsulate(ss_buf, msg.kyber_ct, srv->identity.mlkem_sk)
                    : qgp_kem1024_decapsulate(ss_buf, msg.kyber_ct, srv->identity.kyber_sk);
                if (dec_rc == 0) {
                    uint8_t ns[NODUS_NONCE_LEN];
                    nodus_random(ns, NODUS_NONCE_LEN);
                    uint8_t ka_buf[4096];
                    size_t ka_len = 0;
                    nodus_t2_key_ack(msg.txn_id, ns, ka_buf, sizeof(ka_buf), &ka_len);
                    nodus_tcp_send_raw(sess->conn, ka_buf, ka_len);
                    /* B3 fix — init per-conn channel_crypto directly.
                     * We ACCEPTED this inter-node conn → responder. */
                    nodus_channel_crypto_init(&sess->conn->channel_crypto,
                                               ss_buf, msg.key_nonce, ns,
                                               NODUS_CHANNEL_ROLE_RESPONDER);
                    qgp_secure_memzero(ss_buf, sizeof(ss_buf));
                    /* Rev 2 item 7: open the send gate only now (and only
                     * for an authenticated peer); DISCARD the auth queue —
                     * it holds pre-framed plaintext, exactly as the dialing
                     * side does on key_ack. */
                    if (sess->authenticated) {
                        sess->conn->auth_state = NODUS_CONN_AUTH_OK;
                        if (sess->conn->pending_buf) {
                            free(sess->conn->pending_buf);
                            sess->conn->pending_buf = NULL;
                            sess->conn->pending_len = 0;
                            sess->conn->pending_cap = 0;
                        }
                    }
                    fprintf(stderr,
                            "CRYPTO: SET_INCOMING slot=%d peer=%s:%u (inter-node encrypted)\n",
                            sess->conn->slot, sess->conn->ip, (unsigned)sess->conn->port);
                } else {
                    /* Phase 3.2b-inv: decap failure was SILENT — log it now. */
                    fprintf(stderr,
                            "CRYPTO: DECAP_FAIL slot=%d peer=%s:%u kyber_ct_len=%zu\n",
                            sess->conn ? sess->conn->slot : -1,
                            sess->conn ? sess->conn->ip : "?",
                            sess->conn ? (unsigned)sess->conn->port : 0,
                            (size_t)NODUS_KYBER_CT_BYTES);
                }
            } else {
                /* Phase 3.2b-inv: identity missing kyber keys was SILENT.
                 * E4 (N1 delta 2): name the algorithm ACTUALLY missing —
                 * before this fix the text always said "no kyber key" even
                 * when use_mlkem was true and the real gap was ML-KEM.
                 * Text/label only, no wire change, no new error code. */
                fprintf(stderr,
                        "CRYPTO: NO_KEY slot=%d peer=%s:%u (identity has no "
                        "%s key)\n",
                        sess->conn ? sess->conn->slot : -1,
                        sess->conn ? sess->conn->ip : "?",
                        sess->conn ? (unsigned)sess->conn->port : 0,
                        use_mlkem ? "ML-KEM-1024" : "Kyber round-3");
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
                /* S2/S3: "own" filters by owner; "pg"/"after" ask for one
                 * page per key in PK order (the cursor applies to every
                 * key; the forwarding node sends one key). Without them the
                 * pre-Package-A read (nodus_storage_get_all) and reply. */
                bool paged = msg.page || msg.has_after;
                const nodus_key_t *own = msg.has_own ? &msg.own_fp : NULL;
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
                            nodus_storage_get_all(&srv->storage, &msg.batch_keys[i],
                                                   &vals[i], &counts[i]);
                            continue;
                        }
                        int more = 0;
                        size_t budget = paged
                            ? (size_t)NODUS_GET_ALL_PAGE_MAX_BYTES / (size_t)n
                            : (size_t)NODUS_GET_ALL_MAX_BYTES;
                        int prc = nodus_storage_get_all_page(&srv->storage, &msg.batch_keys[i],
                                own, msg.has_after ? &msg.after.owner : NULL,
                                msg.has_after ? msg.after.vid : 0, budget,
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
                            if (nodus_storage_get_all_page(&srv->storage,
                                    &msg.batch_keys[i], own, &lastv->owner_fp,
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
                        if (nodus_t2_result_get_batch_ex(msg.txn_id, msg.batch_keys, n,
                                                          vals, counts, pages,
                                                          n_unavail > 0 ? unavail : NULL,
                                                          buf, buf_cap, &rlen) == 0) {
                            nodus_tcp_send(sess->conn, buf, rlen);
                        } else {
                            /* The forwarding peer's BF reader ignores a frame
                             * without batch results and completes the forward
                             * instead of waiting for its timeout. */
                            nodus_t2_error(msg.txn_id, NODUS_ERR_INTERNAL_ERROR,
                                            "batch encode failed", buf, buf_cap, &rlen);
                            nodus_tcp_send(sess->conn, buf, rlen);
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
            nodus_t2_msg_free(&msg);
            return;
        }

        /* ch_rep, ring_check, ring_ack, ring_evict now go via TCP 4003 (channel server) */

        if (strcmp(msg.method, "m_sv") == 0 && msg.has_media) {
            /* Inter-node media replication: store replicated media chunk */

            /* Per-session rate limit (same window as sv) */
            uint64_t msv_now = nodus_time_now();
            if (msv_now != sess->sv_window_start) { sess->sv_window_start = msv_now; sess->sv_count = 0; }
            if (++sess->sv_count > NODUS_SV_MAX_PER_SEC) {
                fprintf(stderr, "MEDIA_REPL: m_sv rate limit hit (%d/s), slot=%d\n",
                        sess->sv_count, sess->conn ? sess->conn->slot : -1);
                nodus_t2_msg_free(&msg);
                return;
            }

            /* Validate fields */
            if (msg.data && msg.data_len > 0 &&
                msg.media_chunk_count > 0 && msg.media_chunk_count <= NODUS_MEDIA_MAX_CHUNKS &&
                msg.media_total_size > 0 && msg.media_total_size <= NODUS_MEDIA_MAX_TOTAL_SIZE &&
                msg.data_len <= NODUS_MEDIA_MAX_CHUNK_SIZE) {

                /* Create meta via INSERT OR IGNORE (dedup safe) */
                nodus_media_meta_t meta;
                memset(&meta, 0, sizeof(meta));
                memcpy(meta.content_hash, msg.media_hash, 64);
                memcpy(meta.owner_fp, "replicated", 11);
                meta.media_type  = msg.media_type;
                meta.total_size  = msg.media_total_size;
                meta.chunk_count = msg.media_chunk_count;
                meta.encrypted   = msg.media_encrypted;
                meta.ttl         = msg.ttl;
                meta.created_at  = (uint64_t)time(NULL);
                meta.expires_at  = (meta.ttl > 0) ? meta.created_at + meta.ttl : 0;
                meta.complete    = false;

                /* INSERT OR IGNORE — if meta already exists, this is a no-op */
                nodus_media_put_meta(&srv->media_storage, &meta);

                /* Store chunk data */
                int rc = nodus_media_put_chunk(&srv->media_storage, msg.media_hash,
                                               msg.media_chunk_idx,
                                               msg.data, msg.data_len);
                if (rc == 0) {
                    /* Check completeness */
                    int chunk_count = nodus_media_count_chunks(&srv->media_storage, msg.media_hash);
                    if (chunk_count >= (int)msg.media_chunk_count) {
                        nodus_media_mark_complete(&srv->media_storage, msg.media_hash);
                        fprintf(stderr, "MEDIA_REPL: m_sv replicated media complete (%d/%u chunks)\n",
                                chunk_count, msg.media_chunk_count);
                    }
                }
            }
            nodus_t2_msg_free(&msg);
            return;
        }

        /* Inter-node circuit forwarding (VPN mesh Faz 1) */
        if (strcmp(msg.method, "ri_open") == 0 && msg.has_ri) {
            handle_inter_ri_open(srv, sess, &msg);
            nodus_t2_msg_free(&msg);
            return;
        }
        if (strcmp(msg.method, "ri_open_ok") == 0 && msg.has_ri) {
            handle_inter_ri_open_ok(srv, sess, &msg);
            nodus_t2_msg_free(&msg);
            return;
        }
        if (strcmp(msg.method, "ri_open_err") == 0 && msg.has_ri) {
            handle_inter_ri_open_err(srv, sess, &msg);
            nodus_t2_msg_free(&msg);
            return;
        }
        if (strcmp(msg.method, "ri_data") == 0 && msg.has_ri) {
            handle_inter_ri_data(srv, sess, &msg);
            nodus_t2_msg_free(&msg);
            return;
        }
        if (strcmp(msg.method, "ri_close") == 0 && msg.has_ri) {
            handle_inter_ri_close(srv, sess, &msg);
            nodus_t2_msg_free(&msg);
            return;
        }

        /* T2 decode succeeded but method is not a known T2 inter-node method.
         * Fall through to T1 decode — sv payloads can parse as valid T2 CBOR. */
        nodus_t2_msg_free(&msg);
    }

    /* F2 (DHT Package A): the T1 dispatch below is reached by a frame the
     * T2 decoder refused, so the T2 auth gate above never saw it. One
     * check here, before any T1 parsing: nothing on 4002 is processed from
     * an unauthenticated peer, nor (F3) before the session key exists. No
     * T1 method is a handshake frame. */
    if (srv->config.require_peer_auth &&
        (!sess->authenticated || inter_pre_established(srv, sess))) {
        fprintf(stderr,
                "INTER_GATE: slot=%d peer=%s:%u T1 frame len=%zu %s — dropped (F2)\n",
                sess->conn ? sess->conn->slot : -1,
                sess->conn ? sess->conn->ip : "?",
                sess->conn ? (unsigned)sess->conn->port : 0, len,
                !sess->authenticated ? "unauthenticated" : "before session key");
        return;
    }

    /* Decode once, dispatch by T1 method (FIX-C6).
     * Prior code decoded twice and silently dropped non-sv T1 methods
     * (sub/unsub/ntf) because the second branch only triggered on decode
     * failure. It also leaked the first decode's value when re-decoding. */
    nodus_tier1_msg_t t1msg;
    memset(&t1msg, 0, sizeof(t1msg));
    if (nodus_t1_decode(payload, len, &t1msg) == 0) {
        /* DBG: T1 decode success on encrypted conn (v0.18.1) */
        if (sess->conn && sess->conn->channel_crypto.established) {
            fprintf(stderr,
                    "DBG_T1_OK: slot=%d method=%s has_value=%d\n",
                    sess->conn->slot,
                    t1msg.method[0] ? t1msg.method : "(empty)",
                    t1msg.value ? 1 : 0);
        }

        if (strcmp(t1msg.method, "sv") == 0 && t1msg.value) {
            /* STORE_VALUE: replication from another node */
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
                /* DBG: log put_rc for replication diagnosis (v0.18.1) */
                if (put_rc != 0) {
                    char dbg_kh[17];
                    for (int x = 0; x < 8; x++)
                        snprintf(dbg_kh + x*2, sizeof(dbg_kh) - x*2,
                                 "%02x", t1msg.value->key_hash.bytes[x]);
                    dbg_kh[16] = '\0';
                    fprintf(stderr,
                            "DBG_PUT_SKIP: put_rc=%d key=%s vid=%llu seq=%llu type=%d\n",
                            put_rc, dbg_kh,
                            (unsigned long long)t1msg.value->value_id,
                            (unsigned long long)t1msg.value->seq,
                            (int)t1msg.value->type);
                }
                if (put_rc == 0) {
                    notify_listeners(srv, &t1msg.value->key_hash, t1msg.value);
                    /* Forward to remote subscribers (Scribe pattern) */
                    subscription_notify(srv, &t1msg.value->key_hash, t1msg.value);
                }
            } else {
                char kh[17];
                for (int i = 0; i < 8; i++)
                    snprintf(kh + i*2, sizeof(kh) - i*2, "%02x", t1msg.value->key_hash.bytes[i]);
                kh[16] = '\0';
                fprintf(stderr, "REPL_TCP: verify FAILED for key=%s... vid=%llu seq=%llu — value DROPPED\n",
                        kh, (unsigned long long)t1msg.value->value_id,
                        (unsigned long long)t1msg.value->seq);
            }

        } else if (strcmp(t1msg.method, "sub") == 0) {
            /* SUBSCRIBE_FWD: remote node subscribing to a key on us.
             * Look up subscriber's TCP 4002 port from routing table. */
            nodus_peer_t peer;
            uint16_t sub_port = NODUS_DEFAULT_PEER_PORT;
            if (nodus_routing_lookup(&srv->routing, &sess->client_fp, &peer) == 0) {
                sub_port = peer.tcp_port ? peer.tcp_port : NODUS_DEFAULT_PEER_PORT;
            }
            subscription_add(&srv->subscriptions, &t1msg.target, &sess->client_fp,
                              sess->conn ? sess->conn->ip : "", sub_port);

        } else if (strcmp(t1msg.method, "unsub") == 0) {
            subscription_remove(&srv->subscriptions, &t1msg.target, &sess->client_fp);

        } else if (strcmp(t1msg.method, "ntf") == 0 && t1msg.value) {
            /* NOTIFY forwarded from a responsible node — we have a local
             * listener that asked for this key. Verify and push to local
             * listeners only. Do NOT store: this node is not necessarily
             * a responsible node for the key, and storing here would bloat
             * non-responsible nodes and break R=3 invariants. Scribe is
             * push-only — the value lives only on responsible nodes. */
            if (nodus_value_verify(t1msg.value) == 0) {
                notify_listeners(srv, &t1msg.value->key_hash, t1msg.value);
            }

        } else {
            QGP_LOG_DEBUG(LOG_TAG, "INTER_TCP: unknown T1 method '%s'",
                           t1msg.method[0] ? t1msg.method : "(empty)");
        }

        nodus_t1_msg_free(&t1msg);
        return;
    }

    /* T1 decode failed — unknown frame on inter-node port.
     * Phase 3.2a: crypto state. Phase 3.2b-inv: authenticated + peer_id_set
     * + sess session pointer for root cause correlation. */
    {
        char hexdump[65] = {0};
        size_t dumplen = len < 32 ? len : 32;
        for (size_t i = 0; i < dumplen; i++)
            snprintf(hexdump + i * 2, 3, "%02x", payload[i]);

        /* B3 fix — channel_crypto storage now lives on the conn struct.
         * Read counters/state from there directly; no alias to validate. */
        const char *crypto_state = "none";
        uint64_t tx_ctr = 0, rx_ctr = 0;
        if (sess->conn) {
            nodus_channel_crypto_t *cc = &sess->conn->channel_crypto;
            /* C1: rx_counter is now per-role. For this forensic summary report
             * the PEER's stream — i.e. the role opposite ours; a legacy peer's
             * frames land in the LEGACY slot, so take the max of the two we can
             * legitimately receive (we never accept our own role). */
            uint64_t rx_peer = cc->rx_counter[NODUS_CHANNEL_ROLE_LEGACY];
            for (uint8_t r = NODUS_CHANNEL_ROLE_INITIATOR;
                 r < NODUS_CHANNEL_ROLE_COUNT; r++) {
                if (r != cc->my_role && cc->rx_counter[r] > rx_peer)
                    rx_peer = cc->rx_counter[r];
            }
            crypto_state = cc->established ? "established" :
                           (cc->tx_counter || rx_peer ? "pending" : "none");
            tx_ctr = cc->tx_counter;
            rx_ctr = rx_peer;
        }
        int authed = (sess->conn && sess->conn->authenticated) ? 1 : 0;
        int peer_id_set = (sess->conn && sess->conn->peer_id_set) ? 1 : 0;
        /* B3 — sess_cc_est and sess_aliases_conn fields are obsolete; the
         * Phase 3.2c forensic logic was diagnosing the very pointer-alias
         * race that B3 eliminates by removing the alias entirely. Keep the
         * field names with constant values for log-format compatibility
         * with downstream parsers; they will always read 1 / 1 now. */
        int sess_cc_est = (sess->conn) ? sess->conn->channel_crypto.established : 0;
        int sess_aliases_conn = 1;  /* always — storage IS the conn now */
        fprintf(stderr,
                "REPL_TCP: T1 decode failed (len=%zu) slot=%d src=%s:%u "
                "head=%s crypto=%s tx=%llu rx=%llu authed=%d peer_id_set=%d "
                "auth_state=%d dispatch_mask=0x%02x decrypt_skip=%llu "
                "sess_cc_est=%d sess_alias=%d "
                "sess=%p sess_conn=%p\n",
                len, sess->conn ? sess->conn->slot : -1,
                sess->conn ? sess->conn->ip : "?",
                sess->conn ? (unsigned)sess->conn->port : 0,
                hexdump, crypto_state,
                (unsigned long long)tx_ctr, (unsigned long long)rx_ctr,
                authed, peer_id_set,
                sess->conn ? (int)sess->conn->auth_state : -1,
                sess->conn ? (unsigned)sess->conn->dispatch_logged_mask : 0,
                sess->conn ? (unsigned long long)sess->conn->decrypt_skip_count : 0ULL,
                sess_cc_est, sess_aliases_conn,
                (void *)sess, (void *)(sess->conn));
    }
    nodus_t1_msg_free(&t1msg);
}

void nodus_server_dispatch_inter_frame(nodus_server_t *srv,
                                       nodus_inter_session_t *sess,
                                       const uint8_t *payload, size_t len) {
    if (!srv || !sess || !payload) return;
    dispatch_inter(srv, sess, payload, len);
}

/* ── Inter-node TCP callbacks ───────────────────────────────────── */

static void on_inter_connect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;

    /* Initialize inter session for outgoing connection (on_inter_accept
     * does this for incoming, but outgoing connections need it too —
     * dispatch_inter uses sess->conn for auth response handling). */
    nodus_inter_session_t *sess = inter_session_for_conn(srv, conn);
    if (sess) {
        inter_session_clear(sess, conn->slot, "on_inter_connect");
        sess->conn = conn;
    }

    conn->is_nodus = true;
    conn->auth_required = srv->inter_tcp.auth_required;

    /* Phase 3.2b-inv: conn lifecycle visibility */
    fprintf(stderr, "INTER_CONN: CONNECT slot=%d peer=%s:%u sess=%p\n",
            conn->slot, conn->ip, (unsigned)conn->port, (void *)sess);

    if (conn->auth_required) {
        /* Auto-send hello to initiate auth */
        uint8_t hello_buf[8192];
        size_t hello_len = 0;
        if (nodus_t2_hello(0, &srv->identity.pk, &srv->identity.node_id,
                            hello_buf, sizeof(hello_buf), &hello_len) == 0) {
            nodus_tcp_send_raw(conn, hello_buf, hello_len);
            conn->auth_state = NODUS_CONN_AUTH_HELLO_SENT;
        } else {
            conn->auth_state = NODUS_CONN_AUTH_FAILED;
        }
    } else {
        conn->auth_state = NODUS_CONN_AUTH_OK;
    }
}

static void on_inter_accept(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    nodus_inter_session_t *sess = inter_session_for_conn(srv, conn);
    if (sess) {
        inter_session_clear(sess, conn->slot, "on_inter_accept");
        sess->conn = conn;
    }
    conn->is_nodus = true;
    conn->auth_required = srv->inter_tcp.auth_required;

    /* Phase 3.2b-inv: conn lifecycle visibility */
    fprintf(stderr, "INTER_CONN: ACCEPT slot=%d peer=%s:%u sess=%p\n",
            conn->slot, conn->ip, (unsigned)conn->port, (void *)sess);
}

static void on_inter_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                             size_t len, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    nodus_inter_session_t *sess = inter_session_for_conn(srv, conn);
    if (!sess) return;

    /* DBG: trace encrypted frames for replication diagnosis (v0.18.1) */
    if (conn->channel_crypto.established) {
        fprintf(stderr,
                "DBG_RX_ENC: slot=%d peer=%s:%u len=%zu auth_state=%d\n",
                conn->slot, conn->ip, (unsigned)conn->port, len,
                (int)conn->auth_state);
    }

    /* Phase 3.2c: log first frame seen on this conn — tells us whether
     * an INBOUND ACCEPT ever made it past the TCP handshake into actual
     * data exchange. If conns drop with first_frame_logged=0, the peer
     * never sent anything (TCP-only churn). */
    if (!conn->first_frame_logged) {
        conn->first_frame_logged = true;
        /* B3 fix — read inline channel_crypto state. */
        int has_crypto = conn->channel_crypto.established ? 1 : 0;
        /* Phase 3.2d: include fd so we can detect any cross-conn fd alias
         * by matching against TCP_CONN: FD_SET and TCP_SEND_FIRST logs. */
        fprintf(stderr,
                "INTER_FRAME_FIRST: slot=%d fd=%d peer=%s:%u len=%zu auth_state=%d "
                "has_crypto=%d sess=%p sess_conn=%p conn=%p match=%d\n",
                conn->slot, conn->fd, conn->ip, (unsigned)conn->port, len,
                (int)conn->auth_state, has_crypto,
                (void *)sess, (void *)sess->conn, (void *)conn,
                (sess->conn == conn) ? 1 : 0);
    }

    /* Phase 3.2b-inv: SESS_MISMATCH detector — critical bug if fires.
     * on_inter_accept/connect sets sess->conn = conn, so they should be
     * equal. If not, the session was not re-initialized after a slot
     * reuse, or a different conn is hitting the same slot's session. */
    if (sess->conn != conn) {
        fprintf(stderr,
                "SESS_MISMATCH: slot=%d peer=%s:%u sess_conn=%p actual_conn=%p\n",
                conn->slot, conn->ip, (unsigned)conn->port,
                (void *)sess->conn, (void *)conn);
    }

    dispatch_inter(srv, sess, payload, len);
}

static void on_inter_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_server_inter_disconnected((nodus_server_t *)ctx, conn);
}

void nodus_server_inter_disconnected(nodus_server_t *srv, nodus_tcp_conn_t *conn) {
    if (!srv || !conn) return;
    nodus_inter_session_t *sess = inter_session_for_conn(srv, conn);

    /* Phase 3.2b-inv: conn lifecycle visibility — capture crypto state
     * before we clear the session.
     * B3 fix — read inline channel_crypto state directly. */
    int had_crypto = conn->channel_crypto.established ? 1 : 0;
    int established = had_crypto;
    /* Phase 3.2c: include auth_state at disconnect — tells us how far the
     * handshake got before the conn died. INBOUND conn that drops with
     * auth_state=NONE means peer never even sent hello. */
    fprintf(stderr,
            "INTER_CONN: DISCONNECT slot=%d peer=%s:%u had_crypto=%d established=%d "
            "auth_state=%d authed=%d peer_id_set=%d frames_seen=%d "
            "sess=%p sess_conn=%p conn=%p\n",
            conn->slot, conn->ip, (unsigned)conn->port, had_crypto, established,
            (int)conn->auth_state, conn->authenticated ? 1 : 0,
            conn->peer_id_set ? 1 : 0, conn->first_frame_logged ? 1 : 0,
            (void *)sess, sess ? (void *)sess->conn : NULL, (void *)conn);

    /* F1: no inter-circuit may keep a pointer to this conn. */
    nodus_server_inter_conn_closed(srv, conn);

    if (sess) {
        inter_session_clear(sess, conn->slot, "on_inter_disconnect");
    }
}

/* P2P-PORT F5 — the witness-port callbacks on_witness_connect /
 * on_witness_accept / on_witness_frame / on_witness_disconnect (the 4004
 * nodus_tcp transport: the T2 hello → challenge → auth → auth_ok
 * exchange gated by require_peer_auth, the IDENT send after it, and the
 * hand-off of every other frame to the tier-3 dispatcher) are DELETED.
 * Port 4004 is the witness's p2p host (nodus_witness_p2p.h): every
 * connection runs the secret-connection handshake, no T2 message is
 * spoken there, and no frame reaches a dispatcher unauthenticated. */

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
            sess->proto_version = msg.proto_version;
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

    /* Post-auth key exchange: key_init has no token (transition message).
     * Faz 1 KEM migration: dispatch by msg.key_alg (0 = round-3 default). */
    if (strcmp(msg.method, "key_init") == 0 && msg.has_kyber_ct && msg.has_key_nonce) {
        nodus_auth_handle_key_init_alg(srv, sess, msg.key_alg,
                                        msg.kyber_ct, msg.key_nonce, msg.txn_id);
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

    /* P2P-PORT F5 (witness-port session design §2R R16; p2p-port design
     * §3): the `w_*` witness methods are REFUSED on the client port. The
     * forward to the tier-3 dispatcher that stood here is deleted with the
     * dispatcher; every witness message now travels only on port 4004,
     * inside a secret connection. No T2 method and no client string starts
     * with `w_` (grep 2026-09-26), so only a stale peer is refused here. */
    if (strncmp(msg.method, "w_", 2) == 0) {
        size_t rlen = 0;
        nodus_t2_error(msg.txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "witness methods are not served on the client port",
                        resp_buf, sizeof(resp_buf), &rlen);
        nodus_tcp_send(sess->conn, resp_buf, rlen);
        nodus_t2_msg_free(&msg);
        return;
    }

    /* The node-side governance approval collection (decision
     * 2026-09-26-cc-approval-via-own-node.md): the ONE dnac_* method that
     * receives the requesting session's identity, because it is served
     * only to this node's own identity key (checked by the witness,
     * nodus_witness_cc_collect_start). Every other dnac_* method takes the
     * generic route below, unchanged. */
    if (strcmp(msg.method, "dnac_cc_collect") == 0 && srv->witness) {
        nodus_witness_handle_cc_collect(srv->witness, sess->conn,
                                        sess->client_pk.bytes, sess->token,
                                        payload, len, msg.txn_id);
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
    else if (strcmp(msg.method, "status") == 0)
        handle_t2_status(srv, sess, &msg);
    else if (strcmp(msg.method, "ch_list") == 0)
        handle_t2_ch_list(srv, sess, &msg);
    else if (strcmp(msg.method, "ch_search") == 0)
        handle_t2_ch_search(srv, sess, &msg);
    else if (strcmp(msg.method, "ch_get") == 0)
        handle_t2_ch_get(srv, sess, &msg);
    else if (strcmp(msg.method, "m_put") == 0)
        handle_t2_media_put(srv, sess, &msg);
    else if (strcmp(msg.method, "m_meta") == 0)
        handle_t2_media_get_meta(srv, sess, &msg);
    else if (strcmp(msg.method, "m_chunk") == 0)
        handle_t2_media_get_chunk(srv, sess, &msg);
    else if (strcmp(msg.method, "circ_open") == 0)
        handle_t2_circ_open(srv, sess, &msg);
    else if (strcmp(msg.method, "circ_data") == 0)
        handle_t2_circ_data(srv, sess, &msg);
    else if (strcmp(msg.method, "circ_close") == 0)
        handle_t2_circ_close(srv, sess, &msg);
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
        /* NODES_FOUND: feed to iterative lookup engine FIRST (FIX-C3),
         * then update routing table (existing behavior, kept). */
        iterative_lookup_handle_response(srv, msg.txn_id, &msg,
                                          from_ip, from_port);
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
                    snprintf(kh + i*2, sizeof(kh) - i*2, "%02x", msg.value->key_hash.bytes[i]);
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
        /* Storage fault → answered like a miss (closest nodes), logged —
         * see the 4002 "fv" handler. */
        if (rc == NODUS_STORAGE_RC_FAULT)
            QGP_LOG_WARN(LOG_TAG, "UDP fv: storage read fault — answered as "
                         "not-found with closest nodes");

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
                snprintf(fp_hex + i*2, sizeof(fp_hex) - i*2, "%02x", sess->client_fp.bytes[i]);
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
        /* Tear down circuits (notify bridge peers) before clearing session */
        session_teardown_circuits(srv, sess);
        session_clear(sess);
    }
}

/* ── Channel post replication callback ────────────────────────── */

#ifndef NODUS_CHANNELS_DISABLED
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
#endif /* !NODUS_CHANNELS_DISABLED — ch callbacks */

/* P2P-PORT F5 — nodus_server_publish_identity (the DHT `nodus:pk`
 * registry record {id, pk, ip, witness port, kpk}, re-published every
 * 60 s with a 10-minute TTL) is DELETED with both of its readers (the
 * witness transport roster, nodus_witness_peer.c): validator addresses
 * left the DHT (decision record 2026-09-26-witness-port-session.md "N7
 * SON") and travel as self-signed ADDR records over the 4004 PEX
 * reactor. Rows already stored under the key expire by their TTL. */

/* ── Channel startup rejoin ───────────────────────────────────────
 * Called once from the main loop after hashring has ≥2 members.
 * 1. Scan channels.db for existing channel tables
 * 2. Re-track channels this node is responsible for
 * 3. Send ring_rejoin to authenticated peer sessions
 * 4. Send ch_sync_request to PRIMARY for each tracked channel
 */
#ifndef NODUS_CHANNELS_DISABLED
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
#endif /* !NODUS_CHANNELS_DISABLED */

/* ── PR 3 / E5 — Partial-wipe XOR check (H-10) ──────────────────── */

int nodus_server_check_partial_wipe(const char *data_path) {
    if (!data_path) return -1;

    /* If the orphan-bootstrap sentinel (.bootstrap_in_progress) is
     * present the previous bootstrap's FETCH_GENESIS crashed mid-
     * write. The downstream witness init runs E0
     * (nodus_witness_check_orphan_bootstrap_sentinel) which archives
     * any partial witness_*.db, clears the sentinel, and lets
     * DISCOVER restart. If we run the strict-XOR gate first, the
     * crashed-mid-bootstrap state (marker present, only the partial
     * witness file present) trips the gate and we never reach the
     * E0 cleanup — operator has to manually clear sentinel + wipe.
     * The orphan sentinel takes precedence; defer to E0. */
    char sentinel[640];
    int ns = snprintf(sentinel, sizeof(sentinel),
                      "%s/.bootstrap_in_progress", data_path);
    if (ns > 0 && (size_t)ns < sizeof(sentinel)) {
        struct stat sst;
        if (stat(sentinel, &sst) == 0) return 0;
    }

    /* The strict XOR invariant only applies AFTER the chain DB has
     * been created at least once. Without the marker, the file-level
     * state (nodus.db + channels.db present, witness_*.db absent) is
     * the legitimate mid-bootstrap state — stagef_up.sh's identity-gen
     * pre-spawn produces it, and a real production node can land
     * there too if it crashes between storage_open and the first
     * FETCH_GENESIS commit. Gating on the marker prevents false
     * positives in both cases without weakening the post-genesis
     * operator-mistake detection. */
    char marker[640];
    int nm = snprintf(marker, sizeof(marker), "%s/%s",
                      data_path, NODUS_PARTIAL_WIPE_GENESIS_MARKER);
    if (nm < 0 || (size_t)nm >= sizeof(marker)) return -1;

    struct stat mst;
    if (stat(marker, &mst) != 0) {
        /* No marker: pre-genesis state (or operator wiped marker +
         * everything, which is the intended fresh-restart path). Any
         * subset of the 3 DB files is allowed. */
        return 0;
    }

    char nodus_db[640];
    char channels_db[640];
    int n1 = snprintf(nodus_db, sizeof(nodus_db),
                      "%s/nodus.db", data_path);
    int n2 = snprintf(channels_db, sizeof(channels_db),
                      "%s/channels.db", data_path);
    if (n1 < 0 || (size_t)n1 >= sizeof(nodus_db) ||
        n2 < 0 || (size_t)n2 >= sizeof(channels_db))
        return -1;

    struct stat st;
    int has_nodus    = (stat(nodus_db,    &st) == 0) ? 1 : 0;
    int has_channels = (stat(channels_db, &st) == 0) ? 1 : 0;

    /* Witness DB filename is chain-id-suffixed and not known until
     * genesis lands, so scan for any witness_<hex>.db (excluding the
     * -wal / -shm sidecars whose presence alone is not enough — they
     * vanish on clean shutdown). */
    int has_witness = 0;
    DIR *dir = opendir(data_path);
    if (dir) {
        struct dirent *e;
        while ((e = readdir(dir)) != NULL) {
            if (strncmp(e->d_name, "witness_", 8) != 0) continue;
            size_t len = strlen(e->d_name);
            if (len < 11) continue;  /* "witness_" + at least 1 char + ".db" */
            if (strcmp(e->d_name + len - 3, ".db") != 0) continue;
            has_witness = 1;
            break;
        }
        closedir(dir);
    }

    int present = has_nodus + has_channels + has_witness;
    if (present == 0 || present == 3) return 0;

    fprintf(stderr,
        "%s: PARTIAL WIPE DETECTED at %s — "
        "nodus.db=%s channels.db=%s witness_*.db=%s "
        "(genesis marker " NODUS_PARTIAL_WIPE_GENESIS_MARKER " present). "
        "REFUSING START. After this node has crossed genesis the 3 "
        "SQLite DBs MUST be all-present (normal boot) or all-absent "
        "(treated as fresh-restart). Investigate the missing file(s); "
        "restore from backup, OR wipe ALL 3 DBs (keep the marker) to "
        "trigger a clean re-bootstrap from peers, OR wipe ALL 3 DBs "
        "AND the marker to force a fresh first-boot path.\n",
        LOG_TAG, data_path,
        has_nodus    ? "yes" : "MISSING",
        has_channels ? "yes" : "MISSING",
        has_witness  ? "yes" : "MISSING");
    return -1;
}

/* ── P2P-PORT F6 — chain id reader + the pin-at-start check ─────── */

int nodus_server_read_chain_id(const char *db_path, uint8_t out[32]) {
    if (!db_path || !out) return -1;
    /* Heap, never stack: nodus_witness_t is multi-MB. Only `db` is used
     * by the stored-chain-id reader (nodus_witness_v2_gen.h). */
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return -1;
    if (sqlite3_open_v2(db_path, &w->db, SQLITE_OPEN_READONLY, NULL)
        != SQLITE_OK) {
        if (w->db) sqlite3_close(w->db);
        free(w);
        return -1;
    }
    int rc = nodus_witness_v2_gen_stored_chain_id(w, out);
    sqlite3_close(w->db);
    free(w);
    return rc == 0 ? 0 : -1;
}

static void hex32_lower(const uint8_t b[32], char out[65]) {
    static const char hd[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i]     = hd[b[i] >> 4];
        out[2 * i + 1] = hd[b[i] & 0x0F];
    }
    out[64] = '\0';
}

/* The witness scan's filename predicate, restated (nodus_witness.c
 * witness_chain_id_from_name is file-static): "witness_" + EXACTLY 32
 * LOWERCASE hex digits + ".db", nothing after (-wal / -shm rejected, an
 * upper-case alias rejected). Restated rather than shared because the
 * witness header is outside this change; the two MUST stay identical —
 * a drift would make the start check look at a different file than the
 * one the node runs. */
static bool chain_db_name_ok(const char *d_name) {
    if (strncmp(d_name, "witness_", 8) != 0) return false;
    const char *hex = d_name + 8;
    const char *dot = strstr(hex, ".db");
    if (!dot || dot[3] != '\0' || (size_t)(dot - hex) != 32) return false;
    for (size_t i = 0; i < 32; i++) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

int nodus_server_check_chain_pin(const char *data_path, const uint8_t pin[32]) {
    if (!data_path || !pin) return -1;
    DIR *dir = opendir(data_path);
    if (!dir) {
        /* An absent data directory holds no chain; any other failure is
         * "could not establish", which is not "no chain". */
        if (errno == ENOENT) return 0;
        QGP_LOG_ERROR(LOG_TAG, "network file pin: cannot read data "
                      "directory %s (%s) — refusing to start without "
                      "knowing whether it holds a chain", data_path,
                      strerror(errno));
        return -1;
    }
    /* The ONE file the witness will open: the lexicographically smallest
     * canonical name (nodus_witness_scan_chain_db, O15A deterministic
     * selection). Other files in the directory are never opened by the
     * node and are not judged here either. */
    char best[256];
    bool have = false;
    struct dirent *e;
    while ((e = readdir(dir)) != NULL) {
        if (!chain_db_name_ok(e->d_name)) continue;
        if (!have || strcmp(e->d_name, best) < 0) {
            snprintf(best, sizeof(best), "%s", e->d_name);
            have = true;
        }
    }
    closedir(dir);
    if (!have) return 0;                         /* no chain: a joiner */

    char want[65];
    hex32_lower(pin, want);
    char p[640];
    int n = snprintf(p, sizeof(p), "%s/%s", data_path, best);
    if (n < 0 || (size_t)n >= sizeof(p)) {
        QGP_LOG_ERROR(LOG_TAG, "network file pin: chain database path under "
                      "%s too long — refusing to start", data_path);
        return -1;
    }
    uint8_t id[32];
    if (nodus_server_read_chain_id(p, id) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "network file pin: %s holds no readable "
                      "version-3 chain id — cannot verify it against the "
                      "pin %s; refusing to start", p, want);
        return -1;
    }
    if (memcmp(id, pin, 32) != 0) {
        char have_hex[65];
        hex32_lower(id, have_hex);
        QGP_LOG_ERROR(LOG_TAG, "REFUSING START — the network file pins chain "
                      "%s but this node's database %s is chain %s. A wrong "
                      "database is caught here, locally, before it can talk "
                      "to the network. Fix the network file or the data "
                      "directory.", want, p, have_hex);
        return -1;
    }
    return 0;
}

#ifdef NODUS_HAS_JSONC
/* ── P2P-PORT F6 — the network file (nodus_server.h) ────────────── */

#define NF_KEY_PIN   "v2_genesis_pin"
#define NF_KEY_PEERS "persistent_peers"

static int nf_hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* A pin value: "" → no pin (0, *has = false); 64 hex digits → the pin;
 * anything else → -1. */
static int nf_parse_pin(struct json_object *v, bool *has, uint8_t out[32]) {
    *has = false;
    if (!json_object_is_type(v, json_type_string)) return -1;
    const char *s = json_object_get_string(v);
    size_t n = (size_t)json_object_get_string_len(v);
    if (n == 0) return 0;
    if (n != 64 || strlen(s) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        int hi = nf_hexval(s[2 * i]), lo = nf_hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *has = true;
    return 0;
}

/* Validate a parsed root object into `out`. `path` is for messages. */
static int nf_validate(struct json_object *root, const char *path,
                       nodus_network_file_t *out) {
    memset(out, 0, sizeof(*out));
    if (!json_object_is_type(root, json_type_object)) {
        QGP_LOG_ERROR(LOG_TAG, "network file %s: not a JSON object", path);
        return -1;
    }
    json_object_object_foreach(root, key, val) {
        if (strcmp(key, NF_KEY_PIN) == 0) {
            if (nf_parse_pin(val, &out->has_pin, out->pin) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "network file %s: \"%s\" must be a "
                              "string of 64 hex digits or empty", path, key);
                return -1;
            }
        } else if (strcmp(key, NF_KEY_PEERS) == 0) {
            if (!json_object_is_type(val, json_type_array)) {
                QGP_LOG_ERROR(LOG_TAG, "network file %s: \"%s\" must be an "
                              "array of \"id@ip:port\" strings", path, key);
                return -1;
            }
            size_t n = json_object_array_length(val);
            if (n > NODUS_P2P_MAX_PEER_LIST) {
                QGP_LOG_ERROR(LOG_TAG, "network file %s: %zu persistent "
                              "peers, at most %d", path, n,
                              NODUS_P2P_MAX_PEER_LIST);
                return -1;
            }
            for (size_t i = 0; i < n; i++) {
                struct json_object *it = json_object_array_get_idx(val, i);
                if (!json_object_is_type(it, json_type_string)) {
                    QGP_LOG_ERROR(LOG_TAG, "network file %s: peer %zu is "
                                  "not a string", path, i);
                    return -1;
                }
                const char *s = json_object_get_string(it);
                size_t sl = (size_t)json_object_get_string_len(it);
                cmt_p2p_netaddr_t na;
                if (sl == 0 || sl >= CMT_P2P_NETADDR_STR_MAX ||
                    strlen(s) != sl ||
                    cmt_p2p_netaddr_new_string(s, sl, &na) !=
                        CMT_P2P_ERR_NONE) {
                    /* NO_ID included: the 4004 layer never dials an
                     * unpinned address (R-P2P-33); a non-IP host is
                     * ErrNetAddressLookup (R-P2P-24). */
                    QGP_LOG_ERROR(LOG_TAG, "network file %s: peer \"%s\" is "
                                  "not id@ip:port with a valid ID and an IP "
                                  "literal", path, s);
                    return -1;
                }
                for (int j = 0; j < out->n_peers; j++) {
                    if (strcmp(out->peers[j], s) == 0) {
                        QGP_LOG_ERROR(LOG_TAG, "network file %s: peer "
                                      "\"%s\" listed twice", path, s);
                        return -1;
                    }
                }
                memcpy(out->peers[out->n_peers], s, sl + 1);
                out->n_peers++;
            }
        } else {
            /* A typo'd pin key would otherwise read as "no pin" and
             * silently change what the node does. */
            QGP_LOG_ERROR(LOG_TAG, "network file %s: unknown key \"%s\" "
                          "(allowed: \"%s\", \"%s\")", path, key,
                          NF_KEY_PIN, NF_KEY_PEERS);
            return -1;
        }
    }
    return 0;
}

int nodus_network_file_load(const char *path, nodus_network_file_t *out) {
    if (!path || !out) return -1;
    memset(out, 0, sizeof(*out));
    struct json_object *root = json_object_from_file(path);
    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "network file %s: missing, unreadable or not "
                      "JSON (%s)", path, json_util_get_last_err()
                      ? json_util_get_last_err() : "?");
        return -1;
    }
    int rc = nf_validate(root, path, out);
    json_object_put(root);
    if (rc != 0) memset(out, 0, sizeof(*out));
    return rc;
}

int nodus_network_file_apply(const nodus_network_file_t *nf,
                             nodus_server_config_t *cfg) {
    if (!nf || !cfg) return -1;
    if (nf->has_pin) {
        if (cfg->has_v2_genesis_pin &&
            memcmp(cfg->v2_genesis_pin, nf->pin, 32) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "--v2-genesis-pin and the network file's "
                          "pin differ — two different chains named; "
                          "refusing");
            return -1;
        }
        memcpy(cfg->v2_genesis_pin, nf->pin, 32);
        cfg->has_v2_genesis_pin = true;
        memcpy(cfg->network_pin, nf->pin, 32);
        cfg->has_network_pin = true;
    }
    for (int i = 0; i < nf->n_peers; i++) {
        bool dup = false;
        for (int j = 0; j < cfg->p2p.n_persistent_peers; j++) {
            if (strcmp(cfg->p2p.persistent_peers[j], nf->peers[i]) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        if (nodus_p2p_config_add_persistent(&cfg->p2p, nf->peers[i]) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "network file peer \"%s\": the persistent "
                          "peer list is full (%d)", nf->peers[i],
                          NODUS_P2P_MAX_PEER_LIST);
            return -1;
        }
    }
    return 0;
}

int nodus_network_file_write_pin(const char *path, const uint8_t chain32[32]) {
    if (!path || !chain32) return -1;
    struct json_object *root = json_object_from_file(path);
    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "network file %s: missing, unreadable or not "
                      "JSON — the pin was NOT written", path);
        return -1;
    }
    nodus_network_file_t nf;
    int rc = -1;
    char hex[65];
    char tmp[600];
    int fd = -1;
    tmp[0] = '\0';
    hex32_lower(chain32, hex);

    /* Never write into a file the loader would refuse. */
    if (nf_validate(root, path, &nf) != 0) goto out;
    if (nf.has_pin) {
        if (memcmp(nf.pin, chain32, 32) == 0) { rc = 1; goto out; }
        char have[65];
        hex32_lower(nf.pin, have);
        QGP_LOG_ERROR(LOG_TAG, "network file %s already pins chain %s, this "
                      "ceremony derived %s — NOT overwritten; the ceremony "
                      "stops here", path, have, hex);
        goto out;
    }

    /* Replaces an existing "" in place (json-c keeps the key's position)
     * or appends the key; every other key is untouched. */
    if (json_object_object_add(root, NF_KEY_PIN,
                               json_object_new_string(hex)) != 0)
        goto out;
    const char *text = json_object_to_json_string_ext(
        root, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);
    if (!text) goto out;
    size_t tlen = strlen(text);

    struct stat st;
    mode_t mode = 0644;
    if (stat(path, &st) == 0) mode = st.st_mode & 0777;

    int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp)) { tmp[0] = '\0'; goto out; }
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "network file %s: cannot create %s (%s)",
                      path, tmp, strerror(errno));
        tmp[0] = '\0';
        goto out;
    }
    size_t off = 0;
    while (off < tlen) {
        ssize_t w = write(fd, text + off, tlen - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            goto io_fail;
        }
        off += (size_t)w;
    }
    if (write(fd, "\n", 1) != 1) goto io_fail;
    if (fsync(fd) != 0) goto io_fail;
    if (close(fd) != 0) { fd = -1; goto io_fail; }
    fd = -1;
    if (rename(tmp, path) != 0) goto io_fail;
    tmp[0] = '\0';                              /* now the real file */
    {
        /* make the rename itself durable */
        char dir[600];
        snprintf(dir, sizeof(dir), "%s", path);
        char *slash = strrchr(dir, '/');
        if (slash == dir) dir[1] = '\0';
        else if (slash) *slash = '\0';
        else snprintf(dir, sizeof(dir), ".");
        int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd >= 0) {
            if (fsync(dfd) != 0)
                QGP_LOG_WARN(LOG_TAG, "network file: directory fsync of %s "
                             "failed (%s)", dir, strerror(errno));
            close(dfd);
        }
    }
    rc = 0;
    goto out;

io_fail:
    QGP_LOG_ERROR(LOG_TAG, "network file %s: writing the pin failed (%s) — "
                  "the file is unchanged", path, strerror(errno));
out:
    if (fd >= 0) close(fd);
    if (tmp[0]) unlink(tmp);
    json_object_put(root);
    return rc;
}
#endif /* NODUS_HAS_JSONC */

/* ── Public API ──────────────────────────────────────────────────── */

int nodus_server_init(nodus_server_t *srv, const nodus_server_config_t *config) {
    if (!srv || !config) return -1;
    memset(srv, 0, sizeof(*srv));
    srv->config = *config;
    /* 2026-07-21 fd-leak fix: every resource acquired below is released on
     * ANY later init failure (goto fail). Before this, a mid-init failure
     * (e.g. a port bind lost to a concurrent process) leaked the already-
     * bound listen sockets for the life of the process — observed as a test
     * process holding TCP 15001 hostage after "server init failed". Flags
     * (not nodus_server_close) because close() on the zeroed structs of
     * never-initialized members would touch fd 0. */
    bool have_bf = false, have_storage = false, have_media = false,
         have_ch = false, have_tcp = false, have_udp = false,
         have_inter = false;
#ifndef NODUS_CHANNELS_DISABLED
    bool have_chsrv = false;
#endif

    /* PR 3 / E5 — H-10 partial-wipe XOR boot gate. MUST run BEFORE
     * nodus_storage_open / nodus_channel_store_open below — those
     * calls auto-create missing files and would silently mask a
     * partial-wipe accident. Skip when no persistent data_path is
     * configured (dev/test default falls back to /tmp inside the
     * storage opens). */
    if (config->data_path[0] != '\0') {
        if (nodus_server_check_partial_wipe(config->data_path) != 0) {
            return -1;
        }
    }

    /* P2P-PORT F6 — the network file's pin, checked against the chain
     * this node already holds (decision 2026-09-26-witness-port-
     * session.md "Ağ config dosyası": pin set + local chain → must equal,
     * or the node does not start). After the partial-wipe gate, so its
     * message wins on a half-wiped directory; before anything opens a
     * database or a socket. Refusing here makes main() exit 1 — a
     * witness-init failure would not (the process keeps its DHT half). */
    if (config->has_network_pin) {
        /* the witness scans config->data_path as given (nodus_witness.c
         * init), so the same directory is checked here */
        if (nodus_server_check_chain_pin(config->data_path,
                                         config->network_pin) != 0) {
            return -1;
        }
    }

    /* Phase 3.2e FIX: bf_state.batches[].forwards[].fd starts at 0 from
     * memset above, but 0 is a VALID stdio fd (stdin). Cleanup paths use
     * fd >= 0 as "active" check, so uninitialized forwards trigger
     * close(0) and stomp stdin. Initialize all forward fds to -1. */
    for (int bi = 0; bi < NODUS_BF_MAX_BATCHES; bi++) {
        for (int fi = 0; fi < NODUS_BF_MAX_FORWARDS; fi++) {
            srv->bf_state.batches[bi].forwards[fi].fd = -1;
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
        srv->republish.cycle_start = now - NODUS_REPUBLISH_SEC + value_jitter;
        /* Stagger media 60s after value cycle to avoid wbuf contention */
        srv->media_republish.cycle_start = now - NODUS_MEDIA_REPUBLISH_SEC + media_jitter + 60;
    }

    /* Iterative Kademlia lookup engine — no epoll/fd state.
     * All active lookups live in srv->lookup_state (already zeroed by memset). */
    srv->lookup_state.next_txn = 1;

    /* Create batch forward epoll fd */
    srv->bf_state.bf_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (srv->bf_state.bf_epoll_fd < 0) {
        fprintf(stderr, "Failed to create BF epoll fd\n");
        return -1;
    }
    have_bf = true;
    for (int i = 0; i < NODUS_BF_FD_TABLE_SIZE; i++) {
        srv->bf_fd_table[i].batch_idx = -1;
        srv->bf_fd_table[i].forward_idx = -1;
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
        goto fail;
    }
    have_storage = true;

    /* Open media storage (shares same DB handle) */
    if (nodus_media_storage_open(srv->storage.db, &srv->media_storage) != 0) {
        fprintf(stderr, "Failed to open media storage\n");
        goto fail;
    }
    have_media = true;

    /* Open channel storage */
    char ch_db_path[512];
    snprintf(ch_db_path, sizeof(ch_db_path), "%s/channels.db",
             config->data_path[0] ? config->data_path : "/tmp");
    if (nodus_channel_store_open(ch_db_path, &srv->ch_store) != 0) {
        fprintf(stderr, "Failed to open channel store: %s\n", ch_db_path);
        goto fail;
    }
    have_ch = true;

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

    /* Init inter-node circuit table (VPN mesh Faz 1) */
    nodus_inter_circuit_table_init(&srv->inter_circuits);

    /* Init cluster membership (heartbeat, leader election) */
    nodus_cluster_init(&srv->cluster, srv);

    /* Init TCP transport (own epoll) */
    if (nodus_tcp_init(&srv->tcp, -1) != 0)
        goto fail;
    have_tcp = true;
    srv->tcp.on_accept = on_tcp_accept;
    srv->tcp.on_frame = on_tcp_frame;
    srv->tcp.on_disconnect = on_tcp_disconnect;
    srv->tcp.cb_ctx = srv;

    /* Init UDP transport (own epoll — udp_poll uses non-blocking recvfrom) */
    if (nodus_udp_init(&srv->udp, -1) != 0)
        goto fail;
    have_udp = true;
    srv->udp.on_recv = handle_udp_message;
    srv->udp.cb_ctx = srv;

    /* Init inter-node TCP transport (own epoll — shared epoll not possible
     * because listen socket uses NULL data.ptr as marker) */
    uint16_t peer_port = config->peer_port ? config->peer_port : NODUS_DEFAULT_PEER_PORT;
    if (peer_port == config->tcp_port) {
        fprintf(stderr, "ERROR: peer_port (%d) must differ from tcp_port (%d)\n",
                peer_port, config->tcp_port);
        goto fail;
    }
    if (nodus_tcp_init(&srv->inter_tcp, -1) != 0)
        goto fail;
    have_inter = true;
    srv->inter_tcp.on_accept     = on_inter_accept;
    srv->inter_tcp.on_connect    = on_inter_connect;
    srv->inter_tcp.on_frame      = on_inter_frame;
    srv->inter_tcp.on_disconnect = on_inter_disconnect;
    srv->inter_tcp.cb_ctx        = srv;
    srv->inter_tcp.auth_required = srv->config.require_peer_auth;
    srv->inter_tcp.auth_ctx      = &srv->identity;
    /* Phase 3: hint-table fallback when pending queue is saturated. */
    srv->inter_tcp.on_pending_full   = server_on_pending_full;
    srv->inter_tcp.pending_full_ctx  = srv;

    /* Bind TCP (client port) */
    if (nodus_tcp_listen(&srv->tcp, config->bind_ip, config->tcp_port) != 0) {
        fprintf(stderr, "Failed to listen on TCP %s:%d (%s)\n",
                config->bind_ip, config->tcp_port, strerror(errno));
        goto fail;
    }

    /* Bind inter-node TCP (peer port) */
    if (nodus_tcp_listen(&srv->inter_tcp, config->bind_ip, peer_port) != 0) {
        fprintf(stderr, "Failed to listen on inter-node TCP %s:%d (%s)\n",
                config->bind_ip, peer_port, strerror(errno));
        goto fail;
    }

    /* WebSocket entry (decision 2026-09-25-web-wallet-nodus-send-transport):
     * a second listening socket of the CLIENT transport, 127.0.0.1 only.
     * Its connections live in srv->tcp's pool and slot space, so
     * session_for_conn, the same-identity eviction (nodus_auth.c) and
     * idle_timeout_sweep cover them without change. */
    if (config->ws_port != 0) {
        uint16_t ws_port = config->ws_port;
        if (ws_port == config->tcp_port || ws_port == peer_port ||
            ws_port == config->witness_port || ws_port == config->ch_port) {
            QGP_LOG_ERROR(LOG_TAG, "ws_port %u collides with another TCP port "
                          "(tcp %u, peer %u, witness %u, channel %u)",
                          (unsigned)ws_port, (unsigned)config->tcp_port,
                          (unsigned)peer_port, (unsigned)config->witness_port,
                          (unsigned)config->ch_port);
            goto fail;
        }
        /* The list the transport reads lives in srv->config (stable for
         * the server's lifetime); fill the default there. */
        if (srv->config.ws_origins.count <= 0)
            nodus_ws_origins_default(&srv->config.ws_origins);
        if (nodus_tcp_ws_listen(&srv->tcp, ws_port, &srv->config.ws_origins) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to listen on WebSocket entry 127.0.0.1:%u (%s)",
                          (unsigned)ws_port, strerror(errno));
            goto fail;
        }
        QGP_LOG_INFO(LOG_TAG, "WebSocket entry listening on 127.0.0.1:%u, %d allowed origin(s)",
                     (unsigned)srv->tcp.ws_port, srv->config.ws_origins.count);
        for (int i = 0; i < srv->config.ws_origins.count; i++)
            QGP_LOG_INFO(LOG_TAG, "  ws origin: %s", srv->config.ws_origins.origin[i]);
    }

    /* Channel server (TCP 4003) — DISABLED: heap corruption in ring/replication.
     * Channel system has known memory safety issues causing SIGABRT crashes.
     * Disabled until root cause is fixed. See commit history for re-enable. */
#ifndef NODUS_CHANNELS_DISABLED
    if (nodus_channel_server_init(&srv->ch_server) != 0)
        goto fail;
    have_chsrv = true;

    srv->ch_server.ch_store = &srv->ch_store;
    srv->ch_server.ring = &srv->ring;
    srv->ch_server.identity = &srv->identity;
    const char *ch_self_ip = config->external_ip[0] ? config->external_ip : config->bind_ip;
    snprintf(srv->ch_server.self_ip, sizeof(srv->ch_server.self_ip), "%s", ch_self_ip);

    uint16_t ch_port = config->ch_port ? config->ch_port : NODUS_DEFAULT_CH_PORT;
    if (ch_port == config->tcp_port || ch_port == peer_port) {
        fprintf(stderr, "ERROR: ch_port (%d) must differ from tcp_port (%d) and peer_port (%d)\n",
                ch_port, config->tcp_port, peer_port);
        goto fail;
    }
    if (nodus_channel_server_listen(&srv->ch_server, config->bind_ip, ch_port) != 0) {
        fprintf(stderr, "Failed to listen on channel TCP %s:%d (%s)\n",
                config->bind_ip, ch_port, strerror(errno));
        goto fail;
    }

    nodus_ch_replication_init(&srv->ch_replication, &srv->ch_server);
    nodus_ch_ring_init(&srv->ch_ring, &srv->ch_server);

    srv->ch_server.on_post = ch_on_post_callback;
    srv->ch_server.cb_ctx = srv;
    srv->ch_server.dht_put_signed = ch_dht_put_signed;
    srv->ch_server.dht_ctx = srv;
    srv->ch_server.ch_ring_ptr = &srv->ch_ring;
    srv->ch_server.ch_replication_ptr = &srv->ch_replication;
#else
    fprintf(stderr, "  Channels: DISABLED (NODUS_CHANNELS_DISABLED)\n");
#endif

    /* The witness port (4004) — P2P-PORT F5: it is opened by the
     * witness's p2p host (nodus_witness_p2p_new, from nodus_witness_init
     * below), not by a nodus_tcp transport; only the port-collision check
     * stays here. */
    uint16_t witness_port = config->witness_port ? config->witness_port : NODUS_DEFAULT_WITNESS_PORT;
#ifndef NODUS_CHANNELS_DISABLED
    if (witness_port == config->tcp_port || witness_port == peer_port || witness_port == ch_port) {
        fprintf(stderr, "ERROR: witness_port (%d) must differ from tcp_port (%d), "
                "peer_port (%d), and ch_port (%d)\n",
                witness_port, config->tcp_port, peer_port, ch_port);
        goto fail;
    }
#else
    if (witness_port == config->tcp_port || witness_port == peer_port) {
        fprintf(stderr, "ERROR: witness_port (%d) must differ from tcp_port (%d) "
                "and peer_port (%d)\n",
                witness_port, config->tcp_port, peer_port);
        goto fail;
    }
#endif

    /* Bind UDP */
    if (nodus_udp_bind(&srv->udp, config->bind_ip, config->udp_port) != 0) {
        fprintf(stderr, "Failed to bind UDP %s:%d (%s)\n",
                config->bind_ip, config->udp_port, strerror(errno));
        goto fail;
    }

    /* Add seed nodes to cluster.
     * Seeds don't have node_ids yet — they'll be discovered via PING/PONG.
     * For now, create placeholder node_ids from the seed's ENDPOINT. The
     * real node_id will be learned when the seed responds to our PING.
     *
     * O15B.1 — the placeholder used to be a hash of the IP STRING alone,
     * while nodus_cluster_add_peer deduplicates on the id. Every seed on
     * a shared address therefore collapsed onto one peer, and six of the
     * harness's seven seeds were dropped without a word. Downstream that
     * left one Kademlia routing entry and a DHT replication fan-out of
     * one, which is what stranded a joining witness in bootstrap
     * DISCOVER (nodus/BUGS.md). Keyed by ip:udp_port the seeds stay
     * distinct.
     *
     * A node is also NOT its own seed. The Stage F harness — and any
     * co-located deployment — hands every node the full seed list,
     * itself included; without this skip the node registers a phantom
     * peer for its own address, heartbeats itself, and injects a
     * placeholder-id entry for itself into its own routing table, where
     * it consumes a replication slot forever (nodus_cluster_on_pong
     * rewrites the cluster row's id but never the routing entry). */
    {
        const char *self_ip = config->external_ip[0] ? config->external_ip
                                                     : config->bind_ip;
        for (int i = 0; i < config->seed_count; i++) {
            if (config->seed_ports[i] == config->udp_port &&
                strcmp(config->seed_nodes[i], self_ip) == 0) {
                fprintf(stderr,
                        "CLUSTER: skipping own address %s:%u in seed list\n",
                        config->seed_nodes[i],
                        (unsigned)config->seed_ports[i]);
                continue;
            }
            nodus_key_t seed_id;
            nodus_cluster_seed_placeholder_id(config->seed_nodes[i],
                                              config->seed_ports[i],
                                              &seed_id);
            nodus_cluster_add_peer(&srv->cluster, &seed_id,
                                  config->seed_nodes[i],
                                  config->seed_ports[i],
                                  config->seed_ports[i] + 2);  /* Peer TCP = UDP + 2 */
        }
    }

    /* Initialize witness module (all nodes are automatic witnesses) */
    srv->witness = calloc(1, sizeof(nodus_witness_t));
    if (!srv->witness) {
        fprintf(stderr, "Failed to allocate witness context\n");
        goto fail;
    }
    if (nodus_witness_init(srv->witness, srv, &config->witness) != 0) {
        free(srv->witness);
        srv->witness = NULL;

        /* ── O15L Faz 2 — A DEGRADED NODE SAYS SO, LOUDLY ─────────────
         *
         * This used to be two lines — "Witness module init failed" and
         * "WARNING: running without witness module" — and neither said
         * what it COSTS. A reader had to already know that the witness
         * module is the consensus role to understand that the node just
         * stopped validating blocks, voting and certifying, and would go
         * on serving DHT traffic as if nothing had happened. In a journal
         * full of startup chatter that is indistinguishable from noise.
         *
         * The process deliberately does NOT exit. nodus is dual-role, and
         * the DHT half is fine; killing it to retire the witness half
         * costs a working service for nothing. Worse, exiting is not free
         * even for the witness half: nodus/deploy/nodus.service carries
         * Restart=on-failure with StartLimitBurst=3 and
         * StartLimitIntervalSec=300, so three exits inside five minutes
         * leave the unit permanently stopped — the failure mode a
         * transient database fault must not be able to cause. The
         * witness-less mode is safe, not latent — but NOT because every
         * call site is guarded, which is what this comment used to claim
         * and is false. P2P-PORT F5: the two tier-3 dispatch sites this
         * paragraph used to describe are deleted — a witness-less node
         * opens no port 4004 at all (its p2p host lives inside the
         * witness), and the client port refuses `w_*` methods regardless.
         *
         * The periodic nodus_witness_tick call in the server loop is
         * guarded by `if (srv->witness)` AND NULL-checks its own argument
         * (`if (!witness || !witness->running) return;`), so that one is
         * safe from either side.
         *
         * fprintf(stderr) rather than QGP_LOG_ERROR matches the block
         * this replaces and the adjacent init logging (this file uses
         * both); the witness module logs exclusively this way, so the
         * WITNESS lines this message points at are interleaved with it in
         * the journal rather than filtered separately. */
        fprintf(stderr,
            "ERROR: WITNESS MODULE INIT FAILED — THIS NODE IS RUNNING "
            "DEGRADED\n");
        fprintf(stderr,
            "ERROR:   consensus: NOT PARTICIPATING. This node validates no "
            "block, casts no vote,\n"
            "ERROR:              signs no certificate and produces no "
            "block for as long as it runs.\n");
        fprintf(stderr,
            "ERROR:   DHT:       unaffected — Kademlia, storage and client "
            "service continue.\n");
        fprintf(stderr,
            "ERROR:   cause:     named in the WITNESS lines above — a chain "
            "database that is\n"
            "ERROR:              PRESENT but unusable (with its sqlite "
            "fault), a refused startup\n"
            "ERROR:              gate, or an unmet bootstrap "
            "precondition.\n");
        fprintf(stderr,
            "ERROR:   action:    the process is NOT exiting on purpose "
            "(nodus.service would stop\n"
            "ERROR:              the unit after 3 restarts in 300 s, "
            "retiring the DHT role too).\n"
            "ERROR:              Fix the database, then restart this "
            "node.\n");
    }

    /* ── O16A — ARM THE PARTIAL-WIPE GATE, HERE AND NOWHERE ELSE ──────
     *
     * WHAT THE MARKER ASSERTS. Not "a chain exists" — "this node has
     * completed a normal boot with a chain". That distinction is the
     * whole reason this write sits at the bottom of init rather than
     * where a chain is first produced. The gate it arms
     * (nodus_server_check_partial_wipe, called near the top of this
     * function) demands that nodus.db, channels.db and witness_*.db be
     * all-present or all-absent, and refuses the start otherwise. The
     * three are not functionally coupled; the rule is an ACCIDENT
     * DETECTOR for an operator who removed one of them by hand
     * (docs/BOOTSTRAP.md, "Operator wiped one of the 3 SQLite DBs by
     * accident"). Arming it is only honest once all three are real.
     *
     * WHY NOT IN THE V2 GENESIS BUILDER. That was the first cut and it
     * was wrong: the genesis derivation (nodus_witness_v2_gen_derive_v3
     * today; the version-2 nodus_witness_v2_gen_derive where the defect
     * was found is deleted, tokenomics-v3 P4) runs as an offline one-shot
     * that creates exactly ONE of the three, and this gate runs BEFORE
     * nodus_storage_open and nodus_channel_store_open create the other
     * two. A marker written there fails the gate on the very next start
     * of a freshly provisioned host, and the refusal's printed remedy is
     * to delete all three — the chain the ceremony just produced.
     *
     * WHAT THIS PLACEMENT ALSO FIXES, for free:
     *   - a crash or a failed write during the ceremony self-heals on the
     *     next boot, because this runs on every successful start;
     *   - a node that JOINED rather than derived is covered, which the
     *     builder-side write structurally could not do — the joiner
     *     builds in its own scratch directory (nodus_witness_v2_join.c)
     *     and nodus_witness_create_chain_db's own marker write lands
     *     there and is discarded with it (nodus_witness.c:1173-1180);
     *   - a legacy node keeps the behaviour it already had: its
     *     create_chain_db wrote the marker at genesis, and re-writing an
     *     existing file changes nothing.
     *
     * GATED ON AN OPEN CHAIN. `srv->witness->db` is non-NULL only when a
     * chain database was found and opened (nodus_witness_scan_chain_db).
     * A pre-genesis node has no chain, has not crossed the boundary the
     * marker records, and must not arm the gate — doing so would make
     * its perfectly legitimate two-of-three state a refusal.
     *
     * NOT FATAL, BUT LOUD. A node is not worse off for a missing marker
     * than it is today, and the next boot retries; but a gate silently
     * staying open is exactly what an operator would never otherwise
     * learn. The file's presence is the signal — its contents are never
     * read. */
    if (srv->witness && srv->witness->db) {
        char marker[640];
        int mk = snprintf(marker, sizeof(marker), "%s/%s",
                          config->data_path[0] ? config->data_path : "/tmp",
                          NODUS_PARTIAL_WIPE_GENESIS_MARKER);
        if (mk < 0 || (size_t)mk >= sizeof(marker)) {
            fprintf(stderr,
                "NODUS_SRV: WARNING data path too long to form %s — the "
                "partial-wipe gate stays OPEN on this node\n",
                NODUS_PARTIAL_WIPE_GENESIS_MARKER);
        } else {
            FILE *mf = fopen(marker, "w");
            if (mf) {
                fclose(mf);
            } else {
                fprintf(stderr,
                    "NODUS_SRV: WARNING failed to write %s: %s — the "
                    "partial-wipe gate stays OPEN on this node's next "
                    "boot\n", marker, strerror(errno));
            }
        }
    }

    return 0;

fail:
    /* Release everything acquired before the failure — a caller retry (or a
     * failed test process kept alive by its harness) must not keep ports or
     * DB handles hostage. Flag-guarded: never touches a member whose _init
     * did not run (zeroed struct fds would alias fd 0). */
#ifndef NODUS_CHANNELS_DISABLED
    if (have_chsrv) nodus_channel_server_close(&srv->ch_server);
#endif
    if (have_inter) nodus_tcp_close(&srv->inter_tcp);
    if (have_udp) nodus_udp_close(&srv->udp);
    if (have_tcp) nodus_tcp_close(&srv->tcp);
    if (have_ch) nodus_channel_store_close(&srv->ch_store);
    if (have_media) nodus_media_storage_close(&srv->media_storage);
    if (have_storage) nodus_storage_close(&srv->storage);
    if (have_bf) {
        close(srv->bf_state.bf_epoll_fd);
        srv->bf_state.bf_epoll_fd = -1;
    }
    nodus_identity_clear(&srv->identity);
    return -1;
}

int nodus_server_run(nodus_server_t *srv) {
    if (!srv) return -1;

    /* A stop that already arrived must not be resurrected. `running` is
     * set below, so a SIGTERM delivered while nodus_server_init() was
     * still working (storage migration, VACUUM, identity generation)
     * would be overwritten here and the process would then ignore the
     * signal forever — it never blocks long enough to be interrupted
     * again, it just polls. See stop_requested in nodus_server.h. */
    if (srv->stop_requested) {
        fprintf(stderr, "Nodus: stop requested during init — not starting\n");
        return 0;
    }

    srv->running = true;
    srv->start_time = (uint64_t)time(NULL);

    fprintf(stderr, "Nodus v%s running\n", NODUS_VERSION_STRING);
    fprintf(stderr, "  Identity: %s\n", srv->identity.fingerprint);
    fprintf(stderr, "  TCP port: %d\n", srv->tcp.port);
    fprintf(stderr, "  Peer port: %d\n", srv->inter_tcp.port);
    fprintf(stderr, "  Witness port: %d%s\n",
            srv->witness ? (int)nodus_witness_p2p_listen_port(srv->witness->p2p) : 0,
            (srv->witness && srv->witness->p2p) ? "" : " (not opened)");
#ifndef NODUS_CHANNELS_DISABLED
    fprintf(stderr, "  Channel port: %d\n", srv->ch_server.port);
#endif
    fprintf(stderr, "  UDP port: %d\n", srv->udp.port);

    while (srv->running && !srv->stop_requested) {
        /* Read budget: while either transport has connections left on its
         * pending-read list, neither poll may block — nodus_tcp_poll waits
         * 0 ms only for its OWN list, so the sibling's 50 ms wait would
         * delay that input. Re-evaluated before each call: the first poll
         * can fill or empty a list. The UDP socket is not in either epoll:
         * when the last nodus_udp_poll() stopped at its read budget,
         * neither poll may block either, or queued datagrams would wait
         * up to 2 x 50 ms per budget. */
        int poll_ms = (nodus_tcp_read_pending(&srv->tcp) ||
                       nodus_tcp_read_pending(&srv->inter_tcp) ||
                       nodus_udp_read_pending(&srv->udp)) ? 0 : 50;

        /* Poll client TCP events (plain port and, when enabled, the
         * WebSocket entry — same transport) */
        nodus_tcp_poll(&srv->tcp, poll_ms);

        /* WebSocket entry: close Upgrades not finished within
         * NODUS_WS_HANDSHAKE_TIMEOUT_S. Local connection housekeeping only. */
        if (srv->tcp.ws_listen_fd >= 0)
            nodus_tcp_ws_sweep(&srv->tcp, nodus_time_now());

        /* Poll inter-node TCP events */
        poll_ms = (nodus_tcp_read_pending(&srv->tcp) ||
                   nodus_tcp_read_pending(&srv->inter_tcp) ||
                   nodus_udp_read_pending(&srv->udp)) ? 0 : 50;
        nodus_tcp_poll(&srv->inter_tcp, poll_ms);

        /* The witness port 4004 (the p2p host) is polled inside
         * nodus_witness_tick() */

#ifndef NODUS_CHANNELS_DISABLED
        /* Poll new channel server (TCP 4003) */
        nodus_channel_server_poll(&srv->ch_server, 50);
#endif

        /* Process any pending UDP datagrams */
        nodus_udp_poll(&srv->udp);

        /* Cluster: send heartbeats, check peer health */
        nodus_cluster_tick(&srv->cluster);

        /* Ping-before-evict: evict LRU peers that didn't respond */
        eviction_sweep(srv);

        /* CRIT-4: Disconnect idle TCP connections */
        idle_timeout_sweep(srv);

        /* Witness: the 4004 p2p host and the consensus lane */
        if (srv->witness)
            nodus_witness_tick(srv->witness);

#ifndef NODUS_CHANNELS_DISABLED
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
#endif

        /* Presence: expire stale entries + broadcast local list to peers */
        nodus_presence_tick(srv);

        /* Retry DHT hinted handoff (failed replication, every 30s) */
        dht_hinted_retry(srv);

        /* Listen-forward subscription cleanup (every 60s) */
        {
            uint64_t now_sec = nodus_time_now();
            if (now_sec - srv->last_sub_cleanup > 60) {
                subscription_cleanup_expired(&srv->subscriptions);
                srv->last_sub_cleanup = now_sec;
            }
        }

        /* Periodic subscription renewal (re-forward local LISTENs to K-closest).
         * Rate-limited internally to NODUS_SUB_RENEWAL_PER_TICK per call. */
        subscription_renew_tick(srv);

        /* Iterative Kademlia FIND_NODE lookup engine tick */
        iterative_lookup_tick(srv);

        /* Batch forward async tick */
        bf_tick(srv);

        /* Kademlia bucket refresh (every 15 min) */
        dht_bucket_refresh(srv);

        /* Storage cleanup — remove expired values (every 1 hour) */
        dht_storage_cleanup(srv);

        /* Periodic republish — send stored values to R-closest (every 1 hour) */
        dht_republish(srv);

        /* Periodic media republish — send stored media to R-closest (every 24 hours) */
        dht_media_republish(srv);

        /* WAL checkpoint — truncate WAL file (every 5 min) */
        dht_wal_checkpoint(srv);

        /* Incremental vacuum — reclaim freelist pages (every 24 hours) */
        dht_incremental_vacuum(srv);

        /* Phase 1 visibility: per-peer send counter dump (every 5 min) */
        dht_send_stats_dump(srv);
    }

    return 0;
}

void nodus_server_stop(nodus_server_t *srv) {
    if (!srv) return;
    /* Latch FIRST: nodus_server_run() consults stop_requested before it
     * sets running, so a stop delivered during init is not lost. */
    srv->stop_requested = 1;
    srv->running = false;
}

void nodus_server_close(nodus_server_t *srv) {
    if (!srv) return;

    /* Clean up any active iterative lookups (free callback data) */
    for (int i = 0; i < NODUS_LOOKUP_MAX_INFLIGHT; i++) {
        iterative_lookup_t *l = &srv->lookup_state.lookups[i];
        if (!l->active) continue;
        if (l->cb_data && l->cb_data_free) l->cb_data_free(l->cb_data);
        l->cb_data = NULL;
        l->cb_data_free = NULL;
        l->active = false;
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

    if (srv->witness) {
        nodus_witness_close(srv->witness);
        free(srv->witness);
        srv->witness = NULL;
    }

#ifndef NODUS_CHANNELS_DISABLED
    nodus_channel_server_close(&srv->ch_server);
#endif
    nodus_tcp_close(&srv->tcp);
    nodus_tcp_close(&srv->inter_tcp);
    nodus_udp_close(&srv->udp);
    nodus_media_storage_close(&srv->media_storage);
    nodus_storage_close(&srv->storage);
    nodus_channel_store_close(&srv->ch_store);
    nodus_identity_clear(&srv->identity);
}
