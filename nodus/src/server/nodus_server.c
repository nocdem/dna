/**
 * Nodus — Server Core Implementation
 *
 * Dual-transport event loop: UDP (Kademlia) + TCP (data + clients).
 * Handles: auth, sessions, PING, presence, circuits, the 4002 handshake,
 * cluster heartbeat, status — and routes the DHT's requests (PUT, GET,
 * GET_ALL, LISTEN, Kademlia queries, replication frames) to the DHT half
 * through server/nodus_dht_backend.h (split S4; the DHT code is
 * dht/nodus_dht_server.c).
 */

#include "server/nodus_server.h"
#include "server/nodus_chain_backend.h"     /* the witness, behind one door */
#include "witness/nodus_witness_ipc.h"      /* NODUS_WITNESS_IPC_SOCK_NAME (S3) */
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
#include <sys/socket.h>
#include <errno.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* Response buffer (shared, single-threaded).
 * Must accommodate max value (1MB data) + Dilithium5 pk(2592) + sig(4627) + CBOR.
 * Previous 64KB was too small — values >55KB data caused silent GET failures. */
#define RESP_BUF_SIZE (NODUS_MAX_VALUE_SIZE + 65536)
static uint8_t resp_buf[RESP_BUF_SIZE];

/* Channel post signature verification is now in nodus_channel_primary.c */

/* Forward declaration for inter_tcp pool send (the DHT host's inter_send) */
static int dht_republish_send(nodus_server_t *srv, const char *ip,
                               uint16_t port,
                               const nodus_key_t *expected_node_id,
                               const uint8_t *frame, size_t flen);

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

/* The DHT origin of a 4002 session: its connection's slot (the index
 * inter_session_for_conn uses); -1 without a connection. */
static int inter_origin_slot(const nodus_inter_session_t *sess) {
    return sess->conn ? sess->conn->slot : -1;
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

/* Split S5a, decision item 33: is this 4002 payload a DHT REPLICATION frame
 * — the only kind the hint table may hold? Rule: the payload is a CBOR map
 * whose envelope says query ("y" == "q") and whose method ("q") is "sv" or
 * "m_sv". Those are exactly the frames the DHT builds with
 * nodus_t1_store_value (replication on put, republish, hinted retry) and
 * nodus_t2_media_store_value (media chunk replication); T1 and T2 encode
 * the envelope with the same bytes (`y` = text "q", `q` = method text).
 * Everything else — p_sync, ri_*, ntf, sub / unsub, and every reply or
 * error ("y" == "r" / "e": fv_r, sv_ack, get_batch results, ...) — is not.
 * Only the envelope is read; the value is not parsed. */
static bool pending_full_is_replication(const uint8_t *payload, size_t len) {
    cbor_decoder_t dec;
    cbor_decoder_init(&dec, payload, len);
    cbor_item_t top = cbor_decode_next(&dec);
    if (top.type != CBOR_ITEM_MAP) return false;
    bool is_query = false, is_repl = false, saw_y = false, saw_q = false;
    for (size_t i = 0; i < top.count && !dec.error && !(saw_y && saw_q); i++) {
        cbor_item_t k = cbor_decode_next(&dec);
        if (k.type != CBOR_ITEM_TSTR) return false;
        if (k.tstr.len == 1 && (k.tstr.ptr[0] == 'y' || k.tstr.ptr[0] == 'q')) {
            char which = k.tstr.ptr[0];
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type != CBOR_ITEM_TSTR) return false;
            if (which == 'y') {
                saw_y = true;
                is_query = v.tstr.len == 1 && v.tstr.ptr[0] == 'q';
            } else {
                saw_q = true;
                is_repl = (v.tstr.len == 2 && memcmp(v.tstr.ptr, "sv", 2) == 0) ||
                          (v.tstr.len == 4 && memcmp(v.tstr.ptr, "m_sv", 4) == 0);
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }
    return !dec.error && is_query && is_repl;
}

/* Invoked by the TCP layer when a send cannot fit into wbuf AND the
 * per-conn pending queue is also at its cap. A DHT replication frame is
 * persisted to the DHT hinted handoff table so it can be delivered when
 * the peer has drained — same path that periodic republish already uses.
 * Any other frame is dropped (decision item 33).
 *
 * Dedup key policy: the authenticated peer identity (peer_id), so
 * retries bucket with the canonical node_id. DHT Package A F4: a conn
 * without an authenticated peer_id persists nothing (the former synthetic
 * SHA3-512("ip:port") fallback is gone); the per-peer and whole-table caps
 * live in nodus_storage_hinted_insert. */
void nodus_server_on_pending_full(nodus_tcp_conn_t *conn,
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
    /* Decision item 33: only DHT replication frames are parked; p_sync,
     * ri_*, notifications, subscriptions and relayed replies are dropped
     * (their senders repeat them or their requester times out). */
    if (!pending_full_is_replication(payload, len)) {
        QGP_LOG_WARN(LOG_TAG, "PENDING_FULL: peer=%s:%u len=%zu not a "
                     "replication frame — frame DROPPED (no hint)",
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

    /* The hint table is the DHT's (nodus.db): parked there through the
     * seam, with the insert's result back for the log lines below. */
    int rc = srv->dht->ops->hint_store(srv->dht, &dedup_id,
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

/* ── Outbound 4002 dial (find-or-dial, identity pinned) ────────────── */

nodus_tcp_conn_t *nodus_server_inter_dial(nodus_server_t *srv, const char *ip,
                                          uint16_t port,
                                          const nodus_key_t *expected_node_id) {
    nodus_tcp_conn_t *conn = nodus_tcp_find_by_addr(&srv->inter_tcp, ip, port);
    if (conn) return conn;
    conn = nodus_tcp_connect(&srv->inter_tcp, ip, port);
    if (!conn) return NULL;
    conn->is_nodus = true;
    /* CRIT-1: record WHO we believe we are dialing, from the routing/roster
     * entry that produced this ip:port. The auth_ok handler pins
     * fingerprint(server_pk) against it before Kyber-encapsulating, so an
     * on-path attacker cannot substitute its own identity. Stored on the
     * conn (not the session): on_inter_connect clears the session, and on
     * an immediate (localhost) connect it has already run inside
     * nodus_tcp_connect above — the dialer reads the pin from the conn at
     * auth_ok time. */
    if (expected_node_id) {
        conn->expected_peer_id = *expected_node_id;
        conn->expected_peer_id_set = true;
    }
    /* on_inter_connect callback handles auth_required + hello */
    return conn;
}

/* ── Periodic republish (via inter_tcp pool) ────────────────────── */

/** Send a pre-framed replication payload via persistent inter_tcp pool.
 *  Frame is already wire-encoded (nodus_frame_encode already called by caller).
 *  Returns 0 on success, -1 on failure (caller should use hinted handoff). */
static int dht_republish_send(nodus_server_t *srv, const char *ip,
                               uint16_t port,
                               const nodus_key_t *expected_node_id,
                               const uint8_t *frame, size_t flen) {
    nodus_tcp_conn_t *conn = nodus_server_inter_dial(srv, ip, port,
                                                     expected_node_id);
    if (!conn) return -1;

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

        /* Open or reuse inter-node TCP 4002 connection to peer nodus, the
         * cluster member's node_id pinned (decision item 30). The member is
         * ALIVE (find_cluster_peer_by_idx), so its node_id is the real one:
         * ALIVE is set only after a PONG, which replaces a seed's
         * placeholder id first (nodus_cluster_on_pong). */
        nodus_tcp_conn_t *pconn = nodus_server_inter_dial(
            srv, peer_node->ip, peer_node->tcp_port, &peer_node->node_id);
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

static void handle_t2_ping(nodus_server_t *srv, nodus_session_t *sess,
                            nodus_tier2_msg_t *msg) {
    (void)srv;
    size_t len = 0;
    nodus_t2_pong(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
    nodus_tcp_send(sess->conn, resp_buf, len);
}

/* Cluster-status query handler (Phase 0 / Task 0.2).
 * Reports this nodus-server's own block_height, state_root, chain_id,
 * peer count, uptime and wall clock. All fields are public and
 * authenticated only by the existing tier2 session token. */
static void handle_t2_status(nodus_server_t *srv, nodus_session_t *sess,
                              nodus_tier2_msg_t *msg) {
    nodus_t2_status_info_t info;
    memset(&info, 0, sizeof(info));

    /* block_height / state_root / chain_id of the open chain
     * (nodus_chain_backend_inproc.c inproc_status); zero without one. */
    if (srv->chain)
        srv->chain->ops->status(srv->chain, &info);

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

/* ── The dialer handshake's host side (split S5a, decision item 28) ── */

/* On a conn we dialed, core's session flag and the dialer module's are the
 * same fact: an auth_ok was received. Core's gates (F2/F3, "authenticate
 * first") read sess->authenticated, the module reads d->authenticated —
 * carried into the module before each call, and back out (with the proven
 * peer identity, F4) to the session and the conn after it. */
static void inter_dial_sync_out(nodus_inter_session_t *sess) {
    const nodus_inter_dial_t *d = &sess->dial;
    if (d->authenticated) {
        sess->authenticated = true;
        sess->conn->authenticated = true;
    }
    if (d->peer_id_set) {
        /* F4: like the accepting side does after auth, so pending-full
         * hints key on a real identity. */
        sess->conn->peer_id = d->peer_id;
        sess->conn->peer_pk = d->peer_pk;
        sess->conn->peer_id_set = true;
    }
}

static int inter_dial_send_raw(void *ctx, const uint8_t *payload, size_t len) {
    nodus_inter_session_t *sess = (nodus_inter_session_t *)ctx;
    return nodus_tcp_send_raw(sess->conn, payload, len);
}

/* The hello's send (on_inter_connect): ctx is the conn itself. */
static int inter_dial_send_raw_conn(void *ctx, const uint8_t *payload, size_t len) {
    return nodus_tcp_send_raw((nodus_tcp_conn_t *)ctx, payload, len);
}

static void inter_dial_established(void *ctx, bool encrypted) {
    nodus_inter_session_t *sess = (nodus_inter_session_t *)ctx;
    nodus_tcp_conn_t *conn = sess->conn;
    inter_dial_sync_out(sess);
    conn->auth_state = NODUS_CONN_AUTH_OK;
    if (!encrypted) {
        /* No Kyber identity on this node: plaintext is the only option —
         * release what was queued during the handshake. */
        nodus_tcp_pending_flush(conn);
        return;
    }
    /* Session key set. DISCARD the pending queue — it contains pre-framed
     * plaintext that would bypass encryption. Inter-node queued frames are
     * periodic (heartbeat/repl) and will be re-sent on next cycle. */
    if (conn->pending_buf) {
        free(conn->pending_buf);
        conn->pending_buf = NULL;
        conn->pending_len = 0;
        conn->pending_cap = 0;
    }
    QGP_LOG_INFO(LOG_TAG, "INTER_CRYPTO: outgoing conn to %s:%d encrypted",
                 conn->ip, conn->port);
}

static void inter_dial_io(nodus_server_t *srv, nodus_inter_session_t *sess,
                          nodus_inter_dial_io_t *io) {
    nodus_tcp_conn_t *conn = sess->conn;
    memset(io, 0, sizeof(*io));
    io->identity = &srv->identity;
    /* CRIT-1: the pin recorded at dial time (nodus_server_inter_dial),
     * read from the conn now — never cached in the session. */
    io->expected_peer_id = conn->expected_peer_id_set ? &conn->expected_peer_id
                                                      : NULL;
    io->crypto = &conn->channel_crypto;
    io->peer_ip = conn->ip;
    io->peer_port = conn->port;
    io->slot = conn->slot;
    io->send_raw = inter_dial_send_raw;
    io->established = inter_dial_established;
    io->ctx = sess;
}

/* One received T2 frame through the dialer module, on a conn we DIALED
 * (sess->conn non-NULL, auth_initiated_by_us). On an accepted conn the
 * role split above has already disconnected any challenge / auth_ok /
 * key_ack, so the module is not consulted there. */
static nodus_inter_dial_rc_t inter_dial_frame(nodus_server_t *srv,
                                              nodus_inter_session_t *sess,
                                              const nodus_tier2_msg_t *msg) {
    nodus_inter_dial_io_t io;
    inter_dial_io(srv, sess, &io);
    if (sess->authenticated) sess->dial.authenticated = true;
    nodus_inter_dial_rc_t rc = nodus_inter_dial_on_frame(&sess->dial, &io, msg);
    inter_dial_sync_out(sess);
    return rc;
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
         * node opened the conn, sent hello, now receives challenge /
         * auth_ok / key_ack): the shared dialer module (split S5a, decision
         * item 28 — server/nodus_inter_dial.h, the code that was inline
         * here). These must be handled regardless of require_peer_auth —
         * they complete auth initiated by us.
         *
         * C2 fix: enforce outbound-only gate — now the role split above: a
         * challenge on an inbound conn disconnects before this point, so
         * this node never signs a nonce an accepted peer chose (closes the
         * Dilithium5 oracle). */
        if (sess->conn && sess->conn->auth_initiated_by_us) {
            nodus_inter_dial_rc_t drc = inter_dial_frame(srv, sess, &msg);
            if (drc == NODUS_INTER_DIAL_REFUSED) {
                /* CRIT-1 fail-closed (the module logged why). */
                sess->conn->auth_state = NODUS_CONN_AUTH_FAILED;
                nodus_t2_msg_free(&msg);
                nodus_tcp_disconnect(&srv->inter_tcp, sess->conn);
                return;
            }
            if (drc == NODUS_INTER_DIAL_DONE) {
                nodus_t2_msg_free(&msg);
                return;
            }
        }
        if (strcmp(msg.method, "error") == 0) {
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
            /* Inter-node FIND_VALUE — the DHT's (nodus_dht_inter_request) */
            srv->dht->ops->inter_frame(srv->dht, inter_origin_slot(sess),
                                       payload, len, &msg);
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
            /* Inter-node forwarded get_batch — local-only, no re-forward:
             * the DHT's (nodus_dht_inter_request) */
            srv->dht->ops->inter_frame(srv->dht, inter_origin_slot(sess),
                                       payload, len, &msg);
            nodus_t2_msg_free(&msg);
            return;
        }

        /* ch_rep, ring_check, ring_ack, ring_evict now go via TCP 4003 (channel server) */

        if (strcmp(msg.method, "m_sv") == 0 && msg.has_media) {
            /* Inter-node media replication: store replicated media chunk —
             * the DHT's (nodus_dht_inter_request) */
            srv->dht->ops->inter_frame(srv->dht, inter_origin_slot(sess),
                                       payload, len, &msg);
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

        if ((strcmp(t1msg.method, "sv") == 0 && t1msg.value) ||
            strcmp(t1msg.method, "sub") == 0 ||
            strcmp(t1msg.method, "unsub") == 0 ||
            (strcmp(t1msg.method, "ntf") == 0 && t1msg.value)) {
            /* STORE_VALUE (replication), SUBSCRIBE_FWD / unsubscribe (a
             * remote listener), NOTIFY (for a local listener) — the DHT's
             * (nodus_dht_inter_t1), with this session's peer identity */
            srv->dht->ops->inter_t1(srv->dht, inter_origin_slot(sess),
                                    &sess->client_fp,
                                    sess->conn ? sess->conn->ip : "",
                                    payload, len, &t1msg);

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

/* Item 29: a fresh generation for a session core opens (client accept,
 * 4002 connect / accept). One server-wide counter; it only increases. */
static uint64_t session_gen_next(nodus_server_t *srv) {
    return ++srv->next_session_gen;
}

/* The DHT's shadow of a 4002 session (its rate windows) is reset wherever
 * core's session is (connect, accept, disconnect). `gen`: the generation
 * of the session opened, or of the one that ended. */
static void inter_session_dht(nodus_server_t *srv, nodus_tcp_conn_t *conn,
                              uint64_t gen, bool opened) {
    nodus_dht_origin_t o = { NODUS_DHT_ORIGIN_INTER, conn->slot, gen };
    if (opened)
        srv->dht->ops->session_opened(srv->dht, o);
    else
        srv->dht->ops->session_closed(srv->dht, o);
}

static void on_inter_connect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;

    /* Initialize inter session for outgoing connection (on_inter_accept
     * does this for incoming, but outgoing connections need it too —
     * dispatch_inter uses sess->conn for auth response handling). */
    nodus_inter_session_t *sess = inter_session_for_conn(srv, conn);
    if (sess) {
        inter_session_clear(sess, conn->slot, "on_inter_connect");
        sess->conn = conn;
        sess->dht_gen = session_gen_next(srv);
        inter_session_dht(srv, conn, sess->dht_gen, true);
    }

    conn->is_nodus = true;
    conn->auth_required = srv->inter_tcp.auth_required;

    /* Phase 3.2b-inv: conn lifecycle visibility */
    fprintf(stderr, "INTER_CONN: CONNECT slot=%d peer=%s:%u sess=%p\n",
            conn->slot, conn->ip, (unsigned)conn->port, (void *)sess);

    if (conn->auth_required) {
        /* Auto-send hello to initiate auth — the dialer module's first
         * frame (split S5a, decision item 28). The hello needs only this
         * node's identity and the conn. */
        nodus_inter_dial_io_t io;
        memset(&io, 0, sizeof(io));
        io.identity = &srv->identity;
        io.send_raw = inter_dial_send_raw_conn;
        io.ctx = conn;
        if (nodus_inter_dial_start(&io) == 0)
            conn->auth_state = NODUS_CONN_AUTH_HELLO_SENT;
        else
            conn->auth_state = NODUS_CONN_AUTH_FAILED;
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
        sess->dht_gen = session_gen_next(srv);
        inter_session_dht(srv, conn, sess->dht_gen, true);
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
        uint64_t gen = sess->dht_gen;
        inter_session_clear(sess, conn->slot, "on_inter_disconnect");
        inter_session_dht(srv, conn, gen, false);
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
    if (strcmp(msg.method, "dnac_cc_collect") == 0 && srv->chain) {
        srv->chain->ops->cc_collect(srv->chain, sess->conn,
                                    sess->client_pk.bytes, sess->token,
                                    payload, len, msg.txn_id);
        nodus_t2_msg_free(&msg);
        return;
    }

    /* DNAC client methods (post-auth, requires witness module) */
    if (strncmp(msg.method, "dnac_", 5) == 0) {
        if (srv->chain) {
            srv->chain->ops->dispatch_dnac(srv->chain, sess->conn,
                                           sess->client_pk.bytes, sess->token,
                                           payload, len,
                                           msg.method, msg.txn_id);
        } else {
            size_t rlen = 0;
            nodus_t2_error(msg.txn_id, NODUS_ERR_PROTOCOL_ERROR,
                            NODUS_CHAIN_NO_WITNESS_MSG,
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

    /* Dispatch to handler. The DHT methods (values, listen, channels
     * directory, media) go to the DHT with this session's slot and
     * authenticated identity (nodus_dht_client_request). */
    if (strcmp(msg.method, "put") == 0 ||
        strcmp(msg.method, "get") == 0 ||
        strcmp(msg.method, "get_all") == 0 ||
        strcmp(msg.method, "get_batch") == 0 ||
        strcmp(msg.method, "cnt_batch") == 0 ||
        strcmp(msg.method, "listen") == 0 ||
        strcmp(msg.method, "unlisten") == 0 ||
        strcmp(msg.method, "ch_list") == 0 ||
        strcmp(msg.method, "ch_search") == 0 ||
        strcmp(msg.method, "ch_get") == 0 ||
        strcmp(msg.method, "m_put") == 0 ||
        strcmp(msg.method, "m_meta") == 0 ||
        strcmp(msg.method, "m_chunk") == 0)
        srv->dht->ops->client_frame(srv->dht, (int)(sess - srv->sessions),
                                    &sess->client_fp, &sess->client_pk,
                                    payload, len, &msg);
    else if (strcmp(msg.method, "ping") == 0)
        handle_t2_ping(srv, sess, &msg);
    else if (strcmp(msg.method, "servers") == 0)
        handle_t2_servers(srv, sess, &msg);
    else if (strcmp(msg.method, "status") == 0)
        handle_t2_status(srv, sess, &msg);
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

        /* Update routing table (ping-before-evict if bucket full) and
         * cancel any pending eviction for this peer — a received PING
         * proves the peer is alive (same as PONG). The DHT's. */
        srv->dht->ops->peer_seen(srv->dht, NODUS_DHT_PEER_PING, &msg.node_id,
                                 from_ip, from_port,
                                 from_port + 2 /* Peer TCP = UDP + 2 */);
        nodus_cluster_on_pong(&srv->cluster, &msg.node_id, from_ip, from_port);

    } else if (strcmp(msg.method, "pong") == 0) {
        /* Update routing table + cluster health (IP-aware for seed discovery) */
        srv->dht->ops->peer_seen(srv->dht, NODUS_DHT_PEER_PONG_TOUCH, &msg.node_id,
                                 from_ip, from_port, from_port + 2);
        nodus_cluster_on_pong(&srv->cluster, &msg.node_id, from_ip, from_port);

        /* Cancel pending evictions for this peer (it responded), and
         * insert it into the routing table if new — the DHT's. */
        srv->dht->ops->peer_seen(srv->dht, NODUS_DHT_PEER_PONG, &msg.node_id,
                                 from_ip, from_port,
                                 from_port + 2 /* Peer TCP = UDP + 2 */);

    } else if (strcmp(msg.method, "fn") == 0 || strcmp(msg.method, "fn_r") == 0 ||
               strcmp(msg.method, "sv") == 0 || strcmp(msg.method, "fv") == 0) {
        /* FIND_NODE, NODES_FOUND, STORE_VALUE, FIND_VALUE — the DHT's
         * (nodus_dht_udp_request); its replies leave from this socket. */
        srv->dht->ops->udp_frame(srv->dht, from_ip, from_port, payload, len, &msg);
    }

    nodus_t1_msg_free(&msg);
}

/* ── TCP callbacks ───────────────────────────────────────────────── */

/* A client session ends (or its slot starts a new one): the chain
 * backend forgets it, so a reply the witness sends later finds no
 * session (split S3; the in-process backend has nothing to do). */
static void session_chain_closed(nodus_server_t *srv, nodus_tcp_conn_t *conn) {
    if (srv->chain)
        srv->chain->ops->session_closed(srv->chain, conn);
}

/* The DHT's shadow of a client session follows core's: opened where
 * `sess->conn` is set (with the session's fresh generation), closed where
 * the session is cleared (`gen`: the generation of the one that ended). */
static void session_dht_opened(nodus_server_t *srv, nodus_tcp_conn_t *conn,
                               uint64_t gen) {
    nodus_dht_origin_t o = { NODUS_DHT_ORIGIN_CLIENT, conn->slot, gen };
    srv->dht->ops->session_opened(srv->dht, o);
}

static void session_dht_closed(nodus_server_t *srv, nodus_tcp_conn_t *conn,
                               uint64_t gen) {
    nodus_dht_origin_t o = { NODUS_DHT_ORIGIN_CLIENT, conn->slot, gen };
    srv->dht->ops->session_closed(srv->dht, o);
}

static void on_tcp_accept(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    nodus_session_t *sess = session_for_conn(srv, conn);
    if (sess) {
        session_chain_closed(srv, conn);
        session_clear(sess);
        sess->conn = conn;
        sess->dht_gen = session_gen_next(srv);
        session_dht_opened(srv, conn, sess->dht_gen);
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
        session_chain_closed(srv, conn);
        uint64_t gen = sess->dht_gen;
        session_clear(sess);
        session_dht_closed(srv, conn, gen);
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

    /* Store locally (the channel server runs only with the in-process
     * DHT) */
    nodus_dht_t *dht = nodus_dht_backend_inproc_state(srv->dht);
    rc = nodus_storage_put(&dht->storage, val);
    if (rc != 0) { nodus_value_free(val); return -1; }

    /* Replicate to K-closest peers */
    nodus_dht_replicate_value(dht, val);
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
    /* The channel server runs only with the in-process DHT */
    nodus_dht_t *dht = nodus_dht_backend_inproc_state(srv->dht);

    /* 1. List all channels in local store */
    uint8_t *uuids = NULL;
    size_t count = 0;
    if (nodus_channel_store_list_all(&dht->ch_store, &uuids, &count) != 0 || count == 0) {
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
        if (nodus_hashring_responsible(&dht->ring, uuid, &rset) != 0)
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
        nodus_ch_ring_track(&srv->ch_ring, uuid, dht->ring.version);

        /* Ensure table exists (idempotent) */
        nodus_channel_create(&dht->ch_store, uuid, false, NULL, NULL, false);

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
                                     dht->ring.version,
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
        if (nodus_hashring_responsible(&dht->ring, uuid, &rset) != 0)
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

/* ── S1 witness seam — the host this server gives its witness ───── */

/* The witness's session lookup (nodus_witness_host_t.find_session_conn):
 * the client session authenticated as `pk` in the session `token`, if it
 * is still there. This loop was cc_collect_session_conn's body
 * (nodus_witness_chain_config.c) before the seam, moved unchanged. */
static struct nodus_tcp_conn *server_find_session_conn(
        void *ctx,
        const uint8_t pk[NODUS_PK_BYTES],
        const uint8_t token[NODUS_SESSION_TOKEN_LEN]) {
    const nodus_server_t *srv = ctx;
    if (!srv) return NULL;
    for (int i = 0; i < NODUS_MAX_SESSIONS; i++) {
        const nodus_session_t *s = &srv->sessions[i];
        if (s->authenticated && s->conn != NULL &&
            memcmp(s->token, token, NODUS_SESSION_TOKEN_LEN) == 0 &&
            memcmp(s->client_pk.bytes, pk, NODUS_PK_BYTES) == 0) {
            return s->conn;
        }
    }
    return NULL;
}

/* The config subset (and its array-size asserts) is the shared
 * nodus_server_witness_host_config (nodus_server.h), so the split
 * nodus-witness process fills the very same values. */
void nodus_server_witness_host(nodus_server_t *srv, nodus_witness_host_t *out) {
    memset(out, 0, sizeof(*out));
    out->identity = &srv->identity;
    nodus_server_witness_host_config(&srv->config, &out->config);
    out->find_session_conn = server_find_session_conn;
    out->ctx = srv;
}

/* ── S4 DHT seam — the host this server gives its DHT ───────────── */

/* HOT: a DHT reply / push to the session in `origin`'s slot — the
 * connection the DHT handler wrote to before the seam (`sess->conn`) —
 * only when that session is the one the origin names (item 29: same
 * generation). A slot reused by another session gets nothing. */
static int server_dht_send_to_origin(void *ctx, nodus_dht_origin_t origin,
                                     const uint8_t *frame, size_t len) {
    nodus_server_t *srv = ctx;
    if (!srv || origin.slot < 0) return -1;
    if (origin.kind == NODUS_DHT_ORIGIN_CLIENT) {
        if (origin.slot >= NODUS_MAX_SESSIONS) return -1;
        nodus_session_t *sess = &srv->sessions[origin.slot];
        if (sess->dht_gen != origin.gen) return -1;
        return nodus_tcp_send(sess->conn, frame, len);
    }
    if (origin.slot >= NODUS_MAX_INTER_SESSIONS) return -1;
    nodus_inter_session_t *isess = &srv->inter_sessions[origin.slot];
    if (isess->dht_gen != origin.gen) return -1;
    return nodus_tcp_send(isess->conn, frame, len);
}

/* A T1 datagram from this node's UDP 4000 socket. */
static int server_dht_udp_send(void *ctx, const uint8_t *payload, size_t len,
                               const char *ip, uint16_t port) {
    nodus_server_t *srv = ctx;
    return nodus_udp_send(&srv->udp, payload, len, ip, port);
}

/* A pre-framed frame over the inter-node pool (dht_republish_send). */
static int server_dht_inter_send(void *ctx, const char *ip, uint16_t port,
                                 const nodus_key_t *expected_peer_id,
                                 const uint8_t *frame, size_t flen) {
    nodus_server_t *srv = ctx;
    return dht_republish_send(srv, ip, port, expected_peer_id, frame, flen);
}

/* Hints only for a member of this node's cluster (item 9) seen less than
 * NODUS_HINT_OFFLINE_SKIP_SEC ago — the test every hint writer made
 * before the seam. */
static bool server_dht_hint_wanted(void *ctx, const nodus_key_t *node_id) {
    const nodus_server_t *srv = ctx;
    if (!cluster_knows_peer(srv, node_id)) return false;
    return nodus_cluster_peer_offline_secs(&srv->cluster, node_id) <
           NODUS_HINT_OFFLINE_SKIP_SEC;
}

void nodus_server_dht_host(nodus_server_t *srv, nodus_dht_host_t *out) {
    memset(out, 0, sizeof(*out));
    out->identity       = &srv->identity;
    out->ctx            = srv;
    out->send_to_origin = server_dht_send_to_origin;
    out->udp_send       = server_dht_udp_send;
    out->inter_send     = server_dht_inter_send;
    out->hint_wanted    = server_dht_hint_wanted;
}

/* Arm the partial-wipe gate: write NODUS_PARTIAL_WIPE_GENESIS_MARKER under
 * `data_path` (see "O16A — ARM THE PARTIAL-WIPE GATE" in nodus_server_init
 * for when this may run). Not fatal, but loud. */
static void server_write_genesis_marker(const char *data_path) {
    char marker[640];
    int mk = snprintf(marker, sizeof(marker), "%s/%s",
                      data_path[0] ? data_path : "/tmp",
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
    bool have_tcp = false, have_udp = false, have_inter = false;
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
        if (nodus_chain_backend_inproc_check_pin(config->data_path,
                                                 config->network_pin) != 0) {
            return -1;
        }
    }

    /* The DHT half, phase one (S4 seam, nodus_dht_init): batch-forward
     * fds, republish jitter, lookup txn counter, batch-forward epoll —
     * here, before the identity is loaded, as before the seam. Its host
     * view points at srv->identity, which is filled just below. */
    {
        nodus_dht_host_t dhost;
        nodus_server_dht_host(srv, &dhost);
        int drc = nodus_dht_backend_inproc_new(&dhost, &srv->dht);
        if (drc == -2)
            fprintf(stderr, "Failed to allocate DHT state\n");
        if (drc != 0)
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

    /* The DHT half, phase two (nodus_dht_open): nodus.db (values + media),
     * channels.db + default channels, the routing table, the hash ring
     * with this node at its advertised address and peer port. */
    uint16_t self_peer_port = config->peer_port ? config->peer_port : NODUS_DEFAULT_PEER_PORT;
    const char *self_ip = config->external_ip[0] ? config->external_ip : config->bind_ip;
    if (nodus_dht_backend_inproc_open(srv->dht, config->data_path,
                                      self_ip, self_peer_port) != 0)
        goto fail;

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
    srv->inter_tcp.on_pending_full   = nodus_server_on_pending_full;
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

    /* The channel server shares the in-process DHT's channels.db and ring */
    srv->ch_server.ch_store = &nodus_dht_backend_inproc_state(srv->dht)->ch_store;
    srv->ch_server.ring = &nodus_dht_backend_inproc_state(srv->dht)->ring;
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

    /* Initialize witness module (all nodes are automatic witnesses),
     * in this process, through the chain backend. Its host view is this
     * server's identity, config and session table
     * (nodus_server_witness_host). */
    int wrc;
    if (config->witness_external) {
        /* Split S3 — the witness is the separate nodus-witness process
         * (decision 2026-10-01-nodus-component-split items 5, 19, 20):
         * this server opens no port 4004 and no chain database; it
         * reaches the witness over <data_path>/witness.sock. Nothing is
         * dialled here — a witness that is not (yet) running only makes
         * `dnac_*` requests answer NODUS_CHAIN_NO_WITNESS_MSG. */
        wrc = nodus_chain_backend_ipc_open(config->data_path, &srv->chain);
        if (wrc == -1) {
            fprintf(stderr, "witness_external: the witness socket path "
                    "under data_path \"%s\" is unusable (too long) — not "
                    "starting\n", config->data_path);
            goto fail;
        }
        if (wrc == 0)
            fprintf(stderr, "WITNESS: external — served by the nodus-witness "
                    "process over %s/%s\n",
                    config->data_path[0] ? config->data_path : "/tmp",
                    NODUS_WITNESS_IPC_SOCK_NAME);
    } else {
        nodus_witness_host_t whost;
        nodus_server_witness_host(srv, &whost);
        wrc = nodus_chain_backend_inproc_open(&whost, &config->witness,
                                              &srv->chain);
    }
    if (wrc == -2) {
        fprintf(stderr, "Failed to allocate witness context\n");
        goto fail;
    }
    if (wrc != 0) {

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
         * guarded by `if (srv->chain)` AND NULL-checks its own argument
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
     * GATED ON AN OPEN CHAIN. The backend's `chain_open` (the witness's
     * `db` non-NULL) holds only when a chain database was found and
     * opened (nodus_witness_scan_chain_db).
     * A pre-genesis node has no chain, has not crossed the boundary the
     * marker records, and must not arm the gate — doing so would make
     * its perfectly legitimate two-of-three state a refusal.
     *
     * NOT FATAL, BUT LOUD. A node is not worse off for a missing marker
     * than it is today, and the next boot retries; but a gate silently
     * staying open is exactly what an operator would never otherwise
     * learn. The file's presence is the signal — its contents are never
     * read. */
    if (srv->chain && srv->chain->ops->chain_open(srv->chain))
        server_write_genesis_marker(config->data_path);

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
    /* The DHT's databases (those it opened) and its batch-forward epoll */
    srv->dht->ops->close(srv->dht);
    srv->dht = NULL;
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
    if (srv->config.witness_external) {
        /* Split S3: port 4004 belongs to the nodus-witness process, which
         * logs its own "Witness port" line. */
        fprintf(stderr, "  Witness port: external (nodus-witness)\n");
    } else {
        bool wport_opened = false;
        int wport = srv->chain
                  ? srv->chain->ops->listen_port(srv->chain, &wport_opened) : 0;
        fprintf(stderr, "  Witness port: %d%s\n",
                wport, wport_opened ? "" : " (not opened)");
    }
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
         * up to 2 x 50 ms per budget. The chain backend's own transport
         * counts too (split S3: the IPC backend's Unix socket, polled
         * 0 ms from its tick); the in-process backend always answers
         * false, so the combined binary's timings are unchanged. The DHT
         * backend's likewise (S4: in-process, always false). */
        int poll_ms = (nodus_tcp_read_pending(&srv->tcp) ||
                       nodus_tcp_read_pending(&srv->inter_tcp) ||
                       nodus_udp_read_pending(&srv->udp) ||
                       srv->dht->ops->read_pending(srv->dht) ||
                       (srv->chain &&
                        srv->chain->ops->read_pending(srv->chain))) ? 0 : 50;

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
                   nodus_udp_read_pending(&srv->udp) ||
                   srv->dht->ops->read_pending(srv->dht) ||
                   (srv->chain &&
                    srv->chain->ops->read_pending(srv->chain))) ? 0 : 50;
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

        /* Ping-before-evict: evict LRU peers that didn't respond (DHT) */
        srv->dht->ops->evict_tick(srv->dht);

        /* CRIT-4: Disconnect idle TCP connections */
        idle_timeout_sweep(srv);

        /* Witness: the 4004 p2p host and the consensus lane */
        if (srv->chain)
            srv->chain->ops->tick(srv->chain);

        /* Split S3: with the witness in nodus-witness, init could not see
         * its chain (no status answer yet), so the partial-wipe marker is
         * armed here, once, when the witness first reports an open chain
         * — this process has opened nodus.db and channels.db by now, so
         * "all three are real" holds as at the end of init (O16A). */
        if (srv->config.witness_external && !srv->genesis_marker_armed &&
            srv->chain && srv->chain->ops->chain_open(srv->chain)) {
            server_write_genesis_marker(srv->config.data_path);
            srv->genesis_marker_armed = true;
        }

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
            if (!srv->ch_startup_done &&
                nodus_dht_backend_inproc_state(srv->dht)->ring.count >= 2) {
                srv->ch_startup_done = true;
                ch_startup_rejoin(srv);
            }
        }
#endif

        /* Presence: expire stale entries + broadcast local list to peers */
        nodus_presence_tick(srv);

        /* The DHT's periodic work (nodus_dht_tick): hinted-handoff retry,
         * subscription cleanup + renewal, lookups, batch forward, bucket
         * refresh, storage cleanup, republish, media republish, WAL
         * checkpoint, incremental vacuum — in that order. */
        srv->dht->ops->tick(srv->dht);

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

    /* The DHT's in-flight lookups (callback data freed) and batch
     * forwards; NULL after a failed init (released there). */
    if (srv->dht)
        srv->dht->ops->stop(srv->dht);

    if (srv->chain) {
        srv->chain->ops->close(srv->chain);
        srv->chain = NULL;
    }

#ifndef NODUS_CHANNELS_DISABLED
    nodus_channel_server_close(&srv->ch_server);
#endif
    nodus_tcp_close(&srv->tcp);
    nodus_tcp_close(&srv->inter_tcp);
    nodus_udp_close(&srv->udp);
    /* The DHT's databases (media, values, channels) */
    if (srv->dht) {
        srv->dht->ops->close(srv->dht);
        srv->dht = NULL;
    }
    nodus_identity_clear(&srv->identity);
}
