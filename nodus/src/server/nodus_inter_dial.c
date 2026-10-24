/**
 * Nodus — the 4002 inter-node session (SecretConnection, NODE profile) and
 * the outbound 4002 pool, one shared module. See nodus_inter_dial.h.
 *
 * The dialer's old handshake (challenge → auth, auth_ok → CRIT-1 kpk_sig +
 * identity pin → KEM → key_init, key_ack → channel crypto; moved here
 * verbatim from core's dispatch_inter by decision 2026-10-01-nodus-component-
 * split item 28) is deleted with the rest of the old session protocol
 * (DHT v2 3b-2). The identity pin it enforced is now the SecretConnection
 * layer's own pre-ENCAPS check (nodus_tcp_sc.c sc_pin_ok), fed from
 * conn->expected_peer_id.
 *
 * @file nodus_inter_dial.c
 */

#include "server/nodus_inter_dial.h"
#include "transport/nodus_tcp.h"
#include "transport/nodus_tcp_sc.h"
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_wire.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"           /* nodus_fingerprint */
#include "crypto/utils/qgp_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "NODUS_DIAL"

/* ── The node session ─────────────────────────────────────────────── */

_Static_assert(sizeof(((nodus_pubkey_t *)0)->bytes) == CMT_P2P_SC_DSA_PK_SIZE,
               "nodus_pubkey_t must be the SecretConnection's key size");

int nodus_inter_session_enable(nodus_tcp_t *pool, nodus_tcp_conn_t *conn,
                               bool initiator) {
    if (!pool || !conn) return -1;
    const nodus_inter_session_cfg_t *sc =
        (const nodus_inter_session_cfg_t *)pool->auth_ctx;
    if (!sc || !sc->identity || !sc->chain_id) {
        QGP_LOG_ERROR(LOG_TAG, "INTER: no node-session config on this pool — "
                      "%s %s:%u refused", initiator ? "dial to" : "accept from",
                      conn->ip, (unsigned)conn->port);
        return -1;
    }
    nodus_tcp_sc_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role      = initiator ? CMT_P2P_SC_ROLE_INITIATOR : CMT_P2P_SC_ROLE_RESPONDER;
    cfg.profile   = &CMT_P2P_SC_PROFILE_NODE;
    cfg.id        = sc->identity;
    cfg.proto_ver = NODUS_NSESS_PROTO_VERSION;
    /* The chain id is part of the HELLO of both ends: a node that does not
     * know its chain yet has nothing to say — refuse (fail closed). */
    if (!sc->chain_id(sc->ctx, cfg.chain_id)) {
        QGP_LOG_WARN(LOG_TAG, "INTER: chain id not known — %s %s:%u refused",
                     initiator ? "dial to" : "accept from",
                     conn->ip, (unsigned)conn->port);
        return -1;
    }
    if (initiator) {
        /* There is no unpinned 4002 dial (O-4). */
        if (!conn->expected_peer_id_set) {
            QGP_LOG_WARN(LOG_TAG, "INTER: dial to %s:%u without an expected "
                         "peer identity — refused", conn->ip, (unsigned)conn->port);
            return -1;
        }
        cfg.expected_peer = &conn->expected_peer_id;
    }
    if (nodus_tcp_sc_enable(pool, conn, &cfg) != 0)
        return -1;
    /* The send gate stays closed until the session is authenticated: sends
     * wait in the dial queue (nodus_tcp_send / nodus_inter_pool_send_framed)
     * and are replayed, sealed, by nodus_inter_dial_conn_open. */
    conn->auth_required = true;
    if (initiator)
        conn->auth_state = NODUS_CONN_AUTH_HELLO_SENT;
    return 0;
}

int nodus_inter_session_proven(nodus_tcp_conn_t *conn) {
    if (!conn) return -1;
    uint8_t pkb[CMT_P2P_SC_DSA_PK_SIZE];
    if (nodus_tcp_sc_peer_pubkey(conn, pkb) != 0) return -1;
    nodus_pubkey_t pk;
    memcpy(pk.bytes, pkb, sizeof(pk.bytes));
    nodus_key_t fp;
    if (nodus_fingerprint(&pk, &fp) != 0) return -1;
    if (conn->auth_initiated_by_us &&
        (!conn->expected_peer_id_set ||
         nodus_key_cmp(&fp, &conn->expected_peer_id) != 0)) {
        QGP_LOG_ERROR(LOG_TAG, "INTER: identity PIN MISMATCH at %s:%u after the "
                      "session — closing", conn->ip, (unsigned)conn->port);
        return -1;
    }
    conn->peer_pk = pk;
    conn->peer_id = fp;
    conn->peer_id_set = true;
    conn->authenticated = true;
    return 0;
}

/* ── The outbound 4002 pool (split S5b) ──────────────────────────────
 *
 * Moved from nodus_server.c at f1d48425 unchanged (nodus_server_inter_find
 * :447-474, nodus_server_inter_dial :476-502, dht_republish_send :509-617,
 * the inter-pool part of idle_timeout_sweep :1167-1185,
 * pending_full_is_replication :326-352) so core and nodus-storage share it —
 * decision 2026-10-01-nodus-component-split items 16, 28. */

nodus_tcp_conn_t *nodus_inter_pool_find(nodus_tcp_t *pool, const char *ip,
                                        uint16_t port,
                                        const nodus_key_t *expected_node_id) {
    if (!pool || !ip) return NULL;
    /* No pin requested: the first pool entry for ip:port, as before. */
    if (!expected_node_id)
        return nodus_tcp_find_by_addr(pool, ip, port);
    /* Pinned: only a conn WE dialed whose identity is the requested one —
     * never an accepted conn (its peer chose to call us; the pin was never
     * checked on it), never a dial pinned to another node_id, never a conn
     * proven for another node_id. Every identity the conn carries must
     * match (expected and, once proven, peer_id) and at least one must be
     * set. Pool slot order: the first such conn. */
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = pool->pool[i];
        if (!c || c->is_unix || c->port != port || strcmp(c->ip, ip) != 0)
            continue;
        if (!c->auth_initiated_by_us) continue;
        bool exp_eq = c->expected_peer_id_set &&
                      nodus_key_cmp(&c->expected_peer_id, expected_node_id) == 0;
        bool proven_eq = c->peer_id_set &&
                         nodus_key_cmp(&c->peer_id, expected_node_id) == 0;
        if (c->expected_peer_id_set && !exp_eq) continue;
        if (c->peer_id_set && !proven_eq) continue;
        if (exp_eq || proven_eq) return c;
    }
    return NULL;
}

/* Is this pool able to make a node session now: a config, and a chain id
 * (fail closed)? Checked BEFORE a TCP connect is made. */
static bool pool_session_ready(nodus_tcp_t *pool) {
    const nodus_inter_session_cfg_t *sc =
        (const nodus_inter_session_cfg_t *)pool->auth_ctx;
    uint8_t cid[32];
    return sc && sc->identity && sc->chain_id && sc->chain_id(sc->ctx, cid);
}

/* find-or-dial; *refused is set when the dial was refused LOCALLY (no pin,
 * no config, chain id unknown), as opposed to a connect that failed. */
static nodus_tcp_conn_t *pool_dial_ex(nodus_tcp_t *pool, const char *ip,
                                      uint16_t port,
                                      const nodus_key_t *expected_node_id,
                                      bool *refused) {
    *refused = false;
    if (!pool || !ip) return NULL;
    /* No unpinned dial: the SecretConnection layer is pinned to one exact
     * identity (O-4) and there is no round-3 / plaintext fallback. Refused
     * before anything else — before the find as well. */
    if (!expected_node_id) {
        QGP_LOG_WARN(LOG_TAG, "INTER: dial to %s:%u without an expected peer "
                     "identity — refused", ip, (unsigned)port);
        *refused = true;
        return NULL;
    }
    nodus_tcp_conn_t *conn = nodus_inter_pool_find(pool, ip, port,
                                                   expected_node_id);
    if (conn) return conn;
    /* No session without a chain id: refuse BEFORE the TCP connect (no
     * useless connect, nothing to tear down). */
    if (!pool_session_ready(pool)) {
        QGP_LOG_WARN(LOG_TAG, "INTER: no node-session config or chain id not "
                     "known — dial to %s:%u refused", ip, (unsigned)port);
        *refused = true;
        return NULL;
    }
    /* None usable: a fresh conn. The transport has no duplicate check —
     * a second conn to an ip:port already in the pool (an accepted conn,
     * or one dialed for another identity) is simply another slot. */
    conn = nodus_tcp_connect(pool, ip, port);
    if (!conn) return NULL;
    conn->is_nodus = true;
    /* CRIT-1: record WHO we believe we are dialing, from the routing/roster
     * entry that produced this ip:port. The layer pins the responder's
     * claimed key against it before ENCAPS, so an on-path attacker cannot
     * substitute its own identity. Stored on the conn (not the session): the
     * pool's on_connect clears the session, and on an immediate (localhost)
     * connect it has already run inside nodus_tcp_connect above. */
    conn->expected_peer_id = *expected_node_id;
    conn->expected_peer_id_set = true;
    if (nodus_inter_session_enable(pool, conn, true) != 0) {
        nodus_tcp_disconnect(pool, conn);
        return NULL;
    }
    return conn;
}

nodus_tcp_conn_t *nodus_inter_pool_dial(nodus_tcp_t *pool, const char *ip,
                                        uint16_t port,
                                        const nodus_key_t *expected_node_id) {
    bool refused;
    return pool_dial_ex(pool, ip, port, expected_node_id, &refused);
}

nodus_inter_send_t nodus_inter_pool_send_framed(nodus_tcp_t *pool, const char *ip,
                                                uint16_t port,
                                                const nodus_key_t *expected_node_id,
                                                const uint8_t *frame, size_t flen) {
    bool refused;
    nodus_tcp_conn_t *conn = pool_dial_ex(pool, ip, port, expected_node_id, &refused);
    if (!conn) return refused ? NODUS_INTER_SEND_REFUSED : NODUS_INTER_SEND_FAILED;

    /* Not authenticated yet: the frame waits in the dial queue. Sent bytes of
     * a queued frame are plaintext in memory only; they are sealed when the
     * gate opens (nodus_inter_dial_conn_open). */
    if (conn->auth_required && conn->auth_state != NODUS_CONN_AUTH_OK) {
        if (conn->auth_state == NODUS_CONN_AUTH_FAILED) return NODUS_INTER_SEND_FAILED;
        /* Queue raw pre-framed bytes in pending buffer */
        if (!conn->pending_buf) {
            conn->pending_cap = NODUS_TCP_BUF_INIT;
            conn->pending_buf = malloc(conn->pending_cap);
            if (!conn->pending_buf) return NODUS_INTER_SEND_FAILED;
            conn->pending_len = 0;
        }
        if (conn->pending_len + flen > NODUS_TCP_PENDING_MAX)
            return NODUS_INTER_SEND_FAILED;
        if (conn->pending_len + flen > conn->pending_cap) {
            size_t new_cap = conn->pending_cap;
            while (new_cap < conn->pending_len + flen) new_cap *= 2;
            if (new_cap > NODUS_TCP_PENDING_MAX) new_cap = NODUS_TCP_PENDING_MAX;
            uint8_t *nb = realloc(conn->pending_buf, new_cap);
            if (!nb) return NODUS_INTER_SEND_FAILED;
            conn->pending_buf = nb;
            conn->pending_cap = new_cap;
        }
        memcpy(conn->pending_buf + conn->pending_len, frame, flen);
        conn->pending_len += flen;
        return NODUS_INTER_SEND_QUEUED;
    }

    /* The session is authenticated: the payload goes through the sealed path.
     * frame = [7-byte header][payload]. */
    if (flen <= NODUS_FRAME_HEADER_SIZE) return NODUS_INTER_SEND_FAILED;
    const uint8_t *payload = frame + NODUS_FRAME_HEADER_SIZE;
    size_t payload_len = flen - NODUS_FRAME_HEADER_SIZE;
    /* The transport's queue-full fallback (tcp->on_pending_full) reports a
     * SUCCESSFUL send (0) although nothing was written: the frame was parked
     * in the hint table (an INSERT OR IGNORE — against the very row a hinted
     * retry is delivering, that is a no-op) or dropped. It counts the
     * diversion in pending_hint_fallback_count; a changed count means "not
     * written" — QUEUED, so the durable row stays. */
    uint64_t diverted_before = conn->pending_hint_fallback_count;
    int rc = nodus_tcp_send_progress(conn, payload, payload_len, NULL, NULL);
    if (rc == 0 && conn->pending_hint_fallback_count != diverted_before)
        return NODUS_INTER_SEND_QUEUED;
    if (rc != 0) {
        /* Send failed (buffer full / slow consumer) — disconnect so
         * next retry opens a fresh connection instead of hammering
         * the same stalled conn with buf_ensure errors. */
        fprintf(stderr, "REPL_SEND: slow consumer %s:%d, disconnecting\n",
                conn->ip, conn->port);
        nodus_tcp_disconnect(pool, conn);
        return NODUS_INTER_SEND_FAILED;
    }
    return NODUS_INTER_SEND_WRITTEN;
}

void nodus_inter_pool_sweep(nodus_tcp_t *pool, uint64_t now) {
    if (!pool) return;
    /* Idle connections */
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = pool->pool[i];
        if (!c || c->state != NODUS_CONN_CONNECTED) continue;
        if (now - c->last_activity > NODUS_INTER_POOL_IDLE_SEC)
            nodus_tcp_disconnect(pool, c);
    }

    /* Auth timeout: dialed connections whose session is still in
     * HELLO_SENT NODUS_INTER_POOL_HELLO_TIMEOUT_SEC after the DIAL — one
     * bound over connect + handshake, on the monotonic clock (connected_at
     * is 0 while the connect is still in progress, so it cannot serve). */
    uint64_t now_mono = nodus_time_mono_ms();
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = pool->pool[i];
        if (!c || c->auth_state != NODUS_CONN_AUTH_HELLO_SENT) continue;
        if (now_mono > c->dial_mono_ms &&
            now_mono - c->dial_mono_ms >
                (uint64_t)NODUS_INTER_POOL_HELLO_TIMEOUT_SEC * 1000) {
            fprintf(stderr, "INTER_AUTH: auth timeout for %s:%d, disconnecting\n",
                    c->ip, c->port);
            c->auth_state = NODUS_CONN_AUTH_FAILED;
            nodus_tcp_disconnect(pool, c);
        }
    }
}

/* Rule: the payload is a CBOR map whose envelope says query ("y" == "q")
 * and whose method ("q") is "sv" or "m_sv". Those are exactly the frames
 * the DHT builds with nodus_t1_store_value (replication on put, republish,
 * hinted retry) and nodus_t2_media_store_value (media chunk replication);
 * T1 and T2 encode the envelope with the same bytes (`y` = text "q", `q` =
 * method text). Everything else — p_sync, ri_*, ntf, sub / unsub, and every
 * reply or error ("y" == "r" / "e": fv_r, sv_ack, get_batch results, ...)
 * — is not. Only the envelope is read; the value is not parsed. */
bool nodus_inter_frame_is_replication(const uint8_t *payload, size_t len) {
    if (!payload) return false;
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

void nodus_inter_dial_conn_open(nodus_tcp_conn_t *conn) {
    if (!conn) return;
    conn->auth_state = NODUS_CONN_AUTH_OK;
    /* The dial queue holds PRE-FRAMED PLAINTEXT ([7-byte header][payload] per
     * frame, written while the session was not authenticated —
     * nodus_inter_pool_send_framed, nodus_tcp_send's pending_queue_append): it
     * must never reach the socket as it is. Every queued frame is REPLAYED
     * through nodus_tcp_send, in queue order — its payload is sealed now that
     * auth_state is OK. The bound is the one the queue already had
     * (NODUS_TCP_PENDING_MAX). A frame that does not parse ends the replay
     * (the rest is dropped, logged): its bytes are not trusted as a frame
     * boundary. */
    uint8_t *q = conn->pending_buf;
    size_t qlen = conn->pending_len;
    conn->pending_buf = NULL;
    conn->pending_len = 0;
    conn->pending_cap = 0;
    size_t off = 0;
    int resent = 0, failed = 0;
    while (q && off < qlen) {
        nodus_frame_t f;
        memset(&f, 0, sizeof(f));
        int used = nodus_frame_decode(q + off, qlen - off, &f);
        if (used <= 0 || !f.payload) {
            QGP_LOG_WARN(LOG_TAG, "INTER_SESSION: %s:%d dial queue holds %zu "
                         "unparsable byte(s) — dropped", conn->ip, conn->port,
                         qlen - off);
            break;
        }
        if (nodus_tcp_send(conn, f.payload, f.payload_len) == 0)
            resent++;
        else
            failed++;
        off += (size_t)used;
    }
    free(q);
    QGP_LOG_INFO(LOG_TAG, "INTER_SESSION: %s conn %s %s:%d open "
                 "(%d queued frame(s) replayed sealed%s)",
                 conn->auth_initiated_by_us ? "outgoing" : "accepted",
                 conn->auth_initiated_by_us ? "to" : "from",
                 conn->ip, conn->port, resent, failed ? ", some FAILED" : "");
    if (failed)
        QGP_LOG_WARN(LOG_TAG, "INTER_SESSION: %s:%d — %d queued frame(s) could "
                     "not be replayed", conn->ip, conn->port, failed);
}
