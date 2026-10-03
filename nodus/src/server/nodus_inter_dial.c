/**
 * Nodus — the DIALER side of the 4002 inter-node handshake (shared module)
 *
 * Moved verbatim from core's dispatch_inter (nodus_server.c at e1f906a5:
 * challenge :1267-1287, auth_ok :1288-1444, key_ack :1445-1482) and
 * on_inter_connect's hello (:1928-1941) — decision
 * 2026-10-01-nodus-component-split item 28. Same encoder calls with the
 * same arguments (txn ids, buffer sizes), same checks in the same order;
 * the per-connection fields moved from nodus_inter_session_t into
 * nodus_inter_dial_t. See nodus_inter_dial.h.
 *
 * @file nodus_inter_dial.c
 */

#include "server/nodus_inter_dial.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_wire.h"
#include "crypto/nodus_sign.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/qgp_mlkem.h"
#include "crypto/utils/qgp_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/epoll.h>
#endif

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "NODUS_DIAL"

extern void qgp_secure_memzero(void *ptr, size_t len);

static const char *io_ip(const nodus_inter_dial_io_t *io) {
    return io->peer_ip ? io->peer_ip : "?";
}

int nodus_inter_dial_start(const nodus_inter_dial_io_t *io) {
    if (!io || !io->identity || !io->send_raw) return -1;
    uint8_t hello_buf[8192];
    size_t hello_len = 0;
    if (nodus_t2_hello(0, &io->identity->pk, &io->identity->node_id,
                        hello_buf, sizeof(hello_buf), &hello_len) != 0)
        return -1;
    io->send_raw(io->ctx, hello_buf, hello_len);
    return 0;
}

/* True when every byte of the challenge nonce is zero. The T2 decoder has
 * no presence flag for "nonce": nodus_t2_decode zeroes the message first
 * and copies the field only when it is a bstr of exactly NODUS_NONCE_LEN
 * bytes, so a challenge whose nonce is absent (or malformed) reaches us as
 * all zeros. An honest acceptor draws the nonce from nodus_random (32
 * bytes); all zeros from it has probability 2^-256, and a refused honest
 * dial is simply redialed. */
static bool nonce_all_zero(const uint8_t *nonce) {
    uint8_t acc = 0;
    for (size_t i = 0; i < NODUS_NONCE_LEN; i++) acc |= nonce[i];
    return acc == 0;
}

/* challenge → auth. Only on a conn we dialed (the caller's role split), and
 * once: a repeated challenge (the nonce is already retained) is not signed
 * again — this node never signs a nonce a second time on one conn.
 * Fail closed (REFUSED, nothing sent, the nonce not retained) when the
 * nonce is absent, or when signing or encoding the auth fails. */
static nodus_inter_dial_rc_t on_challenge(nodus_inter_dial_t *d,
                                          const nodus_inter_dial_io_t *io,
                                          const nodus_tier2_msg_t *msg) {
    if (d->has_challenge_nonce || d->authenticated) {
        QGP_LOG_WARN(LOG_TAG, "INTER: repeated challenge from %s:%u — "
                     "not signed, dropped", io_ip(io), (unsigned)io->peer_port);
        return NODUS_INTER_DIAL_DONE;
    }
    if (nonce_all_zero(msg->nonce)) {
        QGP_LOG_WARN(LOG_TAG, "INTER: challenge from %s:%u without a nonce — "
                     "not signed, refusing", io_ip(io), (unsigned)io->peer_port);
        return NODUS_INTER_DIAL_REFUSED;
    }
    nodus_sig_t sig;
    memset(&sig, 0, sizeof(sig));
    if (nodus_sign_auth_challenge(&sig, msg->nonce, &io->identity->sk) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "INTER: signing the challenge from %s:%u failed "
                      "— refusing", io_ip(io), (unsigned)io->peer_port);
        return NODUS_INTER_DIAL_REFUSED;
    }
    uint8_t buf[8192];
    size_t rlen = 0;
    if (nodus_t2_auth(msg->txn_id, &sig, buf, sizeof(buf), &rlen) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "INTER: encoding the auth for %s:%u failed "
                      "— refusing", io_ip(io), (unsigned)io->peer_port);
        return NODUS_INTER_DIAL_REFUSED;
    }
    /* CRIT-1: retain the challenge nonce — the peer signs
     * (kyber_pk || this nonce) as kpk_sig, so auth_ok cannot verify the
     * binding without it. */
    memcpy(d->challenge_nonce, msg->nonce, NODUS_NONCE_LEN);
    d->has_challenge_nonce = true;
    io->send_raw(io->ctx, buf, rlen);
    return NODUS_INTER_DIAL_DONE;
}

/* CRIT-1: authenticate the peer's Kyber public key BEFORE encapsulating to
 * it. Without this an active MITM on the plaintext handshake substitutes
 * its own self-consistent triple (server_pk', kyber_pk', kpk_sig') and owns
 * the channel key. Three gates, all fail-closed:
 *   1. downgrade-close: WE support Kyber, so a missing kyber_pk / kpk_sig /
 *      server_pk is refused — never fall through to plaintext (an attacker
 *      could otherwise strip the field to force cleartext inter-node
 *      traffic).
 *   2. signature: kpk_sig must verify over (kyber_pk || the nonce we
 *      challenged with) under server_pk.
 *   3. identity pin: fingerprint(server_pk) must equal the node_id we
 *      believed we were dialing. Step 2 alone only proves the triple is
 *      SELF-consistent — the attacker signs its own key with its own
 *      identity and passes. The pin binds the channel to the intended peer;
 *      SHA3-512 preimage resistance means a MITM cannot produce a pk
 *      matching that fingerprint.
 * Trust note: the pin reference is the routing-table / roster node_id
 * (trusted discovery; adversarial UDP-4000 Kademlia injection is out of
 * scope per the threat model).
 * @return true when all three hold (d->peer_* recorded). */
static bool auth_ok_bind(nodus_inter_dial_t *d, const nodus_inter_dial_io_t *io,
                         const nodus_tier2_msg_t *msg) {
    if (!msg->has_kyber_pk || !msg->has_kpk_sig || !msg->has_server_pk) {
        QGP_LOG_WARN(LOG_TAG, "INTER CRIT-1: auth_ok missing kyber_pk/kpk_sig/"
                     "server_pk from %s:%u — refusing (downgrade attempt?)",
                     io_ip(io), (unsigned)io->peer_port);
        return false;
    }
    if (!d->has_challenge_nonce) {
        QGP_LOG_WARN(LOG_TAG, "INTER CRIT-1: no retained challenge nonce for "
                     "%s:%u — cannot verify kpk_sig, refusing",
                     io_ip(io), (unsigned)io->peer_port);
        return false;
    }
    uint8_t sign_data[NODUS_KYBER_PK_BYTES + NODUS_NONCE_LEN];
    memcpy(sign_data, msg->kyber_pk, NODUS_KYBER_PK_BYTES);
    memcpy(sign_data + NODUS_KYBER_PK_BYTES, d->challenge_nonce, NODUS_NONCE_LEN);
    if (nodus_verify_kyber_bind(&msg->kpk_sig, sign_data, sizeof(sign_data),
                                &msg->server_pk) != 0) {
        QGP_LOG_WARN(LOG_TAG, "INTER CRIT-1: kyber_pk signature INVALID from "
                     "%s:%u — possible MITM, refusing",
                     io_ip(io), (unsigned)io->peer_port);
        return false;
    }
    if (!io->expected_peer_id) {
        QGP_LOG_WARN(LOG_TAG, "INTER CRIT-1: no expected peer identity for "
                     "%s:%u — cannot pin, refusing",
                     io_ip(io), (unsigned)io->peer_port);
        return false;
    }
    nodus_key_t actual_id;
    if (nodus_fingerprint(&msg->server_pk, &actual_id) != 0) {
        QGP_LOG_WARN(LOG_TAG, "INTER CRIT-1: fingerprint() failed for %s:%u "
                     "— refusing", io_ip(io), (unsigned)io->peer_port);
        return false;
    }
    if (nodus_key_cmp(&actual_id, io->expected_peer_id) != 0) {
        /* Fail closed + alarm. Do NOT re-resolve the identity here:
         * FIND_NODE data is unsigned, so adopting a fresh node_id at attack
         * time would let the same adversary both trigger and answer the
         * mismatch. Recovery is via authenticated discovery refresh. */
        QGP_LOG_ERROR(LOG_TAG, "INTER CRIT-1: identity PIN MISMATCH at %s:%u — "
                      "server_pk fingerprint != dialed node_id. "
                      "Refusing (MITM or peer identity rotation).",
                      io_ip(io), (unsigned)io->peer_port);
        return false;
    }
    /* F4: the dialed peer's identity is now proven (signature + pin). */
    d->peer_id = actual_id;
    d->peer_pk = msg->server_pk;
    d->peer_id_set = true;
    return true;
}

/* auth_ok → (CRIT-1 checks) → key_init. Only on a conn we dialed, once: a
 * repeated auth_ok would start a second key exchange. */
static nodus_inter_dial_rc_t on_auth_ok(nodus_inter_dial_t *d,
                                        const nodus_inter_dial_io_t *io,
                                        const nodus_tier2_msg_t *msg) {
    if (d->authenticated || d->pending_kem) {
        QGP_LOG_WARN(LOG_TAG, "INTER: repeated auth_ok from %s:%u — dropped",
                     io_ip(io), (unsigned)io->peer_port);
        return NODUS_INTER_DIAL_DONE;
    }
    d->authenticated = true;

    if (!io->identity->has_kyber) {
        /* This node has no Kyber identity — it cannot do channel encryption
         * at all, so plaintext is the only option and is not an
         * attacker-induced downgrade. */
        if (io->established) io->established(io->ctx, false);
        return NODUS_INTER_DIAL_DONE;
    }

    /* Keep the send gate CLOSED during the key exchange (the caller opens
     * it on established) so no plaintext frame leaks through. */
    if (!auth_ok_bind(d, io, msg))
        return NODUS_INTER_DIAL_REFUSED;

    /* Faz 1 KEM migration (docs/plans/decisions/2026-09-23-kem-mlkem-
     * migration.md): if the peer ALSO advertised a signed ML-KEM-1024
     * pubkey, verify it under MLKEM_BIND against the SAME pinned server_pk
     * (auth_ok_bind proved it) and prefer it; otherwise the Kyber kpk. */
    bool use_mlkem = false;
    if (msg->has_mlkem_pk && msg->has_mpk_sig) {
        uint8_t msign_data[NODUS_MLKEM_PK_BYTES + NODUS_NONCE_LEN];
        memcpy(msign_data, msg->mlkem_pk, NODUS_MLKEM_PK_BYTES);
        memcpy(msign_data + NODUS_MLKEM_PK_BYTES, d->challenge_nonce, NODUS_NONCE_LEN);
        if (nodus_verify_mlkem_bind(&msg->mpk_sig, msign_data, sizeof(msign_data),
                                    &msg->server_pk) == 0) {
            use_mlkem = true;
        } else {
            QGP_LOG_WARN(LOG_TAG, "INTER: mlkem_pk signature INVALID from %s:%u — "
                         "falling back to Kyber round-3",
                         io_ip(io), (unsigned)io->peer_port);
        }
    }

    uint8_t ct[NODUS_KYBER_CT_BYTES], ss_buf[NODUS_KYBER_SS_BYTES];
    uint8_t alg = use_mlkem ? 1 : 0;
    int enc_rc = use_mlkem
        ? qgp_mlkem1024_encapsulate(ct, ss_buf, msg->mlkem_pk)
        : qgp_kem1024_encapsulate(ct, ss_buf, msg->kyber_pk);
    if (enc_rc == 0) {
        uint8_t nc[NODUS_NONCE_LEN];
        nodus_random(nc, NODUS_NONCE_LEN);
        uint8_t ki_buf[4096];
        size_t ki_len = 0;
        if (nodus_t2_key_init(msg->txn_id, ct, nc, alg, ki_buf, sizeof(ki_buf),
                              &ki_len) != 0) {
            /* Nothing sent, no key exchange pending: fail closed. */
            QGP_LOG_ERROR(LOG_TAG, "INTER: encoding key_init for %s:%u failed "
                          "— refusing", io_ip(io), (unsigned)io->peer_port);
            qgp_secure_memzero(ss_buf, sizeof(ss_buf));
            qgp_secure_memzero(nc, sizeof(nc));
            return NODUS_INTER_DIAL_REFUSED;
        }
        io->send_raw(io->ctx, ki_buf, ki_len);
        /* Store shared secret + nonce for key_ack */
        memcpy(d->pending_ss, ss_buf, 32);
        memcpy(d->pending_nc, nc, 32);
        d->pending_kem = true;
    }
    qgp_secure_memzero(ss_buf, sizeof(ss_buf));
    return NODUS_INTER_DIAL_DONE;
}

/* key_ack → channel crypto. Only while a key exchange is pending. */
static nodus_inter_dial_rc_t on_key_ack(nodus_inter_dial_t *d,
                                        const nodus_inter_dial_io_t *io,
                                        const nodus_tier2_msg_t *msg) {
    QGP_LOG_INFO(LOG_TAG, "CRYPTO: KEY_ACK_RX slot=%d peer=%s:%u has_nonce=%d",
                 io->slot, io_ip(io), (unsigned)io->peer_port,
                 msg->has_key_nonce ? 1 : 0);
    if (msg->has_key_nonce) {
        /* We DIALED this peer (outgoing inter-node conn) → initiator. */
        nodus_channel_crypto_init(io->crypto, d->pending_ss, d->pending_nc,
                                  msg->key_nonce, NODUS_CHANNEL_ROLE_INITIATOR);
        QGP_LOG_INFO(LOG_TAG, "CRYPTO: SET_OUTGOING slot=%d peer=%s:%u "
                     "(inter-node encrypted)",
                     io->slot, io_ip(io), (unsigned)io->peer_port);
        qgp_secure_memzero(d->pending_ss, sizeof(d->pending_ss));
        qgp_secure_memzero(d->pending_nc, sizeof(d->pending_nc));
        d->pending_kem = false;
        if (io->established) io->established(io->ctx, true);
    }
    return NODUS_INTER_DIAL_DONE;
}

nodus_inter_dial_rc_t nodus_inter_dial_on_frame(nodus_inter_dial_t *d,
                                                const nodus_inter_dial_io_t *io,
                                                const nodus_tier2_msg_t *msg) {
    if (!d || !io || !io->identity || !io->send_raw || !io->crypto || !msg)
        return NODUS_INTER_DIAL_NOT_MINE;
    if (strcmp(msg->method, "challenge") == 0)
        return on_challenge(d, io, msg);
    if (strcmp(msg->method, "auth_ok") == 0)
        return on_auth_ok(d, io, msg);
    if (strcmp(msg->method, "key_ack") == 0 && d->pending_kem)
        return on_key_ack(d, io, msg);
    return NODUS_INTER_DIAL_NOT_MINE;
}

/* ── The outbound 4002 pool (split S5b) ──────────────────────────────
 *
 * Moved from nodus_server.c at f1d48425 unchanged (nodus_server_inter_find
 * :447-474, nodus_server_inter_dial :476-502, dht_republish_send :509-617,
 * the inter-pool part of idle_timeout_sweep :1167-1185,
 * pending_full_is_replication :326-352, inter_dial_sync_out :1271-1284 and
 * inter_dial_established :1296-1318) so core and nodus-storage share it —
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

nodus_tcp_conn_t *nodus_inter_pool_dial(nodus_tcp_t *pool, const char *ip,
                                        uint16_t port,
                                        const nodus_key_t *expected_node_id) {
    nodus_tcp_conn_t *conn = nodus_inter_pool_find(pool, ip, port,
                                                   expected_node_id);
    if (conn) return conn;
    /* None usable: a fresh conn. The transport has no duplicate check —
     * a second conn to an ip:port already in the pool (an accepted conn,
     * or one dialed for another identity) is simply another slot. */
    conn = nodus_tcp_connect(pool, ip, port);
    if (!conn) return NULL;
    conn->is_nodus = true;
    /* CRIT-1: record WHO we believe we are dialing, from the routing/roster
     * entry that produced this ip:port. The auth_ok handler pins
     * fingerprint(server_pk) against it before Kyber-encapsulating, so an
     * on-path attacker cannot substitute its own identity. Stored on the
     * conn (not the session): the pool's on_connect clears the session,
     * and on an immediate (localhost) connect it has already run inside
     * nodus_tcp_connect above — the dialer reads the pin from the conn at
     * auth_ok time. */
    if (expected_node_id) {
        conn->expected_peer_id = *expected_node_id;
        conn->expected_peer_id_set = true;
    }
    /* the pool's on_connect callback handles auth_required + hello */
    return conn;
}

int nodus_inter_pool_send_framed(nodus_tcp_t *pool, const char *ip,
                                 uint16_t port,
                                 const nodus_key_t *expected_node_id,
                                 const uint8_t *frame, size_t flen) {
    nodus_tcp_conn_t *conn = nodus_inter_pool_dial(pool, ip, port,
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
            nodus_tcp_disconnect(pool, conn);
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
        nodus_tcp_disconnect(pool, conn);
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
    if (conn->fd >= 0 && pool->epoll_fd >= 0) {
        uint32_t et = pool->level_triggered ? 0 : EPOLLET;
        struct epoll_event ev = { .events = EPOLLIN | EPOLLOUT | et, .data.ptr = conn };
        epoll_ctl(pool->epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
    }
#endif

    return 0;
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

    /* Auth timeout: connections stuck in HELLO_SENT for >10s */
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = pool->pool[i];
        if (!c || c->auth_state != NODUS_CONN_AUTH_HELLO_SENT) continue;
        if (now - c->connected_at > NODUS_INTER_POOL_HELLO_TIMEOUT_SEC) {
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

void nodus_inter_dial_conn_sync(const nodus_inter_dial_t *d,
                                nodus_tcp_conn_t *conn) {
    if (!d || !conn) return;
    if (d->authenticated)
        conn->authenticated = true;
    if (d->peer_id_set) {
        /* F4: like the accepting side does after auth, so pending-full
         * hints key on a real identity. */
        conn->peer_id = d->peer_id;
        conn->peer_pk = d->peer_pk;
        conn->peer_id_set = true;
    }
}

void nodus_inter_dial_conn_open(nodus_tcp_conn_t *conn, bool encrypted) {
    if (!conn) return;
    conn->auth_state = NODUS_CONN_AUTH_OK;
    if (!encrypted) {
        /* No Kyber identity on this node: plaintext is the only option —
         * release what was queued during the handshake. */
        nodus_tcp_pending_flush(conn);
        return;
    }
    /* Session key set. The auth queue holds PRE-FRAMED PLAINTEXT
     * ([7-byte header][payload] per frame, written while the handshake
     * ran — nodus_inter_pool_send_framed, nodus_tcp_send's
     * pending_queue_append): it must never reach the socket as it is. S5b
     * fix round F2: before, it was DISCARDED here although each sender had
     * been told "queued" (0) — a hinted retry then deleted its row for a
     * frame never sent, and a put's replication / a circuit's ri_open were
     * lost the same way. Now every queued frame is RE-SENT ENCRYPTED, in
     * queue order: its payload goes through nodus_tcp_send, which applies
     * the channel crypto now that auth_state is OK. The bound is the one
     * the queue already had (NODUS_TCP_PENDING_MAX). A frame that does not
     * parse ends the replay (the rest is dropped, logged): its bytes are
     * not trusted as a frame boundary. */
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
            QGP_LOG_WARN(LOG_TAG, "INTER_CRYPTO: %s:%d auth queue holds %zu "
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
    QGP_LOG_INFO(LOG_TAG, "INTER_CRYPTO: %s conn %s %s:%d encrypted "
                 "(%d queued frame(s) re-sent encrypted%s)",
                 conn->auth_initiated_by_us ? "outgoing" : "accepted",
                 conn->auth_initiated_by_us ? "to" : "from",
                 conn->ip, conn->port, resent, failed ? ", some FAILED" : "");
    if (failed)
        QGP_LOG_WARN(LOG_TAG, "INTER_CRYPTO: %s:%d — %d queued frame(s) could "
                     "not be re-sent", conn->ip, conn->port, failed);
}
