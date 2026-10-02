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
#include "crypto/nodus_sign.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/qgp_mlkem.h"
#include "crypto/utils/qgp_log.h"

#include <string.h>

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

/* challenge → auth. Only on a conn we dialed (the caller's role split), and
 * once: a repeated challenge (the nonce is already retained) is not signed
 * again — this node never signs a nonce a second time on one conn. */
static nodus_inter_dial_rc_t on_challenge(nodus_inter_dial_t *d,
                                          const nodus_inter_dial_io_t *io,
                                          const nodus_tier2_msg_t *msg) {
    if (d->has_challenge_nonce || d->authenticated) {
        QGP_LOG_WARN(LOG_TAG, "INTER: repeated challenge from %s:%u — "
                     "not signed, dropped", io_ip(io), (unsigned)io->peer_port);
        return NODUS_INTER_DIAL_DONE;
    }
    nodus_sig_t sig;
    nodus_sign_auth_challenge(&sig, msg->nonce, &io->identity->sk);
    /* CRIT-1: retain the challenge nonce — the peer signs
     * (kyber_pk || this nonce) as kpk_sig, so auth_ok cannot verify the
     * binding without it. */
    memcpy(d->challenge_nonce, msg->nonce, NODUS_NONCE_LEN);
    d->has_challenge_nonce = true;
    uint8_t buf[8192];
    size_t rlen = 0;
    nodus_t2_auth(msg->txn_id, &sig, buf, sizeof(buf), &rlen);
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
        nodus_t2_key_init(msg->txn_id, ct, nc, alg, ki_buf, sizeof(ki_buf), &ki_len);
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
