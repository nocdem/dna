/**
 * Nodus — Authentication Handler
 *
 * 3-way Dilithium5 challenge-response:
 *   1. Client: HELLO(pk, fp)
 *   2. Server: verify fp == SHA3-512(pk), send CHALLENGE(nonce)
 *   3. Client: AUTH(SIGN(nonce, sk))
 *   4. Server: VERIFY(sig, nonce, pk) -> AUTH_OK(token)
 */

#include "server/nodus_server.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_channel_crypto.h"
#include "crypto/enc/qgp_kyber.h"

#include <string.h>
#include <stdio.h>

extern void qgp_secure_memzero(void *ptr, size_t len);

int nodus_auth_handle_hello(nodus_server_t *srv, nodus_session_t *sess,
                             const nodus_pubkey_t *pk, const nodus_key_t *fp,
                             uint32_t txn_id) {
    if (!srv || !sess || !pk || !fp) return -1;

    uint8_t buf[8192];

    /* Verify: fingerprint == SHA3-512(public_key) */
    nodus_key_t computed_fp;
    nodus_fingerprint(pk, &computed_fp);
    if (nodus_key_cmp(&computed_fp, fp) != 0) {
        size_t len = 0;
        nodus_t2_error(txn_id, NODUS_ERR_INVALID_SIGNATURE,
                        "fingerprint mismatch", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return -1;
    }

    /* Store client identity in session */
    sess->client_pk = *pk;
    sess->client_fp = *fp;

    /* Generate random nonce */
    nodus_random(sess->nonce, NODUS_NONCE_LEN);
    sess->nonce_pending = true;

    /* Send CHALLENGE */
    size_t len = 0;
    nodus_t2_challenge(txn_id, sess->nonce,
                        buf, sizeof(buf), &len);
    nodus_tcp_send(sess->conn, buf, len);

    return 0;
}

int nodus_auth_handle_auth(nodus_server_t *srv, nodus_session_t *sess,
                            const nodus_sig_t *sig, uint32_t txn_id) {
    if (!srv || !sess || !sig) return -1;

    uint8_t buf[16384];  /* Large enough for AUTH_OK with spk(2592) + kpk_sig(4627) */

    if (!sess->nonce_pending) {
        size_t len = 0;
        nodus_t2_error(txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "no pending challenge", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return -1;
    }

    /* Verify signature of nonce using client's public key */
    int rc = nodus_verify(sig, sess->nonce, NODUS_NONCE_LEN, &sess->client_pk);
    if (rc != 0) {
        size_t len = 0;
        nodus_t2_error(txn_id, NODUS_ERR_INVALID_SIGNATURE,
                        "auth signature invalid", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        sess->nonce_pending = false;
        return -1;
    }

    /* Auth success — generate session token */
    nodus_random(sess->token, NODUS_SESSION_TOKEN_LEN);
    sess->authenticated = true;
    sess->nonce_pending = false;

    /* Set peer identity on connection */
    sess->conn->peer_id = sess->client_fp;
    sess->conn->peer_pk = sess->client_pk;
    sess->conn->peer_id_set = true;

    /* Evict stale sessions for same identity (ghost connections from dead sockets).
     * When a mobile client reconnects, the old session may still be alive because
     * the server hasn't detected the dead socket yet (idle sweep runs every 30s).
     * Without eviction, stale responses can leak into the new connection's slot. */
    for (int i = 0; i < NODUS_MAX_SESSIONS; i++) {
        nodus_session_t *old = &srv->sessions[i];
        if (old == sess) continue;  /* Skip ourselves */
        if (!old->conn || !old->authenticated) continue;
        if (nodus_key_cmp(&old->client_fp, &sess->client_fp) != 0) continue;
        /* Same identity on a different slot — evict */
        {
            char old_fp[33];
            for (int k = 0; k < 16; k++)
                snprintf(old_fp + k*2, sizeof(old_fp) - k*2, "%02x", old->client_fp.bytes[k]);
            old_fp[32] = '\0';
            fprintf(stderr, "SESSION_EVICT: old slot=%d ip=%s fp=%s... (replaced by new slot=%d)\n",
                    old->conn->slot, old->conn->ip, old_fp, sess->conn->slot);
        }
        nodus_tcp_disconnect(&srv->tcp, old->conn);
        old->conn = NULL;
        old->authenticated = false;
    }

    /* Track presence */
    nodus_presence_add_local(srv, &sess->client_fp);
    {
        char fp_hex[33];
        for (int k = 0; k < 16; k++)
            snprintf(fp_hex + k*2, sizeof(fp_hex) - k*2, "%02x", sess->client_fp.bytes[k]);
        fp_hex[32] = '\0';
        fprintf(stderr, "AUTH_OK: client %s... authenticated (presence added)\n", fp_hex);
    }

    /* Send AUTH_OK with session token (+ Kyber pubkey if client supports v2+) */
    size_t len = 0;
    if (srv->identity.has_kyber && sess->proto_version >= 2) {
        /* Sign kyber_pk || nonce with server's Dilithium5 key.
         * This binds the Kyber public key to this specific auth session,
         * preventing MITM replacement of the Kyber PK. */
        uint8_t sign_data[NODUS_KYBER_PK_BYTES + NODUS_NONCE_LEN];
        memcpy(sign_data, srv->identity.kyber_pk, NODUS_KYBER_PK_BYTES);
        memcpy(sign_data + NODUS_KYBER_PK_BYTES, sess->nonce, NODUS_NONCE_LEN);

        nodus_sig_t kpk_sig;
        if (nodus_sign(&kpk_sig, sign_data, sizeof(sign_data), &srv->identity.sk) != 0) {
            fprintf(stderr, "AUTH: Failed to sign Kyber PK for AUTH_OK\n");
            nodus_t2_auth_ok(txn_id, sess->token, buf, sizeof(buf), &len);
            nodus_tcp_send(sess->conn, buf, len);
            return 0;
        }

        nodus_t2_auth_ok_kyber(txn_id, sess->token, srv->identity.kyber_pk,
                                &srv->identity.pk, &kpk_sig,
                                buf, sizeof(buf), &len);
    } else {
        nodus_t2_auth_ok(txn_id, sess->token,
                          buf, sizeof(buf), &len);
    }
    nodus_tcp_send(sess->conn, buf, len);

    return 0;
}

int nodus_auth_handle_key_init(nodus_server_t *srv, nodus_session_t *sess,
                                const uint8_t *kyber_ct, const uint8_t *nonce_c,
                                uint32_t txn_id) {
    if (!srv || !sess || !kyber_ct || !nonce_c) return -1;
    if (!srv->identity.has_kyber) return -1;

    uint8_t buf[8192];

    /* Decapsulate: shared_secret = Kyber_decap(ct, server_sk) */
    uint8_t shared_secret[32];
    int rc = qgp_kem1024_decapsulate(shared_secret, kyber_ct, srv->identity.kyber_sk);
    if (rc != 0) {
        size_t len = 0;
        nodus_t2_error(txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "KEM decapsulation failed", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return -1;
    }

    /* Generate server nonce */
    uint8_t nonce_s[NODUS_NONCE_LEN];
    nodus_random(nonce_s, NODUS_NONCE_LEN);

    /* Init channel crypto */
    rc = nodus_channel_crypto_init(&sess->channel_crypto, shared_secret, nonce_c, nonce_s);
    qgp_secure_memzero(shared_secret, sizeof(shared_secret));
    if (rc != 0) {
        size_t len = 0;
        nodus_t2_error(txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "channel crypto init failed", buf, sizeof(buf), &len);
        nodus_tcp_send(sess->conn, buf, len);
        return -1;
    }

    /* Send KEY_ACK BEFORE enabling encryption (must arrive plaintext) */
    size_t len = 0;
    nodus_t2_key_ack(txn_id, nonce_s, buf, sizeof(buf), &len);
    nodus_tcp_send_raw(sess->conn, buf, len);

    /* NOW attach crypto to connection — all subsequent frames will be encrypted */
    sess->conn->crypto = &sess->channel_crypto;

    fprintf(stderr, "CHANNEL_CRYPTO: session slot=%d encrypted (Kyber1024+AES-256-GCM)\n",
            sess->conn->slot);

    return 0;
}
