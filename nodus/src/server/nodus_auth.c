/**
 * Nodus v5 — Authentication Handler
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

#include <string.h>
#include <stdio.h>

static uint8_t auth_buf[8192];

int nodus_auth_handle_hello(nodus_server_t *srv, nodus_session_t *sess,
                             const nodus_pubkey_t *pk, const nodus_key_t *fp,
                             uint32_t txn_id) {
    if (!srv || !sess || !pk || !fp) return -1;

    /* Verify: fingerprint == SHA3-512(public_key) */
    nodus_key_t computed_fp;
    nodus_fingerprint(pk, &computed_fp);
    if (nodus_key_cmp(&computed_fp, fp) != 0) {
        size_t len = 0;
        nodus_t2_error(txn_id, NODUS_ERR_INVALID_SIGNATURE,
                        "fingerprint mismatch", auth_buf, sizeof(auth_buf), &len);
        nodus_tcp_send(sess->conn, auth_buf, len);
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
                        auth_buf, sizeof(auth_buf), &len);
    nodus_tcp_send(sess->conn, auth_buf, len);

    return 0;
}

int nodus_auth_handle_auth(nodus_server_t *srv, nodus_session_t *sess,
                            const nodus_sig_t *sig, uint32_t txn_id) {
    if (!srv || !sess || !sig) return -1;

    if (!sess->nonce_pending) {
        size_t len = 0;
        nodus_t2_error(txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "no pending challenge", auth_buf, sizeof(auth_buf), &len);
        nodus_tcp_send(sess->conn, auth_buf, len);
        return -1;
    }

    /* Verify signature of nonce using client's public key */
    int rc = nodus_verify(sig, sess->nonce, NODUS_NONCE_LEN, &sess->client_pk);
    if (rc != 0) {
        size_t len = 0;
        nodus_t2_error(txn_id, NODUS_ERR_INVALID_SIGNATURE,
                        "auth signature invalid", auth_buf, sizeof(auth_buf), &len);
        nodus_tcp_send(sess->conn, auth_buf, len);
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

    /* Track presence */
    nodus_presence_add_local(srv, &sess->client_fp);
    {
        char fp_hex[33];
        for (int k = 0; k < 16; k++)
            sprintf(fp_hex + k*2, "%02x", sess->client_fp.bytes[k]);
        fp_hex[32] = '\0';
        fprintf(stderr, "AUTH_OK: client %s... authenticated (presence added)\n", fp_hex);
    }

    /* Send AUTH_OK with session token */
    size_t len = 0;
    nodus_t2_auth_ok(txn_id, sess->token,
                      auth_buf, sizeof(auth_buf), &len);
    nodus_tcp_send(sess->conn, auth_buf, len);

    return 0;
}
