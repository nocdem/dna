/**
 * @file src/client/nodus_cc_client.c
 * @brief Hard-Fork v1 Stage C.2/E.2 — proposer-side tier-3 client helper.
 *
 * TCP 4004 requires Dilithium5 mutual auth (T2 hello → challenge → auth →
 * auth_ok) before accepting any T3 frame. This helper runs that handshake
 * against each committee peer before sending a w_cc_vote_req and awaiting a
 * verified w_cc_vote_rsp. Each call is a short-lived, authenticated session.
 *
 * Design notes
 *   - Committee-only: the receiving peer's dispatch guard in
 *     nodus/src/witness/nodus_witness.c rejects any non-IDENT t3 message
 *     from a sender that is not in its roster. The caller must therefore be
 *     a committee member whose witness_id appears in the target peer's
 *     roster. Callers outside the committee get a silent drop.
 *   - No Kyber encryption: payloads are already signed; v=1 hello disables
 *     the Kyber handshake branch server-side. Saves one RTT of crypto.
 *   - w_ident drop: the server sends a w_ident to us right after auth_ok.
 *     The on_frame callback filters by msg.type, so anything that is not
 *     NODUS_T3_CC_VOTE_RSP is ignored — including w_ident, stray T2, etc.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nodus/nodus.h"
#include "nodus/nodus_types.h"

#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef enum {
    CC_PHASE_AWAIT_CHALLENGE = 0,  /* hello sent, awaiting t2 challenge */
    CC_PHASE_AWAIT_AUTH_OK,        /* auth sent, awaiting t2 auth_ok */
    CC_PHASE_AWAIT_VOTE_RSP,       /* w_cc_vote_req sent, awaiting rsp */
    CC_PHASE_DONE,
} cc_phase_t;

/* Per-call state threaded through the nodus_tcp poll callback. */
typedef struct {
    cc_phase_t  phase;

    /* Handshake state — filled by the callback, consumed by main loop. */
    bool        challenge_received;
    uint8_t     challenge_nonce[NODUS_NONCE_LEN];

    bool        auth_ok_received;
    bool        auth_error;             /* T2 error at hello/auth phase */
    int         auth_error_code;
    char        auth_error_msg[128];

    /* T3 response state. */
    bool                    response_received;
    bool                    wsig_fail;
    uint32_t                expected_txn_id;
    nodus_t3_cc_vote_rsp_t *rsp_out;
    const nodus_pubkey_t   *expected_peer_pk;
} cc_client_ctx_t;

/* Try T2 decode first during handshake phases, T3 during vote phase.
 * The two wire formats share the CBOR envelope shape ("q" / "r" / "a") so
 * either decoder will reject a foreign-type frame and leave ctx untouched.
 */
static void cc_on_frame(nodus_tcp_conn_t *conn,
                         const uint8_t *payload, size_t len,
                         void *ctx_arg) {
    (void)conn;
    cc_client_ctx_t *ctx = (cc_client_ctx_t *)ctx_arg;
    if (!ctx) return;

    if (ctx->phase == CC_PHASE_AWAIT_CHALLENGE ||
        ctx->phase == CC_PHASE_AWAIT_AUTH_OK) {
        nodus_tier2_msg_t t2;
        memset(&t2, 0, sizeof(t2));
        if (nodus_t2_decode(payload, len, &t2) != 0) {
            nodus_t2_msg_free(&t2);
            return;  /* not T2 — stray frame, keep waiting */
        }

        if (strcmp(t2.method, "challenge") == 0 &&
            ctx->phase == CC_PHASE_AWAIT_CHALLENGE) {
            memcpy(ctx->challenge_nonce, t2.nonce, NODUS_NONCE_LEN);
            ctx->challenge_received = true;
        } else if (strcmp(t2.method, "auth_ok") == 0 &&
                   ctx->phase == CC_PHASE_AWAIT_AUTH_OK) {
            ctx->auth_ok_received = true;
        } else if (strcmp(t2.method, "error") == 0 || t2.type == 'e') {
            ctx->auth_error = true;
            ctx->auth_error_code = t2.error_code;
            size_t mlen = strnlen(t2.error_msg, sizeof(t2.error_msg));
            if (mlen >= sizeof(ctx->auth_error_msg))
                mlen = sizeof(ctx->auth_error_msg) - 1;
            memcpy(ctx->auth_error_msg, t2.error_msg, mlen);
            ctx->auth_error_msg[mlen] = '\0';
        }
        /* Anything else (unexpected method during handshake): ignore. */
        nodus_t2_msg_free(&t2);
        return;
    }

    if (ctx->phase != CC_PHASE_AWAIT_VOTE_RSP) return;
    if (ctx->response_received) return;

    nodus_t3_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    if (nodus_t3_decode(payload, len, &msg) != 0) {
        /* Stray frame (e.g. server-sent w_ident after auth_ok) — keep waiting.
         * t3_decode also fails on T2 frames, which is harmless here. */
        return;
    }
    if (msg.type != NODUS_T3_CC_VOTE_RSP) return;    /* drop w_ident etc */
    if (msg.txn_id != ctx->expected_txn_id)  return;

    if (nodus_t3_verify(&msg, ctx->expected_peer_pk) != 0) {
        ctx->wsig_fail = true;
        ctx->response_received = true;
        return;
    }

    *ctx->rsp_out = msg.cc_vote_rsp;
    ctx->response_received = true;
}

/* Parse "host:port" into host + numeric port. Missing :port falls back to
 * NODUS_DEFAULT_WITNESS_PORT. Returns -1 on malformed input. */
static int parse_peer_address(const char *addr_str, char *ip, size_t ip_cap,
                               uint16_t *port_out) {
    if (!addr_str || !ip || !port_out || ip_cap == 0) return -1;

    const char *colon = strrchr(addr_str, ':');
    if (!colon) {
        size_t host_len = strlen(addr_str);
        if (host_len == 0 || host_len >= ip_cap) return -1;
        memcpy(ip, addr_str, host_len);
        ip[host_len] = '\0';
        *port_out = NODUS_DEFAULT_WITNESS_PORT;
        return 0;
    }

    size_t host_len = (size_t)(colon - addr_str);
    if (host_len == 0 || host_len >= ip_cap) return -1;
    memcpy(ip, addr_str, host_len);
    ip[host_len] = '\0';

    long p = strtol(colon + 1, NULL, 10);
    if (p <= 0 || p > 65535) return -1;
    *port_out = (uint16_t)p;
    return 0;
}

/* Poll the TCP transport until deadline_ms or the predicate returns true.
 * Returns 0 if the predicate succeeded, -2 on deadline expiry. */
static int poll_until(nodus_tcp_t *tcp, cc_client_ctx_t *ctx,
                       uint64_t deadline_ms,
                       bool (*predicate)(cc_client_ctx_t *)) {
    while (!predicate(ctx)) {
        uint64_t now = nodus_time_now_ms();
        if (now >= deadline_ms) return -2;
        int slice = (int)(deadline_ms - now);
        if (slice > 100) slice = 100;
        nodus_tcp_poll(tcp, slice);
    }
    return 0;
}

static bool challenge_or_error(cc_client_ctx_t *ctx) {
    return ctx->challenge_received || ctx->auth_error;
}
static bool auth_ok_or_error(cc_client_ctx_t *ctx) {
    return ctx->auth_ok_received || ctx->auth_error;
}
static bool response_done(cc_client_ctx_t *ctx) {
    return ctx->response_received;
}

int nodus_client_cc_vote_send(const char *peer_address,
                                const nodus_pubkey_t *caller_pk,
                                const nodus_seckey_t *caller_sk,
                                const uint8_t caller_witness_id[32],
                                const nodus_pubkey_t *expected_peer_pk,
                                const uint8_t chain_id[32],
                                const nodus_t3_cc_vote_req_t *req,
                                uint32_t timeout_ms,
                                nodus_t3_cc_vote_rsp_t *rsp_out) {
    if (!peer_address || !caller_pk || !caller_sk || !caller_witness_id ||
        !expected_peer_pk || !chain_id || !req || !rsp_out) {
        return -1;
    }

    char     ip[64];
    uint16_t port = 0;
    if (parse_peer_address(peer_address, ip, sizeof(ip), &port) != 0) {
        return -1;
    }

    memset(rsp_out, 0, sizeof(*rsp_out));

    /* Derive caller fingerprint for T2 hello. */
    nodus_key_t caller_fp;
    if (nodus_fingerprint(caller_pk, &caller_fp) != 0) return -1;

    nodus_tcp_t tcp;
    memset(&tcp, 0, sizeof(tcp));
    if (nodus_tcp_init(&tcp, -1) != 0) return -1;

    cc_client_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.rsp_out          = rsp_out;
    ctx.expected_peer_pk = expected_peer_pk;
    ctx.phase            = CC_PHASE_AWAIT_CHALLENGE;

    tcp.on_frame = cc_on_frame;
    tcp.cb_ctx   = &ctx;

    int rc = -1;

    nodus_tcp_conn_t *conn = nodus_tcp_connect(&tcp, ip, port);
    if (!conn) goto cleanup;

    const uint64_t start_ms    = nodus_time_now_ms();
    const uint64_t deadline_ms = start_ms + (uint64_t)timeout_ms;

    /* TCP connect handshake. */
    while (conn->state != NODUS_CONN_CONNECTED) {
        if (conn->state == NODUS_CONN_CLOSED) { rc = -1; goto cleanup; }
        uint64_t now = nodus_time_now_ms();
        if (now >= deadline_ms) { rc = -2; goto cleanup; }
        int slice = (int)(deadline_ms - now);
        if (slice > 100) slice = 100;
        nodus_tcp_poll(&tcp, slice);
    }

    /* Shared txn for hello/auth — correlates peer's challenge + auth_ok. */
    uint32_t auth_txn = (uint32_t)start_ms ^ (uint32_t)(uintptr_t)&ctx;
    if (auth_txn == 0) auth_txn = 1;

    /* ── Phase 1: send T2 hello, await challenge ─────────────────── */
    {
        static uint8_t buf[4096];
        size_t blen = 0;
        if (nodus_t2_hello(auth_txn, caller_pk, &caller_fp,
                            buf, sizeof(buf), &blen) != 0) {
            rc = -1; goto cleanup;
        }
        if (nodus_tcp_send(conn, buf, blen) != 0) { rc = -1; goto cleanup; }
    }
    if (poll_until(&tcp, &ctx, deadline_ms, challenge_or_error) != 0) {
        rc = -2; goto cleanup;
    }
    if (ctx.auth_error) {
        fprintf(stderr, "cc_vote: hello rejected (code=%d msg=%s)\n",
                ctx.auth_error_code, ctx.auth_error_msg);
        rc = -4; goto cleanup;
    }

    /* ── Phase 2: sign challenge nonce, send auth, await auth_ok ─── */
    {
        nodus_sig_t sig;
        if (nodus_sign(&sig, ctx.challenge_nonce, NODUS_NONCE_LEN,
                        caller_sk) != 0) {
            rc = -1; goto cleanup;
        }
        static uint8_t buf[NODUS_SIG_BYTES + 256];
        size_t blen = 0;
        if (nodus_t2_auth(auth_txn, &sig, buf, sizeof(buf), &blen) != 0) {
            rc = -1; goto cleanup;
        }
        if (nodus_tcp_send(conn, buf, blen) != 0) { rc = -1; goto cleanup; }
        ctx.phase = CC_PHASE_AWAIT_AUTH_OK;
    }
    if (poll_until(&tcp, &ctx, deadline_ms, auth_ok_or_error) != 0) {
        rc = -2; goto cleanup;
    }
    if (ctx.auth_error) {
        fprintf(stderr, "cc_vote: auth rejected (code=%d msg=%s)\n",
                ctx.auth_error_code, ctx.auth_error_msg);
        rc = -4; goto cleanup;
    }

    /* ── Phase 3: send w_cc_vote_req, await w_cc_vote_rsp ────────── */
    ctx.phase = CC_PHASE_AWAIT_VOTE_RSP;

    nodus_t3_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type   = NODUS_T3_CC_VOTE_REQ;

    /* txn_id distinct from auth_txn so a late auth_ok can't spoof as rsp. */
    uint32_t cc_txn = auth_txn + 1;
    if (cc_txn == 0) cc_txn = 2;
    msg.txn_id = cc_txn;
    ctx.expected_txn_id = cc_txn;

    snprintf(msg.method, sizeof(msg.method), "w_cc_vote_req");

    msg.header.version   = NODUS_T3_BFT_PROTOCOL_VER;
    msg.header.round     = 0;
    msg.header.view      = 0;
    memcpy(msg.header.sender_id, caller_witness_id,
           NODUS_T3_WITNESS_ID_LEN);
    msg.header.timestamp = (uint64_t)time(NULL);
    nodus_random((uint8_t *)&msg.header.nonce, sizeof(msg.header.nonce));
    memcpy(msg.header.chain_id, chain_id, 32);

    msg.cc_vote_req = *req;

    static uint8_t enc_buf[NODUS_T3_MAX_MSG_SIZE];
    size_t enc_len = 0;
    if (nodus_t3_encode(&msg, caller_sk,
                         enc_buf, sizeof(enc_buf), &enc_len) != 0) {
        rc = -1; goto cleanup;
    }

    if (nodus_tcp_send(conn, enc_buf, enc_len) != 0) {
        rc = -1; goto cleanup;
    }

    if (poll_until(&tcp, &ctx, deadline_ms, response_done) != 0) {
        rc = -2; goto cleanup;
    }

    rc = ctx.wsig_fail ? -3 : 0;

cleanup:
    nodus_tcp_close(&tcp);
    return rc;
}
