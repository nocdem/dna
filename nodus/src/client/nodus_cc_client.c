/**
 * @file src/client/nodus_cc_client.c
 * @brief Hard-Fork v1 Stage E.2 — proposer-side tier-3 client helper.
 *
 * Short-lived connect → send w_cc_vote_req → await w_cc_vote_rsp → verify
 * peer wsig → return. Implements nodus_client_cc_vote_send declared in
 * include/nodus/nodus.h.
 *
 * Design notes
 *   - Committee-only: the receiving peer's dispatch guard in
 *     nodus/src/witness/nodus_witness.c:661 rejects any non-IDENT t3
 *     message from a sender that is not in its roster. The caller must
 *     therefore be a committee member whose witness_id appears in the
 *     target peer's roster. Callers outside the committee get a silent
 *     drop (no response, which surfaces here as a timeout).
 *   - Short-lived: each call opens + closes its own nodus_tcp_t. CLI
 *     orchestration is the only caller today and iterates peer-by-peer.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nodus/nodus.h"
#include "nodus/nodus_types.h"

#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Per-call state threaded through the nodus_tcp poll callback. */
typedef struct {
    bool        response_received;
    bool        wsig_fail;
    uint32_t    expected_txn_id;
    nodus_t3_cc_vote_rsp_t *rsp_out;
    const nodus_pubkey_t *expected_peer_pk;
} cc_client_ctx_t;

static void cc_on_frame(nodus_tcp_conn_t *conn,
                         const uint8_t *payload, size_t len,
                         void *ctx_arg) {
    (void)conn;
    cc_client_ctx_t *ctx = (cc_client_ctx_t *)ctx_arg;
    if (!ctx || ctx->response_received) return;

    nodus_t3_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    if (nodus_t3_decode(payload, len, &msg) != 0) {
        /* Malformed frame — keep waiting; peer may have sent junk but
         * the real response might still arrive. */
        return;
    }
    if (msg.type != NODUS_T3_CC_VOTE_RSP) return;
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

int nodus_client_cc_vote_send(const char *peer_address,
                                const nodus_seckey_t *caller_sk,
                                const uint8_t caller_witness_id[32],
                                const nodus_pubkey_t *expected_peer_pk,
                                const uint8_t chain_id[32],
                                const nodus_t3_cc_vote_req_t *req,
                                uint32_t timeout_ms,
                                nodus_t3_cc_vote_rsp_t *rsp_out) {
    if (!peer_address || !caller_sk || !caller_witness_id ||
        !expected_peer_pk || !chain_id || !req || !rsp_out) {
        return -1;
    }

    char     ip[64];
    uint16_t port = 0;
    if (parse_peer_address(peer_address, ip, sizeof(ip), &port) != 0) {
        return -1;
    }

    memset(rsp_out, 0, sizeof(*rsp_out));

    nodus_tcp_t tcp;
    memset(&tcp, 0, sizeof(tcp));
    if (nodus_tcp_init(&tcp, -1) != 0) return -1;

    cc_client_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.rsp_out          = rsp_out;
    ctx.expected_peer_pk = expected_peer_pk;

    tcp.on_frame = cc_on_frame;
    tcp.cb_ctx   = &ctx;

    int rc = -1;

    nodus_tcp_conn_t *conn = nodus_tcp_connect(&tcp, ip, port);
    if (!conn) goto cleanup;

    const uint64_t start_ms    = nodus_time_now_ms();
    const uint64_t deadline_ms = start_ms + (uint64_t)timeout_ms;

    /* Drive the connect handshake to completion. */
    while (conn->state != NODUS_CONN_CONNECTED) {
        if (conn->state == NODUS_CONN_CLOSED) { rc = -1; goto cleanup; }
        uint64_t now = nodus_time_now_ms();
        if (now >= deadline_ms) { rc = -2; goto cleanup; }
        int slice = (int)(deadline_ms - now);
        if (slice > 100) slice = 100;
        nodus_tcp_poll(&tcp, slice);
    }

    /* Compose w_cc_vote_req. */
    nodus_t3_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type   = NODUS_T3_CC_VOTE_REQ;

    /* txn_id: non-zero, unlikely to collide in a single committee round.
     * Caller does one send per peer so collisions across calls don't
     * matter for correctness — this is just "ensure we ignore stray
     * frames from other peers on the same connection". */
    uint32_t txn = (uint32_t)start_ms ^ (uint32_t)(uintptr_t)&ctx;
    if (txn == 0) txn = 1;
    msg.txn_id = txn;
    ctx.expected_txn_id = txn;

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

    /* Wait for verified w_cc_vote_rsp. */
    while (!ctx.response_received) {
        uint64_t now = nodus_time_now_ms();
        if (now >= deadline_ms) { rc = -2; goto cleanup; }
        int slice = (int)(deadline_ms - now);
        if (slice > 100) slice = 100;
        nodus_tcp_poll(&tcp, slice);
    }

    rc = ctx.wsig_fail ? -3 : 0;

cleanup:
    nodus_tcp_close(&tcp);
    return rc;
}
