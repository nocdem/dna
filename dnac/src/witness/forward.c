/**
 * @file forward.c
 * @brief Non-Leader Request Forwarding
 *
 * When a client connects to a non-leader witness, the witness forwards
 * the request to the current leader and relays the response back.
 *
 * This provides transparent leader handling for clients.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dnac/bft.h"
#include "dnac/tcp.h"
#include "dnac/nodus.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_dilithium.h"

#define LOG_TAG "BFT_FORWARD"

/* External state from bft_main.c */
extern dnac_bft_context_t *g_bft_ctx;
extern dnac_tcp_server_t *g_tcp_server;

/* External functions */
extern int bft_peer_send_to_leader(const uint8_t *data, size_t len);

/* Pending forward requests (waiting for response from leader) */
typedef struct {
    bool active;
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    int client_fd;                      /* Client socket for response */
    uint64_t timestamp;
    uint64_t timeout_ms;
} pending_forward_t;

#define MAX_PENDING_FORWARDS 64
static pending_forward_t g_pending_forwards[MAX_PENDING_FORWARDS];
static pthread_mutex_t g_forward_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ============================================================================
 * Forward Request
 * ========================================================================== */

int bft_forward_request(dnac_bft_context_t *ctx,
                        const dnac_spend_request_t *request,
                        int client_fd) {
    if (!ctx || !request) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    /* Verify we are not leader */
    if (dnac_bft_is_leader(ctx)) {
        QGP_LOG_WARN(LOG_TAG, "forward_request called but we are leader");
        return DNAC_BFT_ERROR_NOT_LEADER;
    }

    /* Create forward request message */
    dnac_bft_forward_req_t fwd;
    memset(&fwd, 0, sizeof(fwd));

    fwd.header.version = DNAC_BFT_PROTOCOL_VERSION;
    fwd.header.type = BFT_MSG_FORWARD_REQ;
    fwd.header.round = ctx->current_round;
    fwd.header.view = ctx->current_view;
    memcpy(fwd.header.sender_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);
    fwd.header.timestamp = time(NULL);

    memcpy(fwd.tx_hash, request->tx_hash, DNAC_TX_HASH_SIZE);
    /* v0.4.0: Forward full tx_data instead of single nullifier */
    fwd.tx_len = request->tx_len;
    memcpy(fwd.tx_data, request->tx_data, request->tx_len);
    memcpy(fwd.sender_pubkey, request->sender_pubkey, DNAC_PUBKEY_SIZE);
    memcpy(fwd.client_signature, request->signature, DNAC_SIGNATURE_SIZE);
    fwd.fee_amount = request->fee_amount;
    memcpy(fwd.forwarder_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);

    /* Gap 18 Fix (v0.6.0): Sign forward request for authentication */
    if (ctx->my_privkey && ctx->my_privkey_size > 0) {
        /* Sign: tx_hash || forwarder_id || timestamp */
        uint8_t sign_data[DNAC_TX_HASH_SIZE + DNAC_BFT_WITNESS_ID_SIZE + 8];
        memcpy(sign_data, fwd.tx_hash, DNAC_TX_HASH_SIZE);
        memcpy(sign_data + DNAC_TX_HASH_SIZE, fwd.forwarder_id, DNAC_BFT_WITNESS_ID_SIZE);
        /* Little-endian timestamp */
        uint64_t ts = fwd.header.timestamp;
        for (int j = 0; j < 8; j++) {
            sign_data[DNAC_TX_HASH_SIZE + DNAC_BFT_WITNESS_ID_SIZE + j] =
                (ts >> (j * 8)) & 0xFF;
        }

        size_t sig_len = 0;
        int sign_rc = qgp_dsa87_sign(fwd.signature, &sig_len,
                                      sign_data, sizeof(sign_data),
                                      ctx->my_privkey);
        if (sign_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to sign forward request: %d", sign_rc);
            return DNAC_BFT_ERROR_INVALID_SIGNATURE;
        }
        QGP_LOG_DEBUG(LOG_TAG, "Signed forward request (sig_len=%zu)", sig_len);
    } else {
        QGP_LOG_WARN(LOG_TAG, "No private key available, forward request unsigned");
    }

    /* Serialize - buffer must fit tx_data (up to 64KB) */
    uint8_t buffer[DNAC_BFT_MAX_TX_SIZE + 16384];
    size_t written;

    int rc = dnac_bft_forward_req_serialize(&fwd, buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                            sizeof(buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                            &written);
    if (rc != DNAC_BFT_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize forward request");
        return rc;
    }

    dnac_tcp_write_frame_header(buffer, BFT_MSG_FORWARD_REQ, (uint32_t)written);

    /* Register pending request */
    pthread_mutex_lock(&g_forward_mutex);

    int slot = -1;
    for (int i = 0; i < MAX_PENDING_FORWARDS; i++) {
        if (!g_pending_forwards[i].active) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        pthread_mutex_unlock(&g_forward_mutex);
        QGP_LOG_ERROR(LOG_TAG, "Too many pending forwards");
        return DNAC_BFT_ERROR_OUT_OF_MEMORY;
    }

    g_pending_forwards[slot].active = true;
    memcpy(g_pending_forwards[slot].tx_hash, request->tx_hash, DNAC_TX_HASH_SIZE);
    g_pending_forwards[slot].client_fd = client_fd;
    g_pending_forwards[slot].timestamp = dnac_tcp_get_time_ms();
    g_pending_forwards[slot].timeout_ms = 30000;  /* 30 second timeout */

    pthread_mutex_unlock(&g_forward_mutex);

    /* Send to leader */
    rc = bft_peer_send_to_leader(buffer, DNAC_TCP_FRAME_HEADER_SIZE + written);
    if (rc != DNAC_BFT_SUCCESS) {
        /* Cancel pending */
        pthread_mutex_lock(&g_forward_mutex);
        g_pending_forwards[slot].active = false;
        pthread_mutex_unlock(&g_forward_mutex);

        QGP_LOG_ERROR(LOG_TAG, "Failed to send forward request to leader");
        return rc;
    }

    QGP_LOG_INFO(LOG_TAG, "Forwarded request to leader (slot %d)", slot);
    return DNAC_BFT_SUCCESS;
}

/* ============================================================================
 * Handle Forward Response
 * ========================================================================== */

int bft_handle_forward_response(dnac_bft_context_t *ctx,
                                const dnac_bft_forward_rsp_t *response,
                                dnac_tcp_server_t *server) {
    if (!ctx || !response) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    /* Find pending request */
    pthread_mutex_lock(&g_forward_mutex);

    int slot = -1;
    for (int i = 0; i < MAX_PENDING_FORWARDS; i++) {
        if (g_pending_forwards[i].active &&
            memcmp(g_pending_forwards[i].tx_hash, response->tx_hash,
                   DNAC_TX_HASH_SIZE) == 0) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        pthread_mutex_unlock(&g_forward_mutex);
        QGP_LOG_WARN(LOG_TAG, "Received forward response for unknown request");
        return DNAC_BFT_ERROR_NOT_FOUND;
    }

    int client_fd = g_pending_forwards[slot].client_fd;
    g_pending_forwards[slot].active = false;

    pthread_mutex_unlock(&g_forward_mutex);

    QGP_LOG_INFO(LOG_TAG, "Received forward response, relaying to client");

    /* Convert to spend response */
    dnac_spend_response_t spend_rsp;
    memset(&spend_rsp, 0, sizeof(spend_rsp));

    if (response->status == DNAC_BFT_SUCCESS && response->witness_count >= 2) {
        spend_rsp.status = DNAC_NODUS_STATUS_APPROVED;

        /* Copy first witness attestation */
        memcpy(spend_rsp.witness_id, response->witnesses[0].witness_id, 32);
        memcpy(spend_rsp.signature, response->witnesses[0].signature, DNAC_SIGNATURE_SIZE);
        memcpy(spend_rsp.server_pubkey, response->witnesses[0].server_pubkey, DNAC_PUBKEY_SIZE);
        spend_rsp.timestamp = response->witnesses[0].timestamp;
    } else {
        spend_rsp.status = DNAC_NODUS_STATUS_REJECTED;
        snprintf(spend_rsp.error_message, sizeof(spend_rsp.error_message),
                 "Consensus failed (status=%d, witnesses=%d)",
                 response->status, response->witness_count);
    }

    /* Serialize spend response */
    uint8_t rsp_buffer[16384];
    size_t rsp_written;

    int rc = dnac_spend_response_serialize(&spend_rsp, rsp_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                           sizeof(rsp_buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                           &rsp_written);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize spend response");
        return DNAC_BFT_ERROR_INVALID_MESSAGE;
    }

    dnac_tcp_write_frame_header(rsp_buffer, DNAC_NODUS_MSG_SPEND_RESPONSE, (uint32_t)rsp_written);

    /* Send to client */
    if (server && client_fd >= 0) {
        dnac_tcp_server_send(server, client_fd, rsp_buffer,
                             DNAC_TCP_FRAME_HEADER_SIZE + rsp_written);
    }

    return DNAC_BFT_SUCCESS;
}

/* ============================================================================
 * Timeout Handling
 * ========================================================================== */

int bft_forward_check_timeouts(void) {
    uint64_t now = dnac_tcp_get_time_ms();
    int expired = 0;

    pthread_mutex_lock(&g_forward_mutex);

    for (int i = 0; i < MAX_PENDING_FORWARDS; i++) {
        if (g_pending_forwards[i].active) {
            uint64_t elapsed = now - g_pending_forwards[i].timestamp;
            if (elapsed > g_pending_forwards[i].timeout_ms) {
                QGP_LOG_WARN(LOG_TAG, "Forward request slot %d timed out", i);

                int client_fd = g_pending_forwards[i].client_fd;
                g_pending_forwards[i].active = false;
                expired++;

                /* Send timeout response to client (Gap 16: v0.6.0) */
                if (g_tcp_server && client_fd >= 0 && g_bft_ctx) {
                    dnac_spend_response_t timeout_rsp;
                    memset(&timeout_rsp, 0, sizeof(timeout_rsp));

                    timeout_rsp.status = DNAC_NODUS_STATUS_TIMEOUT;
                    memcpy(timeout_rsp.witness_id, g_bft_ctx->my_id, 32);
                    memcpy(timeout_rsp.server_pubkey, g_bft_ctx->my_pubkey, DNAC_PUBKEY_SIZE);
                    timeout_rsp.timestamp = (uint64_t)time(NULL);
                    strncpy(timeout_rsp.error_message, "Forward request timed out",
                            sizeof(timeout_rsp.error_message) - 1);

                    uint8_t rsp_buffer[16384];
                    size_t rsp_written;
                    if (dnac_spend_response_serialize(&timeout_rsp,
                            rsp_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                            sizeof(rsp_buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                            &rsp_written) == 0) {
                        dnac_tcp_write_frame_header(rsp_buffer,
                            DNAC_NODUS_MSG_SPEND_RESPONSE, (uint32_t)rsp_written);
                        dnac_tcp_server_send(g_tcp_server, client_fd, rsp_buffer,
                            DNAC_TCP_FRAME_HEADER_SIZE + rsp_written);
                        QGP_LOG_INFO(LOG_TAG, "Sent timeout response to client %d", client_fd);
                    }
                }
            }
        }
    }

    pthread_mutex_unlock(&g_forward_mutex);

    return expired;
}

/* ============================================================================
 * Initialization
 * ========================================================================== */

void bft_forward_init(void) {
    pthread_mutex_lock(&g_forward_mutex);
    memset(g_pending_forwards, 0, sizeof(g_pending_forwards));
    pthread_mutex_unlock(&g_forward_mutex);
}

void bft_forward_shutdown(void) {
    pthread_mutex_lock(&g_forward_mutex);
    memset(g_pending_forwards, 0, sizeof(g_pending_forwards));
    pthread_mutex_unlock(&g_forward_mutex);
}

int bft_forward_pending_count(void) {
    int count = 0;

    pthread_mutex_lock(&g_forward_mutex);
    for (int i = 0; i < MAX_PENDING_FORWARDS; i++) {
        if (g_pending_forwards[i].active) {
            count++;
        }
    }
    pthread_mutex_unlock(&g_forward_mutex);

    return count;
}

/* ============================================================================
 * Complete Pending Forward (called when forwarder reaches COMMIT)
 *
 * When a non-leader witness forwards a request and then participates in
 * consensus, this function is called when COMMIT is reached to send the
 * response back to the waiting client.
 * ========================================================================== */

int bft_forward_complete_for_txhash(const uint8_t *tx_hash,
                                    dnac_tcp_server_t *server,
                                    const uint8_t *witness_id,
                                    const uint8_t *pubkey) {
    if (!tx_hash) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    fprintf(stderr, "[FORWARD] bft_forward_complete_for_txhash called, tx_hash=%02x%02x%02x%02x...\n",
            tx_hash[0], tx_hash[1], tx_hash[2], tx_hash[3]);
    fflush(stderr);

    pthread_mutex_lock(&g_forward_mutex);

    int slot = -1;
    for (int i = 0; i < MAX_PENDING_FORWARDS; i++) {
        if (g_pending_forwards[i].active) {
            fprintf(stderr, "[FORWARD]   slot[%d] active, tx_hash=%02x%02x%02x%02x...\n",
                    i, g_pending_forwards[i].tx_hash[0], g_pending_forwards[i].tx_hash[1],
                    g_pending_forwards[i].tx_hash[2], g_pending_forwards[i].tx_hash[3]);
        }
        if (g_pending_forwards[i].active &&
            memcmp(g_pending_forwards[i].tx_hash, tx_hash, DNAC_TX_HASH_SIZE) == 0) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        pthread_mutex_unlock(&g_forward_mutex);
        fprintf(stderr, "[FORWARD] No matching pending forward found\n");
        fflush(stderr);
        /* Not a forwarded request on this witness, that's OK */
        return DNAC_BFT_SUCCESS;
    }
    fprintf(stderr, "[FORWARD] Found matching pending forward in slot %d\n", slot);
    fflush(stderr);

    int client_fd = g_pending_forwards[slot].client_fd;
    g_pending_forwards[slot].active = false;

    pthread_mutex_unlock(&g_forward_mutex);

    QGP_LOG_INFO(LOG_TAG, "Completing forward for committed tx (client fd=%d)", client_fd);

    /* Build and send SPEND_RESPONSE to client */
    dnac_spend_response_t spend_rsp;
    memset(&spend_rsp, 0, sizeof(spend_rsp));

    spend_rsp.status = DNAC_NODUS_STATUS_APPROVED;
    if (witness_id) {
        memcpy(spend_rsp.witness_id, witness_id, 32);
    }
    if (pubkey) {
        memcpy(spend_rsp.server_pubkey, pubkey, DNAC_PUBKEY_SIZE);
    }
    spend_rsp.timestamp = (uint64_t)time(NULL);

    /* Sign the response: tx_hash + witness_id + timestamp (little-endian) */
    if (g_bft_ctx && g_bft_ctx->my_privkey && g_bft_ctx->my_privkey_size > 0 && tx_hash) {
        uint8_t signed_data[DNAC_TX_HASH_SIZE + 32 + 8];
        memcpy(signed_data, tx_hash, DNAC_TX_HASH_SIZE);
        memcpy(signed_data + DNAC_TX_HASH_SIZE, spend_rsp.witness_id, 32);
        /* Little-endian timestamp */
        for (int j = 0; j < 8; j++) {
            signed_data[DNAC_TX_HASH_SIZE + 32 + j] = (spend_rsp.timestamp >> (j * 8)) & 0xFF;
        }

        size_t sig_len = 0;
        int sign_rc = qgp_dsa87_sign(spend_rsp.signature, &sig_len,
                                      signed_data, sizeof(signed_data),
                                      g_bft_ctx->my_privkey);
        if (sign_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to sign forward response: %d", sign_rc);
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "Signed forward response (sig_len=%zu)", sig_len);
        }
    }

    /* Serialize spend response */
    uint8_t rsp_buffer[16384];
    size_t rsp_written;

    int rc = dnac_spend_response_serialize(&spend_rsp, rsp_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                           sizeof(rsp_buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                           &rsp_written);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize spend response for forward complete");
        return DNAC_BFT_ERROR_INVALID_MESSAGE;
    }

    dnac_tcp_write_frame_header(rsp_buffer, DNAC_NODUS_MSG_SPEND_RESPONSE, (uint32_t)rsp_written);

    /* Send to client */
    if (server && client_fd >= 0) {
        dnac_tcp_server_send(server, client_fd, rsp_buffer,
                             DNAC_TCP_FRAME_HEADER_SIZE + rsp_written);
        QGP_LOG_INFO(LOG_TAG, "Sent SPEND_RESPONSE to client fd=%d", client_fd);
    }

    return DNAC_BFT_SUCCESS;
}
