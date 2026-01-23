/**
 * @file bft_main.c
 * @brief DNAC Witness Server - BFT Consensus Implementation
 *
 * This is the main loop for DNAC witness servers using BFT consensus.
 * Features:
 * - Uses TCP for inter-witness communication
 * - Participates in PBFT-like consensus rounds
 * - Supports leader election and view changes
 *
 * Usage: dnac-witness [options]
 *   -d <dir>      Data directory (default: ~/.dna)
 *   -p <port>     TCP port (default: 4200)
 *   -a <addr>     My address for roster (IP:port)
 *   -r <roster>   Initial roster file (optional)
 *   -h            Show help
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#include <dna/dna_engine.h>
#include "dnac/bft.h"
#include "dnac/tcp.h"
#include "dnac/nodus.h"
#include "dnac/witness.h"
#include "dnac/version.h"

#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_sha3.h"
#include "crypto/utils/qgp_dilithium.h"

#define LOG_TAG "BFT_MAIN"

/* ============================================================================
 * Global State
 * ========================================================================== */

static volatile int g_running = 1;
dnac_bft_context_t *g_bft_ctx = NULL;  /* Non-static for access from forward.c */
static dnac_tcp_server_t *g_tcp_server = NULL;

/* Identity loading state */
static volatile int g_identity_loaded = 0;
static volatile int g_identity_result = -1;

/* External peer functions */
extern int bft_peer_manager_init(dnac_bft_context_t *bft_ctx, dnac_tcp_server_t *tcp_server);
extern void bft_peer_manager_shutdown(void);
extern int bft_peer_connect_to_roster(void);
extern void bft_peer_on_connect(int peer_index, const uint8_t *peer_id);
extern void bft_peer_on_disconnect(int peer_index);

/* External nullifier functions (from witness/nullifier.c) */
extern int witness_nullifier_init(const char *db_path);
extern void witness_nullifier_shutdown(void);
extern bool witness_nullifier_exists(const uint8_t *nullifier);
extern int witness_nullifier_add(const uint8_t *nullifier, const uint8_t *tx_hash);

/* ============================================================================
 * Signal Handler
 * ========================================================================== */

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    printf("\nShutting down witness...\n");
}

/* ============================================================================
 * Identity Loading
 * ========================================================================== */

static void identity_loaded_callback(unsigned long request_id, int result, void *user_data) {
    (void)request_id;
    (void)user_data;
    g_identity_result = result;
    g_identity_loaded = 1;
}

static int load_identity_keys(const char *data_dir,
                              uint8_t *witness_id_out,
                              uint8_t *pubkey_out,
                              uint8_t **privkey_out,
                              size_t *privkey_size_out,
                              char *fingerprint_out) {
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/keys/identity.dsa", data_dir);

    qgp_key_t *key = NULL;
    if (qgp_key_load(key_path, &key) != 0 || !key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load signing key: %s", key_path);
        return -1;
    }

    if (key->type != QGP_KEY_TYPE_DSA87 || !key->public_key || !key->private_key) {
        QGP_LOG_ERROR(LOG_TAG, "Not a Dilithium5 key or missing keys");
        qgp_key_free(key);
        return -1;
    }

    /* Copy public key */
    if (key->public_key_size != DNAC_PUBKEY_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Unexpected public key size: %zu", key->public_key_size);
        qgp_key_free(key);
        return -1;
    }
    memcpy(pubkey_out, key->public_key, DNAC_PUBKEY_SIZE);

    /* Copy private key */
    *privkey_out = malloc(key->private_key_size);
    if (!*privkey_out) {
        qgp_key_free(key);
        return -1;
    }
    memcpy(*privkey_out, key->private_key, key->private_key_size);
    *privkey_size_out = key->private_key_size;

    /* Compute fingerprint */
    if (qgp_sha3_512_fingerprint(key->public_key, key->public_key_size, fingerprint_out) != 0) {
        free(*privkey_out);
        qgp_key_free(key);
        return -1;
    }

    /* Use first 32 bytes of fingerprint as witness ID */
    for (int i = 0; i < 32; i++) {
        char hex[3] = {fingerprint_out[i*2], fingerprint_out[i*2+1], 0};
        witness_id_out[i] = (uint8_t)strtol(hex, NULL, 16);
    }

    qgp_key_free(key);
    return 0;
}

/* ============================================================================
 * Roster File Loading
 * ========================================================================== */

/**
 * Load roster addresses from file (one address per line: IP:port)
 * Format: IP:port
 * Example:
 *   192.168.0.195:4200
 *   192.168.0.196:4200
 *   192.168.0.199:4200
 */
static int load_roster_from_file(const char *filename, dnac_bft_context_t *ctx) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open roster file: %s", filename);
        return -1;
    }

    char line[256];
    int count = 0;

    while (fgets(line, sizeof(line), f)) {
        /* Remove newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        char *cr = strchr(line, '\r');
        if (cr) *cr = '\0';

        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#') continue;

        /* Trim whitespace */
        char *addr = line;
        while (*addr == ' ' || *addr == '\t') addr++;
        if (*addr == '\0') continue;

        /* Note: We don't skip ourselves here - we want consistent ordering */
        /* The my_index will be set after sorting */

        /* Add placeholder entry - ID will be filled on IDENTIFY */
        uint8_t placeholder_id[DNAC_BFT_WITNESS_ID_SIZE] = {0};
        uint8_t placeholder_pk[DNAC_PUBKEY_SIZE] = {0};

        /* Set a unique placeholder based on address hash */
        qgp_sha3_256((const uint8_t*)addr, strlen(addr), placeholder_id);

        int rc = dnac_bft_roster_add_witness(ctx, placeholder_id, placeholder_pk, addr);
        if (rc == DNAC_BFT_SUCCESS) {
            QGP_LOG_INFO(LOG_TAG, "Added bootstrap peer: %s", addr);
            count++;
        }
    }

    fclose(f);
    QGP_LOG_INFO(LOG_TAG, "Loaded %d addresses from roster file", count);
    return count;
}

/* ============================================================================
 * Identity Message Helpers
 * ========================================================================== */

/**
 * Send IDENTIFY message to peer (witness_id + pubkey + address)
 */
static void send_identify(int peer_fd, const uint8_t *witness_id,
                          const uint8_t *pubkey, const char *address) {
    /* Payload: witness_id (32) + pubkey (2592) + address_len (2) + address */
    size_t addr_len = strlen(address);
    size_t payload_len = DNAC_BFT_WITNESS_ID_SIZE + DNAC_PUBKEY_SIZE + 2 + addr_len;

    /* Full frame: header (9) + payload */
    size_t frame_len = DNAC_TCP_FRAME_HEADER_SIZE + payload_len;
    uint8_t *frame = malloc(frame_len);
    if (!frame) return;

    /* Write frame header */
    dnac_tcp_write_frame_header(frame, BFT_MSG_IDENTIFY, payload_len);

    /* Write payload */
    uint8_t *payload = frame + DNAC_TCP_FRAME_HEADER_SIZE;
    size_t offset = 0;
    memcpy(payload + offset, witness_id, DNAC_BFT_WITNESS_ID_SIZE);
    offset += DNAC_BFT_WITNESS_ID_SIZE;
    memcpy(payload + offset, pubkey, DNAC_PUBKEY_SIZE);
    offset += DNAC_PUBKEY_SIZE;
    payload[offset++] = (addr_len >> 8) & 0xFF;
    payload[offset++] = addr_len & 0xFF;
    memcpy(payload + offset, address, addr_len);

    /* Send complete frame */
    dnac_tcp_server_send(g_tcp_server, peer_fd, frame, frame_len);
    free(frame);

    QGP_LOG_DEBUG(LOG_TAG, "Sent IDENTIFY to peer %d", peer_fd);
}

/**
 * Handle received IDENTIFY message
 */
static void handle_identify(int peer_index, const uint8_t *data, size_t len) {
    if (len < DNAC_BFT_WITNESS_ID_SIZE + DNAC_PUBKEY_SIZE + 2) {
        QGP_LOG_WARN(LOG_TAG, "IDENTIFY message too short: %zu", len);
        return;
    }

    const uint8_t *witness_id = data;
    const uint8_t *pubkey = data + DNAC_BFT_WITNESS_ID_SIZE;
    size_t addr_len = (data[DNAC_BFT_WITNESS_ID_SIZE + DNAC_PUBKEY_SIZE] << 8) |
                       data[DNAC_BFT_WITNESS_ID_SIZE + DNAC_PUBKEY_SIZE + 1];

    if (len < DNAC_BFT_WITNESS_ID_SIZE + DNAC_PUBKEY_SIZE + 2 + addr_len) {
        QGP_LOG_WARN(LOG_TAG, "IDENTIFY message truncated");
        return;
    }

    char address[256] = {0};
    if (addr_len < sizeof(address)) {
        memcpy(address, data + DNAC_BFT_WITNESS_ID_SIZE + DNAC_PUBKEY_SIZE + 2, addr_len);
    }

    QGP_LOG_INFO(LOG_TAG, "Received IDENTIFY from peer %d: %.8s... at %s",
                 peer_index, (char*)witness_id, address);

    /* Add/update witness in roster */
    int rc = dnac_bft_roster_add_witness(g_bft_ctx, witness_id, pubkey, address);
    if (rc == DNAC_BFT_SUCCESS) {
        /* Notify peer manager */
        /* Note: peer_index is the TCP peer slot, witness_id is from IDENTIFY */
        bft_peer_on_connect(peer_index, witness_id);
        fprintf(stderr, "[WITNESS] Registered peer %d with witness_id %.8s\n",
                peer_index, (char*)witness_id);
        fflush(stderr);
    }
}

/* ============================================================================
 * Client Request Handling
 * ========================================================================== */

/* External forward function */
extern int bft_forward_request(dnac_bft_context_t *ctx,
                               const dnac_spend_request_t *request,
                               int client_fd);

/**
 * Send spend response to client
 */
void bft_send_client_response(int client_fd, int status,
                              const char *error_msg) {
    if (client_fd < 0 || !g_tcp_server || !g_bft_ctx) return;

    dnac_spend_response_t response;
    memset(&response, 0, sizeof(response));

    response.status = status;
    memcpy(response.witness_id, g_bft_ctx->my_id, 32);
    memcpy(response.server_pubkey, g_bft_ctx->my_pubkey, DNAC_PUBKEY_SIZE);
    response.timestamp = (uint64_t)time(NULL);
    response.software_version[0] = DNAC_VERSION_MAJOR;
    response.software_version[1] = DNAC_VERSION_MINOR;
    response.software_version[2] = DNAC_VERSION_PATCH;

    if (error_msg) {
        strncpy(response.error_message, error_msg, sizeof(response.error_message) - 1);
    }

    /* Sign the response: tx_hash + witness_id + timestamp (little-endian) */
    if (g_bft_ctx->my_privkey && g_bft_ctx->my_privkey_size > 0) {
        uint8_t signed_data[DNAC_TX_HASH_SIZE + 32 + 8];
        memcpy(signed_data, g_bft_ctx->round_state.tx_hash, DNAC_TX_HASH_SIZE);
        memcpy(signed_data + DNAC_TX_HASH_SIZE, response.witness_id, 32);
        /* Little-endian timestamp */
        for (int j = 0; j < 8; j++) {
            signed_data[DNAC_TX_HASH_SIZE + 32 + j] = (response.timestamp >> (j * 8)) & 0xFF;
        }

        size_t sig_len = 0;
        int sign_rc = qgp_dsa87_sign(response.signature, &sig_len,
                                      signed_data, sizeof(signed_data),
                                      g_bft_ctx->my_privkey);
        if (sign_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to sign spend response: %d", sign_rc);
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "Signed spend response (sig_len=%zu)", sig_len);
        }
    }

    /* Serialize response */
    uint8_t buffer[16384];
    size_t written;

    int rc = dnac_spend_response_serialize(&response,
                                           buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                           sizeof(buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                           &written);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize spend response");
        return;
    }

    dnac_tcp_write_frame_header(buffer, DNAC_NODUS_MSG_SPEND_RESPONSE, (uint32_t)written);

    dnac_tcp_server_send(g_tcp_server, client_fd, buffer,
                         DNAC_TCP_FRAME_HEADER_SIZE + written);

    QGP_LOG_INFO(LOG_TAG, "Sent spend response to client (fd=%d, status=%d)",
                 client_fd, status);
}

/* Forward completion function (declared in forward.c) */
extern int bft_forward_complete_for_txhash(const uint8_t *tx_hash,
                                           dnac_tcp_server_t *server,
                                           const uint8_t *witness_id,
                                           const uint8_t *pubkey);

/**
 * Callback wrapper for completing pending forwards when COMMIT is reached.
 * This is called from consensus.c when this witness reaches COMMIT phase.
 */
static int bft_complete_forward_callback(const uint8_t *tx_hash,
                                         const uint8_t *witness_id,
                                         const uint8_t *pubkey) {
    return bft_forward_complete_for_txhash(tx_hash, g_tcp_server, witness_id, pubkey);
}

/**
 * Handle client spend request
 *
 * v0.4.0: Now deserializes full TX to extract ALL nullifiers,
 * preventing multi-input double-spend attacks.
 */
static void handle_client_spend_request(int client_fd, const uint8_t *data, size_t len) {
    fprintf(stderr, "[WITNESS] handle_client_spend_request: fd=%d len=%zu\n", client_fd, len);
    fflush(stderr);
    QGP_LOG_INFO(LOG_TAG, "Received SPEND_REQUEST from client (fd=%d)", client_fd);

    /* Deserialize request */
    dnac_spend_request_t request;
    int rc = dnac_spend_request_deserialize(data, len, &request);
    if (rc != 0) {
        fprintf(stderr, "[WITNESS] Failed to deserialize: rc=%d\n", rc);
        fflush(stderr);
        QGP_LOG_ERROR(LOG_TAG, "Failed to deserialize spend request");
        bft_send_client_response(client_fd, DNAC_NODUS_STATUS_ERROR,
                                 "Invalid request format");
        return;
    }
    fprintf(stderr, "[WITNESS] Deserialized request OK, tx_len=%u\n", request.tx_len);
    fflush(stderr);

    /* v0.4.0: Deserialize full transaction to extract all nullifiers */
    dnac_transaction_t *tx = NULL;
    rc = dnac_tx_deserialize(request.tx_data, request.tx_len, &tx);
    if (rc != DNAC_SUCCESS || !tx) {
        fprintf(stderr, "[WITNESS] Failed to deserialize TX: rc=%d\n", rc);
        fflush(stderr);
        QGP_LOG_ERROR(LOG_TAG, "Failed to deserialize transaction from request");
        bft_send_client_response(client_fd, DNAC_NODUS_STATUS_ERROR,
                                 "Invalid transaction data");
        return;
    }

    /* Verify tx_hash matches */
    uint8_t computed_hash[DNAC_TX_HASH_SIZE];
    rc = dnac_tx_compute_hash(tx, computed_hash);
    if (rc != DNAC_SUCCESS || memcmp(computed_hash, request.tx_hash, DNAC_TX_HASH_SIZE) != 0) {
        fprintf(stderr, "[WITNESS] TX hash mismatch!\n");
        fflush(stderr);
        QGP_LOG_ERROR(LOG_TAG, "Transaction hash mismatch");
        dnac_free_transaction(tx);
        bft_send_client_response(client_fd, DNAC_NODUS_STATUS_ERROR,
                                 "Transaction hash mismatch");
        return;
    }

    /* Extract ALL nullifiers from inputs */
    uint8_t nullifiers[DNAC_TX_MAX_INPUTS][DNAC_NULLIFIER_SIZE];
    uint8_t nullifier_count = (uint8_t)tx->input_count;
    for (int i = 0; i < tx->input_count; i++) {
        memcpy(nullifiers[i], tx->inputs[i].nullifier, DNAC_NULLIFIER_SIZE);
    }

    fprintf(stderr, "[WITNESS] Extracted %d nullifiers from TX\n", nullifier_count);
    fflush(stderr);
    QGP_LOG_INFO(LOG_TAG, "Extracted %d nullifiers from transaction", nullifier_count);

    dnac_free_transaction(tx);

    /* Check if we are leader */
    int is_leader = dnac_bft_is_leader(g_bft_ctx);
    fprintf(stderr, "[WITNESS] is_leader=%d\n", is_leader);
    fflush(stderr);

    if (is_leader) {
        fprintf(stderr, "[WITNESS] We are leader - starting consensus\n");
        fflush(stderr);
        QGP_LOG_INFO(LOG_TAG, "We are leader - starting consensus round");

        /* Store client fd for response */
        pthread_mutex_lock(&g_bft_ctx->mutex);
        g_bft_ctx->round_state.client_fd = client_fd;
        g_bft_ctx->round_state.is_forwarded = false;
        pthread_mutex_unlock(&g_bft_ctx->mutex);

        /* Start consensus round with ALL nullifiers */
        rc = dnac_bft_start_round(g_bft_ctx,
                                  request.tx_hash,
                                  nullifiers,
                                  nullifier_count,
                                  request.sender_pubkey,
                                  request.signature,
                                  request.fee_amount);
        fprintf(stderr, "[WITNESS] dnac_bft_start_round returned %d\n", rc);
        fflush(stderr);

        if (rc == DNAC_BFT_ERROR_DOUBLE_SPEND) {
            fprintf(stderr, "[WITNESS] Double spend detected\n");
            fflush(stderr);
            QGP_LOG_WARN(LOG_TAG, "Double spend detected");
            bft_send_client_response(client_fd, DNAC_NODUS_STATUS_REJECTED,
                                     "Nullifier already spent");
        } else if (rc != DNAC_BFT_SUCCESS) {
            fprintf(stderr, "[WITNESS] Consensus failed: rc=%d\n", rc);
            fflush(stderr);
            QGP_LOG_ERROR(LOG_TAG, "Failed to start round: %d", rc);
            bft_send_client_response(client_fd, DNAC_NODUS_STATUS_ERROR,
                                     "Consensus failed to start");
        }
        /* Response will be sent when consensus completes */
    } else {
        fprintf(stderr, "[WITNESS] Not leader - forwarding\n");
        fflush(stderr);
        QGP_LOG_INFO(LOG_TAG, "We are not leader - forwarding to leader");

        /* Forward to leader */
        rc = bft_forward_request(g_bft_ctx, &request, client_fd);
        fprintf(stderr, "[WITNESS] Forward result: rc=%d\n", rc);
        fflush(stderr);
        if (rc != DNAC_BFT_SUCCESS) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to forward request: %d", rc);
            bft_send_client_response(client_fd, DNAC_NODUS_STATUS_ERROR,
                                     "Failed to forward to leader");
        }
        /* Response will be sent when forward response arrives */
    }
}

/* ============================================================================
 * TCP Callbacks
 * ========================================================================== */

static void on_tcp_message(int peer_index, uint8_t msg_type,
                           const uint8_t *data, size_t len, void *user_data) {
    (void)user_data;

    fprintf(stderr, "[WITNESS] on_tcp_message: peer=%d type=%d len=%zu (FORWARD_REQ=%d, IDENTIFY=%d, SPEND_REQ=%d)\n",
            peer_index, msg_type, len, BFT_MSG_FORWARD_REQ, BFT_MSG_IDENTIFY, DNAC_NODUS_MSG_SPEND_REQUEST);
    fflush(stderr);
    QGP_LOG_DEBUG(LOG_TAG, "Received message type %d from peer %d (%zu bytes)",
                 msg_type, peer_index, len);

    dnac_bft_msg_type_t type = (dnac_bft_msg_type_t)msg_type;

    switch (type) {
        case BFT_MSG_PROPOSAL: {
            dnac_bft_proposal_t proposal;
            if (dnac_bft_proposal_deserialize(data, len, &proposal) == DNAC_BFT_SUCCESS) {
                dnac_bft_handle_proposal(g_bft_ctx, &proposal);
            }
            break;
        }

        case BFT_MSG_PREVOTE:
        case BFT_MSG_PRECOMMIT: {
            dnac_bft_vote_msg_t vote;
            if (dnac_bft_vote_deserialize(data, len, &vote) == DNAC_BFT_SUCCESS) {
                dnac_bft_handle_vote(g_bft_ctx, &vote);
            }
            break;
        }

        case BFT_MSG_COMMIT: {
            dnac_bft_commit_t commit;
            if (dnac_bft_commit_deserialize(data, len, &commit) == DNAC_BFT_SUCCESS) {
                dnac_bft_handle_commit(g_bft_ctx, &commit);
            }
            break;
        }

        case BFT_MSG_VIEW_CHANGE: {
            dnac_bft_view_change_t vc;
            if (dnac_bft_view_change_deserialize(data, len, &vc) == DNAC_BFT_SUCCESS) {
                dnac_bft_handle_view_change(g_bft_ctx, &vc);
            }
            break;
        }

        case BFT_MSG_FORWARD_REQ: {
            fprintf(stderr, "[WITNESS] Received BFT_MSG_FORWARD_REQ from peer %d (len=%zu)\n",
                    peer_index, len);
            fflush(stderr);

            dnac_bft_forward_req_t req;
            int deser_rc = dnac_bft_forward_req_deserialize(data, len, &req);
            fprintf(stderr, "[WITNESS] Forward req deserialize: rc=%d\n", deser_rc);
            fflush(stderr);

            if (deser_rc == DNAC_BFT_SUCCESS) {
                /* Handle forwarded request (we are leader) */
                int is_leader = dnac_bft_is_leader(g_bft_ctx);
                fprintf(stderr, "[WITNESS] Forward req: is_leader=%d\n", is_leader);
                fflush(stderr);

                if (is_leader) {
                    QGP_LOG_INFO(LOG_TAG, "Processing forwarded request from peer %d", peer_index);
                    fprintf(stderr, "[WITNESS] Leader processing forwarded request\n");
                    fflush(stderr);

                    /* v0.4.0: Deserialize full TX to extract all nullifiers */
                    dnac_transaction_t *tx = NULL;
                    int rc = dnac_tx_deserialize(req.tx_data, req.tx_len, &tx);
                    if (rc != DNAC_SUCCESS || !tx) {
                        fprintf(stderr, "[WITNESS] Failed to deserialize forwarded TX: rc=%d\n", rc);
                        fflush(stderr);
                        QGP_LOG_ERROR(LOG_TAG, "Failed to deserialize forwarded transaction");
                        break;
                    }

                    /* Extract ALL nullifiers from inputs */
                    uint8_t nullifiers[DNAC_TX_MAX_INPUTS][DNAC_NULLIFIER_SIZE];
                    uint8_t nullifier_count = (uint8_t)tx->input_count;
                    for (int i = 0; i < tx->input_count; i++) {
                        memcpy(nullifiers[i], tx->inputs[i].nullifier, DNAC_NULLIFIER_SIZE);
                    }
                    dnac_free_transaction(tx);

                    fprintf(stderr, "[WITNESS] Forwarded TX has %d nullifiers\n", nullifier_count);
                    fflush(stderr);

                    /* Start consensus round with ALL nullifiers */
                    rc = dnac_bft_start_round(g_bft_ctx,
                                              req.tx_hash,
                                              nullifiers,
                                              nullifier_count,
                                              req.sender_pubkey,
                                              req.client_signature,
                                              req.fee_amount);

                    fprintf(stderr, "[WITNESS] Forward req: start_round returned %d\n", rc);
                    fflush(stderr);

                    if (rc != DNAC_BFT_SUCCESS) {
                        QGP_LOG_ERROR(LOG_TAG, "Failed to start round for forwarded request: %d", rc);
                        fprintf(stderr, "[WITNESS] Failed to start round: %d\n", rc);
                        fflush(stderr);
                        /* TODO: Send error response back */
                    }

                    /* Store forwarder info for response routing */
                    pthread_mutex_lock(&g_bft_ctx->mutex);
                    g_bft_ctx->round_state.is_forwarded = true;
                    memcpy(g_bft_ctx->round_state.forwarder_id, req.forwarder_id,
                           DNAC_BFT_WITNESS_ID_SIZE);
                    g_bft_ctx->round_state.forwarder_fd = peer_index;
                    pthread_mutex_unlock(&g_bft_ctx->mutex);
                } else {
                    QGP_LOG_WARN(LOG_TAG, "Received forward request but we are not leader");
                    fprintf(stderr, "[WITNESS] Received forward request but we are NOT leader!\n");
                    fflush(stderr);
                }
            } else {
                fprintf(stderr, "[WITNESS] Failed to deserialize forward request\n");
                fflush(stderr);
            }
            break;
        }

        case BFT_MSG_FORWARD_RSP: {
            /* TODO: Handle response from leader (for forwarding witnesses) */
            break;
        }

        case BFT_MSG_IDENTIFY: {
            handle_identify(peer_index, data, len);
            break;
        }

        default:
            fprintf(stderr, "[WITNESS] default case: msg_type=%d, SPEND_REQUEST=%d\n",
                    msg_type, DNAC_NODUS_MSG_SPEND_REQUEST);
            fflush(stderr);
            /* Check for NODUS client messages */
            if (msg_type == DNAC_NODUS_MSG_SPEND_REQUEST) {
                fprintf(stderr, "[WITNESS] Calling handle_client_spend_request\n");
                fflush(stderr);
                handle_client_spend_request(peer_index, data, len);
            } else if (msg_type == DNAC_NODUS_MSG_PING) {
                fprintf(stderr, "[WITNESS] Got PING, sending PONG\n");
                fflush(stderr);
                /* Send PONG response */
                uint8_t pong_buf[DNAC_TCP_FRAME_HEADER_SIZE];
                dnac_tcp_write_frame_header(pong_buf, DNAC_NODUS_MSG_PONG, 0);
                dnac_tcp_server_send(g_tcp_server, peer_index, pong_buf,
                                     DNAC_TCP_FRAME_HEADER_SIZE);
            } else {
                fprintf(stderr, "[WITNESS] Unknown message type: %d\n", msg_type);
                fflush(stderr);
                QGP_LOG_WARN(LOG_TAG, "Unknown message type: %d", msg_type);
            }
            break;
    }
}

static void on_tcp_connect(int peer_index, const char *address, void *user_data) {
    (void)user_data;
    QGP_LOG_INFO(LOG_TAG, "Peer %d connected from %s", peer_index, address);

    /* Send our identity */
    if (g_bft_ctx && g_bft_ctx->my_index >= 0) {
        const dnac_roster_entry_t *self = dnac_bft_roster_get_entry(&g_bft_ctx->roster,
                                                                     g_bft_ctx->my_index);
        if (self) {
            send_identify(peer_index, g_bft_ctx->my_id, g_bft_ctx->my_pubkey, self->address);
        }
    }
}

static void on_tcp_disconnect(int peer_index, void *user_data) {
    (void)user_data;
    QGP_LOG_INFO(LOG_TAG, "Peer %d disconnected", peer_index);

    bft_peer_on_disconnect(peer_index);
}

/* ============================================================================
 * Main
 * ========================================================================== */

static void print_usage(const char *prog) {
    printf("DNAC Witness Server v%s\n", dnac_get_version());
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -d <dir>      Data directory (default: ~/.dna)\n");
    printf("  -p <port>     TCP port (default: %d)\n", DNAC_BFT_TCP_PORT);
    printf("  -a <addr>     My address for roster (IP:port)\n");
    printf("  -r <roster>   Initial roster file (optional)\n");
    printf("  -h            Show this help\n");
}

int bft_witness_main(int argc, char *argv[]) {
    char *data_dir = NULL;
    uint16_t tcp_port = DNAC_BFT_TCP_PORT;
    char *my_address = NULL;
    char *roster_file = NULL;
    int opt;

    /* Reset optind for re-parsing */
    optind = 1;

    /* Parse arguments */
    while ((opt = getopt(argc, argv, "d:p:a:r:h")) != -1) {
        switch (opt) {
            case 'd':
                data_dir = strdup(optarg);
                break;
            case 'p':
                tcp_port = (uint16_t)atoi(optarg);
                break;
            case 'a':
                my_address = strdup(optarg);
                break;
            case 'r':
                roster_file = strdup(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                break;
        }
    }

    if (!data_dir) {
        const char *home = qgp_platform_home_dir();
        if (home) {
            size_t len = strlen(home) + strlen("/.dna") + 1;
            data_dir = malloc(len);
            snprintf(data_dir, len, "%s/.dna", home);
        } else {
            data_dir = strdup(".dna");
        }
    }

    printf("DNAC Witness Server v%s\n", dnac_get_version());
    printf("Data directory: %s\n", data_dir);
    printf("TCP port: %u\n", tcp_port);

    /* Enable logging */
    qgp_log_file_enable(true);
    qgp_log_set_level(QGP_LOG_LEVEL_DEBUG);

    QGP_LOG_INFO(LOG_TAG, "=== DNAC Witness Server v%s ===", dnac_get_version());

    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Load identity keys */
    uint8_t witness_id[DNAC_BFT_WITNESS_ID_SIZE];
    uint8_t pubkey[DNAC_PUBKEY_SIZE];
    uint8_t *privkey = NULL;
    size_t privkey_size = 0;
    char fingerprint[129] = {0};

    if (load_identity_keys(data_dir, witness_id, pubkey, &privkey,
                           &privkey_size, fingerprint) != 0) {
        fprintf(stderr, "Failed to load identity keys\n");
        free(data_dir);
        free(my_address);
        free(roster_file);
        return 1;
    }

    printf("Identity: %.32s...\n", fingerprint);

    /* Create DNA engine for DHT */
    dna_engine_t *engine = dna_engine_create(data_dir);
    if (!engine) {
        fprintf(stderr, "Failed to create DNA engine\n");
        free(privkey);
        free(data_dir);
        free(my_address);
        free(roster_file);
        return 1;
    }

    /* Load identity */
    printf("Loading identity...\n");
    if (!dna_engine_has_identity(engine)) {
        fprintf(stderr, "No identity found\n");
        dna_engine_destroy(engine);
        free(privkey);
        free(data_dir);
        free(my_address);
        free(roster_file);
        return 1;
    }

    dna_engine_load_identity_minimal(engine, fingerprint, NULL,
                                     identity_loaded_callback, NULL);

    /* Wait for load */
    int wait_count = 0;
    while (!g_identity_loaded && wait_count < 300 && g_running) {
        usleep(100000);
        wait_count++;
    }

    if (!g_identity_loaded || g_identity_result != 0) {
        fprintf(stderr, "Failed to load identity\n");
        dna_engine_destroy(engine);
        free(privkey);
        free(data_dir);
        free(my_address);
        free(roster_file);
        return 1;
    }

    printf("Identity loaded\n");

    /* Initialize nullifier database */
    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/nullifiers.db", data_dir);

    if (witness_nullifier_init(db_path) != 0) {
        fprintf(stderr, "Failed to initialize nullifier database\n");
        dna_engine_destroy(engine);
        free(privkey);
        free(data_dir);
        free(my_address);
        free(roster_file);
        return 1;
    }

    /* Create BFT context */
    dnac_bft_config_t config;
    dnac_bft_config_init(&config, 3);  /* Start with 3 witnesses */
    config.tcp_port = tcp_port;

    g_bft_ctx = dnac_bft_create(&config, engine);
    if (!g_bft_ctx) {
        fprintf(stderr, "Failed to create BFT context\n");
        witness_nullifier_shutdown();
        dna_engine_destroy(engine);
        free(privkey);
        free(data_dir);
        free(my_address);
        free(roster_file);
        return 1;
    }

    /* Set identity */
    if (dnac_bft_set_identity(g_bft_ctx, witness_id, pubkey, privkey, privkey_size) != 0) {
        fprintf(stderr, "Failed to set BFT identity\n");
        dnac_bft_destroy(g_bft_ctx);
        witness_nullifier_shutdown();
        dna_engine_destroy(engine);
        free(privkey);
        free(data_dir);
        free(my_address);
        free(roster_file);
        return 1;
    }

    /* Set callbacks for consensus operations */
    dnac_bft_set_callbacks(g_bft_ctx,
                           witness_nullifier_exists,
                           witness_nullifier_add,
                           bft_send_client_response,
                           bft_complete_forward_callback,
                           NULL);

    /* Create default address if not provided */
    if (!my_address) {
        my_address = malloc(32);
        snprintf(my_address, 32, "127.0.0.1:%u", tcp_port);
    }

    /* Initialize empty roster */
    dnac_bft_roster_init(&g_bft_ctx->roster);

    /* Load ALL addresses from roster file (including ourselves) */
    if (roster_file) {
        printf("Loading roster from %s...\n", roster_file);
        int loaded = load_roster_from_file(roster_file, g_bft_ctx);
        if (loaded < 0) {
            fprintf(stderr, "Warning: Failed to load roster file\n");
        } else {
            printf("Loaded %d addresses from roster file\n", loaded);
        }
    }

    /* Add ourselves to roster if not already there */
    int my_idx = -1;
    for (uint32_t i = 0; i < g_bft_ctx->roster.n_witnesses; i++) {
        if (strcmp(g_bft_ctx->roster.witnesses[i].address, my_address) == 0) {
            my_idx = i;
            /* Update with our real identity */
            memcpy(g_bft_ctx->roster.witnesses[i].witness_id, witness_id, DNAC_BFT_WITNESS_ID_SIZE);
            memcpy(g_bft_ctx->roster.witnesses[i].pubkey, pubkey, DNAC_PUBKEY_SIZE);
            break;
        }
    }
    if (my_idx < 0) {
        /* Add ourselves if not in roster file */
        dnac_bft_roster_add_witness(g_bft_ctx, witness_id, pubkey, my_address);
    }

    /* Sort roster by address for consistent ordering across all witnesses */
    for (uint32_t i = 0; i < g_bft_ctx->roster.n_witnesses - 1; i++) {
        for (uint32_t j = i + 1; j < g_bft_ctx->roster.n_witnesses; j++) {
            if (strcmp(g_bft_ctx->roster.witnesses[i].address,
                       g_bft_ctx->roster.witnesses[j].address) > 0) {
                /* Swap */
                dnac_roster_entry_t tmp = g_bft_ctx->roster.witnesses[i];
                g_bft_ctx->roster.witnesses[i] = g_bft_ctx->roster.witnesses[j];
                g_bft_ctx->roster.witnesses[j] = tmp;
            }
        }
    }

    /* Find our index in sorted roster */
    g_bft_ctx->my_index = -1;
    for (uint32_t i = 0; i < g_bft_ctx->roster.n_witnesses; i++) {
        if (strcmp(g_bft_ctx->roster.witnesses[i].address, my_address) == 0) {
            g_bft_ctx->my_index = i;
            break;
        }
    }
    printf("Sorted roster: %u witnesses, my_index=%d (address=%s)\n",
           g_bft_ctx->roster.n_witnesses, g_bft_ctx->my_index, my_address);

    /* Try to load from DHT (may update existing entries) */
    int rc = dnac_bft_roster_load_from_dht(g_bft_ctx);
    if (rc == DNAC_BFT_SUCCESS) {
        /* Update our entry in case roster has stale info */
        dnac_bft_roster_add_witness(g_bft_ctx, witness_id, pubkey, my_address);
        g_bft_ctx->my_index = dnac_bft_roster_find(&g_bft_ctx->roster, witness_id);
    }

    /* Save roster */
    dnac_bft_roster_save_to_dht(g_bft_ctx);

    printf("Roster: %u witnesses, my index: %d\n",
           g_bft_ctx->roster.n_witnesses, g_bft_ctx->my_index);

    /* Create TCP server */
    g_tcp_server = dnac_tcp_server_create(tcp_port);
    if (!g_tcp_server) {
        fprintf(stderr, "Failed to create TCP server\n");
        dnac_bft_destroy(g_bft_ctx);
        witness_nullifier_shutdown();
        dna_engine_destroy(engine);
        free(privkey);
        free(data_dir);
        free(my_address);
        free(roster_file);
        return 1;
    }

    /* Set callbacks */
    dnac_tcp_server_set_callbacks(g_tcp_server,
                                  on_tcp_message,
                                  on_tcp_connect,
                                  on_tcp_disconnect,
                                  NULL);

    /* Start TCP server */
    if (dnac_tcp_server_start(g_tcp_server) != 0) {
        fprintf(stderr, "Failed to start TCP server\n");
        dnac_tcp_server_destroy(g_tcp_server);
        dnac_bft_destroy(g_bft_ctx);
        witness_nullifier_shutdown();
        dna_engine_destroy(engine);
        free(privkey);
        free(data_dir);
        free(my_address);
        free(roster_file);
        return 1;
    }

    printf("TCP server listening on port %u\n", tcp_port);

    /* Initialize peer manager */
    if (bft_peer_manager_init(g_bft_ctx, g_tcp_server) != 0) {
        fprintf(stderr, "Failed to initialize peer manager\n");
        dnac_tcp_server_stop(g_tcp_server);
        dnac_tcp_server_destroy(g_tcp_server);
        dnac_bft_destroy(g_bft_ctx);
        witness_nullifier_shutdown();
        dna_engine_destroy(engine);
        free(privkey);
        free(data_dir);
        free(my_address);
        free(roster_file);
        return 1;
    }

    /* Connect to roster peers */
    printf("Connecting to roster peers...\n");
    int connected = bft_peer_connect_to_roster();
    printf("Connected to %d peers\n", connected);

    /* Mark ourselves as running */
    g_bft_ctx->running = true;

    printf("witness running. Press Ctrl+C to stop.\n");

    /* Check leader status */
    if (dnac_bft_is_leader(g_bft_ctx)) {
        printf("*** WE ARE THE CURRENT LEADER ***\n");
    } else {
        uint64_t epoch = time(NULL) / 3600;
        int leader = dnac_bft_get_leader_index(epoch, g_bft_ctx->current_view,
                                               g_bft_ctx->roster.n_witnesses);
        printf("Current leader: witness %d\n", leader);
    }

    /* Main loop */
    time_t last_status_print = 0;
    const int STATUS_INTERVAL = 60;

    while (g_running) {
        /* Sleep briefly */
        usleep(100000);  /* 100ms */

        /* Check for consensus timeouts */
        dnac_bft_check_timeout(g_bft_ctx);

        /* Periodic status */
        time_t now = time(NULL);
        if (now - last_status_print >= STATUS_INTERVAL) {
            last_status_print = now;

            int peer_count = dnac_tcp_server_peer_count(g_tcp_server);
            bool is_leader = dnac_bft_is_leader(g_bft_ctx);

            printf("[STATUS] Peers: %d, Round: %lu, View: %u, Leader: %s\n",
                   peer_count,
                   (unsigned long)g_bft_ctx->current_round,
                   g_bft_ctx->current_view,
                   is_leader ? "YES" : "no");
        }
    }

    /* Shutdown */
    printf("Shutting down witness...\n");

    bft_peer_manager_shutdown();
    dnac_tcp_server_stop(g_tcp_server);
    dnac_tcp_server_destroy(g_tcp_server);
    dnac_bft_destroy(g_bft_ctx);
    witness_nullifier_shutdown();
    dna_engine_destroy(engine);

    /* Clean up memory */
    if (privkey) {
        memset(privkey, 0, privkey_size);
        free(privkey);
    }
    free(data_dir);
    free(my_address);
    free(roster_file);

    printf("witness stopped.\n");
    return 0;
}
