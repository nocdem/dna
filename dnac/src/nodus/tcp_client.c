/**
 * @file tcp_client.c
 * @brief TCP Client for BFT Witness Requests
 *
 * Provides TCP-based communication with BFT witnesses for spend requests.
 * Client can connect to any witness; non-leaders forward to the leader.
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
#include <openssl/evp.h>

#define LOG_TAG "NODUS_TCP"

/* Compute SHA3-512 hash */
static int compute_sha3_512(const uint8_t *data, size_t len, uint8_t *hash_out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, hash_out, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

/**
 * Derive fingerprint from Dilithium5 public key
 * Fingerprint = hex(SHA3-512(pubkey))
 */
static void derive_fingerprint(const uint8_t *pubkey, char *fingerprint_out) {
    uint8_t hash[64];
    if (compute_sha3_512(pubkey, DNAC_PUBKEY_SIZE, hash) != 0) {
        fingerprint_out[0] = '\0';
        return;
    }

    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        fingerprint_out[i * 2] = hex[(hash[i] >> 4) & 0xF];
        fingerprint_out[i * 2 + 1] = hex[hash[i] & 0xF];
    }
    fingerprint_out[128] = '\0';
}

/* ============================================================================
 * BFT Witness Request (TCP-based)
 * ========================================================================== */

int dnac_bft_witness_request(void *dna_engine,
                             const dnac_spend_request_t *request,
                             dnac_witness_sig_t *witnesses_out,
                             int *witness_count_out) {
    if (!dna_engine || !request || !witnesses_out || !witness_count_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *witness_count_out = 0;

    /* Discover roster from DHT */
    dnac_roster_t roster;
    int rc = dnac_bft_client_discover_roster(dna_engine, &roster);
    if (rc != DNAC_BFT_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to discover roster");
        return DNAC_ERROR_NETWORK;
    }

    QGP_LOG_INFO(LOG_TAG, "Discovered roster with %u witnesses", roster.n_witnesses);

    /* Try to connect to any active witness */
    dnac_tcp_client_t *client = dnac_tcp_client_create();
    if (!client) {
        return DNAC_ERROR_OUT_OF_MEMORY;
    }

    bool connected = false;
    for (uint32_t i = 0; i < roster.n_witnesses && !connected; i++) {
        if (!roster.witnesses[i].active) continue;

        QGP_LOG_DEBUG(LOG_TAG, "Trying witness %u at %s", i, roster.witnesses[i].address);
        rc = dnac_tcp_client_connect(client, roster.witnesses[i].address);
        if (rc == 0) {
            connected = true;
            QGP_LOG_INFO(LOG_TAG, "Connected to witness at %s", roster.witnesses[i].address);
        }
    }

    if (!connected) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to connect to any witness");
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    /* Serialize spend request */
    uint8_t req_buffer[16384];
    size_t req_written;

    rc = dnac_spend_request_serialize(request, req_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                      sizeof(req_buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                      &req_written);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize spend request");
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_INVALID_PARAM;
    }

    dnac_tcp_write_frame_header(req_buffer, DNAC_NODUS_MSG_SPEND_REQUEST, (uint32_t)req_written);

    /* Send request */
    rc = dnac_tcp_client_send(client, req_buffer, DNAC_TCP_FRAME_HEADER_SIZE + req_written);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to send request");
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Sent spend request, waiting for response...");

    /* Wait for response (30 second timeout) */
    /* Note: Witness may send IDENTIFY first, so we loop until we get SPEND_RESPONSE */
    uint8_t rsp_buffer[16384];
    size_t rsp_received;
    uint8_t msg_type = 0;
    uint32_t payload_len;
    int max_retries = 5;  /* Max messages to skip before giving up */

    while (max_retries-- > 0) {
        rc = dnac_tcp_client_recv(client, rsp_buffer, sizeof(rsp_buffer),
                                  &rsp_received, 30000);
        if (rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to receive response (timeout?)");
            dnac_tcp_client_destroy(client);
            return DNAC_ERROR_TIMEOUT;
        }

        /* Parse frame header */
        rc = dnac_tcp_parse_frame_header(rsp_buffer, rsp_received, &msg_type, &payload_len);
        if (rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Invalid response frame");
            dnac_tcp_client_destroy(client);
            return DNAC_ERROR_NETWORK;
        }

        QGP_LOG_DEBUG(LOG_TAG, "Received message type %d (waiting for %d)",
                      msg_type, DNAC_NODUS_MSG_SPEND_RESPONSE);

        if (msg_type == DNAC_NODUS_MSG_SPEND_RESPONSE) {
            break;  /* Got what we were waiting for */
        }

        /* Skip other messages (e.g., BFT_MSG_IDENTIFY from witness) */
        QGP_LOG_DEBUG(LOG_TAG, "Skipping message type %d", msg_type);
    }

    if (msg_type != DNAC_NODUS_MSG_SPEND_RESPONSE) {
        QGP_LOG_ERROR(LOG_TAG, "Never received SPEND_RESPONSE (last type: %d)", msg_type);
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    /* Deserialize spend response */
    dnac_spend_response_t response;
    rc = dnac_spend_response_deserialize(rsp_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                         payload_len, &response);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to deserialize response");
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    dnac_tcp_client_destroy(client);

    /* Check response status */
    if (response.status != DNAC_NODUS_STATUS_APPROVED) {
        QGP_LOG_WARN(LOG_TAG, "Witness rejected: %s", response.error_message);
        return DNAC_ERROR_DOUBLE_SPEND;
    }

    /* Copy witness signature */
    memcpy(witnesses_out[0].witness_id, response.witness_id, 32);
    memcpy(witnesses_out[0].signature, response.signature, DNAC_SIGNATURE_SIZE);
    memcpy(witnesses_out[0].server_pubkey, response.server_pubkey, DNAC_PUBKEY_SIZE);
    witnesses_out[0].timestamp = response.timestamp;

    *witness_count_out = 1;

    /* For BFT, consensus already collected multiple attestations */
    /* The returned signature represents consensus agreement */

    QGP_LOG_INFO(LOG_TAG, "BFT consensus approved transaction");
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Roster Discovery (Wrapper)
 * ========================================================================== */

int dnac_bft_discover_witnesses(void *dna_engine,
                                dnac_witness_info_t **servers_out,
                                int *count_out) {
    if (!dna_engine || !servers_out || !count_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *servers_out = NULL;
    *count_out = 0;

    /* Discover roster */
    dnac_roster_t roster;
    int rc = dnac_bft_client_discover_roster(dna_engine, &roster);
    if (rc != DNAC_BFT_SUCCESS) {
        return DNAC_ERROR_NOT_FOUND;
    }

    /* Allocate output array */
    *servers_out = calloc(roster.n_witnesses, sizeof(dnac_witness_info_t));
    if (!*servers_out) {
        return DNAC_ERROR_OUT_OF_MEMORY;
    }

    /* Convert roster entries to witness info */
    for (uint32_t i = 0; i < roster.n_witnesses; i++) {
        dnac_roster_entry_t *entry = &roster.witnesses[i];
        dnac_witness_info_t *info = &(*servers_out)[i];

        /* Convert ID to hex string */
        for (int j = 0; j < 32; j++) {
            snprintf(info->id + j*2, 3, "%02x", entry->witness_id[j]);
        }

        strncpy(info->address, entry->address, sizeof(info->address) - 1);
        memcpy(info->pubkey, entry->pubkey, DNAC_PUBKEY_SIZE);
        info->is_available = entry->active;
        info->last_seen = entry->joined_epoch * 3600;

        /* Derive fingerprint from public key */
        derive_fingerprint(entry->pubkey, info->fingerprint);
    }

    *count_out = roster.n_witnesses;

    QGP_LOG_INFO(LOG_TAG, "Discovered %d BFT witnesses", *count_out);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Check Nullifier via BFT
 * ========================================================================== */

int dnac_bft_check_nullifier(void *dna_engine,
                             const uint8_t *nullifier,
                             bool *is_spent_out) {
    if (!dna_engine || !nullifier || !is_spent_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *is_spent_out = false;

    /* Discover roster */
    dnac_roster_t roster;
    int rc = dnac_bft_client_discover_roster(dna_engine, &roster);
    if (rc != DNAC_BFT_SUCCESS) {
        return DNAC_ERROR_NOT_FOUND;
    }

    /* Create check request */
    /* TODO: Implement nullifier check via TCP */

    /* For now, assume not spent if we can't check */
    QGP_LOG_WARN(LOG_TAG, "BFT nullifier check not fully implemented");
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Ping Witness (Health Check)
 * ========================================================================== */

int dnac_bft_ping_witness(const char *address, int *latency_ms_out) {
    if (!address) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    uint64_t start = dnac_tcp_get_time_ms();

    dnac_tcp_client_t *client = dnac_tcp_client_create();
    if (!client) {
        return DNAC_ERROR_OUT_OF_MEMORY;
    }

    int rc = dnac_tcp_client_connect(client, address);
    if (rc != 0) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    /* Send ping */
    uint8_t ping_buf[DNAC_TCP_FRAME_HEADER_SIZE];
    dnac_tcp_write_frame_header(ping_buf, DNAC_NODUS_MSG_PING, 0);

    rc = dnac_tcp_client_send(client, ping_buf, DNAC_TCP_FRAME_HEADER_SIZE);
    if (rc != 0) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    /* Wait for pong */
    uint8_t pong_buf[64];
    size_t received;

    rc = dnac_tcp_client_recv(client, pong_buf, sizeof(pong_buf), &received, 5000);

    dnac_tcp_client_destroy(client);

    if (rc != 0) {
        return DNAC_ERROR_TIMEOUT;
    }

    uint64_t end = dnac_tcp_get_time_ms();

    if (latency_ms_out) {
        *latency_ms_out = (int)(end - start);
    }

    return DNAC_SUCCESS;
}
