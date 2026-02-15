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
#include "dnac/ledger.h"
#include "dnac/commitment.h"
#include "dnac/wallet.h"
#include "dnac/db.h"
#include "crypto/utils/qgp_random.h"
#include "crypto/utils/qgp_log.h"
#include <openssl/evp.h>

#define LOG_TAG "NODUS_TCP"

/* External wallet functions */
extern dna_engine_t *dnac_get_engine(dnac_context_t *ctx);
extern const char *dnac_get_owner_fingerprint(dnac_context_t *ctx);

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
        info->last_seen = entry->joined_epoch * DNAC_EPOCH_DURATION_SEC;

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

    /* Connect to any active witness */
    dnac_tcp_client_t *client = dnac_tcp_client_create();
    if (!client) return DNAC_ERROR_OUT_OF_MEMORY;

    bool connected = false;
    for (uint32_t i = 0; i < roster.n_witnesses && !connected; i++) {
        if (!roster.witnesses[i].active) continue;
        if (dnac_tcp_client_connect(client, roster.witnesses[i].address) == 0) {
            connected = true;
        }
    }

    if (!connected) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    /* Build and send query */
    dnac_nullifier_query_t query;
    memcpy(query.nullifier, nullifier, DNAC_NULLIFIER_SIZE);

    uint8_t req_buffer[128];
    size_t req_written;
    rc = dnac_nullifier_query_serialize(&query, req_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                         sizeof(req_buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                         &req_written);
    if (rc != 0) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_INVALID_PARAM;
    }

    dnac_tcp_write_frame_header(req_buffer, DNAC_NODUS_MSG_CHECK_NULLIFIER, (uint32_t)req_written);
    rc = dnac_tcp_client_send(client, req_buffer, DNAC_TCP_FRAME_HEADER_SIZE + req_written);
    if (rc != 0) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    /* Wait for response */
    uint8_t rsp_buffer[256];
    size_t rsp_received;
    uint8_t msg_type;
    uint32_t payload_len;

    rc = dnac_tcp_client_recv(client, rsp_buffer, sizeof(rsp_buffer), &rsp_received, 10000);
    dnac_tcp_client_destroy(client);

    if (rc != 0) {
        return DNAC_ERROR_TIMEOUT;
    }

    rc = dnac_tcp_parse_frame_header(rsp_buffer, rsp_received, &msg_type, &payload_len);
    if (rc != 0 || msg_type != DNAC_NODUS_MSG_NULLIFIER_STATUS) {
        return DNAC_ERROR_NETWORK;
    }

    /* Deserialize response */
    dnac_nullifier_response_t response;
    rc = dnac_nullifier_response_deserialize(rsp_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                              payload_len, &response);
    if (rc != 0) return DNAC_ERROR_NETWORK;

    if (response.status != DNAC_NODUS_STATUS_APPROVED) {
        return DNAC_ERROR_NETWORK;
    }

    *is_spent_out = response.is_spent;

    QGP_LOG_DEBUG(LOG_TAG, "Nullifier check result: is_spent=%d", response.is_spent);
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

/* ============================================================================
 * v0.5.0: Ledger Query Functions
 * ========================================================================== */

/**
 * Query ledger entry by transaction hash
 */
int dnac_ledger_query_tx(dnac_context_t *ctx,
                         const uint8_t *tx_hash,
                         dnac_ledger_entry_t *entry_out,
                         dnac_merkle_proof_t *proof_out) {
    if (!ctx || !tx_hash || !entry_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* Get DNA engine */
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    /* Discover roster */
    dnac_roster_t roster;
    int rc = dnac_bft_client_discover_roster(engine, &roster);
    if (rc != DNAC_BFT_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to discover roster for ledger query");
        return DNAC_ERROR_NETWORK;
    }

    /* Connect to any active witness */
    dnac_tcp_client_t *client = dnac_tcp_client_create();
    if (!client) return DNAC_ERROR_OUT_OF_MEMORY;

    bool connected = false;
    for (uint32_t i = 0; i < roster.n_witnesses && !connected; i++) {
        if (!roster.witnesses[i].active) continue;
        if (dnac_tcp_client_connect(client, roster.witnesses[i].address) == 0) {
            connected = true;
        }
    }

    if (!connected) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    /* Build and send query */
    dnac_ledger_query_t query;
    memcpy(query.tx_hash, tx_hash, DNAC_TX_HASH_SIZE);
    query.include_proof = (proof_out != NULL);

    uint8_t req_buffer[256];
    size_t req_written;
    rc = dnac_ledger_query_serialize(&query, req_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                      sizeof(req_buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                      &req_written);
    if (rc != 0) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_INVALID_PARAM;
    }

    dnac_tcp_write_frame_header(req_buffer, DNAC_NODUS_MSG_LEDGER_QUERY, (uint32_t)req_written);
    rc = dnac_tcp_client_send(client, req_buffer, DNAC_TCP_FRAME_HEADER_SIZE + req_written);
    if (rc != 0) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    /* Wait for response (witness may send IDENTIFY first, so loop to skip) */
    uint8_t rsp_buffer[16384];
    size_t rsp_received;
    uint8_t msg_type = 0;
    uint32_t payload_len;
    int max_retries = 5;

    while (max_retries-- > 0) {
        rc = dnac_tcp_client_recv(client, rsp_buffer, sizeof(rsp_buffer), &rsp_received, 10000);
        if (rc != 0) {
            dnac_tcp_client_destroy(client);
            return DNAC_ERROR_TIMEOUT;
        }

        rc = dnac_tcp_parse_frame_header(rsp_buffer, rsp_received, &msg_type, &payload_len);
        if (rc != 0) {
            dnac_tcp_client_destroy(client);
            return DNAC_ERROR_NETWORK;
        }

        if (msg_type == DNAC_NODUS_MSG_LEDGER_RESPONSE) {
            break;
        }
    }

    dnac_tcp_client_destroy(client);

    if (msg_type != DNAC_NODUS_MSG_LEDGER_RESPONSE) {
        return DNAC_ERROR_NETWORK;
    }

    /* Deserialize response */
    dnac_ledger_response_t response;
    rc = dnac_ledger_response_deserialize(rsp_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                           payload_len, &response);
    if (rc != 0) return DNAC_ERROR_NETWORK;

    if (response.status != DNAC_NODUS_STATUS_APPROVED) {
        return DNAC_ERROR_NOT_FOUND;
    }

    /* Copy to output */
    entry_out->sequence_number = response.sequence_number;
    memcpy(entry_out->tx_hash, response.tx_hash, DNAC_TX_HASH_SIZE);
    entry_out->tx_type = response.tx_type;
    memcpy(entry_out->merkle_root, response.merkle_root, 64);
    entry_out->timestamp = response.timestamp;
    entry_out->epoch = response.epoch;

    if (proof_out && response.has_proof) {
        memcpy(proof_out->leaf_hash, response.leaf_hash, 64);
        proof_out->proof_length = response.proof_length;
        memcpy(proof_out->root, response.proof_root, 64);
    }

    QGP_LOG_INFO(LOG_TAG, "Ledger query: seq=%llu, type=%d",
                 (unsigned long long)entry_out->sequence_number, entry_out->tx_type);
    return DNAC_SUCCESS;
}

/**
 * Query supply state from witnesses
 */
int dnac_ledger_get_supply(dnac_context_t *ctx,
                           uint64_t *genesis_out,
                           uint64_t *burned_out,
                           uint64_t *current_out) {
    if (!ctx) return DNAC_ERROR_INVALID_PARAM;

    /* Get DNA engine */
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    /* Discover roster */
    dnac_roster_t roster;
    int rc = dnac_bft_client_discover_roster(engine, &roster);
    if (rc != DNAC_BFT_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to discover roster for supply query");
        return DNAC_ERROR_NETWORK;
    }

    /* Connect to any active witness */
    dnac_tcp_client_t *client = dnac_tcp_client_create();
    if (!client) return DNAC_ERROR_OUT_OF_MEMORY;

    bool connected = false;
    for (uint32_t i = 0; i < roster.n_witnesses && !connected; i++) {
        if (!roster.witnesses[i].active) continue;
        if (dnac_tcp_client_connect(client, roster.witnesses[i].address) == 0) {
            connected = true;
        }
    }

    if (!connected) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    /* Build and send query */
    dnac_supply_query_t query = {0};
    uint8_t req_buffer[64];
    size_t req_written;
    rc = dnac_supply_query_serialize(&query, req_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                      sizeof(req_buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                      &req_written);
    if (rc != 0) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_INVALID_PARAM;
    }

    dnac_tcp_write_frame_header(req_buffer, DNAC_NODUS_MSG_SUPPLY_QUERY, (uint32_t)req_written);
    rc = dnac_tcp_client_send(client, req_buffer, DNAC_TCP_FRAME_HEADER_SIZE + req_written);
    if (rc != 0) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    /* Wait for response */
    uint8_t rsp_buffer[256];
    size_t rsp_received;
    uint8_t msg_type;
    uint32_t payload_len;

    rc = dnac_tcp_client_recv(client, rsp_buffer, sizeof(rsp_buffer), &rsp_received, 10000);
    dnac_tcp_client_destroy(client);

    if (rc != 0) return DNAC_ERROR_TIMEOUT;

    rc = dnac_tcp_parse_frame_header(rsp_buffer, rsp_received, &msg_type, &payload_len);
    if (rc != 0 || msg_type != DNAC_NODUS_MSG_SUPPLY_RESPONSE) {
        return DNAC_ERROR_NETWORK;
    }

    /* Deserialize response */
    dnac_supply_response_t response;
    rc = dnac_supply_response_deserialize(rsp_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                           payload_len, &response);
    if (rc != 0) return DNAC_ERROR_NETWORK;

    if (response.status != DNAC_NODUS_STATUS_APPROVED) {
        return DNAC_ERROR_NOT_FOUND;
    }

    /* Copy to outputs */
    if (genesis_out) *genesis_out = response.genesis_supply;
    if (burned_out) *burned_out = response.total_burned;
    if (current_out) *current_out = response.current_supply;

    QGP_LOG_INFO(LOG_TAG, "Supply query: genesis=%llu, burned=%llu, current=%llu",
                 (unsigned long long)response.genesis_supply,
                 (unsigned long long)response.total_burned,
                 (unsigned long long)response.current_supply);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * P0-2 (v0.7.0): Ledger Range Query for Chain Sync
 * ========================================================================== */

/**
 * Sync ledger entries in a range from witnesses
 */
int dnac_ledger_sync_range(dnac_context_t *ctx,
                            uint64_t from_seq,
                            uint64_t to_seq,
                            dnac_ledger_entry_t *entries_out,
                            int max_entries,
                            int *count_out,
                            uint64_t *total_out) {
    if (!ctx || !entries_out || !count_out || max_entries <= 0) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *count_out = 0;
    if (total_out) *total_out = 0;

    /* Get DNA engine */
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    /* Discover roster */
    dnac_roster_t roster;
    int rc = dnac_bft_client_discover_roster(engine, &roster);
    if (rc != DNAC_BFT_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to discover roster for range query");
        return DNAC_ERROR_NETWORK;
    }

    /* Connect to any active witness */
    dnac_tcp_client_t *client = dnac_tcp_client_create();
    if (!client) return DNAC_ERROR_OUT_OF_MEMORY;

    bool connected = false;
    for (uint32_t i = 0; i < roster.n_witnesses && !connected; i++) {
        if (!roster.witnesses[i].active) continue;
        if (dnac_tcp_client_connect(client, roster.witnesses[i].address) == 0) {
            connected = true;
        }
    }

    if (!connected) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    /* Build and send range query */
    dnac_ledger_range_query_t query;
    query.from_sequence = from_seq;
    query.to_sequence = to_seq;
    query.include_proofs = false;

    uint8_t req_buffer[64];
    size_t req_written;
    rc = dnac_ledger_range_query_serialize(&query, req_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                            sizeof(req_buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                            &req_written);
    if (rc != 0) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_INVALID_PARAM;
    }

    dnac_tcp_write_frame_header(req_buffer, DNAC_NODUS_MSG_LEDGER_RANGE_QUERY, (uint32_t)req_written);
    rc = dnac_tcp_client_send(client, req_buffer, DNAC_TCP_FRAME_HEADER_SIZE + req_written);
    if (rc != 0) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    /* Wait for response - larger buffer for range results */
    size_t rsp_buf_size = DNAC_TCP_FRAME_HEADER_SIZE + 29 + (DNAC_MAX_RANGE_RESULTS * 153);
    uint8_t *rsp_buffer = malloc(rsp_buf_size);
    if (!rsp_buffer) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_OUT_OF_MEMORY;
    }

    size_t rsp_received;
    uint8_t msg_type;
    uint32_t payload_len;

    rc = dnac_tcp_client_recv(client, rsp_buffer, rsp_buf_size, &rsp_received, 30000);
    dnac_tcp_client_destroy(client);

    if (rc != 0) {
        free(rsp_buffer);
        return DNAC_ERROR_TIMEOUT;
    }

    rc = dnac_tcp_parse_frame_header(rsp_buffer, rsp_received, &msg_type, &payload_len);
    if (rc != 0 || msg_type != DNAC_NODUS_MSG_LEDGER_RANGE_RESPONSE) {
        free(rsp_buffer);
        return DNAC_ERROR_NETWORK;
    }

    /* Deserialize response */
    dnac_ledger_range_response_t response;
    rc = dnac_ledger_range_response_deserialize(rsp_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                                 payload_len, &response);
    free(rsp_buffer);

    if (rc != 0) return DNAC_ERROR_NETWORK;

    if (response.status != DNAC_NODUS_STATUS_APPROVED) {
        return DNAC_ERROR_WITNESS_FAILED;
    }

    /* Copy to output - convert from compact format */
    int copy_count = (response.count < max_entries) ? response.count : max_entries;
    for (int i = 0; i < copy_count; i++) {
        const dnac_ledger_range_entry_t *e = &response.entries[i];
        memset(&entries_out[i], 0, sizeof(entries_out[i]));

        entries_out[i].sequence_number = e->sequence_number;
        memcpy(entries_out[i].tx_hash, e->tx_hash, DNAC_TX_HASH_SIZE);
        entries_out[i].tx_type = e->tx_type;
        memcpy(entries_out[i].merkle_root, e->merkle_root, 64);
        entries_out[i].timestamp = e->timestamp;
        entries_out[i].epoch = e->epoch;
    }

    *count_out = copy_count;
    if (total_out) *total_out = response.total_entries;

    QGP_LOG_INFO(LOG_TAG, "Range sync: from=%llu to=%llu returned=%d total=%llu",
                 (unsigned long long)from_seq, (unsigned long long)to_seq,
                 copy_count, (unsigned long long)response.total_entries);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * v0.5.0: UTXO Query Functions
 * ========================================================================== */

/**
 * Recover wallet from witness servers by querying UTXOs by owner commitment
 */
int dnac_wallet_recover_from_witnesses(dnac_context_t *ctx,
                                        int *recovered_count,
                                        uint64_t *total_amount) {
    if (!ctx) return DNAC_ERROR_INVALID_PARAM;

    if (recovered_count) *recovered_count = 0;
    if (total_amount) *total_amount = 0;

    /* Get DNA engine */
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    /* Get our owner commitment (based on fingerprint) */
    const char *fingerprint = dnac_get_owner_fingerprint(ctx);
    if (!fingerprint) return DNAC_ERROR_NOT_INITIALIZED;

    /* Gap 22 Fix (v0.6.0): Use proper salt from wallet database */
    uint8_t owner_commitment[64];
    uint8_t salt[32];
    int rc;

    sqlite3 *db = dnac_get_db(ctx);
    if (!db) return DNAC_ERROR_NOT_INITIALIZED;

    /* Load salt from database or generate new one */
    rc = dnac_db_get_owner_salt(db, salt);
    if (rc == DNAC_ERROR_NOT_FOUND) {
        /* Generate new random salt */
        if (qgp_randombytes(salt, 32) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to generate owner salt");
            return DNAC_ERROR_RANDOM_FAILED;
        }
        /* Store for future use */
        rc = dnac_db_set_owner_salt(db, salt);
        if (rc != DNAC_SUCCESS) {
            QGP_LOG_WARN(LOG_TAG, "Failed to store owner salt");
        }
        QGP_LOG_INFO(LOG_TAG, "Generated new owner commitment salt");
    } else if (rc != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get owner salt: %d", rc);
        return rc;
    }

    /* Compute owner commitment: SHA3-512(fingerprint || salt) */
    {
        uint8_t data[256];
        size_t fp_len = strlen(fingerprint);
        if (fp_len > 128) fp_len = 128;
        memcpy(data, fingerprint, fp_len);
        memcpy(data + fp_len, salt, 32);
        if (compute_sha3_512(data, fp_len + 32, owner_commitment) != 0) {
            return DNAC_ERROR_CRYPTO;
        }
    }

    /* Discover roster */
    dnac_roster_t roster;
    rc = dnac_bft_client_discover_roster(engine, &roster);
    if (rc != DNAC_BFT_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to discover roster for UTXO recovery");
        return DNAC_ERROR_NETWORK;
    }

    /* Connect to any active witness */
    dnac_tcp_client_t *client = dnac_tcp_client_create();
    if (!client) return DNAC_ERROR_OUT_OF_MEMORY;

    bool connected = false;
    for (uint32_t i = 0; i < roster.n_witnesses && !connected; i++) {
        if (!roster.witnesses[i].active) continue;
        if (dnac_tcp_client_connect(client, roster.witnesses[i].address) == 0) {
            connected = true;
        }
    }

    if (!connected) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    /* Build and send query */
    dnac_utxo_query_t query;
    memcpy(query.owner_commitment, owner_commitment, 64);
    query.max_results = DNAC_MAX_UTXO_QUERY_RESULTS;

    uint8_t req_buffer[128];
    size_t req_written;
    rc = dnac_utxo_query_serialize(&query, req_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                    sizeof(req_buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                    &req_written);
    if (rc != 0) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_INVALID_PARAM;
    }

    dnac_tcp_write_frame_header(req_buffer, DNAC_NODUS_MSG_UTXO_QUERY, (uint32_t)req_written);
    rc = dnac_tcp_client_send(client, req_buffer, DNAC_TCP_FRAME_HEADER_SIZE + req_written);
    if (rc != 0) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    /* Wait for response */
    size_t rsp_buffer_size = DNAC_TCP_FRAME_HEADER_SIZE + 5 + (DNAC_MAX_UTXO_QUERY_RESULTS * 148);
    uint8_t *rsp_buffer = malloc(rsp_buffer_size);
    if (!rsp_buffer) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_OUT_OF_MEMORY;
    }

    size_t rsp_received;
    uint8_t msg_type;
    uint32_t payload_len;

    rc = dnac_tcp_client_recv(client, rsp_buffer, rsp_buffer_size, &rsp_received, 30000);
    dnac_tcp_client_destroy(client);

    if (rc != 0) {
        free(rsp_buffer);
        return DNAC_ERROR_TIMEOUT;
    }

    rc = dnac_tcp_parse_frame_header(rsp_buffer, rsp_received, &msg_type, &payload_len);
    if (rc != 0 || msg_type != DNAC_NODUS_MSG_UTXO_RESPONSE) {
        free(rsp_buffer);
        return DNAC_ERROR_NETWORK;
    }

    /* Deserialize response */
    dnac_utxo_response_t response;
    rc = dnac_utxo_response_deserialize(rsp_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                         payload_len, &response);
    free(rsp_buffer);

    if (rc != 0) return DNAC_ERROR_NETWORK;

    if (response.status != DNAC_NODUS_STATUS_APPROVED) {
        return DNAC_ERROR_NOT_FOUND;
    }

    /* Process recovered UTXOs
     *
     * Note: Witness UTXO data includes commitment, tx_hash, output_index, amount,
     * and created_epoch. However, it does NOT include the nullifier_seed needed
     * to derive nullifiers for spending. This is intentional for privacy - the
     * nullifier seed is only known to the UTXO recipient.
     *
     * For full wallet recovery with spendable UTXOs, users should use DHT inbox
     * recovery (dnac_wallet_recover) which retrieves complete payment data including
     * nullifier seeds.
     *
     * This witness-based recovery is useful for:
     * - Verifying total balance
     * - Proving UTXO existence
     * - Cross-checking against DHT recovery
     */
    int count = 0;
    uint64_t total = 0;
    for (int i = 0; i < response.count; i++) {
        const dnac_utxo_entry_t *e = &response.utxos[i];
        total += e->amount;
        count++;

        QGP_LOG_DEBUG(LOG_TAG, "Found UTXO: amount=%llu, output_index=%u, epoch=%llu",
                      (unsigned long long)e->amount,
                      e->output_index,
                      (unsigned long long)e->created_epoch);
    }

    if (recovered_count) *recovered_count = count;
    if (total_amount) *total_amount = total;

    if (count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Witness recovery found %d UTXOs, total: %llu",
                     count, (unsigned long long)total);
        QGP_LOG_INFO(LOG_TAG, "Note: For spendable UTXOs, use DHT inbox recovery");
    } else {
        QGP_LOG_INFO(LOG_TAG, "No UTXOs found for this identity on witnesses");
    }

    return DNAC_SUCCESS;
}

/**
 * Get UTXO existence proof from witnesses
 */
int dnac_utxo_get_proof(dnac_context_t *ctx,
                        const uint8_t *commitment,
                        dnac_smt_proof_t *proof_out) {
    if (!ctx || !commitment || !proof_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* Get DNA engine */
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    /* Discover roster */
    dnac_roster_t roster;
    int rc = dnac_bft_client_discover_roster(engine, &roster);
    if (rc != DNAC_BFT_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to discover roster for UTXO proof query");
        return DNAC_ERROR_NETWORK;
    }

    /* Connect to any active witness */
    dnac_tcp_client_t *client = dnac_tcp_client_create();
    if (!client) return DNAC_ERROR_OUT_OF_MEMORY;

    bool connected = false;
    for (uint32_t i = 0; i < roster.n_witnesses && !connected; i++) {
        if (!roster.witnesses[i].active) continue;
        if (dnac_tcp_client_connect(client, roster.witnesses[i].address) == 0) {
            connected = true;
        }
    }

    if (!connected) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    /* Build and send query */
    dnac_utxo_proof_query_t query;
    memcpy(query.commitment, commitment, 64);

    uint8_t req_buffer[128];
    size_t req_written;
    rc = dnac_utxo_proof_query_serialize(&query, req_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                          sizeof(req_buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                          &req_written);
    if (rc != 0) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_INVALID_PARAM;
    }

    dnac_tcp_write_frame_header(req_buffer, DNAC_NODUS_MSG_UTXO_PROOF_QUERY, (uint32_t)req_written);
    rc = dnac_tcp_client_send(client, req_buffer, DNAC_TCP_FRAME_HEADER_SIZE + req_written);
    if (rc != 0) {
        dnac_tcp_client_destroy(client);
        return DNAC_ERROR_NETWORK;
    }

    /* Wait for response */
    uint8_t rsp_buffer[256];
    size_t rsp_received;
    uint8_t msg_type;
    uint32_t payload_len;

    rc = dnac_tcp_client_recv(client, rsp_buffer, sizeof(rsp_buffer), &rsp_received, 10000);
    dnac_tcp_client_destroy(client);

    if (rc != 0) return DNAC_ERROR_TIMEOUT;

    rc = dnac_tcp_parse_frame_header(rsp_buffer, rsp_received, &msg_type, &payload_len);
    if (rc != 0 || msg_type != DNAC_NODUS_MSG_UTXO_PROOF_RSP) {
        return DNAC_ERROR_NETWORK;
    }

    /* Deserialize response */
    dnac_utxo_proof_response_t response;
    rc = dnac_utxo_proof_response_deserialize(rsp_buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                               payload_len, &response);
    if (rc != 0) return DNAC_ERROR_NETWORK;

    if (response.status != DNAC_NODUS_STATUS_APPROVED) {
        return DNAC_ERROR_NOT_FOUND;
    }

    /* Copy to output */
    memset(proof_out, 0, sizeof(*proof_out));
    memcpy(proof_out->key, commitment, 64);
    proof_out->exists = response.exists;
    memcpy(proof_out->root, response.root, 64);
    proof_out->epoch = response.epoch;

    QGP_LOG_INFO(LOG_TAG, "UTXO proof: exists=%d, epoch=%llu",
                 proof_out->exists, (unsigned long long)proof_out->epoch);
    return DNAC_SUCCESS;
}
