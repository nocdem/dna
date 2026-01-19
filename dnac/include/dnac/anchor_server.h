/**
 * @file anchor_server.h
 * @brief DNAC Anchor Server API
 *
 * The anchor server provides double-spend prevention through nullifier
 * tracking. It communicates via DHT (no TCP ports required).
 *
 * Flow:
 * 1. Server polls DHT for SpendRequests addressed to its fingerprint
 * 2. Server checks nullifier DB - if new, signs anchor response
 * 3. Server PUTs response to DHT for client to retrieve
 * 4. Server replicates nullifier to peer anchor servers
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_ANCHOR_SERVER_H
#define DNAC_ANCHOR_SERVER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <dna/dna_engine.h>
#include "dnac/nodus.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Nullifier Database Functions
 * ========================================================================== */

/**
 * @brief Initialize nullifier database
 *
 * @param db_path Path to SQLite database file
 * @return 0 on success, -1 on failure
 */
int anchor_nullifier_init(const char *db_path);

/**
 * @brief Shutdown nullifier database
 */
void anchor_nullifier_shutdown(void);

/**
 * @brief Check if nullifier exists (already spent)
 *
 * @param nullifier Nullifier to check (64 bytes)
 * @return true if exists (already spent), false if new
 */
bool anchor_nullifier_exists(const uint8_t *nullifier);

/**
 * @brief Add nullifier to database
 *
 * @param nullifier Nullifier to add (64 bytes)
 * @param tx_hash Transaction hash (64 bytes)
 * @return 0 on success, -1 on failure
 */
int anchor_nullifier_add(const uint8_t *nullifier, const uint8_t *tx_hash);

/**
 * @brief Mark nullifier as replicated
 *
 * @param nullifier Nullifier to mark (64 bytes)
 * @return 0 on success, -1 on failure
 */
int anchor_nullifier_mark_replicated(const uint8_t *nullifier);

/**
 * @brief Get unreplicated nullifiers
 *
 * @param nullifiers Output array (caller provides buffer)
 * @param max_count Maximum number to return
 * @return Number of nullifiers returned, -1 on error
 */
int anchor_nullifier_get_unreplicated(uint8_t (*nullifiers)[64], int max_count);

/* ============================================================================
 * Server Functions
 * ========================================================================== */

/**
 * @brief Publish anchor server identity to DHT
 *
 * Publishes the server's fingerprint and public key so clients can discover it.
 *
 * @param engine DNA engine with loaded identity
 * @return 0 on success, -1 on failure
 */
int anchor_publish_identity(dna_engine_t *engine);

/**
 * @brief Process pending anchor requests
 *
 * Polls DHT for requests, processes them, and sends responses.
 * Should be called in main loop.
 *
 * @param engine DNA engine with loaded identity
 * @return Number of requests processed, -1 on error
 */
int anchor_process_requests(dna_engine_t *engine);

/**
 * @brief Get next pending request from DHT
 *
 * @param engine DNA engine
 * @param request Output request structure
 * @return 0 if request found, 1 if no requests, -1 on error
 */
int anchor_get_next_request(dna_engine_t *engine, dnac_spend_request_t *request);

/**
 * @brief Send anchor response to DHT
 *
 * @param engine DNA engine
 * @param request Original request
 * @param response Response to send
 * @return 0 on success, -1 on failure
 */
int anchor_send_response(dna_engine_t *engine,
                         const dnac_spend_request_t *request,
                         const dnac_spend_response_t *response);

/* ============================================================================
 * Replication Functions
 * ========================================================================== */

/**
 * @brief Replicate nullifier to peer anchor servers
 *
 * @param nullifier Nullifier to replicate (64 bytes)
 * @param tx_hash Transaction hash (64 bytes)
 * @return 0 on success, -1 on failure
 */
int anchor_replicate_nullifier(const uint8_t *nullifier, const uint8_t *tx_hash);

/**
 * @brief Process incoming nullifier replications from peers
 *
 * @param engine DNA engine
 * @return Number of nullifiers received, -1 on error
 */
int anchor_process_replications(dna_engine_t *engine);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ANCHOR_SERVER_H */
