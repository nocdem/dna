/**
 * @file witness.h
 * @brief DNAC Witness Server API
 *
 * The witness server provides double-spend prevention through nullifier
 * tracking. It communicates via DHT (no TCP ports required).
 *
 * Flow:
 * 1. Server polls DHT for SpendRequests addressed to its fingerprint
 * 2. Server checks nullifier DB - if new, signs attestation response
 * 3. Server PUTs response to DHT for client to retrieve
 * 4. Server replicates nullifier to peer witness servers
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_WITNESS_H
#define DNAC_WITNESS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include <dna/dna_engine.h>
#include "dnac/nodus.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Listener Context Types
 * ========================================================================== */

/**
 * @brief Context for request listener callback
 */
typedef struct {
    dna_engine_t *engine;
    pthread_mutex_t *mutex;
    pthread_cond_t *cond;
    int *pending_count;
} witness_request_ctx_t;

/**
 * @brief Context for replication listener callback
 */
typedef struct {
    dna_engine_t *engine;
    pthread_mutex_t *mutex;
    pthread_cond_t *cond;
    int *pending_count;
} witness_replication_ctx_t;

/* ============================================================================
 * Nullifier Database Functions
 * ========================================================================== */

/**
 * @brief Initialize nullifier database
 *
 * @param db_path Path to SQLite database file
 * @return 0 on success, -1 on failure
 */
int witness_nullifier_init(const char *db_path);

/**
 * @brief Shutdown nullifier database
 */
void witness_nullifier_shutdown(void);

/**
 * @brief Check if nullifier exists (already spent)
 *
 * @param nullifier Nullifier to check (64 bytes)
 * @return true if exists (already spent), false if new
 */
bool witness_nullifier_exists(const uint8_t *nullifier);

/**
 * @brief Add nullifier to database
 *
 * @param nullifier Nullifier to add (64 bytes)
 * @param tx_hash Transaction hash (64 bytes)
 * @return 0 on success, -1 on failure
 */
int witness_nullifier_add(const uint8_t *nullifier, const uint8_t *tx_hash);

/**
 * @brief Mark nullifier as replicated
 *
 * @param nullifier Nullifier to mark (64 bytes)
 * @return 0 on success, -1 on failure
 */
int witness_nullifier_mark_replicated(const uint8_t *nullifier);

/**
 * @brief Get unreplicated nullifiers
 *
 * @param nullifiers Output array (caller provides buffer)
 * @param max_count Maximum number to return
 * @return Number of nullifiers returned, -1 on error
 */
int witness_nullifier_get_unreplicated(uint8_t (*nullifiers)[64], int max_count);

/* ============================================================================
 * Server Functions
 * ========================================================================== */

/**
 * @brief Publish witness server identity to DHT
 *
 * Publishes the server's fingerprint and public key so clients can discover it.
 *
 * @param engine DNA engine with loaded identity
 * @return 0 on success, -1 on failure
 */
int witness_publish_identity(dna_engine_t *engine);

/**
 * @brief Process pending attestation requests
 *
 * Polls DHT for requests, processes them, and sends responses.
 * Should be called in main loop.
 *
 * @param engine DNA engine with loaded identity
 * @return Number of requests processed, -1 on error
 */
int witness_process_requests(dna_engine_t *engine);

/**
 * @brief Get next pending request from DHT
 *
 * @param engine DNA engine
 * @param request Output request structure
 * @return 0 if request found, 1 if no requests, -1 on error
 */
int witness_get_next_request(dna_engine_t *engine, dnac_spend_request_t *request);

/**
 * @brief Send attestation response to DHT
 *
 * @param engine DNA engine
 * @param request Original request
 * @param response Response to send
 * @return 0 on success, -1 on failure
 */
int witness_send_response(dna_engine_t *engine,
                         const dnac_spend_request_t *request,
                         const dnac_spend_response_t *response);

/**
 * @brief Start request listener (event-driven)
 *
 * Starts listening for incoming attestation requests via DHT.
 * Callbacks run on DHT worker thread.
 *
 * @param engine DNA engine with loaded identity
 * @param ctx Listener context (must remain valid until stop)
 * @return Listen token (0 on failure)
 */
size_t witness_start_request_listener(dna_engine_t *engine,
                                      witness_request_ctx_t *ctx);

/**
 * @brief Stop request listener
 *
 * @param engine DNA engine
 * @param token Listen token from start function
 */
void witness_stop_request_listener(dna_engine_t *engine, size_t token);

/* ============================================================================
 * Replication Functions
 * ========================================================================== */

/**
 * @brief Replicate nullifier to peer witness servers
 *
 * @param nullifier Nullifier to replicate (64 bytes)
 * @param tx_hash Transaction hash (64 bytes)
 * @return 0 on success, -1 on failure
 */
int witness_replicate_nullifier(const uint8_t *nullifier, const uint8_t *tx_hash);

/**
 * @brief Process incoming nullifier replications from peers
 *
 * @param engine DNA engine
 * @return Number of nullifiers received, -1 on error
 */
int witness_process_replications(dna_engine_t *engine);

/**
 * @brief Set DNA engine for nullifier replication
 *
 * @param engine DNA engine with loaded identity
 */
void witness_set_replication_engine(dna_engine_t *engine);

/**
 * @brief Start replication listener (event-driven)
 *
 * Starts listening for incoming nullifier replications via DHT.
 * Callbacks run on DHT worker thread.
 *
 * @param engine DNA engine with loaded identity
 * @param ctx Listener context (must remain valid until stop)
 * @return Listen token (0 on failure)
 */
size_t witness_start_replication_listener(dna_engine_t *engine,
                                          witness_replication_ctx_t *ctx);

/**
 * @brief Stop replication listener
 *
 * @param engine DNA engine
 * @param token Listen token from start function
 */
void witness_stop_replication_listener(dna_engine_t *engine, size_t token);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_WITNESS_H */
