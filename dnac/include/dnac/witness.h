/**
 * @file witness.h
 * @brief DNAC Witness Server API
 *
 * The witness server provides double-spend prevention through nullifier
 * tracking using BFT (Byzantine Fault Tolerant) consensus over TCP.
 *
 * Flow:
 * 1. Client sends SpendRequest to any witness via TCP
 * 2. If not leader, witness forwards to current leader
 * 3. Leader initiates BFT consensus round (PROPOSE → PREVOTE → PRECOMMIT → COMMIT)
 * 4. On quorum (2f+1), nullifier is recorded and response sent to client
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_WITNESS_H
#define DNAC_WITNESS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "dnac/nodus.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Witness Announcement Structure (for DHT roster discovery)
 * ========================================================================== */

/**
 * @brief Witness announcement (published to DHT for discovery)
 *
 * Each witness publishes this to a permanent DHT key so clients and
 * other witnesses can discover the witness cluster.
 */
typedef struct {
    uint8_t  version;                           /**< Announcement version (2) */
    uint8_t  witness_id[32];                    /**< Witness ID (first 32 bytes of fp) */
    uint64_t current_epoch;                     /**< Current epoch number */
    uint64_t epoch_duration;                    /**< Epoch duration in seconds */
    uint64_t timestamp;                         /**< Announcement timestamp */
    uint8_t  software_version[3];               /**< Software version [major, minor, patch] */
    uint8_t  witness_pubkey[DNAC_PUBKEY_SIZE];  /**< Witness Dilithium5 public key */
    uint8_t  signature[DNAC_SIGNATURE_SIZE];    /**< Signature over above fields */
} dnac_witness_announcement_t;

/* Serialized size: 1 + 32 + 8 + 8 + 8 + 3 + 2592 + 4627 = 7279 bytes */
#define DNAC_ANNOUNCEMENT_SERIALIZED_SIZE (1 + 32 + 8 + 8 + 8 + 3 + DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE)

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
 * Announcement Serialization (for DHT roster)
 * ========================================================================== */

/**
 * @brief Serialize witness announcement
 */
int witness_announcement_serialize(const dnac_witness_announcement_t *announcement,
                                   uint8_t *buffer,
                                   size_t buffer_len,
                                   size_t *written_out);

/**
 * @brief Deserialize witness announcement
 */
int witness_announcement_deserialize(const uint8_t *buffer,
                                     size_t buffer_len,
                                     dnac_witness_announcement_t *announcement_out);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_WITNESS_H */
