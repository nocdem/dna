/**
 * @file zone.h
 * @brief DNAC Zone/Hub Multi-Chain Architecture (v0.10.0)
 *
 * Zones are independent blockchains, each with their own:
 * - Chain ID (derived from genesis block hash)
 * - BFT consensus context
 * - UTXO set and state root
 * - Merkle ledger
 * - Block storage
 * - SQLite database
 *
 * A single witness process can manage multiple zones via the zone manager.
 * Chain ID = SHA3-512(genesis_block_hash)[0:32] — self-describing, no registry.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_ZONE_H
#define DNAC_ZONE_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sqlite3.h>

#include "dnac/bft.h"
#include "dnac/tcp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/** Chain ID size (first 32 bytes of SHA3-512 genesis block hash) */
#define DNAC_CHAIN_ID_SIZE      32

/** Maximum zones per witness process */
#define DNAC_MAX_ZONES          16

/** Maximum zone name length */
#define DNAC_ZONE_NAME_SIZE     64

/* ============================================================================
 * Zone Types
 * ========================================================================== */

/**
 * @brief Per-zone state
 *
 * Each zone is an independent blockchain with its own consensus,
 * state, and database. All fields that were previously global
 * (nullifier_db, g_utxo_state_root, g_block_height, etc.) are
 * now per-zone.
 */
typedef struct dnac_zone {
    /* Identity */
    uint8_t chain_id[DNAC_CHAIN_ID_SIZE];   /**< Chain ID (zeros = pre-genesis) */
    char    zone_name[DNAC_ZONE_NAME_SIZE];  /**< Human-readable zone name */
    bool    active;                          /**< Zone is active */

    /* BFT consensus context (one per zone) */
    dnac_bft_context_t *bft_ctx;

    /* Database (one SQLite DB per zone) */
    sqlite3 *db;
    char     db_path[512];

    /* Per-zone cached state (moved from globals) */
    uint64_t block_height;                   /**< Current tip height (UINT64_MAX = none) */

    uint8_t  utxo_state_root[64];            /**< Rolling SHA3-512 UTXO state root */
    int      state_root_initialized;         /**< Whether state root has been computed */

    uint8_t  merkle_root[64];                /**< Ledger Merkle root */
    uint64_t leaf_count;                     /**< Ledger leaf count */
    bool     merkle_initialized;             /**< Whether Merkle tree is initialized */
} dnac_zone_t;

/**
 * @brief Zone manager — manages all zones for a witness process
 *
 * Shared resources (TCP server, DNA engine, witness identity) are
 * held here. Per-zone resources are in dnac_zone_t.
 */
typedef struct dnac_zone_manager {
    dnac_zone_t zones[DNAC_MAX_ZONES];
    int         zone_count;
    pthread_mutex_t mutex;

    /* Shared resources */
    dnac_tcp_server_t *tcp_server;           /**< Single TCP server, muxed by chain_id */
    void *dna_engine;                        /**< Shared DNA engine for DHT */

    /* Shared witness identity */
    uint8_t witness_id[DNAC_BFT_WITNESS_ID_SIZE];
    uint8_t pubkey[DNAC_PUBKEY_SIZE];
    uint8_t *privkey;
    size_t   privkey_size;
    char     fingerprint[129];
    char     data_dir[512];
} dnac_zone_manager_t;

/* ============================================================================
 * Zone Manager API
 * ========================================================================== */

/**
 * @brief Create zone manager
 * @return Manager pointer or NULL on failure
 */
dnac_zone_manager_t *dnac_zone_manager_create(void);

/**
 * @brief Destroy zone manager and all zones
 */
void dnac_zone_manager_destroy(dnac_zone_manager_t *mgr);

/**
 * @brief Look up a zone by chain_id
 * @param mgr Zone manager
 * @param chain_id Chain ID to look up (DNAC_CHAIN_ID_SIZE bytes)
 * @return Zone pointer or NULL if not found
 */
dnac_zone_t *dnac_zone_lookup(dnac_zone_manager_t *mgr, const uint8_t *chain_id);

/**
 * @brief Create a new zone slot
 * @param mgr Zone manager
 * @param name Human-readable zone name
 * @param chain_id Initial chain_id (can be all-zeros for pre-genesis)
 * @return Zone pointer or NULL if full
 */
dnac_zone_t *dnac_zone_create(dnac_zone_manager_t *mgr, const char *name,
                               const uint8_t *chain_id);

/**
 * @brief Get the default zone (index 0)
 * @param mgr Zone manager
 * @return Default zone pointer or NULL
 */
dnac_zone_t *dnac_zone_get_default(dnac_zone_manager_t *mgr);

/**
 * @brief Initialize zone database (open SQLite, create schema)
 * @param zone Zone to initialize
 * @param db_path Path to SQLite database file
 * @return 0 on success, -1 on error
 */
int dnac_zone_init_db(dnac_zone_t *zone, const char *db_path);

/**
 * @brief Initialize zone subsystems (ledger, UTXO set, blocks)
 * @param zone Zone with initialized DB
 * @return 0 on success, -1 on error
 */
int dnac_zone_init_subsystems(dnac_zone_t *zone);

/**
 * @brief Shutdown a zone (close DB, free resources)
 * @param zone Zone to shut down
 */
void dnac_zone_shutdown(dnac_zone_t *zone);

/**
 * @brief Set chain_id after genesis block creation
 *
 * Stores chain_id in the zone_metadata table and updates the zone struct.
 *
 * @param zone Zone to update
 * @param chain_id New chain ID (DNAC_CHAIN_ID_SIZE bytes)
 * @return 0 on success, -1 on error
 */
int dnac_zone_set_chain_id(dnac_zone_t *zone, const uint8_t *chain_id);

/**
 * @brief Load chain_id from zone_metadata table
 * @param zone Zone with initialized DB
 * @return 0 on success (chain_id loaded), -1 if not found or error
 */
int dnac_zone_load_chain_id(dnac_zone_t *zone);

/**
 * @brief Scan data directory for existing zone databases
 * @param mgr Zone manager
 * @param data_dir Directory to scan
 * @return Number of zones found, -1 on error
 */
int dnac_zone_scan_data_dir(dnac_zone_manager_t *mgr, const char *data_dir);

/* ============================================================================
 * Utility
 * ========================================================================== */

/**
 * @brief Check if chain_id is all zeros (pre-genesis)
 */
static inline bool dnac_chain_id_is_zero(const uint8_t *chain_id) {
    for (int i = 0; i < DNAC_CHAIN_ID_SIZE; i++) {
        if (chain_id[i] != 0) return false;
    }
    return true;
}

/**
 * @brief Format chain_id as hex string (first 8 bytes = 16 chars)
 */
static inline void dnac_chain_id_short_hex(const uint8_t *chain_id, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[i * 2]     = hex[(chain_id[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[chain_id[i] & 0xF];
    }
    out[16] = '\0';
}

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZONE_H */
