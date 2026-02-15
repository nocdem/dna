/**
 * @file utxo_set.c
 * @brief Shared UTXO set for transaction validation (v0.8.0)
 *
 * All validators maintain this UTXO set in lockstep. On every transaction:
 * - Inputs are checked against this set (must exist, amount must match)
 * - On COMMIT: spent UTXOs are removed, new output UTXOs are added
 *
 * This prevents counterfeiting: you can only spend UTXOs that were
 * legitimately created by a previous transaction or genesis.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/dnac.h"
#include "dnac/transaction.h"
#include "dnac/zone.h"
#include <sqlite3.h>
#include <string.h>
#include <time.h>

#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_sha3.h"

#define LOG_TAG "UTXO_SET"

/* Shared database handle from nullifier.c */
extern sqlite3 *nullifier_db;

/* v0.9.0: Rolling state root — updated on every add/remove */
static uint8_t g_utxo_state_root[64];
static int g_state_root_initialized = 0;

/* v0.10.0: Get DB handle from zone user_data, falling back to global */
static inline sqlite3 *get_db(void *user_data) {
    if (user_data) {
        dnac_zone_t *zone = (dnac_zone_t *)user_data;
        if (zone->db) return zone->db;
    }
    return nullifier_db;
}

/* v0.10.0: Get state root pointer from zone or global */
static inline uint8_t *get_state_root(void *user_data) {
    if (user_data) {
        dnac_zone_t *zone = (dnac_zone_t *)user_data;
        return zone->utxo_state_root;
    }
    return g_utxo_state_root;
}

/* v0.10.0: Get state_root_initialized flag pointer from zone or global */
static inline int *get_state_root_initialized(void *user_data) {
    if (user_data) {
        dnac_zone_t *zone = (dnac_zone_t *)user_data;
        return &zone->state_root_initialized;
    }
    return &g_state_root_initialized;
}

/**
 * @brief Update state root after an operation
 *
 * new_root = SHA3-512(old_root || operation_hash)
 * The operation_hash encodes the action (add/remove) + nullifier.
 */
static void update_state_root_ctx(uint8_t *state_root, const uint8_t *operation_hash) {
    uint8_t input[128];  /* old_root(64) + operation_hash(64) */
    memcpy(input, state_root, 64);
    memcpy(input + 64, operation_hash, 64);
    qgp_sha3_512(input, 128, state_root);
}

/* ============================================================================
 * Lookup
 * ========================================================================== */

int witness_utxo_set_lookup(const uint8_t *nullifier,
                             uint64_t *amount_out,
                             char *owner_out, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !nullifier) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "SELECT amount, owner_fingerprint FROM utxo_set WHERE nullifier = ?",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare UTXO lookup: %s",
                      sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, nullifier, DNAC_NULLIFIER_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;  /* Not found */
    }

    if (amount_out) {
        *amount_out = (uint64_t)sqlite3_column_int64(stmt, 0);
    }

    if (owner_out) {
        const char *fp = (const char *)sqlite3_column_text(stmt, 1);
        if (fp) {
            strncpy(owner_out, fp, DNAC_FINGERPRINT_SIZE - 1);
            owner_out[DNAC_FINGERPRINT_SIZE - 1] = '\0';
        }
    }

    sqlite3_finalize(stmt);
    return 0;
}

/* ============================================================================
 * Add (new UTXO from TX output)
 * ========================================================================== */

int witness_utxo_set_add(const uint8_t *nullifier,
                          const char *owner,
                          uint64_t amount,
                          const uint8_t *tx_hash,
                          uint32_t index,
                          uint64_t block_height, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !nullifier || !owner || !tx_hash) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO utxo_set "
        "(nullifier, owner_fingerprint, amount, tx_hash, output_index, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare UTXO add: %s",
                      sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, nullifier, DNAC_NULLIFIER_SIZE, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, owner, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (int64_t)amount);
    sqlite3_bind_blob(stmt, 4, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, (int)index);
    sqlite3_bind_int64(stmt, 6, (int64_t)block_height);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to add UTXO: %s",
                      sqlite3_errmsg(db));
        return -1;
    }

    /* v0.9.0: Update state root — hash "add" + nullifier */
    {
        uint8_t op_input[65];  /* 'A' + nullifier(64) */
        op_input[0] = 'A';
        memcpy(op_input + 1, nullifier, DNAC_NULLIFIER_SIZE);
        uint8_t op_hash[64];
        qgp_sha3_512(op_input, 65, op_hash);
        update_state_root_ctx(get_state_root(user_data), op_hash);
    }

    QGP_LOG_DEBUG(LOG_TAG, "Added UTXO: amount=%llu owner=%.16s...",
                  (unsigned long long)amount, owner);
    return 0;
}

/* ============================================================================
 * Remove (spent UTXO)
 * ========================================================================== */

int witness_utxo_set_remove(const uint8_t *nullifier, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !nullifier) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM utxo_set WHERE nullifier = ?",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare UTXO remove: %s",
                      sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, nullifier, DNAC_NULLIFIER_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to remove UTXO: %s",
                      sqlite3_errmsg(db));
        return -1;
    }

    if (changes == 0) {
        QGP_LOG_WARN(LOG_TAG, "UTXO not found for removal");
        return -1;
    }

    /* v0.9.0: Update state root — hash "remove" + nullifier */
    {
        uint8_t op_input[65];  /* 'R' + nullifier(64) */
        op_input[0] = 'R';
        memcpy(op_input + 1, nullifier, DNAC_NULLIFIER_SIZE);
        uint8_t op_hash[64];
        qgp_sha3_512(op_input, 65, op_hash);
        update_state_root_ctx(get_state_root(user_data), op_hash);
    }

    return 0;
}

/* ============================================================================
 * Genesis: Populate UTXO set from genesis TX outputs
 * ========================================================================== */

int witness_utxo_set_genesis(const dnac_transaction_t *genesis_tx,
                              const uint8_t *tx_hash, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !genesis_tx || !tx_hash) return -1;

    if (genesis_tx->type != DNAC_TX_GENESIS) {
        QGP_LOG_ERROR(LOG_TAG, "Not a genesis transaction");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Populating UTXO set from genesis (%d outputs)",
                 genesis_tx->output_count);

    for (int i = 0; i < genesis_tx->output_count; i++) {
        const dnac_tx_output_internal_t *out = &genesis_tx->outputs[i];

        /* For genesis outputs, we need to derive the nullifier the same way
         * the recipient's wallet will. This uses:
         * nullifier = SHA3-512(owner_fingerprint || nullifier_seed) */
        uint8_t derived_nullifier[DNAC_NULLIFIER_SIZE];

        /* Use the shared nullifier derivation function */
        extern int dnac_derive_nullifier(const char *owner_fp,
                                          const uint8_t *seed,
                                          uint8_t *nullifier_out);

        int rc = dnac_derive_nullifier(out->owner_fingerprint,
                                        out->nullifier_seed,
                                        derived_nullifier);
        if (rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to derive nullifier for genesis output %d", i);
            return -1;
        }

        rc = witness_utxo_set_add(derived_nullifier,
                                   out->owner_fingerprint,
                                   out->amount,
                                   tx_hash,
                                   (uint32_t)i,
                                   0 /* block height 0 = genesis */,
                                   user_data);
        if (rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to add genesis output %d to UTXO set", i);
            return -1;
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Genesis UTXO set populated: %d UTXOs", genesis_tx->output_count);
    return 0;
}

/* ============================================================================
 * Query: Count UTXOs (for diagnostics)
 * ========================================================================== */

int witness_utxo_set_count(uint64_t *count_out) {
    sqlite3 *db = nullifier_db;  /* uses global — no user_data param */
    if (!db || !count_out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM utxo_set", -1, &stmt, NULL);

    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *count_out = (uint64_t)sqlite3_column_int64(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return 0;
}

/* ============================================================================
 * v0.9.0: State Root — Deterministic UTXO set fingerprint
 * ========================================================================== */

/**
 * @brief Initialize UTXO state root by replaying all UTXOs from DB
 *
 * Iterates all UTXOs sorted by (tx_hash, output_index) for deterministic order.
 * Each UTXO contributes an "add" operation to the rolling hash.
 * All witnesses produce identical roots because they have identical UTXO sets
 * and iterate in the same sorted order.
 */
int witness_utxo_set_init(void) {
    sqlite3 *db = nullifier_db;  /* uses global at startup */
    if (!db) return -1;

    /* Start with zero root */
    memset(g_utxo_state_root, 0, 64);

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "SELECT nullifier FROM utxo_set ORDER BY tx_hash, output_index",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare UTXO set init query: %s",
                      sqlite3_errmsg(db));
        return -1;
    }

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(stmt, 0);
        int blob_size = sqlite3_column_bytes(stmt, 0);

        if (blob && blob_size == DNAC_NULLIFIER_SIZE) {
            uint8_t op_input[65];  /* 'A' + nullifier(64) */
            op_input[0] = 'A';
            memcpy(op_input + 1, blob, DNAC_NULLIFIER_SIZE);
            uint8_t op_hash[64];
            qgp_sha3_512(op_input, 65, op_hash);
            update_state_root_ctx(g_utxo_state_root, op_hash);
            count++;
        }
    }

    sqlite3_finalize(stmt);
    g_state_root_initialized = 1;

    QGP_LOG_INFO(LOG_TAG, "UTXO state root initialized from %d UTXOs", count);
    return 0;
}

/**
 * @brief Get current UTXO state root
 *
 * @param root_out Output buffer (64 bytes)
 * @return 0 on success, -1 if not initialized
 */
int witness_utxo_set_get_root(uint8_t *root_out) {
    if (!root_out) return -1;
    if (!g_state_root_initialized) {
        /* Return zeros if not yet initialized */
        memset(root_out, 0, 64);
        return 0;
    }
    memcpy(root_out, g_utxo_state_root, 64);
    return 0;
}

/* v0.10.0: Zone-aware version for block creation callback */
int witness_utxo_set_get_root_ctx(void *user_data, uint8_t *root_out) {
    if (!root_out) return -1;
    int *initialized = get_state_root_initialized(user_data);
    if (!*initialized) {
        memset(root_out, 0, 64);
        return 0;
    }
    memcpy(root_out, get_state_root(user_data), 64);
    return 0;
}
