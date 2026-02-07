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
#include <sqlite3.h>
#include <string.h>
#include <time.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "UTXO_SET"

/* Shared database handle from nullifier.c */
extern sqlite3 *nullifier_db;

/* ============================================================================
 * Lookup
 * ========================================================================== */

int witness_utxo_set_lookup(const uint8_t *nullifier,
                             uint64_t *amount_out,
                             char *owner_out) {
    if (!nullifier_db || !nullifier) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "SELECT amount, owner_fingerprint FROM utxo_set WHERE nullifier = ?",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare UTXO lookup: %s",
                      sqlite3_errmsg(nullifier_db));
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
                          uint64_t block_height) {
    if (!nullifier_db || !nullifier || !owner || !tx_hash) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "INSERT OR IGNORE INTO utxo_set "
        "(nullifier, owner_fingerprint, amount, tx_hash, output_index, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare UTXO add: %s",
                      sqlite3_errmsg(nullifier_db));
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
                      sqlite3_errmsg(nullifier_db));
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Added UTXO: amount=%llu owner=%.16s...",
                  (unsigned long long)amount, owner);
    return 0;
}

/* ============================================================================
 * Remove (spent UTXO)
 * ========================================================================== */

int witness_utxo_set_remove(const uint8_t *nullifier) {
    if (!nullifier_db || !nullifier) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "DELETE FROM utxo_set WHERE nullifier = ?",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare UTXO remove: %s",
                      sqlite3_errmsg(nullifier_db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, nullifier, DNAC_NULLIFIER_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(nullifier_db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to remove UTXO: %s",
                      sqlite3_errmsg(nullifier_db));
        return -1;
    }

    if (changes == 0) {
        QGP_LOG_WARN(LOG_TAG, "UTXO not found for removal");
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Genesis: Populate UTXO set from genesis TX outputs
 * ========================================================================== */

int witness_utxo_set_genesis(const dnac_transaction_t *genesis_tx,
                              const uint8_t *tx_hash) {
    if (!nullifier_db || !genesis_tx || !tx_hash) return -1;

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
                                   0 /* block height 0 = genesis */);
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
    if (!nullifier_db || !count_out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "SELECT COUNT(*) FROM utxo_set", -1, &stmt, NULL);

    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *count_out = (uint64_t)sqlite3_column_int64(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return 0;
}
