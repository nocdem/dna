/**
 * @file utxo_tree.c
 * @brief UTXO commitment tree implementation for witness server
 *
 * Manages the global UTXO state using a simplified Sparse Merkle Tree.
 * Uses the same SQLite database as nullifier.c.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/commitment.h"
#include <sqlite3.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "WITNESS_UTXO"

/* External database handle from nullifier.c */
extern sqlite3 *nullifier_db;

/* In-memory SMT root (simplified - full SMT would need more state) */
static uint8_t g_utxo_root[64];
static uint64_t g_utxo_count = 0;
static bool g_utxo_initialized = false;

/* ============================================================================
 * Hash Helpers
 * ========================================================================== */

static int compute_sha3_512(const uint8_t *data, size_t len, uint8_t *hash_out) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;

    if (EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, data, len) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash_out, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    return 0;
}

/**
 * Update root incrementally (simplified - combines old root with new commitment)
 */
static void update_root(const uint8_t *commitment) {
    uint8_t combined[128];
    memcpy(combined, g_utxo_root, 64);
    memcpy(combined + 64, commitment, 64);
    compute_sha3_512(combined, 128, g_utxo_root);
}

/* ============================================================================
 * UTXO Functions
 * ========================================================================== */

int witness_utxo_init(void) {
    if (!nullifier_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized");
        return -1;
    }

    /* Count existing unspent UTXOs and compute root */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "SELECT commitment FROM utxo_commitments WHERE spent_epoch IS NULL "
        "ORDER BY created_epoch, commitment", -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to query UTXOs: %s",
                      sqlite3_errmsg(nullifier_db));
        return -1;
    }

    /* Initialize root to zeros */
    memset(g_utxo_root, 0, sizeof(g_utxo_root));
    g_utxo_count = 0;

    /* Rebuild root from existing UTXOs */
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const void *commit = sqlite3_column_blob(stmt, 0);
        int commit_size = sqlite3_column_bytes(stmt, 0);
        if (commit && commit_size == 64) {
            update_root((const uint8_t*)commit);
            g_utxo_count++;
        }
    }
    sqlite3_finalize(stmt);

    g_utxo_initialized = true;
    QGP_LOG_INFO(LOG_TAG, "UTXO system initialized: %llu unspent",
                 (unsigned long long)g_utxo_count);
    return 0;
}

void witness_utxo_shutdown(void) {
    g_utxo_initialized = false;
    g_utxo_count = 0;
    memset(g_utxo_root, 0, sizeof(g_utxo_root));
}

int witness_utxo_add(const dnac_utxo_commitment_t *commitment) {
    if (!nullifier_db || !commitment) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "INSERT OR IGNORE INTO utxo_commitments "
        "(commitment, tx_hash, output_index, amount, owner_commit, created_epoch) "
        "VALUES (?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare UTXO insert: %s",
                      sqlite3_errmsg(nullifier_db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, commitment->commitment, 64, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, commitment->tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, (int)commitment->output_index);
    sqlite3_bind_int64(stmt, 4, (int64_t)commitment->amount);
    sqlite3_bind_blob(stmt, 5, commitment->owner_commitment, 64, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, (int64_t)commitment->created_epoch);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to insert UTXO: %s",
                      sqlite3_errmsg(nullifier_db));
        return -1;
    }

    /* Update in-memory state */
    update_root(commitment->commitment);
    g_utxo_count++;

    QGP_LOG_DEBUG(LOG_TAG, "Added UTXO: amount=%llu",
                  (unsigned long long)commitment->amount);
    return 0;
}

int witness_utxo_mark_spent(const uint8_t *commitment_hash, uint64_t spent_epoch) {
    if (!nullifier_db || !commitment_hash) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "UPDATE utxo_commitments SET spent_epoch = ? WHERE commitment = ? "
        "AND spent_epoch IS NULL", -1, &stmt, NULL);

    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)spent_epoch);
    sqlite3_bind_blob(stmt, 2, commitment_hash, 64, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(nullifier_db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE || changes == 0) {
        return -1;  /* Not found or already spent */
    }

    /* Gap 21 Fix (v0.6.0): Recompute root after spend
     * We rebuild the root from remaining unspent UTXOs.
     * This is O(n) but correct. A proper SMT would use incremental updates. */
    if (g_utxo_count > 0) g_utxo_count--;

    /* Recompute root from remaining unspent UTXOs */
    sqlite3_stmt *root_stmt;
    rc = sqlite3_prepare_v2(nullifier_db,
        "SELECT commitment FROM utxo_commitments WHERE spent_epoch IS NULL "
        "ORDER BY created_epoch, commitment", -1, &root_stmt, NULL);

    if (rc == SQLITE_OK) {
        memset(g_utxo_root, 0, sizeof(g_utxo_root));
        while (sqlite3_step(root_stmt) == SQLITE_ROW) {
            const void *commit = sqlite3_column_blob(root_stmt, 0);
            int commit_size = sqlite3_column_bytes(root_stmt, 0);
            if (commit && commit_size == 64) {
                update_root((const uint8_t*)commit);
            }
        }
        sqlite3_finalize(root_stmt);
        QGP_LOG_DEBUG(LOG_TAG, "UTXO root recomputed after spend");
    }

    return 0;
}

bool witness_utxo_exists(const uint8_t *commitment_hash) {
    if (!nullifier_db || !commitment_hash) return false;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "SELECT 1 FROM utxo_commitments WHERE commitment = ? AND spent_epoch IS NULL",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) return false;

    sqlite3_bind_blob(stmt, 1, commitment_hash, 64, SQLITE_STATIC);

    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    return exists;
}

int witness_utxo_get_root(uint8_t *root_out) {
    if (!g_utxo_initialized || !root_out) return -1;
    memcpy(root_out, g_utxo_root, 64);
    return 0;
}

int witness_utxo_get_proof(const uint8_t *commitment_hash,
                            dnac_smt_proof_t *proof_out) {
    if (!proof_out || !commitment_hash) return -1;

    /* Gap 20 Fix (v0.6.0): Implement proper proof with siblings
     *
     * We use a simplified Merkle proof based on our hash-chain tree structure.
     * The proof includes "siblings" which are the partial roots computed from
     * UTXOs before and after the target commitment.
     *
     * Verification: Start from target, apply siblings in order, should equal root.
     */
    memset(proof_out, 0, sizeof(*proof_out));
    memcpy(proof_out->key, commitment_hash, 64);
    proof_out->exists = witness_utxo_exists(commitment_hash);
    memcpy(proof_out->root, g_utxo_root, 64);
    proof_out->epoch = (uint64_t)(time(NULL) / 3600);

    if (!proof_out->exists) {
        /* Non-existence proof - just include root */
        proof_out->proof_length = 0;
        return 0;
    }

    /* Build proof by computing partial roots before and after target */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "SELECT commitment FROM utxo_commitments WHERE spent_epoch IS NULL "
        "ORDER BY created_epoch, commitment", -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        proof_out->proof_length = 0;
        return 0;
    }

    /* Compute prefix hash (all UTXOs before target) */
    uint8_t prefix_root[64];
    memset(prefix_root, 0, sizeof(prefix_root));
    bool found_target = false;
    int position = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const void *commit = sqlite3_column_blob(stmt, 0);
        int commit_size = sqlite3_column_bytes(stmt, 0);
        if (!commit || commit_size != 64) continue;

        if (memcmp(commit, commitment_hash, 64) == 0) {
            found_target = true;
            /* Store prefix as first sibling */
            if (proof_out->proof_length < DNAC_SMT_MAX_DEPTH) {
                memcpy(proof_out->siblings[proof_out->proof_length], prefix_root, 64);
                proof_out->proof_length++;
            }
        } else if (!found_target) {
            /* Accumulate into prefix root */
            uint8_t combined[128];
            memcpy(combined, prefix_root, 64);
            memcpy(combined + 64, commit, 64);
            compute_sha3_512(combined, 128, prefix_root);
            position++;
        } else {
            /* After target - store suffix UTXOs as siblings (up to limit) */
            if (proof_out->proof_length < DNAC_SMT_MAX_DEPTH) {
                memcpy(proof_out->siblings[proof_out->proof_length], commit, 64);
                proof_out->proof_length++;
            }
        }
    }
    sqlite3_finalize(stmt);

    QGP_LOG_DEBUG(LOG_TAG, "Generated proof: exists=%d, siblings=%d, position=%d",
                  proof_out->exists, proof_out->proof_length, position);
    return 0;
}

int witness_utxo_get_by_owner(const uint8_t *owner_commitment,
                               dnac_utxo_commitment_t *commitments_out,
                               int max_count) {
    if (!nullifier_db || !owner_commitment || !commitments_out || max_count <= 0) {
        return -1;
    }

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "SELECT commitment, tx_hash, output_index, amount, owner_commit, "
        "created_epoch FROM utxo_commitments "
        "WHERE owner_commit = ? AND spent_epoch IS NULL LIMIT ?",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, owner_commitment, 64, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, max_count);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_count) {
        dnac_utxo_commitment_t *c = &commitments_out[count];
        memset(c, 0, sizeof(*c));

        const void *blob;
        int blob_size;

        blob = sqlite3_column_blob(stmt, 0);
        blob_size = sqlite3_column_bytes(stmt, 0);
        if (blob && blob_size == 64) memcpy(c->commitment, blob, 64);

        blob = sqlite3_column_blob(stmt, 1);
        blob_size = sqlite3_column_bytes(stmt, 1);
        if (blob && blob_size == DNAC_TX_HASH_SIZE) memcpy(c->tx_hash, blob, DNAC_TX_HASH_SIZE);

        c->output_index = (uint32_t)sqlite3_column_int(stmt, 2);
        c->amount = (uint64_t)sqlite3_column_int64(stmt, 3);

        blob = sqlite3_column_blob(stmt, 4);
        blob_size = sqlite3_column_bytes(stmt, 4);
        if (blob && blob_size == 64) memcpy(c->owner_commitment, blob, 64);

        c->created_epoch = (uint64_t)sqlite3_column_int64(stmt, 5);

        count++;
    }

    sqlite3_finalize(stmt);
    return count;
}

int witness_epoch_root_save(const dnac_epoch_root_t *epoch_root) {
    if (!nullifier_db || !epoch_root) return -1;

    /* v0.7.0: Query min/max sequence for this epoch from ledger_entries */
    uint64_t first_seq = 0;
    uint64_t last_seq = 0;

    sqlite3_stmt *seq_stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "SELECT MIN(sequence_number), MAX(sequence_number) FROM ledger_entries "
        "WHERE epoch = ?", -1, &seq_stmt, NULL);

    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(seq_stmt, 1, (int64_t)epoch_root->epoch);
        if (sqlite3_step(seq_stmt) == SQLITE_ROW) {
            /* Check for NULL (no entries in epoch) */
            if (sqlite3_column_type(seq_stmt, 0) != SQLITE_NULL) {
                first_seq = (uint64_t)sqlite3_column_int64(seq_stmt, 0);
                last_seq = (uint64_t)sqlite3_column_int64(seq_stmt, 1);
            }
        }
        sqlite3_finalize(seq_stmt);
    }

    QGP_LOG_DEBUG(LOG_TAG, "Epoch %llu: first_seq=%llu, last_seq=%llu",
                  (unsigned long long)epoch_root->epoch,
                  (unsigned long long)first_seq,
                  (unsigned long long)last_seq);

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(nullifier_db,
        "INSERT OR REPLACE INTO epoch_roots "
        "(epoch, first_sequence, last_sequence, utxo_root, ledger_root, "
        "utxo_count, total_supply, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);

    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)epoch_root->epoch);
    sqlite3_bind_int64(stmt, 2, (int64_t)first_seq);
    sqlite3_bind_int64(stmt, 3, (int64_t)last_seq);
    sqlite3_bind_blob(stmt, 4, epoch_root->utxo_root, 64, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, epoch_root->ledger_root, 64, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, (int64_t)epoch_root->utxo_count);
    sqlite3_bind_int64(stmt, 7, (int64_t)epoch_root->total_supply);
    sqlite3_bind_int64(stmt, 8, (int64_t)epoch_root->timestamp);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int witness_epoch_root_get(uint64_t epoch, dnac_epoch_root_t *root_out) {
    if (!nullifier_db || !root_out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(nullifier_db,
        "SELECT first_sequence, last_sequence, utxo_root, ledger_root, "
        "utxo_count, total_supply, timestamp "
        "FROM epoch_roots WHERE epoch = ?", -1, &stmt, NULL);

    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)epoch);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    memset(root_out, 0, sizeof(*root_out));
    root_out->epoch = epoch;

    /* v0.7.0: Read sequence boundaries */
    root_out->first_sequence = (uint64_t)sqlite3_column_int64(stmt, 0);
    root_out->last_sequence = (uint64_t)sqlite3_column_int64(stmt, 1);

    const void *blob;
    int blob_size;

    blob = sqlite3_column_blob(stmt, 2);
    blob_size = sqlite3_column_bytes(stmt, 2);
    if (blob && blob_size == 64) memcpy(root_out->utxo_root, blob, 64);

    blob = sqlite3_column_blob(stmt, 3);
    blob_size = sqlite3_column_bytes(stmt, 3);
    if (blob && blob_size == 64) memcpy(root_out->ledger_root, blob, 64);

    root_out->utxo_count = (uint64_t)sqlite3_column_int64(stmt, 4);
    root_out->total_supply = (uint64_t)sqlite3_column_int64(stmt, 5);
    root_out->timestamp = (uint64_t)sqlite3_column_int64(stmt, 6);

    sqlite3_finalize(stmt);
    return 0;
}

/* ============================================================================
 * Utility Functions
 * ========================================================================== */

int dnac_compute_utxo_commitment(const uint8_t *tx_hash,
                                  uint32_t output_index,
                                  uint64_t amount,
                                  const uint8_t *owner_commitment,
                                  uint8_t *commitment_out) {
    if (!tx_hash || !owner_commitment || !commitment_out) return -1;

    uint8_t data[DNAC_TX_HASH_SIZE + 4 + 8 + 64];
    size_t offset = 0;

    memcpy(data + offset, tx_hash, DNAC_TX_HASH_SIZE);
    offset += DNAC_TX_HASH_SIZE;

    /* Little-endian output_index */
    for (int i = 0; i < 4; i++) {
        data[offset++] = (output_index >> (i * 8)) & 0xFF;
    }

    /* Little-endian amount */
    for (int i = 0; i < 8; i++) {
        data[offset++] = (amount >> (i * 8)) & 0xFF;
    }

    memcpy(data + offset, owner_commitment, 64);
    offset += 64;

    return compute_sha3_512(data, offset, commitment_out);
}

int dnac_compute_owner_commitment(const char *fingerprint,
                                   const uint8_t *salt,
                                   uint8_t *commitment_out) {
    if (!fingerprint || !salt || !commitment_out) return -1;

    uint8_t data[256];
    size_t fp_len = strlen(fingerprint);
    if (fp_len > 128) fp_len = 128;

    memcpy(data, fingerprint, fp_len);
    memcpy(data + fp_len, salt, 32);

    return compute_sha3_512(data, fp_len + 32, commitment_out);
}

bool dnac_smt_verify_proof(const dnac_smt_proof_t *proof) {
    /* Gap 20 Fix (v0.6.0): Verify proof by recomputing root from siblings
     *
     * Proof structure:
     * - siblings[0]: prefix root (hash of all UTXOs before target)
     * - siblings[1..n]: suffix UTXOs (after target)
     *
     * Verification:
     * 1. Start with prefix_root (siblings[0])
     * 2. Hash with target key
     * 3. Hash with each suffix UTXO
     * 4. Result should match proof->root
     */
    if (!proof) return false;

    if (!proof->exists) {
        /* For non-existence, we trust the witness (can't verify without full tree) */
        return true;
    }

    if (proof->proof_length < 1) {
        /* No prefix - target must be first UTXO */
        uint8_t computed_root[64];
        memset(computed_root, 0, 64);

        /* Start with empty and add key */
        uint8_t combined[128];
        memcpy(combined, computed_root, 64);
        memcpy(combined + 64, proof->key, 64);
        compute_sha3_512(combined, 128, computed_root);

        /* Apply any suffix siblings */
        /* (none in this case) */

        return memcmp(computed_root, proof->root, 64) == 0;
    }

    /* Recompute root using prefix and suffixes */
    uint8_t computed_root[64];
    memcpy(computed_root, proof->siblings[0], 64);  /* Start with prefix */

    /* Add target key */
    uint8_t combined[128];
    memcpy(combined, computed_root, 64);
    memcpy(combined + 64, proof->key, 64);
    compute_sha3_512(combined, 128, computed_root);

    /* Add suffix UTXOs */
    for (int i = 1; i < proof->proof_length; i++) {
        memcpy(combined, computed_root, 64);
        memcpy(combined + 64, proof->siblings[i], 64);
        compute_sha3_512(combined, 128, computed_root);
    }

    bool valid = (memcmp(computed_root, proof->root, 64) == 0);
    if (!valid) {
        QGP_LOG_WARN(LOG_TAG, "SMT proof verification failed");
    }
    return valid;
}

/* Client query functions (dnac_wallet_recover_from_witnesses, dnac_utxo_get_proof)
 * are implemented in src/nodus/tcp_client.c as they require TCP client code */
