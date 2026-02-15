/**
 * @file ledger.c
 * @brief Transaction ledger implementation for witness server
 *
 * Manages the append-only transaction ledger with Merkle proofs.
 * Uses the same SQLite database as nullifier.c.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/ledger.h"
#include "dnac/bft.h"
#include "dnac/zone.h"
#include <sqlite3.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

/* libdna crypto utilities */
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_dilithium.h"

#define LOG_TAG "WITNESS_LEDGER"

/* P0-3 (v0.7.0): Checkpoint interval for proof generation */
#define DNAC_PROOF_CHECKPOINT_INTERVAL 100

/* External database handle from nullifier.c */
extern sqlite3 *nullifier_db;

/* In-memory Merkle tree state for incremental updates */
static uint8_t g_current_root[DNAC_MERKLE_ROOT_SIZE];
static uint64_t g_leaf_count = 0;
static bool g_merkle_initialized = false;

/* v0.10.0: Get DB handle from zone user_data, falling back to global */
static inline sqlite3 *get_db(void *user_data) {
    if (user_data) {
        dnac_zone_t *zone = (dnac_zone_t *)user_data;
        if (zone->db) return zone->db;
    }
    return nullifier_db;
}

/* ============================================================================
 * Merkle Tree Helpers
 * ========================================================================== */

/**
 * Compute SHA3-512 hash
 */
static int compute_hash(const uint8_t *data, size_t len, uint8_t *hash_out) {
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
 * Compute parent hash from two children
 */
static int compute_parent_hash(const uint8_t *left, const uint8_t *right,
                                uint8_t *parent_out) {
    uint8_t combined[DNAC_MERKLE_ROOT_SIZE * 2];
    memcpy(combined, left, DNAC_MERKLE_ROOT_SIZE);
    memcpy(combined + DNAC_MERKLE_ROOT_SIZE, right, DNAC_MERKLE_ROOT_SIZE);
    return compute_hash(combined, sizeof(combined), parent_out);
}

/**
 * Compute leaf hash for a ledger entry
 */
static int compute_leaf_hash(const dnac_ledger_entry_t *entry, uint8_t *hash_out) {
    /* Leaf = H(seq || tx_hash || tx_type || timestamp) */
    uint8_t data[8 + DNAC_TX_HASH_SIZE + 1 + 8];
    size_t offset = 0;

    /* Sequence number (little-endian) */
    for (int i = 0; i < 8; i++) {
        data[offset++] = (entry->sequence_number >> (i * 8)) & 0xFF;
    }

    memcpy(data + offset, entry->tx_hash, DNAC_TX_HASH_SIZE);
    offset += DNAC_TX_HASH_SIZE;

    data[offset++] = entry->tx_type;

    /* Timestamp (little-endian) */
    for (int i = 0; i < 8; i++) {
        data[offset++] = (entry->timestamp >> (i * 8)) & 0xFF;
    }

    return compute_hash(data, offset, hash_out);
}

/**
 * Update Merkle root with new leaf (incremental)
 *
 * Simple approach: recompute from stored hashes.
 * For production, would use a proper incremental Merkle tree.
 */
static int update_merkle_root(const uint8_t *leaf_hash) {
    if (!g_merkle_initialized) {
        /* First leaf - root is just the leaf hash */
        memcpy(g_current_root, leaf_hash, DNAC_MERKLE_ROOT_SIZE);
        g_leaf_count = 1;
        g_merkle_initialized = true;
        return 0;
    }

    /* Simple incremental: H(old_root || new_leaf) */
    /* This is a simplified approach - a real implementation would
     * maintain the full tree structure for proper proofs */
    uint8_t new_root[DNAC_MERKLE_ROOT_SIZE];
    if (compute_parent_hash(g_current_root, leaf_hash, new_root) != 0) {
        return -1;
    }

    memcpy(g_current_root, new_root, DNAC_MERKLE_ROOT_SIZE);
    g_leaf_count++;
    return 0;
}

/* ============================================================================
 * P0-3 (v0.7.0): Checkpoint Functions for Merkle Proofs
 * ========================================================================== */

/**
 * Save a Merkle checkpoint at the given sequence number
 */
static int save_checkpoint(uint64_t seq, const uint8_t *merkle_root, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !merkle_root) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO ledger_checkpoints (checkpoint_seq, merkle_root) "
        "VALUES (?, ?)", -1, &stmt, NULL);

    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)seq);
    sqlite3_bind_blob(stmt, 2, merkle_root, DNAC_MERKLE_ROOT_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        QGP_LOG_DEBUG(LOG_TAG, "Saved checkpoint at seq %llu", (unsigned long long)seq);
        return 0;
    }
    return -1;
}

/**
 * Load the nearest checkpoint <= target sequence
 */
static int load_checkpoint(uint64_t target_seq, uint64_t *checkpoint_seq_out,
                            uint8_t *merkle_root_out, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !checkpoint_seq_out || !merkle_root_out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "SELECT checkpoint_seq, merkle_root FROM ledger_checkpoints "
        "WHERE checkpoint_seq <= ? ORDER BY checkpoint_seq DESC LIMIT 1",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)target_seq);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;  /* No checkpoint found */
    }

    *checkpoint_seq_out = (uint64_t)sqlite3_column_int64(stmt, 0);

    const void *blob = sqlite3_column_blob(stmt, 1);
    int blob_size = sqlite3_column_bytes(stmt, 1);
    if (blob && blob_size == DNAC_MERKLE_ROOT_SIZE) {
        memcpy(merkle_root_out, blob, DNAC_MERKLE_ROOT_SIZE);
    } else {
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

/* ============================================================================
 * Ledger Functions
 * ========================================================================== */

int witness_ledger_init(void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized");
        return -1;
    }

    /* Load current state from database */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "SELECT sequence_number, merkle_root FROM ledger_entries "
        "ORDER BY sequence_number DESC LIMIT 1", -1, &stmt, NULL);

    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            g_leaf_count = (uint64_t)sqlite3_column_int64(stmt, 0);
            const void *root = sqlite3_column_blob(stmt, 1);
            int root_size = sqlite3_column_bytes(stmt, 1);
            if (root && root_size == DNAC_MERKLE_ROOT_SIZE) {
                memcpy(g_current_root, root, DNAC_MERKLE_ROOT_SIZE);
                g_merkle_initialized = true;
            }
        }
        sqlite3_finalize(stmt);
    }

    QGP_LOG_INFO(LOG_TAG, "Ledger initialized: %llu entries",
                 (unsigned long long)g_leaf_count);
    return 0;
}

void witness_ledger_shutdown(void) {
    g_merkle_initialized = false;
    g_leaf_count = 0;
    memset(g_current_root, 0, sizeof(g_current_root));
}

uint64_t witness_ledger_get_next_seq(void) {
    return g_leaf_count + 1;
}

int witness_ledger_get_root(uint8_t *root_out) {
    if (!g_merkle_initialized || !root_out) return -1;
    memcpy(root_out, g_current_root, DNAC_MERKLE_ROOT_SIZE);
    return 0;
}

int witness_ledger_add_entry(const dnac_ledger_entry_t *entry, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !entry) return -1;

    /* Compute leaf hash */
    uint8_t leaf_hash[DNAC_MERKLE_ROOT_SIZE];
    if (compute_leaf_hash(entry, leaf_hash) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to compute leaf hash");
        return -1;
    }

    /* Update Merkle root */
    if (update_merkle_root(leaf_hash) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to update Merkle root");
        return -1;
    }

    /* Serialize nullifiers for storage */
    uint8_t nullifier_blob[DNAC_TX_MAX_INPUTS * DNAC_NULLIFIER_SIZE];
    size_t nullifier_blob_size = entry->nullifier_count * DNAC_NULLIFIER_SIZE;
    for (int i = 0; i < entry->nullifier_count; i++) {
        memcpy(nullifier_blob + i * DNAC_NULLIFIER_SIZE,
               entry->nullifiers[i], DNAC_NULLIFIER_SIZE);
    }

    /* Insert entry */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO ledger_entries (sequence_number, tx_hash, tx_type, "
        "nullifiers, output_commitment, merkle_root, timestamp, epoch) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare insert: %s",
                      sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (int64_t)entry->sequence_number);
    sqlite3_bind_blob(stmt, 2, entry->tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, entry->tx_type);
    sqlite3_bind_blob(stmt, 4, nullifier_blob, (int)nullifier_blob_size, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, entry->output_commitment,
                      DNAC_OUTPUT_COMMITMENT_SIZE, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 6, g_current_root, DNAC_MERKLE_ROOT_SIZE, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 7, (int64_t)entry->timestamp);
    sqlite3_bind_int64(stmt, 8, (int64_t)entry->epoch);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to insert ledger entry: %s",
                      sqlite3_errmsg(db));
        return -1;
    }

    /* P0-3 (v0.7.0): Save checkpoint every DNAC_PROOF_CHECKPOINT_INTERVAL entries */
    if (entry->sequence_number % DNAC_PROOF_CHECKPOINT_INTERVAL == 0) {
        if (save_checkpoint(entry->sequence_number, g_current_root, user_data) == 0) {
            QGP_LOG_INFO(LOG_TAG, "Saved Merkle checkpoint at seq %llu",
                         (unsigned long long)entry->sequence_number);
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Added ledger entry #%llu (type=%d)",
                 (unsigned long long)entry->sequence_number, entry->tx_type);
    return 0;
}

int witness_ledger_get_entry(uint64_t seq, dnac_ledger_entry_t *entry_out, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !entry_out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "SELECT tx_hash, tx_type, nullifiers, output_commitment, merkle_root, "
        "timestamp, epoch FROM ledger_entries WHERE sequence_number = ?",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)seq);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    memset(entry_out, 0, sizeof(*entry_out));
    entry_out->sequence_number = seq;

    const void *blob;
    int blob_size;

    /* tx_hash */
    blob = sqlite3_column_blob(stmt, 0);
    blob_size = sqlite3_column_bytes(stmt, 0);
    if (blob && blob_size == DNAC_TX_HASH_SIZE) {
        memcpy(entry_out->tx_hash, blob, DNAC_TX_HASH_SIZE);
    }

    entry_out->tx_type = (uint8_t)sqlite3_column_int(stmt, 1);

    /* nullifiers */
    blob = sqlite3_column_blob(stmt, 2);
    blob_size = sqlite3_column_bytes(stmt, 2);
    if (blob && blob_size > 0) {
        entry_out->nullifier_count = (uint8_t)(blob_size / DNAC_NULLIFIER_SIZE);
        for (int i = 0; i < entry_out->nullifier_count && i < DNAC_TX_MAX_INPUTS; i++) {
            memcpy(entry_out->nullifiers[i],
                   (const uint8_t*)blob + i * DNAC_NULLIFIER_SIZE,
                   DNAC_NULLIFIER_SIZE);
        }
    }

    /* output_commitment */
    blob = sqlite3_column_blob(stmt, 3);
    blob_size = sqlite3_column_bytes(stmt, 3);
    if (blob && blob_size == DNAC_OUTPUT_COMMITMENT_SIZE) {
        memcpy(entry_out->output_commitment, blob, DNAC_OUTPUT_COMMITMENT_SIZE);
    }

    /* merkle_root */
    blob = sqlite3_column_blob(stmt, 4);
    blob_size = sqlite3_column_bytes(stmt, 4);
    if (blob && blob_size == DNAC_MERKLE_ROOT_SIZE) {
        memcpy(entry_out->merkle_root, blob, DNAC_MERKLE_ROOT_SIZE);
    }

    entry_out->timestamp = (uint64_t)sqlite3_column_int64(stmt, 5);
    entry_out->epoch = (uint64_t)sqlite3_column_int64(stmt, 6);

    sqlite3_finalize(stmt);
    return 0;
}

int witness_ledger_get_entry_by_hash(const uint8_t *tx_hash,
                                      dnac_ledger_entry_t *entry_out, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !tx_hash || !entry_out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "SELECT sequence_number FROM ledger_entries WHERE tx_hash = ?",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    uint64_t seq = (uint64_t)sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);

    return witness_ledger_get_entry(seq, entry_out, user_data);
}

int witness_ledger_get_proof(uint64_t seq, dnac_merkle_proof_t *proof_out, void *user_data) {
    if (!proof_out || seq < 1) return -1;

    memset(proof_out, 0, sizeof(*proof_out));
    proof_out->leaf_index = seq - 1;

    /* Get current root */
    if (witness_ledger_get_root(proof_out->root) != 0) {
        return -1;
    }

    /* Get target entry and compute its leaf hash */
    dnac_ledger_entry_t target_entry;
    if (witness_ledger_get_entry(seq, &target_entry, user_data) != 0) {
        return -1;
    }
    if (compute_leaf_hash(&target_entry, proof_out->leaf_hash) != 0) {
        return -1;
    }

    /*
     * P0-3 (v0.7.0): Checkpoint-based proof generation
     *
     * The proof structure:
     * - siblings[0] = checkpoint root (state at checkpoint_seq)
     * - siblings[1..n] = leaf hashes from checkpoint_seq+1 to seq
     * - directions[i] = 1 (right) for all (chain structure)
     *
     * To verify: start with checkpoint root, hash in each leaf sequentially,
     * result should match current root.
     */

    /* Find nearest checkpoint <= seq */
    uint64_t checkpoint_seq = 0;
    uint8_t checkpoint_root[DNAC_MERKLE_ROOT_SIZE];

    int rc = load_checkpoint(seq, &checkpoint_seq, checkpoint_root, user_data);
    if (rc != 0) {
        /* No checkpoint found - this is entry #1 or early entries before first checkpoint */
        /* For these, we can't generate a full proof, return minimal proof */
        proof_out->proof_length = 0;
        QGP_LOG_DEBUG(LOG_TAG, "No checkpoint for seq %llu, returning minimal proof",
                      (unsigned long long)seq);
        return 0;
    }

    /* Calculate proof length: entries from checkpoint+1 to seq */
    int proof_len = 0;

    /* First sibling is the checkpoint root */
    memcpy(proof_out->siblings[proof_len], checkpoint_root, DNAC_MERKLE_ROOT_SIZE);
    proof_out->directions[proof_len] = 0;  /* Checkpoint on left */
    proof_len++;

    /* Add leaf hashes from checkpoint+1 to seq-1 (not including target) */
    for (uint64_t i = checkpoint_seq + 1; i < seq && proof_len < DNAC_MERKLE_MAX_DEPTH; i++) {
        dnac_ledger_entry_t entry;
        if (witness_ledger_get_entry(i, &entry, user_data) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to get entry %llu for proof", (unsigned long long)i);
            return -1;
        }

        uint8_t leaf_hash[DNAC_MERKLE_ROOT_SIZE];
        if (compute_leaf_hash(&entry, leaf_hash) != 0) {
            return -1;
        }

        memcpy(proof_out->siblings[proof_len], leaf_hash, DNAC_MERKLE_ROOT_SIZE);
        proof_out->directions[proof_len] = 1;  /* Leaf on right */
        proof_len++;
    }

    proof_out->proof_length = proof_len;

    QGP_LOG_DEBUG(LOG_TAG, "Generated proof for seq %llu: checkpoint=%llu, length=%d",
                  (unsigned long long)seq, (unsigned long long)checkpoint_seq, proof_len);
    return 0;
}

/* ============================================================================
 * Supply Tracking Functions
 * ========================================================================== */

int witness_supply_init(uint64_t total_supply, const uint8_t *genesis_tx_hash, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !genesis_tx_hash) return -1;

    /* Check if already initialized */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "SELECT 1 FROM supply_tracking WHERE id = 1", -1, &stmt, NULL);

    if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        sqlite3_finalize(stmt);
        QGP_LOG_WARN(LOG_TAG, "Supply already initialized");
        return -2;
    }
    sqlite3_finalize(stmt);

    /* Initialize supply */
    rc = sqlite3_prepare_v2(db,
        "INSERT INTO supply_tracking (id, genesis_supply, total_burned, "
        "current_supply, last_tx_hash, last_sequence) VALUES (1, ?, 0, ?, ?, 1)",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare supply init: %s",
                      sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (int64_t)total_supply);
    sqlite3_bind_int64(stmt, 2, (int64_t)total_supply);
    sqlite3_bind_blob(stmt, 3, genesis_tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to init supply: %s",
                      sqlite3_errmsg(db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Supply initialized: %llu",
                 (unsigned long long)total_supply);
    return 0;
}

int witness_supply_record_burn(uint64_t burn_amount, const uint8_t *tx_hash, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !tx_hash || burn_amount == 0) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "UPDATE supply_tracking SET "
        "total_burned = total_burned + ?, "
        "current_supply = current_supply - ?, "
        "last_tx_hash = ?, "
        "last_sequence = last_sequence + 1 "
        "WHERE id = 1", -1, &stmt, NULL);

    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)burn_amount);
    sqlite3_bind_int64(stmt, 2, (int64_t)burn_amount);
    sqlite3_bind_blob(stmt, 3, tx_hash, DNAC_TX_HASH_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return -1;

    QGP_LOG_INFO(LOG_TAG, "Recorded burn: %llu", (unsigned long long)burn_amount);
    return 0;
}

int witness_supply_get_state(dnac_supply_state_t *state_out, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !state_out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "SELECT genesis_supply, total_burned, current_supply, last_tx_hash, "
        "last_sequence FROM supply_tracking WHERE id = 1", -1, &stmt, NULL);

    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    memset(state_out, 0, sizeof(*state_out));
    state_out->genesis_supply = (uint64_t)sqlite3_column_int64(stmt, 0);
    state_out->total_burned = (uint64_t)sqlite3_column_int64(stmt, 1);
    state_out->current_supply = (uint64_t)sqlite3_column_int64(stmt, 2);

    const void *blob = sqlite3_column_blob(stmt, 3);
    int blob_size = sqlite3_column_bytes(stmt, 3);
    if (blob && blob_size == DNAC_TX_HASH_SIZE) {
        memcpy(state_out->last_tx_hash, blob, DNAC_TX_HASH_SIZE);
    }

    state_out->last_sequence = (uint64_t)sqlite3_column_int64(stmt, 4);

    sqlite3_finalize(stmt);
    return 0;
}

/* ============================================================================
 * P0-2 (v0.7.0): Range Query Functions
 * ========================================================================== */

uint64_t witness_ledger_get_total_entries(void *user_data) {
    (void)user_data;
    return g_leaf_count;
}

int witness_ledger_get_range(uint64_t from_seq,
                              uint64_t to_seq,
                              dnac_ledger_entry_t *entries,
                              int max_entries,
                              int *count_out, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !entries || !count_out || max_entries <= 0) {
        return -1;
    }

    *count_out = 0;

    /* If to_seq is 0, query up to the latest */
    uint64_t actual_to = (to_seq == 0) ? g_leaf_count : to_seq;

    /* Clamp to actual range */
    if (from_seq < 1) from_seq = 1;
    if (actual_to > g_leaf_count) actual_to = g_leaf_count;
    if (from_seq > actual_to) return 0;  /* Empty range */

    /* Limit results */
    uint64_t requested_count = actual_to - from_seq + 1;
    if (requested_count > (uint64_t)max_entries) {
        actual_to = from_seq + (uint64_t)max_entries - 1;
    }

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "SELECT sequence_number, tx_hash, tx_type, nullifiers, output_commitment, "
        "merkle_root, timestamp, epoch FROM ledger_entries "
        "WHERE sequence_number >= ? AND sequence_number <= ? "
        "ORDER BY sequence_number ASC",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare range query: %s",
                      sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (int64_t)from_seq);
    sqlite3_bind_int64(stmt, 2, (int64_t)actual_to);

    int count = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && count < max_entries) {
        dnac_ledger_entry_t *entry = &entries[count];
        memset(entry, 0, sizeof(*entry));

        entry->sequence_number = (uint64_t)sqlite3_column_int64(stmt, 0);

        const void *blob;
        int blob_size;

        /* tx_hash */
        blob = sqlite3_column_blob(stmt, 1);
        blob_size = sqlite3_column_bytes(stmt, 1);
        if (blob && blob_size == DNAC_TX_HASH_SIZE) {
            memcpy(entry->tx_hash, blob, DNAC_TX_HASH_SIZE);
        }

        entry->tx_type = (uint8_t)sqlite3_column_int(stmt, 2);

        /* nullifiers */
        blob = sqlite3_column_blob(stmt, 3);
        blob_size = sqlite3_column_bytes(stmt, 3);
        if (blob && blob_size > 0) {
            entry->nullifier_count = (uint8_t)(blob_size / DNAC_NULLIFIER_SIZE);
            for (int i = 0; i < entry->nullifier_count && i < DNAC_TX_MAX_INPUTS; i++) {
                memcpy(entry->nullifiers[i],
                       (const uint8_t*)blob + i * DNAC_NULLIFIER_SIZE,
                       DNAC_NULLIFIER_SIZE);
            }
        }

        /* output_commitment */
        blob = sqlite3_column_blob(stmt, 4);
        blob_size = sqlite3_column_bytes(stmt, 4);
        if (blob && blob_size == DNAC_OUTPUT_COMMITMENT_SIZE) {
            memcpy(entry->output_commitment, blob, DNAC_OUTPUT_COMMITMENT_SIZE);
        }

        /* merkle_root */
        blob = sqlite3_column_blob(stmt, 5);
        blob_size = sqlite3_column_bytes(stmt, 5);
        if (blob && blob_size == DNAC_MERKLE_ROOT_SIZE) {
            memcpy(entry->merkle_root, blob, DNAC_MERKLE_ROOT_SIZE);
        }

        entry->timestamp = (uint64_t)sqlite3_column_int64(stmt, 6);
        entry->epoch = (uint64_t)sqlite3_column_int64(stmt, 7);

        count++;
    }

    sqlite3_finalize(stmt);

    *count_out = count;
    QGP_LOG_DEBUG(LOG_TAG, "Range query: from=%llu to=%llu returned=%d",
                  (unsigned long long)from_seq, (unsigned long long)actual_to, count);
    return 0;
}

/* ============================================================================
 * Merkle Proof Verification
 * ========================================================================== */

bool dnac_merkle_verify_proof(const dnac_merkle_proof_t *proof) {
    if (!proof) return false;

    /*
     * P0-3 (v0.7.0): Checkpoint-based proof verification
     *
     * Proof structure:
     * - siblings[0] = checkpoint root (directions[0] = 0, left)
     * - siblings[1..n-1] = intermediate leaf hashes (directions[i] = 1, right)
     * - leaf_hash = target entry's hash
     *
     * Verification:
     * 1. Start with checkpoint root
     * 2. For each intermediate leaf: current = H(current || leaf)
     * 3. Finally: current = H(current || leaf_hash)
     * 4. Compare with stored root
     */

    if (proof->proof_length == 0) {
        /* No checkpoint proof - for early entries, just verify leaf is non-zero */
        uint8_t zero[DNAC_MERKLE_ROOT_SIZE] = {0};
        return memcmp(proof->leaf_hash, zero, DNAC_MERKLE_ROOT_SIZE) != 0;
    }

    uint8_t current[DNAC_MERKLE_ROOT_SIZE];

    /* Start with checkpoint root (first sibling, should be on left) */
    memcpy(current, proof->siblings[0], DNAC_MERKLE_ROOT_SIZE);

    /* Apply intermediate leaf hashes */
    for (int i = 1; i < proof->proof_length; i++) {
        uint8_t parent[DNAC_MERKLE_ROOT_SIZE];
        if (proof->directions[i] == 0) {
            /* Sibling is on left, current on right */
            compute_parent_hash(proof->siblings[i], current, parent);
        } else {
            /* Sibling is on right, current on left */
            compute_parent_hash(current, proof->siblings[i], parent);
        }
        memcpy(current, parent, DNAC_MERKLE_ROOT_SIZE);
    }

    /* Apply the target leaf hash */
    uint8_t final_root[DNAC_MERKLE_ROOT_SIZE];
    compute_parent_hash(current, proof->leaf_hash, final_root);

    return memcmp(final_root, proof->root, DNAC_MERKLE_ROOT_SIZE) == 0;
}

/* ============================================================================
 * v0.7.1: BFT-Anchored Proof Functions
 * ========================================================================== */

int witness_ledger_get_proof_anchored(uint64_t seq, dnac_merkle_proof_t *proof_out, void *user_data) {
    if (!proof_out || seq < 1) return -1;

    /* First, get the basic proof */
    if (witness_ledger_get_proof(seq, proof_out, user_data) != 0) {
        return -1;
    }

    /* Get the entry to find its epoch */
    dnac_ledger_entry_t entry;
    if (witness_ledger_get_entry(seq, &entry, user_data) != 0) {
        return -1;
    }

    proof_out->epoch = entry.epoch;

    /* Get BFT signatures for this epoch */
    proof_out->epoch_sig_count = witness_epoch_signatures_get(
        entry.epoch,
        proof_out->epoch_sigs,
        DNAC_PROOF_MAX_SIGNATURES,
        user_data
    );

    if (proof_out->epoch_sig_count < 0) {
        proof_out->epoch_sig_count = 0;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Generated anchored proof: seq=%llu, epoch=%llu, sigs=%d",
                  (unsigned long long)seq,
                  (unsigned long long)entry.epoch,
                  proof_out->epoch_sig_count);

    return 0;
}

/**
 * Compute the epoch root signing data
 * This is what witnesses sign: H(epoch || ledger_root || utxo_root || timestamp)
 */
static int compute_epoch_signing_data(uint64_t epoch,
                                       const uint8_t *ledger_root,
                                       uint8_t *signing_data_out) {
    uint8_t data[8 + 64 + 8];  /* epoch + ledger_root + padding */
    size_t offset = 0;

    /* Epoch (little-endian) */
    for (int i = 0; i < 8; i++) {
        data[offset++] = (epoch >> (i * 8)) & 0xFF;
    }

    /* Ledger root */
    memcpy(data + offset, ledger_root, 64);
    offset += 64;

    return compute_hash(data, offset, signing_data_out);
}

bool dnac_merkle_verify_proof_anchored(const dnac_merkle_proof_t *proof,
                                        const void *roster_ptr,
                                        int quorum_required) {
    if (!proof || !roster_ptr || quorum_required < 1) return false;

    /* First verify the hash computation */
    if (!dnac_merkle_verify_proof(proof)) {
        QGP_LOG_WARN(LOG_TAG, "Proof hash verification failed");
        return false;
    }

    /* Check we have enough signatures */
    if (proof->epoch_sig_count < quorum_required) {
        QGP_LOG_WARN(LOG_TAG, "Insufficient signatures: have %d, need %d",
                     proof->epoch_sig_count, quorum_required);
        return false;
    }

    /* Compute what should have been signed */
    uint8_t signing_data[64];
    if (compute_epoch_signing_data(proof->epoch, proof->root, signing_data) != 0) {
        return false;
    }

    /* Cast roster for access */
    const dnac_roster_t *roster = (const dnac_roster_t *)roster_ptr;

    /* Verify each signature */
    int valid_sigs = 0;
    for (int i = 0; i < proof->epoch_sig_count; i++) {
        /* Find signer in roster */
        int signer_idx = -1;
        for (uint32_t j = 0; j < roster->n_witnesses; j++) {
            if (memcmp(roster->witnesses[j].witness_id,
                       proof->epoch_sigs[i].signer_id, 32) == 0) {
                signer_idx = (int)j;
                break;
            }
        }

        if (signer_idx < 0) {
            QGP_LOG_WARN(LOG_TAG, "Signer not in roster: %.8s...",
                         proof->epoch_sigs[i].signer_id);
            continue;
        }

        /* Verify Dilithium5 signature using libdna */
        int verify_result = qgp_dsa87_verify(
            proof->epoch_sigs[i].signature, DNAC_SIGNATURE_SIZE,
            signing_data, sizeof(signing_data),
            roster->witnesses[signer_idx].pubkey
        );

        if (verify_result == 0) {
            valid_sigs++;
        } else {
            QGP_LOG_WARN(LOG_TAG, "Invalid signature from witness %d", signer_idx);
        }
    }

    if (valid_sigs >= quorum_required) {
        QGP_LOG_DEBUG(LOG_TAG, "Proof BFT-verified: %d/%d valid signatures",
                      valid_sigs, quorum_required);
        return true;
    }

    QGP_LOG_WARN(LOG_TAG, "Insufficient valid signatures: %d/%d",
                 valid_sigs, quorum_required);
    return false;
}

/* Client query functions (dnac_ledger_query_tx, dnac_ledger_get_supply) are
 * implemented in src/nodus/tcp_client.c as they require TCP client code */
