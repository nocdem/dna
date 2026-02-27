/**
 * @file block.c
 * @brief DNAC Block Chain Structure Implementation (v0.9.0)
 *
 * Implements block hash computation, chain verification, and SQLite storage.
 * Each committed TX becomes a block with height, prev_hash, and state_root.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/block.h"
#include "dnac/zone.h"
#include <sqlite3.h>
#include <string.h>
#include <limits.h>

#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_sha3.h"

#define LOG_TAG "BLOCK"

/* Shared database handle from nullifier.c */
extern sqlite3 *nullifier_db;

/* Cached tip block height */
static uint64_t g_block_height = UINT64_MAX;  /* UINT64_MAX = no blocks */

/* v0.10.0: Get DB handle from zone user_data, falling back to global */
static inline sqlite3 *get_db(void *user_data) {
    if (user_data) {
        dnac_zone_t *zone = (dnac_zone_t *)user_data;
        if (zone->db) return zone->db;
    }
    return nullifier_db;
}

/* v0.10.0: Get block height pointer from zone or global */
static inline uint64_t *get_block_height(void *user_data) {
    if (user_data) {
        dnac_zone_t *zone = (dnac_zone_t *)user_data;
        return &zone->block_height;
    }
    return &g_block_height;
}

/* ============================================================================
 * Block Hash Computation
 * ========================================================================== */

/**
 * Hash input layout (250 bytes, all deterministic):
 *   height(8 LE) || prev_hash(64) || state_root(64) || tx_hash(64) ||
 *   tx_count(2 LE) || epoch(8 LE) || timestamp(8 LE) || proposer_id(32)
 */
#define BLOCK_HASH_INPUT_SIZE 250

int dnac_block_compute_hash(dnac_block_t *block) {
    if (!block) return -1;

    uint8_t input[BLOCK_HASH_INPUT_SIZE];
    size_t offset = 0;

    /* height — 8 bytes little-endian */
    for (int i = 0; i < 8; i++) {
        input[offset++] = (block->block_height >> (i * 8)) & 0xFF;
    }

    /* prev_block_hash — 64 bytes */
    memcpy(input + offset, block->prev_block_hash, 64);
    offset += 64;

    /* state_root — 64 bytes */
    memcpy(input + offset, block->state_root, 64);
    offset += 64;

    /* tx_hash — 64 bytes */
    memcpy(input + offset, block->tx_hash, 64);
    offset += 64;

    /* tx_count — 2 bytes little-endian */
    input[offset++] = block->tx_count & 0xFF;
    input[offset++] = (block->tx_count >> 8) & 0xFF;

    /* epoch — 8 bytes little-endian */
    for (int i = 0; i < 8; i++) {
        input[offset++] = (block->epoch >> (i * 8)) & 0xFF;
    }

    /* timestamp — 8 bytes little-endian */
    for (int i = 0; i < 8; i++) {
        input[offset++] = (block->timestamp >> (i * 8)) & 0xFF;
    }

    /* proposer_id — 32 bytes */
    memcpy(input + offset, block->proposer_id, 32);
    offset += 32;

    /* Verify size matches expected */
    if (offset != BLOCK_HASH_INPUT_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Block hash input size mismatch: %zu != %d",
                      offset, BLOCK_HASH_INPUT_SIZE);
        return -1;
    }

    qgp_sha3_512(input, BLOCK_HASH_INPUT_SIZE, block->block_hash);
    return 0;
}

int dnac_block_verify_link(const dnac_block_t *block, const dnac_block_t *prev) {
    if (!block) return -1;

    if (prev == NULL) {
        /* Genesis block: height must be 0, prev_hash must be all zeros */
        if (block->block_height != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Genesis block height must be 0, got %llu",
                          (unsigned long long)block->block_height);
            return -1;
        }
        uint8_t zeros[64] = {0};
        if (memcmp(block->prev_block_hash, zeros, 64) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Genesis block prev_hash must be all zeros");
            return -1;
        }
    } else {
        /* Non-genesis: check chain link */
        if (block->block_height != prev->block_height + 1) {
            QGP_LOG_ERROR(LOG_TAG, "Block height mismatch: %llu != %llu + 1",
                          (unsigned long long)block->block_height,
                          (unsigned long long)prev->block_height);
            return -1;
        }
        if (memcmp(block->prev_block_hash, prev->block_hash, 64) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Block prev_hash does not match previous block_hash");
            return -1;
        }
    }

    /* Verify block_hash is correct */
    dnac_block_t verify_copy = *block;
    memset(verify_copy.block_hash, 0, 64);
    if (dnac_block_compute_hash(&verify_copy) != 0) {
        return -1;
    }
    if (memcmp(verify_copy.block_hash, block->block_hash, 64) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Block hash verification failed");
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Block Storage (SQLite)
 * ========================================================================== */

int witness_block_init(void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db) return -1;

    uint64_t *height = get_block_height(user_data);

    /* Load tip height from DB */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "SELECT MAX(block_height) FROM blocks", -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to query block tip: %s",
                      sqlite3_errmsg(db));
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW && sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
        *height = (uint64_t)sqlite3_column_int64(stmt, 0);
        QGP_LOG_INFO(LOG_TAG, "Block chain loaded: tip height = %llu",
                     (unsigned long long)*height);
    } else {
        *height = UINT64_MAX;
        QGP_LOG_INFO(LOG_TAG, "Block chain empty (no blocks yet)");
    }

    sqlite3_finalize(stmt);
    return 0;
}

void witness_block_shutdown(void) {
    QGP_LOG_INFO(LOG_TAG, "Block storage shutdown (height=%llu)",
                 g_block_height == UINT64_MAX ? 0ULL : (unsigned long long)g_block_height);
}

int witness_block_add(const dnac_block_t *block, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !block) return -1;

    uint64_t *height = get_block_height(user_data);

    /* Verify chain continuity */
    if (*height == UINT64_MAX) {
        if (block->block_height != 0) {
            QGP_LOG_ERROR(LOG_TAG, "First block must be height 0, got %llu",
                          (unsigned long long)block->block_height);
            return -1;
        }
    } else {
        if (block->block_height != *height + 1) {
            QGP_LOG_ERROR(LOG_TAG, "Block height gap: expected %llu, got %llu",
                          (unsigned long long)(*height + 1),
                          (unsigned long long)block->block_height);
            return -1;
        }
    }

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO blocks "
        "(block_height, prev_block_hash, state_root, tx_hash, tx_count, "
        " epoch, timestamp, proposer_id, block_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare block insert: %s",
                      sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (int64_t)block->block_height);
    sqlite3_bind_blob(stmt, 2, block->prev_block_hash, 64, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, block->state_root, 64, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, block->tx_hash, 64, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, block->tx_count);
    sqlite3_bind_int64(stmt, 6, (int64_t)block->epoch);
    sqlite3_bind_int64(stmt, 7, (int64_t)block->timestamp);
    sqlite3_bind_blob(stmt, 8, block->proposer_id, 32, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 9, block->block_hash, 64, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to insert block %llu: %s",
                      (unsigned long long)block->block_height,
                      sqlite3_errmsg(db));
        return -1;
    }

    *height = block->block_height;

    QGP_LOG_INFO(LOG_TAG, "Block %llu stored (hash=%.8s...)",
                 (unsigned long long)block->block_height,
                 (const char *)block->block_hash);
    return 0;
}

/**
 * Helper: populate dnac_block_t from a SQLite row
 * Expected columns: block_height, prev_block_hash, state_root, tx_hash,
 *                   tx_count, epoch, timestamp, proposer_id, block_hash
 */
static int block_from_row(sqlite3_stmt *stmt, dnac_block_t *out) {
    memset(out, 0, sizeof(*out));

    out->block_height = (uint64_t)sqlite3_column_int64(stmt, 0);

    const void *prev = sqlite3_column_blob(stmt, 1);
    if (prev && sqlite3_column_bytes(stmt, 1) == 64) {
        memcpy(out->prev_block_hash, prev, 64);
    }

    const void *root = sqlite3_column_blob(stmt, 2);
    if (root && sqlite3_column_bytes(stmt, 2) == 64) {
        memcpy(out->state_root, root, 64);
    }

    const void *txh = sqlite3_column_blob(stmt, 3);
    if (txh && sqlite3_column_bytes(stmt, 3) == 64) {
        memcpy(out->tx_hash, txh, 64);
    }

    out->tx_count = (uint16_t)sqlite3_column_int(stmt, 4);
    out->epoch = (uint64_t)sqlite3_column_int64(stmt, 5);
    out->timestamp = (uint64_t)sqlite3_column_int64(stmt, 6);

    const void *prop = sqlite3_column_blob(stmt, 7);
    if (prop && sqlite3_column_bytes(stmt, 7) == 32) {
        memcpy(out->proposer_id, prop, 32);
    }

    const void *hash = sqlite3_column_blob(stmt, 8);
    if (hash && sqlite3_column_bytes(stmt, 8) == 64) {
        memcpy(out->block_hash, hash, 64);
    }

    return 0;
}

int witness_block_get(uint64_t height, dnac_block_t *out, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "SELECT block_height, prev_block_hash, state_root, tx_hash, "
        "       tx_count, epoch, timestamp, proposer_id, block_hash "
        "FROM blocks WHERE block_height = ?",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare block get: %s",
                      sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (int64_t)height);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    block_from_row(stmt, out);
    sqlite3_finalize(stmt);
    return 0;
}

int witness_block_get_latest(dnac_block_t *out, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !out) return -1;
    uint64_t *height = get_block_height(user_data);
    if (*height == UINT64_MAX) return -1;

    return witness_block_get(*height, out, user_data);
}

uint64_t witness_block_get_height(void *user_data) {
    return *get_block_height(user_data);
}

int witness_block_get_range(uint64_t from, uint64_t to,
                             dnac_block_t *out, int max, int *count, void *user_data) {
    sqlite3 *db = get_db(user_data);
    if (!db || !out || !count || max <= 0) return -1;

    *count = 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "SELECT block_height, prev_block_hash, state_root, tx_hash, "
        "       tx_count, epoch, timestamp, proposer_id, block_hash "
        "FROM blocks WHERE block_height >= ? AND block_height <= ? "
        "ORDER BY block_height LIMIT ?",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare block range query: %s",
                      sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (int64_t)from);
    sqlite3_bind_int64(stmt, 2, (int64_t)to);
    sqlite3_bind_int(stmt, 3, max);

    while (sqlite3_step(stmt) == SQLITE_ROW && *count < max) {
        block_from_row(stmt, &out[*count]);
        (*count)++;
    }

    sqlite3_finalize(stmt);
    return 0;
}
