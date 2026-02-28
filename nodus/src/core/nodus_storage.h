/**
 * Nodus v5 — SQLite DHT Storage
 *
 * Persistent storage for DHT values with TTL cleanup.
 * Schema matches the design doc's nodus_values table.
 *
 * @file nodus_storage.h
 */

#ifndef NODUS_STORAGE_H
#define NODUS_STORAGE_H

#include "nodus/nodus_types.h"
#include "core/nodus_value.h"
#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

/** DHT storage handle */
typedef struct {
    sqlite3 *db;
    sqlite3_stmt *stmt_put;
    sqlite3_stmt *stmt_get;
    sqlite3_stmt *stmt_get_all;
    sqlite3_stmt *stmt_delete;
    sqlite3_stmt *stmt_cleanup;
    sqlite3_stmt *stmt_count;
} nodus_storage_t;

/**
 * Open (or create) DHT storage database.
 *
 * @param path     SQLite database file path
 * @param store    Output storage handle
 * @return 0 on success, -1 on error
 */
int nodus_storage_open(const char *path, nodus_storage_t *store);

/**
 * Close storage and free resources.
 */
void nodus_storage_close(nodus_storage_t *store);

/**
 * Store a value (INSERT OR REPLACE based on key_hash + owner_fp + value_id).
 * Conflict resolution: highest seq wins.
 *
 * @param store   Storage handle
 * @param val     Value to store (must be signed)
 * @return 0 on success, -1 on error
 */
int nodus_storage_put(nodus_storage_t *store, const nodus_value_t *val);

/**
 * Get the best value for a key (highest seq, single result).
 *
 * @param store     Storage handle
 * @param key_hash  Key to look up
 * @param val_out   Output value (caller must free with nodus_value_free)
 * @return 0 on success, -1 if not found or error
 */
int nodus_storage_get(nodus_storage_t *store,
                      const nodus_key_t *key_hash,
                      nodus_value_t **val_out);

/**
 * Get all values for a key (multi-writer).
 *
 * @param store      Storage handle
 * @param key_hash   Key to look up
 * @param vals_out   Output array of values (caller must free each + array)
 * @param count_out  Number of values
 * @return 0 on success, -1 on error
 */
int nodus_storage_get_all(nodus_storage_t *store,
                          const nodus_key_t *key_hash,
                          nodus_value_t ***vals_out,
                          size_t *count_out);

/**
 * Delete a specific value.
 *
 * @param store     Storage handle
 * @param key_hash  Key
 * @param owner_fp  Owner fingerprint
 * @param value_id  Value ID
 * @return 0 on success, -1 on error
 */
int nodus_storage_delete(nodus_storage_t *store,
                         const nodus_key_t *key_hash,
                         const nodus_key_t *owner_fp,
                         uint64_t value_id);

/**
 * Clean up expired EPHEMERAL values.
 *
 * @param store  Storage handle
 * @return Number of values cleaned, or -1 on error
 */
int nodus_storage_cleanup(nodus_storage_t *store);

/**
 * Get total number of stored values.
 */
int nodus_storage_count(nodus_storage_t *store);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_STORAGE_H */
