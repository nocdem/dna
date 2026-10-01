/**
 * Nodus — SQLite DHT Storage
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

/* ── Storage quotas ──────────────────────────────────────────────── */
#define NODUS_STORAGE_MAX_VALUES     100000
#define NODUS_STORAGE_MAX_BYTES      (500ULL * 1024 * 1024)  /* 500 MB */
#define NODUS_STORAGE_MAX_PER_OWNER  1000

/* Per-owner BYTE quota, enforced inside nodus_storage_put and
 * nodus_storage_put_if_newer: the sum of NODUS_STORAGE_ROW_CHARGE(data_len)
 * over every LIVE row the owner holds on this node.
 * Operator 2026-10-01: 16 MB per owner, counting per-row overhead. */
#define NODUS_STORAGE_OWNER_MAX_BYTES (16ULL * 1024 * 1024)  /* 16 MiB */

/* Fixed per-row overhead charged to the owner on top of data + owner_pk +
 * signature. Tally of what one nodus_values row costs besides those three:
 *   table record: key_hash 64 + owner_fp 64 + data_hash 32 + six INTEGER
 *     columns (value_id, type, ttl, created_at, expires_at, seq) <= 48,
 *     + record / cell headers ~20                                  ~ 228
 *   index entries (rowid table: indexed columns + rowid each):
 *     PRIMARY KEY autoindex (key_hash, owner_fp, value_id) ~ 150,
 *     idx_nodus_values_key ~ 75, idx_nodus_values_owner ~ 75,
 *     idx_nodus_values_expires (partial) <= 16                     ~ 316
 *   total ~ 544, rounded up to the next power of two (1024) to cover
 *   B-tree page fill slack. A zero-byte row is therefore never free. */
#define NODUS_STORAGE_ROW_FIXED_BYTES 1024
#define NODUS_STORAGE_ROW_CHARGE(data_len) \
    ((uint64_t)(data_len) + (uint64_t)NODUS_PK_BYTES + \
     (uint64_t)NODUS_SIG_BYTES + (uint64_t)NODUS_STORAGE_ROW_FIXED_BYTES)

/* Storage return codes beyond 0 / -1 (error) */
#define NODUS_STORAGE_RC_KEY_OWNED   (-2)  /* EXCLUSIVE key owned by another identity */
#define NODUS_STORAGE_RC_QUOTA       (-3)  /* a storage cap / quota / hint cap would be exceeded */
#define NODUS_STORAGE_RC_STALE       (-4)  /* seq lower than the stored row's */
#define NODUS_STORAGE_RC_FAULT       (-5)  /* read FAULT: SQLite error or allocation
                                            * failure — the store could not be
                                            * looked at; NOT "no row" */

/* DHT hinted handoff caps (operator 2026-10-01): per target node id 64 rows
 * and 16 MiB of frame bytes, 128 MiB of frame bytes over the whole table,
 * 24 h TTL. Over a cap the insert is refused; the table never grows past it.
 * Every row counts until nodus_storage_hinted_cleanup removes it (expired or
 * not), the same rows nodus_storage_hinted_get returns. The per-peer usage is
 * an indexed query (node_id); the whole-table byte total is a one-row table
 * kept by SQLite triggers on every insert / delete, read in O(1). */
#define NODUS_DHT_HINT_PEER_MAX_ROWS   64
#define NODUS_DHT_HINT_PEER_MAX_BYTES  (16ULL * 1024 * 1024)   /* 16 MiB */
#define NODUS_DHT_HINT_TOTAL_MAX_BYTES (128ULL * 1024 * 1024)  /* 128 MiB */
#define NODUS_DHT_HINT_TTL_SEC         (24 * 3600)              /* 24 h */

/* Serialized size estimate of one value — the exact buffer estimate of
 * nodus_value_serialize (core/nodus_value.c, "Conservative buffer size
 * estimate"). Page budgets (nodus_storage_get_all_page) are counted in this
 * unit; any code that truncates a merged page MUST use the same macro. */
#define NODUS_VALUE_SERIALIZED_EST(data_len) \
    ((size_t)256 + (size_t)(data_len) + NODUS_PK_BYTES + NODUS_SIG_BYTES + \
     (size_t)NODUS_KEY_BYTES * 2)

/** DHT hinted handoff entry (failed replication, pending retry) */
typedef struct {
    int64_t     id;
    nodus_key_t node_id;
    char        peer_ip[64];
    uint16_t    peer_port;
    uint8_t    *frame_data;
    size_t      frame_len;
    uint64_t    created_at;
    uint64_t    expires_at;
    int         retry_count;
} nodus_dht_hint_t;

/** DHT storage handle */
typedef struct {
    sqlite3 *db;
    sqlite3_stmt *stmt_put;
    sqlite3_stmt *stmt_get;
    sqlite3_stmt *stmt_get_all;
    sqlite3_stmt *stmt_delete;
    sqlite3_stmt *stmt_cleanup;
    sqlite3_stmt *stmt_count;
    sqlite3_stmt *stmt_put_if_newer;
    sqlite3_stmt *stmt_fetch_batch;
    /* Quota checks */
    sqlite3_stmt *stmt_quota_total_bytes;
    sqlite3_stmt *stmt_quota_owner_count;
    /* Live-row usage (count, data bytes) of one owner / of the whole table —
     * the write caps inside put / put_if_newer */
    sqlite3_stmt *stmt_quota_owner_usage;
    sqlite3_stmt *stmt_quota_global_usage;
    /* Existing row of one (key, owner, value_id): seq, data length, expires_at */
    sqlite3_stmt *stmt_existing_row;
    /* put_if_newer "would be skipped" pre-check (same predicate as the put) */
    sqlite3_stmt *stmt_newer_exists;
    /* Owner-scoped and paged reads */
    sqlite3_stmt *stmt_get_owner;
    sqlite3_stmt *stmt_get_all_page;
    /* EXCLUSIVE ownership check */
    sqlite3_stmt *stmt_exclusive_owner;
    /* Hinted handoff for DHT replication */
    sqlite3_stmt *stmt_hint_insert;
    sqlite3_stmt *stmt_hint_get;
    sqlite3_stmt *stmt_hint_delete;
    sqlite3_stmt *stmt_hint_cleanup;
    sqlite3_stmt *stmt_hint_count;
    sqlite3_stmt *stmt_hint_peer_usage;
    sqlite3_stmt *stmt_hint_total_bytes;
    sqlite3_stmt *stmt_hint_exists;
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
 * EXCLUSIVE values enforce first-writer-owns: if the key already has an
 * EXCLUSIVE value from a different owner, the PUT is rejected.
 *
 * Checks, in this order: signature, EXCLUSIVE owner (-2), stale seq (-4:
 * the stored row for the same key, owner and value_id has a STRICTLY higher
 * seq — live or expired; equal or higher seq replaces as before), then the
 * write caps (-3), growth-only:
 *   - a replace of a LIVE stored row of the same (key, owner, value_id)
 *     whose data does not grow is never refused by any cap;
 *   - a NEW row (none stored, or the stored one is expired) is checked
 *     against the owner row cap NODUS_STORAGE_MAX_PER_OWNER and the global
 *     row cap NODUS_STORAGE_MAX_VALUES, and its full charge against the
 *     byte caps;
 *   - a GROWING replace is checked against the byte caps for the growth.
 * Byte caps: per owner NODUS_STORAGE_OWNER_MAX_BYTES over
 * NODUS_STORAGE_ROW_CHARGE(data_len) (data + owner_pk + signature + fixed
 * overhead per row); global NODUS_STORAGE_MAX_BYTES over data bytes only
 * (the unit nodus_storage_check_quota uses). Every cap counts LIVE rows
 * only: a row is expired exactly when nodus_storage_cleanup would delete it
 * (expires_at > 0 AND expires_at <= now); the clock is this node's, the
 * check is node-local storage admission, not consensus.
 * seq is compared as SQLite INTEGER (signed int64), as in put_if_newer.
 *
 * @param store   Storage handle
 * @param val     Value to store (must be signed)
 * @return 0 on success, -1 on error, -2 if EXCLUSIVE key owned by another
 *         identity, -3 if a cap or quota would be exceeded, -4 if stale
 */
int nodus_storage_put(nodus_storage_t *store, const nodus_value_t *val);

/**
 * Get the best value for a key (highest seq, single result).
 *
 * @param store     Storage handle
 * @param key_hash  Key to look up
 * @param val_out   Output value (caller must free with nodus_value_free)
 * @return 0 on success, -1 if not found (or invalid arguments),
 *         NODUS_STORAGE_RC_FAULT (-5) on a SQLite error or allocation
 *         failure. Every non-zero is still "no value" to a caller that only
 *         tests for 0.
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
 * Get one owner's newest value at a key: highest seq, then highest
 * data_hash (SHA3-256 of data; legacy NULL hashes rank lowest), then lowest
 * value_id — a total order, so every node holding the same rows answers
 * with the same row.
 *
 * @param store     Storage handle
 * @param key_hash  Key to look up
 * @param owner_fp  Owner fingerprint
 * @param val_out   Output value (caller must free with nodus_value_free);
 *                  NULL unless 0 is returned
 * @return 0 on success, -1 if the owner has no row at the key (or invalid
 *         arguments), NODUS_STORAGE_RC_FAULT (-5) on a SQLite error or
 *         allocation failure — "could not look", distinct from "no row"
 */
int nodus_storage_get_owner(nodus_storage_t *store,
                            const nodus_key_t *key_hash,
                            const nodus_key_t *owner_fp,
                            nodus_value_t **val_out);

/**
 * Get one page of the values at a key in primary-key order.
 *
 * ORDER: owner_fp ASC (bytewise), then value_id ASC — value_id ordered and
 * compared AS SQLITE INTEGER (SIGNED INT64), the PRIMARY KEY order. A C-side
 * comparator that merges pages from several nodes MUST compare
 * (int64_t)value_id, never uint64_t, or pages interleave differently.
 *
 * Rows strictly after the cursor (after_owner, after_vid) when after_owner is
 * non-NULL; only owner_fp's rows when owner_fp is non-NULL. Rows are added
 * while the cumulative NODUS_VALUE_SERIALIZED_EST(data_len) stays
 * <= budget_bytes; the first row is always returned even if it alone is
 * larger. With ~7.5 KB fixed cost per row the budget also bounds the row
 * count (2 MiB -> ~270 rows); no separate row cap.
 *
 * @param store        Storage handle
 * @param key_hash     Key
 * @param owner_fp     Owner filter, or NULL for every owner
 * @param after_owner  Cursor owner_fp, or NULL to start at the first row
 * @param after_vid    Cursor value_id (used only when after_owner is set)
 * @param budget_bytes Serialized byte budget for the page
 * @param vals_out     Output array (caller frees each + array); NULL if empty
 * @param count_out    Number of values in the page
 * @param more_out     1 if rows remain after the page, else 0
 * @return 0 on success — INCLUDING an empty page (count 0, more 0);
 *         -1 on invalid arguments; NODUS_STORAGE_RC_FAULT (-5) on a SQLite
 *         error or allocation failure ("could not look"). Never -1 for
 *         "no rows" (differs from get_all's -1-on-none). On any non-zero
 *         return *vals_out is NULL, *count_out 0, *more_out 0.
 */
int nodus_storage_get_all_page(nodus_storage_t *store,
                               const nodus_key_t *key_hash,
                               const nodus_key_t *owner_fp,
                               const nodus_key_t *after_owner,
                               uint64_t after_vid,
                               size_t budget_bytes,
                               nodus_value_t ***vals_out,
                               size_t *count_out,
                               int *more_out);

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

/**
 * Store a value only if it has a higher seq than existing.
 * On equal seq, tiebreak by SHA3-256(data) — higher hash wins.
 * Atomic single-SQL operation (no TOCTOU race).
 * A value that would be stored is first checked against the per-owner caps
 * with the same growth-only rule and the same accounting as
 * nodus_storage_put: owner row cap NODUS_STORAGE_MAX_PER_OWNER for a new
 * row, owner byte quota NODUS_STORAGE_OWNER_MAX_BYTES over
 * NODUS_STORAGE_ROW_CHARGE for the growth, live rows only. The global caps
 * (NODUS_STORAGE_MAX_VALUES / NODUS_STORAGE_MAX_BYTES) are NOT applied here.
 * A value that would be skipped returns 1 without a cap check.
 *
 * @return 0 = stored, 1 = skipped (existing is newer/equal), -1 = error,
 *         -2 = EXCLUSIVE key owned by another identity, -3 = owner cap
 */
int nodus_storage_put_if_newer(nodus_storage_t *store, const nodus_value_t *val);

/**
 * Fetch a batch of values for republish (bookmark pagination).
 * Returns values with key_hash > after_key, ordered by key_hash, up to batch_size.
 * Pass NULL for after_key to start from the beginning.
 * Finalizes statement immediately (no held cursor — safe for WAL).
 *
 * Bookmark uses composite (key_hash, owner_fp, value_id) to avoid skipping
 * rows with the same key_hash across batch boundaries — PRIMARY KEY of
 * nodus_values is composite, and bookmarking only on key_hash drops the
 * remaining tied rows on the next batch.
 *
 * @param store      Storage handle
 * @param after_key  Bookmark key_hash, or NULL for first batch
 * @param after_owner Bookmark owner_fp (used only when after_key set)
 * @param after_vid  Bookmark value_id (used only when after_key set)
 * @param batch_out  Output array (must hold batch_size entries, caller frees each)
 * @param batch_size Maximum values to fetch
 * @return Number of values fetched (< batch_size means end of data)
 */
int nodus_storage_fetch_batch(nodus_storage_t *store,
                               const nodus_key_t *after_key,
                               const nodus_key_t *after_owner,
                               uint64_t after_vid,
                               nodus_value_t **batch_out,
                               int batch_size);

/**
 * Check storage quotas before a PUT.
 * Checks: global count, global bytes, per-owner count — over EVERY row,
 * expired or not, and with no notion of a replace: an owner at the row cap
 * is refused even for a non-growing replace. nodus_storage_put applies the
 * same caps itself with the growth-only rule; this pre-check is kept for
 * callers that want the old, stricter answer.
 *
 * @param store     Storage handle
 * @param owner_fp  Owner fingerprint (for per-owner check)
 * @return 0 = OK (within quota), -1 = quota exceeded
 */
int nodus_storage_check_quota(nodus_storage_t *store,
                               const nodus_key_t *owner_fp);

/**
 * Count values for a specific key (all owners).
 *
 * @param store     Storage handle
 * @param key_hash  Key to count
 * @return count >= 0 on success, -1 on error
 */
int nodus_storage_count_key(nodus_storage_t *store,
                             const nodus_key_t *key_hash);

/**
 * Check if a specific owner has a value for a key.
 *
 * @param store     Storage handle
 * @param key_hash  Key to check
 * @param owner_fp  Owner fingerprint
 * @return 1 if owner has value, 0 if not, -1 on error
 */
int nodus_storage_has_owner(nodus_storage_t *store,
                             const nodus_key_t *key_hash,
                             const nodus_key_t *owner_fp);

/* ── DHT Hinted Handoff ─────────────────────────────────────────── */

/**
 * Insert a hinted handoff entry (failed DHT replication).
 * TTL: NODUS_DHT_HINT_TTL_SEC (24 h). Capped per node_id at
 * NODUS_DHT_HINT_PEER_MAX_ROWS rows and NODUS_DHT_HINT_PEER_MAX_BYTES frame
 * bytes, and at NODUS_DHT_HINT_TOTAL_MAX_BYTES over the whole table.
 * A duplicate (node_id, frame) is ignored and returns 0.
 * The per-peer caps are checked first (indexed by node_id) and refuse
 * before the whole-table total is read.
 *
 * @return 0 = queued (or duplicate), -1 = error, NODUS_STORAGE_RC_QUOTA (-3)
 *         = a cap would be exceeded (refused, logged, nothing stored)
 */
int nodus_storage_hinted_insert(nodus_storage_t *store,
                                 const nodus_key_t *node_id,
                                 const char *peer_ip, uint16_t peer_port,
                                 const uint8_t *frame_data, size_t frame_len);

/**
 * Get pending hints for a node (up to limit), oldest first. The result also
 * stops before its frame bytes would exceed NODUS_DHT_HINT_PEER_MAX_BYTES
 * (the first entry is always returned).
 * Caller must free entries with nodus_storage_hinted_free().
 */
int nodus_storage_hinted_get(nodus_storage_t *store,
                              const nodus_key_t *node_id,
                              int limit,
                              nodus_dht_hint_t **entries_out,
                              size_t *count_out);

/** Delete a hint by ID (on successful delivery). */
int nodus_storage_hinted_delete(nodus_storage_t *store, int64_t id);

/** Increment retry_count for a hint. Returns new retry_count, or -1 on error. */
int nodus_storage_hinted_bump_retry(nodus_storage_t *store, int64_t id);

/** Delete expired hinted handoff entries. Returns count deleted. */
int nodus_storage_hinted_cleanup(nodus_storage_t *store);

/** Get count of pending hints. */
int nodus_storage_hinted_count(nodus_storage_t *store);

/** Free hint entries returned by hinted_get. */
void nodus_storage_hinted_free(nodus_dht_hint_t *entries, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_STORAGE_H */
