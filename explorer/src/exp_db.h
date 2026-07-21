/* exp_db — DNAC Explorer sqlite index DB module.
 *
 * Derived-data store (rebuildable from the chain). Schema per
 * docs/plans/2026-07-21-dnac-explorer-design.md §3:
 *   blocks / txs / tx_io / addr_stats / meta
 * `txs.multi_signer` and `txs.raw` are additions on top of the design-doc
 * schema per docs/plans/2026-07-21-dnac-explorer-plan.md Task 2.
 *
 * Ownership / return-code conventions:
 *   - All functions return 0 on success, -1 on error or not-found, unless
 *     documented otherwise.
 *   - `exp_db_query_tx`'s `raw_out` is malloc'd; caller frees. Passing
 *     `raw_out == NULL` skips fetching/copying the raw blob (list/summary
 *     callers that don't need it).
 *   - Cursor pagination (`exp_db_query_blocks` `before_height`,
 *     `exp_db_query_address` `before_seq`): rows returned always satisfy
 *     `key < cursor` (strict), DESC order. Genesis is height 0
 *     (`dnac/include/dnac/block.h`), so 0 is NOT usable as an "unbounded"
 *     sentinel — a walk that reaches genesis and re-queries with cursor=0
 *     must legitimately get zero rows back, not wrap to the top. Callers
 *     wanting the most recent page pass `INT64_MAX` (or any value above
 *     the current tip, but at most `INT64_MAX`) as the first cursor, then
 *     page by passing the smallest key seen in the previous page as the
 *     next cursor. Cursor values are bound to sqlite as signed 64-bit
 *     (`sqlite3_bind_int64`); heights/seqs are always non-negative and
 *     far below 2^63 in practice, but a caller-supplied cursor at or above
 *     2^63 (e.g. `UINT64_MAX`) wraps to negative and silently matches
 *     nothing — stay at or below `INT64_MAX`.
 *
 * Determinism (PRIMARY OBJECTIVE: DETERMINISM): every multi-row query below
 * has an explicit ORDER BY on a total key (height/seq, tie-broken where
 * rows can't collide on the ordering key by table PRIMARY KEY structure).
 * `exp_db_verify_addr_stats` (D3) recomputes addr_stats from tx_io+txs
 * using the same credit/debit derivation the incremental path uses, and
 * diffs both directions — the two paths are derivations of one rule, not
 * two independent implementations that happen to agree.
 */
#ifndef EXP_DB_H
#define EXP_DB_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct exp_db exp_db_t;

typedef struct {
    uint64_t height;
    uint8_t  block_hash[64];   /* filled by exp_db_set_block_hash from the child's prev_hash */
    int      has_block_hash;   /* 0 = block_hash unset (tip, child not seen yet) */
    uint8_t  tx_root[64];
    uint64_t timestamp;
    uint8_t  proposer[32];
    uint32_t tx_count;
} exp_block_row_t;

typedef struct {
    uint8_t  hash[64];
    uint64_t seq;               /* ledger sequence — total order */
    uint64_t height;
    int      tx_type;
    uint64_t fee;
    uint32_t size;
    uint64_t timestamp;         /* from the deserialized TX, never envelope wall-clock */
    int      multi_signer;      /* 0/1 */
} exp_tx_row_t;

typedef struct {
    uint8_t  tx_hash[64];
    int      io_index;
    int      direction;         /* 0=in 1=out */
    char     address[129];      /* 128-hex fingerprint + NUL */
    uint8_t  token_id[64];
    uint64_t amount;
} exp_io_row_t;

int  exp_db_open(const char *path, exp_db_t **db_out);      /* creates schema */
void exp_db_close(exp_db_t *db);

int  exp_db_insert_block(exp_db_t *db, const exp_block_row_t *b);
int  exp_db_set_block_hash(exp_db_t *db, uint64_t height, const uint8_t hash[64]);

/* One sqlite transaction. Duplicate tx (txs.hash already present) is a
 * no-op: io rows and addr_stats are not touched, return 0.
 * `raw`/`raw_len` are the exact wire bytes stored in txs.raw; `tx->size`
 * is bound as given (caller's responsibility that it matches raw_len). */
int  exp_db_insert_tx(exp_db_t *db, const exp_tx_row_t *tx,
                      const uint8_t *raw, size_t raw_len,
                      const exp_io_row_t *ios, int io_count);

int  exp_db_get_meta_u64(exp_db_t *db, const char *key, uint64_t *val_out); /* -1 not found */
int  exp_db_set_meta_u64(exp_db_t *db, const char *key, uint64_t val);
int  exp_db_get_meta_blob(exp_db_t *db, const char *key, uint8_t *buf, size_t buflen, size_t *len_out);
int  exp_db_set_meta_blob(exp_db_t *db, const char *key, const uint8_t *buf, size_t len);

int  exp_db_verify_addr_stats(exp_db_t *db);   /* D3: recompute from tx_io, diff; 0 = identical */

/* read side (Task 6) */
int  exp_db_query_blocks(exp_db_t *db, uint64_t before_height, int limit, exp_block_row_t *rows, int *count_out);
int  exp_db_query_block_by_height(exp_db_t *db, uint64_t height, exp_block_row_t *row_out);
int  exp_db_query_block_by_hash(exp_db_t *db, const uint8_t hash[64], exp_block_row_t *row_out);
int  exp_db_query_txs_by_height(exp_db_t *db, uint64_t height, exp_tx_row_t *rows, int max, int *count_out);
int  exp_db_query_tx(exp_db_t *db, const uint8_t hash[64], exp_tx_row_t *tx_out,
                     exp_io_row_t *ios, int max_ios, int *io_count_out, uint8_t **raw_out, size_t *raw_len_out);
int  exp_db_query_address(exp_db_t *db, const char *fp, uint64_t before_seq, int limit,
                          exp_tx_row_t *rows, int *count_out);
int  exp_db_query_balance(exp_db_t *db, const char *fp, const uint8_t token_id[64], uint64_t *balance_out, uint64_t *txc_out);

#ifdef __cplusplus
}
#endif

#endif /* EXP_DB_H */
