/* exp_db — DNAC Explorer sqlite index DB module (index schema v2, the
 * version-3 chain).
 *
 * Derived-data store, rebuildable from the chain at any time. Schema v2
 * (design docs/plans/2026-09-28-scan-v3-design.md item 4):
 *   blocks       one row per committed height (the dnac_v3_block header)
 *   items        one row per block item — applied AND refused
 *   item_io      coins an applied item consumed (dir 0) / created (dir 1)
 *   item_records the SYSTEM record an applied item wrote (stake, delegate,
 *                unstake, undelegate, validator update, chain config)
 *   item_names   the chain name an applied NAME_REGISTER item registered
 *                (HF-4, dnac_v3_block optional keys "nm"/"pr"; design
 *                docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.7):
 *                name, price paid into the reward pool, and the owner — the
 *                resolved address of the item's first consumed coin (every
 *                input of a NAME_REGISTER is owned by its one signer, the
 *                name's owner: rtn_name_exec, nodus_witness_rt_native.c),
 *                NULL when that coin's creating item is not indexed
 *   meta         key/value (watermark, chain_id32 reference, tip, supply)
 *
 * item_names is created with CREATE TABLE IF NOT EXISTS on every open, so
 * an existing v2 index gains it without a rebuild (no name can exist
 * before the HF-4 switch height). An index advanced past that height by a
 * binary WITHOUT this table lacks those heights' names until it is rebuilt
 * (the design's rule: explorer decoders ship before the vote).
 *
 * Schema versioning: meta "schema_version" = EXP_DB_SCHEMA_VERSION, written
 * in the same transaction that creates the schema. exp_db_open on a file
 * whose schema_version is absent or different (the v1 ledger-sequence
 * index, or anything else) drops every explorer table and recreates the v2
 * schema — the index is rebuilt from height 1 by the next sync ticks.
 *
 * No local balance: the v1 `addr_stats` credit/debit accumulation is gone.
 * Block-boundary movements (reward payouts, stake graduation releases) are
 * not block items, so a balance replayed from items would be wrong (design
 * item 4). The address view carries item history only.
 *
 * Consumed coins (item_io dir 0) are resolved at write time against the
 * creating row (item_io dir 1, same coin_id): address/token/amount are
 * copied when the explorer indexed the creating item, NULL otherwise (a
 * coin created at a block boundary — not an item). Creation always
 * precedes consumption in chain order (lower height, or lower index in the
 * same block, written earlier in the same transaction), so the resolution
 * is a pure function of the indexed heights.
 *
 * Ownership / return-code conventions:
 *   - All functions return 0 on success, -1 on error or not-found, unless
 *     documented otherwise.
 *   - Cursor pagination is strict (`key < cursor`), DESC order; callers
 *     wanting the newest page pass UINT64_MAX (clamped to INT64_MAX before
 *     binding — sqlite binds signed 64-bit).
 *
 * Determinism (PRIMARY OBJECTIVE: DETERMINISM, index reproducibility — the
 * explorer is outside consensus): every multi-row query has an explicit
 * ORDER BY on a total key — blocks by height, items by (height, idx), io
 * rows by (dir, pos). Index content is a function of the queried heights
 * only.
 */
#ifndef EXP_DB_H
#define EXP_DB_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EXP_DB_SCHEMA_VERSION 2

typedef struct exp_db exp_db_t;

typedef struct {
    uint64_t height;
    uint8_t  block_id[64];       /* cometbft header hash (v2_blocks.block_id) */
    uint8_t  prev_id[64];
    uint64_t time_ms;            /* header time, ms since the Unix epoch */
    uint8_t  proposer[64];
    uint32_t proposer_len;       /* 1..64 (32 on this chain) */
    uint8_t  global_root[64];
    uint64_t applied_count;      /* applied envelopes, claims excluded */
    uint32_t n_items;            /* items the block carries, applied AND refused */
} exp_block_row_t;

/* SYSTEM record kinds — the node's NODUS_DNAC_V3_REC_* values
 * (nodus/include/nodus/nodus.h), stored as-is. */
typedef struct {
    int      kind;               /* 0 = none */
    char     validator[129];     /* "" when absent */
    char     delegator[129];
    char     dest[129];
    uint64_t amount;
    uint32_t commission_bps;
    uint32_t param_id;
    uint64_t new_value;
    uint64_t effective;
} exp_record_row_t;

typedef struct {
    uint64_t height;
    uint32_t idx;                /* item index in the block */
    int      kind;               /* NODUS_DNAC_V3_KIND_*: 1 envelope, 2 claim, 0 empty */
    uint32_t code;               /* 0 = applied, else refused */
    int      has_wire_id;
    uint8_t  wire_id[64];
    int      has_intent_id;
    uint8_t  intent_id[64];
    int      has_fee;
    uint64_t fee;
    char     op[25];             /* "" when unnamed */
    int      has_effects;        /* 1 = applied item with decoded effects */
    uint64_t burned;
    exp_record_row_t rec;        /* rec.kind 0 = no record */
    /* HF-4 NAME_REGISTER (applied items only): the registered name ("" =
     * not a registration), the price paid into the reward pool — never a
     * burn — and, read side only, the owner (the resolved address of the
     * first consumed coin; "" when not indexed). */
    char     name[37];
    uint64_t name_price;
    char     name_owner[129];
    uint64_t block_time_ms;      /* read side only: the block's header time */
} exp_item_row_t;

typedef struct {
    uint64_t height;
    uint32_t idx;
    int      dir;                /* 0 consumed, 1 created */
    uint32_t pos;                /* call order within (item, dir) */
    uint8_t  coin_id[64];
    int      has_owner;          /* created: 1; consumed: 1 iff resolved */
    char     address[129];       /* 128 lowercase hex + NUL */
    uint8_t  token_id[64];       /* all-zero = native */
    uint64_t amount;
    uint64_t unlock_block;       /* created only; 0 = unlocked */
} exp_io_row_t;

/* One whole height, as exp_extract builds it from the dnac_v3_block pages.
 * items[] is index-ascending (items[i].idx == i); ios[] holds every item's
 * rows grouped by item, consumed before created, each in call order.
 * Heap arrays — exp_block_batch_free releases them. */
typedef struct {
    int              have_header;
    exp_block_row_t  block;
    exp_item_row_t  *items;
    size_t           n_items;
    size_t           cap_items;
    exp_io_row_t    *ios;
    size_t           n_ios;
    size_t           cap_ios;
} exp_block_batch_t;

void exp_block_batch_init(exp_block_batch_t *b);
void exp_block_batch_free(exp_block_batch_t *b);

/* Opens (creating if needed) the index. A schema_version other than
 * EXP_DB_SCHEMA_VERSION drops every explorer table and recreates schema v2
 * (see the file header). */
int  exp_db_open(const char *path, exp_db_t **db_out);
void exp_db_close(exp_db_t *db);

/* Writes one whole height in ONE sqlite transaction: the block row, every
 * item, every record, every io row (consumed rows resolved against their
 * creating row), and meta "last_indexed_height" = b->block.height. The
 * watermark moves in the same transaction, so a height is either fully
 * indexed with its watermark or not at all.
 *
 * Refuses (-1, nothing written) when: the batch has no header; n_items
 * disagrees with block.n_items; items are not exactly 0..n-1; an io row
 * names an item outside the batch; or the height is not the next one
 * (last_indexed_height + 1, or 1 on an empty index) — heights are written
 * strictly in order, never skipped, never twice. */
int  exp_db_write_height(exp_db_t *db, const exp_block_batch_t *b);

int  exp_db_get_meta_u64(exp_db_t *db, const char *key, uint64_t *val_out); /* -1 not found */
int  exp_db_set_meta_u64(exp_db_t *db, const char *key, uint64_t val);
int  exp_db_get_meta_blob(exp_db_t *db, const char *key, uint8_t *buf, size_t buflen, size_t *len_out);
int  exp_db_set_meta_blob(exp_db_t *db, const char *key, const uint8_t *buf, size_t len);

/* `--verify-index`: a consistency check of the stored index (no network).
 * Checks: the blocks are exactly heights 1..last_indexed_height; every
 * block's item count equals its n_items and its applied envelope count
 * (kind 1, code 0) equals applied_count; every item has a block row; every
 * io row, record row and name row belongs to an applied item; no refused
 * item has effects; no chain name is registered twice. 0 = consistent,
 * -1 = inconsistent or query failure. */
int  exp_db_verify_index(exp_db_t *db);

/* ── read side ─────────────────────────────────────────────────────── */

int  exp_db_query_blocks(exp_db_t *db, uint64_t before_height, int limit,
                         exp_block_row_t *rows, int *count_out);
int  exp_db_query_block_by_height(exp_db_t *db, uint64_t height, exp_block_row_t *row_out);
int  exp_db_query_block_by_id(exp_db_t *db, const uint8_t block_id[64], exp_block_row_t *row_out);

/* Items of one height with idx >= from_idx, idx ascending, at most `max`. */
int  exp_db_query_items(exp_db_t *db, uint64_t height, uint32_t from_idx, int max,
                        exp_item_row_t *rows, int *count_out);
int  exp_db_query_item(exp_db_t *db, uint64_t height, uint32_t idx, exp_item_row_t *row_out);

/* The first item (lowest height, then idx) whose wire_id OR intent_id is
 * `id` — deterministic when an id recurs. */
int  exp_db_query_item_by_id(exp_db_t *db, const uint8_t id[64], exp_item_row_t *row_out);

/* An item's io rows, (dir, pos) ascending, at most `max`. */
int  exp_db_query_item_ios(exp_db_t *db, uint64_t height, uint32_t idx,
                           exp_io_row_t *rows, int max, int *count_out);

/* Items touching `fp` — as the owner of a created or (resolved) consumed
 * coin, or as a record's validator / delegator / destination — strictly
 * before the (before_height, before_idx) position, (height, idx)
 * descending, at most `limit`. Pass UINT64_MAX / UINT32_MAX for the newest
 * page. */
int  exp_db_query_address(exp_db_t *db, const char *fp,
                          uint64_t before_height, uint32_t before_idx, int limit,
                          exp_item_row_t *rows, int *count_out);

/* HF-4: the item that registered chain name `name` (exact, lower-case).
 * A name is registered once (first wins, permanent — the chain refuses a
 * second registration), so at most one applied item holds it; ORDER BY
 * keeps a (never expected) duplicate deterministic. 0 found, -1 not found
 * or error. */
int  exp_db_query_item_by_name(exp_db_t *db, const char *name, exp_item_row_t *row_out);

#ifdef __cplusplus
}
#endif

#endif /* EXP_DB_H */
