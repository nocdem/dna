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
 *   item_evm     Nodus EVM: the EVM facts of an applied EVM item (dnac_v3_block
 *                optional keys "ev"/"ri"/"ro"): status, gas, sender,
 *                target / created / value, recipient, log count, opened
 *                tickets (<= 32 + a "more" flag), wei destroyed, receipt
 *                digest, the CORE EVM reserve move
 *   meta         key/value (watermark, chain_id32 reference, tip, supply)
 *
 * item_evm follows the item_names rule: CREATE TABLE IF NOT EXISTS on
 * every open, no schema bump. An index advanced past the EVM activation
 * height by a binary WITHOUT it lacks those items' EVM rows until it is
 * rebuilt (delete the index file; the next start re-indexes from 1).
 *
 * item_names is created with CREATE TABLE IF NOT EXISTS on every open, so
 * an existing v2 index gains it without a rebuild (no name can exist
 * before the HF-4 switch height). An index advanced past that height by a
 * binary WITHOUT this table lacks those heights' names until it is rebuilt
 * (the design's rule: explorer decoders ship before the vote).
 *
 * idx_blocks_time (blocks(time_ms, applied_count), /api/tps) is likewise
 * created IF NOT EXISTS on every open: an existing v2 index gains it on
 * the first open of a binary that has it, built from the stored rows.
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
 * ORDER BY on a total key — blocks by height, items (and the record list
 * of exp_db_query_records_by_kind) by (height, idx), io rows by (dir, pos). Index content is a function of the queried heights
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

/* Nodus EVM P4-C: the EVM facts of one APPLIED EVM item (dnac_v3_block "ev",
 * "ri", "ro" — nodus/include/nodus/nodus.h), stored in item_evm. Every
 * field is the node's answer copied as-is: the node read it from its
 * stored receipt (evm_receipts) and the decoded call; nothing is derived
 * here. Byte strings are big-endian as on the wire. */
#define EXP_EVM_MAX_TICKETS 32   /* == NODUS_DNAC_V3_EVM_MAX_TICKETS (checked in exp_extract.c) */

typedef struct {
    uint64_t height;
    uint32_t idx;
    int      status;             /* 1 success, 0 failed (a paid failure) */
    uint64_t gas_used;           /* EVM gas, not ledger units */
    uint8_t  sender[32];
    int      has_target;         /* CALL */
    uint8_t  target[32];
    int      has_created;        /* successful CREATE */
    uint8_t  created[32];
    int      has_value;          /* CALL / CREATE */
    uint8_t  value_wei[32];
    char     dest[129];          /* WITHDRAW / REDEEM recipient fp; "" = none */
    uint32_t n_logs;
    uint32_t n_tickets;          /* <= EXP_EVM_MAX_TICKETS */
    int      tickets_more;       /* the receipt holds more than n_tickets */
    uint8_t  tickets[EXP_EVM_MAX_TICKETS][64];
    uint8_t  wei_destroyed[32];
    uint8_t  digest[64];         /* the receipt digest = ExecTxResult.Data */
    uint64_t reserve_in;         /* raw units into the CORE EVM reserve (DEPOSIT) */
    uint64_t reserve_out;        /* raw units out of it (WITHDRAW / REDEEM) */
} exp_evm_row_t;

/* One whole height, as exp_extract builds it from the dnac_v3_block pages.
 * items[] is index-ascending (items[i].idx == i); ios[] holds every item's
 * rows grouped by item, consumed before created, each in call order;
 * evms[] (Nodus EVM) one row per applied EVM item, idx strictly ascending.
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
    exp_evm_row_t   *evms;
    size_t           n_evms;
    size_t           cap_evms;
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
 * io row, record row, name row and EVM row belongs to an applied item; no
 * refused item has effects; no chain name is registered twice. 0 = consistent,
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

/* The items that wrote a SYSTEM record of kind `rec_kind` (the node's
 * NODUS_DNAC_V3_REC_* value — /api/governance asks for CHAIN_CONFIG),
 * (height, idx) ascending, at most `max`. Only applied items carry a
 * record (exp_db_verify_index), so every row is an applied item. */
int  exp_db_query_records_by_kind(exp_db_t *db, int rec_kind, int max,
                                  exp_item_row_t *rows, int *count_out);

/* ── Nodus EVM (item_evm) ───────────────────────────────────────────────── */

/* The EVM row of item (height, idx). @return 1 found (*out filled), 0 the
 * item has none, -1 query failure. */
int  exp_db_query_item_evm(exp_db_t *db, uint64_t height, uint32_t idx,
                           exp_evm_row_t *out);

/* Items whose EVM row names the 32-byte address `addr` as sender, CALL
 * target or created contract, strictly before (before_height,
 * before_idx), (height, idx) descending, at most `limit` — the
 * exp_db_query_address cursor contract. */
int  exp_db_query_evm_address(exp_db_t *db, const uint8_t addr[32],
                              uint64_t before_height, uint32_t before_idx,
                              int limit, exp_item_row_t *rows, int *count_out);

/* The item that CREATED contract `addr` (a successful CREATE; lowest
 * (height, idx) if the index ever held two). @return 1 found, 0 none,
 * -1 query failure. */
int  exp_db_query_evm_creation(exp_db_t *db, const uint8_t addr[32],
                               exp_item_row_t *out);

/* ── throughput (/api/tps) ─────────────────────────────────────────── */

#define EXP_TPS_HOUR_MS       3600000ULL
#define EXP_TPS_HISTORY_HOURS 24

/* Applied transactions (blocks.applied_count) and blocks in a span of
 * block time. */
typedef struct {
    uint64_t tx;
    uint64_t blocks;
} exp_tps_count_t;

/* One hourly history bucket: block times in [start_ms, start_ms + 1 h).
 * seconds = 3600, except the newest bucket (the hour in progress at
 * now_ms): ceil((now_ms - start_ms) / 1000), at least 1. */
typedef struct {
    uint64_t        start_ms;   /* UTC-aligned: start_ms % EXP_TPS_HOUR_MS == 0 */
    uint64_t        seconds;
    exp_tps_count_t count;
} exp_tps_bucket_t;

/* Payday cadence: rewards are paid at a block whose height is a multiple
 * of DNAC_EPOCH_LENGTH (720) × payout_interval_epochs (24) = 17280 —
 * nodus/src/witness/nodus_witness_v2_econ.c nodus_witness_v2_payday_apply
 * (boundary_height % E == 0 and (boundary_height / E) % interval == 0) and
 * the live chain's genesis payout_interval_epochs = 24
 * (nodus/tools/genesis/testnet_v3.conf.template). A named constant here:
 * the explorer displays an estimate, it does not read the genesis. */
#define EXP_PAYDAY_INTERVAL_BLOCKS 17280ULL
/* The epoch length the above is built from: DNAC_EPOCH_LENGTH (720,
 * dnac/include/dnac/dnac.h) — the APY estimate's blocks per epoch. */
#define EXP_EPOCH_BLOCKS 720ULL

/* The next payday estimate. avg_block_ms = the mean block interval over the
 * last hour's indexed blocks — (newest time − oldest time) / (count − 1),
 * floored — or, when that hour holds fewer than 2 blocks, over the last 100
 * indexed heights. est_ms = now_ms + blocks_left × avg_block_ms. */
typedef struct {
    uint64_t height;          /* the smallest multiple of 17280 > the newest indexed height */
    uint64_t blocks_left;     /* height − the newest indexed height */
    int      have_pace;       /* 0: fewer than 2 blocks indexed (or est_ms would overflow) */
    uint64_t avg_block_ms;
    uint64_t est_ms;
} exp_payday_t;

/* The smallest multiple of EXP_PAYDAY_INTERVAL_BLOCKS strictly greater
 * than `height`. */
uint64_t exp_next_payday_height(uint64_t height);

/* A past payday: an indexed block whose height is a multiple of
 * EXP_PAYDAY_INTERVAL_BLOCKS (the payout runs in that block's epoch
 * boundary — nodus_witness_v2_epoch.h step 1c), and its block time. No
 * amount in this index-only /api/tps view: payouts are boundary rows, not
 * block items. The optional exp_rewards source supplies actual amounts
 * through /api/paydays; owner-gated dnac_addr_history stays unchanged. */
typedef struct {
    uint64_t height;
    uint64_t time_ms;
} exp_payday_row_t;

/* Past paydays one reply lists at most, newest first. */
#define EXP_TPS_PAYDAYS_MAX 100

typedef struct {
    int              have;        /* 0 = empty index: nothing below is set */
    uint64_t         now_ms;      /* the time of the newest indexed block (highest height) */
    uint64_t         newest_height;
    exp_payday_t     payday;
    exp_payday_row_t paydays[EXP_TPS_PAYDAYS_MAX];  /* newest first */
    int              n_paydays;
    /* the mean block interval over the last 24 h of block time,
     * (now_ms − 24 h, now_ms] — (newest − oldest) / (count − 1), floored;
     * have_day_pace 0 below 2 blocks (the APY estimate's pace) */
    uint64_t         day_blocks;
    int              have_day_pace;
    uint64_t         day_avg_block_ms;
    exp_tps_count_t  last_minute; /* block times in (now_ms - 60 s, now_ms] */
    exp_tps_count_t  last_hour;   /* block times in (now_ms - 1 h, now_ms] */
    exp_tps_bucket_t history[EXP_TPS_HISTORY_HOURS]; /* oldest first */
    int              n_history;   /* 24; fewer only when now_ms is within 23 h of the Unix epoch */
} exp_tps_t;

/* Throughput figures and the next payday estimate, every one a function of
 * the index alone: "now" is
 * the newest indexed block's time, never the explorer's clock, and every
 * span is bounded above by it. History = the hour containing now_ms and
 * the 23 before it, oldest first, an hour with no block a zero bucket.
 * Bounded cost: each span is a range scan of the covering index
 * idx_blocks_time (time_ms, applied_count) over at most 24 h of blocks;
 * the payday pace fallback reads at most 100 heights by primary key.
 * 0 on success (out->have 0 on an empty index), -1 on a query failure. */
int  exp_db_query_tps(exp_db_t *db, exp_tps_t *out);

#ifdef __cplusplus
}
#endif

#endif /* EXP_DB_H */
