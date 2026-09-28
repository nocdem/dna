/* exp_sync — DNAC Explorer height sync loop (version-3 chain).
 *
 * One poll per exp_sync_tick() call (design
 * docs/plans/2026-09-28-scan-v3-design.md item 4):
 *   1. src->tip -> chain_id32 + committed tip height (+ supply figures),
 *      fed into the F4 chain-reset FSM (exp_chain.h). A confirmed reset
 *      archives the current index db aside and starts a fresh one.
 *   2. Walk heights last_indexed_height+1 .. tip (at most
 *      EXP_SYNC_MAX_HEIGHTS_PER_TICK per tick). Per height: every
 *      dnac_v3_block page is fetched (exp_sync_collect_block), then the
 *      block + its items + their io rows + records + the watermark are
 *      written in ONE sqlite transaction (exp_db_write_height).
 *
 * Watermark discipline: meta "last_indexed_height" moves only inside the
 * transaction that writes that whole height. A failure anywhere in a
 * height (a page fetch, a page that does not continue the block, the
 * write) leaves the watermark where it was and ends the tick with -1; the
 * next tick retries that same height from its first page. Heights are
 * written strictly in order — never skipped.
 *
 * Binding FSM-integration rules (G3 / former G6):
 *   1. On startup, preseed the FSM's ref_chain_id from db meta
 *      ("chain_id32" blob) IF present and non-zero; if absent, adopt the
 *      first tip observation's chain_id32 into BOTH db meta and the FSM
 *      ONLY if it is non-zero (exp_sync_preseed + exp_sync_tick's
 *      first-adoption path). The key is new with index schema v2 — a v1
 *      index's legacy "chain_id" can never preseed it (the schema rebuild
 *      drops v1 meta anyway).
 *   2. NEVER adopt an all-zero chain_id32 as reference — skip + log error
 *      + rotate.
 *   3. One FSM feed per server per poll cycle; after a PENDING result the
 *      tick rotates so the NEXT tick's observation lands on a different
 *      server. Nothing is indexed on a PENDING tick.
 *   4. On CONFIRMED: rename the db file aside to
 *      "<db>.stale-<hex8(new chain_id32)>" (exp_sync_stale_name), reopen a
 *      fresh db at the original path, and re-preseed the FSM + db meta with
 *      the confirmed candidate. The tick returns after handling the reset;
 *      the re-sync from height 1 happens on the next ticks.
 */
#ifndef EXP_SYNC_H
#define EXP_SYNC_H

#include <stddef.h>
#include <stdint.h>

#include <pthread.h>

#include "exp_chain.h"
#include "exp_db.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EXP_SYNC_POLL_SECONDS 30

/* Heights one tick indexes at most; a tick that stops at this bound
 * returns 1 and the sync thread starts the next tick without the poll
 * sleep (a fresh index catches up continuously, and the stop flag is still
 * checked between ticks). */
#define EXP_SYNC_MAX_HEIGHTS_PER_TICK 256u

/* Where the sync reads the chain from. Production: exp_sync_source_chain
 * (an exp_chain_t). Tests: fakes — no network. */
typedef struct {
    void *ctx;
    int  (*tip)(void *ctx, exp_chain_tip_t *out);
    int  (*page)(void *ctx, uint64_t height, uint32_t from_index,
                 nodus_dnac_v3_block_result_t *out);
    int  (*server)(void *ctx);       /* current server index, for the FSM */
    void (*rotate)(void *ctx);
} exp_sync_source_t;

/* Fill `src` to read from `chain`. */
void exp_sync_source_chain(exp_sync_source_t *src, exp_chain_t *chain);

/* Fetch every page of one height into `batch` (exp_block_batch_init'd by
 * the caller, empty): pages from index 0, then next_index while the node
 * names one, each appended through exp_extract_page (same header on every
 * page, items contiguous). Succeeds only when the collected item count
 * equals the block's announced count.
 * @return 0 collected; -1 any page failed or did not continue the block
 *         (the batch then holds a partial block — free it, do not write it)
 */
int exp_sync_collect_block(const exp_sync_source_t *src, uint64_t height,
                           exp_block_batch_t *batch);

/* One full poll iteration. `db` is passed by pointer-to-pointer because a
 * confirmed chain reset (rule 4) closes the current db, renames its file
 * aside, and opens a fresh one in its place.
 *
 * `fsm` must be zero-initialized (or preseeded via exp_sync_preseed())
 * before the first call and threaded through every later call.
 *
 * @param db_lock  writer lock taken around (a) each exp_db_write_height —
 *                 the HTTP thread shares the sqlite connection and would
 *                 otherwise see a height mid-write — (b) the tick's meta
 *                 reads/writes (the HTTP thread's meta reads share the one
 *                 prepared statement), and (c) the close->rename->reopen
 *                 swap of a CONFIRMED reset. NULL skips locking (--once,
 *                 and unit tests: no reader thread).
 * @return 0 caught up (or a PENDING rotate / a handled reset); 1 the
 *         per-tick height bound was reached with more heights to index;
 *         -1 any failure (logged) — retry next poll, the watermark is
 *         crash-safe.
 */
int exp_sync_tick(const exp_sync_source_t *src, exp_db_t **db, const char *db_path,
                  exp_reset_fsm_t *fsm, pthread_rwlock_t *db_lock);

/* Preseed `fsm`'s ref_chain_id from `db`'s "chain_id32" meta blob, if one
 * is present and non-zero (rule 1). Safe no-op on NULL db or fsm. */
void exp_sync_preseed(exp_db_t *db, exp_reset_fsm_t *fsm);

/* Pure helper (no I/O): builds "<db_path>.stale-<hex8>" into `out`, where
 * hex8 is the lowercase-hex encoding of chain_id[0..4) (8 hex chars).
 * Truncation-safe: returns -1 rather than writing a truncated path.
 * @return 0 on success, -1 on bad params or truncation */
int exp_sync_stale_name(const char *db_path, const uint8_t chain_id[32], char *out, size_t outlen);

/* Sync thread entry point (pthread_create-compatible). Runs exp_sync_tick()
 * in a loop, sleeping EXP_SYNC_POLL_SECONDS between polls unless the tick
 * returned 1 (checking *args->stop once per second so shutdown is
 * prompt), until *args->stop becomes non-zero. Preseeds its own FSM from
 * *args->db at startup. */
typedef struct {
    exp_chain_t   *chain;     /* open chain client */
    exp_db_t     **db;        /* pointer to the caller's db handle (rename-aside swap) */
    const char    *db_path;   /* filesystem path *db was opened from */
    volatile int  *stop;      /* set non-zero (e.g. from a signal handler) to request shutdown */
    pthread_rwlock_t *db_lock; /* same lock the HTTP thread reads under; NULL = no locking */
} exp_sync_args_t;

void *exp_sync_thread(void *arg);

#ifdef __cplusplus
}
#endif

#endif /* EXP_SYNC_H */
