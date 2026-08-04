/* exp_sync — DNAC Explorer ledger-sequence sync loop.
 *
 * Drives the chain -> index walk described by
 * docs/plans/2026-07-21-dnac-explorer-design.md and the Task 5 plan:
 * one poll per exp_sync_tick() call —
 *   1. exp_chain_supply() -> chain_id / tip sequence, fed into the F4
 *      chain-reset FSM (exp_chain.h). A confirmed reset archives the
 *      current index db aside and starts a fresh one.
 *   2. Walk ledger sequences in the index's [last_indexed_seq+1, tip]
 *      gap in chunks of 100, extracting + inserting each TX.
 *   3. Backfill block headers for every new height observed in step 2.
 *      Each row's OWN block_hash is computed locally at insert when the
 *      dnac_block response carries a non-zero state_root AND a non-zero
 *      tx_root (exp_sync_compute_block_hash below) — the tip is never
 *      left hash-less on a current witness. The CHILD block's prev_hash
 *      backfill of the PARENT's block_hash stays as the authoritative
 *      overwrite and as the only path for rows the helper can't compute
 *      (genesis at height 1, pre-v0.18.22 witness serving no
 *      state_root/tx_root keys).
 *
 * Binding FSM-integration rules (Task 4 security review, G6):
 *   1. On startup, preseed the FSM's ref_chain_id from db meta
 *      ("chain_id" blob) IF present and non-zero; if meta chain_id is
 *      absent, adopt the first supply response's chain_id into BOTH db
 *      meta and the FSM ONLY if it is non-zero (exp_sync_preseed +
 *      exp_sync_tick's first-adoption path).
 *   2. NEVER adopt an all-zero chain_id as reference — skip + log error
 *      + rotate.
 *   3. One FSM feed per server per poll cycle: exp_sync_tick issues
 *      exactly one exp_chain_supply() per call -> one exp_reset_fsm_feed()
 *      call; after a PENDING result the tick rotates so the NEXT tick's
 *      supply query lands on a different server.
 *   4. On CONFIRMED: rename the db file aside to
 *      "<db>.stale-<hex8(new chain_id)>" (exp_sync_stale_name), reopen a
 *      fresh db at the original path (watermarks reset for free — a new
 *      db has no meta rows), and re-preseed the FSM + db meta with the
 *      confirmed candidate (guaranteed non-zero by rule 2, enforced
 *      again defensively). The tick returns after handling the reset;
 *      the actual re-sync happens on the next tick.
 *
 * Malformed-TX / not-found policy (ledger walk, step 2): a ledger entry
 * whose TX fails exp_extract_tx() (hostile/undecodable) or whose
 * exp_chain_tx() lookup fails/returns not-found is logged at ERROR and
 * SKIPPED — the pipeline never stalls on one bad entry. The seq is still
 * covered by the chunk's watermark advance (idempotent re-processing on
 * retry would hit the same skip again, so there is no reason to retry it
 * alone).
 *
 * Watermark discipline (determinism / crash-safety): last_indexed_seq is
 * persisted only after a full 100-entry chunk's inserts all committed;
 * last_block_height is persisted only after the full per-tick block
 * backfill loop completes. A partial failure leaves the watermark at its
 * old value and returns -1 — the next tick retries from there. Every
 * insert this module drives (exp_db_insert_tx, exp_db_insert_block) is
 * idempotent, so replaying already-applied work on retry is safe.
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

/* One full poll iteration. `db` is passed by pointer-to-pointer because a
 * confirmed chain reset (see file header, rule 4) closes the current db,
 * renames its file aside, and opens a fresh one in its place — the
 * caller's db handle must observe the swap.
 *
 * `fsm` must be zero-initialized (or preseeded via exp_sync_preseed())
 * before the first call, and the same instance must be threaded through
 * every subsequent call — it carries the F4 reset-detection state across
 * polls.
 *
 * @param chain    open chain client (network I/O happens here)
 * @param db       pointer to the caller's db handle; may be swapped on a
 *                 confirmed chain reset
 * @param db_path  filesystem path *db was opened from (needed to rename
 *                 it aside and reopen fresh on a confirmed reset)
 * @param fsm      F4 chain-reset FSM state, persisted by the caller
 *                 across ticks
 * @param db_lock  Task 7 (db-swap race): wrlock taken ONLY around the
 *                 close->rename->reopen swap inside a CONFIRMED reset
 *                 (handle_confirmed_reset) — normal-tick inserts on the
 *                 unchanged *db handle need no app-level lock (FULLMUTEX,
 *                 see exp_db.c, already serializes same-handle use safely
 *                 against the HTTP thread's reads). NULL skips locking —
 *                 the --once single-shot path (main.c) has no concurrent
 *                 HTTP thread and passes NULL.
 * @return 0 on a tick that completed cleanly (including a no-op PENDING
 *         rotate or a handled CONFIRMED reset), -1 on any failure (already
 *         logged at ERROR) — the caller should just retry on the next
 *         poll, all internal watermarks are crash-safe.
 */
int exp_sync_tick(exp_chain_t *chain, exp_db_t **db, const char *db_path, exp_reset_fsm_t *fsm,
                   pthread_rwlock_t *db_lock);

/* Preseed `fsm`'s ref_chain_id from `db`'s "chain_id" meta blob, if one
 * is present and non-zero (rule 1). If no usable meta chain_id exists,
 * `fsm` is left zero-initialized: exp_sync_tick's first successful
 * exp_chain_supply() observation adopts it as the reference and persists
 * it to db meta at that point (rule 1's second clause) — no work needed
 * here in that case.
 *
 * Call once before the first exp_sync_tick() call for a given db/fsm
 * pair (thread startup, or the --once single-shot path in main.c). Safe
 * no-op on NULL db or fsm. */
void exp_sync_preseed(exp_db_t *db, exp_reset_fsm_t *fsm);

/* Pure helper (no I/O): builds "<db_path>.stale-<hex8>" into `out`, where
 * hex8 is the lowercase-hex encoding of chain_id[0..4) (8 hex chars).
 * Truncation-safe: returns -1 (leaving `out` unspecified) rather than
 * writing a truncated path if `outlen` is too small.
 *
 * @param db_path  original db file path
 * @param chain_id 32-byte chain id whose first 4 bytes name the archive
 * @param out      [out] caller-allocated buffer
 * @param outlen   capacity of `out`, including the NUL terminator
 * @return 0 on success, -1 on bad params or truncation
 */
int exp_sync_stale_name(const char *db_path, const uint8_t chain_id[32], char *out, size_t outlen);

/* Pure helper (no I/O): compute a block's OWN hash from the fields the
 * dnac_block response carries, via libdna's dnac_block_compute_hash — the
 * same canonical preimage the witness chain uses
 * (nodus/src/witness/nodus_witness_db.c nodus_witness_compute_block_hash_ex;
 * layout pinned at dnac/include/dnac/block.h "Compute block_hash" doc:
 * SHA3-512( height(8 LE) || prev_hash(64) || state_root(64) || tx_root(64)
 *           || tx_count(4 LE) || proposer_id(32) ), timestamp NOT hashed).
 * Lets the tip block show its real hash immediately instead of waiting for
 * the child block's prev_hash backfill (which stays in place as the
 * authoritative overwrite).
 *
 * Returns -1 (out untouched) when the hash is NOT locally computable:
 *   - height <= 1: height 1 is this witness implementation's genesis (see
 *     sync_blocks' h-init comment) and its preimage appends the chain_def
 *     blob, which the dnac_block response does not carry;
 *   - blk->state_root all-zero: a pre-upgrade witness that doesn't serve
 *     state_root yet (the field decodes as zeros) — hashing a zeroed
 *     state_root would produce a WRONG hash, so fail closed and leave the
 *     row on the child-backfill path;
 *   - blk->tx_root all-zero (2026-08-04): a pre-v0.18.22 witness omits the
 *     explicit "tx_root" response key, so the parsed field decodes as
 *     zeros; a legitimate tx_root is never all-zero (empty block's RFC
 *     6962 root is SHA3-512("")), and hashing zeros produced a live wrong
 *     tip hash — fail closed, child-backfill path takes over.
 * @return 0 on success (out filled), -1 otherwise
 */
int exp_sync_compute_block_hash(uint64_t height,
                                 const nodus_dnac_block_result_t *blk,
                                 uint8_t out[64]);

/* Sync thread entry point (pthread_create-compatible). Runs exp_sync_tick()
 * in a loop, sleeping EXP_SYNC_POLL_SECONDS between polls (checking
 * *args->stop once per second so shutdown is prompt), until *args->stop
 * becomes non-zero. Preseeds its own FSM instance from *args->db at
 * startup (rule 1) — the caller does not need to preseed separately when
 * using this entry point. */
typedef struct {
    exp_chain_t   *chain;     /* open chain client */
    exp_db_t     **db;        /* pointer to the caller's db handle (rename-aside swap) */
    const char    *db_path;   /* filesystem path *db was opened from */
    volatile int  *stop;      /* set non-zero (e.g. from a signal handler) to request shutdown */

    /* Task 7 (db-swap race): forwarded to every exp_sync_tick() call this
     * thread makes — see exp_sync_tick's db_lock doc above. Same
     * pthread_rwlock_t* the caller (main.c) also wires into
     * exp_http_ctx_t.db_lock; NULL is a valid no-op value. */
    pthread_rwlock_t *db_lock;
} exp_sync_args_t;

void *exp_sync_thread(void *arg);

#ifdef __cplusplus
}
#endif

#endif /* EXP_SYNC_H */
