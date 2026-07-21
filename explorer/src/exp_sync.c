/* exp_sync — DNAC Explorer ledger-sequence sync loop. See exp_sync.h. */

#include "exp_sync.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "exp_extract.h"
#include "nodus/nodus.h"
#include "dnac/transaction.h"

#include "crypto/utils/qgp_log.h"
#define LOG_TAG "EXP_SYNC"

/* input_count + output_count never exceeds DNAC_TX_MAX_INPUTS +
 * DNAC_TX_MAX_OUTPUTS (dnac/transaction.h) — exp_extract_tx enforces this
 * itself (returns -1 if it would overflow max_ios), this is just the
 * caller-side buffer sized to the real ceiling rather than a guessed
 * constant. */
#define EXP_SYNC_MAX_IOS (DNAC_TX_MAX_INPUTS + DNAC_TX_MAX_OUTPUTS)

/* Ledger-range chunk size: [from, from+99] = 100 sequences per
 * exp_chain_ledger_range() call, per plan Task 5 step 2. */
#define EXP_SYNC_CHUNK_SPAN 100

static int is_all_zero32(const uint8_t v[32]) {
    for (int i = 0; i < 32; i++) {
        if (v[i] != 0) return 0;
    }
    return 1;
}

int exp_sync_stale_name(const char *db_path, const uint8_t chain_id[32], char *out, size_t outlen) {
    if (!db_path || !chain_id || !out || outlen == 0) return -1;

    static const char hexchars[] = "0123456789abcdef";
    char hex8[9];
    for (int i = 0; i < 4; i++) {
        hex8[i * 2]     = hexchars[(chain_id[i] >> 4) & 0xF];
        hex8[i * 2 + 1] = hexchars[chain_id[i] & 0xF];
    }
    hex8[8] = '\0';

    int n = snprintf(out, outlen, "%s.stale-%s", db_path, hex8);
    if (n < 0 || (size_t)n >= outlen) return -1;
    return 0;
}

void exp_sync_preseed(exp_db_t *db, exp_reset_fsm_t *fsm) {
    if (!db || !fsm) return;

    uint8_t buf[32];
    size_t len = 0;
    if (exp_db_get_meta_blob(db, "chain_id", buf, sizeof(buf), &len) == 0 &&
        len == 32 && !is_all_zero32(buf)) {
        memcpy(fsm->ref_chain_id, buf, 32);
        QGP_LOG_INFO(LOG_TAG, "preseeded chain_id reference from db meta");
        return;
    }

    /* No usable meta chain_id — leave fsm zero-initialized. exp_sync_tick's
     * first successful supply observation adopts + persists it (rule 1,
     * second clause). */
}

/* CONFIRMED reset handler (rule 4): archive *db_ptr's file aside, reopen a
 * fresh db at db_path, and re-preseed both the FSM and the new db's meta
 * with the confirmed candidate (fsm->cand). On any failure this may leave
 * *db_ptr NULL (a dead-db state, loudly logged) — see exp_sync.h header
 * comment: watermark discipline means the caller retries next tick, and a
 * caller dereferencing NULL is guarded by exp_sync_tick's own NULL check
 * at entry. */
static int handle_confirmed_reset(exp_db_t **db_ptr, const char *db_path, exp_reset_fsm_t *fsm,
                                   pthread_rwlock_t *db_lock) {
    if (is_all_zero32(fsm->cand)) {
        /* Rule 2, enforced again defensively: exp_sync_tick never feeds an
         * all-zero observation into the FSM, so this candidate should be
         * unreachable in practice — refuse rather than trust it. */
        QGP_LOG_ERROR(LOG_TAG, "CONFIRMED reset candidate is all-zero — refusing reset");
        return -1;
    }

    char stale_path[PATH_MAX];
    if (exp_sync_stale_name(db_path, fsm->cand, stale_path, sizeof(stale_path)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "exp_sync_stale_name failed for %s", db_path);
        return -1;
    }

    /* Task 7 (db-swap race): wrlock spans exactly the close->rename->reopen
     * swap below — the HTTP thread may be mid-query on the old *db_ptr via
     * its own rdlock (exp_http.c handle_client). Held through every return
     * path from here on, including the rename-failure reopen (it also
     * mutates *db_ptr). Normal-tick db use (sync_ledger/sync_blocks, called
     * from exp_sync_tick before/after this function) takes no lock — the
     * handle itself doesn't change there, only its contents (FULLMUTEX
     * covers that). */
    if (db_lock) pthread_rwlock_wrlock(db_lock);

    exp_db_close(*db_ptr);
    *db_ptr = NULL;

    if (rename(db_path, stale_path) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "rename(%s -> %s) failed: %s", db_path, stale_path, strerror(errno));
        /* db_path still holds the pre-reset file (rename never happened) —
         * reopen it so *db_ptr isn't left dangling; the reset is retried
         * next tick against the same (still-mismatching) chain_id. */
        if (exp_db_open(db_path, db_ptr) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "failed to reopen original db after failed rename — index unavailable");
        }
        if (db_lock) pthread_rwlock_unlock(db_lock);
        return -1;
    }
    QGP_LOG_WARN(LOG_TAG, "chain reset CONFIRMED: archived stale index to %s", stale_path);

    exp_db_t *fresh = NULL;
    if (exp_db_open(db_path, &fresh) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "exp_db_open(%s) failed after chain reset — index unavailable", db_path);
        if (db_lock) pthread_rwlock_unlock(db_lock);
        return -1;
    }

    if (exp_db_set_meta_blob(fresh, "chain_id", fsm->cand, 32) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "failed to persist new chain_id after reset");
        exp_db_close(fresh);
        if (db_lock) pthread_rwlock_unlock(db_lock);
        return -1;
    }

    memcpy(fsm->ref_chain_id, fsm->cand, 32);
    fsm->cand_set = 0;
    fsm->servers_seen[0] = -1;
    fsm->servers_seen[1] = -1;
    fsm->polls_seen = 0;

    *db_ptr = fresh;
    if (db_lock) pthread_rwlock_unlock(db_lock);
    QGP_LOG_INFO(LOG_TAG, "chain reset complete: fresh index open at %s", db_path);
    return 0;
}

/* Step 2: walk ledger sequences (last_indexed_seq, tip] in chunks of
 * EXP_SYNC_CHUNK_SPAN. On success, *max_height_out / *have_max_height_out
 * report the highest TX block_height observed this tick (for step 3). */
static int sync_ledger(exp_chain_t *chain, exp_db_t *db, uint64_t tip,
                        uint64_t *max_height_out, int *have_max_height_out) {
    uint64_t last_indexed_seq = 0;
    int have_seq = (exp_db_get_meta_u64(db, "last_indexed_seq", &last_indexed_seq) == 0);
    uint64_t from = have_seq ? last_indexed_seq + 1 : 1;

    while (from <= tip) {
        uint64_t to = (from + (EXP_SYNC_CHUNK_SPAN - 1) <= tip) ? from + (EXP_SYNC_CHUNK_SPAN - 1) : tip;

        nodus_dnac_range_result_t range;
        memset(&range, 0, sizeof(range));
        if (exp_chain_ledger_range(chain, from, to, &range) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "ledger_range(%llu,%llu) failed",
                          (unsigned long long)from, (unsigned long long)to);
            return -1;
        }

        /* fix round 1, finding 1 (second clause): `to` is already clamped
         * to the supply tip by the loop guard above, so a short range
         * here is never "asked past what exists" — it means the server
         * under-delivered entries it should have had. Treat exactly like
         * any other chunk failure: don't advance last_indexed_seq past
         * seqs that were never actually returned. */
        uint64_t expected_count = to - from + 1;
        /* fix round 2, R1: a negative range.count would wrap huge when
         * cast to uint64_t below and silently pass the under-delivery
         * check (hostile/malformed server response); range.count > 0
         * with a NULL entries pointer would NULL-deref the loop below.
         * Both are checked BEFORE the cast-based comparison. */
        if (range.count < 0 || !range.entries || (uint64_t)range.count < expected_count) {
            QGP_LOG_ERROR(LOG_TAG, "ledger_range(%llu,%llu) under-delivered/malformed: got count=%d entries=%p of %llu expected — chunk retry",
                          (unsigned long long)from, (unsigned long long)to, range.count,
                          (void *)range.entries, (unsigned long long)expected_count);
            nodus_client_free_range_result(&range);
            return -1;
        }

        int chunk_ok = 1;
        for (int i = 0; i < range.count; i++) {
            const nodus_dnac_range_entry_t *e = &range.entries[i];

            nodus_dnac_tx_result_t txr;
            memset(&txr, 0, sizeof(txr));
            int tx_rc = exp_chain_tx(chain, e->tx_hash, &txr);
            if (tx_rc != 0) {
                /* fix round 1, finding 1: a transport/query FAILURE is not
                 * an authoritative "this tx doesn't exist" — the ledger
                 * range entry we just got proves it does. Treat as a
                 * chunk failure (do not advance the watermark) so a
                 * transient outage retries this seq next tick instead of
                 * skipping it forever. */
                QGP_LOG_ERROR(LOG_TAG, "tx lookup FAILED (transport) for seq %llu — chunk retry",
                              (unsigned long long)e->sequence);
                nodus_client_free_tx_result(&txr);
                chunk_ok = 0;
                break;
            }
            if (!txr.found) {
                /* rc==0 && !found: an authoritative not-found from a
                 * reachable server — keep the existing log+skip policy
                 * (exp_sync.h "Malformed-TX / not-found policy"). */
                QGP_LOG_ERROR(LOG_TAG, "tx not found for seq %llu — skipping",
                              (unsigned long long)e->sequence);
                nodus_client_free_tx_result(&txr);
                continue;
            }

            exp_tx_row_t tx_row;
            exp_io_row_t ios[EXP_SYNC_MAX_IOS];
            int io_count = 0;
            if (exp_extract_tx(txr.tx_data, txr.tx_len, e->sequence, txr.block_height,
                                &tx_row, ios, EXP_SYNC_MAX_IOS, &io_count) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "exp_extract_tx failed for seq %llu (malformed/hostile TX) — skipping",
                              (unsigned long long)e->sequence);
                nodus_client_free_tx_result(&txr);
                continue;
            }

            if (exp_db_insert_tx(db, &tx_row, txr.tx_data, txr.tx_len, ios, io_count) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "exp_db_insert_tx failed for seq %llu",
                              (unsigned long long)e->sequence);
                nodus_client_free_tx_result(&txr);
                chunk_ok = 0;
                break;
            }

            if (!*have_max_height_out || tx_row.height > *max_height_out) {
                *max_height_out = tx_row.height;
                *have_max_height_out = 1;
            }

            nodus_client_free_tx_result(&txr);
        }

        nodus_client_free_range_result(&range);

        if (!chunk_ok) {
            /* Partial chunk failure — leave last_indexed_seq at its old
             * value; the next tick retries from `from` (inserts already
             * committed in this chunk are idempotent). */
            return -1;
        }

        if (exp_db_set_meta_u64(db, "last_indexed_seq", to) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "failed to persist last_indexed_seq=%llu", (unsigned long long)to);
            return -1;
        }

        /* fix round 2, R2: persist the running max block_height to meta
         * ("max_tx_height") at the SAME commit point as last_indexed_seq,
         * not just once at the end of exp_sync_tick. If a LATER chunk in
         * this same tick fails, sync_ledger returns -1 before
         * exp_sync_tick's own post-call persist ever runs — and this
         * chunk's seqs are never re-walked once last_indexed_seq has
         * moved past them (idempotent-retry only replays the FAILED
         * chunk). Without this, heights already durably committed here
         * would never reach meta and their blocks would never get
         * backfilled. Never regress: max of what's stored and the
         * running max observed across every chunk processed so far in
         * this call (including this one). */
        if (*have_max_height_out) {
            uint64_t stored_target = 0;
            int have_stored_target = (exp_db_get_meta_u64(db, "max_tx_height", &stored_target) == 0);
            uint64_t target = (have_stored_target && stored_target > *max_height_out) ? stored_target : *max_height_out;
            if (exp_db_set_meta_u64(db, "max_tx_height", target) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "failed to persist max_tx_height=%llu", (unsigned long long)target);
                return -1;
            }
        }

        from = to + 1;
    }

    return 0;
}

/* Step 3: backfill block headers for every new height in
 * (last_block_height, max_height]. Each block's tx_root is stored via
 * exp_db_insert_block (has_block_hash=0 — this row doesn't know its own
 * hash yet); the CHILD block's prev_hash backfills the PARENT's
 * block_hash via exp_db_set_block_hash. On the full-success path,
 * last_block_height is persisted once, after the whole loop commits
 * (watermark discipline). fix round 2, R3: a transport/query failure at
 * height h returns -1 with the watermark untouched (retry next tick); an
 * AUTHORITATIVE not-found at height h instead persists progress through
 * h-1 (bounded by the same never-regress guard as the entry check below)
 * and returns 0 — see the loop body for why. */
static int sync_blocks(exp_chain_t *chain, exp_db_t *db, uint64_t max_height) {
    uint64_t last_block_height = 0;
    int have_lbh = (exp_db_get_meta_u64(db, "last_block_height", &last_block_height) == 0);

    if (have_lbh && max_height <= last_block_height) {
        /* fix round 1, finding 4: nothing new to backfill — and critically,
         * do NOT fall through to the trailing exp_db_set_meta_u64 below.
         * That unconditional persist would otherwise write a
         * last_block_height SMALLER than what's already stored (e.g. a
         * hostile/misbehaving witness feeding a TX with a lower
         * block_height than heights already indexed). A regressed
         * watermark would make a LATER tick re-walk heights already
         * fully processed and INSERT OR REPLACE their `blocks` row with
         * has_block_hash=0 (exp_db.c), wiping the hash already
         * back-filled from the child block's prev_hash. Only run the
         * loop/persist when the target actually advances. */
        return 0;
    }

    /* Genesis is height 1, not 0, on this protocol's actual witness
     * implementation: nodus_witness_block_height() returns MAX(height)
     * FROM blocks (0 for an empty table), and nodus_witness_commit_genesis
     * computes bh = nodus_witness_block_height(w) + 1
     * (nodus/src/witness/nodus_witness_bft.c:5604-751 with the height
     * helper at nodus_witness_db.c:759) — so genesis always commits at
     * height 1, never 0. Confirmed live against a production witness
     * (2026-07-21 smoke): dnac_block(height=0) is an AUTHORITATIVE
     * not-found while dnac_block(height=1) returns the genesis block. The
     * `dnac/block.h` struct doc comment ("sequential from 0") describes the
     * field's abstract numbering, not this witness implementation's actual
     * floor — starting the backfill walk at 0 left `blocks` permanently
     * empty (every tick hit height 0's not-found and returned before ever
     * trying height 1). */
    uint64_t h = have_lbh ? last_block_height + 1 : 1;

    for (; h <= max_height; h++) {
        nodus_dnac_block_result_t blk;
        memset(&blk, 0, sizeof(blk));
        int block_rc = exp_chain_block(chain, h, &blk);
        if (block_rc != 0) {
            /* fix round 2, R3: transport/query FAILURE is not an
             * authoritative "this height doesn't exist" — retry next
             * tick from the untouched watermark, same split as sync_ledger's
             * tx lookup (fix round 1, finding 1). */
            QGP_LOG_ERROR(LOG_TAG, "block(%llu) fetch FAILED (transport) — retry next tick", (unsigned long long)h);
            nodus_client_free_block_result(&blk);
            return -1;
        }
        if (!blk.found) {
            /* rc==0 && !found: an authoritative not-found at height h.
             * Heights below h (up through h-1) ARE fully processed —
             * persist that much progress and return 0 (not a failure), so
             * a hostile/malformed report of a huge block_height (e.g.
             * 2^60, driving max_height way out) degrades to exactly ONE
             * extra block query per tick (this one) instead of a
             * permanent failure with an ever-repeated, unbounded re-walk
             * from the old watermark on every retry. */
            QGP_LOG_ERROR(LOG_TAG, "block(%llu) not found — stopping backfill, persisting progress through %llu",
                          (unsigned long long)h, (unsigned long long)(h - 1));
            nodus_client_free_block_result(&blk);
            /* h is always >= 1 here (loop floor is 1, genesis's height —
             * see the h-init comment above), so h - 1 never underflows.
             * h == 1 not-found (nothing committed yet) still falls through
             * correctly: stop_at = 0, and since have_lbh is false on a
             * first-ever call, the regression guard below is skipped and
             * last_block_height=0 is persisted (the documented "no blocks
             * synced yet" watermark, not a claim that height 0 exists). */
            uint64_t stop_at = h - 1;
            if (have_lbh && stop_at <= last_block_height) {
                /* Never regress below what's already stored (round 1,
                 * finding 4's guard, reused here for the same reason). */
                return 0;
            }
            if (exp_db_set_meta_u64(db, "last_block_height", stop_at) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "failed to persist last_block_height=%llu", (unsigned long long)stop_at);
                return -1;
            }
            return 0;
        }

        exp_block_row_t row;
        memset(&row, 0, sizeof(row));
        row.height = h;
        memcpy(row.tx_root, blk.tx_root, 64);
        row.has_block_hash = 0;
        row.timestamp = blk.timestamp;
        memcpy(row.proposer, blk.proposer_id, 32);
        row.tx_count = blk.tx_count;

        if (exp_db_insert_block(db, &row) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "insert_block(%llu) failed", (unsigned long long)h);
            nodus_client_free_block_result(&blk);
            return -1;
        }

        /* h > 1 (not h > 0): height 1 is genesis, the lowest height any
         * `blocks` row is ever inserted at (see the h-init comment above) —
         * there is no height-0 parent row to backfill. Height 1's own
         * block_hash instead gets backfilled when height 2 arrives, exactly
         * like every other block. */
        if (h > 1) {
            if (exp_db_set_block_hash(db, h - 1, blk.prev_hash) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "set_block_hash(%llu) failed", (unsigned long long)(h - 1));
                nodus_client_free_block_result(&blk);
                return -1;
            }
        }

        nodus_client_free_block_result(&blk);
    }

    if (exp_db_set_meta_u64(db, "last_block_height", max_height) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "failed to persist last_block_height=%llu", (unsigned long long)max_height);
        return -1;
    }

    return 0;
}

int exp_sync_tick(exp_chain_t *chain, exp_db_t **db_ptr, const char *db_path, exp_reset_fsm_t *fsm,
                   pthread_rwlock_t *db_lock) {
    if (!chain || !db_ptr || !*db_ptr || !db_path || !fsm) {
        QGP_LOG_ERROR(LOG_TAG, "exp_sync_tick: invalid params");
        return -1;
    }

    nodus_dnac_supply_result_t supply;
    memset(&supply, 0, sizeof(supply));
    if (exp_chain_supply(chain, &supply) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "exp_chain_supply failed");
        return -1;
    }

    if (is_all_zero32(supply.chain_id)) {
        /* Rule 2: never adopt/feed an all-zero chain_id. */
        QGP_LOG_ERROR(LOG_TAG, "supply returned all-zero chain_id — skipping, rotating");
        exp_chain_rotate(chain);
        return -1;
    }

    int server_idx = exp_chain_current_server(chain);
    int was_unset = is_all_zero32(fsm->ref_chain_id);

    int rc = exp_reset_fsm_feed(fsm, supply.chain_id, server_idx);

    if (was_unset && rc == EXP_RESET_NO) {
        /* First-ever adoption (meta chain_id was absent at preseed time) —
         * persist it now (rule 1, second clause). */
        if (exp_db_set_meta_blob(*db_ptr, "chain_id", supply.chain_id, 32) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "failed to persist adopted chain_id to meta");
            /* fix round 1, finding 3: exp_reset_fsm_feed already adopted
             * chain_id into fsm->ref_chain_id in memory (its own
             * first-feed contract, exp_chain.c) before we got here — only
             * the db persist failed. Zero ref_chain_id back to "unset" so
             * was_unset is true again next tick and the whole adoption
             * (feed + persist) retries cleanly, instead of leaving the
             * FSM believing a reference is established that the db never
             * recorded. */
            memset(fsm->ref_chain_id, 0, 32);
            return -1;
        }
        QGP_LOG_INFO(LOG_TAG, "adopted chain_id reference from first supply observation");
    }

    if (rc == EXP_RESET_PENDING) {
        QGP_LOG_WARN(LOG_TAG, "chain_id mismatch observed (reset PENDING) — rotating for next poll");
        exp_chain_rotate(chain);
        return 0;
    }

    if (rc == EXP_RESET_CONFIRMED) {
        QGP_LOG_WARN(LOG_TAG, "chain_id mismatch CONFIRMED across >=2 servers/polls — resetting index");
        if (handle_confirmed_reset(db_ptr, db_path, fsm, db_lock) != 0) {
            return -1;
        }
        return 0;
    }

    /* rc == EXP_RESET_NO: this observation matches the established
     * reference (whether just adopted or previously known) — proceed with
     * the normal sync using this tip.
     *
     * fix round 1, finding 1: cache the latest supply/tip observation in
     * meta so /api/stats (which has no live chain access of its own — it
     * only reads *db_ptr) can report tip state and staleness (indexed_seq
     * vs tip_seq) without a network query. This MUST happen only after
     * exp_reset_fsm_feed has confirmed rc == EXP_RESET_NO — persisting
     * before the feed gate let a lying witness's supply numbers land in
     * meta (and be served on public /api/stats) even while the FSM was
     * still refusing the observed chain_id (PENDING). Best-effort: a
     * persist failure here is logged but never aborts the tick — these are
     * display-only staleness fields, not part of the indexing watermark
     * discipline below. */
    if (exp_db_set_meta_u64(*db_ptr, "tip_seq", supply.last_sequence) != 0 ||
        exp_db_set_meta_u64(*db_ptr, "supply_current", supply.current_supply) != 0 ||
        exp_db_set_meta_u64(*db_ptr, "supply_burned", supply.total_burned) != 0 ||
        exp_db_set_meta_u64(*db_ptr, "supply_genesis", supply.genesis_supply) != 0) {
        QGP_LOG_WARN(LOG_TAG, "failed to persist supply/tip meta (stats staleness display only)");
    }

    exp_db_t *db = *db_ptr;
    uint64_t tip = supply.last_sequence;
    uint64_t max_height = 0;
    int have_max_height = 0;

    if (sync_ledger(chain, db, tip, &max_height, &have_max_height) != 0) {
        return -1;
    }

    /* fix round 1, finding 2: persist the highest TX block_height observed
     * so far to meta ("max_tx_height"), independent of whether THIS tick
     * saw any new TXs. Without this, a backfill that failed (sync_blocks
     * returned -1, e.g. a transient block fetch error) was never retried
     * on a later tick that happened to see no new TXs of its own — a
     * quiet chain would leave the backfill gap forever. Never regress the
     * stored value: take the max of what's already there and what this
     * tick observed (mirrors fix 4's regression guard in sync_blocks).
     * fix round 2, R2: sync_ledger now ALSO persists max_tx_height at each
     * chunk commit (same never-regress logic) — sync_ledger only returns 0
     * here on full success, by which point every chunk it walked already
     * ran that same persist with the same final accumulated max, so this
     * block is idempotent on the success path (target == stored value
     * already). Kept anyway as defense-in-depth per explicit review
     * guidance rather than deleted, since it's harmless and a single
     * extra meta read+write per tick is not a cost worth trading
     * belt-and-suspenders coverage for. */
    if (have_max_height) {
        uint64_t stored_target = 0;
        int have_stored_target = (exp_db_get_meta_u64(db, "max_tx_height", &stored_target) == 0);
        uint64_t target = (have_stored_target && stored_target > max_height) ? stored_target : max_height;
        if (exp_db_set_meta_u64(db, "max_tx_height", target) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "failed to persist max_tx_height=%llu", (unsigned long long)target);
            return -1;
        }
    }

    uint64_t backfill_target = 0;
    int have_backfill_target = (exp_db_get_meta_u64(db, "max_tx_height", &backfill_target) == 0);
    if (have_backfill_target) {
        uint64_t last_block_height = 0;
        int have_lbh = (exp_db_get_meta_u64(db, "last_block_height", &last_block_height) == 0);
        if (!have_lbh || last_block_height < backfill_target) {
            if (sync_blocks(chain, db, backfill_target) != 0) {
                return -1;
            }
        }
    }

    return 0;
}

void *exp_sync_thread(void *arg) {
    exp_sync_args_t *a = (exp_sync_args_t *)arg;
    if (!a || !a->chain || !a->db || !*a->db || !a->db_path || !a->stop) {
        QGP_LOG_ERROR(LOG_TAG, "exp_sync_thread: invalid args");
        return NULL;
    }

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    exp_sync_preseed(*a->db, &fsm);

    QGP_LOG_INFO(LOG_TAG, "sync thread started (poll interval %d s)", EXP_SYNC_POLL_SECONDS);

    while (!*a->stop) {
        if (exp_sync_tick(a->chain, a->db, a->db_path, &fsm, a->db_lock) != 0) {
            QGP_LOG_WARN(LOG_TAG, "sync tick failed — retrying next poll");
        }

        for (int waited = 0; waited < EXP_SYNC_POLL_SECONDS && !*a->stop; waited++) {
            sleep(1);
        }
    }

    QGP_LOG_INFO(LOG_TAG, "sync thread stopping");
    return NULL;
}
