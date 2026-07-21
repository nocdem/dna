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
static int handle_confirmed_reset(exp_db_t **db_ptr, const char *db_path, exp_reset_fsm_t *fsm) {
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
        return -1;
    }
    QGP_LOG_WARN(LOG_TAG, "chain reset CONFIRMED: archived stale index to %s", stale_path);

    exp_db_t *fresh = NULL;
    if (exp_db_open(db_path, &fresh) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "exp_db_open(%s) failed after chain reset — index unavailable", db_path);
        return -1;
    }

    if (exp_db_set_meta_blob(fresh, "chain_id", fsm->cand, 32) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "failed to persist new chain_id after reset");
        exp_db_close(fresh);
        return -1;
    }

    memcpy(fsm->ref_chain_id, fsm->cand, 32);
    fsm->cand_set = 0;
    fsm->servers_seen[0] = -1;
    fsm->servers_seen[1] = -1;
    fsm->polls_seen = 0;

    *db_ptr = fresh;
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

        int chunk_ok = 1;
        for (int i = 0; i < range.count; i++) {
            const nodus_dnac_range_entry_t *e = &range.entries[i];

            nodus_dnac_tx_result_t txr;
            memset(&txr, 0, sizeof(txr));
            if (exp_chain_tx(chain, e->tx_hash, &txr) != 0 || !txr.found) {
                QGP_LOG_ERROR(LOG_TAG, "tx lookup failed/not-found for seq %llu — skipping",
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

        from = to + 1;
    }

    return 0;
}

/* Step 3: backfill block headers for every new height in
 * (last_block_height, max_height]. Each block's tx_root is stored via
 * exp_db_insert_block (has_block_hash=0 — this row doesn't know its own
 * hash yet); the CHILD block's prev_hash backfills the PARENT's
 * block_hash via exp_db_set_block_hash. last_block_height is persisted
 * once, after the whole loop commits (watermark discipline). */
static int sync_blocks(exp_chain_t *chain, exp_db_t *db, uint64_t max_height) {
    uint64_t last_block_height = 0;
    int have_lbh = (exp_db_get_meta_u64(db, "last_block_height", &last_block_height) == 0);
    uint64_t h = have_lbh ? last_block_height + 1 : 0;

    for (; h <= max_height; h++) {
        nodus_dnac_block_result_t blk;
        memset(&blk, 0, sizeof(blk));
        if (exp_chain_block(chain, h, &blk) != 0 || !blk.found) {
            QGP_LOG_ERROR(LOG_TAG, "block(%llu) fetch failed", (unsigned long long)h);
            nodus_client_free_block_result(&blk);
            return -1;
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

        if (h > 0) {
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

int exp_sync_tick(exp_chain_t *chain, exp_db_t **db_ptr, const char *db_path, exp_reset_fsm_t *fsm) {
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
        if (handle_confirmed_reset(db_ptr, db_path, fsm) != 0) {
            return -1;
        }
        return 0;
    }

    /* rc == EXP_RESET_NO: this observation matches the established
     * reference (whether just adopted or previously known) — proceed with
     * the normal sync using this tip. */
    exp_db_t *db = *db_ptr;
    uint64_t tip = supply.last_sequence;
    uint64_t max_height = 0;
    int have_max_height = 0;

    if (sync_ledger(chain, db, tip, &max_height, &have_max_height) != 0) {
        return -1;
    }

    if (have_max_height) {
        if (sync_blocks(chain, db, max_height) != 0) {
            return -1;
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
        if (exp_sync_tick(a->chain, a->db, a->db_path, &fsm) != 0) {
            QGP_LOG_WARN(LOG_TAG, "sync tick failed — retrying next poll");
        }

        for (int waited = 0; waited < EXP_SYNC_POLL_SECONDS && !*a->stop; waited++) {
            sleep(1);
        }
    }

    QGP_LOG_INFO(LOG_TAG, "sync thread stopping");
    return NULL;
}
