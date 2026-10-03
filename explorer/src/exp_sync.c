/* exp_sync — DNAC Explorer height sync loop (version-3 chain). See
 * exp_sync.h. */

#include "exp_sync.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "exp_extract.h"
#include "nodus/nodus.h"

#include "crypto/utils/qgp_log.h"
#define LOG_TAG "EXP_SYNC"

/* Meta key of the F4 reference (rule 1): the version-3 32-byte chain id. */
#define EXP_META_CHAIN_ID32 "chain_id32"

static int is_all_zero32(const uint8_t v[32]) {
    for (int i = 0; i < 32; i++) {
        if (v[i] != 0) return 0;
    }
    return 1;
}

/* ── Production source: an exp_chain_t ──────────────────────────────── */

static int chain_src_tip(void *ctx, exp_chain_tip_t *out) {
    return exp_chain_tip((exp_chain_t *)ctx, out);
}

static int chain_src_page(void *ctx, uint64_t height, uint32_t from_index,
                          nodus_dnac_v3_block_result_t *out) {
    return exp_chain_v3_page((exp_chain_t *)ctx, height, from_index, out);
}

static int chain_src_server(void *ctx) {
    return exp_chain_current_server((const exp_chain_t *)ctx);
}

static void chain_src_rotate(void *ctx) {
    exp_chain_rotate((exp_chain_t *)ctx);
}

static int chain_src_stake(void *ctx, exp_active_stake_t *out) {
    return exp_chain_active_stake((exp_chain_t *)ctx, out);
}

void exp_sync_source_chain(exp_sync_source_t *src, exp_chain_t *chain) {
    if (!src) return;
    src->ctx = chain;
    src->tip = chain_src_tip;
    src->page = chain_src_page;
    src->server = chain_src_server;
    src->rotate = chain_src_rotate;
    src->stake = chain_src_stake;
}

/* ── Helpers ─────────────────────────────────────────────────────────── */

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
    if (exp_db_get_meta_blob(db, EXP_META_CHAIN_ID32, buf, sizeof(buf), &len) == 0 &&
        len == 32 && !is_all_zero32(buf)) {
        memcpy(fsm->ref_chain_id, buf, 32);
        QGP_LOG_INFO(LOG_TAG, "preseeded chain_id32 reference from db meta");
        return;
    }
    /* No usable reference — leave fsm zero-initialized; the first tip
     * observation adopts + persists it (rule 1). */
}

/* CONFIRMED reset handler (rule 4): archive *db_ptr's file aside, reopen a
 * fresh db at db_path, and re-preseed both the FSM and the new db's meta
 * with the confirmed candidate (fsm->cand). On a failure *db_ptr may be
 * left NULL (a dead-db state, loudly logged); exp_sync_tick's entry check
 * refuses a NULL handle and the HTTP layer answers 503. */
static int handle_confirmed_reset(exp_db_t **db_ptr, const char *db_path, exp_reset_fsm_t *fsm,
                                  pthread_rwlock_t *db_lock) {
    if (is_all_zero32(fsm->cand)) {
        /* Rule 2, enforced again defensively. */
        QGP_LOG_ERROR(LOG_TAG, "CONFIRMED reset candidate is all-zero — refusing reset");
        return -1;
    }

    char stale_path[PATH_MAX];
    if (exp_sync_stale_name(db_path, fsm->cand, stale_path, sizeof(stale_path)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "exp_sync_stale_name failed for %s", db_path);
        return -1;
    }

    /* The wrlock spans exactly the close->rename->reopen swap — the HTTP
     * thread may be mid-query on the old *db_ptr under its rdlock. */
    if (db_lock) pthread_rwlock_wrlock(db_lock);

    exp_db_close(*db_ptr);
    *db_ptr = NULL;

    if (rename(db_path, stale_path) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "rename(%s -> %s) failed: %s", db_path, stale_path, strerror(errno));
        /* The rename never happened — reopen the original so *db_ptr is not
         * left dangling; the reset is retried next tick. */
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

    if (exp_db_set_meta_blob(fresh, EXP_META_CHAIN_ID32, fsm->cand, 32) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "failed to persist new chain_id32 after reset");
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

/* ── Page loop ───────────────────────────────────────────────────────── */

int exp_sync_collect_block(const exp_sync_source_t *src, uint64_t height,
                           exp_block_batch_t *batch) {
    if (!src || !src->page || !batch || height == 0) return -1;

    uint32_t from = 0;
    /* Every page that names a next index carries at least one item (the
     * client decoder: nx == last + 1), so a block of at most
     * EXP_BLOCK_MAX_ITEMS items takes at most that many pages plus one;
     * the bound only stops a source that violates it. */
    for (uint32_t pages = 0; pages <= EXP_BLOCK_MAX_ITEMS; pages++) {
        nodus_dnac_v3_block_result_t page;
        memset(&page, 0, sizeof(page));

        int rc = src->page(src->ctx, height, from, &page);
        if (rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "dnac_v3_block(%llu, i=%u) failed (rc=%d)",
                          (unsigned long long)height, (unsigned)from, rc);
            nodus_client_free_v3_block_result(&page);
            return -1;
        }
        if (page.height != height) {
            QGP_LOG_ERROR(LOG_TAG, "dnac_v3_block(%llu) answered height %llu",
                          (unsigned long long)height, (unsigned long long)page.height);
            nodus_client_free_v3_block_result(&page);
            return -1;
        }
        if (exp_extract_page(&page, batch) != 0) {
            nodus_client_free_v3_block_result(&page);
            return -1;
        }

        int has_next = page.has_next ? 1 : 0;
        uint32_t next = page.next_index;
        nodus_client_free_v3_block_result(&page);

        if (!has_next) {
            if (batch->n_items != (size_t)batch->block.n_items) {
                QGP_LOG_ERROR(LOG_TAG, "height %llu: %zu items collected of %u announced",
                              (unsigned long long)height, batch->n_items, (unsigned)batch->block.n_items);
                return -1;
            }
            return 0;
        }
        if ((size_t)next != batch->n_items) {
            QGP_LOG_ERROR(LOG_TAG, "height %llu: next index %u after %zu items",
                          (unsigned long long)height, (unsigned)next, batch->n_items);
            return -1;
        }
        from = next;
    }

    QGP_LOG_ERROR(LOG_TAG, "height %llu: page bound exceeded", (unsigned long long)height);
    return -1;
}

/* ── Tick ────────────────────────────────────────────────────────────── */

int exp_sync_tick(const exp_sync_source_t *src, exp_db_t **db_ptr, const char *db_path,
                  exp_reset_fsm_t *fsm, pthread_rwlock_t *db_lock) {
    if (!src || !src->tip || !src->page || !src->server || !src->rotate ||
        !db_ptr || !*db_ptr || !db_path || !fsm) {
        QGP_LOG_ERROR(LOG_TAG, "exp_sync_tick: invalid params");
        return -1;
    }

    exp_chain_tip_t tip;
    memset(&tip, 0, sizeof(tip));
    if (src->tip(src->ctx, &tip) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "tip observation failed");
        return -1;
    }

    if (is_all_zero32(tip.chain_id32)) {
        /* Rule 2: never adopt/feed an all-zero chain id. */
        QGP_LOG_ERROR(LOG_TAG, "server answered an all-zero chain_id32 — skipping, rotating");
        src->rotate(src->ctx);
        return -1;
    }

    int server_idx = src->server(src->ctx);
    int was_unset = is_all_zero32(fsm->ref_chain_id);

    int rc = exp_reset_fsm_feed(fsm, tip.chain_id32, server_idx);

    if (was_unset && rc == EXP_RESET_NO) {
        if (db_lock) pthread_rwlock_wrlock(db_lock);
        int prc = exp_db_set_meta_blob(*db_ptr, EXP_META_CHAIN_ID32, tip.chain_id32, 32);
        if (db_lock) pthread_rwlock_unlock(db_lock);
        if (prc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "failed to persist adopted chain_id32 to meta");
            /* The feed adopted the reference in memory only — undo it so
             * the whole adoption (feed + persist) retries next tick. */
            memset(fsm->ref_chain_id, 0, 32);
            return -1;
        }
        QGP_LOG_INFO(LOG_TAG, "adopted chain_id32 reference from first tip observation");
    }

    if (rc == EXP_RESET_PENDING) {
        QGP_LOG_WARN(LOG_TAG, "chain_id32 mismatch observed (reset PENDING) — rotating for next poll");
        src->rotate(src->ctx);
        return 0;
    }

    if (rc == EXP_RESET_CONFIRMED) {
        QGP_LOG_WARN(LOG_TAG, "chain_id32 mismatch CONFIRMED across >=2 servers/polls — resetting index");
        return handle_confirmed_reset(db_ptr, db_path, fsm, db_lock) == 0 ? 0 : -1;
    }

    /* rc == EXP_RESET_NO: the observation matches the reference. Only now
     * does anything it says reach meta (a PENDING server's numbers are
     * never shown). Display-only fields: a persist failure is logged and
     * does not stop indexing. */
    /* Writer lock over the meta span: the HTTP thread runs
     * exp_db_get_meta_* on the SAME prepared statement (one connection,
     * one stmt_get_meta); FULLMUTEX serializes single sqlite calls, not a
     * reset->bind->step->column sequence, so an unlocked read here could
     * interleave with /api/stats and read the other thread's row. */
    exp_db_t *db = *db_ptr;
    uint64_t last = 0;
    /* The buckets as ONE blob, written on every observation — an older
     * node's "none" replaces the previous server's figures (exp_chain.h). */
    uint8_t buckets[EXP_SUPPLY_BUCKETS_BLOB_LEN];
    exp_supply_buckets_pack(&tip.buckets, buckets);
    /* The active stake (display only): read now, on the server that gave
     * the accepted observation, outside the lock (a network round trip);
     * a failure is stored as "unknown" (has 0), never a stale or zero
     * figure, and does not stop indexing. */
    exp_active_stake_t stake;
    memset(&stake, 0, sizeof(stake));
    if (src->stake) {
        if (src->stake(src->ctx, &stake) == 0 && stake.has) {
            stake.at_tip = tip.tip;
        } else {
            QGP_LOG_WARN(LOG_TAG, "%s", "active stake read failed — stored as unknown (display only)");
            memset(&stake, 0, sizeof(stake));
        }
    }
    uint8_t stake_blob[EXP_ACTIVE_STAKE_BLOB_LEN];
    exp_active_stake_pack(&stake, stake_blob);
    if (db_lock) pthread_rwlock_wrlock(db_lock);
    if (exp_db_set_meta_u64(db, "tip_height", tip.tip) != 0 ||
        exp_db_set_meta_u64(db, "supply_current", tip.supply_current) != 0 ||
        exp_db_set_meta_u64(db, "supply_burned", tip.supply_burned) != 0 ||
        exp_db_set_meta_u64(db, "supply_genesis", tip.supply_genesis) != 0 ||
        exp_db_set_meta_blob(db, EXP_META_SUPPLY_BUCKETS, buckets,
                             sizeof(buckets)) != 0 ||
        exp_db_set_meta_blob(db, EXP_META_ACTIVE_STAKE, stake_blob,
                             sizeof(stake_blob)) != 0) {
        QGP_LOG_WARN(LOG_TAG, "failed to persist tip/supply meta (display only)");
    }
    if (exp_db_get_meta_u64(db, "last_indexed_height", &last) != 0) last = 0;
    if (db_lock) pthread_rwlock_unlock(db_lock);

    uint64_t h = last + 1;
    for (unsigned done = 0; h <= tip.tip; h++, done++) {
        if (done >= EXP_SYNC_MAX_HEIGHTS_PER_TICK) return 1;

        exp_block_batch_t batch;
        exp_block_batch_init(&batch);
        if (exp_sync_collect_block(src, h, &batch) != 0) {
            exp_block_batch_free(&batch);
            QGP_LOG_ERROR(LOG_TAG, "height %llu not collected — watermark stays at %llu",
                          (unsigned long long)h, (unsigned long long)(h - 1));
            return -1;
        }

        if (db_lock) pthread_rwlock_wrlock(db_lock);
        int wrc = exp_db_write_height(db, &batch);
        if (db_lock) pthread_rwlock_unlock(db_lock);
        exp_block_batch_free(&batch);

        if (wrc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "height %llu not written — watermark stays at %llu",
                          (unsigned long long)h, (unsigned long long)(h - 1));
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

    exp_sync_source_t src;
    exp_sync_source_chain(&src, a->chain);

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    /* The HTTP thread may already be serving: preseed reads through the
     * shared stmt_get_meta (see exp_sync_tick's meta span). */
    if (a->db_lock) pthread_rwlock_wrlock(a->db_lock);
    exp_sync_preseed(*a->db, &fsm);
    if (a->db_lock) pthread_rwlock_unlock(a->db_lock);

    QGP_LOG_INFO(LOG_TAG, "sync thread started (poll interval %d s)", EXP_SYNC_POLL_SECONDS);

    while (!*a->stop) {
        int rc = exp_sync_tick(&src, a->db, a->db_path, &fsm, a->db_lock);
        if (rc < 0) {
            QGP_LOG_WARN(LOG_TAG, "sync tick failed — retrying next poll");
        }
        if (rc == 1) continue;   /* more heights to index — no poll sleep */

        for (int waited = 0; waited < EXP_SYNC_POLL_SECONDS && !*a->stop; waited++) {
            sleep(1);
        }
    }

    QGP_LOG_INFO(LOG_TAG, "sync thread stopping");
    return NULL;
}
