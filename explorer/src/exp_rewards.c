#include "exp_rewards.h"

#include <limits.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

struct exp_rewards {
    sqlite3 *db;
    uint64_t from_height;
    uint64_t at_height;
    unsigned progress_calls;
};

static int rewards_progress(void *ctx) {
    exp_rewards_t *r = ctx;
    return ++r->progress_calls >= EXP_REWARDS_VM_BUDGET / 1000;
}

static int rewards_u64(sqlite3_stmt *s, int col, uint64_t max, uint64_t *out) {
    if (sqlite3_column_type(s, col) != SQLITE_INTEGER) return -1;
    sqlite3_int64 v = sqlite3_column_int64(s, col);
    if (v < 0 || (uint64_t)v > max) return -1;
    *out = (uint64_t)v;
    return 0;
}

static int rewards_blob64(sqlite3_stmt *s, int col, uint8_t out[64]) {
    if (sqlite3_column_type(s, col) != SQLITE_BLOB ||
        sqlite3_column_bytes(s, col) != 64) return -1;
    const void *b = sqlite3_column_blob(s, col);
    if (!b) return -1;
    memcpy(out, b, 64);
    return 0;
}

int exp_rewards_open(const char *path, const exp_block_row_t *anchor,
                     exp_rewards_t **out) {
    if (!out) return -1;
    *out = NULL;
    if (!path || !*path || !anchor || !anchor->height ||
        anchor->height > INT64_MAX || strncmp(path, "file:", 5) == 0)
        return -1;
    exp_rewards_t *r = calloc(1, sizeof(*r));
    if (!r) return -1;
    sqlite3_stmt *s = NULL;
    uint8_t id[64];
    uint64_t last = 0;
    if (sqlite3_open_v2(path, &r->db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
                        NULL) != SQLITE_OK) goto fail;
    sqlite3_progress_handler(r->db, 1000, rewards_progress, r);
    /* No busy retries: this display endpoint fails honestly if unavailable. */
    if (sqlite3_exec(r->db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) goto fail;
    if (sqlite3_prepare_v2(r->db,
            "SELECT block_id FROM v2_blocks WHERE global_height=?1",
            -1, &s, NULL) != SQLITE_OK) goto fail;
    sqlite3_bind_int64(s, 1, (sqlite3_int64)anchor->height);
    if (sqlite3_step(s) != SQLITE_ROW || rewards_blob64(s, 0, id) != 0 ||
        memcmp(id, anchor->block_id, 64) != 0 ||
        sqlite3_step(s) != SQLITE_DONE) goto fail;
    sqlite3_finalize(s); s = NULL;
    if (sqlite3_prepare_v2(r->db,
            "SELECT global_height FROM v2_blocks ORDER BY global_height DESC LIMIT 1",
            -1, &s, NULL) != SQLITE_OK) goto fail;
    if (sqlite3_step(s) != SQLITE_ROW ||
        rewards_u64(s, 0, INT64_MAX, &r->at_height) != 0 ||
        r->at_height < anchor->height || sqlite3_step(s) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(s); s = NULL;
    if (sqlite3_prepare_v2(r->db,
            "SELECT from_height,last_height FROM addr_history_mark WHERE id=1",
            -1, &s, NULL) != SQLITE_OK) goto fail;
    if (sqlite3_step(s) != SQLITE_ROW ||
        rewards_u64(s, 0, INT64_MAX, &r->from_height) != 0 ||
        rewards_u64(s, 1, INT64_MAX, &last) != 0 ||
        !r->from_height || r->from_height > last || last != r->at_height ||
        sqlite3_step(s) != SQLITE_DONE) goto fail;
    sqlite3_finalize(s);
    *out = r;
    return 0;
fail:
    sqlite3_finalize(s);
    exp_rewards_close(r);
    return -1;
}

void exp_rewards_close(exp_rewards_t *r) {
    if (!r) return;
    if (r->db) {
        sqlite3_progress_handler(r->db, 0, NULL, NULL);
        sqlite3_exec(r->db, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_close(r->db);
    }
    free(r);
}

uint64_t exp_rewards_from_height(const exp_rewards_t *r) {
    return r ? r->from_height : 0;
}

uint64_t exp_rewards_at_height(const exp_rewards_t *r) {
    return r ? r->at_height : 0;
}

/* Every selected payout is a native boundary row. No implicit SQLite
 * conversions: corrupt/NULL/overflowing data makes the request unavailable. */
static int rewards_row(sqlite3_stmt *s, exp_payout_t *p) {
    uint64_t i = 0, seq = 0, seconds = 0;
    uint8_t token[64], native[64] = {0};
    if (rewards_u64(s, 0, INT64_MAX, &p->height) != 0 || !p->height ||
        rewards_u64(s, 1, UINT32_MAX, &i) != 0 || i != UINT32_MAX ||
        rewards_u64(s, 2, UINT32_MAX, &seq) != 0 ||
        rewards_blob64(s, 3, p->owner) != 0 ||
        rewards_u64(s, 4, INT64_MAX, &p->amount) != 0 ||
        rewards_blob64(s, 5, token) != 0 || memcmp(token, native, 64) != 0 ||
        rewards_u64(s, 6, INT64_MAX / 1000, &seconds) != 0)
        return -1;
    p->sequence = (uint32_t)seq;
    p->time_ms = seconds * 1000;
    return 0;
}

static int rewards_add(exp_rewards_page_t *out, const exp_payout_t *p) {
    if (UINT64_MAX - out->total < p->amount || out->recipients == UINT64_MAX)
        return -1;
    out->total += p->amount;
    out->recipients++;
    return 0;
}

int exp_rewards_payday(exp_rewards_t *r, uint64_t height, uint32_t from,
                       int limit, exp_rewards_page_t *out) {
    if (!r || !out || limit < 0 || limit > EXP_REWARDS_MAX ||
        height < r->from_height || height > r->at_height) return -1;
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *s = NULL;
    /* Primary-key h range: never a scan of the entire history table. */
    if (sqlite3_prepare_v2(r->db,
            "SELECT h,i,seq,owner,amount,token,ts FROM addr_history "
            "WHERE h=?1 AND kind='payout' ORDER BY i,seq", -1, &s, NULL)
        != SQLITE_OK) return -1;
    sqlite3_bind_int64(s, 1, (sqlite3_int64)height);
    int rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
        exp_payout_t p;
        if (rewards_row(s, &p) != 0 || rewards_add(out, &p) != 0) goto fail;
        if (limit && p.sequence >= from) {
            if (out->count < limit) out->rows[out->count++] = p;
            else if (!out->has_next) {
                out->has_next = 1;
                out->next_from = p.sequence;
            }
        }
    }
    sqlite3_finalize(s);
    return rc == SQLITE_DONE ? 0 : -1;
fail:
    sqlite3_finalize(s);
    return -1;
}

int exp_rewards_address(exp_rewards_t *r, const uint8_t owner[64],
                        uint64_t before_h, uint32_t before_seq, int limit,
                        exp_rewards_page_t *out) {
    if (!r || !owner || !out || limit < 1 || limit > EXP_REWARDS_MAX ||
        before_h > INT64_MAX) return -1;
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *s = NULL;
    /* A single owner-index range supplies BOTH the exact paid total and
     * requested page. The VM budget bounds an address with huge history;
     * exhaustion is 503, never a partial total or a false zero. */
    if (sqlite3_prepare_v2(r->db,
            "SELECT h,i,seq,owner,amount,token,ts FROM addr_history "
            "INDEXED BY idx_addr_history_owner "
            "WHERE owner=?1 AND h>=?2 AND h<=?3 AND kind='payout' "
            "ORDER BY h DESC,i DESC,seq DESC", -1, &s, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(s, 1, owner, 64, SQLITE_STATIC);
    sqlite3_bind_int64(s, 2, (sqlite3_int64)r->from_height);
    sqlite3_bind_int64(s, 3, (sqlite3_int64)r->at_height);
    int rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
        exp_payout_t p;
        if (rewards_row(s, &p) != 0 || rewards_add(out, &p) != 0) goto fail;
        if (!before_h || p.height < before_h ||
            (p.height == before_h && p.sequence < before_seq)) {
            if (out->count < limit) out->rows[out->count++] = p;
            else out->has_next = 1;
        }
    }
    sqlite3_finalize(s); s = NULL;
    if (rc != SQLITE_DONE) return -1;
    if (sqlite3_prepare_v2(r->db,
            "SELECT amount FROM v2_reward_accrual WHERE owner_fp=?1",
            -1, &s, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(s, 1, owner, 64, SQLITE_STATIC);
    rc = sqlite3_step(s);
    if (rc == SQLITE_ROW) {
        if (rewards_u64(s, 0, INT64_MAX, &out->pending) != 0) goto fail;
        rc = sqlite3_step(s);
    }
    sqlite3_finalize(s);
    return rc == SQLITE_DONE ? 0 : -1;
fail:
    sqlite3_finalize(s);
    return -1;
}
