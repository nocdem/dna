/**
 * @file shared/dnac/cmt_light_store.c
 * @brief cometbft @v0.38.26 `light/store/db/db.go` over SQLite — see
 *        cmt_light_store.h for the mapping, the deviations D1-D8 and the
 *        taşınmadı list.
 *
 * NOTHING HERE READS A CLOCK, DRAWS RANDOMNESS OR ITERATES A MAP. Every
 * query that picks a row by position says ORDER BY height.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_light_store.h"

#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CMT_LIGHT_STORE"

struct cmt_light_store_db {
    sqlite3  *db;
    uint8_t   prefix[CMT_LIGHT_STORE_PREFIX_MAX];
    size_t    prefix_len;
    uint64_t  block_protocol;   /* D8 */
    uint64_t  size;             /* db.go:24 — 64-bit (D1); equals the file's */
};

/* ══════════════════════════════════════════════════════════════════════
 * SQLite helpers. Every failure is logged and becomes CMT_FAULT (header,
 * THE MAPPING).
 * ══════════════════════════════════════════════════════════════════════ */

static const char SQL_CREATE_BLOCK[] =
    "CREATE TABLE IF NOT EXISTS cmt_light_block ("
    " prefix BLOB NOT NULL,"
    " height INTEGER NOT NULL,"
    " value  BLOB NOT NULL,"
    " PRIMARY KEY (prefix, height))";

static const char SQL_CREATE_SIZE[] =
    "CREATE TABLE IF NOT EXISTS cmt_light_size ("
    " prefix BLOB NOT NULL PRIMARY KEY,"
    " size   INTEGER NOT NULL)";

static int db_exec(cmt_light_store_db_t *s, const char *sql)
{
    char *msg = NULL;

    if (sqlite3_exec(s->db, sql, NULL, NULL, &msg) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "exec failed: %s", msg != NULL ? msg : "?");
        sqlite3_free(msg);
        return CMT_FAULT;
    }
    return CMT_OK;
}

static int db_prepare(cmt_light_store_db_t *s, const char *sql,
                      sqlite3_stmt **st)
{
    if (sqlite3_prepare_v2(s->db, sql, -1, st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "prepare failed: %s", sqlite3_errmsg(s->db));
        *st = NULL;
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* The prefix as a BLOB. `s->prefix` is an array, never NULL, so the
 * empty prefix binds as a zero-length BLOB — not as SQL NULL. */
static int bind_prefix(cmt_light_store_db_t *s, sqlite3_stmt *st, int idx)
{
    if (sqlite3_bind_blob(st, idx, s->prefix, (int)s->prefix_len,
                          SQLITE_STATIC) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "bind failed: %s", sqlite3_errmsg(s->db));
        return CMT_FAULT;
    }
    return CMT_OK;
}

static int bind_i64(cmt_light_store_db_t *s, sqlite3_stmt *st, int idx,
                    int64_t v)
{
    if (sqlite3_bind_int64(st, idx, (sqlite3_int64)v) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "bind failed: %s", sqlite3_errmsg(s->db));
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* Run a statement that returns no row. */
static int step_done(cmt_light_store_db_t *s, sqlite3_stmt *st)
{
    if (sqlite3_step(st) != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "step failed: %s", sqlite3_errmsg(s->db));
        return CMT_FAULT;
    }
    return CMT_OK;
}

static int tx_begin(cmt_light_store_db_t *s)
{
    return db_exec(s, "BEGIN IMMEDIATE");
}

static int tx_commit(cmt_light_store_db_t *s)
{
    return db_exec(s, "COMMIT");
}

static void tx_rollback(cmt_light_store_db_t *s)
{
    char *msg = NULL;

    /* A failed ROLLBACK leaves nothing to undo that SQLite would keep:
     * an open transaction is rolled back when the connection closes. */
    if (sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, &msg) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "rollback failed: %s",
                      msg != NULL ? msg : "?");
    }
    sqlite3_free(msg);
}

/* The stored count for this prefix. `*present` false when no row. */
static int read_count(cmt_light_store_db_t *s, int64_t *out, bool *present)
{
    sqlite3_stmt *st = NULL;
    int           rc;
    int           sr;

    *present = false;
    *out     = 0;
    rc = db_prepare(s, "SELECT size FROM cmt_light_size WHERE prefix = ?1",
                    &st);
    if (rc == CMT_OK) {
        rc = bind_prefix(s, st, 1);
    }
    if (rc == CMT_OK) {
        sr = sqlite3_step(st);
        if (sr == SQLITE_ROW) {
            *out     = (int64_t)sqlite3_column_int64(st, 0);
            *present = true;
        } else if (sr != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG, "step failed: %s", sqlite3_errmsg(s->db));
            rc = CMT_FAULT;
        }
    }
    sqlite3_finalize(st);
    return rc;
}

/* The number of rows this prefix holds. */
static int count_rows(cmt_light_store_db_t *s, int64_t *out)
{
    sqlite3_stmt *st = NULL;
    int           rc;

    *out = 0;
    rc = db_prepare(s, "SELECT COUNT(*) FROM cmt_light_block WHERE prefix = ?1",
                    &st);
    if (rc == CMT_OK) {
        rc = bind_prefix(s, st, 1);
    }
    if (rc == CMT_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            *out = (int64_t)sqlite3_column_int64(st, 0);
        } else {
            QGP_LOG_ERROR(LOG_TAG, "step failed: %s", sqlite3_errmsg(s->db));
            rc = CMT_FAULT;
        }
    }
    sqlite3_finalize(st);
    return rc;
}

/* Write the count for this prefix (inside the caller's transaction). */
static int write_count(cmt_light_store_db_t *s, uint64_t size)
{
    sqlite3_stmt *st = NULL;
    int           rc;

    if (size > (uint64_t)INT64_MAX) {
        return CMT_FAULT;   /* an SQLite INTEGER is int64 */
    }
    rc = db_prepare(s, "INSERT OR REPLACE INTO cmt_light_size (prefix, size)"
                       " VALUES (?1, ?2)", &st);
    if (rc == CMT_OK) {
        rc = bind_prefix(s, st, 1);
    }
    if (rc == CMT_OK) {
        rc = bind_i64(s, st, 2, (int64_t)size);
    }
    if (rc == CMT_OK) {
        rc = step_done(s, st);
    }
    sqlite3_finalize(st);
    return rc;
}

/* The height chosen by a `SELECT height … LIMIT 1` with prefix as ?1 and,
 * when `bound` is non-NULL, *bound as ?2. `*found` false when none. */
static int select_height(cmt_light_store_db_t *s, const char *sql,
                         const int64_t *bound, int64_t *out, bool *found)
{
    sqlite3_stmt *st = NULL;
    int           rc;
    int           sr;

    *found = false;
    *out   = 0;
    rc = db_prepare(s, sql, &st);
    if (rc == CMT_OK) {
        rc = bind_prefix(s, st, 1);
    }
    if (rc == CMT_OK && bound != NULL) {
        rc = bind_i64(s, st, 2, *bound);
    }
    if (rc == CMT_OK) {
        sr = sqlite3_step(st);
        if (sr == SQLITE_ROW) {
            *out   = (int64_t)sqlite3_column_int64(st, 0);
            *found = true;
        } else if (sr != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG, "step failed: %s", sqlite3_errmsg(s->db));
            rc = CMT_FAULT;
        }
    }
    sqlite3_finalize(st);
    return rc;
}

/* ══════════════════════════════════════════════════════════════════════
 * db.go:27-37 — New
 * ══════════════════════════════════════════════════════════════════════ */

int cmt_light_store_db_open(const char *path,
                            const uint8_t *prefix, size_t prefix_len,
                            uint64_t block_protocol,
                            cmt_light_store_db_t **out)
{
    cmt_light_store_db_t *s;
    int64_t               stored = 0;
    int64_t               rows   = 0;
    bool                  present = false;
    int                   rc;

    if (out != NULL) {
        *out = NULL;
    }
    if (path == NULL || out == NULL || (prefix == NULL && prefix_len != 0u)) {
        return CMT_FAULT;
    }
    if (prefix_len > (size_t)CMT_LIGHT_STORE_PREFIX_MAX) {
        return CMT_REJECT;
    }
    s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return CMT_FAULT;
    }
    if (prefix_len != 0u) {
        memcpy(s->prefix, prefix, prefix_len);
    }
    s->prefix_len     = prefix_len;
    s->block_protocol = block_protocol;

    if (sqlite3_open_v2(path, &s->db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                        NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "open %s failed: %s", path,
                      s->db != NULL ? sqlite3_errmsg(s->db) : "out of memory");
        sqlite3_close(s->db);
        free(s);
        return CMT_FAULT;
    }

    /* WriteSync durability (header, THE MAPPING). */
    rc = db_exec(s, "PRAGMA synchronous=FULL");
    if (rc == CMT_OK) {
        rc = db_exec(s, SQL_CREATE_BLOCK);
    }
    if (rc == CMT_OK) {
        rc = db_exec(s, SQL_CREATE_SIZE);
    }
    if (rc == CMT_OK) {
        rc = tx_begin(s);
        if (rc == CMT_OK) {
            /* :30-34 — read the stored size; D6 — check it. */
            rc = read_count(s, &stored, &present);
            if (rc == CMT_OK) {
                rc = count_rows(s, &rows);
            }
            if (rc == CMT_OK) {
                if (!present && rows == 0) {
                    rc = write_count(s, 0u);       /* a fresh prefix */
                } else if (!present || stored < 0 || stored != rows) {
                    QGP_LOG_ERROR(LOG_TAG, "stored count %lld does not match "
                                  "%lld rows", (long long)stored,
                                  (long long)rows);
                    rc = CMT_REJECT;               /* D6 */
                }
            }
            if (rc == CMT_OK) {
                rc = tx_commit(s);
            } else {
                tx_rollback(s);
            }
        }
    }
    if (rc != CMT_OK) {
        sqlite3_close(s->db);
        free(s);
        return rc;
    }
    s->size = (uint64_t)rows;
    *out = s;
    return CMT_OK;
}

void cmt_light_store_db_close(cmt_light_store_db_t *s)
{
    if (s == NULL) {
        return;
    }
    if (sqlite3_close(s->db) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "close failed: %s", sqlite3_errmsg(s->db));
    }
    free(s);
}

/* ══════════════════════════════════════════════════════════════════════
 * db.go:39-74 — SaveLightBlock
 * ══════════════════════════════════════════════════════════════════════ */

int cmt_light_store_db_save_light_block(cmt_light_store_db_t *s,
                                        const cmt_light_block_t *lb)
{
    sqlite3_stmt *st  = NULL;
    uint8_t      *bz  = NULL;
    size_t        bz_len = 0u;
    int64_t       height;
    bool          added = false;
    int           rc;

    if (s == NULL || lb == NULL || lb->signed_header == NULL ||
        lb->signed_header->header == NULL) {
        return CMT_FAULT;   /* :43 dereferences lb.SignedHeader.Header */
    }
    height = lb->signed_header->header->height;
    if (height <= 0) {
        return CMT_FAULT;   /* :43-45 "negative or zero height" */
    }

    rc = cmt_light_block_encode(lb, &bz, &bz_len);          /* :47-55 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (bz_len > (size_t)INT_MAX) {
        free(bz);
        return CMT_REJECT;  /* sqlite3_bind_blob takes an int length */
    }
    if (s->size >= (uint64_t)INT64_MAX) {
        free(bz);
        return CMT_REJECT;  /* the count would not fit an SQLite INTEGER */
    }

    rc = tx_begin(s);                                       /* :60 */
    if (rc != CMT_OK) {
        free(bz);
        return rc;
    }
    /* :62 — `b.Set(lbKey(height), lbBz)`. D2: a NEW height is inserted
     * and counted; an existing one is REPLACED and not counted. */
    rc = db_prepare(s, "INSERT OR IGNORE INTO cmt_light_block"
                       " (prefix, height, value) VALUES (?1, ?2, ?3)", &st);
    if (rc == CMT_OK) {
        rc = bind_prefix(s, st, 1);
    }
    if (rc == CMT_OK) {
        rc = bind_i64(s, st, 2, height);
    }
    if (rc == CMT_OK &&
        sqlite3_bind_blob(st, 3, bz, (int)bz_len, SQLITE_STATIC) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "bind failed: %s", sqlite3_errmsg(s->db));
        rc = CMT_FAULT;
    }
    if (rc == CMT_OK) {
        rc = step_done(s, st);
    }
    if (rc == CMT_OK) {
        added = sqlite3_changes(s->db) == 1;
    }
    sqlite3_finalize(st);
    st = NULL;

    if (rc == CMT_OK && !added) {
        rc = db_prepare(s, "UPDATE cmt_light_block SET value = ?3"
                           " WHERE prefix = ?1 AND height = ?2", &st);
        if (rc == CMT_OK) {
            rc = bind_prefix(s, st, 1);
        }
        if (rc == CMT_OK) {
            rc = bind_i64(s, st, 2, height);
        }
        if (rc == CMT_OK &&
            sqlite3_bind_blob(st, 3, bz, (int)bz_len, SQLITE_STATIC)
                != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "bind failed: %s", sqlite3_errmsg(s->db));
            rc = CMT_FAULT;
        }
        if (rc == CMT_OK) {
            rc = step_done(s, st);
        }
        sqlite3_finalize(st);
        st = NULL;
    }

    /* :65 — the count, in the SAME transaction (D3), +1 only if added. */
    if (rc == CMT_OK && added) {
        rc = write_count(s, s->size + 1u);
    }
    if (rc == CMT_OK) {
        rc = tx_commit(s);                                  /* :68 */
    } else {
        tx_rollback(s);
    }
    free(bz);
    if (rc != CMT_OK) {
        return rc;
    }
    if (added) {
        s->size++;                                          /* :71 */
    }
    return CMT_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * db.go:76-102 — DeleteLightBlock
 * ══════════════════════════════════════════════════════════════════════ */

int cmt_light_store_db_delete_light_block(cmt_light_store_db_t *s,
                                          int64_t height)
{
    sqlite3_stmt *st = NULL;
    uint64_t      removed = 0u;
    int           rc;

    if (s == NULL || height <= 0) {
        return CMT_FAULT;   /* :81-83 "negative or zero height" */
    }
    rc = tx_begin(s);                                       /* :88 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = db_prepare(s, "DELETE FROM cmt_light_block"
                       " WHERE prefix = ?1 AND height = ?2", &st);   /* :90 */
    if (rc == CMT_OK) {
        rc = bind_prefix(s, st, 1);
    }
    if (rc == CMT_OK) {
        rc = bind_i64(s, st, 2, height);
    }
    if (rc == CMT_OK) {
        rc = step_done(s, st);
    }
    if (rc == CMT_OK) {
        removed = (uint64_t)sqlite3_changes(s->db);
    }
    sqlite3_finalize(st);

    /* :93 — D4: the count moves by the rows actually deleted. */
    if (rc == CMT_OK && removed > s->size) {
        rc = CMT_FAULT;     /* the D6 invariant does not hold */
    }
    if (rc == CMT_OK && removed != 0u) {
        rc = write_count(s, s->size - removed);
    }
    if (rc == CMT_OK) {
        rc = tx_commit(s);                                  /* :96 */
    } else {
        tx_rollback(s);
    }
    if (rc != CMT_OK) {
        return rc;
    }
    s->size -= removed;                                     /* :99 */
    return CMT_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * db.go:104-132 — LightBlock
 * ══════════════════════════════════════════════════════════════════════ */

int cmt_light_store_db_light_block(cmt_light_store_db_t *s, int64_t height,
                                   cmt_light_block_buf_t *out, bool *found)
{
    sqlite3_stmt  *st = NULL;
    const uint8_t *bz;
    int            bz_len;
    int            sr;
    int            rc;

    if (found != NULL) {
        *found = false;
    }
    if (s == NULL || out == NULL || found == NULL || height <= 0) {
        return CMT_FAULT;   /* :108-110 "negative or zero height" */
    }
    rc = cmt_light_block_buf_reset(out);
    if (rc != CMT_OK) {
        return rc;
    }

    rc = db_prepare(s, "SELECT value FROM cmt_light_block"
                       " WHERE prefix = ?1 AND height = ?2", &st);  /* :112 */
    if (rc == CMT_OK) {
        rc = bind_prefix(s, st, 1);
    }
    if (rc == CMT_OK) {
        rc = bind_i64(s, st, 2, height);
    }
    if (rc != CMT_OK) {
        sqlite3_finalize(st);
        return rc;
    }
    sr = sqlite3_step(st);
    if (sr == SQLITE_DONE) {
        sqlite3_finalize(st);
        return CMT_OK;      /* :116-118 ErrLightBlockNotFound */
    }
    if (sr != SQLITE_ROW) {
        QGP_LOG_ERROR(LOG_TAG, "step failed: %s", sqlite3_errmsg(s->db));
        sqlite3_finalize(st);
        return CMT_FAULT;   /* :113-115 panic(err) */
    }
    bz     = (const uint8_t *)sqlite3_column_blob(st, 0);
    bz_len = sqlite3_column_bytes(st, 0);
    if (bz_len <= 0 || bz == NULL) {
        sqlite3_finalize(st);
        return CMT_OK;      /* :116 `len(bz) == 0` — not found */
    }

    /* :120-129 — Unmarshal + LightBlockFromProto, bounded by the row. The
     * decode copies everything into `out`, so the column memory may go. */
    rc = cmt_light_block_decode(bz, (size_t)bz_len, s->block_protocol, out);
    sqlite3_finalize(st);
    if (rc != CMT_OK) {
        (void)cmt_light_block_buf_reset(out);
        return rc;          /* :122-124, :127-129 */
    }

    /* D7 — the row must be the height it is stored under. */
    if (out->lb.signed_header == NULL ||
        out->lb.signed_header->header == NULL ||
        out->lb.signed_header->header->height != height) {
        QGP_LOG_ERROR(LOG_TAG, "row at height %lld does not hold that height",
                      (long long)height);
        (void)cmt_light_block_buf_reset(out);
        return CMT_REJECT;
    }
    *found = true;
    return CMT_OK;                                          /* :131 */
}

/* ══════════════════════════════════════════════════════════════════════
 * db.go:134-182 — LastLightBlockHeight / FirstLightBlockHeight
 * ══════════════════════════════════════════════════════════════════════ */

/* :138-141 / :163-166 iterate [lbKey(1), lbKey(MaxInt64)]: heights >= 1. */
int cmt_light_store_db_last_light_block_height(cmt_light_store_db_t *s,
                                               int64_t *out)
{
    bool found = false;
    int  rc;

    if (s == NULL || out == NULL) {
        return CMT_FAULT;
    }
    rc = select_height(s, "SELECT height FROM cmt_light_block"
                          " WHERE prefix = ?1 AND height >= 1"
                          " ORDER BY height DESC LIMIT 1", NULL, out, &found);
    if (rc != CMT_OK) {
        return rc;          /* :142-144 panic(err) */
    }
    if (!found) {
        *out = -1;          /* :156 */
    }
    return CMT_OK;
}

int cmt_light_store_db_first_light_block_height(cmt_light_store_db_t *s,
                                                int64_t *out)
{
    bool found = false;
    int  rc;

    if (s == NULL || out == NULL) {
        return CMT_FAULT;
    }
    rc = select_height(s, "SELECT height FROM cmt_light_block"
                          " WHERE prefix = ?1 AND height >= 1"
                          " ORDER BY height ASC LIMIT 1", NULL, out, &found);
    if (rc != CMT_OK) {
        return rc;          /* :167-169 panic(err) */
    }
    if (!found) {
        *out = -1;          /* :181 */
    }
    return CMT_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * db.go:184-215 — LightBlockBefore
 * ══════════════════════════════════════════════════════════════════════ */

int cmt_light_store_db_light_block_before(cmt_light_store_db_t *s,
                                          int64_t height,
                                          cmt_light_block_buf_t *out,
                                          bool *found)
{
    int64_t existing = 0;
    bool    any      = false;
    int     rc;

    if (found != NULL) {
        *found = false;
    }
    if (s == NULL || out == NULL || found == NULL || height <= 0) {
        return CMT_FAULT;   /* :189-191 "negative or zero height" */
    }
    rc = cmt_light_block_buf_reset(out);
    if (rc != CMT_OK) {
        return rc;
    }
    /* :193-196 — ReverseIterator(lbKey(1), lbKey(height)): [1, height). */
    rc = select_height(s, "SELECT height FROM cmt_light_block"
                          " WHERE prefix = ?1 AND height >= 1 AND height < ?2"
                          " ORDER BY height DESC LIMIT 1",
                       &height, &existing, &any);
    if (rc != CMT_OK) {
        return rc;          /* :197-199 panic(err), :210-212 */
    }
    if (!any) {
        return CMT_OK;      /* :214 ErrLightBlockNotFound */
    }
    return cmt_light_store_db_light_block(s, existing, out, found); /* :206 */
}

/* ══════════════════════════════════════════════════════════════════════
 * db.go:217-278 — Prune
 * ══════════════════════════════════════════════════════════════════════ */

int cmt_light_store_db_prune(cmt_light_store_db_t *s, uint64_t size)
{
    sqlite3_stmt *st = NULL;
    uint64_t      to_prune;
    uint64_t      pruned = 0u;
    int           rc;

    if (s == NULL) {
        return CMT_FAULT;
    }
    if (s->size <= size) {
        return CMT_OK;      /* :227-229 "nothing to prune" */
    }
    to_prune = s->size - size;                              /* :230 */

    rc = tx_begin(s);                                       /* :242 */
    if (rc != CMT_OK) {
        return rc;
    }
    /* :233-257 — the OLDEST first (the ascending iterator). One DELETE
     * per INT_MAX rows, because sqlite3_changes reports an int; all of
     * them inside the one transaction. */
    while (rc == CMT_OK && pruned < to_prune) {
        uint64_t chunk = to_prune - pruned;
        uint64_t got;

        if (chunk > (uint64_t)INT_MAX) {
            chunk = (uint64_t)INT_MAX;
        }
        rc = db_prepare(s, "DELETE FROM cmt_light_block WHERE prefix = ?1"
                           " AND height IN (SELECT height FROM cmt_light_block"
                           " WHERE prefix = ?1 AND height >= 1"
                           " ORDER BY height ASC LIMIT ?2)", &st);
        if (rc == CMT_OK) {
            rc = bind_prefix(s, st, 1);
        }
        if (rc == CMT_OK) {
            rc = bind_i64(s, st, 2, (int64_t)chunk);
        }
        if (rc == CMT_OK) {
            rc = step_done(s, st);
        }
        sqlite3_finalize(st);
        st = NULL;
        if (rc != CMT_OK) {
            break;
        }
        got = (uint64_t)sqlite3_changes(s->db);
        pruned += got;
        if (got < chunk) {
            break;          /* no more rows; the D6 invariant says none */
        }
    }
    /* :267-275 — D3: the count in the SAME transaction; D4: by the rows
     * actually deleted. */
    if (rc == CMT_OK && pruned > s->size) {
        rc = CMT_FAULT;
    }
    if (rc == CMT_OK) {
        rc = write_count(s, s->size - pruned);
    }
    if (rc == CMT_OK) {
        rc = tx_commit(s);                                  /* :262 */
    } else {
        tx_rollback(s);
    }
    if (rc != CMT_OK) {
        return rc;
    }
    s->size -= pruned;                                      /* :271 */
    return CMT_OK;
}

/* db.go:280-287 — Size */
int cmt_light_store_db_size(cmt_light_store_db_t *s, uint64_t *out)
{
    if (s == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = s->size;                                         /* :286 */
    return CMT_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * The Store table (store.go:5-48) over this implementation
 * ══════════════════════════════════════════════════════════════════════ */

static int vt_save(void *ctx, const cmt_light_block_t *lb)
{
    return cmt_light_store_db_save_light_block(ctx, lb);
}

static int vt_delete(void *ctx, int64_t height)
{
    return cmt_light_store_db_delete_light_block(ctx, height);
}

static int vt_light_block(void *ctx, int64_t height,
                          cmt_light_block_buf_t *out, bool *found)
{
    return cmt_light_store_db_light_block(ctx, height, out, found);
}

static int vt_last(void *ctx, int64_t *out)
{
    return cmt_light_store_db_last_light_block_height(ctx, out);
}

static int vt_first(void *ctx, int64_t *out)
{
    return cmt_light_store_db_first_light_block_height(ctx, out);
}

static int vt_before(void *ctx, int64_t height,
                     cmt_light_block_buf_t *out, bool *found)
{
    return cmt_light_store_db_light_block_before(ctx, height, out, found);
}

static int vt_prune(void *ctx, uint64_t size)
{
    return cmt_light_store_db_prune(ctx, size);
}

static int vt_size(void *ctx, uint64_t *out)
{
    return cmt_light_store_db_size(ctx, out);
}

void cmt_light_store_db_bind(cmt_light_store_db_t *s, cmt_light_store_t *out)
{
    if (out == NULL) {
        return;
    }
    out->ctx                      = s;
    out->save_light_block         = vt_save;
    out->delete_light_block       = vt_delete;
    out->light_block              = vt_light_block;
    out->last_light_block_height  = vt_last;
    out->first_light_block_height = vt_first;
    out->light_block_before       = vt_before;
    out->prune                    = vt_prune;
    out->size                     = vt_size;
}
