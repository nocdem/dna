/**
 * @file faucet_journal.c
 * @brief nodus-faucet durable journal (see faucet_journal.h).
 *
 * "A DB failure is never a value" (nodus/CLAUDE.md): every bind and every
 * column extraction is checked; a column of the wrong type, a NULL text, a
 * text that does not fit its field or a blob of the wrong length is a
 * FAULT (-1) of the read, never an empty or zero field.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE                 /* pthread_mutex_clocklock */
#endif
#include "faucet_journal.h"

#include <errno.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "FAUCET_JNL"

#define SCHEMA_VERSION 1

struct faucet_journal {
    sqlite3        *db;
    pthread_mutex_t mu;
    char            path[512];
    uint64_t        ceiling;
};

static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS claims("
    " seq INTEGER PRIMARY KEY AUTOINCREMENT,"
    " claim_id TEXT NOT NULL UNIQUE,"
    " kind TEXT NOT NULL CHECK(kind IN ('full','start')),"
    " address TEXT NOT NULL,"
    " name TEXT NOT NULL DEFAULT '',"
    " state TEXT NOT NULL CHECK(state IN "
    "('planned','paused','signed','submitted','confirmed','expired','unknown')),"
    " message TEXT NOT NULL DEFAULT '');"
    "CREATE INDEX IF NOT EXISTS claims_addr ON claims(address);"
    "CREATE TABLE IF NOT EXISTS paid("
    " marker TEXT PRIMARY KEY,"
    " claim_seq INTEGER NOT NULL);"
    "CREATE TABLE IF NOT EXISTS attempts("
    " claim_seq INTEGER NOT NULL,"
    " n INTEGER NOT NULL,"
    " env BLOB NOT NULL,"
    " wire_id BLOB NOT NULL,"
    " intent_id BLOB NOT NULL,"
    " inputs BLOB NOT NULL,"
    " build_tip INTEGER NOT NULL,"
    " expiry INTEGER NOT NULL,"
    " scan_next INTEGER NOT NULL,"
    " last_submit_tip INTEGER NOT NULL DEFAULT 0,"
    " PRIMARY KEY(claim_seq, n));"
    "CREATE TABLE IF NOT EXISTS reservations("
    " nul BLOB PRIMARY KEY,"
    " claim_seq INTEGER NOT NULL);";

/* ── checked column access ──────────────────────────────────────────── */

/* A TEXT column into dst[cap]. NULL, another type, or a text that does not
 * fit (never truncated) is a fault. @return 0 / -1. */
static int col_text(sqlite3_stmt *st, int i, char *dst, size_t cap) {
    if (sqlite3_column_type(st, i) != SQLITE_TEXT) return -1;
    const unsigned char *s = sqlite3_column_text(st, i);
    int n = sqlite3_column_bytes(st, i);
    if (!s || n < 0 || (size_t)n >= cap) return -1;
    memcpy(dst, s, (size_t)n);
    dst[n] = '\0';
    return 0;
}

static int col_i64(sqlite3_stmt *st, int i, int64_t *out) {
    if (sqlite3_column_type(st, i) != SQLITE_INTEGER) return -1;
    *out = sqlite3_column_int64(st, i);
    return 0;
}

/* A BLOB column: pointer + length (an empty blob has a NULL pointer). */
static int col_blob(sqlite3_stmt *st, int i, const void **p, int *len) {
    if (sqlite3_column_type(st, i) != SQLITE_BLOB) return -1;
    *len = sqlite3_column_bytes(st, i);
    *p = sqlite3_column_blob(st, i);
    if (*len < 0 || (*len > 0 && !*p)) return -1;
    return 0;
}

/* Bind result check: a failed bind leaves the parameter NULL, so the
 * statement would run with a wrong filter or value. Finalises and jumps. */
#define B_OK(call, st, lbl)                                                  \
    do {                                                                     \
        if ((call) != SQLITE_OK) {                                           \
            QGP_LOG_ERROR(LOG_TAG, "bind failed: %s", sqlite3_errmsg(j->db)); \
            sqlite3_finalize(st);                                            \
            (st) = NULL;                                                     \
            goto lbl;                                                        \
        }                                                                    \
    } while (0)

static int exec_sql(sqlite3 *db, const char *sql) {
    char *em = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &em);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "sql failed (%d): %s", rc, em ? em : "?");
        sqlite3_free(em);
        return -1;
    }
    return 0;
}

/* ── locking, bounded by the calling thread's deadline ──────────────── */

static _Thread_local uint64_t t_deadline_ms = FJ_NO_DEADLINE;

void faucet_journal_thread_deadline(uint64_t deadline_ms) {
    t_deadline_ms = deadline_ms;
}

static uint64_t mono_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* Take the journal for a call that has no deadline (the settlement thread):
 * an unbounded mutex wait and the full SQLite busy timeout (an earlier call
 * of ANOTHER thread may have lowered it — it is per connection). */
static void lock_plain(faucet_journal_t *j) {
    pthread_mutex_lock(&j->mu);
    sqlite3_busy_timeout(j->db, (int)FJ_BUSY_MS);
}

/* Take the journal for an HTTP-path call: with a thread deadline the mutex
 * wait ends at it (CLOCK_MONOTONIC, the faucet_now_ms() clock) and the
 * SQLite busy timeout is the time left (at most FJ_BUSY_MS). @return 0 held
 * / FJ_BUSY not held, nothing touched. */
static int lock_dl(faucet_journal_t *j) {
    const uint64_t dl = t_deadline_ms;
    if (dl == FJ_NO_DEADLINE) { lock_plain(j); return 0; }
    if (mono_now_ms() >= dl) return FJ_BUSY;
    struct timespec ts;
    ts.tv_sec = (time_t)(dl / 1000u);
    ts.tv_nsec = (long)(dl % 1000u) * 1000000L;
    if (pthread_mutex_clocklock(&j->mu, CLOCK_MONOTONIC, &ts) != 0) return FJ_BUSY;
    const uint64_t now = mono_now_ms();
    if (now >= dl) { pthread_mutex_unlock(&j->mu); return FJ_BUSY; }
    const uint64_t left = dl - now;
    sqlite3_busy_timeout(j->db, (int)(left < FJ_BUSY_MS ? left : FJ_BUSY_MS));
    return 0;
}

static int begin(faucet_journal_t *j)    { return exec_sql(j->db, "BEGIN IMMEDIATE"); }
static int commit(faucet_journal_t *j)   { return exec_sql(j->db, "COMMIT"); }
static void rollback(faucet_journal_t *j) { sqlite3_exec(j->db, "ROLLBACK", NULL, NULL, NULL); }

static void hex_of(const uint8_t *b, size_t n, char *out) {
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = '\0';
}

/* ── legal state graph ──────────────────────────────────────────────── */
static int legal(const char *from, const char *to) {
    static const struct { const char *f, *t; } ok[] = {
        {"planned", "paused"},   {"planned", "signed"},
        {"paused", "planned"},   {"paused", "paused"},   {"paused", "signed"},
        {"signed", "submitted"}, {"signed", "confirmed"},
        {"signed", "expired"},   {"signed", "unknown"},
        {"submitted", "submitted"}, {"submitted", "confirmed"},
        {"submitted", "expired"},   {"submitted", "unknown"},
        {"unknown", "unknown"},  {"unknown", "submitted"},
        {"unknown", "confirmed"}, {"unknown", "expired"},
        {"expired", "signed"},   {"expired", "paused"},
    };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++)
        if (!strcmp(from, ok[i].f) && !strcmp(to, ok[i].t)) return 1;
    return 0;
}

static int known_state(const char *s) {
    static const char *all[] = {"planned", "paused", "signed", "submitted",
                                "confirmed", "expired", "unknown"};
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        if (!strcmp(s, all[i])) return 1;
    return 0;
}

/* Load one claim row. Every field is checked; a row that does not read
 * back as a valid claim is a fault. @return 0 / -1. */
static int load_claim_row(sqlite3_stmt *st, faucet_claim_t *c) {
    memset(c, 0, sizeof(*c));
    int64_t seq = 0;
    if (col_i64(st, 0, &seq) != 0 ||
        col_text(st, 1, c->claim_id, sizeof(c->claim_id)) != 0 ||
        col_text(st, 2, c->kind, sizeof(c->kind)) != 0 ||
        col_text(st, 3, c->address, sizeof(c->address)) != 0 ||
        col_text(st, 4, c->name, sizeof(c->name)) != 0 ||
        col_text(st, 5, c->state, sizeof(c->state)) != 0 ||
        col_text(st, 6, c->message, sizeof(c->message)) != 0 ||
        strlen(c->claim_id) != 32 || strlen(c->address) != 128 ||
        (strcmp(c->kind, "full") && strcmp(c->kind, "start")) ||
        !known_state(c->state)) {
        QGP_LOG_ERROR(LOG_TAG, "a claim row does not read back as a valid claim "
                      "(seq %lld)", (long long)seq);
        memset(c, 0, sizeof(*c));
        return -1;
    }
    c->seq = seq;
    return 0;
}

#define CLAIM_COLS "seq, claim_id, kind, address, name, state, message"

/* One-claim query with a single text or int64 bind. mode 0 = text bind,
 * 1 = int64 bind. @return 0 found / 1 none / -1 fault. Lock held. */
static int claim_query(faucet_journal_t *j, const char *sql, const char *text,
                       int64_t num, faucet_claim_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(j->db, sql, -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "prepare failed: %s", sqlite3_errmsg(j->db));
        return -1;
    }
    if (text) B_OK(sqlite3_bind_text(st, 1, text, -1, SQLITE_STATIC), st, bad);
    else if (num >= 0) B_OK(sqlite3_bind_int64(st, 1, num), st, bad);
    int rc = sqlite3_step(st);
    int ret;
    if (rc == SQLITE_ROW) {
        faucet_claim_t tmp;
        if (load_claim_row(st, &tmp) != 0) ret = -1;
        else { if (out) *out = tmp; ret = 0; }
    } else if (rc == SQLITE_DONE) {
        ret = 1;
    } else {
        QGP_LOG_ERROR(LOG_TAG, "step failed: %s", sqlite3_errmsg(j->db));
        ret = -1;
    }
    sqlite3_finalize(st);
    return ret;
bad:
    return -1;
}

/* The state of a claim. @return 0 ok / 1 none / -1 fault. Lock held. */
static int claim_state(faucet_journal_t *j, int64_t seq, char *state, size_t cap) {
    faucet_claim_t c;
    int r = claim_query(j, "SELECT " CLAIM_COLS " FROM claims WHERE seq=?1",
                        NULL, seq, &c);
    if (r == 0) snprintf(state, cap, "%s", c.state);
    return r;
}

/* A single integer result. @return 0 / -1 (a missing row, a step error or
 * a non-integer column is a fault). */
static int one_int(faucet_journal_t *j, const char *sql, const char *text,
                   int64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(j->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    if (text) B_OK(sqlite3_bind_text(st, 1, text, -1, SQLITE_STATIC), st, bad);
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW && col_i64(st, 0, out) == 0) ret = 0;
    sqlite3_finalize(st);
    return ret;
bad:
    return -1;
}

/* ── open / close ───────────────────────────────────────────────────── */

/* The WAL growth the next commit and the checkpoint lag can add on top of
 * the -wal file as it is now: a full autocheckpoint window plus the bound of
 * one transaction. */
static uint64_t wal_margin(uint64_t page_size) {
    return (uint64_t)FJ_WAL_CKPT_PAGES * page_size + FJ_TX_BOUND_BYTES;
}

int faucet_journal_open(const char *path, uint64_t storage_ceiling,
                        faucet_journal_t **out) {
    if (!path || !out || strlen(path) >= sizeof(((faucet_journal_t *)0)->path))
        return -1;
    *out = NULL;
    faucet_journal_t *j = calloc(1, sizeof(*j));
    if (!j) return -1;
    pthread_mutex_init(&j->mu, NULL);
    snprintf(j->path, sizeof(j->path), "%s", path);
    j->ceiling = storage_ceiling;
    if (sqlite3_open_v2(path, &j->db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                        SQLITE_OPEN_NOMUTEX, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "cannot open journal %s", path);
        goto fail;
    }
    sqlite3_busy_timeout(j->db, (int)FJ_BUSY_MS);
    int64_t psize = 0;
    if (one_int(j, "PRAGMA page_size", NULL, &psize) != 0 || psize <= 0) goto fail;
    /* A ceiling that cannot hold the WAL margin plus two claim reserves can
     * never admit a claim without breaking the disk bound: refuse it. */
    if (storage_ceiling <= wal_margin((uint64_t)psize) + 2u * FJ_CLAIM_RESERVE_BYTES) {
        QGP_LOG_ERROR(LOG_TAG, "storage ceiling %llu is too small: it must exceed "
                      "the WAL margin %llu plus two claim reserves",
                      (unsigned long long)storage_ceiling,
                      (unsigned long long)wal_margin((uint64_t)psize));
        goto fail;
    }
    {   /* WAL must really be on: a silent fallback would weaken durability */
        sqlite3_stmt *st = NULL;
        int ok = 0;
        if (sqlite3_prepare_v2(j->db, "PRAGMA journal_mode=WAL", -1, &st,
                               NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW) {
            const char *m = (const char *)sqlite3_column_text(st, 0);
            ok = m && !strcmp(m, "wal");
        }
        sqlite3_finalize(st);
        if (!ok) { QGP_LOG_ERROR(LOG_TAG, "WAL mode not available"); goto fail; }
    }
    if (exec_sql(j->db, "PRAGMA synchronous=FULL") != 0) goto fail;
    {   /* bound the WAL: checkpoint every FJ_WAL_CKPT_PAGES pages and cut the
         * -wal file back to that size after a checkpoint */
        char pr[96];
        snprintf(pr, sizeof(pr), "PRAGMA wal_autocheckpoint=%u", FJ_WAL_CKPT_PAGES);
        if (exec_sql(j->db, pr) != 0) goto fail;
        snprintf(pr, sizeof(pr), "PRAGMA journal_size_limit=%llu",
                 (unsigned long long)FJ_WAL_CKPT_PAGES * (unsigned long long)psize);
        if (exec_sql(j->db, pr) != 0) goto fail;
    }
    {
        int64_t ver = 0;
        if (one_int(j, "PRAGMA user_version", NULL, &ver) != 0) goto fail;
        if (ver > SCHEMA_VERSION) {
            QGP_LOG_ERROR(LOG_TAG, "journal schema %lld is newer than this "
                          "binary (%d)", (long long)ver, SCHEMA_VERSION);
            goto fail;
        }
    }
    if (exec_sql(j->db, SCHEMA_SQL) != 0) goto fail;
    if (exec_sql(j->db, "PRAGMA user_version=1") != 0) goto fail;
    chmod(path, 0600);
    *out = j;
    return 0;
fail:
    if (j->db) sqlite3_close(j->db);
    pthread_mutex_destroy(&j->mu);
    free(j);
    return -1;
}

void faucet_journal_close(faucet_journal_t *j) {
    if (!j) return;
    if (j->db) sqlite3_close(j->db);
    pthread_mutex_destroy(&j->mu);
    free(j);
}

/* ── storage ceiling ────────────────────────────────────────────────── */

/* Bytes the journal holds NOW: the database's LIVE pages (page_count minus
 * the free-list: SQLite reuses freed pages and never shrinks the file, so
 * the file size would stay at its high-water mark after a compaction) plus
 * the -wal file. An absent -wal file is 0; any other stat() failure is a
 * fault. @return 0 / -1. Lock held. */
static int storage_measure_locked(faucet_journal_t *j, uint64_t *used,
                                  uint64_t *disk, uint64_t *margin) {
    int64_t pages = 0, freep = 0, psize = 0;
    if (one_int(j, "PRAGMA page_count", NULL, &pages) != 0 ||
        one_int(j, "PRAGMA freelist_count", NULL, &freep) != 0 ||
        one_int(j, "PRAGMA page_size", NULL, &psize) != 0 ||
        pages < 0 || freep < 0 || freep > pages || psize <= 0) return -1;
    uint64_t wal = 0;
    char p[560];
    struct stat sb;
    snprintf(p, sizeof(p), "%s-wal", j->path);
    if (stat(p, &sb) == 0) wal = (uint64_t)sb.st_size;
    else if (errno != ENOENT) {
        QGP_LOG_ERROR(LOG_TAG, "cannot stat %s: %s", p, strerror(errno));
        return -1;
    }
    *used = (uint64_t)(pages - freep) * (uint64_t)psize + wal;
    if (disk) *disk = (uint64_t)pages * (uint64_t)psize + wal;
    if (margin) *margin = wal_margin((uint64_t)psize);
    return 0;
}

static int storage_used_locked(faucet_journal_t *j, uint64_t *used) {
    return storage_measure_locked(j, used, NULL, NULL);
}

/* The ceiling test of NEW CLAIMS. The configured value is a hard DISK
 * ceiling, so admission stops BEFORE the real files can reach it:
 *     live + wal + margin + reserve  <  ceiling
 *     margin  = FJ_WAL_CKPT_PAGES * page_size + FJ_TX_BOUND_BYTES
 *               (the WAL growth of the next commit and the checkpoint lag)
 *     reserve = FJ_CLAIM_RESERVE_BYTES * (open claims + the one admitted)
 * and, separately, the ON-DISK size (page_count * page_size + wal — the
 * file never shrinks, free pages included) must still be below the ceiling.
 * 1 full, 0 room, -1 fault. Lock held. */
static int storage_full_locked(faucet_journal_t *j) {
    uint64_t used = 0, disk = 0, margin = 0;
    int64_t open = 0;
    if (storage_measure_locked(j, &used, &disk, &margin) != 0) return -1;
    if (one_int(j, "SELECT COUNT(*) FROM claims WHERE state<>'confirmed'", NULL,
                &open) != 0 || open < 0) return -1;
    if (used >= j->ceiling || disk >= j->ceiling) return 1;
    uint64_t reserve = ((uint64_t)open + 1u) * FJ_CLAIM_RESERVE_BYTES;
    return (margin + reserve >= j->ceiling - used) ? 1 : 0;
}

int faucet_journal_storage_full(faucet_journal_t *j) {
    if (lock_dl(j) != 0) return FJ_BUSY;
    int r = storage_full_locked(j);
    pthread_mutex_unlock(&j->mu);
    return r;
}

int faucet_journal_wal_limits(faucet_journal_t *j, int64_t *size_limit,
                              int64_t *autockpt_pages) {
    lock_plain(j);
    int r = (one_int(j, "PRAGMA journal_size_limit", NULL, size_limit) == 0 &&
             one_int(j, "PRAGMA wal_autocheckpoint", NULL, autockpt_pages) == 0) ? 0 : -1;
    pthread_mutex_unlock(&j->mu);
    return r;
}

/* ── claims ─────────────────────────────────────────────────────────── */

int faucet_journal_claim_create(faucet_journal_t *j, const char *kind,
                                const char *address, const char *name,
                                int queue_cap, const uint8_t rand16[16],
                                faucet_claim_t *out) {
    if (!j || !kind || !address || !rand16 || !out || queue_cap < 1) return FJ_ERR;
    int is_full = !strcmp(kind, "full");
    if (!is_full && strcmp(kind, "start")) return FJ_ERR;
    if (strlen(address) != 128) return FJ_ERR;
    if (is_full && (!name || !*name || strlen(name) > 36)) return FJ_ERR;
    if (!is_full) name = "";

    char marker[200];
    if (is_full) snprintf(marker, sizeof(marker), "full:%s", name);
    else         snprintf(marker, sizeof(marker), "start:%s", address);

    int ret = FJ_ERR;
    if (lock_dl(j) != 0) return FJ_BUSY;     /* deadline: nothing was touched */
    if (begin(j) != 0) {
        /* the write lock was not free within the time left: busy, and no
         * transaction was opened, so nothing can be half-created */
        if (sqlite3_errcode(j->db) == SQLITE_BUSY) ret = FJ_BUSY;
        goto unlock;
    }

    int64_t seq = 0;
    sqlite3_stmt *st = NULL;
    int r;

    /* 1. the permanent marker */
    r = -1;
    if (sqlite3_prepare_v2(j->db, "SELECT claim_seq FROM paid WHERE marker=?1",
                           -1, &st, NULL) == SQLITE_OK) {
        B_OK(sqlite3_bind_text(st, 1, marker, -1, SQLITE_STATIC), st, rb);
        int s = sqlite3_step(st);
        if (s == SQLITE_ROW) { if (col_i64(st, 0, &seq) == 0) r = 0; }
        else if (s == SQLITE_DONE) r = 1;
    }
    sqlite3_finalize(st);
    if (r < 0) goto rb;
    if (r == 0) {
        if (claim_query(j, "SELECT " CLAIM_COLS " FROM claims WHERE seq=?1",
                        NULL, seq, out) != 0) goto rb;
        rollback(j);
        ret = FJ_EXISTS;
        goto unlock;
    }
    /* 2. an open claim of this address */
    r = claim_query(j, "SELECT " CLAIM_COLS " FROM claims WHERE address=?1 "
                    "AND state<>'confirmed' ORDER BY seq LIMIT 1",
                    address, -1, out);
    if (r < 0) goto rb;
    if (r == 0) { rollback(j); ret = FJ_EXISTS; goto unlock; }
    /* 3. stopped: a claim whose settlement is unknown */
    int64_t cnt = 0;
    if (one_int(j, "SELECT COUNT(*) FROM claims WHERE state='unknown'", NULL,
                &cnt) != 0) goto rb;
    if (cnt > 0) { rollback(j); ret = FJ_STOPPED; goto unlock; }
    /* 4. storage (live bytes + the settlement reserve of every open claim) */
    r = storage_full_locked(j);
    if (r < 0) goto rb;
    if (r == 1) { rollback(j); ret = FJ_STORAGE_FULL; goto unlock; }
    /* 5. queue */
    if (one_int(j, "SELECT COUNT(*) FROM claims WHERE state<>'confirmed'", NULL,
                &cnt) != 0) goto rb;
    if (cnt >= queue_cap) { rollback(j); ret = FJ_QUEUE_FULL; goto unlock; }
    /* 6. insert claim + marker */
    char cid[33];
    hex_of(rand16, 16, cid);
    st = NULL;
    if (sqlite3_prepare_v2(j->db,
            "INSERT INTO claims(claim_id, kind, address, name, state, message)"
            " VALUES(?1, ?2, ?3, ?4, 'planned', '')", -1, &st, NULL) != SQLITE_OK)
        goto rb;
    B_OK(sqlite3_bind_text(st, 1, cid, -1, SQLITE_STATIC), st, rb);
    B_OK(sqlite3_bind_text(st, 2, kind, -1, SQLITE_STATIC), st, rb);
    B_OK(sqlite3_bind_text(st, 3, address, -1, SQLITE_STATIC), st, rb);
    B_OK(sqlite3_bind_text(st, 4, name, -1, SQLITE_STATIC), st, rb);
    r = sqlite3_step(st);
    sqlite3_finalize(st);
    if (r != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "claim insert failed: %s", sqlite3_errmsg(j->db));
        goto rb;
    }
    seq = sqlite3_last_insert_rowid(j->db);
    st = NULL;
    if (sqlite3_prepare_v2(j->db, "INSERT INTO paid(marker, claim_seq) VALUES(?1, ?2)",
                           -1, &st, NULL) != SQLITE_OK) goto rb;
    B_OK(sqlite3_bind_text(st, 1, marker, -1, SQLITE_STATIC), st, rb);
    B_OK(sqlite3_bind_int64(st, 2, seq), st, rb);
    r = sqlite3_step(st);
    sqlite3_finalize(st);
    if (r != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "marker insert failed: %s", sqlite3_errmsg(j->db));
        goto rb;
    }
    if (claim_query(j, "SELECT " CLAIM_COLS " FROM claims WHERE seq=?1", NULL,
                    seq, out) != 0) goto rb;
    if (commit(j) != 0) goto rb;
    ret = FJ_CREATED;
    goto unlock;
rb:
    rollback(j);
    ret = FJ_ERR;
unlock:
    pthread_mutex_unlock(&j->mu);
    return ret;
}

int faucet_journal_claim_get(faucet_journal_t *j, const char *claim_id,
                             faucet_claim_t *out) {
    if (lock_dl(j) != 0) return FJ_BUSY;
    int r = claim_query(j, "SELECT " CLAIM_COLS " FROM claims WHERE claim_id=?1",
                        claim_id, -1, out);
    pthread_mutex_unlock(&j->mu);
    return r;
}

int faucet_journal_claim_by_address(faucet_journal_t *j, const char *address,
                                    faucet_claim_t *out) {
    if (lock_dl(j) != 0) return FJ_BUSY;
    int r = claim_query(j, "SELECT " CLAIM_COLS " FROM claims WHERE address=?1 "
                        "ORDER BY seq DESC LIMIT 1", address, -1, out);
    pthread_mutex_unlock(&j->mu);
    return r;
}

int faucet_journal_head(faucet_journal_t *j, faucet_claim_t *out) {
    lock_plain(j);
    int r = claim_query(j, "SELECT " CLAIM_COLS " FROM claims WHERE "
                        "state<>'confirmed' ORDER BY seq LIMIT 1", NULL, -1, out);
    pthread_mutex_unlock(&j->mu);
    return r;
}

/* Checked state change inside its own transaction. Lock held. */
static int transition_locked(faucet_journal_t *j, int64_t seq, const char *to,
                             const char *msg, int release_reservations) {
    char from[FJ_STATE_MAX];
    char m[FJ_MSG_MAX];                       /* a longer text is cut here,   */
    snprintf(m, sizeof(m), "%s", msg ? msg : ""); /* never refused on reading */
    if (begin(j) != 0) return -1;
    int r = claim_state(j, seq, from, sizeof(from));
    if (r != 0) { rollback(j); return -1; }
    if (!legal(from, to)) { rollback(j); return -2; }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(j->db, "UPDATE claims SET state=?1, message=?2 "
                           "WHERE seq=?3", -1, &st, NULL) != SQLITE_OK) {
        rollback(j);
        return -1;
    }
    B_OK(sqlite3_bind_text(st, 1, to, -1, SQLITE_STATIC), st, rb);
    B_OK(sqlite3_bind_text(st, 2, m, -1, SQLITE_STATIC), st, rb);
    B_OK(sqlite3_bind_int64(st, 3, seq), st, rb);
    int s = sqlite3_step(st);
    sqlite3_finalize(st);
    if (s != SQLITE_DONE) goto rb;
    if (release_reservations) {
        st = NULL;
        if (sqlite3_prepare_v2(j->db, "DELETE FROM reservations WHERE claim_seq=?1",
                               -1, &st, NULL) != SQLITE_OK) goto rb;
        B_OK(sqlite3_bind_int64(st, 1, seq), st, rb);
        s = sqlite3_step(st);
        sqlite3_finalize(st);
        if (s != SQLITE_DONE) goto rb;
        /* A paid claim's envelope bytes are obsolete; its evidence (wire id,
         * intent id, inputs, expiry, cursor) and the paid marker stay. */
        st = NULL;
        if (sqlite3_prepare_v2(j->db, "UPDATE attempts SET env=X'' "
                               "WHERE claim_seq=?1 AND length(env)>0", -1, &st,
                               NULL) != SQLITE_OK) goto rb;
        B_OK(sqlite3_bind_int64(st, 1, seq), st, rb);
        s = sqlite3_step(st);
        sqlite3_finalize(st);
        if (s != SQLITE_DONE) goto rb;
    }
    if (commit(j) != 0) goto rb;
    return 0;
rb:
    rollback(j);
    return -1;
}

int faucet_journal_set_state(faucet_journal_t *j, int64_t seq,
                             const char *state, const char *message) {
    /* signed is reachable only through attempt_sign; terminal states only
     * through finish */
    if (!strcmp(state, "signed") || !strcmp(state, "confirmed") ||
        !strcmp(state, "expired") || !strcmp(state, "unknown")) return -2;
    lock_plain(j);
    int r = transition_locked(j, seq, state, message, 0);
    pthread_mutex_unlock(&j->mu);
    return r;
}

int faucet_journal_finish(faucet_journal_t *j, int64_t seq, const char *state,
                          const char *message) {
    if (strcmp(state, "confirmed") && strcmp(state, "expired") &&
        strcmp(state, "unknown")) return -2;
    lock_plain(j);
    int r = transition_locked(j, seq, state, message,
                              !strcmp(state, "confirmed"));
    pthread_mutex_unlock(&j->mu);
    return r;
}

/* ── attempts ───────────────────────────────────────────────────────── */

int faucet_journal_attempt_sign(faucet_journal_t *j, int64_t seq,
                                faucet_attempt_t *a) {
    if (!a || !a->env || a->env_len == 0 || a->n_in < 1 ||
        a->n_in > FJ_MAX_INPUTS || a->env_len > 0x7fffffffu) return -1;
    int ret = -1;
    lock_plain(j);
    if (begin(j) != 0) goto unlock;
    char from[FJ_STATE_MAX];
    if (claim_state(j, seq, from, sizeof(from)) != 0) goto rb;
    if (strcmp(from, "planned") && strcmp(from, "paused") &&
        strcmp(from, "expired")) { rollback(j); ret = -2; goto unlock; }

    int64_t n = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(j->db, "SELECT COALESCE(MAX(n),0) FROM attempts "
                           "WHERE claim_seq=?1", -1, &st, NULL) != SQLITE_OK)
        goto rb;
    B_OK(sqlite3_bind_int64(st, 1, seq), st, rb);
    if (sqlite3_step(st) != SQLITE_ROW || col_i64(st, 0, &n) != 0) {
        sqlite3_finalize(st);
        goto rb;
    }
    n += 1;
    sqlite3_finalize(st);

    st = NULL;
    if (sqlite3_prepare_v2(j->db,
            "INSERT INTO attempts(claim_seq, n, env, wire_id, intent_id, inputs,"
            " build_tip, expiry, scan_next, last_submit_tip)"
            " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,0)", -1, &st, NULL) != SQLITE_OK)
        goto rb;
    B_OK(sqlite3_bind_int64(st, 1, seq), st, rb);
    B_OK(sqlite3_bind_int64(st, 2, n), st, rb);
    B_OK(sqlite3_bind_blob(st, 3, a->env, (int)a->env_len, SQLITE_STATIC), st, rb);
    B_OK(sqlite3_bind_blob(st, 4, a->wire_id, 64, SQLITE_STATIC), st, rb);
    B_OK(sqlite3_bind_blob(st, 5, a->intent_id, 64, SQLITE_STATIC), st, rb);
    B_OK(sqlite3_bind_blob(st, 6, a->inputs, a->n_in * 64, SQLITE_STATIC), st, rb);
    B_OK(sqlite3_bind_int64(st, 7, (sqlite3_int64)a->build_tip), st, rb);
    B_OK(sqlite3_bind_int64(st, 8, (sqlite3_int64)a->expiry), st, rb);
    B_OK(sqlite3_bind_int64(st, 9, (sqlite3_int64)a->scan_next), st, rb);
    int s = sqlite3_step(st);
    sqlite3_finalize(st);
    if (s != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "attempt insert failed: %s", sqlite3_errmsg(j->db));
        goto rb;
    }

    if (n > 1) {
        /* A REPLACEMENT. The earlier attempts of this claim are expired and
         * fully scanned: their envelope bytes are obsolete (a stored
         * envelope past its expiry can never be applied). Free them — the
         * evidence rows (wire id, intent id, inputs, cursor, expiry) and the
         * paid marker stay — then require that the live bytes still fit
         * under the storage ceiling; otherwise the replacement is NOT
         * recorded (-4) and the claim waits. */
        st = NULL;
        if (sqlite3_prepare_v2(j->db, "UPDATE attempts SET env=X'' "
                               "WHERE claim_seq=?1 AND n<?2 AND length(env)>0",
                               -1, &st, NULL) != SQLITE_OK) goto rb;
        B_OK(sqlite3_bind_int64(st, 1, seq), st, rb);
        B_OK(sqlite3_bind_int64(st, 2, n), st, rb);
        s = sqlite3_step(st);
        sqlite3_finalize(st);
        if (s != SQLITE_DONE) goto rb;
        uint64_t used = 0;
        if (storage_used_locked(j, &used) != 0) goto rb;
        if (used >= j->ceiling) { rollback(j); ret = -4; goto unlock; }
    }

    /* reservations: this claim's old set goes, the new set comes */
    st = NULL;
    if (sqlite3_prepare_v2(j->db, "DELETE FROM reservations WHERE claim_seq=?1",
                           -1, &st, NULL) != SQLITE_OK) goto rb;
    B_OK(sqlite3_bind_int64(st, 1, seq), st, rb);
    s = sqlite3_step(st);
    sqlite3_finalize(st);
    if (s != SQLITE_DONE) goto rb;
    for (int i = 0; i < a->n_in; i++) {
        st = NULL;
        if (sqlite3_prepare_v2(j->db, "INSERT INTO reservations(nul, claim_seq) "
                               "VALUES(?1, ?2)", -1, &st, NULL) != SQLITE_OK)
            goto rb;
        B_OK(sqlite3_bind_blob(st, 1, a->inputs[i], 64, SQLITE_STATIC), st, rb);
        B_OK(sqlite3_bind_int64(st, 2, seq), st, rb);
        s = sqlite3_step(st);
        sqlite3_finalize(st);
        if (s == SQLITE_CONSTRAINT) { rollback(j); ret = -3; goto unlock; }
        if (s != SQLITE_DONE) goto rb;
    }

    st = NULL;
    if (sqlite3_prepare_v2(j->db, "UPDATE claims SET state='signed', message='' "
                           "WHERE seq=?1", -1, &st, NULL) != SQLITE_OK) goto rb;
    B_OK(sqlite3_bind_int64(st, 1, seq), st, rb);
    s = sqlite3_step(st);
    sqlite3_finalize(st);
    if (s != SQLITE_DONE) goto rb;
    if (commit(j) != 0) goto rb;
    a->n = (int)n;
    ret = 0;
    goto unlock;
rb:
    rollback(j);
    ret = -1;
unlock:
    pthread_mutex_unlock(&j->mu);
    return ret;
}

int faucet_journal_attempt_latest(faucet_journal_t *j, int64_t seq,
                                  faucet_attempt_t *out) {
    memset(out, 0, sizeof(*out));
    int ret = -1;
    lock_plain(j);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(j->db,
            "SELECT n, env, wire_id, intent_id, inputs, build_tip, expiry,"
            " scan_next, last_submit_tip FROM attempts WHERE claim_seq=?1 "
            "ORDER BY n DESC LIMIT 1", -1, &st, NULL) != SQLITE_OK) goto unlock;
    B_OK(sqlite3_bind_int64(st, 1, seq), st, unlock);
    int s = sqlite3_step(st);
    if (s == SQLITE_DONE) { ret = 1; goto fin; }
    if (s != SQLITE_ROW) goto fin;
    {
        int64_t n = 0, bt = 0, ex = 0, sn = 0, ls = 0;
        const void *env = NULL, *wid = NULL, *iid = NULL, *inp = NULL;
        int env_len = 0, wid_len = 0, iid_len = 0, in_len = 0;
        if (col_i64(st, 0, &n) != 0 || col_blob(st, 1, &env, &env_len) != 0 ||
            col_blob(st, 2, &wid, &wid_len) != 0 ||
            col_blob(st, 3, &iid, &iid_len) != 0 ||
            col_blob(st, 4, &inp, &in_len) != 0 ||
            col_i64(st, 5, &bt) != 0 || col_i64(st, 6, &ex) != 0 ||
            col_i64(st, 7, &sn) != 0 || col_i64(st, 8, &ls) != 0 ||
            env_len <= 0 || wid_len != 64 || iid_len != 64 || in_len <= 0 ||
            in_len % 64 != 0 || in_len / 64 > FJ_MAX_INPUTS || n < 1) {
            QGP_LOG_ERROR(LOG_TAG, "malformed attempt row for claim %lld",
                          (long long)seq);
            goto fin;
        }
        out->env = malloc((size_t)env_len);
        if (!out->env) goto fin;
        memcpy(out->env, env, (size_t)env_len);
        out->env_len = (size_t)env_len;
        out->n = (int)n;
        memcpy(out->wire_id, wid, 64);
        memcpy(out->intent_id, iid, 64);
        memcpy(out->inputs, inp, (size_t)in_len);
        out->n_in = in_len / 64;
        out->build_tip = (uint64_t)bt;
        out->expiry = (uint64_t)ex;
        out->scan_next = (uint64_t)sn;
        out->last_submit_tip = (uint64_t)ls;
        ret = 0;
    }
fin:
    sqlite3_finalize(st);
unlock:
    pthread_mutex_unlock(&j->mu);
    return ret;
}

void faucet_attempt_free(faucet_attempt_t *a) {
    if (!a) return;
    free(a->env);
    memset(a, 0, sizeof(*a));
}

int faucet_journal_attempt_submitted(faucet_journal_t *j, int64_t seq,
                                     uint64_t tip) {
    int ret = -1;
    lock_plain(j);
    if (begin(j) != 0) goto unlock;
    char from[FJ_STATE_MAX];
    if (claim_state(j, seq, from, sizeof(from)) != 0) goto rb;
    if (strcmp(from, "signed") && strcmp(from, "submitted")) {
        rollback(j);
        ret = -2;
        goto unlock;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(j->db,
            "UPDATE attempts SET last_submit_tip=?2 WHERE claim_seq=?1 AND n="
            "(SELECT MAX(n) FROM attempts WHERE claim_seq=?1)", -1, &st,
            NULL) != SQLITE_OK) goto rb;
    B_OK(sqlite3_bind_int64(st, 1, seq), st, rb);
    B_OK(sqlite3_bind_int64(st, 2, (sqlite3_int64)tip), st, rb);
    int s = sqlite3_step(st);
    sqlite3_finalize(st);
    if (s != SQLITE_DONE) goto rb;
    st = NULL;
    if (sqlite3_prepare_v2(j->db, "UPDATE claims SET state='submitted' WHERE seq=?1",
                           -1, &st, NULL) != SQLITE_OK) goto rb;
    B_OK(sqlite3_bind_int64(st, 1, seq), st, rb);
    s = sqlite3_step(st);
    sqlite3_finalize(st);
    if (s != SQLITE_DONE) goto rb;
    if (commit(j) != 0) goto rb;
    ret = 0;
    goto unlock;
rb:
    rollback(j);
    ret = -1;
unlock:
    pthread_mutex_unlock(&j->mu);
    return ret;
}

int faucet_journal_attempt_scanned(faucet_journal_t *j, int64_t seq,
                                   uint64_t scan_next) {
    int ret = -1;
    lock_plain(j);
    if (begin(j) != 0) goto unlock;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(j->db,
            "UPDATE attempts SET scan_next=?2 WHERE claim_seq=?1 AND n="
            "(SELECT MAX(n) FROM attempts WHERE claim_seq=?1) AND scan_next<?2",
            -1, &st, NULL) != SQLITE_OK) goto rb;
    B_OK(sqlite3_bind_int64(st, 1, seq), st, rb);
    B_OK(sqlite3_bind_int64(st, 2, (sqlite3_int64)scan_next), st, rb);
    int s = sqlite3_step(st);
    sqlite3_finalize(st);
    if (s != SQLITE_DONE) goto rb;
    int changed = sqlite3_changes(j->db);
    if (commit(j) != 0) goto rb;
    ret = changed == 1 ? 0 : -2;
    goto unlock;
rb:
    rollback(j);
    ret = -1;
unlock:
    pthread_mutex_unlock(&j->mu);
    return ret;
}

int faucet_journal_reserved_other(faucet_journal_t *j, int64_t except_seq,
                                  uint8_t (*out)[64], int cap) {
    int n = -1;
    lock_plain(j);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(j->db, "SELECT nul FROM reservations WHERE "
                           "claim_seq<>?1 ORDER BY nul", -1, &st,
                           NULL) != SQLITE_OK) goto unlock;
    B_OK(sqlite3_bind_int64(st, 1, except_seq), st, unlock);
    n = 0;
    int s;
    while ((s = sqlite3_step(st)) == SQLITE_ROW) {
        const void *p = NULL;
        int len = 0;
        if (n >= cap || col_blob(st, 0, &p, &len) != 0 || len != 64) { n = -1; break; }
        memcpy(out[n++], p, 64);
    }
    if (n >= 0 && s != SQLITE_DONE) n = -1;
    sqlite3_finalize(st);
unlock:
    pthread_mutex_unlock(&j->mu);
    return n;
}

int faucet_journal_counts(faucet_journal_t *j, faucet_jcounts_t *out) {
    memset(out, 0, sizeof(*out));
    int ret = -1;
    if (lock_dl(j) != 0) return FJ_BUSY;
    int64_t v = 0;
    if (one_int(j, "SELECT COUNT(*) FROM claims WHERE state<>'confirmed'", NULL, &v)) goto unlock;
    out->open = (int)v;
    if (one_int(j, "SELECT COUNT(*) FROM claims WHERE state='paused'", NULL, &v)) goto unlock;
    out->paused = (int)v;
    if (one_int(j, "SELECT COUNT(*) FROM claims WHERE state='unknown'", NULL, &v)) goto unlock;
    out->unknown = (int)v;
    ret = 0;
unlock:
    pthread_mutex_unlock(&j->mu);
    return ret;
}
