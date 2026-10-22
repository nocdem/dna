/**
 * @file faucet_journal.c
 * @brief nodus-faucet durable journal (see faucet_journal.h).
 */
#include "faucet_journal.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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

static void copy_str(char *dst, size_t cap, const unsigned char *src) {
    if (!src) { dst[0] = '\0'; return; }
    snprintf(dst, cap, "%s", (const char *)src);
}

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

static int load_claim_row(sqlite3_stmt *st, faucet_claim_t *c) {
    memset(c, 0, sizeof(*c));
    c->seq = sqlite3_column_int64(st, 0);
    copy_str(c->claim_id, sizeof(c->claim_id), sqlite3_column_text(st, 1));
    copy_str(c->kind, sizeof(c->kind), sqlite3_column_text(st, 2));
    copy_str(c->address, sizeof(c->address), sqlite3_column_text(st, 3));
    copy_str(c->name, sizeof(c->name), sqlite3_column_text(st, 4));
    copy_str(c->state, sizeof(c->state), sqlite3_column_text(st, 5));
    copy_str(c->message, sizeof(c->message), sqlite3_column_text(st, 6));
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
    if (text) sqlite3_bind_text(st, 1, text, -1, SQLITE_STATIC);
    else if (num >= 0) sqlite3_bind_int64(st, 1, num);
    int rc = sqlite3_step(st);
    int ret;
    if (rc == SQLITE_ROW) { if (out) load_claim_row(st, out); ret = 0; }
    else if (rc == SQLITE_DONE) ret = 1;
    else {
        QGP_LOG_ERROR(LOG_TAG, "step failed: %s", sqlite3_errmsg(j->db));
        ret = -1;
    }
    sqlite3_finalize(st);
    return ret;
}

/* The state of a claim. @return 0 ok / 1 none / -1 fault. Lock held. */
static int claim_state(faucet_journal_t *j, int64_t seq, char *state, size_t cap) {
    faucet_claim_t c;
    int r = claim_query(j, "SELECT " CLAIM_COLS " FROM claims WHERE seq=?1",
                        NULL, seq, &c);
    if (r == 0) snprintf(state, cap, "%s", c.state);
    return r;
}

static int one_int(faucet_journal_t *j, const char *sql, const char *text,
                   int64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(j->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    if (text) sqlite3_bind_text(st, 1, text, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW) { *out = sqlite3_column_int64(st, 0); ret = 0; }
    sqlite3_finalize(st);
    return ret;
}

/* ── open / close ───────────────────────────────────────────────────── */

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
    sqlite3_busy_timeout(j->db, 5000);
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

static int storage_full_locked(faucet_journal_t *j) {
    uint64_t total = 0;
    char p[560];
    struct stat sb;
    if (stat(j->path, &sb) != 0) return -1;
    total += (uint64_t)sb.st_size;
    snprintf(p, sizeof(p), "%s-wal", j->path);
    if (stat(p, &sb) == 0) total += (uint64_t)sb.st_size;
    return total >= j->ceiling ? 1 : 0;
}

int faucet_journal_storage_full(faucet_journal_t *j) {
    pthread_mutex_lock(&j->mu);
    int r = storage_full_locked(j);
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
    pthread_mutex_lock(&j->mu);
    if (begin(j) != 0) goto unlock;

    int64_t seq = 0;
    sqlite3_stmt *st = NULL;
    int r;

    /* 1. the permanent marker */
    r = -1;
    if (sqlite3_prepare_v2(j->db, "SELECT claim_seq FROM paid WHERE marker=?1",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, marker, -1, SQLITE_STATIC);
        int s = sqlite3_step(st);
        if (s == SQLITE_ROW) { seq = sqlite3_column_int64(st, 0); r = 0; }
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
    /* 4. storage */
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
    sqlite3_bind_text(st, 1, cid, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, kind, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, address, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, name, -1, SQLITE_STATIC);
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
    sqlite3_bind_text(st, 1, marker, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, seq);
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
    pthread_mutex_lock(&j->mu);
    int r = claim_query(j, "SELECT " CLAIM_COLS " FROM claims WHERE claim_id=?1",
                        claim_id, -1, out);
    pthread_mutex_unlock(&j->mu);
    return r;
}

int faucet_journal_claim_by_address(faucet_journal_t *j, const char *address,
                                    faucet_claim_t *out) {
    pthread_mutex_lock(&j->mu);
    int r = claim_query(j, "SELECT " CLAIM_COLS " FROM claims WHERE address=?1 "
                        "ORDER BY seq DESC LIMIT 1", address, -1, out);
    pthread_mutex_unlock(&j->mu);
    return r;
}

int faucet_journal_head(faucet_journal_t *j, faucet_claim_t *out) {
    pthread_mutex_lock(&j->mu);
    int r = claim_query(j, "SELECT " CLAIM_COLS " FROM claims WHERE "
                        "state<>'confirmed' ORDER BY seq LIMIT 1", NULL, -1, out);
    pthread_mutex_unlock(&j->mu);
    return r;
}

/* Checked state change inside its own transaction. Lock held. */
static int transition_locked(faucet_journal_t *j, int64_t seq, const char *to,
                             const char *msg, int release_reservations) {
    char from[FJ_STATE_MAX];
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
    sqlite3_bind_text(st, 1, to, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, msg ? msg : "", -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, seq);
    int s = sqlite3_step(st);
    sqlite3_finalize(st);
    if (s != SQLITE_DONE) { rollback(j); return -1; }
    if (release_reservations) {
        st = NULL;
        if (sqlite3_prepare_v2(j->db, "DELETE FROM reservations WHERE claim_seq=?1",
                               -1, &st, NULL) != SQLITE_OK) { rollback(j); return -1; }
        sqlite3_bind_int64(st, 1, seq);
        s = sqlite3_step(st);
        sqlite3_finalize(st);
        if (s != SQLITE_DONE) { rollback(j); return -1; }
    }
    if (commit(j) != 0) { rollback(j); return -1; }
    return 0;
}

int faucet_journal_set_state(faucet_journal_t *j, int64_t seq,
                             const char *state, const char *message) {
    /* signed is reachable only through attempt_sign; terminal states only
     * through finish */
    if (!strcmp(state, "signed") || !strcmp(state, "confirmed") ||
        !strcmp(state, "expired") || !strcmp(state, "unknown")) return -2;
    pthread_mutex_lock(&j->mu);
    int r = transition_locked(j, seq, state, message, 0);
    pthread_mutex_unlock(&j->mu);
    return r;
}

int faucet_journal_finish(faucet_journal_t *j, int64_t seq, const char *state,
                          const char *message) {
    if (strcmp(state, "confirmed") && strcmp(state, "expired") &&
        strcmp(state, "unknown")) return -2;
    pthread_mutex_lock(&j->mu);
    int r = transition_locked(j, seq, state, message,
                              !strcmp(state, "confirmed"));
    pthread_mutex_unlock(&j->mu);
    return r;
}

/* ── attempts ───────────────────────────────────────────────────────── */

int faucet_journal_attempt_sign(faucet_journal_t *j, int64_t seq,
                                faucet_attempt_t *a) {
    if (!a || !a->env || a->env_len == 0 || a->n_in < 1 ||
        a->n_in > FJ_MAX_INPUTS) return -1;
    int ret = -1;
    pthread_mutex_lock(&j->mu);
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
    sqlite3_bind_int64(st, 1, seq);
    if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_finalize(st); goto rb; }
    n = sqlite3_column_int64(st, 0) + 1;
    sqlite3_finalize(st);

    st = NULL;
    if (sqlite3_prepare_v2(j->db,
            "INSERT INTO attempts(claim_seq, n, env, wire_id, intent_id, inputs,"
            " build_tip, expiry, scan_next, last_submit_tip)"
            " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,0)", -1, &st, NULL) != SQLITE_OK)
        goto rb;
    sqlite3_bind_int64(st, 1, seq);
    sqlite3_bind_int64(st, 2, n);
    sqlite3_bind_blob(st, 3, a->env, (int)a->env_len, SQLITE_STATIC);
    sqlite3_bind_blob(st, 4, a->wire_id, 64, SQLITE_STATIC);
    sqlite3_bind_blob(st, 5, a->intent_id, 64, SQLITE_STATIC);
    sqlite3_bind_blob(st, 6, a->inputs, a->n_in * 64, SQLITE_STATIC);
    sqlite3_bind_int64(st, 7, (sqlite3_int64)a->build_tip);
    sqlite3_bind_int64(st, 8, (sqlite3_int64)a->expiry);
    sqlite3_bind_int64(st, 9, (sqlite3_int64)a->scan_next);
    int s = sqlite3_step(st);
    sqlite3_finalize(st);
    if (s != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "attempt insert failed: %s", sqlite3_errmsg(j->db));
        goto rb;
    }

    /* reservations: this claim's old set goes, the new set comes */
    st = NULL;
    if (sqlite3_prepare_v2(j->db, "DELETE FROM reservations WHERE claim_seq=?1",
                           -1, &st, NULL) != SQLITE_OK) goto rb;
    sqlite3_bind_int64(st, 1, seq);
    s = sqlite3_step(st);
    sqlite3_finalize(st);
    if (s != SQLITE_DONE) goto rb;
    for (int i = 0; i < a->n_in; i++) {
        st = NULL;
        if (sqlite3_prepare_v2(j->db, "INSERT INTO reservations(nul, claim_seq) "
                               "VALUES(?1, ?2)", -1, &st, NULL) != SQLITE_OK)
            goto rb;
        sqlite3_bind_blob(st, 1, a->inputs[i], 64, SQLITE_STATIC);
        sqlite3_bind_int64(st, 2, seq);
        s = sqlite3_step(st);
        sqlite3_finalize(st);
        if (s == SQLITE_CONSTRAINT) { rollback(j); ret = -3; goto unlock; }
        if (s != SQLITE_DONE) goto rb;
    }

    st = NULL;
    if (sqlite3_prepare_v2(j->db, "UPDATE claims SET state='signed', message='' "
                           "WHERE seq=?1", -1, &st, NULL) != SQLITE_OK) goto rb;
    sqlite3_bind_int64(st, 1, seq);
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
    pthread_mutex_lock(&j->mu);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(j->db,
            "SELECT n, env, wire_id, intent_id, inputs, build_tip, expiry,"
            " scan_next, last_submit_tip FROM attempts WHERE claim_seq=?1 "
            "ORDER BY n DESC LIMIT 1", -1, &st, NULL) != SQLITE_OK) goto unlock;
    sqlite3_bind_int64(st, 1, seq);
    int s = sqlite3_step(st);
    if (s == SQLITE_DONE) { ret = 1; goto fin; }
    if (s != SQLITE_ROW) goto fin;
    int env_len = sqlite3_column_bytes(st, 1);
    int in_len = sqlite3_column_bytes(st, 4);
    if (env_len <= 0 || sqlite3_column_bytes(st, 2) != 64 ||
        sqlite3_column_bytes(st, 3) != 64 || in_len <= 0 || in_len % 64 != 0 ||
        in_len / 64 > FJ_MAX_INPUTS) {
        QGP_LOG_ERROR(LOG_TAG, "malformed attempt row for claim %lld",
                      (long long)seq);
        goto fin;
    }
    out->env = malloc((size_t)env_len);
    if (!out->env) goto fin;
    memcpy(out->env, sqlite3_column_blob(st, 1), (size_t)env_len);
    out->env_len = (size_t)env_len;
    out->n = (int)sqlite3_column_int64(st, 0);
    memcpy(out->wire_id, sqlite3_column_blob(st, 2), 64);
    memcpy(out->intent_id, sqlite3_column_blob(st, 3), 64);
    memcpy(out->inputs, sqlite3_column_blob(st, 4), (size_t)in_len);
    out->n_in = in_len / 64;
    out->build_tip = (uint64_t)sqlite3_column_int64(st, 5);
    out->expiry = (uint64_t)sqlite3_column_int64(st, 6);
    out->scan_next = (uint64_t)sqlite3_column_int64(st, 7);
    out->last_submit_tip = (uint64_t)sqlite3_column_int64(st, 8);
    ret = 0;
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
    pthread_mutex_lock(&j->mu);
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
    sqlite3_bind_int64(st, 1, seq);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)tip);
    int s = sqlite3_step(st);
    sqlite3_finalize(st);
    if (s != SQLITE_DONE) goto rb;
    st = NULL;
    if (sqlite3_prepare_v2(j->db, "UPDATE claims SET state='submitted' WHERE seq=?1",
                           -1, &st, NULL) != SQLITE_OK) goto rb;
    sqlite3_bind_int64(st, 1, seq);
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
    pthread_mutex_lock(&j->mu);
    if (begin(j) != 0) goto unlock;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(j->db,
            "UPDATE attempts SET scan_next=?2 WHERE claim_seq=?1 AND n="
            "(SELECT MAX(n) FROM attempts WHERE claim_seq=?1) AND scan_next<?2",
            -1, &st, NULL) != SQLITE_OK) goto rb;
    sqlite3_bind_int64(st, 1, seq);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)scan_next);
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
    pthread_mutex_lock(&j->mu);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(j->db, "SELECT nul FROM reservations WHERE "
                           "claim_seq<>?1 ORDER BY nul", -1, &st,
                           NULL) != SQLITE_OK) goto unlock;
    sqlite3_bind_int64(st, 1, except_seq);
    n = 0;
    int s;
    while ((s = sqlite3_step(st)) == SQLITE_ROW) {
        if (n >= cap || sqlite3_column_bytes(st, 0) != 64) { n = -1; break; }
        memcpy(out[n++], sqlite3_column_blob(st, 0), 64);
    }
    if (s != SQLITE_ROW && s != SQLITE_DONE) n = -1;
    sqlite3_finalize(st);
unlock:
    pthread_mutex_unlock(&j->mu);
    return n;
}

int faucet_journal_counts(faucet_journal_t *j, faucet_jcounts_t *out) {
    memset(out, 0, sizeof(*out));
    int ret = -1;
    pthread_mutex_lock(&j->mu);
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
