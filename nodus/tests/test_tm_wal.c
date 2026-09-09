/**
 * Nodus — Tendermint consensus WAL (`tm_wal`) and validator state row
 * (`tm_state`) tests. T3 wave 1 (T2 wire design §4.6; D-13, D-15 rev 4).
 *
 * ── WHAT IT PROVES ────────────────────────────────────────────────────
 * Four properties that would each be FALSE if this file failed:
 *
 *  1. The second connection really is a second connection at
 *     synchronous=FULL. `PRAGMA synchronous` is per-connection state, so
 *     it is READ BACK (2 on the FULL handle, 1 on the main one) rather
 *     than assumed — D-13's own verification obligation. A refusal to
 *     open on a database with no file (`:memory:`) is proved too, because
 *     two connections cannot share one.
 *  2. Every stored row is SHA3-512(payload) ‖ payload, with the digest
 *     computed HERE, independently, and compared byte for byte against
 *     the stored prefix. A module that hashed something else, or hashed
 *     nothing, fails.
 *  3. A flipped bit STOPS a replay. The corrupted row is not delivered
 *     and neither is any row after it — there is no skip path, which is
 *     the whole point of the digest (D-15 rev 4 (1), DG-15, G21).
 *  4. Sequence numbers are monotonic per protocol_id, continue across
 *     heights, and are restored as max(seq)+1 after a restart; replay
 *     returns rows in (height, seq) order and honours the exclusive
 *     height filter; the startup classification is a pure function of
 *     three integers with exactly three defined rows.
 *
 * ── WHAT IT REQUIRES ──────────────────────────────────────────────────
 * COMPILE FLAGS: none beyond a default build. No fault injection, no
 * epoch/grace overrides. `NODUS_WITNESS_INTERNAL_API` is supplied by
 * register_witness_test and is needed for the FULL-handle accessor.
 * ENVIRONMENT: none is required. `TMPDIR` is READ if set and used as the
 * parent of a `mkdtemp` directory; otherwise /tmp. Nothing must be
 * exported before the run.
 *
 * ── WHAT IT LEAVES BEHIND ─────────────────────────────────────────────
 * Nothing. Every fixture creates its own `mkdtemp` directory (unique per
 * process, so `ctest -j` is safe) holding one witness chain database, and
 * removes the whole directory — WAL and shm files included — before it
 * returns. No node directory, no arm file, no process, no port.
 *
 * ── HOW IT CAN LIE ────────────────────────────────────────────────────
 *  - If schema stage S13 stopped creating `tm_wal`, `fx_open` would fail
 *    and the run would ABORT with a CHECK, not pass quietly. There is no
 *    skip path and no rc=99 anywhere in this file.
 *  - The digest assertions would be worthless if they compared the
 *    module's own digest to itself; they recompute it from the payload
 *    with `qgp_sha3_512` and compare against the raw stored bytes read
 *    back through plain SQL.
 *  - `TMPDIR` pointing at a non-writable path makes `mkdtemp` fail and
 *    the fixture CHECK fires; it never silently falls back to /tmp after
 *    the variable has been honoured.
 *  - This file proves the WAL's own contract only. That the host calls it
 *    in the right ORDER at a height close (D-15 rev 4's five steps) is
 *    wave-2 behaviour and is NOT covered here — no host exists yet.
 *
 * @file test_tm_wal.c
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_tm_wal.h"

#include "crypto/hash/qgp_sha3.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ── Fixture (idiom: test_v2_schema.c — heap witness, temp dir) ──────── */

static void rmrf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0) continue;
            char child[1024];
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            struct stat st;
            if (lstat(child, &st) == 0) {
                if (S_ISDIR(st.st_mode)) rmrf(child);
                else (void)unlink(child);
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

typedef struct {
    nodus_witness_t *w;
    char             dir[256];
    uint8_t          chain_id16[16];
} fixture_t;

/* A file-backed database is MANDATORY here: the module opens a second
 * connection to the same file, and `:memory:` gives each connection its
 * own private database. */
static int fx_open(fixture_t *fx) {
    fx->w = calloc(1, sizeof(*fx->w));      /* multi-MB — ALWAYS heap */
    if (!fx->w) return -1;
    const char *base = getenv("TMPDIR");
    if (!base || !*base) base = "/tmp";
    snprintf(fx->dir, sizeof(fx->dir), "%s/test_tm_wal_XXXXXX", base);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x5a, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) {
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
    /* tm_wal / tm_state exist only from schema 13 onward. */
    if (nodus_witness_db_migrate_v2s13(fx->w) != 0) {
        sqlite3_close(fx->w->db); fx->w->db = NULL;
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
    return 0;
}

static int fx_reopen(fixture_t *fx) {
    sqlite3_close(fx->w->db);
    fx->w->db = NULL;
    return nodus_witness_create_chain_db(fx->w, fx->chain_id16);
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) { sqlite3_close(fx->w->db); fx->w->db = NULL; }
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
}

/* ── SQL helpers (deliberately independent of the module) ────────────── */

static int pragma_int(sqlite3 *db, const char *sql, int *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) *out = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 0 : -1;
}

static int pragma_text(sqlite3 *db, const char *sql, char *out, size_t cap) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        const unsigned char *t = sqlite3_column_text(st, 0);
        snprintf(out, cap, "%s", t ? (const char *)t : "");
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 0 : -1;
}

/* Raw `bytes` of one WAL row. Returns the length, or -1. */
static int row_bytes(sqlite3 *db, uint64_t height, uint64_t seq,
                     uint8_t *out, size_t cap) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT bytes FROM tm_wal WHERE height=?1 AND seq=?2",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)seq);
    int len = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const void *b = sqlite3_column_blob(st, 0);
        int n = sqlite3_column_bytes(st, 0);
        if (b && n >= 0 && (size_t)n <= cap) { memcpy(out, b, (size_t)n); len = n; }
    }
    sqlite3_finalize(st);
    return len;
}

/* Raw `bytes` of the single tm_state row. Returns the length, or -1. */
static int state_bytes(sqlite3 *db, uint8_t *out, size_t cap) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT bytes FROM tm_state", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    int len = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const void *b = sqlite3_column_blob(st, 0);
        int n = sqlite3_column_bytes(st, 0);
        if (b && n >= 0 && (size_t)n <= cap) { memcpy(out, b, (size_t)n); len = n; }
    }
    sqlite3_finalize(st);
    return len;
}

/* Flip one bit of a stored BLOB through plain SQL — the disk-corruption
 * the digest exists to catch. 0 on success. */
static int flip_bit(sqlite3 *db, const char *sel, const char *upd,
                    int keyed, uint64_t k1, uint64_t k2, size_t off) {
    uint8_t buf[8192];
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sel, -1, &st, NULL) != SQLITE_OK) return -1;
    if (keyed) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)k1);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)k2);
    }
    int len = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const void *b = sqlite3_column_blob(st, 0);
        int n = sqlite3_column_bytes(st, 0);
        if (b && n > 0 && (size_t)n <= sizeof(buf)) {
            memcpy(buf, b, (size_t)n); len = n;
        }
    }
    sqlite3_finalize(st);
    if (len < 0 || off >= (size_t)len) return -1;

    buf[off] ^= 0x01u;

    if (sqlite3_prepare_v2(db, upd, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(st, 1, buf, len, SQLITE_STATIC);
    if (keyed) {
        sqlite3_bind_int64(st, 2, (sqlite3_int64)k1);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)k2);
    }
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int flip_wal_bit(sqlite3 *db, uint64_t h, uint64_t seq, size_t off) {
    return flip_bit(db,
        "SELECT bytes FROM tm_wal WHERE height=?1 AND seq=?2",
        "UPDATE tm_wal SET bytes=?1 WHERE height=?2 AND seq=?3",
        1, h, seq, off);
}

static int flip_state_bit(sqlite3 *db, size_t off) {
    return flip_bit(db, "SELECT bytes FROM tm_state",
                        "UPDATE tm_state SET bytes=?1", 0, 0, 0, off);
}

/* Row count of a table, or -1. */
static int count_rows(sqlite3 *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int n = (sqlite3_step(st) == SQLITE_ROW) ? sqlite3_column_int(st, 0) : -1;
    sqlite3_finalize(st);
    return n;
}

/* Digest oracle: recompute SHA3-512 over the payload half and compare it
 * with the stored 64-byte prefix. 1 = matches. */
static int digest_prefix_ok(const uint8_t *row, size_t row_len) {
    if (row_len <= 64) return 0;
    uint8_t want[64];
    if (qgp_sha3_512(row + 64, row_len - 64, want) != 0) return 0;
    return memcmp(want, row, 64) == 0;
}

/* ── Replay collector ────────────────────────────────────────────────── */

#define MAX_SEEN 32
typedef struct {
    int      n;
    uint8_t  kind[MAX_SEEN];
    uint64_t height[MAX_SEEN];
    uint64_t seq[MAX_SEEN];
    size_t   len[MAX_SEEN];
    uint8_t  first[MAX_SEEN];
    int      stop_at;                 /* stop when n reaches this; -1 never */
} seen_t;

static int collect_cb(void *ctx, uint8_t kind, uint64_t height, uint64_t seq,
                      const uint8_t *payload, size_t len) {
    seen_t *s = (seen_t *)ctx;
    if (s->n < MAX_SEEN) {
        s->kind[s->n]   = kind;
        s->height[s->n] = height;
        s->seq[s->n]    = seq;
        s->len[s->n]    = len;
        s->first[s->n]  = len ? payload[0] : 0;
        s->n++;
    }
    if (s->stop_at >= 0 && s->n >= s->stop_at) return 1;   /* ask to stop */
    return 0;
}

static void seen_reset(seen_t *s) { memset(s, 0, sizeof(*s)); s->stop_at = -1; }

/* ── Startup classification: PURE, no database ───────────────────────── */

static int test_startup_table(void) {
    /* The three defined rows (T2 §4.6; D-15 rev 4 (2)). */
    CHECK(nodus_tm_wal_startup_classify(10, 10, 11) ==
          NODUS_TM_STARTUP_NORMAL, "S=E+1,T=E is NORMAL"); OK();
    CHECK(nodus_tm_wal_startup_classify(10, 10, 10) ==
          NODUS_TM_STARTUP_FAST_FORWARD, "S=E,T=E is FAST_FORWARD"); OK();
    CHECK(nodus_tm_wal_startup_classify(11, 10, 11) ==
          NODUS_TM_STARTUP_WRITE_END_THEN_FF,
          "S=E+1,T=E+1 is WRITE_END_THEN_FF"); OK();

    /* Same three at the genesis edge, where E = 0 means "no END_HEIGHT". */
    CHECK(nodus_tm_wal_startup_classify(0, 0, 1) ==
          NODUS_TM_STARTUP_NORMAL, "genesis NORMAL"); OK();
    CHECK(nodus_tm_wal_startup_classify(0, 0, 0) ==
          NODUS_TM_STARTUP_FAST_FORWARD, "genesis FAST_FORWARD"); OK();
    CHECK(nodus_tm_wal_startup_classify(1, 0, 1) ==
          NODUS_TM_STARTUP_WRITE_END_THEN_FF, "genesis WRITE_END"); OK();

    /* Everything else is FAULT — the four combinations D-15 rev 4 names,
     * plus the wrap guard. */
    CHECK(nodus_tm_wal_startup_classify(10, 10, 12) ==
          NODUS_TM_STARTUP_FAULT, "S=E+2 must FAULT"); OK();
    CHECK(nodus_tm_wal_startup_classify(12, 10, 11) ==
          NODUS_TM_STARTUP_FAULT, "T=E+2 must FAULT"); OK();
    CHECK(nodus_tm_wal_startup_classify(10, 10, 9) ==
          NODUS_TM_STARTUP_FAULT, "S<E must FAULT"); OK();
    CHECK(nodus_tm_wal_startup_classify(9, 10, 11) ==
          NODUS_TM_STARTUP_FAULT, "T<E must FAULT"); OK();
    CHECK(nodus_tm_wal_startup_classify(10, 10, 0) ==
          NODUS_TM_STARTUP_FAULT, "S=0 with E=10 must FAULT"); OK();
    CHECK(nodus_tm_wal_startup_classify(UINT64_MAX, UINT64_MAX, 0) ==
          NODUS_TM_STARTUP_FAULT, "E=UINT64_MAX must FAULT"); OK();

    /* Purity: the same three integers answer the same way every time. */
    for (int i = 0; i < 4; i++) {
        CHECK(nodus_tm_wal_startup_classify(10, 10, 11) ==
              NODUS_TM_STARTUP_NORMAL, "classification not pure");
    }
    OK();
    return 0;
}

/* ── Open refusals ───────────────────────────────────────────────────── */

static int test_open_refusals(void) {
    nodus_tm_wal_t *w = NULL;
    sqlite3 *mem = NULL;

    CHECK(nodus_tm_wal_open(NULL, NULL, 1) == -1, "NULL out accepted"); OK();

    /* Two connections cannot share an in-memory database, so the module
     * must refuse it DETERMINISTICALLY (-1), not fault later (-2). */
    CHECK(sqlite3_open(":memory:", &mem) == SQLITE_OK, "open :memory:");
    CHECK(nodus_tm_wal_open(&w, mem, 1) == -1, ":memory: was accepted"); OK();
    CHECK(w == NULL, ":memory: refusal left a handle"); OK();
    sqlite3_close(mem);

    CHECK(nodus_tm_wal_open(&w, NULL, 1) == -1, "NULL db accepted"); OK();
    return 0;
}

/* ── The database-backed body ────────────────────────────────────────── */

static int test_wal_body(void) {
    fixture_t fx;
    nodus_tm_wal_t *w = NULL;
    uint8_t row[8192];
    seen_t seen;

    CHECK(fx_open(&fx) == 0, "fixture open (S13)"); OK();
    CHECK(nodus_tm_wal_open(&w, fx.w->db, 1) == 0, "wal open"); OK();

    /* ── 1. The two connections, asserted not assumed (D-13) ────────── */
    {
        sqlite3 *full = nodus_tm_wal_full_conn(w);
        CHECK(full != NULL, "no FULL handle"); OK();
        CHECK(full != fx.w->db, "FULL handle IS the main handle"); OK();

        int sync_full = -1, sync_main = -1;
        CHECK(pragma_int(full, "PRAGMA synchronous", &sync_full) == 0,
              "read FULL synchronous");
        CHECK(sync_full == 2, "FULL connection is not synchronous=FULL"); OK();
        CHECK(pragma_int(fx.w->db, "PRAGMA synchronous", &sync_main) == 0,
              "read main synchronous");
        CHECK(sync_main == 1, "main connection is not synchronous=NORMAL"); OK();

        char jm_full[32] = {0}, jm_main[32] = {0};
        CHECK(pragma_text(full, "PRAGMA journal_mode", jm_full,
                          sizeof(jm_full)) == 0, "read FULL journal_mode");
        CHECK(pragma_text(fx.w->db, "PRAGMA journal_mode", jm_main,
                          sizeof(jm_main)) == 0, "read main journal_mode");
        CHECK(strcmp(jm_full, "wal") == 0, "FULL connection not in WAL mode"); OK();
        CHECK(strcmp(jm_main, "wal") == 0, "main connection not in WAL mode"); OK();
    }

    /* ── 2. A fresh log has no END_HEIGHT and no state row ──────────── */
    {
        int have = 1;
        uint64_t h = 12345;
        CHECK(nodus_tm_wal_last_end_height(w, &have, &h) == 0,
              "last_end_height on an empty log");
        CHECK(have == 0, "empty log reported an END_HEIGHT"); OK();
        CHECK(h == 0, "empty log wrote a height"); OK();
    }

    /* ── 3. Row framing and the three payload layouts ───────────────── */
    {
        static const uint8_t body[] = { 0xC0, 0xFF, 0xEE, 0x01, 0x02 };
        uint64_t s_msg = UINT64_MAX;

        CHECK(nodus_tm_wal_append_msg(w, 1, body, sizeof(body), 1,
                                      &s_msg) == 0, "append own msg"); OK();
        CHECK(s_msg == 0, "first seq is not 0"); OK();
        CHECK(nodus_tm_wal_append_timeout(w, 1, 2, 3) == 0,
              "append timeout"); OK();
        CHECK(nodus_tm_wal_append_end_height(w, 1) == 0,
              "append end_height"); OK();

        /* kind 1 — the body is stored VERBATIM after the digest. */
        int n = row_bytes(fx.w->db, 1, 0, row, sizeof(row));
        CHECK(n == 64 + (int)sizeof(body), "msg row length"); OK();
        CHECK(digest_prefix_ok(row, (size_t)n), "msg row digest"); OK();
        CHECK(memcmp(row + 64, body, sizeof(body)) == 0,
              "msg body was altered"); OK();

        /* kind 2 — height u64 ‖ round u32 ‖ step u8, big-endian. */
        n = row_bytes(fx.w->db, 1, 1, row, sizeof(row));
        CHECK(n == 64 + 13, "timeout row length"); OK();
        CHECK(digest_prefix_ok(row, (size_t)n), "timeout row digest"); OK();
        {
            static const uint8_t want[13] = {
                0,0,0,0,0,0,0,1,   /* height 1 */
                0,0,0,2,           /* round 2  */
                3                  /* step 3   */
            };
            CHECK(memcmp(row + 64, want, 13) == 0,
                  "timeout payload layout"); OK();
        }

        /* kind 3 — height u64. */
        n = row_bytes(fx.w->db, 1, 2, row, sizeof(row));
        CHECK(n == 64 + 8, "end_height row length"); OK();
        CHECK(digest_prefix_ok(row, (size_t)n), "end_height row digest"); OK();
        {
            static const uint8_t want[8] = { 0,0,0,0,0,0,0,1 };
            CHECK(memcmp(row + 64, want, 8) == 0,
                  "end_height payload layout"); OK();
        }

        /* The kinds landed in the right columns. */
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
                "SELECT kind FROM tm_wal WHERE height=1 ORDER BY seq",
                -1, &st, NULL) == SQLITE_OK, "kind query");
        int want_kind[3] = { 1, 2, 3 }, i = 0, kinds_ok = 1;
        while (sqlite3_step(st) == SQLITE_ROW && i < 3) {
            if (sqlite3_column_int(st, 0) != want_kind[i]) kinds_ok = 0;
            i++;
        }
        sqlite3_finalize(st);
        CHECK(i == 3 && kinds_ok, "kind column values"); OK();
    }

    /* ── 4. END_HEIGHT is the MAX over kind 3, not the last row ─────── */
    {
        int have = 0;
        uint64_t h = 0;
        CHECK(nodus_tm_wal_last_end_height(w, &have, &h) == 0, "end_height");
        CHECK(have == 1 && h == 1, "END_HEIGHT(1) not reported"); OK();
    }

    /* ── 5. seq is monotonic ACROSS heights and survives a restart ──── */
    {
        static const uint8_t b2[] = { 0x21 };
        static const uint8_t b3[] = { 0x31 };
        uint64_t s = 0;

        CHECK(nodus_tm_wal_append_msg(w, 2, b2, sizeof(b2), 0, &s) == 0,
              "append received msg at h=2");
        CHECK(s == 3, "seq did not continue across heights"); OK();

        /* Reopen the WAL handle: next_seq must come back as max+1. */
        nodus_tm_wal_close(&w);
        CHECK(w == NULL, "close left a handle"); OK();
        CHECK(nodus_tm_wal_open(&w, fx.w->db, 1) == 0, "wal reopen"); OK();
        CHECK(nodus_tm_wal_append_msg(w, 3, b3, sizeof(b3), 1, &s) == 0,
              "append after reopen");
        CHECK(s == 4, "next_seq was not restored as max(seq)+1"); OK();

        /* And across a full database close/open, not just a handle one. */
        nodus_tm_wal_close(&w);
        CHECK(fx_reopen(&fx) == 0, "database reopen"); OK();
        CHECK(nodus_tm_wal_open(&w, fx.w->db, 1) == 0, "wal open after db"); OK();
        CHECK(nodus_tm_wal_append_msg(w, 3, b3, sizeof(b3), 0, &s) == 0,
              "append after db reopen");
        CHECK(s == 5, "seq lost across a database restart"); OK();
    }

    /* ── 6. Replay order and the exclusive height filter ─────────────── */
    {
        seen_reset(&seen);
        CHECK(nodus_tm_wal_replay(w, 0, collect_cb, &seen) == 0,
              "replay from 0"); OK();
        CHECK(seen.n == 6, "replay delivered the wrong number of rows"); OK();

        int ordered = 1;
        for (int i = 1; i < seen.n; i++) {
            if (seen.height[i] < seen.height[i - 1]) ordered = 0;
            if (seen.height[i] == seen.height[i - 1] &&
                seen.seq[i] <= seen.seq[i - 1]) ordered = 0;
            if (seen.height[i] > seen.height[i - 1] &&
                seen.seq[i] <= seen.seq[i - 1]) ordered = 0;
        }
        CHECK(ordered, "replay is not in (height, seq) order"); OK();
        CHECK(seen.kind[0] == 1 && seen.kind[1] == 2 && seen.kind[2] == 3,
              "replay kinds"); OK();
        CHECK(seen.len[1] == 13 && seen.len[2] == 8,
              "replay payload lengths"); OK();

        /* from_height_exclusive drops everything at or below it. */
        seen_reset(&seen);
        CHECK(nodus_tm_wal_replay(w, 2, collect_cb, &seen) == 0,
              "replay from 2"); OK();
        CHECK(seen.n == 2, "height filter delivered the wrong count"); OK();
        CHECK(seen.height[0] == 3 && seen.height[1] == 3,
              "height filter let a low row through"); OK();

        /* A callback that stops is reported as -1, and delivery stops. */
        seen_reset(&seen);
        seen.stop_at = 2;
        CHECK(nodus_tm_wal_replay(w, 0, collect_cb, &seen) == -1,
              "callback stop is not -1"); OK();
        CHECK(seen.n == 2, "replay continued after the callback stopped"); OK();
    }

    /* ── 7. A flipped bit STOPS the replay — no skip path ────────────── */
    {
        /* Corrupt the digest of the row at height 2 (seq 3). Rows below it
         * must still be delivered; the row itself and everything after it
         * must NOT be. */
        CHECK(flip_wal_bit(fx.w->db, 2, 3, 0) == 0, "flip a digest bit"); OK();

        seen_reset(&seen);
        CHECK(nodus_tm_wal_replay(w, 0, collect_cb, &seen) == -2,
              "corrupt row did not FAULT"); OK();
        CHECK(seen.n == 3, "replay did not stop at the corrupt row"); OK();
        CHECK(seen.height[2] == 1, "a row past the corruption was delivered"); OK();

        /* Corruption in the PAYLOAD half is caught the same way. */
        CHECK(flip_wal_bit(fx.w->db, 2, 3, 0) == 0, "restore the digest bit");
        CHECK(flip_wal_bit(fx.w->db, 2, 3, 64) == 0, "flip a payload bit"); OK();
        seen_reset(&seen);
        CHECK(nodus_tm_wal_replay(w, 0, collect_cb, &seen) == -2,
              "corrupt payload did not FAULT"); OK();
        CHECK(seen.n == 3, "payload corruption did not stop the replay"); OK();

        /* Undo, so the rest of the file works on a healthy log. */
        CHECK(flip_wal_bit(fx.w->db, 2, 3, 64) == 0, "restore the payload bit");
        seen_reset(&seen);
        CHECK(nodus_tm_wal_replay(w, 0, collect_cb, &seen) == 0,
              "log not healthy after restore"); OK();
    }

    /* ── 8. prune_below removes strictly-lower heights ───────────────── */
    {
        CHECK(nodus_tm_wal_prune_below(w, 3) == 0, "prune below 3"); OK();
        seen_reset(&seen);
        CHECK(nodus_tm_wal_replay(w, 0, collect_cb, &seen) == 0,
              "replay after prune"); OK();
        CHECK(seen.n == 2, "prune removed the wrong rows"); OK();
        CHECK(seen.height[0] == 3 && seen.height[1] == 3,
              "prune kept a height below the bound"); OK();

        /* The pruned END_HEIGHT is gone with its rows. */
        int have = 1;
        uint64_t h = 7;
        CHECK(nodus_tm_wal_last_end_height(w, &have, &h) == 0,
              "end_height after prune");
        CHECK(have == 0, "pruned END_HEIGHT still reported"); OK();
    }

    nodus_tm_wal_close(&w);
    fx_close(&fx);
    return 0;
}

/* ── tm_state ────────────────────────────────────────────────────────── */

static void state_fill(nodus_tm_state_row_t *r, uint32_t n) {
    memset(r, 0, sizeof(*r));
    r->height = 4242;
    for (int i = 0; i < 64; i++) r->vset_hash[i] = (uint8_t)(0xB0 + i);
    r->n = n;
    for (uint32_t i = 0; i < n; i++) {
        memset(r->voter_id[i], (int)(i & 0xFF), 32);
        r->priority[i] = (int64_t)i * -7;
    }
    /* The edges of the signed range, so the two's-complement round trip
     * is exercised rather than assumed. */
    if (n > 0) r->priority[0] = INT64_MIN;
    if (n > 1) r->priority[1] = INT64_MAX;
    r->proposer_idx = n ? n - 1 : 0;
}

static int state_equal(const nodus_tm_state_row_t *a,
                       const nodus_tm_state_row_t *b) {
    if (a->height != b->height || a->n != b->n ||
        a->proposer_idx != b->proposer_idx) return 0;
    if (memcmp(a->vset_hash, b->vset_hash, 64) != 0) return 0;
    for (uint32_t i = 0; i < a->n; i++) {
        if (memcmp(a->voter_id[i], b->voter_id[i], 32) != 0) return 0;
        if (a->priority[i] != b->priority[i]) return 0;
    }
    return 1;
}

static int test_state(void) {
    fixture_t fx;
    nodus_tm_wal_t *w = NULL;
    nodus_tm_state_row_t *in = NULL, *out = NULL;
    uint8_t *payload = NULL, *raw = NULL;
    int rc = 1;

    /* ~5.2 KB apiece — heap, per the tree's fixture rule. */
    in  = calloc(1, sizeof(*in));
    out = calloc(1, sizeof(*out));
    payload = calloc(1, NODUS_TM_STATE_MAX_PAYLOAD + 128);
    raw = calloc(1, NODUS_TM_STATE_MAX_PAYLOAD + 256);
    CHECK(in && out && payload && raw, "state fixtures");

    CHECK(fx_open(&fx) == 0, "state fixture open"); OK();
    CHECK(nodus_tm_wal_open(&w, fx.w->db, 1) == 0, "wal open for state"); OK();

    /* No row yet. */
    {
        int have = 1;
        CHECK(nodus_tm_state_read(w, &have, out) == 0, "state read (empty)");
        CHECK(have == 0, "empty tm_state reported a row"); OK();
    }

    /* ── n = 4: the published length is 240 payload bytes ───────────── */
    {
        size_t written = 0;
        state_fill(in, 4);
        CHECK(nodus_tm_state_encode(in, payload,
                  NODUS_TM_STATE_MAX_PAYLOAD, &written) == 0, "encode n=4");
        CHECK(written == 240, "n=4 payload is not 240 bytes"); OK();
        CHECK(NODUS_TM_STATE_PAYLOAD_LEN(4) == 240, "the macro disagrees"); OK();

        CHECK(nodus_tm_state_decode(payload, written, out) == 0, "decode n=4");
        CHECK(state_equal(in, out), "n=4 round trip lost a field"); OK();

        CHECK(nodus_tm_state_write(w, in) == 0, "state write n=4"); OK();
        int n = state_bytes(fx.w->db, raw, NODUS_TM_STATE_MAX_PAYLOAD + 256);
        CHECK(n == 240 + 64, "stored n=4 row is not 304 bytes"); OK();
        CHECK(digest_prefix_ok(raw, (size_t)n), "n=4 row digest"); OK();
        CHECK(memcmp(raw + 64, payload, 240) == 0,
              "stored payload differs from the encoder's"); OK();

        memset(out, 0, sizeof(*out));
        int have = 0;
        CHECK(nodus_tm_state_read(w, &have, out) == 0, "state read n=4");
        CHECK(have == 1 && state_equal(in, out), "state read n=4 round trip"); OK();
    }

    /* ── n = 128: the ceiling, 5 200 payload bytes ──────────────────── */
    {
        size_t written = 0;
        state_fill(in, DNA_MAX_ACTIVE_VALIDATORS);
        CHECK(nodus_tm_state_encode(in, payload,
                  NODUS_TM_STATE_MAX_PAYLOAD, &written) == 0, "encode n=128");
        CHECK(written == 5200, "n=128 payload is not 5200 bytes"); OK();
        CHECK(NODUS_TM_STATE_MAX_PAYLOAD == 5200, "the ceiling macro"); OK();

        CHECK(nodus_tm_state_write(w, in) == 0, "state write n=128"); OK();
        int n = state_bytes(fx.w->db, raw, NODUS_TM_STATE_MAX_PAYLOAD + 256);
        CHECK(n == 5200 + 64, "stored n=128 row is not 5264 bytes"); OK();
        CHECK(digest_prefix_ok(raw, (size_t)n), "n=128 row digest"); OK();

        memset(out, 0, sizeof(*out));
        int have = 0;
        CHECK(nodus_tm_state_read(w, &have, out) == 0, "state read n=128");
        CHECK(have == 1 && state_equal(in, out),
              "n=128 round trip lost a field"); OK();
        /* INSERT OR REPLACE: the n=4 row was overwritten, not joined by a
         * second row — tm_state holds the CURRENT set and nothing else. */
        CHECK(count_rows(fx.w->db, "SELECT COUNT(*) FROM tm_state") == 1,
              "tm_state grew a second row"); OK();
    }

    /* ── Strict decode ──────────────────────────────────────────────── */
    {
        size_t written = 0;
        state_fill(in, 4);
        CHECK(nodus_tm_state_encode(in, payload,
                  NODUS_TM_STATE_MAX_PAYLOAD, &written) == 0, "encode again");

        CHECK(nodus_tm_state_decode(payload, written - 1, out) == -1,
              "a short payload decoded"); OK();
        CHECK(nodus_tm_state_decode(payload, written + 1, out) == -1,
              "a trailing byte was ignored"); OK();
        CHECK(nodus_tm_state_decode(payload, 79, out) == -1,
              "a truncated header decoded"); OK();

        /* n = 129 exceeds DNA_MAX_ACTIVE_VALIDATORS: rejected even when
         * the buffer really is 80 + 40 × 129 bytes long. */
        payload[72] = 0; payload[73] = 0; payload[74] = 0; payload[75] = 129;
        CHECK(nodus_tm_state_decode(payload, 80u + 40u * 129u, out) == -1,
              "n=129 decoded"); OK();

        /* Encode refuses the same over-sized set, and a cap that is one
         * byte short. */
        in->n = DNA_MAX_ACTIVE_VALIDATORS + 1;
        CHECK(nodus_tm_state_encode(in, payload,
                  NODUS_TM_STATE_MAX_PAYLOAD, &written) == -1,
              "encode accepted n=129"); OK();
        in->n = 4;
        CHECK(nodus_tm_state_encode(in, payload, 239, &written) == -1,
              "encode overran a short buffer"); OK();
        CHECK(nodus_tm_state_encode(NULL, payload, 240, &written) == -1,
              "encode accepted a NULL row"); OK();
    }

    /* ── A flipped bit in the state row is a FAULT ──────────────────── */
    {
        int have = 0;
        CHECK(flip_state_bit(fx.w->db, 3) == 0, "flip a state digest bit"); OK();
        CHECK(nodus_tm_state_read(w, &have, out) == -2,
              "corrupt state row did not FAULT"); OK();
        CHECK(have == 0, "a faulted state read reported a row"); OK();

        CHECK(flip_state_bit(fx.w->db, 3) == 0, "restore the state bit");
        CHECK(nodus_tm_state_read(w, &have, out) == 0,
              "state row not healthy after restore"); OK();
        CHECK(have == 1, "restored state row went missing"); OK();
    }

    rc = 0;
    nodus_tm_wal_close(&w);
    fx_close(&fx);
    free(in); free(out); free(payload); free(raw);
    return rc;
}

int main(void) {
    if (test_startup_table() != 0) return 1;
    if (test_open_refusals() != 0) return 1;
    if (test_wal_body() != 0) return 1;
    if (test_state() != 0) return 1;

    printf("test_tm_wal: ALL %d checks passed\n", g_checks);
    return 0;
}
