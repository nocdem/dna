/**
 * @file nodus/tests/test_v2_migration_toctou.c
 * @brief O15A obligation 5 — the state validated for migration must be
 *        the exact state migrated and committed.
 *
 * ── THE HAZARD ────────────────────────────────────────────────────────
 * The v8→v9 migration rebuilds `v2_blocks` (`DROP TABLE IF EXISTS` — the
 * column it adds is NOT NULL and SQLite cannot add one without a default,
 * and a defaulted header is exactly the hole the column closes). It is
 * only safe because it refuses to run on a populated table.
 *
 * Before O15A that refusal, and the schema-version check, were both
 * evaluated BEFORE `BEGIN IMMEDIATE` took its write lock. A connection
 * that committed a block inside that window would have had it dropped by
 * a migration that had already concluded the table was empty — and by
 * this migration's own reasoning those canonical header bytes cannot be
 * reconstructed. Silent, unrecoverable loss of committed consensus state.
 *
 * ── WHAT THIS TEST PROVES ─────────────────────────────────────────────
 * A SECOND CONNECTION to the same database file — not a second handle on
 * the same connection — writes at the migration seam. The invariant is
 * that its write must land wholly BEFORE the protected snapshot (and be
 * seen, so the migration refuses) or wholly AFTER (blocked by the write
 * lock), never in between.
 *
 * O14 rated this LOW because "a second writer does not exist
 * (single-process, single-connection)". That is a deployment property,
 * not a property of the code, and it is exactly the kind of assumption
 * that stops being true without anyone revisiting the migration. The
 * invariant is tested directly instead.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <pthread.h>
#include <unistd.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"

static int checks;
#define CHECK(c, msg)                                                     \
    do {                                                                  \
        if (!(c)) {                                                       \
            printf("CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,      \
                   msg);                                                  \
            exit(1);                                                      \
        }                                                                 \
        checks++;                                                         \
    } while (0)

/* A witness handle wrapping a real on-disk database, so a genuinely
 * separate sqlite3 connection can be opened against the same file. */
typedef struct {
    char             dir[256];
    char             path[512];
    nodus_witness_t *w;
} fx_t;

static int fx_open(fx_t *f, const char *tag) {
    snprintf(f->dir, sizeof(f->dir), "/tmp/test_v2_toctou_%s_XXXXXX", tag);
    if (!mkdtemp(f->dir)) return -1;

    f->w = calloc(1, sizeof(*f->w));      /* multi-MB — never on stack */
    if (!f->w) return -1;
    snprintf(f->w->data_path, sizeof(f->w->data_path), "%s", f->dir);

    /* Build the REAL base schema through the production entry point —
     * the v8 migration rebuilds utxo_set and refuses on column drift, so
     * a hand-rolled database is not an acceptable stand-in. */
    uint8_t chain_id16[16];
    memset(chain_id16, 0x2b, sizeof(chain_id16));
    if (nodus_witness_create_chain_db(f->w, chain_id16) != 0) return -1;

    /* The on-disk path create_chain_db chose, so a genuinely separate
     * connection can be opened against the same file. */
    char hex[33];
    for (int i = 0; i < 16; i++)
        snprintf(hex + i * 2, 3, "%02x", chain_id16[i]);
    snprintf(f->path, sizeof(f->path), "%s/witness_%s.db", f->dir, hex);

    (void)sqlite3_busy_timeout(f->w->db, 250);
    return 0;
}

static void fx_close(fx_t *f) {
    if (f->w) {
        if (f->w->db) sqlite3_close(f->w->db);
        free(f->w);
        f->w = NULL;
    }
}

/* Bring the database to exactly schema v8 — the migration's input state. */
static int seed_v8(fx_t *f) {
    return nodus_witness_db_migrate_v2s8(f->w);
}

static uint32_t ver_of(fx_t *f) {
    uint32_t v = 0;
    if (nodus_witness_db_schema_version(f->w, &v) != 0) return 0xffffffffu;
    return v;
}

/* A second, genuinely independent connection. */
static sqlite3 *second_connection(fx_t *f) {
    sqlite3 *db2 = NULL;
    if (sqlite3_open(f->path, &db2) != SQLITE_OK) return NULL;
    (void)sqlite3_busy_timeout(db2, 250);
    return db2;
}

/* Insert one v2_blocks row through `db`, in the SCHEMA-8 shape — the v8
 * table has no `header` column, because adding it is exactly what the v9
 * migration does. Writing a v9-shaped row here would test nothing: the
 * interloper we care about is a node still running the OLD schema. */
static int insert_block_row(sqlite3 *db, sqlite3_int64 height) {
    static const char *sql =
        "INSERT INTO v2_blocks (global_height, block_id, prev_block_id,"
        " epoch, tx_root, domain_updates_root, domains_root, global_root,"
        " vset_hash, tx_count)"
        " VALUES (?1, ?2, ?3, 0, ?4, ?4, ?4, ?4, ?4, 0);";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return SQLITE_ERROR;
    uint8_t id[64], prev[64], root[64];
    memset(id, (int)(height & 0x7f), sizeof(id));
    memset(prev, 0, sizeof(prev));
    memset(root, 0x33, sizeof(root));
    sqlite3_bind_int64(st, 1, height);
    sqlite3_bind_blob(st, 2, id, 64, SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, prev, 64, SQLITE_STATIC);
    sqlite3_bind_blob(st, 4, root, 64, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE) ? SQLITE_OK : rc;
}

static sqlite3_int64 count_rows(sqlite3 *db, const char *table) {
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_int64 n = (sqlite3_step(st) == SQLITE_ROW)
                          ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    return n;
}

/* ── the racing writer ───────────────────────────────────────────────
 * Holds an already-open write transaction on `g_race_db`. It waits long
 * enough for the migration to finish its pre-BEGIN reads and park on
 * BEGIN IMMEDIATE, then inserts a block row and commits — releasing the
 * lock so the migration proceeds with a snapshot that is now stale.
 *
 * The sleep only has to outlast two SELECTs on an empty table; if it
 * ever fired too early the assertions would simply degrade to the
 * already-covered section-3 case rather than passing spuriously. */
static sqlite3 *g_race_db;
static int      g_race_insert_rc = -1;
/* Set by the interloper AFTER its COMMIT lands. Sampled by the main
 * thread immediately before it invokes the migration: if it is still 0 at
 * that instant, the row was not yet committed when the migration began,
 * so the migration's pre-BEGIN COUNT — the first thing it does — read an
 * empty table and cannot be what refused. That is what makes the run
 * discriminating. */
static volatile int g_race_committed;
static int      g_race_pre_begin_saw_empty = -1;

static void *toctou_interloper(void *unused) {
    (void)unused;
    usleep(150000);                       /* 150 ms */
    g_race_insert_rc = insert_block_row(g_race_db, 1);
    if (g_race_insert_rc == SQLITE_OK)
        g_race_insert_rc = (sqlite3_exec(g_race_db, "COMMIT", NULL, NULL,
                                         NULL) == SQLITE_OK)
                               ? SQLITE_OK : -1;
    g_race_committed = 1;
    return NULL;
}

int main(void) {
    printf("=== O15A obligation 5 — migration TOCTOU ===\n");

    /* ── 1. BASELINE: a clean v8 → v9 migration still works. Without
     * this everything below could pass on a migration that never runs. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "base") == 0, "fixture open");
        CHECK(seed_v8(&f) == 0, "seed v8");
        CHECK(ver_of(&f) == NODUS_V2_SCHEMA_VERSION_S8, "v8 reached");
        CHECK(nodus_witness_db_migrate_v2s9(f.w) == 0, "clean migration");
        CHECK(ver_of(&f) == NODUS_V2_SCHEMA_VERSION_S9, "v9 reached");
        fx_close(&f);
    }

    /* ── 2. IDEMPOTENCE: re-running is a no-op success, and repeated
     * runs never mutate. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "idem") == 0, "fixture open");
        CHECK(seed_v8(&f) == 0, "seed v8");
        CHECK(nodus_witness_db_migrate_v2s9(f.w) == 0, "first migration");
        CHECK(nodus_witness_db_migrate_v2s9(f.w) == 0, "second is a no-op");
        CHECK(nodus_witness_db_migrate_v2s9(f.w) == 0, "third is a no-op");
        CHECK(ver_of(&f) == NODUS_V2_SCHEMA_VERSION_S9, "still v9");
        fx_close(&f);
    }

    /* ── 3. THE TOCTOU CASE — the reason this file exists.
     * A SECOND CONNECTION commits a block row after the process has
     * begun migrating but before the protected snapshot could have been
     * taken. The migration must SEE it and refuse; the row must survive.
     *
     * The write is issued while no migration holds the lock, which is
     * precisely the window the old code validated in. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "race") == 0, "fixture open");
        CHECK(seed_v8(&f) == 0, "seed v8");

        sqlite3 *db2 = second_connection(&f);
        CHECK(db2 != NULL, "second connection opened");

        /* The interloper commits through its OWN connection. */
        CHECK(insert_block_row(db2, 1) == SQLITE_OK,
              "second connection committed a block row");
        CHECK(count_rows(f.w->db, "v2_blocks") == 1,
              "the row is visible to the migrating connection");

        /* The migration must now refuse — and, critically, must refuse
         * WITHOUT having dropped the table first. */
        CHECK(nodus_witness_db_migrate_v2s9(f.w) != 0,
              "migration must refuse a populated table");
        CHECK(ver_of(&f) == NODUS_V2_SCHEMA_VERSION_S8,
              "a refused migration must not advance the schema version");
        CHECK(count_rows(f.w->db, "v2_blocks") == 1,
              "THE COMMITTED ROW MUST SURVIVE A REFUSED MIGRATION");

        sqlite3_close(db2);
        fx_close(&f);
    }

    /* ── 3b. THE ACTUAL RACE — the in-transaction check as the DECIDING
     * gate.
     *
     * Section 3 proves the PRE-BEGIN check refuses an already-populated
     * table. It does NOT prove the in-transaction re-check does anything:
     * the row is already there when the migration starts, so the early
     * check fires first and the later one is never reached with new
     * information. (The mutation campaign caught exactly that — deleting
     * the in-transaction check left section 3 green.)
     *
     * This drives the REAL interleaving. A second connection holds a
     * write transaction; the migration's pre-BEGIN COUNT therefore reads
     * an EMPTY table (WAL readers do not block on a writer), then its
     * BEGIN IMMEDIATE blocks. While it is blocked the other connection
     * inserts a block row and commits, releasing the lock. The migration
     * then acquires the lock and MUST notice, inside the transaction,
     * that the state it validated is no longer the state it is about to
     * destroy.
     *
     * Without the in-transaction re-check this DROPs a committed block. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "race2") == 0, "fixture open");
        CHECK(seed_v8(&f) == 0, "seed v8");
        /* WAL so the migration's pre-BEGIN read is not blocked by the
         * writer — that is what creates the stale snapshot. */
        (void)sqlite3_exec(f.w->db, "PRAGMA journal_mode=WAL;", NULL, NULL,
                           NULL);
        /* Long enough that BEGIN IMMEDIATE waits for the interloper
         * instead of failing outright. */
        (void)sqlite3_busy_timeout(f.w->db, 5000);

        sqlite3 *db2 = second_connection(&f);
        CHECK(db2 != NULL, "second connection");
        (void)sqlite3_busy_timeout(db2, 5000);

        /* Hold the write lock BEFORE the migration begins, so its
         * BEGIN IMMEDIATE will have to wait. */
        CHECK(sqlite3_exec(db2, "BEGIN IMMEDIATE", NULL, NULL, NULL)
                  == SQLITE_OK, "interloper took the write lock");

        /* The interloper commits from another thread a moment after the
         * migration starts — i.e. while the migration is parked on
         * BEGIN IMMEDIATE, AFTER its pre-BEGIN COUNT already read an
         * empty table. That is the TOCTOU window, reproduced exactly. */
        g_race_db = db2;
        pthread_t th;
        CHECK(pthread_create(&th, NULL, toctou_interloper, NULL) == 0,
              "interloper thread");

        /* Sampled at the instant of invocation — see g_race_committed. */
        g_race_pre_begin_saw_empty = (g_race_committed == 0) ? 1 : 0;
        int mrc = nodus_witness_db_migrate_v2s9(f.w);
        pthread_join(th, NULL);

        CHECK(g_race_insert_rc == SQLITE_OK,
              "the interloper must have committed its row");

        /* O15A (reviewer R3): `mrc != 0` ALONE is not a sound test of the
         * in-transaction check. If the migrating thread were descheduled
         * past the interloper's commit, the PRE-BEGIN early-out would
         * refuse instead and every assertion would still pass — with the
         * in-transaction check deleted. A green run would then prove only
         * that *some* refusal happened.
         *
         * `g_race_pre_begin_saw_empty` records what the migration's
         * pre-BEGIN snapshot actually observed. Only when it saw an EMPTY
         * table is this run a genuine TOCTOU: the refusal must then have
         * come from INSIDE the transaction, because nothing else looked.
         * When the scheduling did not cooperate the run is reported as
         * NOT DISCRIMINATING rather than counted as proof. */
        CHECK(mrc != 0,
              "MIGRATION VALIDATED A STALE SNAPSHOT — it must notice, "
              "INSIDE the transaction, that v2_blocks is no longer empty");
        if (g_race_pre_begin_saw_empty == 1) {
            printf("  [discriminating] pre-BEGIN saw an EMPTY table, so the "
                   "refusal came from the in-transaction re-check\n");
            checks++;
        } else {
            printf("  [NOT DISCRIMINATING] the interloper committed before "
                   "the migration's pre-BEGIN read (scheduling); this run "
                   "does not prove the in-transaction check — rerun\n");
        }
        CHECK(ver_of(&f) == NODUS_V2_SCHEMA_VERSION_S8,
              "a refused race must not advance the schema version");
        CHECK(count_rows(f.w->db, "v2_blocks") == 1,
              "THE RACING WRITER'S COMMITTED ROW MUST SURVIVE");
        sqlite3_close(db2);
        fx_close(&f);
    }

    /* ── 4. THE IN-TRANSACTION CHECK IS THE DECIDING ONE.
     * Fault-inject at the new re-validation point: the migration must
     * abort with the schema version untouched and the table intact,
     * proving the snapshot is taken BEFORE any mutation. If the DROP had
     * already run by this point, the table would be empty-but-rebuilt. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "reval") == 0, "fixture open");
        CHECK(seed_v8(&f) == 0, "seed v8");
        CHECK(nodus_witness_db_migrate_v2s9_ex(
                  f.w, V2S9MIG_FAIL_AFTER_REVALIDATE) != 0,
              "injected abort at the re-validation point");
        CHECK(ver_of(&f) == NODUS_V2_SCHEMA_VERSION_S8,
              "aborted migration left the version untouched");
        /* A clean retry after the injected fault must still succeed —
         * the abort may not leave the database wedged. */
        CHECK(nodus_witness_db_migrate_v2s9(f.w) == 0,
              "clean retry after an injected abort");
        CHECK(ver_of(&f) == NODUS_V2_SCHEMA_VERSION_S9, "retry reached v9");
        fx_close(&f);
    }

    /* ── 5. EVERY fault point rolls back to exactly v8, and a retry from
     * each still reaches v9. */
    {
        const nodus_v2s9_mig_fail_t pts[] = {
            V2S9MIG_FAIL_AFTER_BEGIN,
            V2S9MIG_FAIL_AFTER_REVALIDATE,
            V2S9MIG_FAIL_AFTER_TABLES,
            V2S9MIG_FAIL_AFTER_VERIFY,
            V2S9MIG_FAIL_BEFORE_COMMIT
        };
        for (size_t i = 0; i < sizeof(pts) / sizeof(pts[0]); i++) {
            fx_t f = {0};
            char tag[32];
            snprintf(tag, sizeof(tag), "fp%zu", i);
            CHECK(fx_open(&f, tag) == 0, "fixture open");
            CHECK(seed_v8(&f) == 0, "seed v8");
            CHECK(nodus_witness_db_migrate_v2s9_ex(f.w, pts[i]) != 0,
                  "fault point must abort");
            CHECK(ver_of(&f) == NODUS_V2_SCHEMA_VERSION_S8,
                  "fault point must roll back to v8");
            CHECK(nodus_witness_db_migrate_v2s9(f.w) == 0,
                  "retry after fault point must succeed");
            CHECK(ver_of(&f) == NODUS_V2_SCHEMA_VERSION_S9,
                  "retry reached v9");
            fx_close(&f);
        }
    }

    /* ── 6. A NEWER schema is refused, not "migrated backwards". */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "newer") == 0, "fixture open");
        CHECK(seed_v8(&f) == 0, "seed v8");
        CHECK(sqlite3_exec(f.w->db, "PRAGMA user_version = 99", NULL, NULL,
                           NULL) == SQLITE_OK, "forced a newer version");
        CHECK(nodus_witness_db_migrate_v2s9(f.w) != 0,
              "a newer schema must be refused");
        CHECK(ver_of(&f) == 99, "refusal must not rewrite the version");
        fx_close(&f);
    }

    printf("test_v2_migration_toctou: ALL %d checks passed\n", checks);
    return 0;
}
