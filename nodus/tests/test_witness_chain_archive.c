/**
 * Nodus — Witness Chain DB Archive Tests (Fix 1)
 *
 * Verifies that nodus_witness_create_chain_db() atomically archives
 * any pre-existing witness_<other>.db files to data_path/archive/
 * before creating the new chain DB. This prevents the orphan-DB
 * class of bug that produced the EU-6 fork on 2026-04-10.
 *
 * Tests:
 *   1. Stale witness_<old>.db file is archived, not deleted
 *   2. Stale -wal / -shm sidecar files are archived too
 *   3. The target witness_<new>.db file is NOT archived (it's the keep)
 *   4. Archive directory is created on demand
 *   5. Non-witness files in data_path are left untouched
 */

#include "witness/nodus_witness.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sqlite3.h>

#define TEST(name) do { printf("  %-55s", name); fflush(stdout); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static int rm_rf(const char *path) {
    DIR *d = opendir(path);
    if (!d) return unlink(path);
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char child[1024];
        snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
        rm_rf(child);
    }
    closedir(d);
    return rmdir(path);
}

static void touch(const char *path) {
    FILE *f = fopen(path, "w");
    if (f) {
        fputs("stub\n", f);
        fclose(f);
    }
}

/* Find any file in archive/ whose name ends with `suffix`.
 * Returns 1 on match, 0 otherwise. */
static int archive_contains_suffix(const char *archive_dir, const char *suffix) {
    DIR *d = opendir(archive_dir);
    if (!d) return 0;
    int found = 0;
    struct dirent *e;
    size_t slen = strlen(suffix);
    while ((e = readdir(d))) {
        size_t nlen = strlen(e->d_name);
        if (nlen >= slen && strcmp(e->d_name + nlen - slen, suffix) == 0) {
            found = 1;
            break;
        }
    }
    closedir(d);
    return found;
}

/* ── Test fixture ──────────────────────────────────────────────── */

static char g_tmpdir[256];

static int setup_tmpdir(void) {
    snprintf(g_tmpdir, sizeof(g_tmpdir), "/tmp/nodus_witness_archive_test_%d",
             (int)getpid());
    rm_rf(g_tmpdir);
    if (mkdir(g_tmpdir, 0700) != 0) return -1;
    return 0;
}

static void teardown_tmpdir(void) {
    rm_rf(g_tmpdir);
}

static void init_minimal_witness(nodus_witness_t *w) {
    memset(w, 0, sizeof(*w));
    snprintf(w->data_path, sizeof(w->data_path), "%s", g_tmpdir);
}

/* ── Tests ─────────────────────────────────────────────────────── */

static void test_stale_db_archived(void) {
    TEST("stale witness_<old>.db archived, not deleted");

    if (setup_tmpdir() != 0) { FAIL("setup"); return; }

    /* Seed a fake stale DB */
    char stale[512];
    snprintf(stale, sizeof(stale), "%s/witness_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.db", g_tmpdir);
    touch(stale);

    nodus_witness_t w;
    init_minimal_witness(&w);

    /* New chain_id — all 0xBB */
    uint8_t new_id[32];
    memset(new_id, 0xBB, sizeof(new_id));

    if (nodus_witness_create_chain_db(&w, new_id) != 0) {
        FAIL("create_chain_db failed");
        if (w.db) sqlite3_close(w.db);
        teardown_tmpdir();
        return;
    }

    /* Stale file must NO LONGER exist at original location */
    if (file_exists(stale)) {
        FAIL("stale file still at original location");
        sqlite3_close(w.db);
        teardown_tmpdir();
        return;
    }

    /* Archive dir must exist and contain the stale basename */
    char archive_dir[512];
    snprintf(archive_dir, sizeof(archive_dir), "%s/archive", g_tmpdir);
    if (!file_exists(archive_dir)) {
        FAIL("archive dir not created");
        sqlite3_close(w.db);
        teardown_tmpdir();
        return;
    }
    if (!archive_contains_suffix(archive_dir,
            "witness_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.db")) {
        FAIL("archived file not found in archive/");
        sqlite3_close(w.db);
        teardown_tmpdir();
        return;
    }

    /* New target DB must exist */
    char new_db[512];
    snprintf(new_db, sizeof(new_db),
             "%s/witness_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.db", g_tmpdir);
    if (!file_exists(new_db)) {
        FAIL("new chain DB not created");
        sqlite3_close(w.db);
        teardown_tmpdir();
        return;
    }

    sqlite3_close(w.db);
    teardown_tmpdir();
    PASS();
}

static void test_wal_shm_archived(void) {
    TEST("stale -wal / -shm sidecars archived too");

    if (setup_tmpdir() != 0) { FAIL("setup"); return; }

    char db[512], wal[512], shm[512];
    snprintf(db,  sizeof(db),  "%s/witness_cccccccccccccccccccccccccccccccc.db", g_tmpdir);
    snprintf(wal, sizeof(wal), "%s/witness_cccccccccccccccccccccccccccccccc.db-wal", g_tmpdir);
    snprintf(shm, sizeof(shm), "%s/witness_cccccccccccccccccccccccccccccccc.db-shm", g_tmpdir);
    touch(db); touch(wal); touch(shm);

    nodus_witness_t w;
    init_minimal_witness(&w);

    uint8_t new_id[32];
    memset(new_id, 0xDD, sizeof(new_id));

    if (nodus_witness_create_chain_db(&w, new_id) != 0) {
        FAIL("create_chain_db failed");
        teardown_tmpdir();
        return;
    }

    if (file_exists(db) || file_exists(wal) || file_exists(shm)) {
        FAIL("sidecar files still at original location");
        sqlite3_close(w.db);
        teardown_tmpdir();
        return;
    }

    char archive_dir[512];
    snprintf(archive_dir, sizeof(archive_dir), "%s/archive", g_tmpdir);
    int ok = archive_contains_suffix(archive_dir,
                "witness_cccccccccccccccccccccccccccccccc.db") &&
             archive_contains_suffix(archive_dir,
                "witness_cccccccccccccccccccccccccccccccc.db-wal") &&
             archive_contains_suffix(archive_dir,
                "witness_cccccccccccccccccccccccccccccccc.db-shm");
    if (!ok) {
        FAIL("one or more sidecars missing from archive/");
        sqlite3_close(w.db);
        teardown_tmpdir();
        return;
    }

    sqlite3_close(w.db);
    teardown_tmpdir();
    PASS();
}

static void test_target_not_archived(void) {
    TEST("target witness_<new>.db not moved to archive");

    if (setup_tmpdir() != 0) { FAIL("setup"); return; }

    /* Pre-create the target as a valid empty SQLite DB (simulates the
     * idempotent case: same chain_id is being committed again on restart). */
    char target[512];
    snprintf(target, sizeof(target),
             "%s/witness_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.db", g_tmpdir);
    sqlite3 *seed_db = NULL;
    if (sqlite3_open(target, &seed_db) != SQLITE_OK || !seed_db) {
        FAIL("seed sqlite_open");
        if (seed_db) sqlite3_close(seed_db);
        teardown_tmpdir();
        return;
    }
    sqlite3_close(seed_db);

    nodus_witness_t w;
    init_minimal_witness(&w);

    uint8_t new_id[32];
    memset(new_id, 0xEE, sizeof(new_id));

    if (nodus_witness_create_chain_db(&w, new_id) != 0) {
        FAIL("create_chain_db failed");
        teardown_tmpdir();
        return;
    }

    /* Target must still exist at its proper location */
    if (!file_exists(target)) {
        FAIL("target was archived instead of kept");
        sqlite3_close(w.db);
        teardown_tmpdir();
        return;
    }

    /* Archive dir should either not exist, or not contain the target basename */
    char archive_dir[512];
    snprintf(archive_dir, sizeof(archive_dir), "%s/archive", g_tmpdir);
    if (file_exists(archive_dir) &&
        archive_contains_suffix(archive_dir,
            "witness_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.db")) {
        FAIL("target was also copied into archive/");
        sqlite3_close(w.db);
        teardown_tmpdir();
        return;
    }

    sqlite3_close(w.db);
    teardown_tmpdir();
    PASS();
}

static void test_non_witness_files_untouched(void) {
    TEST("non-witness files in data_path left alone");

    if (setup_tmpdir() != 0) { FAIL("setup"); return; }

    /* Seed unrelated files */
    char unrelated[512], dht_db[512];
    snprintf(unrelated, sizeof(unrelated), "%s/random.txt", g_tmpdir);
    snprintf(dht_db, sizeof(dht_db), "%s/nodus.db", g_tmpdir);
    touch(unrelated);
    touch(dht_db);

    nodus_witness_t w;
    init_minimal_witness(&w);

    uint8_t new_id[32];
    memset(new_id, 0xFF, sizeof(new_id));

    if (nodus_witness_create_chain_db(&w, new_id) != 0) {
        FAIL("create_chain_db failed");
        teardown_tmpdir();
        return;
    }

    if (!file_exists(unrelated) || !file_exists(dht_db)) {
        FAIL("non-witness files were moved");
        sqlite3_close(w.db);
        teardown_tmpdir();
        return;
    }

    sqlite3_close(w.db);
    teardown_tmpdir();
    PASS();
}

/* ── Entrypoint ────────────────────────────────────────────────── */

int main(void) {
    printf("\n=== Nodus Witness Chain Archive Tests ===\n");

    test_stale_db_archived();
    test_wal_shm_archived();
    test_target_not_archived();
    test_non_witness_files_untouched();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
