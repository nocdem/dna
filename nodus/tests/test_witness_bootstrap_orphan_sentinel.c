/**
 * Nodus — Witness Auto-Bootstrap Orphan Sentinel Tests (PR 3 / E0)
 *
 * Verifies the startup-time orphan .bootstrap_in_progress sentinel
 * cleanup. The bootstrap path writes a marker BEFORE any chain-DB
 * mutation in handle_genesis_rsp and unlinks it on success. If the
 * process is killed mid-FETCH_GENESIS, the marker survives — the next
 * init MUST detect this, archive any partial witness_<hex>.db files,
 * clear the marker, and let DISCOVER restart cleanly.
 *
 * RED state for E0: the stub in nodus_witness.c returns 0 without
 * performing any recovery, so the cleanup-cleared assertions fail.
 * The GREEN commit replaces the stub with the real recovery body.
 */

#include "witness/nodus_witness.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#define TEST(name) do { printf("  %-62s", name); fflush(stdout); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* mkdtemp template — caller-provided buffer. Returns 0 on success. */
static int make_temp_dir(char *out, size_t n) {
    snprintf(out, n, "/tmp/test_witness_orphan_XXXXXX");
    if (!mkdtemp(out)) return -1;
    return 0;
}

static int touch_file(const char *path) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return -1;
    close(fd);
    return 0;
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

/* Best-effort recursive cleanup. The path comes from mkdtemp under
 * /tmp so there is no shell-injection vector. */
static void rmrf_dir(const char *root) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", root);
    int rc = system(cmd);
    (void)rc;
}

/* Count regular-file entries whose name CONTAINS "witness_" inside
 * the given directory. The archive helper renames db files to
 * "<timestamp>_witness_<hex>.db*", so a substring match is what the
 * forensic-recovery contract guarantees. Returns -1 if dir cannot be
 * opened. */
static int count_witness_files(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strstr(e->d_name, "witness_") != NULL) n++;
    }
    closedir(d);
    return n;
}

static void test_null_data_path_rejected(void) {
    TEST("NULL data_path -> rc=-1");
    int rc = nodus_witness_check_orphan_bootstrap_sentinel(NULL);
    if (rc != -1) { FAIL("expected -1"); return; }
    PASS();
}

static void test_no_sentinel_returns_zero(void) {
    TEST("no sentinel present -> rc=0 (no-op)");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    int rc = nodus_witness_check_orphan_bootstrap_sentinel(dir);
    if (rc != 0) { FAIL("expected 0"); rmrf_dir(dir); return; }
    PASS();
    rmrf_dir(dir);
}

static void test_orphan_sentinel_alone_is_cleared(void) {
    TEST("orphan sentinel alone -> cleared, rc=1");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }

    char sentinel[512];
    snprintf(sentinel, sizeof(sentinel),
             "%s/.bootstrap_in_progress", dir);
    if (touch_file(sentinel) != 0) {
        FAIL("touch sentinel"); rmrf_dir(dir); return;
    }

    int rc = nodus_witness_check_orphan_bootstrap_sentinel(dir);
    if (rc != 1) {
        FAIL("expected rc=1 (recovery performed)");
        rmrf_dir(dir); return;
    }
    if (file_exists(sentinel)) {
        FAIL("sentinel was not cleared");
        rmrf_dir(dir); return;
    }
    PASS();
    rmrf_dir(dir);
}

static void test_orphan_sentinel_with_partial_db_archived(void) {
    TEST("orphan sentinel + partial chain DB -> DB archived, sentinel cleared");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }

    char sentinel[512], db[512], wal[512], shm[512];
    snprintf(sentinel, sizeof(sentinel),
             "%s/.bootstrap_in_progress", dir);
    snprintf(db,  sizeof(db),
             "%s/witness_aabbccddeeff00112233445566778899.db", dir);
    snprintf(wal, sizeof(wal),
             "%s/witness_aabbccddeeff00112233445566778899.db-wal", dir);
    snprintf(shm, sizeof(shm),
             "%s/witness_aabbccddeeff00112233445566778899.db-shm", dir);

    if (touch_file(sentinel) != 0 ||
        touch_file(db)       != 0 ||
        touch_file(wal)      != 0 ||
        touch_file(shm)      != 0) {
        FAIL("touch fixtures"); rmrf_dir(dir); return;
    }

    int rc = nodus_witness_check_orphan_bootstrap_sentinel(dir);
    if (rc != 1) {
        FAIL("expected rc=1");
        rmrf_dir(dir); return;
    }
    if (file_exists(sentinel)) {
        FAIL("sentinel not cleared after recovery");
        rmrf_dir(dir); return;
    }
    if (file_exists(db) || file_exists(wal) || file_exists(shm)) {
        FAIL("partial chain DB files not archived (still in data_path)");
        rmrf_dir(dir); return;
    }

    /* Verify files were MOVED to archive/, not deleted — forensic
     * recovery is part of the contract per the design doc. */
    char archive_dir[512];
    snprintf(archive_dir, sizeof(archive_dir), "%s/archive", dir);
    int n = count_witness_files(archive_dir);
    if (n < 3) {
        FAIL("expected >= 3 archived files (db + wal + shm)");
        rmrf_dir(dir); return;
    }
    PASS();
    rmrf_dir(dir);
}

int main(void) {
    printf("\nNodus Witness Auto-Bootstrap Orphan Sentinel Tests (PR 3 / E0)\n");
    printf("===============================================================\n\n");

    test_null_data_path_rejected();
    test_no_sentinel_returns_zero();
    test_orphan_sentinel_alone_is_cleared();
    test_orphan_sentinel_with_partial_db_archived();

    printf("\n===============================================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
