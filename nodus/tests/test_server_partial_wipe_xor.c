/**
 * Nodus — Server Partial-Wipe XOR Tests (PR 3 / E5)
 *
 * Verifies the H-10 partial-wipe detection at server init. The 3
 * SQLite DBs under data_path (nodus.db, channels.db, witness_*.db)
 * MUST be in a consistent state at boot — all-present or all-absent.
 * Mixed presence indicates an operator deleted one DB by mistake;
 * the server MUST refuse start to surface the accident before any
 * auto-create masks it.
 *
 * RED state for E5: the stub returns 0 unconditionally (except for
 * NULL input), so the partial-wipe assertions fail. The GREEN commit
 * replaces the stub with the real scan + XOR logic.
 */

#include "server/nodus_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define TEST(name) do { printf("  %-66s", name); fflush(stdout); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static int make_temp_dir(char *out, size_t n) {
    snprintf(out, n, "/tmp/test_partial_wipe_XXXXXX");
    if (!mkdtemp(out)) return -1;
    return 0;
}

static int touch_file(const char *path) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return -1;
    close(fd);
    return 0;
}

static void rmrf_dir(const char *root) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", root);
    int rc = system(cmd);
    (void)rc;
}

/* Convenience: touch any subset of {nodus.db, channels.db,
 * witness_<hex>.db} inside `dir`. Each parameter is treated as a
 * boolean (non-zero -> create file). */
static int seed_dbs(const char *dir,
                    int with_nodus,
                    int with_channels,
                    int with_witness) {
    char p[512];
    if (with_nodus) {
        snprintf(p, sizeof(p), "%s/nodus.db", dir);
        if (touch_file(p) != 0) return -1;
    }
    if (with_channels) {
        snprintf(p, sizeof(p), "%s/channels.db", dir);
        if (touch_file(p) != 0) return -1;
    }
    if (with_witness) {
        snprintf(p, sizeof(p),
                 "%s/witness_aabbccddeeff00112233445566778899.db", dir);
        if (touch_file(p) != 0) return -1;
    }
    return 0;
}

static void test_null_data_path_rejected(void) {
    TEST("NULL data_path -> rc=-1");
    int rc = nodus_server_check_partial_wipe(NULL);
    if (rc != -1) { FAIL("expected -1"); return; }
    PASS();
}

static void test_all_absent_consistent(void) {
    TEST("all 3 DBs absent (fresh node) -> rc=0 (boot allowed)");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    int rc = nodus_server_check_partial_wipe(dir);
    if (rc != 0) { FAIL("expected 0"); rmrf_dir(dir); return; }
    PASS();
    rmrf_dir(dir);
}

static void test_all_present_consistent(void) {
    TEST("all 3 DBs present (normal boot) -> rc=0");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    if (seed_dbs(dir, 1, 1, 1) != 0) { FAIL("seed"); rmrf_dir(dir); return; }
    int rc = nodus_server_check_partial_wipe(dir);
    if (rc != 0) { FAIL("expected 0"); rmrf_dir(dir); return; }
    PASS();
    rmrf_dir(dir);
}

static void test_only_witness_present_refused(void) {
    TEST("only witness present (nodus + channels wiped) -> rc=-1");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    if (seed_dbs(dir, 0, 0, 1) != 0) { FAIL("seed"); rmrf_dir(dir); return; }
    int rc = nodus_server_check_partial_wipe(dir);
    if (rc != -1) {
        FAIL("expected -1 (partial wipe)");
        rmrf_dir(dir); return;
    }
    PASS();
    rmrf_dir(dir);
}

static void test_only_nodus_missing_refused(void) {
    TEST("only nodus.db wiped (channels + witness present) -> rc=-1");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    if (seed_dbs(dir, 0, 1, 1) != 0) { FAIL("seed"); rmrf_dir(dir); return; }
    int rc = nodus_server_check_partial_wipe(dir);
    if (rc != -1) {
        FAIL("expected -1 (partial wipe)");
        rmrf_dir(dir); return;
    }
    PASS();
    rmrf_dir(dir);
}

static void test_only_channels_missing_refused(void) {
    TEST("only channels.db wiped (nodus + witness present) -> rc=-1");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    if (seed_dbs(dir, 1, 0, 1) != 0) { FAIL("seed"); rmrf_dir(dir); return; }
    int rc = nodus_server_check_partial_wipe(dir);
    if (rc != -1) {
        FAIL("expected -1 (partial wipe)");
        rmrf_dir(dir); return;
    }
    PASS();
    rmrf_dir(dir);
}

static void test_only_witness_missing_refused(void) {
    TEST("only witness wiped (nodus + channels present) -> rc=-1");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    if (seed_dbs(dir, 1, 1, 0) != 0) { FAIL("seed"); rmrf_dir(dir); return; }
    int rc = nodus_server_check_partial_wipe(dir);
    if (rc != -1) {
        FAIL("expected -1 (partial wipe)");
        rmrf_dir(dir); return;
    }
    PASS();
    rmrf_dir(dir);
}

int main(void) {
    printf("\nNodus Server Partial-Wipe XOR Tests (PR 3 / E5)\n");
    printf("================================================\n\n");

    test_null_data_path_rejected();
    test_all_absent_consistent();
    test_all_present_consistent();
    test_only_witness_present_refused();
    test_only_nodus_missing_refused();
    test_only_channels_missing_refused();
    test_only_witness_missing_refused();

    printf("\n================================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
