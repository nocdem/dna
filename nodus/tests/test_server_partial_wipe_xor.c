/**
 * Nodus — Server Partial-Wipe XOR Tests (PR 3 / E5, marker-gated)
 *
 * Verifies the H-10 partial-wipe detection at server init. The 3
 * SQLite DBs under data_path (nodus.db, channels.db, witness_*.db)
 * MUST be in a consistent state at boot — but the strict invariant
 * is gated on the genesis marker (.witness_db_seen) that
 * nodus_witness_create_chain_db drops on first chain DB creation.
 *
 * Coverage:
 *   1. NULL data_path                                          -> -1
 *   2. marker absent, all 3 absent (fresh node)                ->  0
 *   3. marker absent, only nodus.db (mid-bootstrap-ish)        ->  0
 *   4. marker absent, only channels.db (mid-bootstrap-ish)     ->  0
 *   5. marker absent, only witness present                     ->  0
 *   6. marker absent, nodus + channels (real stagef state!)    ->  0
 *   7. marker absent, all 3 present                            ->  0
 *   8. marker present, all 3 absent (everything wiped)         ->  0
 *   9. marker present, all 3 present (normal post-genesis boot)->  0
 *  10. marker present, only witness present                    -> -1
 *  11. marker present, only nodus.db wiped                     -> -1
 *  12. marker present, only channels.db wiped                  -> -1
 *  13. marker present, only witness wiped (operator mistake!)  -> -1
 *
 * Cases 6 + 13 are the regression pair that motivated the marker:
 * file-level identical, but case 6 is legitimate fresh-node bring-up
 * (must pass) and case 13 is post-genesis operator wipe (must fail).
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

/* Touch any subset of {nodus.db, channels.db, witness_<hex>.db}
 * inside dir. Each parameter is treated as a boolean. */
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

/* Drop the post-genesis marker (.witness_db_seen) into dir. This is
 * the side-channel signal nodus_witness_create_chain_db writes after
 * the chain DB lands. Without it, the partial-wipe gate stays open. */
static int seed_marker(const char *dir) {
    char p[512];
    snprintf(p, sizeof(p), "%s/%s",
             dir, NODUS_PARTIAL_WIPE_GENESIS_MARKER);
    return touch_file(p);
}

/* Helper: assert nodus_server_check_partial_wipe(dir) returns expect. */
static void assert_rc(const char *dir, int expect, const char *fail_msg) {
    int rc = nodus_server_check_partial_wipe(dir);
    if (rc != expect) FAIL(fail_msg); else PASS();
    rmrf_dir(dir);
}

static void test_null_data_path_rejected(void) {
    TEST("NULL data_path -> rc=-1");
    int rc = nodus_server_check_partial_wipe(NULL);
    if (rc != -1) { FAIL("expected -1"); return; }
    PASS();
}

/* ── Pre-genesis (marker absent) — all subsets must pass ─────────── */

static void test_pre_genesis_all_absent(void) {
    TEST("pre-genesis, all 3 DBs absent -> rc=0 (fresh node)");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    assert_rc(dir, 0, "expected 0");
}

static void test_pre_genesis_only_nodus(void) {
    TEST("pre-genesis, only nodus.db -> rc=0");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    if (seed_dbs(dir, 1, 0, 0) != 0) { FAIL("seed"); rmrf_dir(dir); return; }
    assert_rc(dir, 0, "expected 0");
}

static void test_pre_genesis_only_channels(void) {
    TEST("pre-genesis, only channels.db -> rc=0");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    if (seed_dbs(dir, 0, 1, 0) != 0) { FAIL("seed"); rmrf_dir(dir); return; }
    assert_rc(dir, 0, "expected 0");
}

static void test_pre_genesis_only_witness(void) {
    TEST("pre-genesis, only witness -> rc=0");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    if (seed_dbs(dir, 0, 0, 1) != 0) { FAIL("seed"); rmrf_dir(dir); return; }
    assert_rc(dir, 0, "expected 0");
}

static void test_pre_genesis_nodus_and_channels(void) {
    TEST("pre-genesis, nodus + channels (stagef pre-spawn state) -> rc=0");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    if (seed_dbs(dir, 1, 1, 0) != 0) { FAIL("seed"); rmrf_dir(dir); return; }
    assert_rc(dir, 0, "expected 0 (mid-bootstrap is legitimate)");
}

static void test_pre_genesis_all_present(void) {
    TEST("pre-genesis, all 3 present (impossible-but-pass) -> rc=0");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    if (seed_dbs(dir, 1, 1, 1) != 0) { FAIL("seed"); rmrf_dir(dir); return; }
    assert_rc(dir, 0, "expected 0");
}

/* ── Post-genesis (marker present) — strict XOR enforced ─────────── */

static void test_post_genesis_all_absent(void) {
    TEST("post-genesis, all 3 absent (operator wiped DBs, kept marker) -> rc=0");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    if (seed_marker(dir) != 0) { FAIL("seed marker"); rmrf_dir(dir); return; }
    assert_rc(dir, 0, "expected 0 (treat as fresh-equivalent)");
}

static void test_post_genesis_all_present(void) {
    TEST("post-genesis, all 3 present (normal boot) -> rc=0");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    if (seed_marker(dir) != 0) { FAIL("seed marker"); rmrf_dir(dir); return; }
    if (seed_dbs(dir, 1, 1, 1) != 0) { FAIL("seed"); rmrf_dir(dir); return; }
    assert_rc(dir, 0, "expected 0");
}

static void test_post_genesis_only_witness_present(void) {
    TEST("post-genesis, only witness present (nodus+channels wiped) -> rc=-1");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    if (seed_marker(dir) != 0) { FAIL("seed marker"); rmrf_dir(dir); return; }
    if (seed_dbs(dir, 0, 0, 1) != 0) { FAIL("seed"); rmrf_dir(dir); return; }
    assert_rc(dir, -1, "expected -1 (partial wipe)");
}

static void test_post_genesis_only_nodus_missing(void) {
    TEST("post-genesis, only nodus.db wiped -> rc=-1");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    if (seed_marker(dir) != 0) { FAIL("seed marker"); rmrf_dir(dir); return; }
    if (seed_dbs(dir, 0, 1, 1) != 0) { FAIL("seed"); rmrf_dir(dir); return; }
    assert_rc(dir, -1, "expected -1 (partial wipe)");
}

static void test_post_genesis_only_channels_missing(void) {
    TEST("post-genesis, only channels.db wiped -> rc=-1");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    if (seed_marker(dir) != 0) { FAIL("seed marker"); rmrf_dir(dir); return; }
    if (seed_dbs(dir, 1, 0, 1) != 0) { FAIL("seed"); rmrf_dir(dir); return; }
    assert_rc(dir, -1, "expected -1 (partial wipe)");
}

static void test_post_genesis_only_witness_missing(void) {
    TEST("post-genesis, only witness wiped (operator mistake) -> rc=-1");
    char dir[256];
    if (make_temp_dir(dir, sizeof(dir)) != 0) { FAIL("mkdtemp"); return; }
    if (seed_marker(dir) != 0) { FAIL("seed marker"); rmrf_dir(dir); return; }
    if (seed_dbs(dir, 1, 1, 0) != 0) { FAIL("seed"); rmrf_dir(dir); return; }
    assert_rc(dir, -1, "expected -1 (partial wipe)");
}

int main(void) {
    printf("\nNodus Server Partial-Wipe XOR Tests (PR 3 / E5, marker-gated)\n");
    printf("==============================================================\n\n");

    test_null_data_path_rejected();

    printf("  -- pre-genesis (marker absent) — all subsets pass --\n");
    test_pre_genesis_all_absent();
    test_pre_genesis_only_nodus();
    test_pre_genesis_only_channels();
    test_pre_genesis_only_witness();
    test_pre_genesis_nodus_and_channels();
    test_pre_genesis_all_present();

    printf("  -- post-genesis (marker present) — strict XOR --\n");
    test_post_genesis_all_absent();
    test_post_genesis_all_present();
    test_post_genesis_only_witness_present();
    test_post_genesis_only_nodus_missing();
    test_post_genesis_only_channels_missing();
    test_post_genesis_only_witness_missing();

    printf("\n==============================================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
