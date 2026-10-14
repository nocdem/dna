/**
 * Nodus — role-based block retention: the pure decision
 *
 * nodus_role_prune_retain_height / nodus_role_prune_base
 * (src/witness/nodus_witness_role_prune.h "THE DECISION"; decision
 * docs/plans/decisions/2026-10-14-role-based-pruning.md):
 *   - every row of the decision table: ARCHIVE (with and without roles),
 *     AUTO with no role / validator / storage / both, EXPLICIT N with and
 *     without roles;
 *   - height <= base and height == base + 1 (the first prune);
 *   - the storage guard: below the role's retain height (binds), above it
 *     (does not), none (every assigned file complete), the unpublished-
 *     period clamp, both together (the lower wins), a guard of 1;
 *   - the guard is ignored for a node that is not a storage member;
 *   - EXPLICIT N with the storage guard;
 *   - a fault answers 0 for every mode;
 *   - AUTO with auto_blocks 0 (below the evidence-window floor) keeps all;
 *   - NODUS_PRUNE_AUTO_RETAIN = 7 × DNA_V2_SEGMENT_BLOCKS.
 * HOW IT CAN LIE: only the pure function is exercised — how the roles and
 * the guard are READ from committed state and the segment directory
 * (nodus_role_prune_commit) is not; that path needs a chain and files.
 * No database, no files, no network, no environment.
 */

#include "witness/nodus_witness_role_prune.h"

#include <stdio.h>
#include <string.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

#define A NODUS_PRUNE_AUTO_RETAIN
#define P ((int64_t)DNA_V2_SEGMENT_BLOCKS)

/* An input with the AUTO base enabled and no guard. */
static nodus_prune_in_t in_of(nodus_prune_cfg_t cfg, int64_t height,
                              bool val, bool sto) {
    nodus_prune_in_t in;
    memset(&in, 0, sizeof(in));
    in.height = height;
    in.cfg = cfg;
    in.auto_blocks = A;
    in.is_validator = val;
    in.is_storage = sto;
    in.keep_from_segment = 0;
    /* far above any retain height used below: the clamp does not bind */
    in.keep_from_unpublished = INT64_MAX;
    return in;
}

static void expect(const char *name, const nodus_prune_in_t *in,
                   int64_t want) {
    TEST(name);
    int64_t got = nodus_role_prune_retain_height(in);
    if (got == want) {
        PASS();
    } else {
        char m[128];
        snprintf(m, sizeof(m), "got %lld, want %lld", (long long)got,
                 (long long)want);
        FAIL(m);
    }
}

static void t_constant(void) {
    TEST("AUTO retain = 7 x segment length");
    if (A == (int64_t)(7u * DNA_V2_SEGMENT_BLOCKS) && A > 0 &&
        (DNAC_EPOCH_LENGTH != 720 || A == 120960))
        PASS();
    else
        FAIL("constant");
}

static void t_archive(void) {
    const int64_t h = 3 * A;
    nodus_prune_in_t in = in_of(NODUS_PRUNE_CFG_ARCHIVE, h, false, false);
    expect("ARCHIVE, no role -> 0", &in, 0);
    in = in_of(NODUS_PRUNE_CFG_ARCHIVE, h, true, false);
    expect("ARCHIVE, validator -> 0", &in, 0);
    in = in_of(NODUS_PRUNE_CFG_ARCHIVE, h, true, true);
    in.keep_from_segment = 5;
    expect("ARCHIVE, validator + storage -> 0", &in, 0);
    in = in_of(NODUS_PRUNE_CFG_ARCHIVE, h, false, true);
    in.cfg_blocks = 200000;           /* ignored: ARCHIVE is 0 */
    expect("ARCHIVE, storage, cfg_blocks set -> 0", &in, 0);
}

static void t_auto(void) {
    const int64_t h = 3 * A;
    nodus_prune_in_t in = in_of(NODUS_PRUNE_CFG_AUTO, h, false, false);
    expect("AUTO, no role -> 0 (keeps everything)", &in, 0);
    in = in_of(NODUS_PRUNE_CFG_AUTO, h, true, false);
    expect("AUTO, validator -> h - A + 1", &in, h - A + 1);
    in = in_of(NODUS_PRUNE_CFG_AUTO, h, false, true);
    expect("AUTO, storage, no guard -> h - A + 1", &in, h - A + 1);
    in = in_of(NODUS_PRUNE_CFG_AUTO, h, true, true);
    expect("AUTO, validator + storage, no guard -> h - A + 1", &in,
           h - A + 1);

    in = in_of(NODUS_PRUNE_CFG_AUTO, A, true, false);
    expect("AUTO, validator, height == A -> 0", &in, 0);
    in = in_of(NODUS_PRUNE_CFG_AUTO, A - 1, true, false);
    expect("AUTO, validator, height < A -> 0", &in, 0);
    in = in_of(NODUS_PRUNE_CFG_AUTO, A + 1, true, false);
    expect("AUTO, validator, height == A + 1 -> 2", &in, 2);

    in = in_of(NODUS_PRUNE_CFG_AUTO, h, true, true);
    in.auto_blocks = 0;
    expect("AUTO below the floor (auto_blocks 0) -> 0", &in, 0);
}

static void t_guard(void) {
    const int64_t h = 10 * A;
    const int64_t r = h - A + 1;          /* the unguarded answer */
    nodus_prune_in_t in = in_of(NODUS_PRUNE_CFG_AUTO, h, false, true);

    in.keep_from_segment = 2 * P + 1;     /* segment 3 incomplete */
    expect("storage guard below R binds", &in, 2 * P + 1);

    in.keep_from_segment = r + P;         /* incomplete above R */
    expect("storage guard above R does not bind", &in, r);

    in.keep_from_segment = 0;
    expect("storage guard none -> R", &in, r);

    in.keep_from_unpublished = r - 7;     /* the current period */
    expect("unpublished-period clamp binds", &in, r - 7);

    in.keep_from_segment = r - 100;
    in.keep_from_unpublished = r - 7;
    expect("segment guard and clamp: the lower wins (segment)", &in,
           r - 100);
    in.keep_from_segment = r - 7;
    in.keep_from_unpublished = r - 100;
    expect("segment guard and clamp: the lower wins (clamp)", &in, r - 100);

    in.keep_from_segment = 1;
    in.keep_from_unpublished = INT64_MAX;
    expect("guard 1 (first segment incomplete) -> 0", &in, 0);
    in.keep_from_segment = 0;
    in.keep_from_unpublished = 1;         /* nothing published yet */
    expect("nothing published (clamp 1) -> 0", &in, 0);

    in = in_of(NODUS_PRUNE_CFG_AUTO, h, true, true);
    in.keep_from_segment = 2 * P + 1;
    expect("validator + storage: guard applies", &in, 2 * P + 1);

    in = in_of(NODUS_PRUNE_CFG_AUTO, h, true, false);
    in.keep_from_segment = 2 * P + 1;
    in.keep_from_unpublished = 1;
    expect("validator only: guard ignored", &in, r);

    in = in_of(NODUS_PRUNE_CFG_AUTO, A - 5, false, true);
    in.keep_from_segment = 1;
    expect("storage, height <= base -> 0", &in, 0);
}

static void t_explicit(void) {
    const int64_t n = 150000;
    const int64_t h = 1000000;
    nodus_prune_in_t in = in_of(NODUS_PRUNE_CFG_EXPLICIT, h, false, false);
    in.cfg_blocks = n;
    expect("EXPLICIT N, no role -> h - N + 1", &in, h - n + 1);
    in.is_validator = true;
    expect("EXPLICIT N, validator -> h - N + 1", &in, h - n + 1);
    in.auto_blocks = 0;
    expect("EXPLICIT N ignores auto_blocks", &in, h - n + 1);

    in = in_of(NODUS_PRUNE_CFG_EXPLICIT, h, false, true);
    in.cfg_blocks = n;
    in.keep_from_segment = 3 * P + 1;
    expect("EXPLICIT N, storage guard binds", &in, 3 * P + 1);
    in.keep_from_segment = h;             /* above h - N + 1 */
    expect("EXPLICIT N, storage guard above R", &in, h - n + 1);
    in.keep_from_segment = 0;
    in.keep_from_unpublished = h - n - 10;
    expect("EXPLICIT N, unpublished clamp binds", &in, h - n - 10);

    in = in_of(NODUS_PRUNE_CFG_EXPLICIT, n, false, false);
    in.cfg_blocks = n;
    expect("EXPLICIT N, height == N -> 0", &in, 0);
}

static void t_fault(void) {
    const int64_t h = 3 * A;
    nodus_prune_in_t in = in_of(NODUS_PRUNE_CFG_AUTO, h, true, false);
    in.fault = true;
    expect("fault, AUTO validator -> 0", &in, 0);
    in = in_of(NODUS_PRUNE_CFG_AUTO, h, false, true);
    in.fault = true;
    expect("fault, AUTO storage -> 0", &in, 0);
    in = in_of(NODUS_PRUNE_CFG_EXPLICIT, h, false, true);
    in.cfg_blocks = 150000;
    in.fault = true;
    expect("fault, EXPLICIT N -> 0", &in, 0);
    in = in_of(NODUS_PRUNE_CFG_ARCHIVE, h, false, false);
    in.fault = true;
    expect("fault, ARCHIVE -> 0", &in, 0);
    TEST("NULL input -> 0");
    if (nodus_role_prune_retain_height(NULL) == 0) PASS();
    else FAIL("NULL");
}

static void t_base(void) {
    nodus_prune_in_t in = in_of(NODUS_PRUNE_CFG_AUTO, 1, false, false);
    int ok = nodus_role_prune_base(&in) == 0;
    in.is_validator = true;
    ok = ok && nodus_role_prune_base(&in) == A;
    in.is_validator = false;
    in.is_storage = true;
    ok = ok && nodus_role_prune_base(&in) == A;
    in.cfg = NODUS_PRUNE_CFG_ARCHIVE;
    ok = ok && nodus_role_prune_base(&in) == 0;
    in.cfg = NODUS_PRUNE_CFG_EXPLICIT;
    in.cfg_blocks = 123456;
    ok = ok && nodus_role_prune_base(&in) == 123456;
    ok = ok && nodus_role_prune_base(NULL) == 0;
    TEST("base per mode and role");
    if (ok) PASS();
    else FAIL("base");
}

int main(void) {
    printf("test_role_prune\n");
    t_constant();
    t_archive();
    t_auto();
    t_guard();
    t_explicit();
    t_fault();
    t_base();
    printf("%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
