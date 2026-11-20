/**
 * Nodus — scratch derivation directory removal (Z-16)
 *
 * The joiner's adoption derives the genesis in `<data>/.v2join.tmp`, and
 * nodus_witness_create_chain_db makes `<scratch>/archive` there as well as
 * the witness_*.db files. The joiner's own cleanup only unlinked first-level
 * entries: unlink() of the subdirectory fails (EISDIR) and the rmdir() after
 * it fails (ENOTEMPTY), so `.v2join.tmp/archive` survived every join. The
 * joiner now uses nodus_witness_v2_scratch_clear, the helper the genesis
 * derivation already used (O15J R2-F6).
 *
 * Proves: for a scratch directory holding database files (including -wal /
 * -shm) and a nested `archive` directory with files in it, the helper leaves
 * NOTHING of the scratch directory behind (the directory itself is gone),
 * touches nothing beside it (a sibling file and a sibling directory survive),
 * and is a no-op on a path that does not exist and on NULL / "".
 * Flags/env: none. Leaves behind: its mkdtemp base under /tmp is removed.
 * How it can falsely pass: it drives the helper, not the joiner's adoption
 * (that path is asserted by test_witness_p2p.c (2e), which checks the joiner's
 * `.v2join.tmp` is gone after a rejected and after an adopted bundle). The
 * helper is deliberately not a recursive delete: a second nesting level is not
 * cleared (the directory then survives, logged) and is not tested here.
 */

#define _DEFAULT_SOURCE 1   /* mkdtemp */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness_v2_gen.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK fail at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

static void touch(const char *dir, const char *name) {
    char p[600];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    FILE *f = fopen(p, "wb");
    CHECK(f != NULL);
    fputs("x", f);
    fclose(f);
}

static int exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

int main(void) {
    char base[] = "/tmp/test_v2_scratch_clear_XXXXXX";
    CHECK(mkdtemp(base) != NULL);

    char scratch[300], arch[320], sib_file[320], sib_dir[320];
    snprintf(scratch, sizeof(scratch), "%s/.v2join.tmp", base);
    snprintf(arch, sizeof(arch), "%s/archive", scratch);
    snprintf(sib_file, sizeof(sib_file), "%s/keep.txt", base);
    snprintf(sib_dir, sizeof(sib_dir), "%s/keepdir", base);

    CHECK(mkdir(scratch, 0700) == 0);
    CHECK(mkdir(arch, 0700) == 0);
    CHECK(mkdir(sib_dir, 0700) == 0);
    touch(scratch, "witness_aa.db");
    touch(scratch, "witness_aa.db-wal");
    touch(scratch, "witness_aa.db-shm");
    touch(arch, "witness_old.db");
    touch(arch, "witness_older.db");
    touch(base, "keep.txt");

    nodus_witness_v2_scratch_clear(scratch);

    CHECK(!exists(scratch));            /* the directory itself is gone   */
    CHECK(!exists(arch));
    CHECK(exists(sib_file));            /* nothing beside it was touched  */
    CHECK(exists(sib_dir));
    printf("[ok] scratch directory with an archive subdirectory is removed whole\n");

    nodus_witness_v2_scratch_clear(scratch);          /* already gone */
    nodus_witness_v2_scratch_clear(NULL);
    nodus_witness_v2_scratch_clear("");
    CHECK(exists(sib_file) && exists(sib_dir));
    printf("[ok] a missing path / NULL / empty is a no-op\n");

    CHECK(unlink(sib_file) == 0);
    CHECK(rmdir(sib_dir) == 0);
    CHECK(rmdir(base) == 0);
    printf("PASS test_v2_scratch_clear\n");
    return 0;
}
