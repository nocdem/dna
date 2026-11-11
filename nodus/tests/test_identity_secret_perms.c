/**
 * Nodus — identity secret-key file permissions (BUGS.md N-01)
 *
 * What it proves: nodus_identity_save() creates nodus.sk, nodus.kyber_sk and
 * nodus.mlkem_sk with mode 0600 and never exposes the secret bytes with wider
 * permissions, even when the process umask is 0.
 *   S1  fresh directory, umask 0: the three secret files are exactly 0600.
 *   S2  files pre-existing with mode 0666 (an older version's leftovers):
 *       after save they are 0600.
 *   S3  the public files (nodus.pk, nodus.fp, nodus.kyber_pk,
 *       nodus.mlkem_pk) are still written (only existence is asserted; their
 *       mode is not pinned).
 *   S4  save + load roundtrip: the secret key read back equals the saved one
 *       (the new write path did not corrupt the bytes).
 *   S5  the Kyber-missing regeneration in nodus_identity_load(): the Kyber
 *       files are removed, load regenerates and re-saves, and nodus.sk and
 *       nodus.kyber_sk are 0600 afterwards (umask 0).
 *
 * Compile flags: none. Environment: none. Directories: mkdtemp under /tmp,
 * removed at the end (files and the directory); the process umask is
 * restored. Leaves nothing behind unless a check aborts mid-way.
 *
 * How it can lie: it observes the final mode, not the instant between
 * creation and chmod (a race window cannot be observed deterministically).
 * The old code also ends at 0600 because of its trailing chmod, so S1 alone
 * would pass on the unfixed code; S2 and the umask-0 setting only prove the
 * end state. What pins the creation mode is the code path itself
 * (identity_write_file_atomic opens with 0600 and fchmods); the test is the
 * regression guard for the end state. Under root the mode bits are still
 * reported correctly (no SKIP needed).
 */

#define _DEFAULT_SOURCE 1

#include "crypto/nodus_identity.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static int passed = 0, failed = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS %s\n", name); passed++; } \
    else { printf("  FAIL %s\n", name); failed++; } } while (0)

static int mode_of(const char *dir, const char *name) {
    char p[1100];
    struct stat st;
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    if (stat(p, &st) != 0) return -1;
    return (int)(st.st_mode & 0777);
}

static void rm_all(const char *dir) {
    static const char *names[] = {"nodus.pk", "nodus.sk", "nodus.fp",
        "nodus.kyber_pk", "nodus.kyber_sk", "nodus.mlkem_pk", "nodus.mlkem_sk"};
    char p[1100];
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(p, sizeof(p), "%s/%s", dir, names[i]);
        unlink(p);
    }
    rmdir(dir);
}

static void secrets_are_0600(const char *dir, const char *tag) {
    char name[96];
    snprintf(name, sizeof(name), "%s nodus.sk is 0600", tag);
    CHECK(mode_of(dir, "nodus.sk") == 0600, name);
    snprintf(name, sizeof(name), "%s nodus.kyber_sk is 0600", tag);
    CHECK(mode_of(dir, "nodus.kyber_sk") == 0600, name);
    snprintf(name, sizeof(name), "%s nodus.mlkem_sk is 0600", tag);
    CHECK(mode_of(dir, "nodus.mlkem_sk") == 0600, name);
}

int main(void) {
    printf("=== identity secret file permissions (N-01) ===\n");
    mode_t old_umask = umask(0);

    char dir[] = "/tmp/nodus_identity_perm_XXXXXX";
    if (!mkdtemp(dir)) { umask(old_umask); return 1; }

    nodus_identity_t *id = calloc(1, sizeof(*id));
    nodus_identity_t *back = calloc(1, sizeof(*back));
    if (!id || !back || nodus_identity_generate(id) != 0) { umask(old_umask); return 1; }
    CHECK(id->has_kyber && id->has_mlkem, "generated identity has both KEM keypairs");

    /* S1 */
    CHECK(nodus_identity_save(id, dir) == 0, "S1 save ok");
    secrets_are_0600(dir, "S1");

    /* S3 */
    CHECK(mode_of(dir, "nodus.pk") >= 0 && mode_of(dir, "nodus.fp") >= 0 &&
          mode_of(dir, "nodus.kyber_pk") >= 0 && mode_of(dir, "nodus.mlkem_pk") >= 0,
          "S3 public files exist");

    /* S2: widen the secret files, save again */
    static const char *sec[] = {"nodus.sk", "nodus.kyber_sk", "nodus.mlkem_sk"};
    for (int i = 0; i < 3; i++) {
        char p[1100];
        snprintf(p, sizeof(p), "%s/%s", dir, sec[i]);
        chmod(p, 0666);
    }
    CHECK(mode_of(dir, "nodus.sk") == 0666, "S2 precondition: widened to 0666");
    CHECK(nodus_identity_save(id, dir) == 0, "S2 save over existing files ok");
    secrets_are_0600(dir, "S2");

    /* S4 */
    CHECK(nodus_identity_load(dir, back) == 0 &&
          memcmp(back->sk.bytes, id->sk.bytes, NODUS_SK_BYTES) == 0 &&
          memcmp(back->kyber_sk, id->kyber_sk, NODUS_KYBER_SK_BYTES) == 0 &&
          memcmp(back->mlkem_sk, id->mlkem_sk, NODUS_MLKEM_SK_BYTES) == 0,
          "S4 save/load roundtrip keeps the secret bytes");

    /* S5: Kyber files missing -> load regenerates and re-saves */
    char p[1100];
    snprintf(p, sizeof(p), "%s/nodus.kyber_pk", dir); unlink(p);
    snprintf(p, sizeof(p), "%s/nodus.kyber_sk", dir); unlink(p);
    snprintf(p, sizeof(p), "%s/nodus.sk", dir); chmod(p, 0666);
    memset(back, 0, sizeof(*back));
    CHECK(nodus_identity_load(dir, back) == 0 && back->has_kyber,
          "S5 load regenerates the Kyber keypair");
    secrets_are_0600(dir, "S5");

    nodus_identity_clear(id);
    nodus_identity_clear(back);
    free(id);
    free(back);
    rm_all(dir);
    umask(old_umask);
    printf("%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
