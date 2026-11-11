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
 *   W1  AT WRITE TIME: every fwrite() of secret-key bytes (size 4896 =
 *       NODUS_SK_BYTES, or 3168 = Kyber / ML-KEM secret key) in S1 and S2
 *       sees a descriptor whose mode has no group/other bit. fwrite is
 *       interposed at link time; the wrapper fstat()s fileno(stream) before
 *       passing the call on. The test also requires that exactly 3 secret
 *       writes were seen per save, so the seam cannot pass by seeing nothing.
 *       Against the old nodus_identity.c (fopen("wb") under umask 0 -> the
 *       file is created 0666, and in S2 is the existing 0666 file, with the
 *       chmod only after fclose) every such fwrite sees 0666 and W1 fails.
 *       On the new code the stream is fdopen() of a descriptor created with
 *       open(.., 0600) and fchmod(0600) before the write, so it sees 0600.
 *
 * Compile flags: none; link option -Wl,--wrap=fwrite (CMakeLists.txt).
 * Environment: none. Directories: mkdtemp under /tmp, removed at the end
 * (files and the directory); the process umask is restored. Leaves nothing
 * behind unless a check aborts mid-way.
 *
 * How it can lie: --wrap sees only calls the linker resolves to the symbol
 * fwrite; if the library ever writes secrets with write(2) or a compiler
 * rewrites the call, the secret-write count check (3 per save) fails rather
 * than W1 passing silently, so that is a loud failure, not a false pass.
 * The wrapper looks at the mode when fwrite is called (data is flushed
 * later), which is the mode the file was created with. S1-S5 end-state
 * checks alone also pass on the old code (trailing chmod).
 */

#define _DEFAULT_SOURCE 1

#include "crypto/nodus_identity.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static int passed = 0, failed = 0;

/* W1 seam: see the header. */
static int g_watch = 0;
static int g_secret_writes = 0;
static int g_wide_secret_writes = 0;

size_t __real_fwrite(const void *ptr, size_t size, size_t n, FILE *stream);
size_t __wrap_fwrite(const void *ptr, size_t size, size_t n, FILE *stream) {
    size_t total = size * n;
    if (g_watch && (total == NODUS_SK_BYTES || total == NODUS_KYBER_SK_BYTES ||
                    total == NODUS_MLKEM_SK_BYTES)) {
        struct stat st;
        g_secret_writes++;
        if (fstat(fileno(stream), &st) != 0 || (st.st_mode & 077) != 0)
            g_wide_secret_writes++;
    }
    return __real_fwrite(ptr, size, n, stream);
}
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
    g_watch = 1;
    CHECK(nodus_identity_save(id, dir) == 0, "S1 save ok");
    g_watch = 0;
    CHECK(g_secret_writes == 3, "W1 S1 seam saw the 3 secret writes");
    CHECK(g_wide_secret_writes == 0, "W1 S1 no secret write into a group/other-accessible file");
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
    g_secret_writes = 0;
    g_watch = 1;
    CHECK(nodus_identity_save(id, dir) == 0, "S2 save over existing files ok");
    g_watch = 0;
    CHECK(g_secret_writes == 3, "W1 S2 seam saw the 3 secret writes");
    CHECK(g_wide_secret_writes == 0, "W1 S2 no secret write into a group/other-accessible file");
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
