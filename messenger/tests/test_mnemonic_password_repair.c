/**
 * test_mnemonic_password_repair — the pre-0.11.22 password-change defect.
 *
 * WHAT IT PROVES: a mnemonic.enc that key_change_password() wrapped in the
 * KEY_ENC ("DNAK") password header (what dna_engine_change_password_sync did
 * before 0.11.22) is (1) unreadable by mnemonic_storage_load — reproducing the
 * defect — and (2) restored byte-for-byte to the original raw KEM blob by
 * mnemonic_storage_repair_password_wrap() with the wrapping password, after
 * which the mnemonic loads again. Also: a wrong password leaves the file
 * untouched, a raw or absent file is a no-op, a repeated wrap (a second old
 * password change) repairs with the latest password.
 *
 * REQUIRES: a default build. Writes under /tmp/test_mnemonic_pw_repair_<pid>
 * and removes it.
 *
 * HOW IT CAN LIE: it drives the SAME primitive the old defect used
 * (key_change_password) to produce the wrapped file, not a replay of
 * dna_engine_change_password_sync itself (that needs a loaded engine);
 * the engine-side call sites (identity load, password change) are covered
 * by reading, not by this test.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto/key/seed_storage.h"
#include "crypto/key/key_encryption.h"
#include "crypto/key/bip39/bip39.h"
#include "crypto/enc/qgp_kyber.h"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS: %s\n", name); g_pass++; } \
    else      { printf("  FAIL: %s\n", name); g_fail++; } \
} while (0)

static long read_file(const char *path, unsigned char *buf, size_t cap) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return (long)n;
}

int main(void) {
    printf("=== mnemonic.enc password-wrap repair ===\n");

    char dir[128], path[256], cmd[300];
    snprintf(dir, sizeof(dir), "/tmp/test_mnemonic_pw_repair_%d", (int)getpid());
    snprintf(path, sizeof(path), "%s/%s", dir, MNEMONIC_STORAGE_FILE);
    snprintf(cmd, sizeof(cmd), "rm -rf %s && mkdir -p %s", dir, dir);
    (void)system(cmd);

    CHECK(mnemonic_storage_repair_password_wrap(dir, "pw") == 0, "absent file -> 0 (nothing to do)");

    uint8_t pk[QGP_KEM1024_PUBLICKEYBYTES], sk[QGP_KEM1024_SECRETKEYBYTES];
    CHECK(qgp_kem1024_keypair(pk, sk) == 0, "round-3 keypair");

    const char *mnemonic = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    CHECK(mnemonic_storage_save(mnemonic, pk, dir) == 0, "mnemonic_storage_save (raw blob)");

    unsigned char original[8192], now[8192];
    long orig_len = read_file(path, original, sizeof(original));
    CHECK(orig_len == (long)MNEMONIC_STORAGE_TOTAL_SIZE, "raw file is exactly the KEM blob size");

    CHECK(mnemonic_storage_repair_password_wrap(dir, "pw") == 0, "raw file -> 0 (nothing to do)");

    /* Reproduce the defect: the old password change (no password -> "pw1"). */
    CHECK(key_change_password(path, NULL, "pw1") == 0, "old defect: key_change_password wraps mnemonic.enc");
    CHECK(key_file_is_encrypted(path), "file now carries the KEY_ENC header");

    char out[BIP39_MAX_MNEMONIC_LENGTH];
    memset(out, 0, sizeof(out));
    CHECK(mnemonic_storage_load(out, sizeof(out), sk, dir) != 0, "wrapped file is unreadable (defect reproduced)");

    long wrapped_len = read_file(path, now, sizeof(now));
    CHECK(mnemonic_storage_repair_password_wrap(dir, "wrong") == -1, "wrong password -> -1");
    unsigned char after_wrong[8192];
    long aw_len = read_file(path, after_wrong, sizeof(after_wrong));
    CHECK(aw_len == wrapped_len && memcmp(after_wrong, now, (size_t)wrapped_len) == 0,
          "wrong password leaves the file byte-identical");
    CHECK(mnemonic_storage_repair_password_wrap(dir, NULL) == -1, "no password on a wrapped file -> -1");

    CHECK(mnemonic_storage_repair_password_wrap(dir, "pw1") == 1, "repair with the wrapping password -> 1");
    long rep_len = read_file(path, now, sizeof(now));
    CHECK(rep_len == orig_len && memcmp(now, original, (size_t)orig_len) == 0,
          "repaired file is byte-identical to the original raw blob");

    memset(out, 0, sizeof(out));
    CHECK(mnemonic_storage_load(out, sizeof(out), sk, dir) == 0 && strcmp(out, mnemonic) == 0,
          "mnemonic loads again after repair");
    CHECK(mnemonic_storage_repair_password_wrap(dir, "pw1") == 0, "second repair -> 0 (idempotent)");

    char tmp[300];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    CHECK(access(tmp, F_OK) != 0, "no temp file left behind");

    /* Two old password changes in a row: the wrap is re-made with each new
     * password (pw1 -> pw2), so the latest password repairs it. */
    CHECK(key_change_password(path, NULL, "pw1") == 0, "old defect again: wrap with pw1");
    CHECK(key_change_password(path, "pw1", "pw2") == 0, "second old change: re-wrap with pw2");
    CHECK(mnemonic_storage_repair_password_wrap(dir, "pw1") == -1, "stale password pw1 cannot repair");
    CHECK(mnemonic_storage_repair_password_wrap(dir, "pw2") == 1, "current password pw2 repairs");
    memset(out, 0, sizeof(out));
    CHECK(mnemonic_storage_load(out, sizeof(out), sk, dir) == 0 && strcmp(out, mnemonic) == 0,
          "mnemonic loads after the double-wrap repair");

    /* Oversized "DNAK" file: must be refused BEFORE decryption (the
     * underlying key_decrypt does not bound its output by the buffer). */
    {
        FILE *f = fopen(path, "wb");
        unsigned char big[4096];
        memset(big, 0x41, sizeof(big));
        memcpy(big, KEY_ENC_MAGIC, KEY_ENC_MAGIC_SIZE);
        CHECK(f && fwrite(big, 1, sizeof(big), f) == sizeof(big), "wrote an oversized DNAK-prefixed file");
        if (f) fclose(f);
        CHECK(mnemonic_storage_repair_password_wrap(dir, "pw2") == -1, "oversized wrapped file -> -1 (refused by size)");
        long ov_len = read_file(path, now, sizeof(now));
        CHECK(ov_len == (long)sizeof(big) && memcmp(now, big, sizeof(big)) == 0,
              "oversized file left byte-identical");
    }

    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    (void)system(cmd);

    printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
