/**
 * @file test_qgp_key_size_validation.c
 * @brief SEC-02 regression test — qgp_key_load must reject malformed key
 *        files whose header.public_key_size or header.private_key_size do
 *        not match the exact spec sizes for the declared key_type, BEFORE
 *        any payload allocation.
 *
 * Uses the public API only (qgp_key_load, qgp_key_new, qgp_key_save,
 * qgp_key_free) — no internal engine headers. Constants come from
 * qgp_dilithium.h / qgp_kyber.h which are part of the public crypto headers
 * already used by other ctest targets.
 *
 * SEC-02 trust boundary: a .dna key file on disk is attacker-controlled
 * input. The header carries the payload sizes used for malloc, so an
 * oversized size field (e.g. 1<<30) would trigger an unbounded allocation.
 * The fix in qgp_key.c rejects any header whose sizes do not equal the
 * exact spec sizes for the declared algorithm.
 *
 * Encrypted-path negative test (DNAK with malformed inner header) is NOT
 * implemented here: constructing a malformed inner header inside an
 * encrypted file requires touching key_encrypt() internals. Instead, the
 * shared validator inside qgp_key_load_encrypted is exercised by all
 * unencrypted tests below, since qgp_key_load delegates to the same
 * function with a NULL password (see qgp_key.c).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <io.h>
#define unlink _unlink
#else
#include <unistd.h>
#endif

#include "crypto/utils/qgp_types.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/enc/qgp_kyber.h"

#define PASS(name) do { printf("  [PASS] %s\n", name); } while (0)
#define FAIL(name) do { printf("  [FAIL] %s\n", name); return 1; } while (0)

/* Write a hand-crafted private-key file header (and nothing else) to `path`.
 * Returns 0 on success, -1 on failure. */
static int write_header_only(const char *path,
                             uint8_t key_type,
                             uint32_t public_key_size,
                             uint32_t private_key_size) {
    qgp_privkey_file_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, QGP_PRIVKEY_MAGIC, 8);
    header.version = QGP_PRIVKEY_VERSION;
    header.key_type = key_type;
    header.purpose = QGP_KEY_PURPOSE_SIGNING;
    header.public_key_size = public_key_size;
    header.private_key_size = private_key_size;
    strncpy(header.name, "sec02-malformed", sizeof(header.name) - 1);

    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    size_t n = fwrite(&header, sizeof(header), 1, fp);
    fclose(fp);
    return (n == 1) ? 0 : -1;
}

/* Common assertion: load must return -1 and out must remain NULL. */
static int expect_load_rejected(const char *path, const char *what) {
    qgp_key_t *out = NULL;
    int rc = qgp_key_load(path, &out);
    if (rc != -1 || out != NULL) {
        printf("    -> rc=%d out=%p (expected rc=-1 out=NULL) for %s\n",
               rc, (void *)out, what);
        if (out) qgp_key_free(out);
        return -1;
    }
    return 0;
}

/* Test 1: oversized public_key_size on an otherwise valid Dilithium5 header. */
static int test_reject_oversized_public_key_size(void) {
    const char *path = "/tmp/sec02_oversized_pub.qgpk";
    if (write_header_only(path,
                          (uint8_t)QGP_KEY_TYPE_DSA87,
                          1u << 30,
                          QGP_DSA87_SECRETKEYBYTES) != 0) {
        FAIL("test_reject_oversized_public_key_size (write failed)");
    }
    int rc = expect_load_rejected(path, "oversized_public_key_size");
    unlink(path);
    if (rc != 0) FAIL("test_reject_oversized_public_key_size");
    PASS("test_reject_oversized_public_key_size");
    return 0;
}

/* Test 2: oversized private_key_size on an otherwise valid Dilithium5 header. */
static int test_reject_oversized_private_key_size(void) {
    const char *path = "/tmp/sec02_oversized_sec.qgpk";
    if (write_header_only(path,
                          (uint8_t)QGP_KEY_TYPE_DSA87,
                          QGP_DSA87_PUBLICKEYBYTES,
                          1u << 30) != 0) {
        FAIL("test_reject_oversized_private_key_size (write failed)");
    }
    int rc = expect_load_rejected(path, "oversized_private_key_size");
    unlink(path);
    if (rc != 0) FAIL("test_reject_oversized_private_key_size");
    PASS("test_reject_oversized_private_key_size");
    return 0;
}

/* Test 3: KEM1024 type but with Dilithium5 public key size — mismatch. */
static int test_reject_mismatched_type_for_kem(void) {
    const char *path = "/tmp/sec02_kem_type_mismatch.qgpk";
    if (write_header_only(path,
                          (uint8_t)QGP_KEY_TYPE_KEM1024,
                          QGP_DSA87_PUBLICKEYBYTES,           /* WRONG: 2592 != 1568 */
                          QGP_KEM1024_SECRETKEYBYTES) != 0) {
        FAIL("test_reject_mismatched_type_for_kem (write failed)");
    }
    int rc = expect_load_rejected(path, "mismatched_type_for_kem");
    unlink(path);
    if (rc != 0) FAIL("test_reject_mismatched_type_for_kem");
    PASS("test_reject_mismatched_type_for_kem");
    return 0;
}

/* Test 4: invalid key_type value (not in the static lookup table). */
static int test_reject_invalid_key_type(void) {
    const char *path = "/tmp/sec02_invalid_type.qgpk";
    if (write_header_only(path,
                          99,                                  /* invalid */
                          QGP_DSA87_PUBLICKEYBYTES,
                          QGP_DSA87_SECRETKEYBYTES) != 0) {
        FAIL("test_reject_invalid_key_type (write failed)");
    }
    int rc = expect_load_rejected(path, "invalid_key_type");
    unlink(path);
    if (rc != 0) FAIL("test_reject_invalid_key_type");
    PASS("test_reject_invalid_key_type");
    return 0;
}

/* Test 5: positive control. A legitimate save/load round-trip with correct
 * spec sizes must still succeed — proves the validator does not reject
 * real user files (D-04 no migration concern). */
static int test_positive_round_trip(void) {
    const char *path = "/tmp/sec02_round_trip.qgpk";

    qgp_key_t *key = qgp_key_new(QGP_KEY_TYPE_DSA87, QGP_KEY_PURPOSE_SIGNING);
    if (!key) FAIL("test_positive_round_trip (qgp_key_new)");

    key->public_key_size = QGP_DSA87_PUBLICKEYBYTES;
    key->public_key = (uint8_t *)malloc(QGP_DSA87_PUBLICKEYBYTES);
    if (!key->public_key) { qgp_key_free(key); FAIL("alloc pub"); }
    for (uint32_t i = 0; i < QGP_DSA87_PUBLICKEYBYTES; i++) {
        key->public_key[i] = (uint8_t)(i & 0xFF);
    }

    key->private_key_size = QGP_DSA87_SECRETKEYBYTES;
    key->private_key = (uint8_t *)malloc(QGP_DSA87_SECRETKEYBYTES);
    if (!key->private_key) { qgp_key_free(key); FAIL("alloc sec"); }
    for (uint32_t i = 0; i < QGP_DSA87_SECRETKEYBYTES; i++) {
        key->private_key[i] = (uint8_t)((i * 7) & 0xFF);
    }
    strncpy(key->name, "sec02-roundtrip", sizeof(key->name) - 1);

    if (qgp_key_save(key, path) != 0) {
        qgp_key_free(key);
        unlink(path);
        FAIL("test_positive_round_trip (qgp_key_save)");
    }

    qgp_key_t *loaded = NULL;
    int rc = qgp_key_load(path, &loaded);
    if (rc != 0 || !loaded) {
        qgp_key_free(key);
        if (loaded) qgp_key_free(loaded);
        unlink(path);
        FAIL("test_positive_round_trip (qgp_key_load)");
    }

    if (loaded->public_key_size != QGP_DSA87_PUBLICKEYBYTES ||
        loaded->private_key_size != QGP_DSA87_SECRETKEYBYTES ||
        memcmp(loaded->public_key, key->public_key, QGP_DSA87_PUBLICKEYBYTES) != 0 ||
        memcmp(loaded->private_key, key->private_key, QGP_DSA87_SECRETKEYBYTES) != 0) {
        qgp_key_free(key);
        qgp_key_free(loaded);
        unlink(path);
        FAIL("test_positive_round_trip (payload mismatch)");
    }

    qgp_key_free(key);
    qgp_key_free(loaded);
    unlink(path);
    PASS("test_positive_round_trip");
    return 0;
}

int main(void) {
    printf("[SEC-02] qgp_key size-validation regression tests\n");

    int failures = 0;
    failures += test_reject_oversized_public_key_size();
    failures += test_reject_oversized_private_key_size();
    failures += test_reject_mismatched_type_for_kem();
    failures += test_reject_invalid_key_type();
    failures += test_positive_round_trip();

    if (failures != 0) {
        printf("[SEC-02] FAILED (%d test(s) failed)\n", failures);
        return 1;
    }
    printf("[SEC-02] all tests passed\n");
    return 0;
}
