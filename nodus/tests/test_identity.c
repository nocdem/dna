/**
 * Nodus — Identity Tests
 *
 * Tests keypair generation, deterministic seed derivation,
 * sign/verify, and save/load roundtrip.
 */

#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static void test_generate_random(void) {
    TEST("generate random identity");
    nodus_identity_t id;
    int rc = nodus_identity_generate(&id);

    if (rc == 0 &&
        !nodus_key_is_zero(&id.node_id) &&
        id.fingerprint[0] != '\0' &&
        strlen(id.fingerprint) == 128) {
        PASS();
    } else {
        FAIL("generate failed");
    }
    nodus_identity_clear(&id);
}

static void test_from_seed_deterministic(void) {
    TEST("seed derivation is deterministic");
    uint8_t seed[32];
    memset(seed, 0xAA, sizeof(seed));

    nodus_identity_t id1, id2;
    nodus_identity_from_seed(seed, &id1);
    nodus_identity_from_seed(seed, &id2);

    if (memcmp(id1.pk.bytes, id2.pk.bytes, NODUS_PK_BYTES) == 0 &&
        memcmp(id1.sk.bytes, id2.sk.bytes, NODUS_SK_BYTES) == 0 &&
        nodus_key_cmp(&id1.node_id, &id2.node_id) == 0 &&
        strcmp(id1.fingerprint, id2.fingerprint) == 0) {
        PASS();
    } else {
        FAIL("same seed produced different identity");
    }
    nodus_identity_clear(&id1);
    nodus_identity_clear(&id2);
}

static void test_different_seeds(void) {
    TEST("different seeds produce different identities");
    uint8_t seed1[32], seed2[32];
    memset(seed1, 0x11, sizeof(seed1));
    memset(seed2, 0x22, sizeof(seed2));

    nodus_identity_t id1, id2;
    nodus_identity_from_seed(seed1, &id1);
    nodus_identity_from_seed(seed2, &id2);

    if (memcmp(id1.pk.bytes, id2.pk.bytes, NODUS_PK_BYTES) != 0 &&
        nodus_key_cmp(&id1.node_id, &id2.node_id) != 0) {
        PASS();
    } else {
        FAIL("different seeds produced same identity");
    }
    nodus_identity_clear(&id1);
    nodus_identity_clear(&id2);
}

static void test_fingerprint_is_sha3_512(void) {
    TEST("fingerprint = SHA3-512(pubkey)");
    uint8_t seed[32] = {0};
    nodus_identity_t id;
    nodus_identity_from_seed(seed, &id);

    /* Compute fingerprint manually */
    nodus_key_t computed_fp;
    nodus_fingerprint(&id.pk, &computed_fp);

    if (nodus_key_cmp(&id.node_id, &computed_fp) == 0) {
        PASS();
    } else {
        FAIL("node_id != SHA3-512(pk)");
    }
    nodus_identity_clear(&id);
}

static void test_sign_verify_with_identity(void) {
    TEST("sign and verify with identity");
    uint8_t seed[32];
    memset(seed, 0x55, sizeof(seed));

    nodus_identity_t id;
    nodus_identity_from_seed(seed, &id);

    const uint8_t msg[] = "test message for signing";
    nodus_sig_t sig;

    int sign_rc = nodus_sign(&sig, msg, sizeof(msg) - 1, &id.sk);
    if (sign_rc != 0) {
        FAIL("sign failed");
        nodus_identity_clear(&id);
        return;
    }

    int verify_rc = nodus_verify(&sig, msg, sizeof(msg) - 1, &id.pk);
    if (verify_rc == 0) {
        PASS();
    } else {
        FAIL("verify failed");
    }
    nodus_identity_clear(&id);
}

static void test_value_id_derivation(void) {
    TEST("value_id from identity");
    uint8_t seed[32];
    memset(seed, 0x77, sizeof(seed));

    nodus_identity_t id;
    nodus_identity_from_seed(seed, &id);

    uint64_t vid = nodus_identity_value_id(&id);

    /* Should be non-zero for non-zero identity */
    if (vid != 0) {
        /* Deterministic */
        nodus_identity_t id2;
        nodus_identity_from_seed(seed, &id2);
        uint64_t vid2 = nodus_identity_value_id(&id2);

        if (vid == vid2)
            PASS();
        else
            FAIL("value_id not deterministic");

        nodus_identity_clear(&id2);
    } else {
        FAIL("value_id is zero");
    }
    nodus_identity_clear(&id);
}

static void test_save_load_roundtrip(void) {
    TEST("save/load identity roundtrip");

    /* Create temp directory */
    const char *tmpdir = "/tmp/nodus_test_identity";
    mkdir(tmpdir, 0700);

    uint8_t seed[32];
    memset(seed, 0xBB, sizeof(seed));

    nodus_identity_t id_orig;
    nodus_identity_from_seed(seed, &id_orig);

    /* Save */
    int rc = nodus_identity_save(&id_orig, tmpdir);
    if (rc != 0) {
        FAIL("save failed");
        nodus_identity_clear(&id_orig);
        return;
    }

    /* Load */
    nodus_identity_t id_loaded;
    rc = nodus_identity_load(tmpdir, &id_loaded);
    if (rc != 0) {
        FAIL("load failed");
        nodus_identity_clear(&id_orig);
        return;
    }

    /* Compare */
    if (memcmp(id_orig.pk.bytes, id_loaded.pk.bytes, NODUS_PK_BYTES) == 0 &&
        memcmp(id_orig.sk.bytes, id_loaded.sk.bytes, NODUS_SK_BYTES) == 0 &&
        nodus_key_cmp(&id_orig.node_id, &id_loaded.node_id) == 0 &&
        strcmp(id_orig.fingerprint, id_loaded.fingerprint) == 0) {
        PASS();
    } else {
        FAIL("loaded identity doesn't match original");
    }

    /* Cleanup */
    char path[256];
    snprintf(path, sizeof(path), "%s/nodus.pk", tmpdir);
    remove(path);
    snprintf(path, sizeof(path), "%s/nodus.sk", tmpdir);
    remove(path);
    snprintf(path, sizeof(path), "%s/nodus.fp", tmpdir);
    remove(path);
    rmdir(tmpdir);

    nodus_identity_clear(&id_orig);
    nodus_identity_clear(&id_loaded);
}

static void test_hex_fingerprint_format(void) {
    TEST("hex fingerprint is 128 lowercase hex chars");
    uint8_t seed[32];
    memset(seed, 0xCC, sizeof(seed));

    nodus_identity_t id;
    nodus_identity_from_seed(seed, &id);

    if (strlen(id.fingerprint) != 128) {
        FAIL("wrong length");
        nodus_identity_clear(&id);
        return;
    }

    /* Check all chars are hex */
    bool all_hex = true;
    for (int i = 0; i < 128; i++) {
        char c = id.fingerprint[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            all_hex = false;
            break;
        }
    }

    if (all_hex)
        PASS();
    else
        FAIL("non-hex characters in fingerprint");

    nodus_identity_clear(&id);
}

int main(void) {
    printf("=== Nodus Identity Tests ===\n");

    test_generate_random();
    test_from_seed_deterministic();
    test_different_seeds();
    test_fingerprint_is_sha3_512();
    test_sign_verify_with_identity();
    test_value_id_derivation();
    test_save_load_roundtrip();
    test_hex_fingerprint_format();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
