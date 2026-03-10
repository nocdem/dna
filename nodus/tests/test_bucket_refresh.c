/**
 * Nodus — Bucket Refresh Key Generation Tests
 *
 * Validates nodus_key_random_in_bucket() generates keys that:
 * - XOR-distance to self falls in the correct bucket
 * - Different calls produce different keys (randomness)
 */

#include "core/nodus_routing.h"
#include <stdio.h>
#include <string.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static nodus_key_t make_key(uint8_t fill) {
    nodus_key_t k;
    memset(k.bytes, fill, NODUS_KEY_BYTES);
    return k;
}

static void test_random_key_in_bucket_0(void) {
    TEST("random key in bucket 0 (MSB differs)");
    nodus_key_t self = make_key(0x00);
    nodus_key_t result;
    nodus_key_random_in_bucket(&result, &self, 0);

    /* Bucket 0 means first bit of XOR distance is 1 (CLZ=0) */
    nodus_key_t dist;
    nodus_key_xor(&dist, &self, &result);
    int clz = nodus_key_clz(&dist);

    if (clz == 0)
        PASS();
    else
        FAIL("expected CLZ=0 for bucket 0");
}

static void test_random_key_in_bucket_7(void) {
    TEST("random key in bucket 7");
    nodus_key_t self = make_key(0x00);
    nodus_key_t result;
    nodus_key_random_in_bucket(&result, &self, 7);

    nodus_key_t dist;
    nodus_key_xor(&dist, &self, &result);
    int clz = nodus_key_clz(&dist);

    if (clz == 7)
        PASS();
    else {
        char buf[64];
        snprintf(buf, sizeof(buf), "expected CLZ=7, got %d", clz);
        FAIL(buf);
    }
}

static void test_random_key_in_bucket_255(void) {
    TEST("random key in bucket 255 (middle of keyspace)");
    nodus_key_t self = make_key(0xAA);
    nodus_key_t result;
    nodus_key_random_in_bucket(&result, &self, 255);

    nodus_key_t dist;
    nodus_key_xor(&dist, &self, &result);
    int clz = nodus_key_clz(&dist);

    if (clz == 255)
        PASS();
    else {
        char buf[64];
        snprintf(buf, sizeof(buf), "expected CLZ=255, got %d", clz);
        FAIL(buf);
    }
}

static void test_random_key_in_bucket_511(void) {
    TEST("random key in bucket 511 (last bucket)");
    nodus_key_t self = make_key(0x00);
    nodus_key_t result;
    nodus_key_random_in_bucket(&result, &self, 511);

    nodus_key_t dist;
    nodus_key_xor(&dist, &self, &result);

    /* Bucket 511 means CLZ=511, only the last bit differs */
    int clz = nodus_key_clz(&dist);
    if (clz == 511)
        PASS();
    else {
        char buf[64];
        snprintf(buf, sizeof(buf), "expected CLZ=511, got %d", clz);
        FAIL(buf);
    }
}

static void test_randomness(void) {
    TEST("different calls produce different keys");
    nodus_key_t self = make_key(0x00);
    nodus_key_t r1, r2;

    nodus_key_random_in_bucket(&r1, &self, 10);
    nodus_key_random_in_bucket(&r2, &self, 10);

    /* With 512-bit keys, collision probability is negligible */
    if (nodus_key_cmp(&r1, &r2) != 0)
        PASS();
    else
        FAIL("two random keys should differ");
}

static void test_multiple_buckets_correct(void) {
    TEST("keys in multiple buckets all land correctly");
    nodus_key_t self = make_key(0x55);
    bool all_correct = true;

    int test_buckets[] = {0, 1, 3, 8, 15, 63, 127, 200, 400, 510};
    int n = (int)(sizeof(test_buckets) / sizeof(test_buckets[0]));

    for (int i = 0; i < n; i++) {
        nodus_key_t result;
        nodus_key_random_in_bucket(&result, &self, test_buckets[i]);

        nodus_key_t dist;
        nodus_key_xor(&dist, &self, &result);
        int clz = nodus_key_clz(&dist);

        if (clz != test_buckets[i]) {
            all_correct = false;
            break;
        }
    }

    if (all_correct)
        PASS();
    else
        FAIL("some bucket keys landed in wrong bucket");
}

int main(void) {
    printf("=== Nodus Bucket Refresh Key Generation Tests ===\n");

    test_random_key_in_bucket_0();
    test_random_key_in_bucket_7();
    test_random_key_in_bucket_255();
    test_random_key_in_bucket_511();
    test_randomness();
    test_multiple_buckets_correct();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
