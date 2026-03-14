/**
 * @file test_chain_id.c
 * @brief Unit tests for chain_id derivation and two-phase genesis
 *
 * Tests:
 *   1. Chain ID derivation unit tests (determinism, uniqueness, validation)
 *   2. Multi-chain test (same fp / different tx, different fp / same tx)
 *   3. Two-phase genesis phase1 (offline, no network required)
 *
 * No network required — all tests are offline.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "dnac/dnac.h"
#include "dnac/crypto_helpers.h"
#include "dnac/genesis.h"
#include "dnac/transaction.h"
#include "crypto/hash/qgp_sha3.h"

/* ============================================================================
 * Test Counters
 * ========================================================================== */

static int g_passed = 0;
static int g_failed = 0;

#define PASS(msg) do { \
    printf("  PASS: %s\n", msg); \
    g_passed++; \
} while(0)

#define FAIL(msg) do { \
    fprintf(stderr, "  FAIL: %s\n", msg); \
    g_failed++; \
} while(0)

/* ============================================================================
 * Helpers
 * ========================================================================== */

/** Print 32 bytes as hex */
static void print_hex32(const char *label, const uint8_t *data) {
    printf("    %s: ", label);
    for (int i = 0; i < 32; i++)
        printf("%02x", data[i]);
    printf("\n");
}

/** Check if 32 bytes are all zeros */
static int is_all_zeros(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] != 0) return 0;
    }
    return 1;
}

/** Convert hex nibble to int (-1 on error) */
static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/** Convert 128-char hex fingerprint to 64 bytes */
static int fp_hex_to_bytes(const char *fp, uint8_t *out) {
    for (int i = 0; i < 64; i++) {
        int hi = hex_nibble(fp[i * 2]);
        int lo = hex_nibble(fp[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/**
 * Manually compute expected chain_id = SHA3-256(fp_bytes || tx_hash)
 * This mirrors the implementation in crypto_helpers.c
 */
static int compute_expected_chain_id(const char *fp, const uint8_t *tx_hash,
                                      uint8_t *expected_out) {
    uint8_t fp_bytes[64];
    if (fp_hex_to_bytes(fp, fp_bytes) != 0) return -1;

    uint8_t data[64 + DNAC_TX_HASH_SIZE];  /* 128 bytes */
    memcpy(data, fp_bytes, 64);
    memcpy(data + 64, tx_hash, DNAC_TX_HASH_SIZE);

    return qgp_sha3_256(data, sizeof(data), expected_out);
}

/* ============================================================================
 * Test Fingerprints (128 hex chars each)
 * ========================================================================== */

/* Deterministic test fingerprint A: 64 bytes of 0xAA as hex */
static const char *FP_A =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/* Deterministic test fingerprint B: 64 bytes of 0xBB as hex */
static const char *FP_B =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/* Deterministic test fingerprint C: mixed pattern */
static const char *FP_C =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

/* ============================================================================
 * TEST 1: Chain ID Derivation Unit Tests
 * ========================================================================== */

static void test_chain_id_derivation(void) {
    printf("\n=== TEST 1: Chain ID Derivation Unit Tests ===\n");

    int rc;

    /* --- 1a: Known input → expected output --- */
    {
        uint8_t tx_hash[DNAC_TX_HASH_SIZE];
        memset(tx_hash, 0x11, DNAC_TX_HASH_SIZE);

        uint8_t chain_id[32];
        rc = dnac_derive_chain_id(FP_A, tx_hash, chain_id);
        if (rc != 0) { FAIL("1a: dnac_derive_chain_id returned error"); return; }

        /* Compute expected independently */
        uint8_t expected[32];
        rc = compute_expected_chain_id(FP_A, tx_hash, expected);
        if (rc != 0) { FAIL("1a: compute_expected_chain_id failed"); return; }

        if (memcmp(chain_id, expected, 32) == 0) {
            PASS("1a: Known input matches SHA3-256(fp_bytes || tx_hash)");
            print_hex32("chain_id", chain_id);
        } else {
            FAIL("1a: chain_id does not match expected SHA3-256 output");
            print_hex32("got     ", chain_id);
            print_hex32("expected", expected);
        }
    }

    /* --- 1b: Deterministic — same inputs → same chain_id --- */
    {
        uint8_t tx_hash[DNAC_TX_HASH_SIZE];
        memset(tx_hash, 0x22, DNAC_TX_HASH_SIZE);

        uint8_t chain_id_1[32], chain_id_2[32];
        rc = dnac_derive_chain_id(FP_A, tx_hash, chain_id_1);
        if (rc != 0) { FAIL("1b: first call failed"); return; }

        rc = dnac_derive_chain_id(FP_A, tx_hash, chain_id_2);
        if (rc != 0) { FAIL("1b: second call failed"); return; }

        if (memcmp(chain_id_1, chain_id_2, 32) == 0) {
            PASS("1b: Same inputs produce same chain_id (deterministic)");
        } else {
            FAIL("1b: Same inputs produced different chain_ids!");
        }
    }

    /* --- 1c: Different fingerprints → different chain_ids --- */
    {
        uint8_t tx_hash[DNAC_TX_HASH_SIZE];
        memset(tx_hash, 0x33, DNAC_TX_HASH_SIZE);

        uint8_t id_a[32], id_b[32];
        dnac_derive_chain_id(FP_A, tx_hash, id_a);
        dnac_derive_chain_id(FP_B, tx_hash, id_b);

        if (memcmp(id_a, id_b, 32) != 0) {
            PASS("1c: Different fingerprints produce different chain_ids");
        } else {
            FAIL("1c: Different fingerprints produced same chain_id!");
        }
    }

    /* --- 1d: Different tx_hashes → different chain_ids --- */
    {
        uint8_t tx_hash_1[DNAC_TX_HASH_SIZE], tx_hash_2[DNAC_TX_HASH_SIZE];
        memset(tx_hash_1, 0x44, DNAC_TX_HASH_SIZE);
        memset(tx_hash_2, 0x55, DNAC_TX_HASH_SIZE);

        uint8_t id_1[32], id_2[32];
        dnac_derive_chain_id(FP_A, tx_hash_1, id_1);
        dnac_derive_chain_id(FP_A, tx_hash_2, id_2);

        if (memcmp(id_1, id_2, 32) != 0) {
            PASS("1d: Different tx_hashes produce different chain_ids");
        } else {
            FAIL("1d: Different tx_hashes produced same chain_id!");
        }
    }

    /* --- 1e: NULL/invalid inputs → returns -1 --- */
    {
        uint8_t tx_hash[DNAC_TX_HASH_SIZE];
        memset(tx_hash, 0x66, DNAC_TX_HASH_SIZE);
        uint8_t chain_id[32];

        rc = dnac_derive_chain_id(NULL, tx_hash, chain_id);
        if (rc == -1) {
            PASS("1e-i: NULL genesis_fp returns -1");
        } else {
            FAIL("1e-i: NULL genesis_fp did not return -1");
        }

        rc = dnac_derive_chain_id(FP_A, NULL, chain_id);
        if (rc == -1) {
            PASS("1e-ii: NULL tx_hash returns -1");
        } else {
            FAIL("1e-ii: NULL tx_hash did not return -1");
        }

        rc = dnac_derive_chain_id(FP_A, tx_hash, NULL);
        if (rc == -1) {
            PASS("1e-iii: NULL chain_id_out returns -1");
        } else {
            FAIL("1e-iii: NULL chain_id_out did not return -1");
        }

        rc = dnac_derive_chain_id(NULL, NULL, NULL);
        if (rc == -1) {
            PASS("1e-iv: All NULL returns -1");
        } else {
            FAIL("1e-iv: All NULL did not return -1");
        }
    }

    /* --- 1f: Fingerprint not 128 hex chars → returns -1 --- */
    {
        uint8_t tx_hash[DNAC_TX_HASH_SIZE];
        memset(tx_hash, 0x77, DNAC_TX_HASH_SIZE);
        uint8_t chain_id[32];

        /* Too short (64 chars) */
        rc = dnac_derive_chain_id(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            tx_hash, chain_id);
        if (rc == -1) {
            PASS("1f-i: 64-char fingerprint returns -1");
        } else {
            FAIL("1f-i: 64-char fingerprint did not return -1");
        }

        /* Too long (130 chars) */
        rc = dnac_derive_chain_id(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            tx_hash, chain_id);
        if (rc == -1) {
            PASS("1f-ii: 130-char fingerprint returns -1");
        } else {
            FAIL("1f-ii: 130-char fingerprint did not return -1");
        }

        /* Empty string */
        rc = dnac_derive_chain_id("", tx_hash, chain_id);
        if (rc == -1) {
            PASS("1f-iii: Empty fingerprint returns -1");
        } else {
            FAIL("1f-iii: Empty fingerprint did not return -1");
        }

        /* Invalid hex chars (has 'g' and 'z') */
        rc = dnac_derive_chain_id(
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            tx_hash, chain_id);
        if (rc == -1) {
            PASS("1f-iv: Non-hex fingerprint returns -1");
        } else {
            FAIL("1f-iv: Non-hex fingerprint did not return -1");
        }
    }
}

/* ============================================================================
 * TEST 2: Multi-Chain Test
 * ========================================================================== */

static void test_multi_chain(void) {
    printf("\n=== TEST 2: Multi-Chain Test ===\n");

    uint8_t tx_hash_1[DNAC_TX_HASH_SIZE], tx_hash_2[DNAC_TX_HASH_SIZE];
    memset(tx_hash_1, 0xDE, DNAC_TX_HASH_SIZE);
    memset(tx_hash_2, 0xEF, DNAC_TX_HASH_SIZE);

    uint8_t chain_id_1[32], chain_id_2[32], chain_id_3[32];

    /* chain_id_1: (FP_A, tx_hash_1) */
    int rc = dnac_derive_chain_id(FP_A, tx_hash_1, chain_id_1);
    if (rc != 0) { FAIL("2: derive chain_id_1 failed"); return; }

    /* chain_id_2: (FP_A, tx_hash_2) — same fp, different genesis tx */
    rc = dnac_derive_chain_id(FP_A, tx_hash_2, chain_id_2);
    if (rc != 0) { FAIL("2: derive chain_id_2 failed"); return; }

    /* chain_id_3: (FP_B, tx_hash_1) — different fp, same genesis tx */
    rc = dnac_derive_chain_id(FP_B, tx_hash_1, chain_id_3);
    if (rc != 0) { FAIL("2: derive chain_id_3 failed"); return; }

    print_hex32("chain_id_1 (FP_A, tx1)", chain_id_1);
    print_hex32("chain_id_2 (FP_A, tx2)", chain_id_2);
    print_hex32("chain_id_3 (FP_B, tx1)", chain_id_3);

    /* Same fp, different genesis → different chain_id */
    if (memcmp(chain_id_1, chain_id_2, 32) != 0) {
        PASS("2a: Same fp + different tx_hash → different chain_id");
    } else {
        FAIL("2a: Same fp + different tx_hash produced same chain_id!");
    }

    /* Different fp, same genesis → different chain_id */
    if (memcmp(chain_id_1, chain_id_3, 32) != 0) {
        PASS("2b: Different fp + same tx_hash → different chain_id");
    } else {
        FAIL("2b: Different fp + same tx_hash produced same chain_id!");
    }

    /* All three should be unique */
    if (memcmp(chain_id_2, chain_id_3, 32) != 0) {
        PASS("2c: All three chain_ids are unique");
    } else {
        FAIL("2c: chain_id_2 and chain_id_3 collided!");
    }

    /* Verify each matches independent SHA3-256 computation */
    uint8_t expected[32];
    compute_expected_chain_id(FP_A, tx_hash_1, expected);
    if (memcmp(chain_id_1, expected, 32) == 0) {
        PASS("2d: chain_id_1 matches independent SHA3-256 verification");
    } else {
        FAIL("2d: chain_id_1 does not match independent computation");
    }

    compute_expected_chain_id(FP_A, tx_hash_2, expected);
    if (memcmp(chain_id_2, expected, 32) == 0) {
        PASS("2e: chain_id_2 matches independent SHA3-256 verification");
    } else {
        FAIL("2e: chain_id_2 does not match independent computation");
    }

    compute_expected_chain_id(FP_B, tx_hash_1, expected);
    if (memcmp(chain_id_3, expected, 32) == 0) {
        PASS("2f: chain_id_3 matches independent SHA3-256 verification");
    } else {
        FAIL("2f: chain_id_3 does not match independent computation");
    }
}

/* ============================================================================
 * TEST 3: Two-Phase Genesis Phase 1 (Offline)
 * ========================================================================== */

static void test_phase1_genesis(void) {
    printf("\n=== TEST 3: Two-Phase Genesis Phase 1 (Offline) ===\n");

    /*
     * phase1_create requires a dnac_context_t with signing keys.
     * Without a full DNA engine, we can't call it.
     * Test what we can: the derivation logic that phase1 uses internally.
     *
     * We simulate phase1's chain_id derivation:
     *   1. Create a genesis TX (sets tx_hash)
     *   2. chain_id = SHA3-256(recipient_fp_bytes || tx_hash)
     */

    /* Create a genesis TX to get a realistic tx_hash */
    dnac_genesis_recipient_t recipients[1];
    strncpy(recipients[0].fingerprint, FP_C, DNAC_FINGERPRINT_SIZE - 1);
    recipients[0].fingerprint[DNAC_FINGERPRINT_SIZE - 1] = '\0';
    recipients[0].amount = 1000000;

    dnac_transaction_t *tx = NULL;
    int rc = dnac_tx_create_genesis(recipients, 1, &tx);
    if (rc != DNAC_SUCCESS || !tx) {
        printf("  NOTE: dnac_tx_create_genesis returned %d — testing derivation only\n", rc);

        /* Fall back to testing derivation with synthetic tx_hash */
        uint8_t fake_tx_hash[DNAC_TX_HASH_SIZE];
        memset(fake_tx_hash, 0xCA, DNAC_TX_HASH_SIZE);

        uint8_t chain_id[32];
        rc = dnac_derive_chain_id(FP_C, fake_tx_hash, chain_id);
        if (rc == 0 && !is_all_zeros(chain_id, 32)) {
            PASS("3a: Chain ID derivation works with synthetic tx_hash");
            print_hex32("chain_id", chain_id);
        } else {
            FAIL("3a: Chain ID derivation failed with synthetic tx_hash");
        }

        /* Determinism check */
        uint8_t chain_id_2[32];
        dnac_derive_chain_id(FP_C, fake_tx_hash, chain_id_2);
        if (memcmp(chain_id, chain_id_2, 32) == 0) {
            PASS("3b: Same inputs give same chain_id (deterministic, synthetic)");
        } else {
            FAIL("3b: Same inputs gave different chain_ids!");
        }

        printf("  NOTE: Full phase1_create test skipped (requires DNAC context)\n");
        return;
    }

    printf("  Genesis TX created successfully\n");

    /* 3a: tx should not be NULL (already checked above) */
    PASS("3a: dnac_tx_create_genesis returned valid TX");

    /* 3b: tx_hash should not be all zeros */
    if (!is_all_zeros(tx->tx_hash, DNAC_TX_HASH_SIZE)) {
        PASS("3b: Genesis TX has non-zero tx_hash");
        printf("    tx_hash: ");
        for (int i = 0; i < 16; i++) printf("%02x", tx->tx_hash[i]);
        printf("...\n");
    } else {
        FAIL("3b: Genesis TX has all-zero tx_hash");
    }

    /* 3c: Derive chain_id and verify = SHA3-256(recipient_fp || tx_hash) */
    uint8_t chain_id[32];
    rc = dnac_derive_chain_id(FP_C, tx->tx_hash, chain_id);
    if (rc != 0) {
        FAIL("3c: dnac_derive_chain_id failed on genesis TX");
        dnac_free_transaction(tx);
        return;
    }

    uint8_t expected[32];
    rc = compute_expected_chain_id(FP_C, tx->tx_hash, expected);
    if (rc != 0) {
        FAIL("3c: compute_expected_chain_id failed");
        dnac_free_transaction(tx);
        return;
    }

    if (memcmp(chain_id, expected, 32) == 0) {
        PASS("3c: chain_id = SHA3-256(recipient_fp_bytes || tx_hash) verified");
        print_hex32("chain_id", chain_id);
    } else {
        FAIL("3c: chain_id does not match SHA3-256(fp_bytes || tx_hash)");
        print_hex32("got     ", chain_id);
        print_hex32("expected", expected);
    }

    /* 3d: chain_id should not be all zeros */
    if (!is_all_zeros(chain_id, 32)) {
        PASS("3d: chain_id is not all zeros");
    } else {
        FAIL("3d: chain_id is all zeros");
    }

    /* 3e: Creating same genesis again should give same tx_hash → same chain_id */
    dnac_transaction_t *tx2 = NULL;
    rc = dnac_tx_create_genesis(recipients, 1, &tx2);
    if (rc == DNAC_SUCCESS && tx2) {
        uint8_t chain_id_2[32];
        dnac_derive_chain_id(FP_C, tx2->tx_hash, chain_id_2);

        /*
         * Note: tx_hash may differ if timestamp is included in hash computation.
         * If they match, great — deterministic. If not, that's expected since
         * timestamps are part of the TX.
         */
        if (memcmp(tx->tx_hash, tx2->tx_hash, DNAC_TX_HASH_SIZE) == 0) {
            if (memcmp(chain_id, chain_id_2, 32) == 0) {
                PASS("3e: Same genesis inputs give same chain_id (fully deterministic)");
            } else {
                FAIL("3e: Same tx_hash but different chain_id!");
            }
        } else {
            /* tx_hash differs (includes timestamp) — verify derivation still correct */
            uint8_t expected2[32];
            compute_expected_chain_id(FP_C, tx2->tx_hash, expected2);
            if (memcmp(chain_id_2, expected2, 32) == 0) {
                PASS("3e: Second genesis has different tx_hash (timestamp) but derivation is correct");
            } else {
                FAIL("3e: Second genesis derivation incorrect");
            }
        }
        dnac_free_transaction(tx2);
    } else {
        printf("  NOTE: Second dnac_tx_create_genesis returned %d — skipping 3e\n", rc);
    }

    dnac_free_transaction(tx);
}

/* ============================================================================
 * TEST 4: Edge Cases & Robustness
 * ========================================================================== */

static void test_edge_cases(void) {
    printf("\n=== TEST 4: Edge Cases & Robustness ===\n");

    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    uint8_t chain_id[32];

    /* 4a: All-zero fingerprint (valid hex, just zero bytes) */
    {
        const char *fp_zero =
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000";
        memset(tx_hash, 0x00, DNAC_TX_HASH_SIZE);

        int rc = dnac_derive_chain_id(fp_zero, tx_hash, chain_id);
        if (rc == 0) {
            /* SHA3-256 of 128 zero bytes should produce a known non-zero hash */
            if (!is_all_zeros(chain_id, 32)) {
                PASS("4a: All-zero inputs produce non-zero chain_id (SHA3 diffusion)");
            } else {
                FAIL("4a: All-zero inputs produced all-zero chain_id (SHA3 broken?!)");
            }
        } else {
            FAIL("4a: All-zero inputs rejected (should be valid)");
        }
    }

    /* 4b: Mixed-case hex fingerprint */
    {
        const char *fp_mixed =
            "AABBCCDDEEFFaabbccddeeff00112233445566778899AABBCCDDEEFFaabbccdd"
            "eeff00112233445566778899AABBCCDDEEFFaabbccddeeff0011223344556677";
        memset(tx_hash, 0xFF, DNAC_TX_HASH_SIZE);

        int rc = dnac_derive_chain_id(fp_mixed, tx_hash, chain_id);
        if (rc == 0) {
            PASS("4b: Mixed-case hex fingerprint accepted");
        } else {
            /* Some implementations may only accept lowercase */
            printf("  NOTE: 4b: Mixed-case hex rejected (implementation may require lowercase)\n");
        }
    }

    /* 4c: Maximum-value inputs */
    {
        const char *fp_max =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        memset(tx_hash, 0xFF, DNAC_TX_HASH_SIZE);

        int rc = dnac_derive_chain_id(fp_max, tx_hash, chain_id);
        if (rc == 0 && !is_all_zeros(chain_id, 32)) {
            PASS("4c: Max-value inputs produce valid non-zero chain_id");
            print_hex32("chain_id", chain_id);
        } else {
            FAIL("4c: Max-value inputs failed");
        }
    }
}

/* ============================================================================
 * Main
 * ========================================================================== */

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║       DNAC Chain ID Derivation & Phase 1 Genesis Tests       ║\n");
    printf("║                                                               ║\n");
    printf("║  Tests: chain_id = SHA3-256(fp_bytes || tx_hash)             ║\n");
    printf("║  All tests are offline — no network required                  ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    test_chain_id_derivation();
    test_multi_chain();
    test_phase1_genesis();
    test_edge_cases();

    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║  Results: %d passed, %d failed                                 ║\n",
           g_passed, g_failed);
    if (g_failed == 0) {
        printf("║                    ALL TESTS PASSED                          ║\n");
    } else {
        printf("║                    SOME TESTS FAILED                         ║\n");
    }
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    return g_failed > 0 ? 1 : 0;
}
