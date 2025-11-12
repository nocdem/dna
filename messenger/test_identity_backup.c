/**
 * Test program for DHT Identity Backup System
 *
 * Tests:
 * 1. Create random DHT identity and encrypted backup
 * 2. Load from local file
 * 3. Verify encryption/decryption roundtrip
 * 4. Test with DHT singleton
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dht/dht_identity_backup.h"
#include "dht/dht_singleton.h"
#include "dht/dht_context.h"
#include "crypto/kem/kem.h"
#include "qgp_sha3.h"

// Test fingerprint (simulated - SHA3-512 = 128 hex characters = 64 bytes)
static const char *TEST_FINGERPRINT =
    "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
    "7890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456";

/**
 * Test 1: Create DHT identity and backup
 */
int test_create_and_backup(void) {
    printf("\n=== Test 1: Create DHT Identity and Backup ===\n");

    // Generate Kyber1024 keypair
    printf("Generating Kyber1024 keypair...\n");
    uint8_t kyber_pk[1568];
    uint8_t kyber_sk[3168];

    if (crypto_kem_keypair(kyber_pk, kyber_sk) != 0) {
        fprintf(stderr, "ERROR: Kyber keypair generation failed\n");
        return -1;
    }
    printf("✓ Kyber1024 keypair generated\n");

    // Initialize DHT singleton (ephemeral identity)
    printf("Initializing DHT singleton...\n");
    if (dht_singleton_init() != 0) {
        fprintf(stderr, "ERROR: DHT singleton initialization failed\n");
        return -1;
    }
    printf("✓ DHT singleton initialized\n");

    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        fprintf(stderr, "ERROR: Failed to get DHT context\n");
        return -1;
    }

    // Create DHT identity and encrypted backup
    printf("Creating DHT identity and encrypted backup...\n");
    dht_identity_t *identity = NULL;
    if (dht_identity_create_and_backup(TEST_FINGERPRINT, kyber_pk, dht_ctx, &identity) != 0) {
        fprintf(stderr, "ERROR: Failed to create DHT identity backup\n");
        dht_singleton_cleanup();
        return -1;
    }
    printf("✓ DHT identity created and backed up\n");

    // Free identity
    dht_identity_free(identity);

    // Check if local file exists
    char local_path[512];
    if (dht_identity_get_local_path(TEST_FINGERPRINT, local_path) == 0) {
        printf("✓ Local backup file: %s\n", local_path);

        if (access(local_path, F_OK) == 0) {
            printf("✓ Local backup file exists\n");
        } else {
            fprintf(stderr, "ERROR: Local backup file does not exist\n");
            dht_singleton_cleanup();
            return -1;
        }
    }

    dht_singleton_cleanup();
    printf("✓ Test 1 PASSED\n");
    return 0;
}

/**
 * Test 2: Load from local file
 */
int test_load_from_local(void) {
    printf("\n=== Test 2: Load DHT Identity from Local File ===\n");

    // Generate same Kyber1024 keypair (for decryption)
    printf("Generating Kyber1024 keypair...\n");
    uint8_t kyber_pk[1568];
    uint8_t kyber_sk[3168];

    if (crypto_kem_keypair(kyber_pk, kyber_sk) != 0) {
        fprintf(stderr, "ERROR: Kyber keypair generation failed\n");
        return -1;
    }

    // Initialize DHT (for create)
    if (dht_singleton_init() != 0) {
        fprintf(stderr, "ERROR: DHT initialization failed\n");
        return -1;
    }

    dht_context_t *dht_ctx = dht_singleton_get();

    // Create backup first
    printf("Creating test backup...\n");
    dht_identity_t *identity1 = NULL;
    if (dht_identity_create_and_backup(TEST_FINGERPRINT, kyber_pk, dht_ctx, &identity1) != 0) {
        fprintf(stderr, "ERROR: Failed to create backup\n");
        dht_singleton_cleanup();
        return -1;
    }
    dht_identity_free(identity1);
    printf("✓ Test backup created\n");

    // Now load from local file
    printf("Loading DHT identity from local file...\n");
    dht_identity_t *identity2 = NULL;
    if (dht_identity_load_from_local(TEST_FINGERPRINT, kyber_sk, &identity2) != 0) {
        fprintf(stderr, "ERROR: Failed to load from local file\n");
        dht_singleton_cleanup();
        return -1;
    }
    printf("✓ DHT identity loaded from local file\n");

    // Cleanup
    dht_identity_free(identity2);
    dht_singleton_cleanup();

    printf("✓ Test 2 PASSED\n");
    return 0;
}

/**
 * Test 3: Reinitialize DHT with permanent identity
 */
int test_dht_reinit_with_identity(void) {
    printf("\n=== Test 3: Reinitialize DHT with Permanent Identity ===\n");

    // Generate Kyber keypair
    uint8_t kyber_pk[1568];
    uint8_t kyber_sk[3168];

    if (crypto_kem_keypair(kyber_pk, kyber_sk) != 0) {
        fprintf(stderr, "ERROR: Kyber keypair generation failed\n");
        return -1;
    }

    // Initialize DHT
    if (dht_singleton_init() != 0) {
        fprintf(stderr, "ERROR: DHT initialization failed\n");
        return -1;
    }

    dht_context_t *dht_ctx = dht_singleton_get();

    // Create backup
    printf("Creating DHT identity...\n");
    dht_identity_t *identity = NULL;
    if (dht_identity_create_and_backup(TEST_FINGERPRINT, kyber_pk, dht_ctx, &identity) != 0) {
        fprintf(stderr, "ERROR: Failed to create identity\n");
        dht_singleton_cleanup();
        return -1;
    }
    printf("✓ DHT identity created\n");

    // Cleanup old DHT
    printf("Cleaning up old DHT singleton...\n");
    dht_singleton_cleanup();

    // Reinitialize with permanent identity
    printf("Reinitializing DHT with permanent identity...\n");
    if (dht_singleton_init_with_identity(identity) != 0) {
        fprintf(stderr, "ERROR: Failed to reinitialize DHT with identity\n");
        dht_identity_free(identity);
        return -1;
    }
    printf("✓ DHT reinitialized with permanent identity\n");

    // Don't free identity - owned by DHT singleton now
    dht_singleton_cleanup();

    printf("✓ Test 3 PASSED\n");
    return 0;
}

/**
 * Test 4: Check local file existence
 */
int test_local_file_exists(void) {
    printf("\n=== Test 4: Check Local File Existence ===\n");

    // Generate Kyber keypair
    uint8_t kyber_pk[1568];
    uint8_t kyber_sk[3168];

    if (crypto_kem_keypair(kyber_pk, kyber_sk) != 0) {
        fprintf(stderr, "ERROR: Kyber keypair generation failed\n");
        return -1;
    }

    // Initialize DHT
    if (dht_singleton_init() != 0) {
        fprintf(stderr, "ERROR: DHT initialization failed\n");
        return -1;
    }

    dht_context_t *dht_ctx = dht_singleton_get();

    // Create backup
    dht_identity_t *identity = NULL;
    if (dht_identity_create_and_backup(TEST_FINGERPRINT, kyber_pk, dht_ctx, &identity) != 0) {
        fprintf(stderr, "ERROR: Failed to create backup\n");
        dht_singleton_cleanup();
        return -1;
    }
    dht_identity_free(identity);

    // Check existence
    if (dht_identity_local_exists(TEST_FINGERPRINT)) {
        printf("✓ Local backup file exists (as expected)\n");
    } else {
        fprintf(stderr, "ERROR: Local backup file does not exist\n");
        dht_singleton_cleanup();
        return -1;
    }

    dht_singleton_cleanup();
    printf("✓ Test 4 PASSED\n");
    return 0;
}

/**
 * Main test runner
 */
int main(int argc, char *argv[]) {
    printf("========================================\n");
    printf("DHT Identity Backup System - Test Suite\n");
    printf("========================================\n");
    printf("Test fingerprint: %.60s...\n", TEST_FINGERPRINT);

    int failed = 0;

    // Run tests
    if (test_create_and_backup() != 0) {
        fprintf(stderr, "✗ Test 1 FAILED\n");
        failed++;
    }

    if (test_load_from_local() != 0) {
        fprintf(stderr, "✗ Test 2 FAILED\n");
        failed++;
    }

    if (test_dht_reinit_with_identity() != 0) {
        fprintf(stderr, "✗ Test 3 FAILED\n");
        failed++;
    }

    if (test_local_file_exists() != 0) {
        fprintf(stderr, "✗ Test 4 FAILED\n");
        failed++;
    }

    // Summary
    printf("\n========================================\n");
    printf("Test Summary\n");
    printf("========================================\n");
    printf("Total Tests: 4\n");
    printf("Passed: %d\n", 4 - failed);
    printf("Failed: %d\n", failed);

    if (failed == 0) {
        printf("\n✓ ALL TESTS PASSED!\n\n");
        return 0;
    } else {
        printf("\n✗ SOME TESTS FAILED\n\n");
        return 1;
    }
}
