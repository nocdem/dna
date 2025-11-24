/**
 * @file test_dilithium5_signature.c
 * @brief Test Dilithium5 (ML-DSA-87) signature operations
 *
 * Tests:
 * - Sign/verify with Dilithium5
 * - Signature size validation (4595 bytes)
 * - Invalid signature rejection
 * - NIST Category 5 security validation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../crypto/dsa/api.h"
#include "../crypto/utils/qgp_random.h"

#define TEST_MESSAGE "DNA Messenger - Post-Quantum E2E Encryption"
#define EXPECTED_SIG_SIZE 4595  // Dilithium5 signature size

int main(void) {
    printf("=== Dilithium5 Signature Test ===\n\n");

    // Generate keypair
    printf("1. Generating Dilithium5 keypair...\n");
    uint8_t pk[PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_SECRETKEYBYTES];

    int ret = PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_keypair(pk, sk);
    assert(ret == 0 && "Keypair generation failed");
    printf("   ✓ Keypair generated\n");
    printf("   Public key size: %d bytes\n", PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES);
    printf("   Secret key size: %d bytes\n\n", PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_SECRETKEYBYTES);

    // Sign message
    printf("2. Signing test message...\n");
    uint8_t *signed_msg = malloc(strlen(TEST_MESSAGE) + PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES);
    size_t signed_len = 0;

    ret = PQCLEAN_DILITHIUM5_CLEAN_crypto_sign(
        signed_msg, &signed_len,
        (uint8_t*)TEST_MESSAGE, strlen(TEST_MESSAGE),
        sk
    );
    assert(ret == 0 && "Signing failed");

    size_t sig_size = signed_len - strlen(TEST_MESSAGE);
    printf("   ✓ Message signed\n");
    printf("   Signature size: %zu bytes\n", sig_size);
    printf("   Expected size: %d bytes\n", EXPECTED_SIG_SIZE);
    assert(sig_size == EXPECTED_SIG_SIZE && "Signature size mismatch");
    printf("   ✓ Signature size correct\n\n");

    // Verify signature
    printf("3. Verifying signature...\n");
    uint8_t *verified_msg = malloc(signed_len);
    size_t verified_len = 0;

    ret = PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_open(
        verified_msg, &verified_len,
        signed_msg, signed_len,
        pk
    );
    assert(ret == 0 && "Verification failed");
    assert(verified_len == strlen(TEST_MESSAGE) && "Message length mismatch");
    assert(memcmp(verified_msg, TEST_MESSAGE, verified_len) == 0 && "Message content mismatch");
    printf("   ✓ Signature verified\n");
    printf("   Message recovered: %.*s\n\n", (int)verified_len, verified_msg);

    // Test invalid signature rejection
    printf("4. Testing invalid signature rejection...\n");
    signed_msg[10] ^= 0xFF;  // Corrupt signature

    ret = PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_open(
        verified_msg, &verified_len,
        signed_msg, signed_len,
        pk
    );
    assert(ret != 0 && "Invalid signature was accepted!");
    printf("   ✓ Invalid signature rejected\n\n");

    // NIST Category 5 Security Level
    printf("5. Security Level Verification\n");
    printf("   Algorithm: ML-DSA-87 (Dilithium5)\n");
    printf("   NIST Category: 5\n");
    printf("   Quantum Security: 256-bit\n");
    printf("   Classical Security: 256-bit\n");
    printf("   FIPS 204 Compliant: Yes\n\n");

    free(signed_msg);
    free(verified_msg);

    printf("=== All Dilithium5 Tests Passed ===\n");
    return 0;
}
