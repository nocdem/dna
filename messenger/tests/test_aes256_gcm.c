/**
 * @file test_aes256_gcm.c
 * @brief Test AES-256-GCM encryption/decryption
 *
 * Tests:
 * - Encrypt/decrypt round-trip
 * - Authentication tag verification
 * - Tampered ciphertext rejection
 * - Tampered AAD rejection
 * - Wrong key rejection
 * - Edge cases (empty plaintext, large data)
 *
 * Part of DNA Messenger beta readiness testing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../crypto/utils/qgp_aes.h"
#include "../crypto/utils/qgp_random.h"

#define TEST_PASSED(name) printf("   ✓ %s\n", name)
#define TEST_FAILED(name) do { printf("   ✗ %s\n", name); return 1; } while(0)

/**
 * Test basic encrypt/decrypt round-trip
 */
static int test_round_trip(void) {
    printf("\n1. Testing encrypt/decrypt round-trip...\n");

    const char *plaintext = "DNA Messenger - Post-Quantum E2E Encryption Test";
    size_t plaintext_len = strlen(plaintext);

    uint8_t key[32];
    qgp_randombytes(key, 32);

    uint8_t nonce[12];
    uint8_t tag[16];
    uint8_t *ciphertext = malloc(plaintext_len);
    size_t ciphertext_len = 0;

    // Encrypt
    int ret = qgp_aes256_encrypt(
        key,
        (uint8_t*)plaintext, plaintext_len,
        NULL, 0,  // No AAD
        ciphertext, &ciphertext_len,
        nonce, tag
    );

    if (ret != 0) TEST_FAILED("Encryption failed");
    if (ciphertext_len != plaintext_len) TEST_FAILED("Ciphertext length mismatch");
    TEST_PASSED("Encryption succeeded");

    // Decrypt
    uint8_t *decrypted = malloc(ciphertext_len);
    size_t decrypted_len = 0;

    ret = qgp_aes256_decrypt(
        key,
        ciphertext, ciphertext_len,
        NULL, 0,  // No AAD
        nonce, tag,
        decrypted, &decrypted_len
    );

    if (ret != 0) TEST_FAILED("Decryption failed");
    if (decrypted_len != plaintext_len) TEST_FAILED("Decrypted length mismatch");
    if (memcmp(decrypted, plaintext, plaintext_len) != 0) TEST_FAILED("Decrypted content mismatch");
    TEST_PASSED("Decryption succeeded");
    TEST_PASSED("Round-trip verified");

    free(ciphertext);
    free(decrypted);
    return 0;
}

/**
 * Test with Additional Authenticated Data (AAD)
 */
static int test_with_aad(void) {
    printf("\n2. Testing with AAD (metadata authentication)...\n");

    const char *plaintext = "Secret message content";
    size_t plaintext_len = strlen(plaintext);
    const char *aad = "sender=alice;recipient=bob;timestamp=1234567890";
    size_t aad_len = strlen(aad);

    uint8_t key[32];
    qgp_randombytes(key, 32);

    uint8_t nonce[12];
    uint8_t tag[16];
    uint8_t *ciphertext = malloc(plaintext_len);
    size_t ciphertext_len = 0;

    // Encrypt with AAD
    int ret = qgp_aes256_encrypt(
        key,
        (uint8_t*)plaintext, plaintext_len,
        (uint8_t*)aad, aad_len,
        ciphertext, &ciphertext_len,
        nonce, tag
    );

    if (ret != 0) TEST_FAILED("Encryption with AAD failed");
    TEST_PASSED("Encryption with AAD succeeded");

    // Decrypt with same AAD
    uint8_t *decrypted = malloc(ciphertext_len);
    size_t decrypted_len = 0;

    ret = qgp_aes256_decrypt(
        key,
        ciphertext, ciphertext_len,
        (uint8_t*)aad, aad_len,
        nonce, tag,
        decrypted, &decrypted_len
    );

    if (ret != 0) TEST_FAILED("Decryption with AAD failed");
    if (memcmp(decrypted, plaintext, plaintext_len) != 0) TEST_FAILED("Content mismatch");
    TEST_PASSED("Decryption with AAD succeeded");

    free(ciphertext);
    free(decrypted);
    return 0;
}

/**
 * Test tampered ciphertext rejection
 */
static int test_tampered_ciphertext(void) {
    printf("\n3. Testing tampered ciphertext rejection...\n");

    const char *plaintext = "This data must not be tampered with";
    size_t plaintext_len = strlen(plaintext);

    uint8_t key[32];
    qgp_randombytes(key, 32);

    uint8_t nonce[12];
    uint8_t tag[16];
    uint8_t *ciphertext = malloc(plaintext_len);
    size_t ciphertext_len = 0;

    // Encrypt
    qgp_aes256_encrypt(key, (uint8_t*)plaintext, plaintext_len,
                       NULL, 0, ciphertext, &ciphertext_len, nonce, tag);

    // Tamper with ciphertext
    ciphertext[0] ^= 0xFF;

    // Attempt decrypt
    uint8_t *decrypted = malloc(ciphertext_len);
    size_t decrypted_len = 0;

    int ret = qgp_aes256_decrypt(key, ciphertext, ciphertext_len,
                                  NULL, 0, nonce, tag, decrypted, &decrypted_len);

    if (ret == 0) TEST_FAILED("Tampered ciphertext was accepted!");
    TEST_PASSED("Tampered ciphertext rejected");

    free(ciphertext);
    free(decrypted);
    return 0;
}

/**
 * Test tampered AAD rejection
 */
static int test_tampered_aad(void) {
    printf("\n4. Testing tampered AAD rejection...\n");

    const char *plaintext = "Message content";
    size_t plaintext_len = strlen(plaintext);
    const char *aad = "original_metadata";
    size_t aad_len = strlen(aad);

    uint8_t key[32];
    qgp_randombytes(key, 32);

    uint8_t nonce[12];
    uint8_t tag[16];
    uint8_t *ciphertext = malloc(plaintext_len);
    size_t ciphertext_len = 0;

    // Encrypt with original AAD
    qgp_aes256_encrypt(key, (uint8_t*)plaintext, plaintext_len,
                       (uint8_t*)aad, aad_len, ciphertext, &ciphertext_len, nonce, tag);

    // Attempt decrypt with different AAD
    const char *tampered_aad = "tampered_metadata";
    uint8_t *decrypted = malloc(ciphertext_len);
    size_t decrypted_len = 0;

    int ret = qgp_aes256_decrypt(key, ciphertext, ciphertext_len,
                                  (uint8_t*)tampered_aad, strlen(tampered_aad),
                                  nonce, tag, decrypted, &decrypted_len);

    if (ret == 0) TEST_FAILED("Tampered AAD was accepted!");
    TEST_PASSED("Tampered AAD rejected");

    free(ciphertext);
    free(decrypted);
    return 0;
}

/**
 * Test wrong key rejection
 */
static int test_wrong_key(void) {
    printf("\n5. Testing wrong key rejection...\n");

    const char *plaintext = "Encrypted with key A";
    size_t plaintext_len = strlen(plaintext);

    uint8_t key_a[32], key_b[32];
    qgp_randombytes(key_a, 32);
    qgp_randombytes(key_b, 32);

    uint8_t nonce[12];
    uint8_t tag[16];
    uint8_t *ciphertext = malloc(plaintext_len);
    size_t ciphertext_len = 0;

    // Encrypt with key A
    qgp_aes256_encrypt(key_a, (uint8_t*)plaintext, plaintext_len,
                       NULL, 0, ciphertext, &ciphertext_len, nonce, tag);

    // Attempt decrypt with key B
    uint8_t *decrypted = malloc(ciphertext_len);
    size_t decrypted_len = 0;

    int ret = qgp_aes256_decrypt(key_b, ciphertext, ciphertext_len,
                                  NULL, 0, nonce, tag, decrypted, &decrypted_len);

    if (ret == 0) TEST_FAILED("Wrong key was accepted!");
    TEST_PASSED("Wrong key rejected");

    free(ciphertext);
    free(decrypted);
    return 0;
}

/**
 * Test tampered tag rejection
 */
static int test_tampered_tag(void) {
    printf("\n6. Testing tampered authentication tag rejection...\n");

    const char *plaintext = "Protected by auth tag";
    size_t plaintext_len = strlen(plaintext);

    uint8_t key[32];
    qgp_randombytes(key, 32);

    uint8_t nonce[12];
    uint8_t tag[16];
    uint8_t *ciphertext = malloc(plaintext_len);
    size_t ciphertext_len = 0;

    // Encrypt
    qgp_aes256_encrypt(key, (uint8_t*)plaintext, plaintext_len,
                       NULL, 0, ciphertext, &ciphertext_len, nonce, tag);

    // Tamper with tag
    tag[0] ^= 0xFF;

    // Attempt decrypt
    uint8_t *decrypted = malloc(ciphertext_len);
    size_t decrypted_len = 0;

    int ret = qgp_aes256_decrypt(key, ciphertext, ciphertext_len,
                                  NULL, 0, nonce, tag, decrypted, &decrypted_len);

    if (ret == 0) TEST_FAILED("Tampered tag was accepted!");
    TEST_PASSED("Tampered tag rejected");

    free(ciphertext);
    free(decrypted);
    return 0;
}

/**
 * Test empty plaintext rejection
 * NOTE: qgp_aes256_encrypt() explicitly rejects empty plaintext as invalid input.
 * This is correct behavior - encrypting nothing is not meaningful.
 */
static int test_empty_plaintext_rejection(void) {
    printf("\n7. Testing empty plaintext rejection...\n");

    uint8_t key[32];
    qgp_randombytes(key, 32);

    uint8_t nonce[12];
    uint8_t tag[16];
    uint8_t ciphertext[1];
    size_t ciphertext_len = 0;

    // Attempt to encrypt empty data - should be rejected
    const char *aad = "metadata_only";
    int ret = qgp_aes256_encrypt(key, NULL, 0,
                                  (uint8_t*)aad, strlen(aad),
                                  ciphertext, &ciphertext_len, nonce, tag);

    if (ret == 0) TEST_FAILED("Empty plaintext should be rejected!");
    TEST_PASSED("Empty plaintext correctly rejected");

    return 0;
}

/**
 * Test large data (64KB)
 */
static int test_large_data(void) {
    printf("\n8. Testing large data (64KB)...\n");

    size_t data_size = 64 * 1024;
    uint8_t *plaintext = malloc(data_size);
    qgp_randombytes(plaintext, data_size);

    uint8_t key[32];
    qgp_randombytes(key, 32);

    uint8_t nonce[12];
    uint8_t tag[16];
    uint8_t *ciphertext = malloc(data_size);
    size_t ciphertext_len = 0;

    // Encrypt
    int ret = qgp_aes256_encrypt(key, plaintext, data_size,
                                  NULL, 0, ciphertext, &ciphertext_len, nonce, tag);

    if (ret != 0) TEST_FAILED("Large data encryption failed");
    TEST_PASSED("Large data encryption succeeded");

    // Decrypt
    uint8_t *decrypted = malloc(data_size);
    size_t decrypted_len = 0;

    ret = qgp_aes256_decrypt(key, ciphertext, ciphertext_len,
                              NULL, 0, nonce, tag, decrypted, &decrypted_len);

    if (ret != 0) TEST_FAILED("Large data decryption failed");
    if (decrypted_len != data_size) TEST_FAILED("Decrypted length mismatch");
    if (memcmp(decrypted, plaintext, data_size) != 0) TEST_FAILED("Large data content mismatch");
    TEST_PASSED("Large data round-trip verified");

    free(plaintext);
    free(ciphertext);
    free(decrypted);
    return 0;
}

/**
 * Security information
 */
static void print_security_info(void) {
    printf("\n9. Security Parameters\n");
    printf("   Algorithm: AES-256-GCM (AEAD)\n");
    printf("   Key size: 256 bits\n");
    printf("   Nonce size: 96 bits (12 bytes)\n");
    printf("   Tag size: 128 bits (16 bytes)\n");
    printf("   Mode: Galois/Counter Mode\n");
    printf("   Properties: Authenticated Encryption with Associated Data\n");
    printf("   NIST Approved: Yes (SP 800-38D)\n");
}

int main(void) {
    printf("=== AES-256-GCM Unit Tests ===\n");

    int failed = 0;

    failed += test_round_trip();
    failed += test_with_aad();
    failed += test_tampered_ciphertext();
    failed += test_tampered_aad();
    failed += test_wrong_key();
    failed += test_tampered_tag();
    failed += test_empty_plaintext_rejection();
    failed += test_large_data();

    print_security_info();

    printf("\n");
    if (failed == 0) {
        printf("=== All AES-256-GCM Tests Passed ===\n");
        return 0;
    } else {
        printf("=== %d Test(s) Failed ===\n", failed);
        return 1;
    }
}
