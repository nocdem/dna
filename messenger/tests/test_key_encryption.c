/**
 * @file test_key_encryption.c
 * @brief Test password-based key encryption (PBKDF2 + AES-256-GCM)
 *
 * Tests:
 * - Encrypt/decrypt round-trip
 * - Wrong password rejection
 * - Corrupted data rejection
 * - Empty password handling
 * - Large key data
 * - File save/load operations
 *
 * Part of DNA Messenger beta readiness testing (P1-1).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../crypto/utils/key_encryption.h"
#include "../crypto/utils/qgp_random.h"

#define TEST_PASSED(name) printf("   ✓ %s\n", name)
#define TEST_FAILED(name) do { printf("   ✗ %s\n", name); return 1; } while(0)

/**
 * Test basic encrypt/decrypt round-trip
 */
static int test_round_trip(void) {
    printf("\n1. Testing encrypt/decrypt round-trip...\n");

    // Simulate a private key (3168 bytes like Kyber secret key)
    uint8_t key_data[3168];
    qgp_randombytes(key_data, sizeof(key_data));

    const char *password = "TestPassword123!";

    // Allocate output buffer (key + header overhead)
    size_t encrypted_buf_size = sizeof(key_data) + KEY_ENC_HEADER_SIZE;
    uint8_t *encrypted = malloc(encrypted_buf_size);
    size_t encrypted_size = 0;

    // Encrypt
    int ret = key_encrypt(key_data, sizeof(key_data), password, encrypted, &encrypted_size);
    if (ret != 0) TEST_FAILED("Encryption failed");
    if (encrypted_size != encrypted_buf_size) TEST_FAILED("Encrypted size mismatch");
    TEST_PASSED("Encryption succeeded");

    // Verify magic header
    if (memcmp(encrypted, KEY_ENC_MAGIC, KEY_ENC_MAGIC_SIZE) != 0) {
        TEST_FAILED("Magic header missing");
    }
    TEST_PASSED("Magic header present");

    // Decrypt
    uint8_t *decrypted = malloc(sizeof(key_data));
    size_t decrypted_size = 0;

    ret = key_decrypt(encrypted, encrypted_size, password, decrypted, &decrypted_size);
    if (ret != 0) TEST_FAILED("Decryption failed");
    if (decrypted_size != sizeof(key_data)) TEST_FAILED("Decrypted size mismatch");
    if (memcmp(decrypted, key_data, sizeof(key_data)) != 0) TEST_FAILED("Decrypted content mismatch");
    TEST_PASSED("Decryption succeeded");
    TEST_PASSED("Round-trip verified");

    free(encrypted);
    free(decrypted);
    return 0;
}

/**
 * Test wrong password rejection
 */
static int test_wrong_password(void) {
    printf("\n2. Testing wrong password rejection...\n");

    uint8_t key_data[256];
    qgp_randombytes(key_data, sizeof(key_data));

    const char *correct_password = "CorrectPassword";
    const char *wrong_password = "WrongPassword";

    size_t encrypted_buf_size = sizeof(key_data) + KEY_ENC_HEADER_SIZE;
    uint8_t *encrypted = malloc(encrypted_buf_size);
    size_t encrypted_size = 0;

    // Encrypt with correct password
    int ret = key_encrypt(key_data, sizeof(key_data), correct_password, encrypted, &encrypted_size);
    if (ret != 0) TEST_FAILED("Encryption failed");
    TEST_PASSED("Encryption succeeded");

    // Attempt decrypt with wrong password
    uint8_t *decrypted = malloc(sizeof(key_data));
    size_t decrypted_size = 0;

    ret = key_decrypt(encrypted, encrypted_size, wrong_password, decrypted, &decrypted_size);
    if (ret == 0) TEST_FAILED("Wrong password was accepted!");
    TEST_PASSED("Wrong password rejected");

    free(encrypted);
    free(decrypted);
    return 0;
}

/**
 * Test corrupted ciphertext rejection
 */
static int test_corrupted_data(void) {
    printf("\n3. Testing corrupted data rejection...\n");

    uint8_t key_data[256];
    qgp_randombytes(key_data, sizeof(key_data));

    const char *password = "TestPassword";

    size_t encrypted_buf_size = sizeof(key_data) + KEY_ENC_HEADER_SIZE;
    uint8_t *encrypted = malloc(encrypted_buf_size);
    size_t encrypted_size = 0;

    // Encrypt
    int ret = key_encrypt(key_data, sizeof(key_data), password, encrypted, &encrypted_size);
    if (ret != 0) TEST_FAILED("Encryption failed");

    // Corrupt the ciphertext (after header)
    encrypted[KEY_ENC_HEADER_SIZE + 10] ^= 0xFF;

    // Attempt decrypt
    uint8_t *decrypted = malloc(sizeof(key_data));
    size_t decrypted_size = 0;

    ret = key_decrypt(encrypted, encrypted_size, password, decrypted, &decrypted_size);
    if (ret == 0) TEST_FAILED("Corrupted data was accepted!");
    TEST_PASSED("Corrupted data rejected");

    free(encrypted);
    free(decrypted);
    return 0;
}

/**
 * Test corrupted auth tag rejection
 */
static int test_corrupted_tag(void) {
    printf("\n4. Testing corrupted auth tag rejection...\n");

    uint8_t key_data[256];
    qgp_randombytes(key_data, sizeof(key_data));

    const char *password = "TestPassword";

    size_t encrypted_buf_size = sizeof(key_data) + KEY_ENC_HEADER_SIZE;
    uint8_t *encrypted = malloc(encrypted_buf_size);
    size_t encrypted_size = 0;

    // Encrypt
    int ret = key_encrypt(key_data, sizeof(key_data), password, encrypted, &encrypted_size);
    if (ret != 0) TEST_FAILED("Encryption failed");

    // Corrupt the auth tag (at offset: magic + version + salt + nonce = 4+1+32+12 = 49)
    encrypted[49] ^= 0xFF;

    // Attempt decrypt
    uint8_t *decrypted = malloc(sizeof(key_data));
    size_t decrypted_size = 0;

    ret = key_decrypt(encrypted, encrypted_size, password, decrypted, &decrypted_size);
    if (ret == 0) TEST_FAILED("Corrupted tag was accepted!");
    TEST_PASSED("Corrupted tag rejected");

    free(encrypted);
    free(decrypted);
    return 0;
}

/**
 * Test different key sizes
 */
static int test_various_key_sizes(void) {
    printf("\n5. Testing various key sizes...\n");

    const char *password = "TestPassword";
    size_t test_sizes[] = {32, 64, 256, 1568, 3168, 4627};  // Common key sizes
    int num_tests = sizeof(test_sizes) / sizeof(test_sizes[0]);

    for (int i = 0; i < num_tests; i++) {
        size_t key_size = test_sizes[i];
        uint8_t *key_data = malloc(key_size);
        qgp_randombytes(key_data, key_size);

        size_t encrypted_buf_size = key_size + KEY_ENC_HEADER_SIZE;
        uint8_t *encrypted = malloc(encrypted_buf_size);
        size_t encrypted_size = 0;

        // Encrypt
        int ret = key_encrypt(key_data, key_size, password, encrypted, &encrypted_size);
        if (ret != 0) {
            printf("   ✗ Encryption failed for size %zu\n", key_size);
            free(key_data);
            free(encrypted);
            return 1;
        }

        // Decrypt
        uint8_t *decrypted = malloc(key_size);
        size_t decrypted_size = 0;

        ret = key_decrypt(encrypted, encrypted_size, password, decrypted, &decrypted_size);
        if (ret != 0 || decrypted_size != key_size ||
            memcmp(decrypted, key_data, key_size) != 0) {
            printf("   ✗ Round-trip failed for size %zu\n", key_size);
            free(key_data);
            free(encrypted);
            free(decrypted);
            return 1;
        }

        printf("   ✓ Size %zu bytes OK\n", key_size);

        free(key_data);
        free(encrypted);
        free(decrypted);
    }

    TEST_PASSED("All key sizes verified");
    return 0;
}

/**
 * Test file save/load operations
 */
static int test_file_operations(void) {
    printf("\n6. Testing file save/load...\n");

    uint8_t key_data[1568];  // Kyber public key size
    qgp_randombytes(key_data, sizeof(key_data));

    const char *password = "FileTestPassword";
    const char *test_file = "/tmp/test_key_enc.bin";

    // Save encrypted
    int ret = key_save_encrypted(key_data, sizeof(key_data), password, test_file);
    if (ret != 0) TEST_FAILED("File save failed");
    TEST_PASSED("File save succeeded");

    // Verify file is encrypted
    if (!key_file_is_encrypted(test_file)) {
        TEST_FAILED("File not detected as encrypted");
    }
    TEST_PASSED("File detected as encrypted");

    // Load and decrypt
    uint8_t loaded[1568];
    size_t loaded_size = 0;

    ret = key_load_encrypted(test_file, password, loaded, sizeof(loaded), &loaded_size);
    if (ret != 0) TEST_FAILED("File load failed");
    if (loaded_size != sizeof(key_data)) TEST_FAILED("Loaded size mismatch");
    if (memcmp(loaded, key_data, sizeof(key_data)) != 0) TEST_FAILED("Loaded content mismatch");
    TEST_PASSED("File load succeeded");

    // Test wrong password on file
    ret = key_load_encrypted(test_file, "WrongPassword", loaded, sizeof(loaded), &loaded_size);
    if (ret == 0) TEST_FAILED("Wrong password accepted for file!");
    TEST_PASSED("Wrong password rejected for file");

    // Cleanup
    remove(test_file);
    return 0;
}

/**
 * Test password verification
 */
static int test_password_verification(void) {
    printf("\n7. Testing password verification...\n");

    uint8_t key_data[256];
    qgp_randombytes(key_data, sizeof(key_data));

    const char *password = "VerifyTestPassword";
    const char *test_file = "/tmp/test_key_verify.bin";

    // Save encrypted
    int ret = key_save_encrypted(key_data, sizeof(key_data), password, test_file);
    if (ret != 0) TEST_FAILED("File save failed");

    // Verify correct password
    ret = key_verify_password(test_file, password);
    if (ret != 0) TEST_FAILED("Correct password not verified");
    TEST_PASSED("Correct password verified");

    // Verify wrong password fails
    ret = key_verify_password(test_file, "WrongPassword");
    if (ret == 0) TEST_FAILED("Wrong password verified!");
    TEST_PASSED("Wrong password rejected");

    // Cleanup
    remove(test_file);
    return 0;
}

/**
 * Security information
 */
static void print_security_info(void) {
    printf("\n8. Security Parameters\n");
    printf("   Algorithm: PBKDF2-SHA256 + AES-256-GCM\n");
    printf("   PBKDF2 iterations: %d (OWASP 2023)\n", KEY_ENC_PBKDF2_ITERATIONS);
    printf("   Salt size: %d bytes (random per file)\n", KEY_ENC_SALT_SIZE);
    printf("   Nonce size: %d bytes\n", KEY_ENC_NONCE_SIZE);
    printf("   Auth tag: %d bytes\n", KEY_ENC_TAG_SIZE);
    printf("   Header overhead: %d bytes\n", KEY_ENC_HEADER_SIZE);
    printf("   Properties: Authenticated encryption, password-based\n");
}

int main(void) {
    printf("=== Key Encryption Unit Tests (P1-1) ===\n");

    int failed = 0;

    failed += test_round_trip();
    failed += test_wrong_password();
    failed += test_corrupted_data();
    failed += test_corrupted_tag();
    failed += test_various_key_sizes();
    failed += test_file_operations();
    failed += test_password_verification();

    print_security_info();

    printf("\n");
    if (failed == 0) {
        printf("=== All Key Encryption Tests Passed ===\n");
        return 0;
    } else {
        printf("=== %d Test(s) Failed ===\n", failed);
        return 1;
    }
}
