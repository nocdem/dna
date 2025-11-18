/*
 * Test v0.08 message format - encrypted timestamp
 *
 * Verifies that sender timestamp is correctly:
 * - Encrypted in payload (fingerprint + timestamp + plaintext)
 * - Decrypted and extracted
 * - Matches original timestamp
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../dna_api.h"
#include "../crypto/utils/qgp_kyber.h"
#include "../crypto/utils/qgp_dilithium.h"

int main(void) {
    printf("=== v0.08 Timestamp Encryption Test ===\n\n");

    // Step 1: Generate keys
    printf("[1/5] Generating keys...\n");

    uint8_t kyber_pubkey[QGP_KEM1024_PUBLICKEYBYTES];
    uint8_t kyber_privkey[QGP_KEM1024_SECRETKEYBYTES];

    uint8_t dilithium_pubkey[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t dilithium_privkey[QGP_DSA87_SECRETKEYBYTES];

    if (qgp_kem1024_keypair(kyber_pubkey, kyber_privkey) != 0) {
        fprintf(stderr, "ERROR: Failed to generate Kyber1024 keypair\n");
        return 1;
    }

    if (qgp_dsa87_keypair(dilithium_pubkey, dilithium_privkey) != 0) {
        fprintf(stderr, "ERROR: Failed to generate Dilithium5 keypair\n");
        return 1;
    }

    printf("  ✓ Kyber1024 keypair generated\n");
    printf("  ✓ Dilithium5 keypair generated\n\n");

    // Step 2: Create DNA context
    printf("[2/5] Creating DNA context...\n");
    dna_context_t *ctx = dna_context_new();
    if (!ctx) {
        fprintf(stderr, "ERROR: Failed to create DNA context\n");
        return 1;
    }
    printf("  ✓ DNA context created\n\n");

    // Step 3: Prepare test data
    printf("[3/5] Preparing test message...\n");
    const char *plaintext = "Hello, this is a test message for v0.08 timestamp encryption!";
    size_t plaintext_len = strlen(plaintext);
    uint64_t original_timestamp = (uint64_t)time(NULL) - 3600;  // 1 hour ago for testing

    printf("  Plaintext: \"%s\"\n", plaintext);
    printf("  Timestamp: %lu (Unix epoch)\n", (unsigned long)original_timestamp);

    struct tm *tm_info = localtime((time_t*)&original_timestamp);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    printf("  Human readable: %s\n\n", time_str);

    // Step 4: Encrypt with timestamp
    printf("[4/5] Encrypting message (v0.08 format)...\n");
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;

    dna_error_t enc_result = dna_encrypt_message_raw(
        ctx,
        (const uint8_t*)plaintext,
        plaintext_len,
        kyber_pubkey,
        dilithium_pubkey,
        dilithium_privkey,
        original_timestamp,  // v0.08: encrypted timestamp
        &ciphertext,
        &ciphertext_len
    );

    if (enc_result != DNA_OK) {
        fprintf(stderr, "ERROR: Encryption failed: %s\n", dna_error_string(enc_result));
        dna_context_free(ctx);
        return 1;
    }

    printf("  ✓ Encryption successful\n");
    printf("  Ciphertext size: %zu bytes\n\n", ciphertext_len);

    // Step 5: Decrypt and verify timestamp
    printf("[5/5] Decrypting and verifying timestamp...\n");
    uint8_t *decrypted = NULL;
    size_t decrypted_len = 0;
    uint8_t *sender_pubkey = NULL;
    size_t sender_pubkey_len = 0;
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    uint64_t extracted_timestamp = 0;

    dna_error_t dec_result = dna_decrypt_message_raw(
        ctx,
        ciphertext,
        ciphertext_len,
        kyber_privkey,
        &decrypted,
        &decrypted_len,
        &sender_pubkey,
        &sender_pubkey_len,
        &signature,
        &signature_len,
        &extracted_timestamp  // v0.08: extract timestamp
    );

    if (dec_result != DNA_OK) {
        fprintf(stderr, "ERROR: Decryption failed: %s\n", dna_error_string(dec_result));
        free(ciphertext);
        dna_context_free(ctx);
        return 1;
    }

    printf("  ✓ Decryption successful\n");
    printf("  Decrypted: \"%.*s\"\n", (int)decrypted_len, decrypted);
    printf("  Extracted timestamp: %lu\n", (unsigned long)extracted_timestamp);

    // Verify timestamp matches
    if (extracted_timestamp != original_timestamp) {
        fprintf(stderr, "\n❌ FAIL: Timestamp mismatch!\n");
        fprintf(stderr, "   Expected: %lu\n", (unsigned long)original_timestamp);
        fprintf(stderr, "   Got: %lu\n", (unsigned long)extracted_timestamp);
        free(ciphertext);
        free(decrypted);
        free(sender_pubkey);
        free(signature);
        dna_context_free(ctx);
        return 1;
    }

    // Verify plaintext matches
    if (decrypted_len != plaintext_len || memcmp(decrypted, plaintext, plaintext_len) != 0) {
        fprintf(stderr, "\n❌ FAIL: Plaintext mismatch!\n");
        free(ciphertext);
        free(decrypted);
        free(sender_pubkey);
        free(signature);
        dna_context_free(ctx);
        return 1;
    }

    printf("\n✅ SUCCESS: All checks passed!\n");
    printf("   ✓ Timestamp correctly encrypted\n");
    printf("   ✓ Timestamp correctly decrypted\n");
    printf("   ✓ Timestamp value matches (%lu)\n", (unsigned long)original_timestamp);
    printf("   ✓ Plaintext integrity preserved\n");

    // Cleanup
    free(ciphertext);
    free(decrypted);
    free(sender_pubkey);
    free(signature);
    dna_context_free(ctx);

    printf("\n=== Test completed successfully ===\n");
    return 0;
}
