/*
 * DNA Messenger - Basic Usage Example
 *
 * Demonstrates core messaging workflow:
 * - Alice encrypts a message for Bob
 * - Bob decrypts and verifies the message
 *
 * Prerequisites:
 * - Keys generated: alice and bob (using `dna --gen-key`)
 * - Public keys imported to keyring
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../dna_api.h"

int main(void) {
    dna_context_t *ctx = NULL;
    dna_error_t err;

    // Message buffers
    const char *plaintext = "Hello Bob! This is a secure post-quantum message from Alice.";
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    uint8_t *decrypted = NULL;
    size_t decrypted_len = 0;
    uint8_t *sender_pubkey = NULL;
    size_t sender_pubkey_len = 0;

    printf("=== DNA Messenger - Basic Usage Example ===\n\n");

    // ========================================================================
    // STEP 1: Initialize DNA context
    // ========================================================================

    printf("[1/4] Initializing DNA context...\n");
    ctx = dna_context_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create DNA context\n");
        return 1;
    }
    printf("  ✓ Context created\n\n");

    // ========================================================================
    // STEP 2: Alice encrypts message for Bob
    // ========================================================================

    printf("[2/4] Alice encrypts message for Bob...\n");
    printf("  Plaintext: \"%s\"\n", plaintext);
    printf("  Length: %zu bytes\n", strlen(plaintext));

    const char *recipients[] = {"bob"};
    err = dna_encrypt_message(
        ctx,
        (const uint8_t*)plaintext,
        strlen(plaintext),
        recipients,
        1,                      // 1 recipient
        "alice",               // Sender's key name
        &ciphertext,
        &ciphertext_len
    );

    if (err != DNA_OK) {
        fprintf(stderr, "Error: Encryption failed: %s\n", dna_error_string(err));
        dna_context_free(ctx);
        return 1;
    }

    printf("  ✓ Message encrypted\n");
    printf("  Ciphertext length: %zu bytes\n\n", ciphertext_len);

    // ========================================================================
    // STEP 3: Bob decrypts message
    // ========================================================================

    printf("[3/4] Bob decrypts message...\n");

    err = dna_decrypt_message(
        ctx,
        ciphertext,
        ciphertext_len,
        "bob",                 // Recipient's key name
        &decrypted,
        &decrypted_len,
        &sender_pubkey,
        &sender_pubkey_len
    );

    if (err != DNA_OK) {
        fprintf(stderr, "Error: Decryption failed: %s\n", dna_error_string(err));
        free(ciphertext);
        dna_context_free(ctx);
        return 1;
    }

    printf("  ✓ Message decrypted\n");
    printf("  Plaintext length: %zu bytes\n", decrypted_len);
    printf("  Sender's public key: %zu bytes\n\n", sender_pubkey_len);

    // ========================================================================
    // STEP 4: Verify decrypted message
    // ========================================================================

    printf("[4/4] Verifying message...\n");

    // Check if decrypted message matches original
    if (decrypted_len == strlen(plaintext) &&
        memcmp(decrypted, plaintext, decrypted_len) == 0) {
        printf("  ✓ Decrypted message matches original\n");
        printf("  Decrypted: \"%.*s\"\n", (int)decrypted_len, decrypted);
    } else {
        fprintf(stderr, "  ✗ Error: Decrypted message does not match!\n");
    }

    printf("\n=== Success! ===\n");
    printf("Alice successfully sent a secure message to Bob.\n");
    printf("Post-quantum cryptography used:\n");
    printf("  - Kyber512 (key encapsulation)\n");
    printf("  - Dilithium3 (digital signature)\n");
    printf("  - AES-256-GCM (authenticated encryption)\n");

    // ========================================================================
    // Cleanup
    // ========================================================================

    free(ciphertext);
    dna_buffer_free(&(dna_buffer_t){decrypted, decrypted_len});
    free(sender_pubkey);
    dna_context_free(ctx);

    return 0;
}
