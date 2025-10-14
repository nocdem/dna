/*
 * QGP AES-256-GCM Encryption (AEAD)
 *
 * OpenSSL-based AES-256-GCM implementation providing authenticated encryption.
 */

#include "qgp_aes.h"
#include "qgp_random.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/**
 * Calculate required buffer size for AES-256-GCM encryption
 *
 * GCM is a stream cipher - no padding required.
 * Ciphertext is exact same size as plaintext.
 */
size_t qgp_aes256_encrypt_size(size_t plaintext_len) {
    // GCM: exact plaintext length (no padding)
    // Nonce (12 bytes) and tag (16 bytes) stored separately
    return plaintext_len;
}

/**
 * Encrypt data with AES-256-GCM
 *
 * Uses OpenSSL EVP interface for AES-256-GCM with AAD support.
 * Generates random 12-byte nonce and 16-byte authentication tag.
 */
int qgp_aes256_encrypt(const uint8_t *key,
                       const uint8_t *plaintext, size_t plaintext_len,
                       const uint8_t *aad, size_t aad_len,
                       uint8_t *ciphertext, size_t *ciphertext_len,
                       uint8_t *nonce,
                       uint8_t *tag) {
    if (!key || !plaintext || !ciphertext || !ciphertext_len || !nonce || !tag) {
        fprintf(stderr, "qgp_aes256_encrypt: NULL parameter\n");
        return -1;
    }

    if (plaintext_len == 0) {
        fprintf(stderr, "qgp_aes256_encrypt: Empty plaintext\n");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    int ciphertext_len_tmp = 0;
    int ret = -1;

    // Generate random 12-byte nonce (GCM standard)
    if (qgp_randombytes(nonce, 12) != 0) {
        fprintf(stderr, "qgp_aes256_encrypt: Failed to generate nonce\n");
        goto cleanup;
    }

    // Create and initialize context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "qgp_aes256_encrypt: Failed to create context\n");
        goto cleanup;
    }

    // Initialize encryption: AES-256-GCM
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
        fprintf(stderr, "qgp_aes256_encrypt: EVP_EncryptInit_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // Set AAD (Additional Authenticated Data) - if provided
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            fprintf(stderr, "qgp_aes256_encrypt: Failed to set AAD\n");
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }
    }

    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "qgp_aes256_encrypt: EVP_EncryptUpdate failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    ciphertext_len_tmp = len;

    // Finalize encryption (GCM has no padding, so this just finalizes)
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        fprintf(stderr, "qgp_aes256_encrypt: EVP_EncryptFinal_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    ciphertext_len_tmp += len;

    // Get authentication tag (16 bytes)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        fprintf(stderr, "qgp_aes256_encrypt: Failed to get GCM tag\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    *ciphertext_len = ciphertext_len_tmp;
    ret = 0;

cleanup:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

    return ret;
}

/**
 * Decrypt data with AES-256-GCM
 *
 * Uses OpenSSL EVP interface for AES-256-GCM with AAD verification.
 * Verifies authentication tag before returning plaintext.
 * Returns error if tag verification fails (tampered data).
 */
int qgp_aes256_decrypt(const uint8_t *key,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *nonce,
                       const uint8_t *tag,
                       uint8_t *plaintext, size_t *plaintext_len) {
    if (!key || !ciphertext || !nonce || !tag || !plaintext || !plaintext_len) {
        fprintf(stderr, "qgp_aes256_decrypt: NULL parameter\n");
        return -1;
    }

    if (ciphertext_len == 0) {
        fprintf(stderr, "qgp_aes256_decrypt: Empty ciphertext\n");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    int plaintext_len_tmp = 0;
    int ret = -1;

    // Create and initialize context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "qgp_aes256_decrypt: Failed to create context\n");
        goto cleanup;
    }

    // Initialize decryption: AES-256-GCM
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
        fprintf(stderr, "qgp_aes256_decrypt: EVP_DecryptInit_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // Set AAD (must match encryption AAD)
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            fprintf(stderr, "qgp_aes256_decrypt: Failed to set AAD\n");
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }
    }

    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "qgp_aes256_decrypt: EVP_DecryptUpdate failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    plaintext_len_tmp = len;

    // Set expected authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        fprintf(stderr, "qgp_aes256_decrypt: Failed to set GCM tag\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // Finalize decryption (verifies authentication tag)
    // This will FAIL if:
    // - Tag doesn't match (ciphertext tampered)
    // - AAD doesn't match (metadata tampered)
    // - Wrong key/nonce
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        // Authentication failed - data was tampered with
        fprintf(stderr, "qgp_aes256_decrypt: Authentication failed (tag verification failed)\n");
        fprintf(stderr, "Ciphertext or AAD has been tampered with\n");

        // Wipe partial plaintext (it's invalid)
        memset(plaintext, 0, plaintext_len_tmp);

        goto cleanup;
    }
    plaintext_len_tmp += len;

    *plaintext_len = plaintext_len_tmp;
    ret = 0;

cleanup:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

    return ret;
}
