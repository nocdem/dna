/*
 * pqsignum - File signing
 *
 * - qgp_key_load() to load signing key (QGP format)
 * - qgp_dilithium3_signature() for Dilithium3 (vendored)
 * - Round-trip verification mandatory before saving signature
 */

#include "qgp.h"
#include "qgp_types.h"
#include "qgp_dilithium.h"

int cmd_sign_file(const char *input_file, const char *key_path, const char *output_sig) {
    qgp_key_t *sign_key = NULL;
    uint8_t *file_data = NULL;
    size_t file_size = 0;
    qgp_signature_t *signature = NULL;
    uint8_t *sig_bytes = NULL;
    size_t sig_size = 0;
    int ret = EXIT_ERROR;

    printf("Signing file...\n");
    printf("  Input file: %s\n", input_file);
    printf("  Signing key: %s\n", key_path);
    printf("  Output signature: %s\n", output_sig);

    // Check if input file exists
    if (!file_exists(input_file)) {
        fprintf(stderr, "Error: Input file not found: %s\n", input_file);
        return EXIT_ERROR;
    }

    // Check if signing key exists
    if (!file_exists(key_path)) {
        fprintf(stderr, "Error: Signing key not found: %s\n", key_path);
        return EXIT_KEY_ERROR;
    }

    // Load signing key using QGP format
    printf("Loading signing key...\n");
    if (qgp_key_load(key_path, &sign_key) != 0) {
        fprintf(stderr, "Error: Failed to load signing key\n");
        ret = EXIT_KEY_ERROR;
        goto cleanup;
    }
    printf("Signing key loaded successfully\n");

    // Read file data
    printf("Reading file...\n");
    if (read_file_data(input_file, &file_data, &file_size) != 0) {
        ret = EXIT_ERROR;
        goto cleanup;
    }
    printf("File size: %zu bytes\n", file_size);

    // Sign the file
    printf("Creating signature...\n");


    if (sign_key->type == QGP_KEY_TYPE_DILITHIUM3) {
        size_t dilithium_sig_size = QGP_DILITHIUM3_BYTES;
        size_t pkey_size = QGP_DILITHIUM3_PUBLICKEYBYTES;

        // Allocate QGP signature structure
        signature = qgp_signature_new(QGP_SIG_TYPE_DILITHIUM, pkey_size, dilithium_sig_size);
        if (!signature) {
            fprintf(stderr, "Error: Memory allocation failed for signature\n");
            ret = EXIT_ERROR;
            goto cleanup;
        }

        // Copy public key to signature data
        memcpy(qgp_signature_get_pubkey(signature), sign_key->public_key, pkey_size);

        // Create Dilithium3 signature
        size_t actual_sig_len = 0;
        if (qgp_dilithium3_signature(
                qgp_signature_get_bytes(signature),  // Output after public key
                &actual_sig_len,
                file_data, file_size,
                sign_key->private_key) != 0) {
            fprintf(stderr, "Error: Dilithium3 signature creation failed\n");
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup;
        }

        // Update signature size with actual length
        signature->signature_size = actual_sig_len;
        printf("Dilithium3 signature created (%zu bytes)\n", actual_sig_len);

        // Protocol Mode: MANDATORY round-trip verification
        printf("Performing round-trip verification...\n");
        if (qgp_dilithium3_verify(
                qgp_signature_get_bytes(signature),  // Signature after public key
                actual_sig_len,
                file_data, file_size,
                qgp_signature_get_pubkey(signature)) != 0) {  // Public key at start
            fprintf(stderr, "Error: Round-trip verification FAILED\n");
            fprintf(stderr, "Signature is invalid - will not save\n");
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup;
        }
        printf("Round-trip verification: OK\n");
    }

    // Get signature size and serialize
    sig_size = qgp_signature_get_size(signature);
    if (sig_size == 0) {
        fprintf(stderr, "Error: Failed to get signature size\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    // Serialize signature to bytes
    sig_bytes = QGP_MALLOC(sig_size);
    if (!sig_bytes) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (qgp_signature_serialize(signature, sig_bytes) == 0) {
        fprintf(stderr, "Error: Signature serialization failed\n");
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    // Write ASCII-armored signature
    printf("Writing signature...\n");

    const char *headers[10];
    size_t header_count = build_signature_headers(signature, headers, 10);

    if (write_armored_file(output_sig, "SIGNATURE",
                           sig_bytes, sig_size,
                           headers, header_count) != 0) {
        fprintf(stderr, "Error: Failed to write armored signature\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    printf("\nFile signed successfully!\n");
    printf("  ASCII-armored signature: %s\n", output_sig);
    printf("  Algorithm: %s\n", get_signature_algorithm_name(signature));

    printf("\nTo verify:\n");
    printf("  qgp --verify --file %s\n", input_file);

    ret = EXIT_SUCCESS;

cleanup:
    if (file_data) {
        free(file_data);
    }
    if (sig_bytes) {
        QGP_FREE(sig_bytes);
    }
    if (signature) {
        qgp_signature_free(signature);
    }


    if (sign_key) qgp_key_free(sign_key);

    return ret;
}
