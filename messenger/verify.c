/*
 * pqsignum - Signature verification
 *
 * - qgp_dilithium3_verify() for Dilithium3 (vendored)
 * - Uses QGP's own signature format
 */

#include "qgp.h"
#include "qgp_types.h"
#include "qgp_dilithium.h"

int cmd_verify_file(const char *input_file, const char *sig_file) {
    uint8_t *file_data = NULL;
    size_t file_size = 0;
    uint8_t *sig_data = NULL;
    size_t sig_size = 0;
    qgp_signature_t *signature = NULL;
    int ret = EXIT_ERROR;

    printf("Verifying signature...\n");
    printf("  File: %s\n", input_file);
    printf("  Signature: %s\n", sig_file);

    // Check if input file exists
    if (!file_exists(input_file)) {
        fprintf(stderr, "Error: Input file not found: %s\n", input_file);
        return EXIT_ERROR;
    }

    // Check if signature file exists
    if (!file_exists(sig_file)) {
        fprintf(stderr, "Error: Signature file not found: %s\n", sig_file);
        return EXIT_ERROR;
    }

    // Read file data
    printf("Reading file...\n");
    if (read_file_data(input_file, &file_data, &file_size) != 0) {
        ret = EXIT_ERROR;
        goto cleanup;
    }
    printf("File size: %zu bytes\n", file_size);

    // Read signature data (auto-detect format)
    printf("Reading signature...\n");

    if (is_armored_file(sig_file)) {
        // ASCII-armored format
        printf("Detected ASCII-armored signature\n");
        char *type = NULL;
        char **headers = NULL;
        size_t header_count = 0;

        if (read_armored_file(sig_file, &type, &sig_data, &sig_size,
                             &headers, &header_count) != 0) {
            fprintf(stderr, "Error: Failed to read armored signature\n");
            ret = EXIT_ERROR;
            goto cleanup;
        }

        // Verify type
        if (strcmp(type, "SIGNATURE") != 0) {
            fprintf(stderr, "Error: Not a signature file (type: %s)\n", type);
            free(type);
            for (size_t i = 0; i < header_count; i++) {
                free(headers[i]);
            }
            free(headers);
            ret = EXIT_ERROR;
            goto cleanup;
        }

        // Print headers
        for (size_t i = 0; i < header_count; i++) {
            printf("  %s\n", headers[i]);
            free(headers[i]);
        }

        free(type);
        free(headers);
    } else {
        // Binary format
        printf("Detected binary signature\n");
        if (read_file_data(sig_file, &sig_data, &sig_size) != 0) {
            ret = EXIT_ERROR;
            goto cleanup;
        }
    }

    printf("Signature size: %zu bytes\n", sig_size);

    // Deserialize QGP signature structure
    printf("Parsing signature...\n");
    if (qgp_signature_deserialize(sig_data, sig_size, &signature) != 0) {
        fprintf(stderr, "Error: Invalid signature structure\n");
        fprintf(stderr, "Signature file may be corrupted\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Get signature info
    const char *type_name = NULL;
    switch (signature->type) {
        case QGP_SIG_TYPE_DILITHIUM:
            type_name = "Dilithium (ML-DSA)";
            break;
        default:
            type_name = "Unknown";
            break;
    }
    printf("Signature algorithm: %s\n", type_name);

    // Verify signature
    printf("Verifying signature...\n");
    int verify_result = -1;


    if (signature->type == QGP_SIG_TYPE_DILITHIUM) {
        // Extract public key and signature from qgp_signature_t structure
        uint8_t *pub_key = qgp_signature_get_pubkey(signature);
        uint8_t *sig = qgp_signature_get_bytes(signature);
        size_t sig_len = signature->signature_size;

        // Verify using Dilithium3 directly
        verify_result = qgp_dilithium3_verify(
            sig, sig_len,
            file_data, file_size,
            pub_key
        );
    } else {
        // QGP only supports Dilithium3 signatures
        fprintf(stderr, "Error: Unsupported signature algorithm\n");
        fprintf(stderr, "QGP only supports Dilithium3 (ML-DSA-65) signatures\n");
        verify_result = -1;
    }

    if (verify_result == 0) {  // 0 = success
        printf("\n");
        printf("========================================\n");
        printf("  GOOD SIGNATURE\n");
        printf("========================================\n");
        printf("\n");
        printf("The signature is valid.\n");
        printf("The file has not been modified since it was signed.\n");
        ret = EXIT_SUCCESS;
    } else {
        printf("\n");
        printf("========================================\n");
        printf("  BAD SIGNATURE\n");
        printf("========================================\n");
        printf("\n");
        fprintf(stderr, "ERROR: Signature verification FAILED\n");
        fprintf(stderr, "The file may have been modified or the signature is invalid.\n");
        ret = 1; // Exit code 1 for bad signature (like gpg)
    }

cleanup:
    if (file_data) {
        free(file_data);
    }
    if (sig_data) {
        free(sig_data);
    }
    if (signature) {
        qgp_signature_free(signature);
    }

    return ret;
}
