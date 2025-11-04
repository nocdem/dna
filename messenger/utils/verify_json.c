/*
 * verify_json - Verify JSON signature with Dilithium5 public key
 *
 * Usage: verify_json <json_string> <signature_b64> <pubkey_b64>
 * Output: "VALID" or "INVALID" to stdout
 * Exit code: 0 if valid, 1 if invalid, 2 if error
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qgp_dilithium.h"
#include "qgp_types.h"

// Simple base64 decoding
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -1;  // Padding
    return -2;  // Invalid
}

uint8_t* base64_decode(const char *input, size_t *output_len) {
    size_t input_len = strlen(input);
    if (input_len % 4 != 0) {
        return NULL;  // Invalid base64
    }

    size_t max_output_len = (input_len / 4) * 3;
    uint8_t *output = malloc(max_output_len);
    if (!output) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < input_len; i += 4) {
        int v1 = base64_char_value(input[i]);
        int v2 = base64_char_value(input[i + 1]);
        int v3 = base64_char_value(input[i + 2]);
        int v4 = base64_char_value(input[i + 3]);

        if (v1 < 0 || v2 < 0) {
            free(output);
            return NULL;
        }

        output[j++] = (v1 << 2) | (v2 >> 4);

        if (v3 >= 0) {
            output[j++] = ((v2 & 0x0F) << 4) | (v3 >> 2);
        }

        if (v4 >= 0) {
            output[j++] = ((v3 & 0x03) << 6) | v4;
        }
    }

    *output_len = j;
    return output;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <json_string> <signature_b64> <pubkey_b64>\n", argv[0]);
        fprintf(stderr, "Example: %s '{\"v\":1}' '<sig>' '<pk>'\n", argv[0]);
        return 2;
    }

    const char *json_str = argv[1];
    const char *sig_b64 = argv[2];
    const char *pubkey_b64 = argv[3];

    // Decode signature
    size_t sig_len;
    uint8_t *signature = base64_decode(sig_b64, &sig_len);
    if (!signature) {
        fprintf(stderr, "Error: Invalid signature base64\n");
        return 2;
    }

    if (sig_len != QGP_DILITHIUM3_BYTES) {
        fprintf(stderr, "Error: Invalid signature length (%zu, expected %d)\n",
                sig_len, QGP_DILITHIUM3_BYTES);
        free(signature);
        return 2;
    }

    // Decode public key
    size_t pubkey_len;
    uint8_t *pubkey = base64_decode(pubkey_b64, &pubkey_len);
    if (!pubkey) {
        fprintf(stderr, "Error: Invalid public key base64\n");
        free(signature);
        return 2;
    }

    if (pubkey_len != QGP_DILITHIUM3_PUBLICKEYBYTES) {
        fprintf(stderr, "Error: Invalid public key length (%zu, expected %d)\n",
                pubkey_len, QGP_DILITHIUM3_PUBLICKEYBYTES);
        free(signature);
        free(pubkey);
        return 2;
    }

    // Verify signature
    int result = qgp_dilithium3_verify(
        signature, sig_len,
        (const uint8_t*)json_str, strlen(json_str),
        pubkey
    );

    free(signature);
    free(pubkey);

    if (result == 0) {
        printf("VALID\n");
        return 0;
    } else {
        printf("INVALID\n");
        return 1;
    }
}
