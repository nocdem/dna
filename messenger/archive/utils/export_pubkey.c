/*
 * export_pubkey - Export public key from PQKEY file as base64
 *
 * Usage: export_pubkey <key_path>
 * Output: base64-encoded public key to stdout
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qgp_dilithium.h"
#include "qgp_types.h"

// Simple base64 encoding
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* base64_encode(const uint8_t *data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = malloc(out_len + 1);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len;) {
        uint32_t octet_a = i < len ? data[i++] : 0;
        uint32_t octet_b = i < len ? data[i++] : 0;
        uint32_t octet_c = i < len ? data[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        out[j++] = base64_chars[(triple >> 18) & 0x3F];
        out[j++] = base64_chars[(triple >> 12) & 0x3F];
        out[j++] = base64_chars[(triple >> 6) & 0x3F];
        out[j++] = base64_chars[triple & 0x3F];
    }

    // Add padding
    size_t mod = len % 3;
    if (mod == 1) {
        out[out_len - 2] = '=';
        out[out_len - 1] = '=';
    } else if (mod == 2) {
        out[out_len - 1] = '=';
    }

    out[out_len] = '\0';
    return out;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <key_path>\n", argv[0]);
        fprintf(stderr, "Example: %s ~/.dna/nocdem.dsa\n", argv[0]);
        return 1;
    }

    const char *key_path = argv[1];

    // Load key
    qgp_key_t *key = NULL;
    if (qgp_key_load(key_path, &key) != 0 || !key) {
        fprintf(stderr, "Error: Failed to load key: %s\n", key_path);
        return 1;
    }

    if (!key->public_key || key->public_key_size == 0) {
        fprintf(stderr, "Error: No public key in file\n");
        qgp_key_free(key);
        return 1;
    }

    // Base64 encode public key
    char *pubkey_b64 = base64_encode(key->public_key, key->public_key_size);
    if (!pubkey_b64) {
        fprintf(stderr, "Error: Base64 encoding failed\n");
        qgp_key_free(key);
        return 1;
    }

    // Output to stdout
    printf("%s\n", pubkey_b64);

    free(pubkey_b64);
    qgp_key_free(key);
    return 0;
}
