/*
 * sign_json - Sign JSON string with Dilithium private key
 *
 * Usage: sign_json <identity> <json_string>
 * Output: base64-encoded signature to stdout
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
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <identity> <json_string>\n", argv[0]);
        fprintf(stderr, "Example: %s rex '{\"v\":1,\"handle\":\"rex\"}'\n", argv[0]);
        return 1;
    }

    const char *identity = argv[1];
    const char *json_str = argv[2];

    // Load Dilithium private key
    char key_path[512];
    const char *home = getenv("HOME");
    if (!home) {
        home = getenv("USERPROFILE");  // Windows fallback
        if (!home) {
            fprintf(stderr, "Error: HOME or USERPROFILE not set\n");
            return 1;
        }
    }

    snprintf(key_path, sizeof(key_path), "%s/.dna/%s.dsa", home, identity);

    qgp_key_t *key = NULL;
    if (qgp_key_load(key_path, &key) != 0 || !key) {
        fprintf(stderr, "Error: Failed to load key: %s\n", key_path);
        return 1;
    }

    if (key->type != QGP_KEY_TYPE_DSA87 || !key->private_key) {
        fprintf(stderr, "Error: Not a Dilithium private key\n");
        qgp_key_free(key);
        return 1;
    }

    // Sign the JSON string
    uint8_t signature[QGP_DSA87_SIGNATURE_BYTES];
    size_t sig_len = QGP_DSA87_SIGNATURE_BYTES;

    if (qgp_dsa87_sign(signature, &sig_len,
                                  (const uint8_t*)json_str, strlen(json_str),
                                  key->private_key) != 0) {
        fprintf(stderr, "Error: Signing failed\n");
        qgp_key_free(key);
        return 1;
    }

    // Base64 encode signature
    char *sig_b64 = base64_encode(signature, sig_len);
    if (!sig_b64) {
        fprintf(stderr, "Error: Base64 encoding failed\n");
        qgp_key_free(key);
        return 1;
    }

    // Output to stdout
    printf("%s\n", sig_b64);

    free(sig_b64);
    qgp_key_free(key);
    return 0;
}
