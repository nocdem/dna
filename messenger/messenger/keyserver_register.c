/*
 * Keyserver Registration
 * Register current user's public keys to the keyserver
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <io.h>
#define popen _popen
#define pclose _pclose
#else
#include <unistd.h>
#endif
#include <json-c/json.h>
#include "qgp_types.h"
#include "qgp_dilithium.h"

#define KEYSERVER_URL "https://cpunk.io/api/keyserver/register"

// Base64 encoding table
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Base64 encode binary data
 * Returns malloc'd string that must be freed by caller
 */
static char* base64_encode(const uint8_t *data, size_t len) {
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

/**
 * Export public key from pqkey file as base64
 * Returns malloc'd string that must be freed by caller
 */
static char* export_pubkey(const char *identity, const char *key_type) {
    char key_path[512];
    const char *home = getenv("HOME");
    if (!home) {
        home = getenv("USERPROFILE");  // Windows fallback
        if (!home) return NULL;
    }

    // Map key_type to extension (dsa → .dsa, kem → .kem)
    const char *ext = (strcmp(key_type, "dsa") == 0) ? "dsa" : "kem";
    snprintf(key_path, sizeof(key_path), "%s/.dna/%s.%s", home, identity, ext);

    // Load key directly
    qgp_key_t *key = NULL;
    if (qgp_key_load(key_path, &key) != 0 || !key) {
        fprintf(stderr, "Error: Failed to load key: %s\n", key_path);
        return NULL;
    }

    if (!key->public_key || key->public_key_size == 0) {
        fprintf(stderr, "Error: No public key in file\n");
        qgp_key_free(key);
        return NULL;
    }

    // Base64 encode public key
    char *pubkey_b64 = base64_encode(key->public_key, key->public_key_size);
    qgp_key_free(key);

    if (!pubkey_b64) {
        fprintf(stderr, "Error: Base64 encoding failed\n");
        return NULL;
    }

    return pubkey_b64;
}

/**
 * Sign JSON string with Dilithium private key
 * Returns malloc'd base64-encoded signature string that must be freed by caller
 */
static char* sign_json(const char *identity, const char *json_str) {
    char key_path[512];
    const char *home = getenv("HOME");
    if (!home) {
        home = getenv("USERPROFILE");  // Windows fallback
        if (!home) return NULL;
    }

    snprintf(key_path, sizeof(key_path), "%s/.dna/%s.dsa", home, identity);

    // Load Dilithium private key
    qgp_key_t *key = NULL;
    if (qgp_key_load(key_path, &key) != 0 || !key) {
        fprintf(stderr, "Error: Failed to load key: %s\n", key_path);
        return NULL;
    }

    if (key->type != QGP_KEY_TYPE_DSA87 || !key->private_key) {
        fprintf(stderr, "Error: Not a Dilithium private key\n");
        qgp_key_free(key);
        return NULL;
    }

    // Sign the JSON string
    uint8_t signature[QGP_DSA87_SIGNATURE_BYTES];
    size_t sig_len = QGP_DSA87_SIGNATURE_BYTES;

    if (qgp_dsa87_sign(signature, &sig_len,
                                  (const uint8_t*)json_str, strlen(json_str),
                                  key->private_key) != 0) {
        fprintf(stderr, "Error: Signing failed\n");
        qgp_key_free(key);
        return NULL;
    }

    qgp_key_free(key);

    // Base64 encode signature
    char *sig_b64 = base64_encode(signature, sig_len);
    if (!sig_b64) {
        fprintf(stderr, "Error: Base64 encoding failed\n");
        return NULL;
    }

    return sig_b64;
}

/**
 * Register current user to keyserver
 */
int register_to_keyserver(const char *identity) {
    printf("\n=== Keyserver Registration ===\n\n");
    printf("Registering '%s' to keyserver...\n", identity);

    // Export public keys
    printf("Exporting public keys...\n");
    char *dilithium_pub = export_pubkey(identity, "dsa");
    if (!dilithium_pub) {
        fprintf(stderr, "Error: Failed to export DSA-87 public key\n");
        return -1;
    }

    char *kyber_pub = export_pubkey(identity, "kem");
    if (!kyber_pub) {
        fprintf(stderr, "Error: Failed to export KEM-1024 public key\n");
        return -1;
    }

    // Build JSON payload using json-c (same as keyserver)
    int updated_at = (int)time(NULL);

    json_object *payload = json_object_new_object();
    json_object_object_add(payload, "v", json_object_new_int(1));
    json_object_object_add(payload, "dna", json_object_new_string(identity));
    json_object_object_add(payload, "dilithium_pub", json_object_new_string(dilithium_pub));
    json_object_object_add(payload, "kyber_pub", json_object_new_string(kyber_pub));
    json_object_object_add(payload, "cf20pub", json_object_new_string(""));
    json_object_object_add(payload, "version", json_object_new_int(1));
    json_object_object_add(payload, "updated_at", json_object_new_int(updated_at));

    // Get canonical JSON string (PLAIN + NOSLASHESCAPE - same as keyserver)
    const char *json_payload = json_object_to_json_string_ext(payload,
        JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);

    // Sign the payload
    printf("Signing payload...\n");
    char *signature = sign_json(identity, json_payload);
    if (!signature) {
        fprintf(stderr, "Error: Failed to sign payload\n");
        json_object_put(payload);
        return -1;
    }

    // Add signature to payload
    json_object_object_add(payload, "sig", json_object_new_string(signature));

    // Free signature (json-c made a copy)
    free(signature);

    // Get final JSON with signature
    const char *final_json = json_object_to_json_string_ext(payload,
        JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);

    // Save to temp file for curl
#ifdef _WIN32
    char temp_file[512];
    if (tmpnam_s(temp_file, sizeof(temp_file)) != 0) {
        fprintf(stderr, "Error: Failed to create temp filename\n");
        json_object_put(payload);
        return -1;
    }
    FILE *fp = fopen(temp_file, "w");
#else
    char temp_file[] = "/tmp/dna_register_XXXXXX";
    int fd = mkstemp(temp_file);
    if (fd == -1) {
        fprintf(stderr, "Error: Failed to create temp file\n");
        json_object_put(payload);
        return -1;
    }
    FILE *fp = fdopen(fd, "w");
#endif
    if (!fp) {
#ifndef _WIN32
        close(fd);
#endif
        fprintf(stderr, "Error: Failed to open temp file\n");
        json_object_put(payload);
        return -1;
    }

    fprintf(fp, "%s", final_json);
    fclose(fp);

    json_object_put(payload);

    // Free exported keys
    free(dilithium_pub);
    free(kyber_pub);

    // POST to keyserver using curl
    printf("Posting to keyserver...\n");
    char curl_cmd[1024];
    snprintf(curl_cmd, sizeof(curl_cmd),
             "curl -s -X POST \"%s\" "
             "-H \"Content-Type: application/json\" "
             "-d @\"%s\"",
             KEYSERVER_URL, temp_file);

    FILE *curl_fp = popen(curl_cmd, "r");
    if (!curl_fp) {
        unlink(temp_file);
        fprintf(stderr, "Error: Failed to execute curl\n");
        return -1;
    }

    // Read response
    char response[4096];
    size_t response_len = fread(response, 1, sizeof(response) - 1, curl_fp);
    response[response_len] = '\0';
    pclose(curl_fp);
    unlink(temp_file);

    // Check if response contains "success":true
    if (strstr(response, "\"success\":true")) {
        printf("\n✓ Successfully registered to keyserver!\n");
        printf("✓ Identity: %s\n", identity);
        printf("✓ Endpoint: %s\n\n", KEYSERVER_URL);
        printf("Response: %s\n\n", response);
        return 0;
    } else {
        printf("\n✗ Registration failed\n");
        printf("Response: %s\n\n", response);
        return -1;
    }
}
