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

#define KEYSERVER_URL "https://cpunk.io/api/keyserver/register"

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

    snprintf(key_path, sizeof(key_path), "%s/.dna/%s-%s.pqkey", home, identity, key_type);

    // Use export_pubkey utility - try multiple paths
    char cmd[1024];
#ifdef _WIN32
    // Windows: try paths one by one (no shell || operator)
    snprintf(cmd, sizeof(cmd), "..\\utils\\export_pubkey.exe \"%s\" 2>nul", key_path);
#else
    // Linux: use shell || to try multiple paths
    snprintf(cmd, sizeof(cmd),
             "(../utils/export_pubkey \"%s\" 2>/dev/null || ./utils/export_pubkey \"%s\" 2>/dev/null || utils/export_pubkey \"%s\" 2>/dev/null)",
             key_path, key_path, key_path);
#endif

    printf("DEBUG: Running command: %s\n", cmd);
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;

    char *pubkey = malloc(10000);
    if (!pubkey) {
        pclose(fp);
        return NULL;
    }

    if (!fgets(pubkey, 10000, fp)) {
        pclose(fp);
        free(pubkey);
        return NULL;
    }

    // Remove trailing newline
    pubkey[strcspn(pubkey, "\n")] = 0;
    pclose(fp);

    if (strlen(pubkey) == 0) {
        free(pubkey);
        return NULL;
    }

    return pubkey;
}

/**
 * Sign JSON string with Dilithium private key
 */
static char* sign_json(const char *identity, const char *json_str) {
    char cmd[40000];  // Large buffer for long JSON
#ifdef _WIN32
    // Windows: use cmd.exe compatible syntax
    snprintf(cmd, sizeof(cmd), "..\\utils\\sign_json.exe \"%s\" \"%s\" 2>nul", identity, json_str);
#else
    // Linux: use shell || to try multiple paths
    snprintf(cmd, sizeof(cmd),
             "(../utils/sign_json '%s' '%s' 2>/dev/null || ./utils/sign_json '%s' '%s' 2>/dev/null || utils/sign_json '%s' '%s' 2>/dev/null)",
             identity, json_str, identity, json_str, identity, json_str);
#endif

    printf("DEBUG: Running command: %s\n", cmd);
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;

    static char signature[10000];
    if (!fgets(signature, sizeof(signature), fp)) {
        pclose(fp);
        return NULL;
    }

    // Remove trailing newline
    signature[strcspn(signature, "\n")] = 0;
    pclose(fp);

    return strlen(signature) > 0 ? signature : NULL;
}

/**
 * Register current user to keyserver
 */
int register_to_keyserver(const char *identity) {
    printf("\n=== Keyserver Registration ===\n\n");
    printf("Registering '%s' to keyserver...\n", identity);

    // Export public keys
    printf("Exporting public keys...\n");
    char *dilithium_pub = export_pubkey(identity, "dilithium");
    if (!dilithium_pub) {
        fprintf(stderr, "Error: Failed to export Dilithium public key\n");
        return -1;
    }

    char *kyber_pub = export_pubkey(identity, "kyber512");
    if (!kyber_pub) {
        fprintf(stderr, "Error: Failed to export Kyber public key\n");
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
