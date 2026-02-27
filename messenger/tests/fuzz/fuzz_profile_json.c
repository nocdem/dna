/**
 * @file fuzz_profile_json.c
 * @brief libFuzzer harness for profile JSON parsing
 *
 * Fuzzes the manual JSON parsing logic used in dht_profile.c.
 * Since the actual parsing functions are static, we duplicate
 * the json_get_string logic here for testing.
 *
 * This tests common JSON parsing vulnerabilities:
 * - Buffer overflows from long values
 * - Escape sequence handling
 * - Missing quotes or delimiters
 * - Null bytes in strings
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/**
 * Copy of json_get_string from dht_profile.c for fuzzing
 * Extracts a string value from JSON by key name
 */
static int json_get_string_fuzz(const char *json, const char *key, char *out, size_t out_size) {
    if (!json || !key || !out || out_size == 0) {
        return 0;
    }

    char search[128];
    int len = snprintf(search, sizeof(search), "\"%s\":", key);
    if (len < 0 || (size_t)len >= sizeof(search)) {
        return 0;
    }

    const char *pos = strstr(json, search);
    if (!pos) {
        return 0;
    }

    pos += strlen(search);

    /* Skip whitespace */
    while (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r') {
        pos++;
    }

    if (*pos != '"') {
        return 0;
    }
    pos++;

    size_t i = 0;
    while (*pos && *pos != '"' && i < out_size - 1) {
        if (*pos == '\\' && *(pos + 1)) {
            pos++;  /* Skip escape character */
        }
        out[i++] = *pos++;
    }
    out[i] = '\0';

    return 1;
}

/**
 * Copy of json_get_uint64 from dht_profile.c for fuzzing
 */
static int json_get_uint64_fuzz(const char *json, const char *key, uint64_t *out) {
    if (!json || !key || !out) {
        return 0;
    }

    char search[128];
    int len = snprintf(search, sizeof(search), "\"%s\":", key);
    if (len < 0 || (size_t)len >= sizeof(search)) {
        return 0;
    }

    const char *pos = strstr(json, search);
    if (!pos) {
        return 0;
    }

    pos += strlen(search);

    /* Skip whitespace */
    while (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r') {
        pos++;
    }

    char *endptr;
    *out = strtoull(pos, &endptr, 10);

    return (endptr != pos) ? 1 : 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 32768) {
        return 0;
    }

    /* Null-terminate the input (JSON needs it) */
    char *json = malloc(size + 1);
    if (!json) {
        return 0;
    }
    memcpy(json, data, size);
    json[size] = '\0';

    /* Test string extraction with various field names */
    char value[512];
    json_get_string_fuzz(json, "display_name", value, sizeof(value));
    json_get_string_fuzz(json, "bio", value, sizeof(value));
    json_get_string_fuzz(json, "avatar_hash", value, sizeof(value));
    json_get_string_fuzz(json, "location", value, sizeof(value));
    json_get_string_fuzz(json, "website", value, sizeof(value));

    /* Test uint64 extraction */
    uint64_t num;
    json_get_uint64_fuzz(json, "created_at", &num);
    json_get_uint64_fuzz(json, "updated_at", &num);

    free(json);
    return 0;
}
