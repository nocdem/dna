/*
 * Request Validation
 */

#include "validation.h"
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdlib.h>

bool validate_dna(const char *dna) {
    if (!dna) return false;

    size_t len = strlen(dna);
    if (len < MIN_DNA_LENGTH || len > MAX_DNA_LENGTH) {
        return false;
    }

    // Only alphanumeric and underscore
    for (size_t i = 0; i < len; i++) {
        if (!isalnum(dna[i]) && dna[i] != '_') {
            return false;
        }
    }

    return true;
}

bool validate_timestamp(int timestamp, int max_skew) {
    time_t now = time(NULL);
    int diff = abs((int)now - timestamp);

    return (diff <= max_skew);
}

bool validate_base64(const char *b64_str) {
    if (!b64_str) return false;

    size_t len = strlen(b64_str);
    if (len == 0) return false;

    // Check for valid base64 chars
    for (size_t i = 0; i < len; i++) {
        char c = b64_str[i];
        if (!isalnum(c) && c != '+' && c != '/' && c != '=') {
            return false;
        }
    }

    return true;
}

int validate_register_payload(json_object *payload, char *error_msg, size_t error_len) {
    json_object *field;

    // Check schema version
    if (!json_object_object_get_ex(payload, "v", &field)) {
        snprintf(error_msg, error_len, "Missing field: v");
        return -1;
    }
    int version = json_object_get_int(field);
    if (version != 1) {
        snprintf(error_msg, error_len, "Unsupported schema version: %d", version);
        return -1;
    }

    // Check dna
    if (!json_object_object_get_ex(payload, "dna", &field)) {
        snprintf(error_msg, error_len, "Missing field: dna");
        return -1;
    }
    const char *dna = json_object_get_string(field);
    if (!validate_dna(dna)) {
        snprintf(error_msg, error_len, "Invalid dna format");
        return -1;
    }

    // Check dilithium_pub
    if (!json_object_object_get_ex(payload, "dilithium_pub", &field)) {
        snprintf(error_msg, error_len, "Missing field: dilithium_pub");
        return -1;
    }
    const char *dil_pub = json_object_get_string(field);
    if (!validate_base64(dil_pub)) {
        snprintf(error_msg, error_len, "Invalid dilithium_pub format");
        return -1;
    }

    // Check kyber_pub
    if (!json_object_object_get_ex(payload, "kyber_pub", &field)) {
        snprintf(error_msg, error_len, "Missing field: kyber_pub");
        return -1;
    }
    const char *kyber_pub = json_object_get_string(field);
    if (!validate_base64(kyber_pub)) {
        snprintf(error_msg, error_len, "Invalid kyber_pub format");
        return -1;
    }

    // Check cf20pub (Cellframe address - can be empty)
    if (!json_object_object_get_ex(payload, "cf20pub", &field)) {
        snprintf(error_msg, error_len, "Missing field: cf20pub");
        return -1;
    }
    const char *cf20pub = json_object_get_string(field);
    if (cf20pub == NULL) {
        snprintf(error_msg, error_len, "cf20pub cannot be null");
        return -1;
    }
    // Allow empty string for now, validate format later when we use it
    size_t cf20_len = strlen(cf20pub);
    if (cf20_len > CF20_ADDRESS_LENGTH) {
        snprintf(error_msg, error_len, "cf20pub too long (max %d chars)", CF20_ADDRESS_LENGTH);
        return -1;
    }

    // Check version number
    if (!json_object_object_get_ex(payload, "version", &field)) {
        snprintf(error_msg, error_len, "Missing field: version");
        return -1;
    }
    int payload_version = json_object_get_int(field);
    if (payload_version < 1) {
        snprintf(error_msg, error_len, "Invalid version: must be >= 1");
        return -1;
    }

    // Check timestamp
    if (!json_object_object_get_ex(payload, "updated_at", &field)) {
        snprintf(error_msg, error_len, "Missing field: updated_at");
        return -1;
    }
    int timestamp = json_object_get_int(field);
    if (!validate_timestamp(timestamp, g_config.max_timestamp_skew)) {
        snprintf(error_msg, error_len, "Timestamp skew too large");
        return -1;
    }

    // Check signature
    if (!json_object_object_get_ex(payload, "sig", &field)) {
        snprintf(error_msg, error_len, "Missing field: sig");
        return -1;
    }
    const char *sig = json_object_get_string(field);
    if (!validate_base64(sig)) {
        snprintf(error_msg, error_len, "Invalid signature format");
        return -1;
    }

    return 0;
}
