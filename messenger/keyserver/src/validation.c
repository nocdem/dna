/*
 * Request Validation
 */

#include "validation.h"
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdlib.h>

bool validate_handle(const char *handle) {
    if (!handle) return false;

    size_t len = strlen(handle);
    if (len < MIN_HANDLE_LENGTH || len > MAX_HANDLE_LENGTH) {
        return false;
    }

    // Only alphanumeric and underscore
    for (size_t i = 0; i < len; i++) {
        if (!isalnum(handle[i]) && handle[i] != '_') {
            return false;
        }
    }

    return true;
}

bool validate_device(const char *device) {
    // Same rules as handle
    return validate_handle(device);
}

bool validate_inbox_key(const char *inbox_key) {
    if (!inbox_key) return false;

    if (strlen(inbox_key) != INBOX_KEY_HEX_LENGTH) {
        return false;
    }

    // Check all hex chars
    for (size_t i = 0; i < INBOX_KEY_HEX_LENGTH; i++) {
        if (!isxdigit(inbox_key[i])) {
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

    // Check handle
    if (!json_object_object_get_ex(payload, "handle", &field)) {
        snprintf(error_msg, error_len, "Missing field: handle");
        return -1;
    }
    const char *handle = json_object_get_string(field);
    if (!validate_handle(handle)) {
        snprintf(error_msg, error_len, "Invalid handle format");
        return -1;
    }

    // Check device
    if (!json_object_object_get_ex(payload, "device", &field)) {
        snprintf(error_msg, error_len, "Missing field: device");
        return -1;
    }
    const char *device = json_object_get_string(field);
    if (!validate_device(device)) {
        snprintf(error_msg, error_len, "Invalid device format");
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

    // Check inbox_key
    if (!json_object_object_get_ex(payload, "inbox_key", &field)) {
        snprintf(error_msg, error_len, "Missing field: inbox_key");
        return -1;
    }
    const char *inbox_key = json_object_get_string(field);
    if (!validate_inbox_key(inbox_key)) {
        snprintf(error_msg, error_len, "Invalid inbox_key format");
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
