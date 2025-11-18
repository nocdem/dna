/**
 * DHT Keyserver Helper Functions
 * Shared utilities used by all keyserver modules
 */

#include "keyserver_core.h"

// Helper function: Validate fingerprint format (128 hex chars)
bool is_valid_fingerprint(const char *str) {
    if (!str || strlen(str) != 128) {
        return false;
    }
    for (int i = 0; i < 128; i++) {
        if (!isxdigit(str[i])) {
            return false;
        }
    }
    return true;
}

// Helper function: Compute DHT storage key using SHA3-512 (fingerprint-based)
void compute_dht_key_by_fingerprint(const char *fingerprint, char *key_out) {
    // Format: SHA3-512(fingerprint + ":pubkey") - 128 hex chars
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "%s:pubkey", fingerprint);

    unsigned char hash[64];  // SHA3-512 = 64 bytes
    if (qgp_sha3_512((unsigned char*)buffer, strlen(buffer), hash) != 0) {
        // Fallback: just clear the output
        key_out[0] = '\0';
        return;
    }

    // Convert to hex string (128 chars)
    for (int i = 0; i < 64; i++) {
        snprintf(key_out + (i * 2), 3, "%02x", hash[i]);
    }
    key_out[128] = '\0';
}

// Helper function: Compute DHT storage key using SHA3-512 (name-based, for alias lookup)
void compute_dht_key_by_name(const char *name, char *key_out) {
    // Format: SHA3-512(name + ":lookup") - 128 hex chars
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "%s:lookup", name);

    unsigned char hash[64];  // SHA3-512 = 64 bytes
    if (qgp_sha3_512((unsigned char*)buffer, strlen(buffer), hash) != 0) {
        // Fallback: just clear the output
        key_out[0] = '\0';
        return;
    }

    // Convert to hex string (128 chars)
    for (int i = 0; i < 64; i++) {
        snprintf(key_out + (i * 2), 3, "%02x", hash[i]);
    }
    key_out[128] = '\0';
}

// Helper function: Compute SHA3-512 fingerprint of dilithium pubkey
void compute_fingerprint(const uint8_t *dilithium_pubkey, char *fingerprint_out) {
    unsigned char hash[64];  // SHA3-512 = 64 bytes
    if (qgp_sha3_512(dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE, hash) != 0) {
        // Fallback: clear output
        fingerprint_out[0] = '\0';
        return;
    }

    // Convert to hex string (128 chars)
    for (int i = 0; i < 64; i++) {
        snprintf(fingerprint_out + (i * 2), 3, "%02x", hash[i]);
    }
    fingerprint_out[128] = '\0';
}

// Helper function: Serialize entry to JSON
char* serialize_entry(const dht_pubkey_entry_t *entry) {
    json_object *root = json_object_new_object();

    // Identity
    json_object_object_add(root, "identity", json_object_new_string(entry->identity));

    // Dilithium pubkey (base64 encode)
    // For simplicity, we'll store as hex string
    char dilithium_hex[DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE * 2 + 1];
    for (int i = 0; i < DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE; i++) {
        snprintf(dilithium_hex + (i * 2), 3, "%02x", entry->dilithium_pubkey[i]);
    }
    dilithium_hex[DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE * 2] = '\0';
    json_object_object_add(root, "dilithium_pubkey", json_object_new_string(dilithium_hex));

    // Kyber pubkey (hex string)
    char kyber_hex[DHT_KEYSERVER_KYBER_PUBKEY_SIZE * 2 + 1];
    for (int i = 0; i < DHT_KEYSERVER_KYBER_PUBKEY_SIZE; i++) {
        snprintf(kyber_hex + (i * 2), 3, "%02x", entry->kyber_pubkey[i]);
    }
    kyber_hex[DHT_KEYSERVER_KYBER_PUBKEY_SIZE * 2] = '\0';
    json_object_object_add(root, "kyber_pubkey", json_object_new_string(kyber_hex));

    // Timestamp
    json_object_object_add(root, "timestamp", json_object_new_int64(entry->timestamp));

    // Version
    json_object_object_add(root, "version", json_object_new_int(entry->version));

    // Fingerprint
    json_object_object_add(root, "fingerprint", json_object_new_string(entry->fingerprint));

    // Signature (hex string)
    char sig_hex[DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE * 2 + 1];
    for (int i = 0; i < DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE; i++) {
        snprintf(sig_hex + (i * 2), 3, "%02x", entry->signature[i]);
    }
    sig_hex[DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE * 2] = '\0';
    json_object_object_add(root, "signature", json_object_new_string(sig_hex));

    // Serialize to string
    const char *json_str = json_object_to_json_string(root);
    char *result = strdup(json_str);

    json_object_put(root);
    return result;
}

// Helper function: Parse hex string to bytes
int hex_to_bytes(const char *hex, uint8_t *bytes, size_t bytes_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != bytes_len * 2) {
        return -1;
    }

    for (size_t i = 0; i < bytes_len; i++) {
        unsigned int byte;
        if (sscanf(hex + (i * 2), "%02x", &byte) != 1) {
            return -1;
        }
        bytes[i] = (uint8_t)byte;
    }

    return 0;
}

// Helper function: Deserialize JSON to entry
int deserialize_entry(const char *json_str, dht_pubkey_entry_t *entry) {
    json_object *root = json_tokener_parse(json_str);
    if (!root) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to parse JSON\n");
        return -1;
    }

    // Identity
    json_object *identity_obj;
    if (!json_object_object_get_ex(root, "identity", &identity_obj)) {
        json_object_put(root);
        return -1;
    }
    strncpy(entry->identity, json_object_get_string(identity_obj), sizeof(entry->identity) - 1);
    entry->identity[sizeof(entry->identity) - 1] = '\0';  // Ensure null termination

    // Dilithium pubkey
    json_object *dilithium_obj;
    if (!json_object_object_get_ex(root, "dilithium_pubkey", &dilithium_obj)) {
        json_object_put(root);
        return -1;
    }
    const char *dilithium_hex = json_object_get_string(dilithium_obj);
    if (hex_to_bytes(dilithium_hex, entry->dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE) != 0) {
        json_object_put(root);
        return -1;
    }

    // Kyber pubkey
    json_object *kyber_obj;
    if (!json_object_object_get_ex(root, "kyber_pubkey", &kyber_obj)) {
        json_object_put(root);
        return -1;
    }
    const char *kyber_hex = json_object_get_string(kyber_obj);
    if (hex_to_bytes(kyber_hex, entry->kyber_pubkey, DHT_KEYSERVER_KYBER_PUBKEY_SIZE) != 0) {
        json_object_put(root);
        return -1;
    }

    // Timestamp
    json_object *timestamp_obj;
    if (!json_object_object_get_ex(root, "timestamp", &timestamp_obj)) {
        json_object_put(root);
        return -1;
    }
    entry->timestamp = json_object_get_int64(timestamp_obj);

    // Version
    json_object *version_obj;
    if (!json_object_object_get_ex(root, "version", &version_obj)) {
        json_object_put(root);
        return -1;
    }
    entry->version = json_object_get_int(version_obj);

    // Fingerprint
    json_object *fingerprint_obj;
    if (!json_object_object_get_ex(root, "fingerprint", &fingerprint_obj)) {
        json_object_put(root);
        return -1;
    }
    strncpy(entry->fingerprint, json_object_get_string(fingerprint_obj), sizeof(entry->fingerprint) - 1);
    entry->fingerprint[sizeof(entry->fingerprint) - 1] = '\0';  // Ensure null termination

    // Signature
    json_object *signature_obj;
    if (!json_object_object_get_ex(root, "signature", &signature_obj)) {
        json_object_put(root);
        return -1;
    }
    const char *sig_hex = json_object_get_string(signature_obj);
    if (hex_to_bytes(sig_hex, entry->signature, DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE) != 0) {
        json_object_put(root);
        return -1;
    }

    json_object_put(root);
    return 0;
}

// Helper function: Create signature for entry
int sign_entry(dht_pubkey_entry_t *entry, const uint8_t *dilithium_privkey) {
    // Sign the entry data (everything except signature itself)
    // Message to sign: identity + dilithium_pubkey + kyber_pubkey + timestamp + version + fingerprint

    size_t msg_len = strlen(entry->identity) +
                     DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE +
                     DHT_KEYSERVER_KYBER_PUBKEY_SIZE +
                     sizeof(entry->timestamp) +
                     sizeof(entry->version) +
                     strlen(entry->fingerprint);

    uint8_t *msg = malloc(msg_len);
    if (!msg) {
        return -1;
    }

    // Build message to sign
    size_t offset = 0;
    memcpy(msg + offset, entry->identity, strlen(entry->identity));
    offset += strlen(entry->identity);
    memcpy(msg + offset, entry->dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    offset += DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE;
    memcpy(msg + offset, entry->kyber_pubkey, DHT_KEYSERVER_KYBER_PUBKEY_SIZE);
    offset += DHT_KEYSERVER_KYBER_PUBKEY_SIZE;

    // Convert to network byte order for cross-platform compatibility
    uint64_t timestamp_net = htonll(entry->timestamp);
    uint32_t version_net = htonl(entry->version);

    memcpy(msg + offset, &timestamp_net, sizeof(timestamp_net));
    offset += sizeof(timestamp_net);
    memcpy(msg + offset, &version_net, sizeof(version_net));
    offset += sizeof(version_net);
    memcpy(msg + offset, entry->fingerprint, strlen(entry->fingerprint));

    // Sign
    size_t siglen = DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE;

    // DEBUG: Print first 32 bytes of message for debugging
    printf("[DHT_KEYSERVER_DEBUG] Signing message (%zu bytes), first 32 bytes:\n  ", msg_len);
    for (int i = 0; i < 32 && i < msg_len; i++) {
        printf("%02x", msg[i]);
    }
    printf("\n");

    int ret = qgp_dsa87_sign(entry->signature, &siglen, msg, msg_len, dilithium_privkey);

    free(msg);
    return ret;
}

// Helper function: Verify entry signature
int verify_entry(const dht_pubkey_entry_t *entry) {
    // Rebuild message (same as sign_entry)
    size_t msg_len = strlen(entry->identity) +
                     DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE +
                     DHT_KEYSERVER_KYBER_PUBKEY_SIZE +
                     sizeof(entry->timestamp) +
                     sizeof(entry->version) +
                     strlen(entry->fingerprint);

    uint8_t *msg = malloc(msg_len);
    if (!msg) {
        return -1;
    }

    // Build message
    size_t offset = 0;
    memcpy(msg + offset, entry->identity, strlen(entry->identity));
    offset += strlen(entry->identity);
    memcpy(msg + offset, entry->dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    offset += DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE;
    memcpy(msg + offset, entry->kyber_pubkey, DHT_KEYSERVER_KYBER_PUBKEY_SIZE);
    offset += DHT_KEYSERVER_KYBER_PUBKEY_SIZE;

    // Convert to network byte order for cross-platform compatibility (same as sign_entry)
    uint64_t timestamp_net = htonll(entry->timestamp);
    uint32_t version_net = htonl(entry->version);

    memcpy(msg + offset, &timestamp_net, sizeof(timestamp_net));
    offset += sizeof(timestamp_net);
    memcpy(msg + offset, &version_net, sizeof(version_net));
    offset += sizeof(version_net);
    memcpy(msg + offset, entry->fingerprint, strlen(entry->fingerprint));

    // DEBUG: Print first 32 bytes of message for debugging
    printf("[DHT_KEYSERVER_DEBUG] Verifying message (%zu bytes), first 32 bytes:\n  ", msg_len);
    for (int i = 0; i < 32 && i < msg_len; i++) {
        printf("%02x", msg[i]);
    }
    printf("\n");

    // Verify signature with dilithium pubkey
    int ret = qgp_dsa87_verify(entry->signature, DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE,
                                     msg, msg_len, entry->dilithium_pubkey);

    free(msg);
    return ret;
}
