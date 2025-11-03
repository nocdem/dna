/**
 * DHT-based Keyserver Implementation
 * Decentralized public key storage and lookup
 *
 * Architecture:
 * - Public keys stored in DHT (distributed, permanent)
 * - Self-signed keys with Dilithium3 signatures
 * - Versioned updates (signature required)
 *
 * DHT Key Format: SHA256(identity + ":pubkey")
 */

#include "dht_keyserver.h"
#include "dht_context.h"
#include "../qgp_dilithium.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <json-c/json.h>

#ifdef _WIN32
    #include <winsock2.h>
    // Windows doesn't have htonll/ntohll, define them
    #define htonll(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFF)) << 32) | htonl((x) >> 32))
    #define ntohll(x) htonll(x)
#else
    #include <arpa/inet.h>
    // Define htonll/ntohll if not available
    #ifndef htonll
        #define htonll(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFF)) << 32) | htonl((x) >> 32))
        #define ntohll(x) htonll(x)
    #endif
#endif

// Helper function: Compute DHT storage key
static void compute_dht_key(const char *identity, char *key_out) {
    // Format: SHA256(identity + ":pubkey")
    char buffer[512];
    snprintf(buffer, sizeof(buffer), "%s:pubkey", identity);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)buffer, strlen(buffer), hash);

    // Convert to hex string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(key_out + (i * 2), "%02x", hash[i]);
    }
    key_out[SHA256_DIGEST_LENGTH * 2] = '\0';
}

// Helper function: Compute fingerprint of dilithium pubkey
static void compute_fingerprint(const uint8_t *dilithium_pubkey, char *fingerprint_out) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE, hash);

    // Convert to hex string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(fingerprint_out + (i * 2), "%02x", hash[i]);
    }
    fingerprint_out[SHA256_DIGEST_LENGTH * 2] = '\0';
}

// Helper function: Serialize entry to JSON
static char* serialize_entry(const dht_pubkey_entry_t *entry) {
    json_object *root = json_object_new_object();

    // Identity
    json_object_object_add(root, "identity", json_object_new_string(entry->identity));

    // Dilithium pubkey (base64 encode)
    // For simplicity, we'll store as hex string
    char dilithium_hex[DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE * 2 + 1];
    for (int i = 0; i < DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE; i++) {
        sprintf(dilithium_hex + (i * 2), "%02x", entry->dilithium_pubkey[i]);
    }
    dilithium_hex[DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE * 2] = '\0';
    json_object_object_add(root, "dilithium_pubkey", json_object_new_string(dilithium_hex));

    // Kyber pubkey (hex string)
    char kyber_hex[DHT_KEYSERVER_KYBER_PUBKEY_SIZE * 2 + 1];
    for (int i = 0; i < DHT_KEYSERVER_KYBER_PUBKEY_SIZE; i++) {
        sprintf(kyber_hex + (i * 2), "%02x", entry->kyber_pubkey[i]);
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
        sprintf(sig_hex + (i * 2), "%02x", entry->signature[i]);
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
static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t bytes_len) {
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
static int deserialize_entry(const char *json_str, dht_pubkey_entry_t *entry) {
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
static int sign_entry(dht_pubkey_entry_t *entry, const uint8_t *dilithium_privkey) {
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

    int ret = qgp_dilithium3_signature(entry->signature, &siglen, msg, msg_len, dilithium_privkey);

    free(msg);
    return ret;
}

// Helper function: Verify entry signature
static int verify_entry(const dht_pubkey_entry_t *entry) {
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
    int ret = qgp_dilithium3_verify(entry->signature, DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE,
                                     msg, msg_len, entry->dilithium_pubkey);

    free(msg);
    return ret;
}

// Publish public keys to DHT
int dht_keyserver_publish(
    dht_context_t *dht_ctx,
    const char *identity,
    const uint8_t *dilithium_pubkey,
    const uint8_t *kyber_pubkey,
    const uint8_t *dilithium_privkey
) {
    if (!dht_ctx || !identity || !dilithium_pubkey || !kyber_pubkey || !dilithium_privkey) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments\n");
        return -1;
    }

    // Build entry
    dht_pubkey_entry_t entry = {0};
    strncpy(entry.identity, identity, sizeof(entry.identity) - 1);
    memcpy(entry.dilithium_pubkey, dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    memcpy(entry.kyber_pubkey, kyber_pubkey, DHT_KEYSERVER_KYBER_PUBKEY_SIZE);
    entry.timestamp = time(NULL);
    entry.version = 1;  // Initial version

    // Compute fingerprint
    compute_fingerprint(dilithium_pubkey, entry.fingerprint);

    // Sign entry
    if (sign_entry(&entry, dilithium_privkey) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to sign entry\n");
        return -1;
    }

    // Serialize to JSON
    char *json = serialize_entry(&entry);
    if (!json) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to serialize entry\n");
        return -1;
    }

    // Compute DHT key
    char dht_key[65];
    compute_dht_key(identity, dht_key);

    // Store in DHT (permanent, no expiry)
    printf("[DHT_KEYSERVER] Publishing keys for identity '%s' to DHT\n", identity);
    printf("[DHT_KEYSERVER] DHT key: %s\n", dht_key);
    printf("[DHT_KEYSERVER] Fingerprint: %s\n", entry.fingerprint);

    int ret = dht_put(dht_ctx, (uint8_t*)dht_key, strlen(dht_key),
                      (uint8_t*)json, strlen(json));

    free(json);

    if (ret != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to store in DHT\n");
        return -1;
    }

    // Publish SIGNED reverse mapping (fingerprint → identity) for unknown sender lookup
    // This allows looking up identity from Dilithium pubkey fingerprint
    // Entry is signed to prevent identity spoofing attacks

    printf("[DHT_KEYSERVER_DEBUG] Starting reverse mapping publish\n");

    // Build message to sign: dilithium_pubkey || identity || timestamp
    size_t reverse_msg_len = DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE + strlen(identity) + sizeof(uint64_t);
    uint8_t *reverse_msg = malloc(reverse_msg_len);
    if (!reverse_msg) {
        fprintf(stderr, "[DHT_KEYSERVER] Warning: Failed to allocate reverse mapping message\n");
    } else {
        printf("[DHT_KEYSERVER_DEBUG] Allocated reverse_msg (%zu bytes)\n", reverse_msg_len);
        size_t offset = 0;
        memcpy(reverse_msg + offset, dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
        offset += DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE;
        memcpy(reverse_msg + offset, identity, strlen(identity));
        offset += strlen(identity);

        // Network byte order for cross-platform compatibility
        uint64_t timestamp_net = htonll(entry.timestamp);
        memcpy(reverse_msg + offset, &timestamp_net, sizeof(timestamp_net));

        // Sign reverse mapping
        uint8_t reverse_signature[DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE];
        size_t reverse_siglen = DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE;

        printf("[DHT_KEYSERVER_DEBUG] Signing reverse mapping message...\n");
        int sign_result = qgp_dilithium3_signature(reverse_signature, &reverse_siglen,
                                      reverse_msg, reverse_msg_len, dilithium_privkey);
        printf("[DHT_KEYSERVER_DEBUG] Signature result: %d, siglen: %zu\n", sign_result, reverse_siglen);

        if (sign_result != 0) {
            fprintf(stderr, "[DHT_KEYSERVER] Warning: Failed to sign reverse mapping\n");
            free(reverse_msg);
        } else {
            free(reverse_msg);
            printf("[DHT_KEYSERVER_DEBUG] Reverse mapping signature succeeded, building JSON...\n");

            // Build reverse mapping entry
            json_object *reverse_obj = json_object_new_object();
            if (!reverse_obj) {
                fprintf(stderr, "[DHT_KEYSERVER] Warning: Failed to create JSON object for reverse mapping\n");
                return 0;  // Non-critical, forward mapping already published
            }
            printf("[DHT_KEYSERVER_DEBUG] Created JSON object for reverse mapping\n");

            // Store dilithium pubkey (needed for signature verification)
            char dilithium_hex[DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE * 2 + 1];
            for (int i = 0; i < DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE; i++) {
                sprintf(dilithium_hex + (i * 2), "%02x", dilithium_pubkey[i]);
            }
            dilithium_hex[DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE * 2] = '\0';

            json_object_object_add(reverse_obj, "dilithium_pubkey", json_object_new_string(dilithium_hex));
            json_object_object_add(reverse_obj, "identity", json_object_new_string(identity));
            json_object_object_add(reverse_obj, "timestamp", json_object_new_int64(entry.timestamp));
            json_object_object_add(reverse_obj, "fingerprint", json_object_new_string(entry.fingerprint));

            // Store signature
            char sig_hex[DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE * 2 + 1];
            for (int i = 0; i < DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE; i++) {
                sprintf(sig_hex + (i * 2), "%02x", reverse_signature[i]);
            }
            sig_hex[DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE * 2] = '\0';
            json_object_object_add(reverse_obj, "signature", json_object_new_string(sig_hex));

            const char *reverse_json_str = json_object_to_json_string(reverse_obj);
            char *reverse_json = strdup(reverse_json_str);
            json_object_put(reverse_obj);

            // Compute DHT key for reverse lookup
            char reverse_key_input[128];
            snprintf(reverse_key_input, sizeof(reverse_key_input), "%s:reverse", entry.fingerprint);

            unsigned char reverse_hash[SHA256_DIGEST_LENGTH];
            SHA256((unsigned char*)reverse_key_input, strlen(reverse_key_input), reverse_hash);

            char reverse_dht_key[65];
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                sprintf(reverse_dht_key + (i * 2), "%02x", reverse_hash[i]);
            }
            reverse_dht_key[SHA256_DIGEST_LENGTH * 2] = '\0';

            printf("[DHT_KEYSERVER] Publishing signed reverse mapping (fingerprint → identity)\n");
            printf("[DHT_KEYSERVER] Reverse key: %s\n", reverse_dht_key);

            ret = dht_put(dht_ctx, (uint8_t*)reverse_dht_key, strlen(reverse_dht_key),
                          (uint8_t*)reverse_json, strlen(reverse_json));

            free(reverse_json);

            if (ret != 0) {
                fprintf(stderr, "[DHT_KEYSERVER] Warning: Failed to store reverse mapping (non-critical)\n");
            } else {
                printf("[DHT_KEYSERVER] ✓ Signed reverse mapping published\n");
            }
        }
    }

    printf("[DHT_KEYSERVER] ✓ Keys published successfully\n");
    return 0;
}

// Lookup public keys from DHT
int dht_keyserver_lookup(
    dht_context_t *dht_ctx,
    const char *identity,
    dht_pubkey_entry_t **entry_out
) {
    if (!dht_ctx || !identity || !entry_out) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments\n");
        return -1;
    }

    // Compute DHT key
    char dht_key[65];
    compute_dht_key(identity, dht_key);

    // Fetch from DHT
    printf("[DHT_KEYSERVER] Looking up identity '%s' from DHT\n", identity);
    printf("[DHT_KEYSERVER] DHT key: %s\n", dht_key);

    uint8_t *data = NULL;
    size_t data_len = 0;
    int ret = dht_get(dht_ctx, (uint8_t*)dht_key, strlen(dht_key), &data, &data_len);

    if (ret != 0 || !data) {
        fprintf(stderr, "[DHT_KEYSERVER] Identity not found in DHT\n");
        return -2;  // Not found
    }

    // Parse JSON
    dht_pubkey_entry_t *entry = malloc(sizeof(dht_pubkey_entry_t));
    if (!entry) {
        free(data);
        return -1;
    }

    if (deserialize_entry((char*)data, entry) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to parse entry\n");
        free(data);
        free(entry);
        return -1;
    }

    free(data);

    // Verify signature
    if (verify_entry(entry) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Signature verification failed\n");
        free(entry);
        return -3;  // Signature verification failed
    }

    printf("[DHT_KEYSERVER] ✓ Keys retrieved and verified\n");
    printf("[DHT_KEYSERVER] Fingerprint: %s\n", entry->fingerprint);
    printf("[DHT_KEYSERVER] Version: %u\n", entry->version);

    *entry_out = entry;
    return 0;
}

// Reverse lookup: fingerprint → identity (with signature verification)
int dht_keyserver_reverse_lookup(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    char **identity_out
) {
    if (!dht_ctx || !fingerprint || !identity_out) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments to reverse_lookup\n");
        return -1;
    }

    *identity_out = NULL;

    // Compute DHT key: SHA256(fingerprint + ":reverse")
    char reverse_key_input[128];
    snprintf(reverse_key_input, sizeof(reverse_key_input), "%s:reverse", fingerprint);

    unsigned char reverse_hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)reverse_key_input, strlen(reverse_key_input), reverse_hash);

    char reverse_dht_key[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(reverse_dht_key + (i * 2), "%02x", reverse_hash[i]);
    }
    reverse_dht_key[SHA256_DIGEST_LENGTH * 2] = '\0';

    printf("[DHT_KEYSERVER] Reverse lookup for fingerprint: %s\n", fingerprint);
    printf("[DHT_KEYSERVER] Reverse DHT key: %s\n", reverse_dht_key);

    // Fetch from DHT
    uint8_t *value = NULL;
    size_t value_len = 0;

    if (dht_get(dht_ctx, (uint8_t*)reverse_dht_key, strlen(reverse_dht_key),
                &value, &value_len) != 0 || !value) {
        printf("[DHT_KEYSERVER] Reverse mapping not found in DHT\n");
        return -2;  // Not found
    }

    // Parse JSON
    json_object *root = json_tokener_parse((char*)value);
    free(value);

    if (!root) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to parse reverse mapping JSON\n");
        return -1;
    }

    // Extract fields
    json_object *dilithium_obj, *identity_obj, *timestamp_obj, *fingerprint_obj, *signature_obj;

    if (!json_object_object_get_ex(root, "dilithium_pubkey", &dilithium_obj) ||
        !json_object_object_get_ex(root, "identity", &identity_obj) ||
        !json_object_object_get_ex(root, "timestamp", &timestamp_obj) ||
        !json_object_object_get_ex(root, "fingerprint", &fingerprint_obj) ||
        !json_object_object_get_ex(root, "signature", &signature_obj)) {
        fprintf(stderr, "[DHT_KEYSERVER] Reverse mapping missing required fields\n");
        json_object_put(root);
        return -1;
    }

    // Parse dilithium pubkey
    const char *dilithium_hex = json_object_get_string(dilithium_obj);
    uint8_t dilithium_pubkey[DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE];
    if (hex_to_bytes(dilithium_hex, dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid dilithium pubkey in reverse mapping\n");
        json_object_put(root);
        return -1;
    }

    // Verify fingerprint matches (prevents pubkey substitution)
    char computed_fingerprint[65];
    compute_fingerprint(dilithium_pubkey, computed_fingerprint);

    if (strcmp(computed_fingerprint, fingerprint) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Fingerprint mismatch in reverse mapping\n");
        json_object_put(root);
        return -3;  // Signature verification failed (invalid data)
    }

    const char *identity = json_object_get_string(identity_obj);
    uint64_t timestamp = json_object_get_int64(timestamp_obj);

    // Parse signature
    const char *sig_hex = json_object_get_string(signature_obj);
    uint8_t signature[DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE];
    if (hex_to_bytes(sig_hex, signature, DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid signature in reverse mapping\n");
        json_object_put(root);
        return -1;
    }

    // Rebuild message to verify: dilithium_pubkey || identity || timestamp
    size_t msg_len = DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE + strlen(identity) + sizeof(uint64_t);
    uint8_t *msg = malloc(msg_len);
    if (!msg) {
        json_object_put(root);
        return -1;
    }

    size_t offset = 0;
    memcpy(msg + offset, dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    offset += DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE;
    memcpy(msg + offset, identity, strlen(identity));
    offset += strlen(identity);

    // Network byte order
    uint64_t timestamp_net = htonll(timestamp);
    memcpy(msg + offset, &timestamp_net, sizeof(timestamp_net));

    // Verify signature
    int verify_result = qgp_dilithium3_verify(signature, DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE,
                                               msg, msg_len, dilithium_pubkey);
    free(msg);

    if (verify_result != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Reverse mapping signature verification failed\n");
        json_object_put(root);
        return -3;  // Signature verification failed
    }

    // All checks passed - return identity
    *identity_out = strdup(identity);
    printf("[DHT_KEYSERVER] ✓ Reverse lookup successful: %s\n", identity);

    json_object_put(root);
    return 0;
}

// Update public keys in DHT
int dht_keyserver_update(
    dht_context_t *dht_ctx,
    const char *identity,
    const uint8_t *new_dilithium_pubkey,
    const uint8_t *new_kyber_pubkey,
    const uint8_t *new_dilithium_privkey
) {
    if (!dht_ctx || !identity || !new_dilithium_pubkey || !new_kyber_pubkey || !new_dilithium_privkey) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments\n");
        return -1;
    }

    // Fetch existing entry to get version
    dht_pubkey_entry_t *old_entry = NULL;
    int ret = dht_keyserver_lookup(dht_ctx, identity, &old_entry);

    uint32_t new_version = 1;
    if (ret == 0 && old_entry) {
        // Increment version
        new_version = old_entry->version + 1;
        dht_keyserver_free_entry(old_entry);
    }

    // Build new entry
    dht_pubkey_entry_t entry = {0};
    strncpy(entry.identity, identity, sizeof(entry.identity) - 1);
    memcpy(entry.dilithium_pubkey, new_dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    memcpy(entry.kyber_pubkey, new_kyber_pubkey, DHT_KEYSERVER_KYBER_PUBKEY_SIZE);
    entry.timestamp = time(NULL);
    entry.version = new_version;

    // Compute fingerprint
    compute_fingerprint(new_dilithium_pubkey, entry.fingerprint);

    // Sign with NEW private key
    if (sign_entry(&entry, new_dilithium_privkey) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to sign entry\n");
        return -1;
    }

    // Serialize to JSON
    char *json = serialize_entry(&entry);
    if (!json) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to serialize entry\n");
        return -1;
    }

    // Compute DHT key
    char dht_key[65];
    compute_dht_key(identity, dht_key);

    // Store in DHT (overwrites old entry)
    printf("[DHT_KEYSERVER] Updating keys for identity '%s'\n", identity);
    printf("[DHT_KEYSERVER] New version: %u\n", new_version);
    printf("[DHT_KEYSERVER] New fingerprint: %s\n", entry.fingerprint);

    ret = dht_put(dht_ctx, (uint8_t*)dht_key, strlen(dht_key),
                  (uint8_t*)json, strlen(json));

    free(json);

    if (ret != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to update in DHT\n");
        return -1;
    }

    printf("[DHT_KEYSERVER] ✓ Keys updated successfully\n");
    return 0;
}

// Delete public keys from DHT
int dht_keyserver_delete(
    dht_context_t *dht_ctx,
    const char *identity
) {
    if (!dht_ctx || !identity) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments\n");
        return -1;
    }

    // Compute DHT key
    char dht_key[65];
    compute_dht_key(identity, dht_key);

    // Note: DHT doesn't support true deletion, but we can try to overwrite with tombstone
    // For now, just return success (keys will expire naturally if DHT implementation supports it)
    printf("[DHT_KEYSERVER] Delete not fully supported by DHT (keys remain until natural expiry)\n");

    return 0;
}

// Free public key entry
void dht_keyserver_free_entry(dht_pubkey_entry_t *entry) {
    if (entry) {
        free(entry);
    }
}
