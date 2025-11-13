/**
 * DHT-based Keyserver Implementation
 * Decentralized public key storage and lookup
 *
 * Architecture:
 * - Public keys stored in DHT (distributed, permanent)
 * - Self-signed keys with Dilithium5 signatures (Category 5)
 * - Versioned updates (signature required)
 *
 * DHT Key Format: SHA3-512(identity + ":pubkey") - 128 hex chars
 */

#include "dht_keyserver.h"
#include "dht_context.h"
#include "../qgp_dilithium.h"
#include "../qgp_sha3.h"
#include "../cellframe_rpc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <openssl/evp.h>
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

// Helper function: Validate fingerprint format (128 hex chars)
static bool is_valid_fingerprint(const char *str) {
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
static void compute_dht_key_by_fingerprint(const char *fingerprint, char *key_out) {
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
        sprintf(key_out + (i * 2), "%02x", hash[i]);
    }
    key_out[128] = '\0';
}

// Helper function: Compute DHT storage key using SHA3-512 (name-based, for alias lookup)
static void compute_dht_key_by_name(const char *name, char *key_out) {
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
        sprintf(key_out + (i * 2), "%02x", hash[i]);
    }
    key_out[128] = '\0';
}

// Helper function: Compute SHA3-512 fingerprint of dilithium pubkey
static void compute_fingerprint(const uint8_t *dilithium_pubkey, char *fingerprint_out) {
    unsigned char hash[64];  // SHA3-512 = 64 bytes
    if (qgp_sha3_512(dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE, hash) != 0) {
        // Fallback: clear output
        fingerprint_out[0] = '\0';
        return;
    }

    // Convert to hex string (128 chars)
    for (int i = 0; i < 64; i++) {
        sprintf(fingerprint_out + (i * 2), "%02x", hash[i]);
    }
    fingerprint_out[128] = '\0';
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

    int ret = qgp_dsa87_sign(entry->signature, &siglen, msg, msg_len, dilithium_privkey);

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
    int ret = qgp_dsa87_verify(entry->signature, DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE,
                                     msg, msg_len, entry->dilithium_pubkey);

    free(msg);
    return ret;
}

// Publish public keys to DHT (FINGERPRINT-FIRST architecture)
int dht_keyserver_publish(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const char *display_name,  // Optional human-readable name
    const uint8_t *dilithium_pubkey,
    const uint8_t *kyber_pubkey,
    const uint8_t *dilithium_privkey
) {
    printf("[DEBUG PUBLISH] dht_keyserver_publish() called for: %.16s... (name: %s)\n",
           fingerprint, display_name ? display_name : "(none)");

    if (!dht_ctx || !fingerprint || !dilithium_pubkey || !kyber_pubkey || !dilithium_privkey) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments\n");
        return -1;
    }

    // Validate fingerprint format
    if (!is_valid_fingerprint(fingerprint)) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid fingerprint format (expected 128 hex chars)\n");
        return -1;
    }

    // Build entry
    dht_pubkey_entry_t entry = {0};

    // Store display name (or fingerprint if no name provided)
    if (display_name && strlen(display_name) > 0) {
        strncpy(entry.identity, display_name, sizeof(entry.identity) - 1);
    } else {
        strncpy(entry.identity, fingerprint, sizeof(entry.identity) - 1);
    }

    memcpy(entry.dilithium_pubkey, dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    memcpy(entry.kyber_pubkey, kyber_pubkey, DHT_KEYSERVER_KYBER_PUBKEY_SIZE);
    entry.timestamp = time(NULL);
    entry.version = 1;  // Initial version

    // Store fingerprint (should match computed one)
    strncpy(entry.fingerprint, fingerprint, sizeof(entry.fingerprint) - 1);

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

    // Compute DHT key FROM FINGERPRINT (primary key)
    char dht_key[129];
    compute_dht_key_by_fingerprint(fingerprint, dht_key);

    // Store in DHT (permanent, signed with fixed value_id=1 to prevent accumulation)
    printf("[DHT_KEYSERVER] Publishing keys for fingerprint '%s' to DHT\n", fingerprint);
    if (display_name && strlen(display_name) > 0) {
        printf("[DHT_KEYSERVER] Display name: %s\n", display_name);
    }
    printf("[DHT_KEYSERVER] DHT key: %s\n", dht_key);

    int ret = dht_put_signed_permanent(dht_ctx, (uint8_t*)dht_key, strlen(dht_key),
                                        (uint8_t*)json, strlen(json), 1);

    free(json);

    if (ret != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to store in DHT\n");
        return -1;
    }

    // Publish SIGNED reverse mapping (fingerprint → identity) for unknown sender lookup
    // This allows looking up identity from Dilithium pubkey fingerprint
    // Entry is signed to prevent identity spoofing attacks

    printf("[DHT_KEYSERVER_DEBUG] Starting reverse mapping publish\n");

    // Build message to sign: dilithium_pubkey || display_name || timestamp
    // Use display_name for reverse mapping (or fingerprint if no name)
    const char *name_for_reverse = (display_name && strlen(display_name) > 0) ? display_name : fingerprint;
    size_t reverse_msg_len = DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE + strlen(name_for_reverse) + sizeof(uint64_t);
    uint8_t *reverse_msg = malloc(reverse_msg_len);
    if (!reverse_msg) {
        fprintf(stderr, "[DHT_KEYSERVER] Warning: Failed to allocate reverse mapping message\n");
    } else {
        printf("[DHT_KEYSERVER_DEBUG] Allocated reverse_msg (%zu bytes)\n", reverse_msg_len);
        size_t offset = 0;
        memcpy(reverse_msg + offset, dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
        offset += DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE;
        memcpy(reverse_msg + offset, name_for_reverse, strlen(name_for_reverse));
        offset += strlen(name_for_reverse);

        // Network byte order for cross-platform compatibility
        uint64_t timestamp_net = htonll(entry.timestamp);
        memcpy(reverse_msg + offset, &timestamp_net, sizeof(timestamp_net));

        // Sign reverse mapping
        uint8_t reverse_signature[DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE];
        size_t reverse_siglen = DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE;

        printf("[DHT_KEYSERVER_DEBUG] Signing reverse mapping message...\n");
        int sign_result = qgp_dsa87_sign(reverse_signature, &reverse_siglen,
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
            json_object_object_add(reverse_obj, "identity", json_object_new_string(name_for_reverse));
            json_object_object_add(reverse_obj, "timestamp", json_object_new_int64(entry.timestamp));
            json_object_object_add(reverse_obj, "fingerprint", json_object_new_string(fingerprint));

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

            // Compute DHT key for reverse lookup using SHA3-512
            char reverse_key_input[256];
            snprintf(reverse_key_input, sizeof(reverse_key_input), "%s:reverse", entry.fingerprint);

            unsigned char reverse_hash[64];  // SHA3-512 = 64 bytes
            if (qgp_sha3_512((unsigned char*)reverse_key_input, strlen(reverse_key_input), reverse_hash) != 0) {
                fprintf(stderr, "[DHT_KEYSERVER] Failed to compute reverse DHT key\n");
                free(reverse_json);
                return ret;  // Still return success for main publish
            }

            char reverse_dht_key[129];
            for (int i = 0; i < 64; i++) {
                sprintf(reverse_dht_key + (i * 2), "%02x", reverse_hash[i]);
            }
            reverse_dht_key[128] = '\0';

            printf("[DHT_KEYSERVER] Publishing signed reverse mapping (fingerprint → identity)\n");
            printf("[DHT_KEYSERVER] Reverse key: %s\n", reverse_dht_key);

            unsigned int ttl_365_days = 365 * 24 * 3600;
            ret = dht_put_signed(dht_ctx, (uint8_t*)reverse_dht_key, strlen(reverse_dht_key),
                                 (uint8_t*)reverse_json, strlen(reverse_json), 1, ttl_365_days);

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

// Publish name → fingerprint alias (for name-based lookups)
int dht_keyserver_publish_alias(
    dht_context_t *dht_ctx,
    const char *name,
    const char *fingerprint
) {
    if (!dht_ctx || !name || !fingerprint) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments to publish_alias\n");
        return -1;
    }

    // Validate name (3-20 alphanumeric)
    size_t name_len = strlen(name);
    if (name_len < 3 || name_len > 20) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid name length: %zu (must be 3-20 chars)\n", name_len);
        return -1;
    }

    // Validate fingerprint
    if (!is_valid_fingerprint(fingerprint)) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid fingerprint format (expected 128 hex chars)\n");
        return -1;
    }

    // Compute alias DHT key
    char alias_key[129];
    compute_dht_key_by_name(name, alias_key);

    // Store fingerprint as plain text (signed with fixed value_id=1 to prevent accumulation)
    // Use 365-day TTL for name registrations (persistent identity)
    printf("[DHT_KEYSERVER] Publishing alias: '%s' → %s\n", name, fingerprint);
    printf("[DHT_KEYSERVER] Alias DHT key: %s\n", alias_key);

    unsigned int ttl_365_days = 365 * 24 * 3600;  // 365 days in seconds
    int ret = dht_put_signed(dht_ctx, (uint8_t*)alias_key, strlen(alias_key),
                             (uint8_t*)fingerprint, 128, 1, ttl_365_days);

    if (ret != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to publish alias\n");
        return -1;
    }

    printf("[DHT_KEYSERVER] ✓ Alias published successfully (TTL=365 days)\n");
    return 0;
}

// Lookup public keys from DHT (supports both fingerprint and name)
int dht_keyserver_lookup(
    dht_context_t *dht_ctx,
    const char *identity_or_fingerprint,
    dht_pubkey_entry_t **entry_out
) {
    if (!dht_ctx || !identity_or_fingerprint || !entry_out) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments\n");
        return -1;
    }

    char fingerprint[129];
    bool is_direct_fingerprint = false;

    // Detect input type: fingerprint (128 hex) or name (3-20 alphanumeric)
    if (is_valid_fingerprint(identity_or_fingerprint)) {
        // Direct fingerprint lookup
        strncpy(fingerprint, identity_or_fingerprint, 128);
        fingerprint[128] = '\0';
        is_direct_fingerprint = true;
        printf("[DHT_KEYSERVER] Direct fingerprint lookup: %s\n", fingerprint);
    } else {
        // Name lookup: first resolve name → fingerprint via alias
        printf("[DHT_KEYSERVER] Name lookup: resolving '%s' to fingerprint\n", identity_or_fingerprint);

        char alias_key[129];
        compute_dht_key_by_name(identity_or_fingerprint, alias_key);

        uint8_t *alias_data = NULL;
        size_t alias_data_len = 0;
        int alias_ret = dht_get(dht_ctx, (uint8_t*)alias_key, strlen(alias_key), &alias_data, &alias_data_len);

        if (alias_ret != 0 || !alias_data) {
            fprintf(stderr, "[DHT_KEYSERVER] Name '%s' not registered (alias not found)\n", identity_or_fingerprint);
            return -2;  // Name not found
        }

        // Parse fingerprint from alias (simple text storage)
        if (alias_data_len != 128) {
            fprintf(stderr, "[DHT_KEYSERVER] Invalid alias data length: %zu (expected 128)\n", alias_data_len);
            free(alias_data);
            return -1;
        }

        memcpy(fingerprint, alias_data, 128);
        fingerprint[128] = '\0';
        free(alias_data);

        printf("[DHT_KEYSERVER] ✓ Name resolved to fingerprint: %s\n", fingerprint);
    }

    // Lookup by fingerprint
    char dht_key[129];
    compute_dht_key_by_fingerprint(fingerprint, dht_key);

    printf("[DHT_KEYSERVER] Fetching keys for fingerprint from DHT\n");
    printf("[DHT_KEYSERVER] DHT key: %s\n", dht_key);

    uint8_t *data = NULL;
    size_t data_len = 0;
    int ret = dht_get(dht_ctx, (uint8_t*)dht_key, strlen(dht_key), &data, &data_len);

    if (ret != 0 || !data) {
        fprintf(stderr, "[DHT_KEYSERVER] Keys not found in DHT for fingerprint %s\n", fingerprint);
        return -2;  // Not found
    }

    // Parse JSON (need to null-terminate first as DHT data isn't)
    char *json_str = (char*)malloc(data_len + 1);
    if (!json_str) {
        free(data);
        fprintf(stderr, "[DHT_KEYSERVER] Failed to allocate memory for JSON string\n");
        return -1;
    }
    memcpy(json_str, data, data_len);
    json_str[data_len] = '\0';
    free(data);
    
    dht_pubkey_entry_t *entry = malloc(sizeof(dht_pubkey_entry_t));
    if (!entry) {
        free(json_str);
        return -1;
    }

    if (deserialize_entry(json_str, entry) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to parse entry\n");
        free(json_str);
        free(entry);
        return -1;
    }

    free(json_str);

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

    // Compute DHT key: SHA3-512(fingerprint + ":reverse")
    char reverse_key_input[256];
    snprintf(reverse_key_input, sizeof(reverse_key_input), "%s:reverse", fingerprint);

    unsigned char reverse_hash[64];  // SHA3-512 = 64 bytes
    if (qgp_sha3_512((unsigned char*)reverse_key_input, strlen(reverse_key_input), reverse_hash) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to compute reverse DHT key\n");
        return -1;
    }

    char reverse_dht_key[129];
    for (int i = 0; i < 64; i++) {
        sprintf(reverse_dht_key + (i * 2), "%02x", reverse_hash[i]);
    }
    reverse_dht_key[128] = '\0';

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

    // Parse JSON (need to null-terminate first as DHT data isn't)
    char *json_str = (char*)malloc(value_len + 1);
    if (!json_str) {
        free(value);
        fprintf(stderr, "[DHT_KEYSERVER] Failed to allocate memory for JSON string\n");
        return -1;
    }
    memcpy(json_str, value, value_len);
    json_str[value_len] = '\0';
    free(value);
    
    json_object *root = json_tokener_parse(json_str);
    free(json_str);

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
    char computed_fingerprint[129];
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
    int verify_result = qgp_dsa87_verify(signature, DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE,
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

// Async reverse lookup helper structure
typedef struct {
    char fingerprint[129];
    void (*callback)(char *identity, void *userdata);
    void *userdata;
} reverse_lookup_async_ctx_t;

// Static callback for async DHT get
static void reverse_lookup_dht_callback(uint8_t *value, size_t value_len, void *cb_userdata) {
    reverse_lookup_async_ctx_t *ctx = (reverse_lookup_async_ctx_t*)cb_userdata;

    if (!value) {
        printf("[DHT_KEYSERVER] Async reverse mapping not found in DHT\n");
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }

    // Parse JSON
    char *json_str = (char*)malloc(value_len + 1);
    if (!json_str) {
        free(value);
        fprintf(stderr, "[DHT_KEYSERVER] Failed to allocate memory for JSON string\n");
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }
    memcpy(json_str, value, value_len);
    json_str[value_len] = '\0';
    free(value);

    json_object *root = json_tokener_parse(json_str);
    free(json_str);

    if (!root) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to parse reverse mapping JSON\n");
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
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
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }

    // Parse dilithium pubkey
    const char *dilithium_hex = json_object_get_string(dilithium_obj);
    uint8_t dilithium_pubkey[DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE];
    if (hex_to_bytes(dilithium_hex, dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid dilithium pubkey in reverse mapping\n");
        json_object_put(root);
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }

    // Verify fingerprint matches
    char computed_fingerprint[129];
    compute_fingerprint(dilithium_pubkey, computed_fingerprint);

    if (strcmp(computed_fingerprint, ctx->fingerprint) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Fingerprint mismatch in reverse mapping\n");
        json_object_put(root);
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }

    const char *identity = json_object_get_string(identity_obj);
    uint64_t timestamp = json_object_get_int64(timestamp_obj);

    // Parse signature
    const char *sig_hex = json_object_get_string(signature_obj);
    uint8_t signature[DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE];
    if (hex_to_bytes(sig_hex, signature, DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid signature in reverse mapping\n");
        json_object_put(root);
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }

    // Rebuild message to verify
    size_t msg_len = DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE + strlen(identity) + sizeof(uint64_t);
    uint8_t *msg = (uint8_t*)malloc(msg_len);
    if (!msg) {
        json_object_put(root);
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }

    size_t offset = 0;
    memcpy(msg + offset, dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    offset += DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE;
    memcpy(msg + offset, identity, strlen(identity));
    offset += strlen(identity);

    uint64_t timestamp_net = htonll(timestamp);
    memcpy(msg + offset, &timestamp_net, sizeof(timestamp_net));

    // Verify signature
    int verify_result = qgp_dsa87_verify(signature, DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE,
                                         msg, msg_len, dilithium_pubkey);
    free(msg);

    if (verify_result != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Async reverse mapping signature verification failed\n");
        json_object_put(root);
        ctx->callback(NULL, ctx->userdata);
        free(ctx);
        return;
    }

    // All checks passed - return identity
    char *identity_copy = strdup(identity);
    printf("[DHT_KEYSERVER] ✓ Async reverse lookup successful: %s\n", identity);

    json_object_put(root);
    ctx->callback(identity_copy, ctx->userdata);
    free(ctx);
}

// Async reverse lookup: fingerprint → identity (non-blocking with callback)
void dht_keyserver_reverse_lookup_async(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    void (*callback)(char *identity, void *userdata),
    void *userdata
) {
    if (!dht_ctx || !fingerprint || !callback) {
        fprintf(stderr, "[DHT_KEYSERVER] Invalid arguments to reverse_lookup_async\n");
        if (callback) callback(NULL, userdata);
        return;
    }

    // Compute DHT key: SHA3-512(fingerprint + ":reverse")
    char reverse_key_input[256];
    snprintf(reverse_key_input, sizeof(reverse_key_input), "%s:reverse", fingerprint);

    unsigned char reverse_hash[64];  // SHA3-512 = 64 bytes
    if (qgp_sha3_512((unsigned char*)reverse_key_input, strlen(reverse_key_input), reverse_hash) != 0) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to compute reverse DHT key\n");
        callback(NULL, userdata);
        return;
    }

    char reverse_dht_key[129];
    for (int i = 0; i < 64; i++) {
        sprintf(reverse_dht_key + (i * 2), "%02x", reverse_hash[i]);
    }
    reverse_dht_key[128] = '\0';

    printf("[DHT_KEYSERVER] Async reverse lookup for fingerprint: %s\n", fingerprint);
    printf("[DHT_KEYSERVER] Reverse DHT key: %s\n", reverse_dht_key);

    // Create context for callback (need to preserve fingerprint)
    reverse_lookup_async_ctx_t *ctx = (reverse_lookup_async_ctx_t*)malloc(sizeof(reverse_lookup_async_ctx_t));
    if (!ctx) {
        fprintf(stderr, "[DHT_KEYSERVER] Failed to allocate async context\n");
        callback(NULL, userdata);
        return;
    }

    strncpy(ctx->fingerprint, fingerprint, 128);
    ctx->fingerprint[128] = '\0';
    ctx->callback = callback;
    ctx->userdata = userdata;

    // Start async DHT get with static callback
    dht_get_async(dht_ctx, (uint8_t*)reverse_dht_key, strlen(reverse_dht_key),
                  reverse_lookup_dht_callback, ctx);
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

    // Compute DHT key FROM FINGERPRINT (fingerprint-first)
    char dht_key[129];
    compute_dht_key_by_fingerprint(entry.fingerprint, dht_key);

    // Store in DHT (signed with fixed value_id=1 to replace old entry)
    printf("[DHT_KEYSERVER] Updating keys for fingerprint: %s\n", entry.fingerprint);
    printf("[DHT_KEYSERVER] New version: %u\n", new_version);

    ret = dht_put_signed_permanent(dht_ctx, (uint8_t*)dht_key, strlen(dht_key),
                                    (uint8_t*)json, strlen(json), 1);

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

    // Compute DHT key (use fingerprint if valid, otherwise treat as name for lookup)
    char dht_key[129];
    if (is_valid_fingerprint(identity)) {
        // Direct fingerprint
        compute_dht_key_by_fingerprint(identity, dht_key);
    } else {
        // Name - resolve to fingerprint first
        // For now, just fail since deletion without fingerprint is ambiguous
        fprintf(stderr, "[DHT_KEYSERVER] Delete requires fingerprint (128 hex chars), not name\n");
        return -1;
    }

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

// ===== DNA NAME SYSTEM FUNCTIONS =====

// Compute fingerprint from Dilithium5 public key (public wrapper)
void dna_compute_fingerprint(
    const uint8_t *dilithium_pubkey,
    char *fingerprint_out
) {
    compute_fingerprint(dilithium_pubkey, fingerprint_out);
}

// Register DNA name for a fingerprint identity
int dna_register_name(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const char *name,
    const char *tx_hash,
    const char *network,
    const uint8_t *dilithium_privkey
) {
    if (!dht_ctx || !fingerprint || !name || !tx_hash || !network || !dilithium_privkey) {
        fprintf(stderr, "[DNA] Invalid arguments to dna_register_name\n");
        return -1;
    }

    // Validate name format
    if (!dna_validate_name(name)) {
        fprintf(stderr, "[DNA] Invalid name format: %s\n", name);
        return -1;
    }

    // Verify blockchain transaction
    printf("[DNA] Verifying blockchain transaction...\n");
    printf("[DNA] TX: %s on %s\n", tx_hash, network);

    int verify_result = cellframe_verify_registration_tx(tx_hash, network, name);
    if (verify_result != 0) {
        if (verify_result == -2) {
            fprintf(stderr, "[DNA] Transaction validation failed (invalid amount, memo, or recipient)\n");
        } else {
            fprintf(stderr, "[DNA] Transaction verification error (RPC failure or tx not found)\n");
        }
        return -1;
    }

    printf("[DNA] ✓ Transaction verified successfully\n");

    // Check if name is already taken
    char *existing_fp = NULL;
    int ret = dna_lookup_by_name(dht_ctx, name, &existing_fp);
    if (ret == 0) {
        // Name exists - check if it's the same fingerprint
        if (strcmp(existing_fp, fingerprint) != 0) {
            fprintf(stderr, "[DNA] Name '%s' already registered to different fingerprint\n", name);
            free(existing_fp);
            return -2;  // Name taken
        }
        free(existing_fp);
        // Same fingerprint - allow re-registration (renewal)
    }

    // Load or create identity
    dna_unified_identity_t *identity = NULL;
    ret = dna_load_identity(dht_ctx, fingerprint, &identity);

    if (ret != 0) {
        // Create new identity
        identity = dna_identity_create();
        if (!identity) {
            return -1;
        }
        strncpy(identity->fingerprint, fingerprint, sizeof(identity->fingerprint) - 1);
        // Note: Keys must be set separately
    }

    // Update name registration
    identity->has_registered_name = true;
    strncpy(identity->registered_name, name, sizeof(identity->registered_name) - 1);
    identity->name_registered_at = time(NULL);
    identity->name_expires_at = identity->name_registered_at + (365 * 24 * 60 * 60);  // +365 days
    strncpy(identity->registration_tx_hash, tx_hash, sizeof(identity->registration_tx_hash) - 1);
    strncpy(identity->registration_network, network, sizeof(identity->registration_network) - 1);
    identity->name_version = 1;
    identity->timestamp = time(NULL);
    identity->version++;

    // Store identity to DHT
    char *json = dna_identity_to_json(identity);
    if (!json) {
        dna_identity_free(identity);
        return -1;
    }

    // Compute identity DHT key
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s:profile", fingerprint);

    unsigned char hash[64];
    if (qgp_sha3_512((unsigned char*)key_input, strlen(key_input), hash) != 0) {
        free(json);
        dna_identity_free(identity);
        return -1;
    }

    char dht_key[129];
    for (int i = 0; i < 64; i++) {
        sprintf(dht_key + (i * 2), "%02x", hash[i]);
    }
    dht_key[128] = '\0';

    ret = dht_put_signed_permanent(dht_ctx, (uint8_t*)dht_key, strlen(dht_key),
                                    (uint8_t*)json, strlen(json), 1);
    free(json);

    if (ret != 0) {
        fprintf(stderr, "[DNA] Failed to store identity in DHT\n");
        dna_identity_free(identity);
        return -1;
    }

    // Store reverse mapping: name → fingerprint
    // Normalize name to lowercase
    char normalized_name[256];
    strncpy(normalized_name, name, sizeof(normalized_name) - 1);
    normalized_name[sizeof(normalized_name) - 1] = '\0';
    for (char *p = normalized_name; *p; p++) {
        *p = tolower(*p);
    }

    snprintf(key_input, sizeof(key_input), "%s:lookup", normalized_name);
    if (qgp_sha3_512((unsigned char*)key_input, strlen(key_input), hash) != 0) {
        dna_identity_free(identity);
        return -1;
    }

    for (int i = 0; i < 64; i++) {
        sprintf(dht_key + (i * 2), "%02x", hash[i]);
    }
    dht_key[128] = '\0';

    unsigned int ttl_365_days = 365 * 24 * 3600;
    ret = dht_put_signed(dht_ctx, (uint8_t*)dht_key, strlen(dht_key),
                         (uint8_t*)fingerprint, 128, 1, ttl_365_days);  // Store fingerprint (128 hex chars, signed)

    if (ret != 0) {
        fprintf(stderr, "[DNA] Failed to store name mapping in DHT\n");
        dna_identity_free(identity);
        return -1;
    }

    uint64_t expires_at = identity->name_expires_at;
    dna_identity_free(identity);

    printf("[DNA] ✓ Name registered: %s → %.16s...\n", name, fingerprint);
    printf("[DNA] Expires: %lu (365 days)\n", expires_at);
    return 0;
}

// Update DNA profile data
int dna_update_profile(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const dna_profile_data_t *profile,
    const uint8_t *dilithium_privkey
) {
    if (!dht_ctx || !fingerprint || !profile || !dilithium_privkey) {
        fprintf(stderr, "[DNA] Invalid arguments to dna_update_profile\n");
        return -1;
    }

    // Load existing identity
    dna_unified_identity_t *identity = NULL;
    int ret = dna_load_identity(dht_ctx, fingerprint, &identity);

    if (ret != 0) {
        // Create new identity if doesn't exist yet
        identity = dna_identity_create();
        if (!identity) {
            return -1;
        }

        // Set fingerprint and keys (keys must be provided separately)
        strncpy(identity->fingerprint, fingerprint, sizeof(identity->fingerprint) - 1);
        // Note: Keys must be set by caller before calling this function
    }

    // Update profile data
    printf("[DNA] DEBUG: Updating profile fields...\n");
    printf("[DNA] DEBUG: Input bio: '%s'\n", profile->bio[0] ? profile->bio : "(empty)");
    printf("[DNA] DEBUG: Input telegram: '%s'\n", profile->socials.telegram[0] ? profile->socials.telegram : "(empty)");
    printf("[DNA] DEBUG: Input twitter: '%s'\n", profile->socials.x[0] ? profile->socials.x : "(empty)");
    printf("[DNA] DEBUG: Input backbone: '%s'\n", profile->wallets.backbone[0] ? profile->wallets.backbone : "(empty)");

    memcpy(&identity->wallets, &profile->wallets, sizeof(identity->wallets));
    memcpy(&identity->socials, &profile->socials, sizeof(identity->socials));
    strncpy(identity->bio, profile->bio, sizeof(identity->bio) - 1);
    strncpy(identity->profile_picture_ipfs, profile->profile_picture_ipfs,
            sizeof(identity->profile_picture_ipfs) - 1);

    printf("[DNA] DEBUG: After copy bio: '%s'\n", identity->bio[0] ? identity->bio : "(empty)");
    printf("[DNA] DEBUG: After copy telegram: '%s'\n", identity->socials.telegram[0] ? identity->socials.telegram : "(empty)");

    // Update metadata
    identity->timestamp = time(NULL);
    identity->version++;

    // Sign the updated identity profile with Dilithium5
    size_t msg_len = sizeof(identity->fingerprint) +
                   sizeof(identity->dilithium_pubkey) +
                   sizeof(identity->kyber_pubkey) +
                   sizeof(bool) +
                   sizeof(identity->registered_name) +
                   sizeof(uint64_t) * 2 +
                   sizeof(identity->registration_tx_hash) +
                   sizeof(identity->registration_network) +
                   sizeof(uint32_t) +
                   sizeof(identity->wallets) +
                   sizeof(identity->socials) +
                   sizeof(identity->bio) +
                   sizeof(identity->profile_picture_ipfs) +
                   sizeof(uint64_t) +
                   sizeof(uint32_t);

    uint8_t *msg = malloc(msg_len);
    if (!msg) {
        fprintf(stderr, "[DNA] Failed to allocate message buffer for signing\n");
        dna_identity_free(identity);
        return -1;
    }

    size_t offset = 0;
    memcpy(msg + offset, identity->fingerprint, sizeof(identity->fingerprint));
    offset += sizeof(identity->fingerprint);
    memcpy(msg + offset, identity->dilithium_pubkey, sizeof(identity->dilithium_pubkey));
    offset += sizeof(identity->dilithium_pubkey);
    memcpy(msg + offset, identity->kyber_pubkey, sizeof(identity->kyber_pubkey));
    offset += sizeof(identity->kyber_pubkey);
    memcpy(msg + offset, &identity->has_registered_name, sizeof(bool));
    offset += sizeof(bool);
    memcpy(msg + offset, identity->registered_name, sizeof(identity->registered_name));
    offset += sizeof(identity->registered_name);

    // Network byte order for integers
    uint64_t registered_at_net = htonll(identity->name_registered_at);
    uint64_t expires_at_net = htonll(identity->name_expires_at);
    uint32_t name_version_net = htonl(identity->name_version);
    uint64_t timestamp_net = htonll(identity->timestamp);
    uint32_t version_net = htonl(identity->version);

    memcpy(msg + offset, &registered_at_net, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(msg + offset, &expires_at_net, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(msg + offset, identity->registration_tx_hash, sizeof(identity->registration_tx_hash));
    offset += sizeof(identity->registration_tx_hash);
    memcpy(msg + offset, identity->registration_network, sizeof(identity->registration_network));
    offset += sizeof(identity->registration_network);
    memcpy(msg + offset, &name_version_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(msg + offset, &identity->wallets, sizeof(identity->wallets));
    offset += sizeof(identity->wallets);
    memcpy(msg + offset, &identity->socials, sizeof(identity->socials));
    offset += sizeof(identity->socials);
    memcpy(msg + offset, identity->bio, sizeof(identity->bio));
    offset += sizeof(identity->bio);
    memcpy(msg + offset, identity->profile_picture_ipfs, sizeof(identity->profile_picture_ipfs));
    offset += sizeof(identity->profile_picture_ipfs);
    memcpy(msg + offset, &timestamp_net, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(msg + offset, &version_net, sizeof(uint32_t));

    // Sign with private key
    size_t siglen = sizeof(identity->signature);
    ret = qgp_dsa87_sign(identity->signature, &siglen, msg, msg_len, dilithium_privkey);

    free(msg);

    if (ret != 0) {
        fprintf(stderr, "[DNA] Failed to sign identity profile\n");
        dna_identity_free(identity);
        return -1;
    }

    printf("[DNA] ✓ Identity profile signed with Dilithium5\n");

    // Serialize to JSON
    char *json = dna_identity_to_json(identity);
    if (!json) {
        fprintf(stderr, "[DNA] Failed to serialize identity\n");
        dna_identity_free(identity);
        return -1;
    }

    // Compute DHT key: SHA3-512(fingerprint + ":profile")
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s:profile", fingerprint);

    unsigned char hash[64];
    if (qgp_sha3_512((unsigned char*)key_input, strlen(key_input), hash) != 0) {
        fprintf(stderr, "[DNA] Failed to compute DHT key\n");
        free(json);
        dna_identity_free(identity);
        return -1;
    }

    char dht_key[129];
    for (int i = 0; i < 64; i++) {
        sprintf(dht_key + (i * 2), "%02x", hash[i]);
    }
    dht_key[128] = '\0';

    printf("[DNA] Updating profile for fingerprint %.16s...\n", fingerprint);
    printf("[DNA] DHT key: %.32s...\n", dht_key);

    // Store in DHT (permanent storage, signed with fixed value_id=1 to prevent accumulation)
    ret = dht_put_signed_permanent(dht_ctx, (uint8_t*)dht_key, strlen(dht_key),
                                    (uint8_t*)json, strlen(json), 1);

    if (ret != 0) {
        fprintf(stderr, "[DNA] Failed to store in DHT\n");
        free(json);
        dna_identity_free(identity);
        return -1;
    }

    // Debug: Show what was stored (BEFORE freeing identity!)
    printf("[DNA] ✓ Profile updated successfully\n");
    printf("[DNA] DEBUG Profile Storage:\n");
    printf("[DNA]   Fingerprint: %s\n", fingerprint);
    printf("[DNA]   DHT Key: %s\n", dht_key);
    printf("[DNA]   Registered Name: %s\n", identity->has_registered_name ? identity->registered_name : "(none)");
    printf("[DNA]   Bio: %s\n", identity->bio[0] ? identity->bio : "(empty)");
    printf("[DNA]   Telegram: %s\n", identity->socials.telegram[0] ? identity->socials.telegram : "(empty)");
    printf("[DNA]   Twitter/X: %s\n", identity->socials.x[0] ? identity->socials.x : "(empty)");
    printf("[DNA]   GitHub: %s\n", identity->socials.github[0] ? identity->socials.github : "(empty)");
    printf("[DNA]   Backbone: %s\n", identity->wallets.backbone[0] ? identity->wallets.backbone : "(empty)");
    printf("[DNA]   Version: %u\n", identity->version);
    printf("[DNA]   Timestamp: %lu\n", (unsigned long)identity->timestamp);

    free(json);
    dna_identity_free(identity);

    return 0;
}

// Renew DNA name registration
int dna_renew_name(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const char *renewal_tx_hash,
    const uint8_t *dilithium_privkey
) {
    if (!dht_ctx || !fingerprint || !renewal_tx_hash || !dilithium_privkey) {
        fprintf(stderr, "[DNA] Invalid arguments to dna_renew_name\n");
        return -1;
    }

    // Load existing identity first to get name and network
    dna_unified_identity_t *identity = NULL;
    int ret_load = dna_load_identity(dht_ctx, fingerprint, &identity);

    if (ret_load != 0) {
        fprintf(stderr, "[DNA] Identity not found\n");
        return -2;
    }

    if (!identity->has_registered_name) {
        fprintf(stderr, "[DNA] No name registered for this fingerprint\n");
        dna_identity_free(identity);
        return -2;
    }

    // Verify blockchain transaction
    printf("[DNA] Verifying renewal transaction...\n");
    printf("[DNA] Renewal TX: %s\n", renewal_tx_hash);

    int verify_result = cellframe_verify_registration_tx(renewal_tx_hash,
                                                         identity->registration_network,
                                                         identity->registered_name);
    if (verify_result != 0) {
        if (verify_result == -2) {
            fprintf(stderr, "[DNA] Renewal transaction validation failed\n");
        } else {
            fprintf(stderr, "[DNA] Renewal transaction verification error\n");
        }
        dna_identity_free(identity);
        return -1;
    }

    printf("[DNA] ✓ Renewal transaction verified successfully\n");

    // Update renewal info
    identity->name_expires_at += (365 * 24 * 60 * 60);  // Extend by 365 days
    strncpy(identity->registration_tx_hash, renewal_tx_hash,
            sizeof(identity->registration_tx_hash) - 1);
    identity->name_version++;
    identity->timestamp = time(NULL);
    identity->version++;

    // Store updated identity
    char *json = dna_identity_to_json(identity);
    if (!json) {
        dna_identity_free(identity);
        return -1;
    }

    // Compute DHT key
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s:profile", fingerprint);

    unsigned char hash[64];
    if (qgp_sha3_512((unsigned char*)key_input, strlen(key_input), hash) != 0) {
        free(json);
        dna_identity_free(identity);
        return -1;
    }

    char dht_key[129];
    for (int i = 0; i < 64; i++) {
        sprintf(dht_key + (i * 2), "%02x", hash[i]);
    }
    dht_key[128] = '\0';

    int ret = dht_put_signed_permanent(dht_ctx, (uint8_t*)dht_key, strlen(dht_key),
                                        (uint8_t*)json, strlen(json), 1);
    free(json);

    if (ret != 0) {
        fprintf(stderr, "[DNA] Failed to store renewed identity in DHT\n");
        dna_identity_free(identity);
        return -1;
    }

    printf("[DNA] ✓ Name renewed: %s\n", identity->registered_name);
    printf("[DNA] New expiration: %lu (+365 days)\n", identity->name_expires_at);

    dna_identity_free(identity);
    return 0;
}

// Load complete DNA identity from DHT
int dna_load_identity(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    dna_unified_identity_t **identity_out
) {
    if (!dht_ctx || !fingerprint || !identity_out) {
        fprintf(stderr, "[DNA] Invalid arguments to dna_load_identity\n");
        return -1;
    }

    // Compute DHT key: SHA3-512(fingerprint + ":profile")
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s:profile", fingerprint);

    unsigned char hash[64];  // SHA3-512 = 64 bytes
    if (qgp_sha3_512((unsigned char*)key_input, strlen(key_input), hash) != 0) {
        fprintf(stderr, "[DNA] Failed to compute DHT key\n");
        return -1;
    }

    char dht_key[129];
    for (int i = 0; i < 64; i++) {
        sprintf(dht_key + (i * 2), "%02x", hash[i]);
    }
    dht_key[128] = '\0';

    printf("[DNA] Loading identity for fingerprint %.16s...\n", fingerprint);
    printf("[DNA] DHT key: %.32s...\n", dht_key);

    // Fetch ALL values from DHT (OpenDHT append-only model)
    uint8_t **values = NULL;
    size_t *values_len = NULL;
    size_t value_count = 0;

    if (dht_get_all(dht_ctx, (uint8_t*)dht_key, strlen(dht_key), &values, &values_len, &value_count) != 0) {
        fprintf(stderr, "[DNA] Identity not found in DHT\n");
        return -2;  // Not found
    }

    printf("[DNA] Found %zu profile version(s) in DHT\n", value_count);

    // Parse and verify all values, track newest valid one
    dna_unified_identity_t *best_identity = NULL;
    uint64_t best_timestamp = 0;

    for (size_t i = 0; i < value_count; i++) {
        if (!values[i] || values_len[i] == 0) {
            continue;  // Skip empty values
        }

        printf("[DNA] Verifying version %zu/%zu (%zu bytes)...\n", i+1, value_count, values_len[i]);

        // Parse JSON
        dna_unified_identity_t *identity = NULL;
        if (dna_identity_from_json((char*)values[i], &identity) != 0) {
            fprintf(stderr, "[DNA] ⚠ Version %zu: JSON parse failed\n", i+1);
            continue;
        }

        // Verify signature
        // Build message to verify: everything except signature field
    size_t msg_len = sizeof(identity->fingerprint) +
                     sizeof(identity->dilithium_pubkey) +
                     sizeof(identity->kyber_pubkey) +
                     sizeof(bool) +  // has_registered_name
                     sizeof(identity->registered_name) +
                     sizeof(identity->name_registered_at) +
                     sizeof(identity->name_expires_at) +
                     sizeof(identity->registration_tx_hash) +
                     sizeof(identity->registration_network) +
                     sizeof(identity->name_version) +
                     sizeof(identity->wallets) +
                     sizeof(identity->socials) +
                     sizeof(identity->bio) +
                     sizeof(identity->profile_picture_ipfs) +
                     sizeof(identity->timestamp) +
                     sizeof(identity->version);

    uint8_t *msg = malloc(msg_len);
    if (!msg) {
        dna_identity_free(identity);
        return -1;
    }

    // Build message (same order as signing in messenger.c)
    size_t offset = 0;
    memcpy(msg + offset, identity->fingerprint, sizeof(identity->fingerprint));
    offset += sizeof(identity->fingerprint);
    memcpy(msg + offset, identity->dilithium_pubkey, sizeof(identity->dilithium_pubkey));
    offset += sizeof(identity->dilithium_pubkey);
    memcpy(msg + offset, identity->kyber_pubkey, sizeof(identity->kyber_pubkey));
    offset += sizeof(identity->kyber_pubkey);
    memcpy(msg + offset, &identity->has_registered_name, sizeof(bool));
    offset += sizeof(bool);
    memcpy(msg + offset, identity->registered_name, sizeof(identity->registered_name));
    offset += sizeof(identity->registered_name);

    // Network byte order for integers (same as signing)
    uint64_t registered_at_net = htonll(identity->name_registered_at);
    uint64_t expires_at_net = htonll(identity->name_expires_at);
    uint32_t name_version_net = htonl(identity->name_version);
    uint64_t timestamp_net = htonll(identity->timestamp);
    uint32_t version_net = htonl(identity->version);

    memcpy(msg + offset, &registered_at_net, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(msg + offset, &expires_at_net, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(msg + offset, identity->registration_tx_hash, sizeof(identity->registration_tx_hash));
    offset += sizeof(identity->registration_tx_hash);
    memcpy(msg + offset, identity->registration_network, sizeof(identity->registration_network));
    offset += sizeof(identity->registration_network);
    memcpy(msg + offset, &name_version_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(msg + offset, &identity->wallets, sizeof(identity->wallets));
    offset += sizeof(identity->wallets);
    memcpy(msg + offset, &identity->socials, sizeof(identity->socials));
    offset += sizeof(identity->socials);
    memcpy(msg + offset, identity->bio, sizeof(identity->bio));
    offset += sizeof(identity->bio);
    memcpy(msg + offset, identity->profile_picture_ipfs, sizeof(identity->profile_picture_ipfs));
    offset += sizeof(identity->profile_picture_ipfs);
    memcpy(msg + offset, &timestamp_net, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(msg + offset, &version_net, sizeof(uint32_t));

    // Verify Dilithium5 signature
    int sig_result = qgp_dsa87_verify(identity->signature, sizeof(identity->signature),
                                       msg, msg_len, identity->dilithium_pubkey);

    free(msg);

        if (sig_result != 0) {
            fprintf(stderr, "[DNA] ✗ Version %zu: Signature verification failed\n", i+1);
            dna_identity_free(identity);
            continue;
        }

        // Verify fingerprint matches
        char computed_fingerprint[129];
        compute_fingerprint(identity->dilithium_pubkey, computed_fingerprint);

        if (strcmp(computed_fingerprint, fingerprint) != 0) {
            fprintf(stderr, "[DNA] ✗ Version %zu: Fingerprint mismatch\n", i+1);
            dna_identity_free(identity);
            continue;
        }

        printf("[DNA] ✓ Version %zu: Valid (timestamp=%lu, version=%u)\n",
               i+1, identity->timestamp, identity->version);

        // Check if this is the newest valid version
        if (identity->timestamp > best_timestamp) {
            // Free previous best if exists
            if (best_identity) {
                dna_identity_free(best_identity);
            }
            best_identity = identity;
            best_timestamp = identity->timestamp;
        } else {
            // This version is older, discard it
            dna_identity_free(identity);
        }
    }

    // Free values array
    for (size_t i = 0; i < value_count; i++) {
        free(values[i]);
    }
    free(values);
    free(values_len);

    // Check if we found any valid identity
    if (!best_identity) {
        fprintf(stderr, "[DNA] No valid identity found (all signatures failed)\n");
        return -3;  // Verification failed
    }

    printf("[DNA] ✓ Loaded newest valid profile (timestamp=%lu, version=%u)\n",
           best_identity->timestamp, best_identity->version);
    if (best_identity->has_registered_name) {
        printf("[DNA] Name: %s (expires: %lu)\n",
               best_identity->registered_name, best_identity->name_expires_at);
    }

    *identity_out = best_identity;
    return 0;
}

// Lookup fingerprint by DNA name
int dna_lookup_by_name(
    dht_context_t *dht_ctx,
    const char *name,
    char **fingerprint_out
) {
    if (!dht_ctx || !name || !fingerprint_out) {
        fprintf(stderr, "[DNA] Invalid arguments to dna_lookup_by_name\n");
        return -1;
    }

    // Normalize name to lowercase
    char normalized_name[256];
    strncpy(normalized_name, name, sizeof(normalized_name) - 1);
    normalized_name[sizeof(normalized_name) - 1] = '\0';
    for (char *p = normalized_name; *p; p++) {
        *p = tolower(*p);
    }

    // Compute DHT key: SHA3-512(name + ":lookup")
    char key_input[300];
    snprintf(key_input, sizeof(key_input), "%s:lookup", normalized_name);

    unsigned char hash[64];
    if (qgp_sha3_512((unsigned char*)key_input, strlen(key_input), hash) != 0) {
        fprintf(stderr, "[DNA] Failed to compute DHT key\n");
        return -1;
    }

    char dht_key[129];
    for (int i = 0; i < 64; i++) {
        sprintf(dht_key + (i * 2), "%02x", hash[i]);
    }
    dht_key[128] = '\0';

    printf("[DNA] Looking up name '%s'\n", normalized_name);
    printf("[DNA] DHT key: %.32s...\n", dht_key);

    // Fetch from DHT
    uint8_t *value = NULL;
    size_t value_len = 0;

    if (dht_get(dht_ctx, (uint8_t*)dht_key, strlen(dht_key), &value, &value_len) != 0 || !value) {
        fprintf(stderr, "[DNA] Name not found in DHT\n");
        return -2;  // Not found
    }

    // Value is just the fingerprint (128 hex chars)
    if (value_len != 128) {
        fprintf(stderr, "[DNA] Invalid fingerprint length: %zu (expected 128)\n", value_len);
        free(value);
        return -1;
    }

    char *fingerprint = malloc(129);
    if (!fingerprint) {
        free(value);
        return -1;
    }

    memcpy(fingerprint, value, 128);
    fingerprint[128] = '\0';
    free(value);

    printf("[DNA] ✓ Name resolved: %s → %.16s...\n", normalized_name, fingerprint);

    *fingerprint_out = fingerprint;
    return 0;
}

// Check if DNA name has expired
bool dna_is_name_expired(const dna_unified_identity_t *identity) {
    if (!identity || !identity->has_registered_name) {
        return false;  // No name registered = not expired
    }

    uint64_t now = time(NULL);
    return (now >= identity->name_expires_at);
}

// Get display name for fingerprint
int dna_get_display_name(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    char **display_name_out
) {
    if (!fingerprint || !display_name_out) {
        return -1;
    }

    // Try to load identity from DHT
    dna_unified_identity_t *identity = NULL;
    int ret = dna_load_identity(dht_ctx, fingerprint, &identity);

    if (ret == 0 && identity) {
        // Check if name is registered and not expired
        if (identity->has_registered_name && !dna_is_name_expired(identity)) {
            // Return registered name
            char *display = strdup(identity->registered_name);
            dna_identity_free(identity);

            if (!display) {
                return -1;
            }

            *display_name_out = display;
            printf("[DNA] ✓ Display name: %s (registered)\n", display);
            return 0;
        }

        dna_identity_free(identity);
    }

    // Fallback: Return shortened fingerprint (first 16 chars + "...")
    char *display = malloc(32);
    if (!display) {
        return -1;
    }

    snprintf(display, 32, "%.16s...", fingerprint);
    *display_name_out = display;

    printf("[DNA] Display name: %s (fingerprint)\n", display);
    return 0;
}

// Resolve DNA name to wallet address
int dna_resolve_address(
    dht_context_t *dht_ctx,
    const char *name,
    const char *network,
    char **address_out
) {
    if (!dht_ctx || !name || !network || !address_out) {
        fprintf(stderr, "[DNA] Invalid arguments to dna_resolve_address\n");
        return -1;
    }

    // Check if input is already a fingerprint (128 hex chars)
    char *fingerprint = NULL;
    bool is_fingerprint = (strlen(name) == 128);

    if (is_fingerprint) {
        // Validate it's all hex
        for (size_t i = 0; i < 128; i++) {
            if (!isxdigit(name[i])) {
                is_fingerprint = false;
                break;
            }
        }
    }

    if (is_fingerprint) {
        // Direct fingerprint lookup
        fingerprint = strdup(name);
    } else {
        // Look up name → fingerprint
        int ret = dna_lookup_by_name(dht_ctx, name, &fingerprint);
        if (ret != 0) {
            return ret;  // -1 error, -2 not found
        }
    }

    // Load identity
    dna_unified_identity_t *identity = NULL;
    int ret = dna_load_identity(dht_ctx, fingerprint, &identity);
    free(fingerprint);

    if (ret != 0) {
        return ret;  // -1 error, -2 not found, -3 verification failed
    }

    // Get wallet address for network
    const char *address = dna_identity_get_wallet(identity, network);

    if (!address || address[0] == '\0') {
        fprintf(stderr, "[DNA] No address for network '%s'\n", network);
        dna_identity_free(identity);
        return -3;  // No address for network
    }

    char *result = strdup(address);
    dna_identity_free(identity);

    if (!result) {
        return -1;
    }

    printf("[DNA] ✓ Resolved: %s → %s on %s\n", name, result, network);

    *address_out = result;
    return 0;
}
