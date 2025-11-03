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
