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

// NOTE: Old helper functions removed (serialize_entry, deserialize_entry, sign_entry, verify_entry)
// Use dna_identity_to_json/dna_identity_from_json from dna_profile.h instead
