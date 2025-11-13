/**
 * DHT Keyserver Core - Shared types and helper functions
 * Used by all keyserver modules
 */

#ifndef DHT_KEYSERVER_CORE_H
#define DHT_KEYSERVER_CORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

// Platform-specific network byte order includes
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

// External dependencies
#include "../dht_context.h"
#include "../dht_keyserver.h"  // Includes type definitions (dht_pubkey_entry_t, sizes)
#include "../dna_profile.h"
#include "../../crypto/utils/qgp_dilithium.h"
#include "../../crypto/utils/qgp_sha3.h"
#include "../../blockchain/blockchain_rpc.h"
#include <openssl/evp.h>
#include <json-c/json.h>

#ifdef __cplusplus
extern "C" {
#endif

// Note: dht_pubkey_entry_t and size constants are defined in ../dht_keyserver.h
// to avoid duplication

// ===== HELPER FUNCTIONS (internal use by keyserver modules) =====

/**
 * Validate fingerprint format (128 hex chars)
 * @param str: String to validate
 * @return: true if valid, false otherwise
 */
bool is_valid_fingerprint(const char *str);

/**
 * Compute DHT storage key using SHA3-512 (fingerprint-based)
 * Format: SHA3-512(fingerprint + ":pubkey") - 128 hex chars
 * @param fingerprint: Fingerprint (128 hex chars)
 * @param key_out: Output buffer (must be 129 bytes for 128 hex + null)
 */
void compute_dht_key_by_fingerprint(const char *fingerprint, char *key_out);

/**
 * Compute DHT storage key using SHA3-512 (name-based, for alias lookup)
 * Format: SHA3-512(name + ":lookup") - 128 hex chars
 * @param name: DNA name
 * @param key_out: Output buffer (must be 129 bytes for 128 hex + null)
 */
void compute_dht_key_by_name(const char *name, char *key_out);

/**
 * Compute SHA3-512 fingerprint of dilithium pubkey
 * @param dilithium_pubkey: Dilithium5 public key (2592 bytes)
 * @param fingerprint_out: Output buffer (must be 129 bytes for 128 hex + null)
 */
void compute_fingerprint(const uint8_t *dilithium_pubkey, char *fingerprint_out);

/**
 * Serialize entry to JSON
 * @param entry: Entry to serialize
 * @return: JSON string (caller must free), NULL on error
 */
char* serialize_entry(const dht_pubkey_entry_t *entry);

/**
 * Parse hex string to bytes
 * @param hex: Hex string
 * @param bytes: Output buffer
 * @param bytes_len: Expected byte length
 * @return: 0 on success, -1 on error
 */
int hex_to_bytes(const char *hex, uint8_t *bytes, size_t bytes_len);

/**
 * Deserialize JSON to entry
 * @param json_str: JSON string
 * @param entry: Output entry
 * @return: 0 on success, -1 on error
 */
int deserialize_entry(const char *json_str, dht_pubkey_entry_t *entry);

/**
 * Create signature for entry
 * @param entry: Entry to sign (signature field will be filled)
 * @param dilithium_privkey: Dilithium5 private key (4896 bytes)
 * @return: 0 on success, -1 on error
 */
int sign_entry(dht_pubkey_entry_t *entry, const uint8_t *dilithium_privkey);

/**
 * Verify entry signature
 * @param entry: Entry to verify
 * @return: 0 on success (valid signature), -1 on error
 */
int verify_entry(const dht_pubkey_entry_t *entry);

#ifdef __cplusplus
}
#endif

#endif // DHT_KEYSERVER_CORE_H
