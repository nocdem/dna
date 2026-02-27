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

/* Redirect printf/fprintf to Android logcat */
#define QGP_LOG_TAG "KEYSERVER"
#define QGP_LOG_REDIRECT_STDIO 1
#include "../../crypto/utils/qgp_log.h"

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
#include "../core/dht_context.h"
#include "../core/dht_keyserver.h"  // Includes size constants and dna_unified_identity_t
#include "../shared/dht_chunked.h"  // Chunked storage layer
#include "../client/dna_profile.h"
#include "../../crypto/utils/qgp_dilithium.h"
#include "../../crypto/utils/qgp_sha3.h"
#include "../../blockchain/cellframe/cellframe_rpc.h"
#include <openssl/evp.h>
#include <json-c/json.h>

#ifdef __cplusplus
extern "C" {
#endif

// Note: Size constants and dna_unified_identity_t are defined in dht_keyserver.h and dna_profile.h

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

// NOTE: Old helper functions (serialize_entry, deserialize_entry, sign_entry, verify_entry)
// have been removed. Use dna_identity_to_json/dna_identity_from_json from dna_profile.h instead.

#ifdef __cplusplus
}
#endif

#endif // DHT_KEYSERVER_CORE_H
