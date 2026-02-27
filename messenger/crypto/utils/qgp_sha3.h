#ifndef QGP_SHA3_H
#define QGP_SHA3_H

#include <stdint.h>
#include <stddef.h>

/**
 * SHA3-512 Hashing Utilities
 *
 * Provides SHA3-512 hash functions for DNA Messenger Category 5 security.
 * SHA3-512 provides 256-bit quantum security (Grover's algorithm resistance).
 *
 * Used for:
 * - Public key fingerprints (64 bytes → 128 hex chars)
 * - DHT storage keys (64 bytes → 128 hex chars)
 * - General cryptographic hashing where 256-bit quantum security is required
 */

#define QGP_SHA3_512_DIGEST_LENGTH 64  // SHA3-512 output size in bytes
#define QGP_SHA3_512_HEX_LENGTH 129    // 128 hex chars + null terminator

#define QGP_SHA3_256_DIGEST_LENGTH 32  // SHA3-256 output size in bytes
#define QGP_SHA3_256_HEX_LENGTH 65     // 64 hex chars + null terminator

/**
 * Compute SHA3-512 hash of data
 *
 * @param data Input data to hash
 * @param len Length of input data in bytes
 * @param hash_out Output buffer for hash (must be at least 64 bytes)
 * @return 0 on success, -1 on error
 */
int qgp_sha3_512(const uint8_t *data, size_t len, uint8_t *hash_out);

/**
 * Compute SHA3-512 hash and convert to hexadecimal string
 *
 * @param data Input data to hash
 * @param len Length of input data in bytes
 * @param hex_out Output buffer for hex string (must be at least 129 bytes: 128 hex + null)
 * @param hex_size Size of hex_out buffer (must be >= 129)
 * @return 0 on success, -1 on error
 */
int qgp_sha3_512_hex(const uint8_t *data, size_t len, char *hex_out, size_t hex_size);

/**
 * Compute SHA3-512 fingerprint of public key
 * Convenience wrapper for qgp_sha3_512_hex with validation
 *
 * @param pubkey Public key bytes
 * @param pubkey_len Length of public key
 * @param fingerprint_out Output buffer for fingerprint (must be at least 129 bytes)
 * @return 0 on success, -1 on error
 */
int qgp_sha3_512_fingerprint(const uint8_t *pubkey, size_t pubkey_len, char *fingerprint_out);

/**
 * Compute SHA3-256 hash of data
 *
 * @param data Input data to hash
 * @param len Length of input data in bytes
 * @param hash_out Output buffer for hash (must be at least 32 bytes)
 * @return 0 on success, -1 on error
 */
int qgp_sha3_256(const uint8_t *data, size_t len, uint8_t *hash_out);

#endif // QGP_SHA3_H
