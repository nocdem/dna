/*
 * qgp_types.h - QGP Custom Data Types 
 *
 * This header defines QGP's own data structures with no external
 * dependencies. These structures are designed for:
 * - Simplicity (no callbacks, no external dependencies)
 * - Portability (standard C types only)
 * - Clarity (explicit field names and purposes)
 */

#ifndef QGP_TYPES_H
#define QGP_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "qgp_compiler.h"

// ============================================================================
// KEY TYPES AND PURPOSES
// ============================================================================

/**
 * QGP Cryptographic Algorithm Types
 */
typedef enum {
    QGP_KEY_TYPE_INVALID = 0,
    QGP_KEY_TYPE_DILITHIUM3 = 1,    // Post-quantum signature (ML-DSA-65, FIPS 204)
    QGP_KEY_TYPE_KYBER512 = 2       // Post-quantum KEM (NIST Level 1)
} qgp_key_type_t;

/**
 * Key Purpose (Signing vs Encryption)
 */
typedef enum {
    QGP_KEY_PURPOSE_UNKNOWN = 0,
    QGP_KEY_PURPOSE_SIGNING = 1,     // Dilithium3 signing keys
    QGP_KEY_PURPOSE_ENCRYPTION = 2   // Kyber512 encryption keys
} qgp_key_purpose_t;

// ============================================================================
// KEY STRUCTURE
// ============================================================================

/**
 * QGP Key Structure
 *
 * Simplified key storage with explicit fields:
 * - No callbacks (direct function calls instead)
 * - Clear ownership (caller manages memory)
 *
 * Key Sizes:
 * - Dilithium3: public=1952, private=4032
 * - Kyber512:   public=800,  private=1632
 */
typedef struct {
    qgp_key_type_t type;          // Algorithm type
    qgp_key_purpose_t purpose;    // Signing or encryption

    // Public key
    uint8_t *public_key;          // Public key bytes (caller owns)
    size_t public_key_size;       // Public key size

    // Private key
    uint8_t *private_key;         // Private key bytes (caller owns)
    size_t private_key_size;      // Private key size

    // Metadata
    char name[256];               // Key name (e.g., "alice")
} qgp_key_t;

// ============================================================================
// SIGNATURE STRUCTURE
// ============================================================================

/**
 * QGP Signature Type
 */
typedef enum {
    QGP_SIG_TYPE_INVALID = 0,
    QGP_SIG_TYPE_DILITHIUM = 1   // Only Dilithium3 supported
} qgp_sig_type_t;

/**
 * QGP Signature Structure
 *
 * Simplified signature format:
 * - Type: Signature algorithm
 * - Public key: Embedded for verification
 * - Signature: Actual signature bytes
 *
 * Layout: [type(1) | pkey_size(2) | sig_size(2) | public_key | signature]
 */
typedef struct {
    qgp_sig_type_t type;          // Signature algorithm
    uint16_t public_key_size;     // Public key size (1952 for Dilithium3)
    uint16_t signature_size;      // Signature size (up to 3309 for Dilithium3)
    uint8_t *data;                // public_key || signature (caller owns)
} qgp_signature_t;

/**
 * Signature helper macros
 */
#define qgp_signature_get_pubkey(sig) ((sig)->data)
#define qgp_signature_get_bytes(sig) ((sig)->data + (sig)->public_key_size)
#define qgp_signature_total_size(sig) (5 + (sig)->public_key_size + (sig)->signature_size)

// ============================================================================
// HASH STRUCTURE
// ============================================================================

/**
 * QGP Hash Structure
 *
 * Simple hash container (SHA256)
 */
typedef struct {
    uint8_t hash[32];  // SHA256 hash (256 bits)
} qgp_hash_t;

// ============================================================================
// FILE FORMAT STRUCTURES
// ============================================================================

/*
 * Kyber512 KEM key type identifier (value: 23) for backward compatibility
 */
#define DAP_ENC_KEY_TYPE_KEM_KYBER512 23

/**
 * PQSigNum Private Key File Header
 * File format: [header | public_key | private_key]
 */
PACK_STRUCT_BEGIN
typedef struct {
    char magic[8];                 // "PQSIGNUM"
    uint8_t version;               // File format version (1)
    uint8_t key_type;              // qgp_key_type_t
    uint8_t purpose;               // qgp_key_purpose_t
    uint8_t reserved;              // Reserved for future use
    uint32_t public_key_size;      // Public key size in bytes
    uint32_t private_key_size;     // Private key size in bytes
    char name[256];                // Key name
} PACK_STRUCT_END qgp_privkey_file_header_t;

#define QGP_PRIVKEY_MAGIC "PQSIGNUM"
#define QGP_PRIVKEY_VERSION 1

/**
 * PQSigNum Public Key File Header (for export)
 * File format: [header | public_key]
 */
PACK_STRUCT_BEGIN
typedef struct {
    char magic[8];                 // "QGPPUBKY"
    uint8_t version;               // File format version (1)
    uint8_t key_type;              // qgp_key_type_t
    uint8_t purpose;               // qgp_key_purpose_t
    uint8_t reserved;              // Reserved for future use
    uint32_t public_key_size;      // Public key size in bytes
    char name[256];                // Key name
} PACK_STRUCT_END qgp_pubkey_file_header_t;

#define QGP_PUBKEY_MAGIC "QGPPUBKY"
#define QGP_PUBKEY_VERSION 1

// ============================================================================
// MEMORY MANAGEMENT MACROS
// ============================================================================

/**
 * Memory allocation macros
 *
 * Simple wrappers around standard C memory functions
 */
#define QGP_MALLOC(size) malloc(size)
#define QGP_CALLOC(count, size) calloc(count, size)
#define QGP_FREE(ptr) do { if (ptr) { free(ptr); (ptr) = NULL; } } while(0)

// ============================================================================
// FUNCTION DECLARATIONS
// ============================================================================

/**
 * Key memory management
 */
qgp_key_t* qgp_key_new(qgp_key_type_t type, qgp_key_purpose_t purpose);
void qgp_key_free(qgp_key_t *key);

/**
 * Signature memory management
 */
qgp_signature_t* qgp_signature_new(qgp_sig_type_t type, uint16_t pkey_size, uint16_t sig_size);
void qgp_signature_free(qgp_signature_t *sig);
size_t qgp_signature_get_size(const qgp_signature_t *sig);
size_t qgp_signature_serialize(const qgp_signature_t *sig, uint8_t *buffer);
int qgp_signature_deserialize(const uint8_t *buffer, size_t buffer_size, qgp_signature_t **sig_out);

/**
 * Key serialization
 */
int qgp_key_save(const qgp_key_t *key, const char *path);
int qgp_key_load(const char *path, qgp_key_t **key_out);
int qgp_pubkey_save(const qgp_key_t *key, const char *path);
int qgp_pubkey_load(const char *path, qgp_key_t **key_out);

/**
 * Hash utilities
 */
void qgp_hash_from_bytes(qgp_hash_t *hash, const uint8_t *data, size_t len);
void qgp_hash_to_hex(const qgp_hash_t *hash, char *hex_out, size_t hex_size);

/**
 * Base64 utilities
 */
char* qgp_base64_encode(const uint8_t *data, size_t data_len, size_t *out_len);
uint8_t* qgp_base64_decode(const char *base64_str, size_t *out_len);

#endif // QGP_TYPES_H
