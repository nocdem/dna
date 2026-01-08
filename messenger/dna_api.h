/*
 * DNA Messenger - Public API Header
 *
 * Post-quantum end-to-end encrypted messaging library
 * Memory-based operations (no file I/O in public API)
 */

#ifndef DNA_API_H
#define DNA_API_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "include/dna/version.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// VERSION INFORMATION (from include/dna/version.h)
// ============================================================================

/**
 * Get library version as string
 * Returns: e.g., "0.2.5"
 */
const char* dna_version(void);

// ============================================================================
// ERROR CODES
// ============================================================================

typedef enum {
    DNA_OK = 0,                    // Success
    DNA_ERROR_MEMORY = -1,         // Memory allocation failed
    DNA_ERROR_INVALID_ARG = -2,    // Invalid argument
    DNA_ERROR_KEY_LOAD = -3,       // Failed to load key
    DNA_ERROR_KEY_INVALID = -4,    // Invalid key type or format
    DNA_ERROR_CRYPTO = -5,         // Cryptographic operation failed
    DNA_ERROR_VERIFY = -6,         // Signature verification failed
    DNA_ERROR_DECRYPT = -7,        // Decryption failed
    DNA_ERROR_NOT_FOUND = -8,      // Resource not found (recipient, key, etc.)
    DNA_ERROR_INTERNAL = -99       // Internal error
} dna_error_t;

/**
 * Get human-readable error message
 * @param error: Error code
 * @return: Error message string (never NULL)
 */
const char* dna_error_string(dna_error_t error);

// ============================================================================
// CONTEXT MANAGEMENT
// ============================================================================

/**
 * DNA Context
 * Opaque structure for library state management
 */
typedef struct dna_context dna_context_t;

/**
 * Create new DNA context
 * @return: Context pointer, or NULL on error
 */
dna_context_t* dna_context_new(void);

/**
 * Free DNA context and all associated resources
 * @param ctx: Context to free (can be NULL)
 */
void dna_context_free(dna_context_t *ctx);

// ============================================================================
// BUFFER MANAGEMENT
// ============================================================================

/**
 * DNA Buffer
 * Memory buffer with size tracking (caller owns memory)
 */
typedef struct {
    uint8_t *data;   // Buffer data (caller must free)
    size_t size;     // Buffer size in bytes
} dna_buffer_t;

/**
 * Allocate new buffer
 * @param size: Buffer size in bytes
 * @return: Buffer structure (caller must free data)
 */
dna_buffer_t dna_buffer_new(size_t size);

/**
 * Free buffer data
 * @param buffer: Buffer to free (securely wipes data)
 */
void dna_buffer_free(dna_buffer_t *buffer);

// ============================================================================
// MESSAGE ENCRYPTION
// ============================================================================

// NOTE: dna_encrypt_message() removed in v0.3.150 - used broken keyring stubs
// Use dna_encrypt_message_raw() instead with explicit key parameters

/**
 * Encrypt message with raw keys (for offline delivery)
 *
 * v0.08: Added timestamp parameter (encrypted in payload)
 *
 * @param ctx: DNA context
 * @param plaintext: Plaintext message buffer
 * @param plaintext_len: Plaintext length
 * @param recipient_enc_pubkey: Recipient's Kyber1024 public key (1568 bytes)
 * @param sender_sign_pubkey: Sender's Dilithium5 public key (2592 bytes)
 * @param sender_sign_privkey: Sender's Dilithium5 private key (4896 bytes)
 * @param timestamp: Message timestamp (Unix time, uint64_t, encrypted in payload)
 * @param ciphertext_out: Output ciphertext buffer (caller must free)
 * @param ciphertext_len_out: Output ciphertext length
 * @return: DNA_OK on success, error code otherwise
 */
dna_error_t dna_encrypt_message_raw(
    dna_context_t *ctx,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *recipient_enc_pubkey,
    const uint8_t *sender_sign_pubkey,
    const uint8_t *sender_sign_privkey,
    uint64_t timestamp,
    uint8_t **ciphertext_out,
    size_t *ciphertext_len_out
);

// ============================================================================
// MESSAGE DECRYPTION
// ============================================================================

// NOTE: dna_decrypt_message() removed in v0.3.150 - used broken keyring stubs
// Use dna_decrypt_message_raw() instead with explicit key parameters

/**
 * Decrypt message with raw keys (for offline delivery)
 *
 * v0.07: sender_sign_pubkey_out now contains 64-byte SHA3-512 fingerprint (not full pubkey)
 * v0.08: Added timestamp_out parameter (extracted from encrypted payload)
 * Caller must query keyserver to get actual public key for signature verification
 *
 * @param ctx: DNA context
 * @param ciphertext: Encrypted message buffer
 * @param ciphertext_len: Ciphertext length
 * @param recipient_enc_privkey: Recipient's Kyber1024 private key (3168 bytes)
 * @param plaintext_out: Output plaintext buffer (caller must free)
 * @param plaintext_len_out: Output plaintext length
 * @param sender_sign_pubkey_out: v0.07: Sender's fingerprint (64 bytes, caller must free)
 * @param sender_sign_pubkey_len_out: Sender's fingerprint length (64)
 * @param signature_out: Signature bytes (caller must free, can be NULL if not needed)
 * @param signature_len_out: Signature length (can be NULL if not needed)
 * @param timestamp_out: v0.08: Message timestamp (can be NULL if not needed)
 * @return: DNA_OK on success, error code otherwise
 */
dna_error_t dna_decrypt_message_raw(
    dna_context_t *ctx,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *recipient_enc_privkey,
    uint8_t **plaintext_out,
    size_t *plaintext_len_out,
    uint8_t **sender_sign_pubkey_out,
    size_t *sender_sign_pubkey_len_out,
    uint8_t **signature_out,
    size_t *signature_len_out,
    uint64_t *timestamp_out
);

// ============================================================================
// SIGNATURE OPERATIONS
// ============================================================================

/**
 * Sign message
 *
 * @param ctx: DNA context
 * @param message: Message to sign
 * @param message_len: Message length
 * @param signer_key_name: Signer's key name (from keyring)
 * @param signature_out: Output signature buffer (caller must free)
 * @param signature_len_out: Output signature length
 * @return: DNA_OK on success, error code otherwise
 */
dna_error_t dna_sign_message(
    dna_context_t *ctx,
    const uint8_t *message,
    size_t message_len,
    const char *signer_key_name,
    uint8_t **signature_out,
    size_t *signature_len_out
);

/**
 * Verify message signature
 *
 * @param ctx: DNA context
 * @param message: Message that was signed
 * @param message_len: Message length
 * @param signature: Signature to verify
 * @param signature_len: Signature length
 * @param signer_pubkey: Signer's public key (from decrypt or contact)
 * @param signer_pubkey_len: Public key length
 * @return: DNA_OK if valid, DNA_ERROR_VERIFY if invalid
 */
dna_error_t dna_verify_message(
    dna_context_t *ctx,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *signer_pubkey,
    size_t signer_pubkey_len
);

// ============================================================================
// KEY MANAGEMENT
// ============================================================================

// NOTE: dna_load_key() and dna_load_pubkey() removed in v0.3.150
// They used broken keyring stubs that always returned NULL.
// Keys are now managed through dna_engine identity system.

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Get key fingerprint (SHA256 hash)
 *
 * @param key_data: Key data
 * @param key_len: Key length
 * @param fingerprint_out: Output fingerprint (32 bytes, caller must allocate)
 * @return: DNA_OK on success
 */
dna_error_t dna_key_fingerprint(
    const uint8_t *key_data,
    size_t key_len,
    uint8_t fingerprint_out[32]
);

/**
 * Fingerprint to hex string
 *
 * @param fingerprint: Fingerprint (32 bytes)
 * @param hex_out: Output hex string (65 bytes, caller must allocate)
 * @return: DNA_OK on success
 */
dna_error_t dna_fingerprint_to_hex(
    const uint8_t fingerprint[32],
    char hex_out[65]
);

// ============================================================================
// GROUP MESSAGING WITH GSK (Phase 13 - v0.09)
// ============================================================================

/**
 * Encrypt message with Group Symmetric Key (GSK)
 *
 * Encrypts a group message using AES-256-GCM with the active GSK.
 * Much more efficient than per-recipient encryption for large groups.
 *
 * Message Format (MSG_TYPE_GROUP_GSK = 0x01):
 * [Header: version(1) | enc_key_type(1) | recipient_count(1) | message_type(1) |
 *          encrypted_size(4) | signature_size(4)]
 * [Group UUID (37 bytes)]
 * [GSK Version (4 bytes, network byte order)]
 * [Nonce (12 bytes)]
 * [Ciphertext: sender_fingerprint(64) || timestamp(8) || plaintext]
 * [Tag (16 bytes)]
 * [Signature: type(1) | sig_size(2) | sig(~4595)]
 *
 * Size: 12-byte header + 37 + 4 + 12 + (64 + 8 + plaintext_len) + 16 + 4598
 *     = 4,751 + plaintext_len bytes (vs 1,608 × N for per-recipient)
 *
 * @param ctx: DNA context
 * @param plaintext: Message plaintext
 * @param plaintext_len: Plaintext length
 * @param group_uuid: Group UUID (36-char UUID v4 string)
 * @param gsk: Group symmetric key (32 bytes)
 * @param gsk_version: GSK version number
 * @param sender_fingerprint: Sender's fingerprint (64 bytes binary)
 * @param sender_sign_privkey: Sender's Dilithium5 private key (for signing)
 * @param timestamp: Message timestamp (Unix time, uint64_t)
 * @param ciphertext_out: Output ciphertext buffer (caller must free)
 * @param ciphertext_len_out: Output ciphertext length
 * @return: DNA_OK on success, error code otherwise
 */
dna_error_t dna_encrypt_message_gsk(
    dna_context_t *ctx,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const char *group_uuid,
    const uint8_t gsk[32],
    uint32_t gsk_version,
    const uint8_t sender_fingerprint[64],
    const uint8_t *sender_sign_privkey,
    uint64_t timestamp,
    uint8_t **ciphertext_out,
    size_t *ciphertext_len_out
);

/**
 * Decrypt message with Group Symmetric Key (GSK)
 *
 * Decrypts a group message encrypted with AES-256-GCM + GSK.
 * Verifies Dilithium5 signature.
 *
 * @param ctx: DNA context
 * @param ciphertext: Message ciphertext
 * @param ciphertext_len: Ciphertext length
 * @param gsk: Group symmetric key (32 bytes)
 * @param sender_dilithium_pubkey: Sender's Dilithium5 public key (for signature verification)
 * @param plaintext_out: Output plaintext buffer (caller must free)
 * @param plaintext_len_out: Output plaintext length
 * @param sender_fingerprint_out: Sender's fingerprint (64 bytes, caller must allocate or pass NULL)
 * @param timestamp_out: Message timestamp (can be NULL if not needed)
 * @param group_uuid_out: Group UUID (37 bytes, caller must allocate or pass NULL)
 * @param gsk_version_out: GSK version (can be NULL if not needed)
 * @return: DNA_OK on success, error code otherwise
 */
dna_error_t dna_decrypt_message_gsk(
    dna_context_t *ctx,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t gsk[32],
    const uint8_t *sender_dilithium_pubkey,
    uint8_t **plaintext_out,
    size_t *plaintext_len_out,
    uint8_t sender_fingerprint_out[64],
    uint64_t *timestamp_out,
    char group_uuid_out[37],
    uint32_t *gsk_version_out
);

// ============================================================================
// FUTURE API (Phase 3+)
// ============================================================================

/*
 * Contact Management (Phase 3):
 * - dna_contact_add()
 * - dna_contact_list()
 * - dna_contact_delete()
 * - dna_contact_get_info()
 *
 * Message Storage (Phase 3):
 * - dna_message_save()
 * - dna_message_load()
 * - dna_conversation_list()
 * - dna_conversation_get_messages()
 *
 * Session Management (Phase 7):
 * - dna_session_create()
 * - dna_session_rotate()
 * - dna_session_close()
 */

#ifdef __cplusplus
}
#endif

#endif // DNA_API_H
