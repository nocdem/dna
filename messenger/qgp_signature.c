/*
 * qgp_signature.c - QGP Signature Management 
 *
 * Signature memory management and manipulation.
 * Uses QGP's own signature format with no external dependencies.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qgp_types.h"

// ============================================================================
// SIGNATURE MEMORY MANAGEMENT
// ============================================================================

/**
 * Create a new QGP signature structure
 *
 * @param type: Signature algorithm type
 * @param pkey_size: Public key size in bytes
 * @param sig_size: Signature size in bytes
 * @return: Allocated signature structure (caller must free with qgp_signature_free())
 */
qgp_signature_t* qgp_signature_new(qgp_sig_type_t type, uint16_t pkey_size, uint16_t sig_size) {
    qgp_signature_t *sig = QGP_CALLOC(1, sizeof(qgp_signature_t));
    if (!sig) {
        return NULL;
    }

    sig->type = type;
    sig->public_key_size = pkey_size;
    sig->signature_size = sig_size;

    // Allocate data buffer for public key + signature
    size_t data_size = pkey_size + sig_size;
    sig->data = QGP_CALLOC(1, data_size);
    if (!sig->data) {
        QGP_FREE(sig);
        return NULL;
    }

    return sig;
}

/**
 * Free a QGP signature structure
 *
 * @param sig: Signature to free (can be NULL)
 */
void qgp_signature_free(qgp_signature_t *sig) {
    if (!sig) {
        return;
    }

    if (sig->data) {
        QGP_FREE(sig->data);
    }

    QGP_FREE(sig);
}

/**
 * Get signature total size (for serialization)
 *
 * @param sig: Signature structure
 * @return: Total size in bytes (header + public key + signature)
 */
size_t qgp_signature_get_size(const qgp_signature_t *sig) {
    if (!sig) {
        return 0;
    }

    // type(1) + pkey_size(2) + sig_size(2) + data
    return 5 + sig->public_key_size + sig->signature_size;
}

/**
 * Verify signature structure size
 *
 * @param sig: Signature structure
 * @param expected_size: Expected total size
 * @return: 0 if valid, -1 if invalid
 */
int qgp_signature_verify_size(const qgp_signature_t *sig, size_t expected_size) {
    if (!sig) {
        return -1;
    }

    size_t actual_size = qgp_signature_get_size(sig);
    if (actual_size != expected_size) {
        fprintf(stderr, "qgp_signature_verify_size: Size mismatch (expected %zu, got %zu)\n",
                expected_size, actual_size);
        return -1;
    }

    return 0;
}

/**
 * Serialize signature to buffer
 *
 * Format: [type(1) | pkey_size(2) | sig_size(2) | public_key | signature]
 *
 * @param sig: Signature to serialize
 * @param buffer: Output buffer (must be at least qgp_signature_get_size() bytes)
 * @return: Bytes written, or 0 on error
 */
size_t qgp_signature_serialize(const qgp_signature_t *sig, uint8_t *buffer) {
    if (!sig || !buffer) {
        return 0;
    }

    uint8_t *ptr = buffer;

    // Type (1 byte)
    *ptr++ = (uint8_t)sig->type;

    // Public key size (2 bytes, big-endian)
    *ptr++ = (sig->public_key_size >> 8) & 0xFF;
    *ptr++ = sig->public_key_size & 0xFF;

    // Signature size (2 bytes, big-endian)
    *ptr++ = (sig->signature_size >> 8) & 0xFF;
    *ptr++ = sig->signature_size & 0xFF;

    // Public key + signature data
    memcpy(ptr, sig->data, sig->public_key_size + sig->signature_size);
    ptr += sig->public_key_size + sig->signature_size;

    return ptr - buffer;
}

/**
 * Deserialize signature from buffer
 *
 * @param buffer: Input buffer
 * @param buffer_size: Buffer size
 * @param sig_out: Output signature (caller must free with qgp_signature_free())
 * @return: 0 on success, -1 on error
 */
int qgp_signature_deserialize(const uint8_t *buffer, size_t buffer_size, qgp_signature_t **sig_out) {
    if (!buffer || !sig_out || buffer_size < 5) {
        fprintf(stderr, "qgp_signature_deserialize: Invalid arguments\n");
        return -1;
    }

    const uint8_t *ptr = buffer;

    // Parse type
    qgp_sig_type_t type = (qgp_sig_type_t)(*ptr++);

    // Parse public key size (big-endian)
    uint16_t pkey_size = ((uint16_t)ptr[0] << 8) | ptr[1];
    ptr += 2;

    // Parse signature size (big-endian)
    uint16_t sig_size = ((uint16_t)ptr[0] << 8) | ptr[1];
    ptr += 2;

    // Validate sizes
    size_t expected_total = 5 + pkey_size + sig_size;
    if (buffer_size < expected_total) {
        fprintf(stderr, "qgp_signature_deserialize: Buffer too small (expected %zu, got %zu)\n",
                expected_total, buffer_size);
        return -1;
    }

    // Create signature structure
    qgp_signature_t *sig = qgp_signature_new(type, pkey_size, sig_size);
    if (!sig) {
        fprintf(stderr, "qgp_signature_deserialize: Memory allocation failed\n");
        return -1;
    }

    // Copy data
    memcpy(sig->data, ptr, pkey_size + sig_size);

    *sig_out = sig;
    return 0;
}
