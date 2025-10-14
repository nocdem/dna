/*
 * qgp_utils_standalone.c - QGP Utility Functions 
 *
 * Hash and Base64 utilities using OpenSSL.
 * Self-contained.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include "qgp_types.h"

// ============================================================================
// HASH UTILITIES
// ============================================================================

/**
 * Compute SHA256 hash of data
 *
 * @param hash: Output hash structure
 * @param data: Input data
 * @param len: Data length
 */
void qgp_hash_from_bytes(qgp_hash_t *hash, const uint8_t *data, size_t len) {
    if (!hash || !data) {
        return;
    }

    SHA256(data, len, hash->hash);
}

/**
 * Convert hash to hex string
 *
 * @param hash: Input hash
 * @param hex_out: Output hex string (must be at least 65 bytes)
 * @param hex_size: Size of output buffer
 */
void qgp_hash_to_hex(const qgp_hash_t *hash, char *hex_out, size_t hex_size) {
    if (!hash || !hex_out || hex_size < 65) {
        return;
    }

    // Add 0x prefix
    hex_out[0] = '0';
    hex_out[1] = 'x';

    // Convert each byte to hex
    for (int i = 0; i < 32; i++) {
        snprintf(&hex_out[2 + i * 2], 3, "%02X", hash->hash[i]);
    }

    hex_out[66] = '\0';
}

/**
 * Compute SHA256 hash of public key (for identification)
 *
 * @param public_key: Public key bytes
 * @param key_size: Public key size
 * @param hash_out: Output hash
 */
void qgp_pubkey_hash(const uint8_t *public_key, size_t key_size, qgp_hash_t *hash_out) {
    if (!public_key || !hash_out) {
        return;
    }

    qgp_hash_from_bytes(hash_out, public_key, key_size);
}

// ============================================================================
// BASE64 UTILITIES
// ============================================================================

/**
 * Encode data to Base64
 *
 * @param data: Input data
 * @param data_len: Input data length
 * @param out_len: Output length (set by function)
 * @return: Allocated Base64 string (caller must free), or NULL on error
 */
char* qgp_base64_encode(const uint8_t *data, size_t data_len, size_t *out_len) {
    if (!data || data_len == 0) {
        return NULL;
    }

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO *bio_b64 = BIO_new(BIO_f_base64());

    // Disable newlines in Base64 output
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);

    bio_b64 = BIO_push(bio_b64, bio_mem);

    // Write data
    BIO_write(bio_b64, data, data_len);
    BIO_flush(bio_b64);

    // Get encoded data
    BUF_MEM *buf_mem = NULL;
    BIO_get_mem_ptr(bio_b64, &buf_mem);

    // Allocate output buffer
    char *result = malloc(buf_mem->length + 1);
    if (result) {
        memcpy(result, buf_mem->data, buf_mem->length);
        result[buf_mem->length] = '\0';
        if (out_len) {
            *out_len = buf_mem->length;
        }
    }

    BIO_free_all(bio_b64);
    return result;
}

/**
 * Decode Base64 to binary data
 *
 * @param base64_str: Input Base64 string
 * @param out_len: Output length (set by function)
 * @return: Allocated binary data (caller must free), or NULL on error
 */
uint8_t* qgp_base64_decode(const char *base64_str, size_t *out_len) {
    if (!base64_str) {
        return NULL;
    }

    size_t input_len = strlen(base64_str);
    if (input_len == 0) {
        return NULL;
    }

    BIO *bio_mem = BIO_new_mem_buf(base64_str, input_len);
    BIO *bio_b64 = BIO_new(BIO_f_base64());

    // Disable newlines in Base64 input
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);

    bio_b64 = BIO_push(bio_b64, bio_mem);

    // Allocate output buffer (decoded data is smaller than Base64)
    size_t max_decoded_len = (input_len * 3) / 4 + 1;
    uint8_t *result = malloc(max_decoded_len);
    if (!result) {
        BIO_free_all(bio_b64);
        return NULL;
    }

    // Decode
    int decoded_len = BIO_read(bio_b64, result, max_decoded_len);
    if (decoded_len < 0) {
        free(result);
        BIO_free_all(bio_b64);
        return NULL;
    }

    if (out_len) {
        *out_len = decoded_len;
    }

    BIO_free_all(bio_b64);
    return result;
}

// ============================================================================
// STRING UTILITIES
// ============================================================================

/**
 * Convert bytes to hex string
 * Utility for debugging and display
 *
 * @param data: Input bytes
 * @param len: Data length
 * @param hex_out: Output hex string (must be at least len*2+1 bytes)
 */
void qgp_bytes_to_hex(const uint8_t *data, size_t len, char *hex_out) {
    if (!data || !hex_out) {
        return;
    }

    for (size_t i = 0; i < len; i++) {
        snprintf(&hex_out[i * 2], 3, "%02x", data[i]);
    }
    hex_out[len * 2] = '\0';
}

/**
 * Convert hex string to bytes
 * Utility for parsing hex input
 *
 * @param hex_str: Input hex string
 * @param data_out: Output bytes (caller must allocate)
 * @param max_len: Maximum bytes to write
 * @return: Bytes written, or -1 on error
 */
int qgp_hex_to_bytes(const char *hex_str, uint8_t *data_out, size_t max_len) {
    if (!hex_str || !data_out) {
        return -1;
    }

    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0) {
        return -1;  // Hex string must have even length
    }

    size_t byte_len = hex_len / 2;
    if (byte_len > max_len) {
        return -1;  // Output buffer too small
    }

    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte;
        if (sscanf(&hex_str[i * 2], "%2x", &byte) != 1) {
            return -1;  // Invalid hex character
        }
        data_out[i] = (uint8_t)byte;
    }

    return byte_len;
}
