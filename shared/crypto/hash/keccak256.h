/**
 * @file keccak256.h
 * @brief Keccak-256 hash function (Ethereum variant)
 *
 * IMPORTANT: This is Keccak-256 (original Keccak with padding 0x01),
 * NOT SHA3-256 (NIST standardized with padding 0x06).
 *
 * Ethereum uses original Keccak-256 for:
 * - Address derivation from public key
 * - Transaction hashing
 * - Contract address computation
 *
 * @author DNA Messenger Team
 * @date 2025-12-08
 */

#ifndef KECCAK256_H
#define KECCAK256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Output sizes */
#define KECCAK256_DIGEST_SIZE   32      /* 256 bits = 32 bytes */
#define KECCAK256_HEX_SIZE      65      /* 64 hex chars + null */

/* Ethereum address sizes */
#define ETH_ADDRESS_SIZE        20      /* 160 bits = 20 bytes */
#define ETH_ADDRESS_HEX_SIZE    43      /* "0x" + 40 hex chars + null */

/**
 * Compute Keccak-256 hash (Ethereum variant)
 *
 * Uses padding byte 0x01 (original Keccak), NOT 0x06 (NIST SHA3).
 *
 * @param data      Input data to hash
 * @param len       Length of input data in bytes
 * @param hash_out  Output buffer for hash (must be at least 32 bytes)
 * @return          0 on success, -1 on error
 */
int keccak256(const uint8_t *data, size_t len, uint8_t hash_out[32]);

/**
 * Compute Keccak-256 hash and return as hex string
 *
 * @param data      Input data to hash
 * @param len       Length of input data in bytes
 * @param hex_out   Output buffer for hex string (must be at least 65 bytes)
 * @return          0 on success, -1 on error
 */
int keccak256_hex(const uint8_t *data, size_t len, char hex_out[65]);

/**
 * Derive Ethereum address from uncompressed secp256k1 public key
 *
 * Address = Keccak256(pubkey[1:65])[-20:]
 * The public key must be 65 bytes (0x04 || x || y).
 * We hash bytes 1-64 (skip the 0x04 prefix) and take last 20 bytes.
 *
 * @param pubkey_uncompressed   65-byte uncompressed public key (04 || x || y)
 * @param address_out           Output: 20-byte Ethereum address
 * @return                      0 on success, -1 on error
 */
int eth_address_from_pubkey(
    const uint8_t pubkey_uncompressed[65],
    uint8_t address_out[20]
);

/**
 * Derive Ethereum address and format as hex string with checksum
 *
 * Returns address in EIP-55 checksummed format: "0xAbCd..."
 *
 * @param pubkey_uncompressed   65-byte uncompressed public key
 * @param address_hex_out       Output: checksummed address string (43 bytes min)
 * @return                      0 on success, -1 on error
 */
int eth_address_from_pubkey_hex(
    const uint8_t pubkey_uncompressed[65],
    char address_hex_out[43]
);

/**
 * Apply EIP-55 checksum to Ethereum address
 *
 * Converts lowercase hex address to mixed-case checksummed format.
 *
 * @param address_lowercase     40-char lowercase hex address (without 0x)
 * @param address_checksummed   Output: 40-char checksummed address (without 0x)
 * @return                      0 on success, -1 on error
 */
int eth_address_checksum(
    const char *address_lowercase,
    char address_checksummed[41]
);

/**
 * Validate Ethereum address checksum (EIP-55)
 *
 * @param address   Address string with or without "0x" prefix
 * @return          1 if valid checksum, 0 if invalid or all lowercase
 */
int eth_address_verify_checksum(const char *address);

#ifdef __cplusplus
}
#endif

#endif /* KECCAK256_H */
