/**
 * @file eth_eip712.h
 * @brief EIP-712 Typed Data Signing
 *
 * Generic EIP-712 structured data signing for Ethereum.
 * Used by: Permit2, meta-transactions, off-chain order protocols.
 *
 * @author DNA Connect Team
 */

#ifndef ETH_EIP712_H
#define ETH_EIP712_H

#include <stdint.h>
#include <stddef.h>

/**
 * Compute an EIP-712 domain separator.
 *
 * domainSeparator = keccak256(
 *   keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
 *   || keccak256(name)
 *   || keccak256(version)
 *   || uint256(chainId)
 *   || uint256(verifyingContract)
 * )
 *
 * @param name                 Domain name (e.g., "Uniswap", "Gnosis Protocol")
 * @param version              Domain version (e.g., "v2", "1")
 * @param chain_id             Chain ID (1 = mainnet)
 * @param verifying_contract   Contract address, 0x-prefixed hex (42 chars)
 * @param domain_hash_out      Output: 32-byte domain separator hash
 * @return                     0 on success, -1 on error
 */
int eip712_compute_domain_separator(
    const char *name,
    const char *version,
    uint64_t chain_id,
    const char *verifying_contract,
    uint8_t domain_hash_out[32]
);

/**
 * Sign an EIP-712 typed data hash with secp256k1.
 *
 * Computes: keccak256("\x19\x01" || domainSeparator || structHash)
 * Then signs the result with the private key.
 *
 * @param private_key       32-byte secp256k1 private key
 * @param domain_separator  32-byte domain separator (from eip712_compute_domain_separator)
 * @param struct_hash       32-byte struct hash (keccak256 of encoded struct data)
 * @param sig_out           Output: 65 bytes — r(32) + s(32) + v(1)
 * @return                  0 on success, -1 on error
 */
int eip712_sign_typed_data(
    const uint8_t private_key[32],
    const uint8_t domain_separator[32],
    const uint8_t struct_hash[32],
    uint8_t sig_out[65]
);

/**
 * Parse hex string to bytes.
 *
 * Handles optional 0x prefix. Requires exact length match.
 *
 * @param hex       Hex string (with or without 0x prefix)
 * @param out       Output byte buffer
 * @param out_len   Expected byte count (hex must be 2 * out_len chars)
 * @return          0 on success, -1 on error
 */
int eth_hex_to_bytes(const char *hex, uint8_t *out, size_t out_len);

/**
 * Write a raw decimal string as uint256 big-endian (32 bytes).
 * Supports values up to 128-bit.
 *
 * @param str   Decimal string (e.g., "1000000000000000000")
 * @param out   Output: 32-byte big-endian uint256
 */
void eth_decimal_to_uint256(const char *str, uint8_t out[32]);

#endif /* ETH_EIP712_H */
