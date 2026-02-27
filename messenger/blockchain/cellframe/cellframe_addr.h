/*
 * cellframe_addr.h - Cellframe Address Generation
 *
 * Generates Cellframe blockchain addresses from Dilithium keys
 */

#ifndef CELLFRAME_ADDR_H
#define CELLFRAME_ADDR_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Cellframe network IDs
#define CELLFRAME_NET_BACKBONE  0x0404202200000000ULL
#define CELLFRAME_NET_KELVPN    0x1807202300000000ULL

// Dilithium signature type in Cellframe
#define CELLFRAME_SIG_DILITHIUM 0x0102

// Address structure size (matches cellframe_tx.h definition)
#define CELLFRAME_ADDR_SIZE 77  // Wire format size (base58-decoded addresses are 77 bytes)
#define CELLFRAME_ADDR_STR_MAX 120  // Base58 encoded string

/**
 * Generate Cellframe address from public key
 *
 * @param pubkey - Dilithium public key data
 * @param pubkey_size - Public key size in bytes
 * @param net_id - Network ID (e.g. CELLFRAME_NET_BACKBONE)
 * @param address_out - Output buffer for base58 address (must be at least CELLFRAME_ADDR_STR_MAX bytes)
 * @return 0 on success, -1 on error
 */
int cellframe_addr_from_pubkey(const uint8_t *pubkey, size_t pubkey_size,
                                 uint64_t net_id, char *address_out);

/**
 * Get Cellframe address for current DNA identity
 *
 * Reads the public key from ~/.dna/[identity]-dilithium3.pqkey
 *
 * @param identity - Identity name (e.g. "nocdem")
 * @param net_id - Network ID (e.g. CELLFRAME_NET_BACKBONE)
 * @param address_out - Output buffer for base58 address (must be at least CELLFRAME_ADDR_STR_MAX bytes)
 * @return 0 on success, -1 on error
 */
int cellframe_addr_for_identity(const char *identity, uint64_t net_id, char *address_out);

/**
 * Convert binary Cellframe address to base58 string
 *
 * @param addr - Binary address structure
 * @param str_out - Output buffer for base58 string (must be at least CELLFRAME_ADDR_STR_MAX bytes)
 * @param str_max - Size of output buffer
 * @return 0 on success, -1 on error
 */
int cellframe_addr_to_str(const void *addr, char *str_out, size_t str_max);

/**
 * Parse base58 string to binary Cellframe address
 *
 * @param str - Base58 address string
 * @param addr_out - Output binary address structure
 * @return 0 on success, -1 on error
 */
int cellframe_addr_from_str(const char *str, void *addr_out);

#ifdef __cplusplus
}
#endif

#endif /* CELLFRAME_ADDR_H */
