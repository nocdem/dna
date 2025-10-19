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

// Address structure size
#define CELLFRAME_ADDR_SIZE 73  // 1 + 8 + 2 + 32 + 32 = 75 bytes (before base58)
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
 * Reads the public key from ~/.dna/[identity]-dilithium.pqkey
 *
 * @param identity - Identity name (e.g. "nocdem")
 * @param net_id - Network ID (e.g. CELLFRAME_NET_BACKBONE)
 * @param address_out - Output buffer for base58 address (must be at least CELLFRAME_ADDR_STR_MAX bytes)
 * @return 0 on success, -1 on error
 */
int cellframe_addr_for_identity(const char *identity, uint64_t net_id, char *address_out);

#ifdef __cplusplus
}
#endif

#endif /* CELLFRAME_ADDR_H */
