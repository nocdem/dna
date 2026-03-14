#ifndef DNAC_CRYPTO_HELPERS_H
#define DNAC_CRYPTO_HELPERS_H

#include <stdint.h>
#include <stddef.h>

/**
 * Build DHT key for payment inbox
 * Key: SHA3-512("dnac:inbox:" + [chain_id_hex:] + owner_fingerprint)
 *
 * @param owner_fp  Owner fingerprint string (128 hex chars)
 * @param chain_id  Optional 32-byte chain ID for zone scoping (NULL = default)
 * @param key_out   Output buffer for 64-byte SHA3-512 key
 * @return 0 on success, -1 on error
 */
int dnac_build_inbox_key(const char *owner_fp, const uint8_t *chain_id,
                          uint8_t *key_out);

/**
 * Derive chain_id from genesis fingerprint and genesis tx_hash.
 * chain_id = SHA3-256(genesis_fingerprint_bytes || genesis_tx_hash)
 *
 * @param genesis_fp   Recipient identity fingerprint (128 hex chars, null-terminated)
 * @param tx_hash      Genesis transaction hash (64 bytes, SHA3-512)
 * @param chain_id_out Output buffer (32 bytes)
 * @return 0 on success, -1 on error
 */
int dnac_derive_chain_id(const char *genesis_fp,
                          const uint8_t *tx_hash,
                          uint8_t *chain_id_out);

#endif /* DNAC_CRYPTO_HELPERS_H */
