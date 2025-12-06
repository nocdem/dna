/*
 * cellframe_sign_minimal.h - Minimal Dilithium Signing for Cellframe
 *
 * Signs transactions with Dilithium MODE_1 matching Cellframe SDK exactly.
 */

#ifndef CELLFRAME_SIGN_MINIMAL_H
#define CELLFRAME_SIGN_MINIMAL_H

#include "cellframe_minimal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Build dap_sign_t structure from public key and signature
 *
 * This builds the complete structure expected by Cellframe:
 * [14-byte header][serialized_public_key][serialized_signature]
 *
 * @param pub_key Raw Dilithium public key OR serialized public key
 *                - If 1184 bytes: raw key (will add 12-byte serialization header)
 *                - If 1196 bytes: already serialized (used as-is)
 * @param pub_key_size Public key size (1184 or 1196)
 * @param signature Raw Dilithium signature OR serialized signature
 *                  - If 2044 bytes: detached signature (will wrap to ATTACHED 2076, then serialize to 2096)
 *                  - If 2076 bytes: attached signature (will serialize to 2096)
 *                  - If 2096 bytes: already serialized (used as-is)
 * @param sig_size Signature size (2044, 2076, or 2096)
 * @param dap_sign_out Output dap_sign_t structure (caller must free)
 * @param dap_sign_size_out Output size (should be 3306 bytes)
 * @return 0 on success, -1 on error
 */
int cellframe_build_dap_sign_t(const uint8_t *pub_key, size_t pub_key_size,
                                 const uint8_t *signature, size_t sig_size,
                                 uint8_t **dap_sign_out, size_t *dap_sign_size_out);

/**
 * Sign transaction binary with Dilithium MODE_1
 *
 * Process:
 * 1. Hash transaction binary (SHA3-256)
 * 2. Sign hash with Dilithium private key
 * 3. Build dap_sign_t structure
 *
 * @param tx_data Transaction binary data
 * @param tx_size Transaction size
 * @param priv_key Dilithium private key (serialized, with 12-byte header)
 * @param priv_key_size Private key size (should be 3856 bytes with header)
 * @param pub_key Dilithium public key (serialized, with 12-byte header)
 * @param pub_key_size Public key size (should be 1196 bytes with header)
 * @param dap_sign_out Output dap_sign_t structure (caller must free)
 * @param dap_sign_size_out Output size (should be 3306 bytes)
 * @return 0 on success, -1 on error
 */
int cellframe_sign_transaction(const uint8_t *tx_data, size_t tx_size,
                                 const uint8_t *priv_key, size_t priv_key_size,
                                 const uint8_t *pub_key, size_t pub_key_size,
                                 uint8_t **dap_sign_out, size_t *dap_sign_size_out);

/**
 * SHA3-256 hash
 * @param data Input data
 * @param data_len Input length
 * @param hash Output hash (32 bytes)
 */
void cellframe_sha3_256(const uint8_t *data, size_t data_len, uint8_t hash[32]);

#ifdef __cplusplus
}
#endif

#endif /* CELLFRAME_SIGN_MINIMAL_H */
