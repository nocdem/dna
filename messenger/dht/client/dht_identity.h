#ifndef DHT_IDENTITY_H
#define DHT_IDENTITY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque DHT identity structure
 *
 * Contains OpenDHT-PQ Dilithium5 identity (private key + certificate)
 * Used for DHT node authentication and encrypted backup system
 *
 * FIPS 204 - ML-DSA-87 - NIST Category 5 (256-bit quantum resistance)
 */
typedef struct dht_identity dht_identity_t;

/**
 * Generate random DHT identity (Dilithium5 - ML-DSA-87)
 *
 * Post-quantum signature scheme with 256-bit quantum resistance
 * FIPS 204 compliant, NIST Category 5 security level
 *
 * @param identity_out Output pointer for new identity
 * @return 0 on success, -1 on error
 */
int dht_identity_generate_dilithium5(dht_identity_t **identity_out);

/**
 * Generate random DHT identity (legacy wrapper)
 *
 * DEPRECATED: This function now generates Dilithium5 identities instead of RSA
 * Use dht_identity_generate_dilithium5() for new code
 *
 * @param identity_out Output pointer for new identity
 * @return 0 on success, -1 on error
 */
int dht_identity_generate_random(dht_identity_t **identity_out);

/**
 * Export identity to buffer (binary format - Dilithium5)
 *
 * Format: [key_size(4)][dilithium5_key][cert_size(4)][dilithium5_cert]
 * Binary format (not PEM) for compact Dilithium5 key storage
 * Buffer is allocated and must be freed by caller.
 *
 * @param identity Identity to export
 * @param buffer_out Output buffer pointer
 * @param buffer_size_out Output buffer size
 * @return 0 on success, -1 on error
 */
int dht_identity_export_to_buffer(
    dht_identity_t *identity,
    uint8_t **buffer_out,
    size_t *buffer_size_out);

/**
 * Import identity from buffer (binary format - Dilithium5)
 *
 * @param buffer Input buffer containing exported identity
 * @param buffer_size Size of input buffer
 * @param identity_out Output pointer for imported identity
 * @return 0 on success, -1 on error
 */
int dht_identity_import_from_buffer(
    const uint8_t *buffer,
    size_t buffer_size,
    dht_identity_t **identity_out);

/**
 * Free DHT identity
 *
 * @param identity Identity to free (may be NULL)
 */
void dht_identity_free(dht_identity_t *identity);

#ifdef __cplusplus
}
#endif

#endif // DHT_IDENTITY_H
