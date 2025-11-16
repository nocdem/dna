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
 * Contains OpenDHT RSA-2048 identity (private key + certificate)
 * Used for DHT node authentication and encrypted backup system
 */
typedef struct dht_identity dht_identity_t;

/**
 * Generate random DHT identity (RSA-2048)
 *
 * @param identity_out Output pointer for new identity
 * @return 0 on success, -1 on error
 */
int dht_identity_generate_random(dht_identity_t **identity_out);

/**
 * Export identity to buffer (PEM format)
 *
 * Format: [key_pem_size(4)][key_pem][cert_pem_size(4)][cert_pem]
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
 * Import identity from buffer (PEM format)
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
