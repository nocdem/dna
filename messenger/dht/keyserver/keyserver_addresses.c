/**
 * DHT Keyserver - Address Resolution
 * Handles resolving DNA names to wallet addresses
 */

#include "keyserver_core.h"
#include "../core/dht_keyserver.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "KEYSERVER"

// Resolve DNA name to wallet address
int dna_resolve_address(
    dht_context_t *dht_ctx,
    const char *name,
    const char *network,
    char **address_out
) {
    if (!dht_ctx || !name || !network || !address_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to dna_resolve_address\n");
        return -1;
    }

    // Check if input is already a fingerprint (128 hex chars)
    char *fingerprint = NULL;
    bool is_fingerprint = (strlen(name) == 128);

    if (is_fingerprint) {
        // Validate it's all hex
        for (size_t i = 0; i < 128; i++) {
            if (!isxdigit(name[i])) {
                is_fingerprint = false;
                break;
            }
        }
    }

    if (is_fingerprint) {
        // Direct fingerprint lookup
        fingerprint = strdup(name);
    } else {
        // Look up name → fingerprint
        int ret = dna_lookup_by_name(dht_ctx, name, &fingerprint);
        if (ret != 0) {
            return ret;  // -1 error, -2 not found
        }
    }

    // Load identity
    dna_unified_identity_t *identity = NULL;
    int ret = dna_load_identity(dht_ctx, fingerprint, &identity);
    free(fingerprint);

    if (ret != 0) {
        return ret;  // -1 error, -2 not found, -3 verification failed
    }

    // Get wallet address for network
    const char *address = dna_identity_get_wallet(identity, network);

    if (!address || address[0] == '\0') {
        QGP_LOG_ERROR(LOG_TAG, "No address for network '%s'\n", network);
        dna_identity_free(identity);
        return -3;  // No address for network
    }

    char *result = strdup(address);
    dna_identity_free(identity);

    if (!result) {
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "✓ Resolved: %s → %s on %s\n", name, result, network);

    *address_out = result;
    return 0;
}
