/**
 * @file discovery.c
 * @brief Nodus server discovery via DHT
 */

#include "dnac/nodus.h"
#include <stdlib.h>
#include <string.h>

/* DHT key for Nodus server list */
#define NODUS_DHT_KEY "dna:system:nodus-servers"

int dnac_nodus_discover(dnac_context_t *ctx,
                        dnac_nodus_info_t **servers_out,
                        int *count_out) {
    if (!ctx || !servers_out || !count_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *servers_out = NULL;
    *count_out = 0;

    /* TODO: Query DHT for Nodus server list */
    /* Key: SHA3-512("dna:system:nodus-servers") */

    /* For now, return hardcoded bootstrap Nodus servers */
    /* These are the same as DNA Messenger bootstrap nodes */

    return DNAC_ERROR_NOT_INITIALIZED;
}

int dnac_get_nodus_list(dnac_context_t *ctx,
                        dnac_nodus_info_t **servers,
                        int *count) {
    return dnac_nodus_discover(ctx, servers, count);
}

void dnac_free_nodus_list(dnac_nodus_info_t *servers, int count) {
    (void)count;
    free(servers);
}

int dnac_check_nullifier(dnac_context_t *ctx,
                         const uint8_t *nullifier,
                         bool *is_spent) {
    return dnac_nodus_check_nullifier(ctx, nullifier, is_spent);
}
