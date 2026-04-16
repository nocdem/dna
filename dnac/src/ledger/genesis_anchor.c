/**
 * @file genesis_anchor.c
 * @brief Hardcoded chain registry
 *
 * Placeholder chain_id (all zeros) until hard fork produces the real
 * value in Phase 13. Until then, attempts to verify genesis will fail
 * and the client cannot connect to any chain — this is intentional
 * (better to fail loudly than silently trust a wrong chain).
 */

#include "dnac/genesis_anchor.h"

const dnac_known_chain_t DNAC_KNOWN_CHAINS[] = {
    {
        .name = "main",
        /* PLACEHOLDER — will be replaced with real chain_id at hard fork.
         * This zero-filled value will fail verification, blocking the
         * client from connecting to any chain until the hard fork happens. */
        .chain_id = { 0 },
    },
};

const size_t DNAC_KNOWN_CHAINS_COUNT =
    sizeof(DNAC_KNOWN_CHAINS) / sizeof(DNAC_KNOWN_CHAINS[0]);
