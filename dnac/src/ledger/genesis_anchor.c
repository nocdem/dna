/**
 * @file genesis_anchor.c
 * @brief Hardcoded chain registry
 *
 * Each entry is a chain_id (= SHA3-512 of the genesis block preimage
 * including chain_def). This is the ONLY hardcoded trust value in the
 * DNAC client — everything else is derived at runtime via
 * dnac_genesis_verify.
 */

#include "dnac/genesis_anchor.h"

const dnac_known_chain_t DNAC_KNOWN_CHAINS[] = {
    {
        .name = "devnet",
        /* TEMPORARILY zeroed — the 32-byte old chain_id (SHA3-256) doesn't
         * match the 64-byte DNAC_BLOCK_HASH_SIZE field. The real anchored
         * chain_id (SHA3-512 of genesis block with chain_def) hasn't been
         * queried from the cluster yet. Leaving zeros skips the bootstrap
         * in wallet init so messaging isn't blocked.
         *
         * TODO: query the cluster for genesis block 0's block_hash (64 bytes)
         * via handle_dnac_genesis, paste here, and re-enable bootstrap. */
        .chain_id = { 0 },
    },
};

const size_t DNAC_KNOWN_CHAINS_COUNT =
    sizeof(DNAC_KNOWN_CHAINS) / sizeof(DNAC_KNOWN_CHAINS[0]);
