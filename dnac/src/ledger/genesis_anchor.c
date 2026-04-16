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
        /* chain_id = SHA3-256(genesis_fp || genesis_tx_hash)
         * Genesis submitted 2026-04-16, 7 witnesses, 1B DNAC supply.
         * Witness DB: witness_b74acae6952c51bfb61f8b5bd0236ce5.db */
        .chain_id = {
            0xb7, 0x4a, 0xca, 0xe6, 0x95, 0x2c, 0x51, 0xbf,
            0xb6, 0x1f, 0x8b, 0x5b, 0xd0, 0x23, 0x6c, 0xe5,
            0x84, 0x15, 0x4a, 0xbc, 0xb6, 0x4b, 0xb3, 0xde,
            0xd9, 0xed, 0xf1, 0x98, 0xd7, 0x33, 0x19, 0x17,
        },
    },
};

const size_t DNAC_KNOWN_CHAINS_COUNT =
    sizeof(DNAC_KNOWN_CHAINS) / sizeof(DNAC_KNOWN_CHAINS[0]);
