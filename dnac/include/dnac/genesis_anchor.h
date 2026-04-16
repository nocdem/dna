/**
 * @file genesis_anchor.h
 * @brief Hardcoded chain trust roots (chain_id constants)
 *
 * This is the ONLY hardcoded trust value in the DNAC client. Each entry
 * is a chain_id (= genesis block SHA3-512 hash). At runtime, the client
 * fetches the genesis block from any peer and verifies its hash matches
 * a known chain_id before trusting any of its contents.
 *
 * Adding a new chain (e.g. a zone): append to DNAC_KNOWN_CHAINS[] and
 * rebuild the client. No verifier code changes needed.
 */

#ifndef DNAC_GENESIS_ANCHOR_H
#define DNAC_GENESIS_ANCHOR_H

#include "dnac/block.h"
#include <stddef.h>

typedef struct {
    const char *name;                                  /* "main", "cpunk-zone" */
    uint8_t     chain_id[DNAC_BLOCK_HASH_SIZE];        /* genesis block hash */
} dnac_known_chain_t;

extern const dnac_known_chain_t DNAC_KNOWN_CHAINS[];
extern const size_t             DNAC_KNOWN_CHAINS_COUNT;

#endif /* DNAC_GENESIS_ANCHOR_H */
