/**
 * @file anchor_verify.c
 * @brief Verifies a block header + 2f+1 PRECOMMIT signatures against
 *        a trusted roster.
 *
 * An anchor is only valid if:
 *   1. The block header, re-hashed from its fields, matches
 *      anchor->header.block_hash (prevents a malicious peer from pairing
 *      a fake block_hash with real sigs).
 *   2. At least (2*N/3 + 1) distinct roster witnesses have signed the
 *      recomputed block_hash with valid Dilithium5 (ML-DSA-87) signatures.
 *   3. No duplicate signers are counted (one signature per witness slot).
 *
 * Pure function — no DB, no network, no allocation beyond sig verify.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/ledger.h"
#include "dnac/block.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdbool.h>
#include <string.h>

/* Look up a witness in the roster by signer_id (first DNAC_WITNESS_ID_SIZE
 * bytes of SHA3-512(pubkey)). Returns roster index or -1 if not found. */
static int find_signer_in_roster(const uint8_t signer_id[DNAC_WITNESS_ID_SIZE],
                                 const dnac_chain_definition_t *cd)
{
    uint8_t fp[QGP_SHA3_512_DIGEST_LENGTH];
    for (uint32_t r = 0; r < cd->witness_count; r++) {
        if (qgp_sha3_512(cd->witness_pubkeys[r], DNAC_PUBKEY_SIZE, fp) != 0) {
            continue;
        }
        if (memcmp(fp, signer_id, DNAC_WITNESS_ID_SIZE) == 0) {
            return (int)r;
        }
    }
    return -1;
}

bool dnac_anchor_verify(const dnac_block_anchor_t *anchor,
                        const dnac_trusted_state_t *trust)
{
    if (!anchor || !trust) return false;

    /* 1. Recompute block hash from header fields, compare to stored hash. */
    dnac_block_t recomputed = anchor->header;
    if (dnac_block_compute_hash(&recomputed) != 0) return false;
    if (memcmp(recomputed.block_hash, anchor->header.block_hash,
               DNAC_BLOCK_HASH_SIZE) != 0) {
        return false;
    }

    /* 2. Compute quorum: floor(2N/3) + 1. For N=7 -> 5. For N=21 -> 15. */
    const uint32_t n = trust->chain_def.witness_count;
    if (n == 0) return false;
    if (n > DNAC_MAX_WITNESSES_COMPILE_CAP) return false;
    if (anchor->sig_count <= 0) return false;
    if (anchor->sig_count > DNAC_MAX_WITNESSES_COMPILE_CAP) return false;

    const uint32_t quorum = (2 * n) / 3 + 1;
    if ((uint32_t)anchor->sig_count < quorum) return false;

    /* 3. Verify each sig, de-dup by roster index. */
    bool     seen[DNAC_MAX_WITNESSES_COMPILE_CAP] = { false };
    uint32_t valid_count = 0;

    for (int i = 0; i < anchor->sig_count; i++) {
        const dnac_witness_signature_t *sig = &anchor->sigs[i];

        int idx = find_signer_in_roster(sig->signer_id, &trust->chain_def);
        if (idx < 0) continue;           /* unknown signer */
        if (seen[idx]) continue;         /* duplicate signer */

        /* qgp_dsa87_verify returns 0 on valid signature. */
        if (qgp_dsa87_verify(sig->signature, DNAC_DILITHIUM5_SIG_SIZE,
                             anchor->header.block_hash, DNAC_BLOCK_HASH_SIZE,
                             trust->chain_def.witness_pubkeys[idx]) == 0) {
            seen[idx] = true;
            valid_count++;
            if (valid_count >= quorum) return true;  /* early exit */
        }
    }

    return valid_count >= quorum;
}
