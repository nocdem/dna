/**
 * @file nodus/src/witness/nodus_witness_v2_qc.c
 * @brief Ledger V2 O13 — QC verification bound to committed authority.
 *
 * INACTIVE — see nodus_witness_v2_qc.h for the contract and the
 * FAULT-vs-VERDICT convention.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_qc.h"

#include <string.h>

#include "dnac/vset_wire.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_epoch.h"

int nodus_witness_v2_qc_verify(nodus_witness_t *w,
                               const dna_block_header_v2_t *hdr,
                               const dna_qc_v2_t *qc) {
    /* A NULL argument is a LOCAL programming fault, not a statement about
     * the block — there is no block here to judge. Reporting it as a
     * verdict (-1) would make a node with a caller bug vote a perfectly
     * valid block invalid instead of abstaining. Fail as a node fault.
     * (Independent review finding; the FAULT-vs-VERDICT contract in the
     * header is only meaningful if the trivial cases obey it too.) */
    if (!w || !hdr || !qc) return -2;

    /* 1. Version gate. The retired version and any unknown version both
     *    fail closed; a v2 header must never be reinterpreted here. */
    /* O15A (reviewer R1): report the two version classes the season
     * created, not a generic verdict. The seam dispatches on the encoded
     * byte before reaching here, so this is currently unreachable through
     * it — but a SECOND caller of this function would otherwise silently
     * lose the retired-vs-unsupported distinction. */
    if (hdr->header_version == DNA_BH2_VERSION_RETIRED)
        return NODUS_V2_RETIRED_VERSION;
    if (hdr->header_version != DNA_BH2_VERSION)
        return NODUS_V2_UNSUPPORTED_VERSION;

    /* 2. The epoch field is VERIFIED, not trusted. Derived purely from
     *    the global height and the committed epoch length, so a header
     *    cannot select the epoch that selects its validator set. */
    if (hdr->epoch != nodus_v2_epoch_for_height(hdr->block_height))
        return -1;

    /* 3. Chain binding against the chain's OWN derived id. A missing
     *    genesis row is a node fault, not a verdict on this block. */
    uint8_t chain_id[DNA_CHAIN_ID_LEN];
    if (nodus_witness_v2_chain_id(w, chain_id) != 0) return -2;
    if (dna_bh2_check_chain(hdr, chain_id) != 0) return -1;

    /* 4. Authority resolved from COMMITTED state, keyed by height. No N
     *    and no quorum parameter exists on this path by construction. */
    dna_vset_snapshot_t *snap = NULL;
    uint32_t n = 0, quorum = 0;
    int arc = nodus_witness_v2_epoch_authority_for_height(w,
                                                          hdr->block_height,
                                                          &snap, &n, &quorum);
    if (arc != 0) {
        /* arc 1 = no committed authority for that epoch (TERMINAL — never
         * fall back to the current set); arc -1 = fault. Both mean THIS
         * NODE cannot decide, so both are -2. Never -1: a block is not
         * invalid merely because we lack its snapshot. */
        return -2;
    }
    if (!snap) return -2;

    int rc = -1;   /* default REJECT — every success path assigns 0 */

    /* 5. The header's validator_set_hash is a COMMITMENT that must equal
     *    the independently resolved authority. */
    uint8_t resolved_hash[DNA_VSET_HASH_LEN];
    if (dna_vset_hash(snap, resolved_hash) != 0) {
        rc = -2;                       /* hash backend failure = fault */
        goto done;
    }
    if (memcmp(hdr->validator_set_hash, resolved_hash,
               DNA_VSET_HASH_LEN) != 0) {
        rc = -1;                       /* header named a foreign set */
        goto done;
    }

    /* 6. The certified BlockID is computed HERE from the header — the
     *    caller cannot nominate the id the signatures are checked over. */
    uint8_t block_id[DNA_BH2_ID_LEN];
    if (dna_bh2_block_id(hdr, block_id) != 0) {
        rc = -2;                       /* hash backend failure = fault */
        goto done;
    }

    /* 7. Signature/membership/quorum verification against the resolved
     *    snapshot. Quorum is derived inside from the snapshot's
     *    active_count; stake is never consulted.
     *
     *    O15A: the verifier reports THREE classes, and this call site is
     *    the reason that matters. It used to collapse every non-zero
     *    return into -1, so an allocation failure inside the verifier's
     *    own dna_vset_hash — the very call this function performs forty
     *    lines above and correctly classifies as a fault — came back out
     *    here as CONSENSUS_INVALID. The map below is three-way, and the
     *    default for anything unrecognised is a fault, not a verdict:
     *    an unknown code is by definition something this node does not
     *    understand, which is exactly when it must abstain. */
    {
        int qrc = dna_qc_v2_verify(qc, block_id, hdr->block_height,
                                   chain_id, resolved_hash, snap);
        if (qrc == 0)                              rc = NODUS_V2_ACCEPTED;
        else if (qrc == NODUS_V2_CONSENSUS_INVALID) rc = NODUS_V2_CONSENSUS_INVALID;
        else                                        rc = NODUS_V2_INTERNAL_FAULT;
    }

done:
    dna_vset_free(&snap);
    return rc;
}
