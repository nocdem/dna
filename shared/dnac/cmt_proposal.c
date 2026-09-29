/**
 * @file shared/dnac/cmt_proposal.c
 * @brief cometbft @709fd12b `types/proposal.go` ported to C — see
 *        cmt_proposal.h for the contract and the taşınmadı list.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_proposal.h"
#include "dnac/cmt_params.h"   /* CMT_MAX_BLOCK_SIZE_BYTES, BlockPartSizeBytes */

#include <string.h>

/* cometbft@709fd12b types/proposal.go:35-46 — NewProposal().
 * `now` replaces the reference's cmttime.Now() at :44; see cmt_proposal.h. */
int cmt_new_proposal(int64_t height, int32_t round, int32_t pol_round,
                     const cmt_block_id_t *block_id, cmt_time_t now,
                     cmt_proposal_t *out)
{
    if (block_id == NULL || out == NULL) {
        return CMT_FAULT;
    }
    cmt_pb_proposal_init(out);
    out->type      = (int32_t)CMT_PB_MSG_TYPE_PROPOSAL;          /* :39  */
    out->height    = height;                                     /* :40  */
    out->round     = round;                                      /* :41  */
    out->block_id  = *block_id;                                  /* :42  */
    out->pol_round = pol_round;                                  /* :43  */
    out->timestamp = now;                                        /* :44  */
    /* The signature stays empty: a fresh proposal is unsigned. */
    return CMT_OK;
}

/* cometbft@709fd12b types/proposal.go:48-80 — (p *Proposal) ValidateBasic() */
int cmt_proposal_validate_basic(const cmt_proposal_t *p)
{
    if (p == NULL) {
        return CMT_FAULT;
    }
    if (p->type != (int32_t)CMT_PB_MSG_TYPE_PROPOSAL) {
        return CMT_REJECT;                                       /* :50-52 */
    }
    if (p->height < 0) {
        return CMT_REJECT;                                       /* :53-55 */
    }
    if (p->round < 0) {
        return CMT_REJECT;                                       /* :56-58 */
    }
    if (p->pol_round < -1) {
        return CMT_REJECT;                                       /* :59-61 */
    }
    if (cmt_block_id_validate_basic(&p->block_id) != CMT_OK) {
        return CMT_REJECT;                                       /* :62-64 */
    }
    /* :65-68 — ValidateBasic alone would pass an EMPTY BlockID, so the
     * proposal additionally requires a COMPLETE one. */
    if (!cmt_block_id_is_complete(&p->block_id)) {
        return CMT_REJECT;
    }
    /* :70 — "Timestamp validation is subtle and handled elsewhere." */
    if (p->signature_len == 0u) {
        return CMT_REJECT;                                       /* :72-74 */
    }
    if (p->signature_len > (size_t)CMT_MAX_SIGNATURE_SIZE) {
        return CMT_REJECT;                                       /* :76-78 */
    }
    return CMT_OK;
}

/* cometbft@v0.38.26 types/proposal.go:82-96 —
 * (p *Proposal) ValidateBlockSize(). New in v0.38.x (#5324). */
int cmt_proposal_validate_block_size(const cmt_proposal_t *p,
                                     int64_t max_block_size_bytes)
{
    int64_t total_parts;
    int64_t max_parts;

    if (p == NULL) {
        return CMT_FAULT;
    }
    if (max_block_size_bytes == -1) {                            /* :87 */
        max_block_size_bytes = (int64_t)CMT_MAX_BLOCK_SIZE_BYTES;/* :88 */
    }
    total_parts = (int64_t)p->block_id.part_set_header.total;    /* :90 */
    /* :91 `(maxBlockSizeBytes-1)/int64(BlockPartSizeBytes) + 1`. The
     * subtraction wraps in Go for INT64_MIN; C's would be undefined, so
     * it is carried in uint64 (the port's wrap pattern). Both divisions
     * truncate toward zero. The caller passes the consensus parameter
     * Block.MaxBytes, which ValidateConsensusParams keeps at -1 or
     * 1..MaxBlockSizeBytes, so the wrap is not reached from consensus. */
    max_parts = (int64_t)((uint64_t)max_block_size_bytes - 1u) /
                (int64_t)CMT_BLOCK_PART_SIZE_BYTES + 1;
    if (total_parts > max_parts) {                               /* :92 */
        /* :93 "proposal has too many parts". A proposal is a PEER's
         * message (consensus/reactor.go:326): REJECT. */
        return CMT_REJECT;
    }
    return CMT_OK;                                               /* :95 */
}

/* cometbft@709fd12b types/proposal.go:102-118 — ProposalSignBytes().
 * CanonicalizeProposal (:111) then MarshalDelimited (:112). */
int cmt_proposal_sign_bytes(const uint8_t *chain_id, size_t chain_id_len,
                            const cmt_pb_proposal_t *p,
                            uint8_t *out, size_t cap, size_t *out_len)
{
    cmt_pb_canonical_proposal_t cp;
    uint8_t                     body[CMT_PROPOSAL_SIGN_BYTES_MAX];
    size_t                      body_len;
    int                         rc;

    if (p == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_canonicalize_proposal(chain_id, chain_id_len, p, &cp);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_pb_canonical_proposal_marshal(&cp, body, sizeof(body),
                                           &body_len);
    if (rc != CMT_OK) {
        return rc;                                   /* :113-115 panics  */
    }
    return cmt_pb_marshal_delimited(body, body_len, out, cap, out_len);
}

/* cometbft@709fd12b types/proposal.go:120-136 — (p *Proposal) ToProto() */
int cmt_proposal_to_proto(const cmt_proposal_t *p, cmt_pb_proposal_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    if (p == NULL) {
        cmt_pb_proposal_init(out);                   /* :122-124 empty   */
        return CMT_OK;
    }
    *out = *p;
    return CMT_OK;
}

/* cometbft@709fd12b types/proposal.go:138-161 — ProposalFromProto() */
int cmt_proposal_from_proto(const cmt_pb_proposal_t *pp, cmt_proposal_t *out)
{
    cmt_block_id_t bid;
    int            rc;

    if (pp == NULL || out == NULL) {
        return CMT_FAULT;                            /* :141-143         */
    }
    rc = cmt_block_id_from_proto(&pp->block_id, &bid);           /* :147 */
    if (rc != CMT_OK) {
        return rc;
    }
    *out = *pp;                                                  /* :152-158 */
    out->block_id = bid;
    return cmt_proposal_validate_basic(out);                     /* :160 */
}
