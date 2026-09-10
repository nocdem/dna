/**
 * @file shared/dnac/cmt_canonical.c
 * @brief cometbft @709fd12b `types/canonical.go` ported to C — see
 *        cmt_canonical.h for the contract and the taşınmadı list.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_canonical.h"

#include <string.h>

/* Copy the chain id into a canonical struct's fixed-width slot. */
static int set_chain_id(uint8_t *dst, size_t *dst_len,
                        const uint8_t *chain_id, size_t chain_id_len)
{
    if (chain_id_len > (size_t)CMT_PB_CHAINID_MAX) {
        return CMT_REJECT;
    }
    if (chain_id_len != 0u) {
        if (chain_id == NULL) {
            return CMT_FAULT;
        }
        memcpy(dst, chain_id, chain_id_len);
    }
    *dst_len = chain_id_len;
    return CMT_OK;
}

/* cometbft@709fd12b types/canonical.go:18-34 — CanonicalizeBlockID() */
int cmt_canonicalize_block_id(const cmt_pb_block_id_t *bid, bool *has,
                              cmt_pb_canonical_block_id_t *out)
{
    cmt_block_id_t rbid;
    int            rc;

    if (bid == NULL || has == NULL || out == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_block_id_from_proto(bid, &rbid);                    /* :19  */
    if (rc != CMT_OK) {
        return CMT_REJECT;                                       /* :20-22 panic */
    }
    cmt_pb_canonical_block_id_init(out);
    if (cmt_block_id_is_zero(&rbid)) {                           /* :24  */
        *has = false;                                            /* :25  */
        return CMT_OK;
    }
    /* :28 — the hash comes from the ARGUMENT; see cmt_canonical.h. */
    if (bid->hash_len != 0u) {
        memcpy(out->hash, bid->hash, bid->hash_len);
    }
    out->hash_len = bid->hash_len;
    rc = cmt_canonicalize_part_set_header(&bid->part_set_header,
                                          &out->part_set_header);/* :29  */
    if (rc != CMT_OK) {
        return rc;
    }
    *has = true;
    return CMT_OK;
}

/* cometbft@709fd12b types/canonical.go:37-39 — CanonicalizePartSetHeader().
 * A Go type conversion between identically shaped messages. */
int cmt_canonicalize_part_set_header(const cmt_pb_part_set_header_t *psh,
                                     cmt_pb_canonical_part_set_header_t *out)
{
    if (psh == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = *psh;                                                 /* :38  */
    return CMT_OK;
}

/* cometbft@709fd12b types/canonical.go:42-52 — CanonicalizeProposal() */
int cmt_canonicalize_proposal(const uint8_t *chain_id, size_t chain_id_len,
                              const cmt_pb_proposal_t *p,
                              cmt_pb_canonical_proposal_t *out)
{
    int rc;

    if (p == NULL || out == NULL) {
        return CMT_FAULT;
    }
    cmt_pb_canonical_proposal_init(out);
    out->type      = (int32_t)CMT_PB_MSG_TYPE_PROPOSAL;          /* :44  */
    out->height    = p->height;                                  /* :45  */
    out->round     = (int64_t)p->round;                          /* :46  */
    out->pol_round = (int64_t)p->pol_round;                      /* :47  */
    rc = cmt_canonicalize_block_id(&p->block_id, &out->has_block_id,
                                   &out->block_id);              /* :48  */
    if (rc != CMT_OK) {
        return rc;
    }
    out->timestamp = p->timestamp;                               /* :49  */
    return set_chain_id(out->chain_id, &out->chain_id_len,
                        chain_id, chain_id_len);                 /* :50  */
}

/* cometbft@709fd12b types/canonical.go:57-66 — CanonicalizeVote() */
int cmt_canonicalize_vote(const uint8_t *chain_id, size_t chain_id_len,
                          const cmt_pb_vote_t *vote,
                          cmt_pb_canonical_vote_t *out)
{
    int rc;

    if (vote == NULL || out == NULL) {
        return CMT_FAULT;
    }
    cmt_pb_canonical_vote_init(out);
    out->type   = vote->type;                                    /* :59  */
    out->height = vote->height;                                  /* :60  */
    out->round  = (int64_t)vote->round;                          /* :61  */
    rc = cmt_canonicalize_block_id(&vote->block_id, &out->has_block_id,
                                   &out->block_id);              /* :62  */
    if (rc != CMT_OK) {
        return rc;
    }
    out->timestamp = vote->timestamp;                            /* :63  */
    return set_chain_id(out->chain_id, &out->chain_id_len,
                        chain_id, chain_id_len);                 /* :64  */
}

/* cometbft@709fd12b types/canonical.go:71-78 — CanonicalizeVoteExtension().
 * No timestamp and no type; the extension bytes are shared, not copied. */
int cmt_canonicalize_vote_extension(const uint8_t *chain_id,
                                    size_t chain_id_len,
                                    const cmt_pb_vote_t *vote,
                                    cmt_pb_canonical_vote_extension_t *out)
{
    if (vote == NULL || out == NULL) {
        return CMT_FAULT;
    }
    cmt_pb_canonical_vote_extension_init(out);
    out->extension = vote->extension;                            /* :73  */
    out->height    = vote->height;                               /* :74  */
    out->round     = (int64_t)vote->round;                       /* :75  */
    return set_chain_id(out->chain_id, &out->chain_id_len,
                        chain_id, chain_id_len);                 /* :76  */
}
