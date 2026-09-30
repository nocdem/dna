/**
 * @file shared/dnac/cmt_vote.c
 * @brief cometbft @v0.38.26 `types/vote.go` ported to C — see cmt_vote.h
 *        for the contract, the substitutions and the taşınmadı list.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_vote.h"

/* `crypto/hash/qgp_sha3.h` was included here for cmt_pubkey_address's own
 * SHA3 call. Wave R1-D made that function a delegate to cmt_address_hash
 * (cmt_tmhash.h), which is where the hash backend is now reached, so the
 * direct include is gone with the direct call. */

#include <stdlib.h>
#include <string.h>

/* cometbft@v0.38.26 types/signed_msg_type.go:6-13 — IsVoteTypeValid() */
bool cmt_is_vote_type_valid(int32_t t)
{
    return t == (int32_t)CMT_PB_MSG_TYPE_PREVOTE ||
           t == (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT;
}

/* cometbft@v0.38.26 crypto/ed25519/ed25519.go:156-161 — (pubKey PubKey)
 * Address() = tmhash.SumTruncated(pubKey), i.e. crypto.AddressHash
 * (crypto/crypto.go:18-20). Wave R1-D moved the ONE truncation into
 * cmt_tmhash.h's cmt_address_hash; this stays as the typed wrapper the
 * reference's ed25519 method is, and does nothing else. */
int cmt_pubkey_address(const uint8_t pubkey[CMT_PB_PUBKEY_LEN],
                       uint8_t out[CMT_ADDRESS_SIZE])
{
    if (pubkey == NULL || out == NULL) {
        return CMT_FAULT;
    }
    return cmt_address_hash(pubkey, (size_t)CMT_PB_PUBKEY_LEN, out);
}

/* cometbft@v0.38.26 types/vote.go:43-48 — NewConflictingVoteError() */
int cmt_new_conflicting_vote_error(const cmt_vote_t *vote1,
                                   const cmt_vote_t *vote2,
                                   cmt_err_vote_conflicting_votes_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    out->vote_a = vote1;                                         /* :45  */
    out->vote_b = vote2;                                         /* :46  */
    return CMT_OK;
}

/* cometbft@v0.38.26 types/vote.go:81-103 — VoteFromProto().
 * NOTE reference asymmetry (:77-80 versus :86): the doc comment promises
 * no validation, but BlockIDFromProto validates. Ported as-is. */
int cmt_vote_from_proto(const cmt_pb_vote_t *pv, cmt_vote_t *out)
{
    cmt_block_id_t bid;
    int            rc;

    if (out == NULL) {
        return CMT_FAULT;
    }
    if (pv == NULL) {
        /* :82-84 — `ErrVoteNil` (#5777, v0.38.23); at 709fd12b :82
         * dereferenced the nil and panicked. A nil vote is what a peer's
         * VoteMessage without a vote decodes to, so the class is REJECT.
         * (This port's VoteMessage decoder already refuses that shape
         * before calling here — cmt_msgs.c; this makes the function
         * itself answer as the reference now does.) */
        return CMT_REJECT;
    }
    rc = cmt_block_id_from_proto(&pv->block_id, &bid);           /* :86  */
    if (rc != CMT_OK) {
        return rc;
    }
    *out = *pv;                                                  /* :91-102 */
    out->block_id = bid;                                         /* :95  */
    return CMT_OK;
}

/* cometbft@v0.38.26 types/vote.go:375-394 — (vote *Vote) ToProto() */
int cmt_vote_to_proto(const cmt_vote_t *vote, cmt_pb_vote_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    if (vote == NULL) {
        cmt_pb_vote_init(out);                       /* :378-380 nil     */
        return CMT_OK;
    }
    *out = *vote;
    return CMT_OK;
}

/* cometbft@v0.38.26 types/vote.go:396-410 — VotesToProto() */
int cmt_votes_to_proto(const cmt_vote_t *const *votes, size_t n,
                       cmt_pb_vote_t *out, size_t cap, size_t *out_len)
{
    size_t i;
    size_t k = 0;

    if (out_len == NULL) {
        return CMT_FAULT;
    }
    *out_len = 0;
    if (votes == NULL) {
        return CMT_OK;                              /* :397-399 nil slice */
    }
    /* `out` may be NULL only when nothing can be written to it. A list of
     * nothing but NULL elements produces no output, and Go returns an
     * empty slice for it rather than failing. */
    if (cap != 0u && out == NULL) {
        return CMT_FAULT;
    }
    for (i = 0; i < n; i++) {                       /* :402-409           */
        if (votes[i] == NULL) {
            continue;      /* :405-407 a nil element is DROPPED, not kept */
        }
        /* INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07: the
         * caller's capacity is checked before the write, where Go's
         * append would grow the slice. */
        if (k >= cap) {
            return CMT_REJECT;
        }
        out[k] = *votes[i];                         /* ToProto = identity */
        k++;
    }
    *out_len = k;
    return CMT_OK;
}

/* cometbft@v0.38.26 types/vote.go:105-127 — (vote *Vote) CommitSig() */
int cmt_vote_commit_sig(const cmt_vote_t *vote, cmt_commit_sig_t *out)
{
    cmt_block_id_flag_t flag;

    if (out == NULL) {
        return CMT_FAULT;
    }
    if (vote == NULL) {
        cmt_new_commit_sig_absent(out);                          /* :107-109 */
        return CMT_OK;
    }
    /* INVARIANT 7495d337: the vote's own length fields drive the copies
     * below; a hand-filled struct could carry a length wider than its
     * array, which Go's slice copy could not. */
    if (vote->validator_address_len > (size_t)CMT_PB_ADDRESS_MAX ||
        vote->signature_len > (size_t)CMT_PB_SIG_MAX) {
        return CMT_REJECT;
    }
    if (cmt_block_id_is_complete(&vote->block_id)) {
        flag = CMT_BLOCK_ID_FLAG_COMMIT;                         /* :113-114 */
    } else if (cmt_block_id_is_zero(&vote->block_id)) {
        flag = CMT_BLOCK_ID_FLAG_NIL;                            /* :115-116 */
    } else {
        return CMT_REJECT;                                       /* :117-119 panic */
    }
    cmt_pb_commit_sig_init(out);
    out->block_id_flag = (int32_t)flag;                          /* :122 */
    memcpy(out->validator_address, vote->validator_address,
           vote->validator_address_len);                         /* :123 */
    out->validator_address_len = vote->validator_address_len;
    out->timestamp = vote->timestamp;                            /* :124 */
    memcpy(out->signature, vote->signature, vote->signature_len);/* :125 */
    out->signature_len = vote->signature_len;
    return CMT_OK;
}

/* cometbft@v0.38.26 types/vote.go:129-142 — (vote *Vote) ExtendedCommitSig() */
int cmt_vote_extended_commit_sig(const cmt_vote_t *vote,
                                 cmt_extended_commit_sig_t *out)
{
    int rc;

    if (out == NULL) {
        return CMT_FAULT;
    }
    if (vote == NULL) {
        cmt_new_extended_commit_sig_absent(out);                 /* :133-135 */
        return CMT_OK;
    }
    if (vote->extension_signature_len > (size_t)CMT_PB_SIG_MAX) {
        return CMT_REJECT;                          /* INVARIANT 7495d337 */
    }
    cmt_pb_extended_commit_sig_init(out);
    rc = cmt_vote_commit_sig(vote, &out->commit_sig);            /* :138 */
    if (rc != CMT_OK) {
        return rc;
    }
    out->extension = vote->extension;                            /* :139 */
    memcpy(out->extension_signature, vote->extension_signature,
           vote->extension_signature_len);                       /* :140 */
    out->extension_signature_len = vote->extension_signature_len;
    return CMT_OK;
}

/* cometbft@v0.38.26 types/vote.go:144-160 — VoteSignBytes().
 * CanonicalizeVote (:153) then MarshalDelimited (:154). */
int cmt_vote_sign_bytes(const uint8_t *chain_id, size_t chain_id_len,
                        const cmt_pb_vote_t *vote,
                        uint8_t *out, size_t cap, size_t *out_len)
{
    cmt_pb_canonical_vote_t cv;
    uint8_t                 body[CMT_VOTE_SIGN_BYTES_MAX];
    size_t                  body_len;
    int                     rc;

    if (vote == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_canonicalize_vote(chain_id, chain_id_len, vote, &cv);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_pb_canonical_vote_marshal(&cv, body, sizeof(body), &body_len);
    if (rc != CMT_OK) {
        return rc;                                   /* :155-157 panics  */
    }
    return cmt_pb_marshal_delimited(body, body_len, out, cap, out_len);
}

/* cometbft@v0.38.26 types/vote.go:162-175 — VoteExtensionSignBytes() */
int cmt_vote_extension_sign_bytes(const uint8_t *chain_id,
                                  size_t chain_id_len,
                                  const cmt_pb_vote_t *vote,
                                  uint8_t *out, size_t cap, size_t *out_len)
{
    cmt_pb_canonical_vote_extension_t ce;
    uint8_t                          *body;
    size_t                            body_cap;
    size_t                            body_len;
    int                               rc;

    if (vote == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_canonicalize_vote_extension(chain_id, chain_id_len, vote, &ce);
    if (rc != CMT_OK) {
        return rc;
    }
    /* The extension is application data of unbounded length, so the
     * canonical message is built in a transient buffer and then framed by
     * cmt_pb_marshal_delimited — the reference's own framing function,
     * which copies and therefore must not be handed overlapping ranges.
     * Bound: extension 11 + len, height 9, round 9, chain id 34 = 63+len. */
    body_cap = 64u + 11u + vote->extension.len;
    body     = (uint8_t *)malloc(body_cap);
    if (body == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_pb_canonical_vote_extension_marshal(&ce, body, body_cap,
                                                 &body_len);
    if (rc == CMT_OK) {                              /* :170-172 panics  */
        rc = cmt_pb_marshal_delimited(body, body_len, out, cap, out_len);
    }
    free(body);
    return rc;
}

/* cometbft@v0.38.26 types/vote.go:177-180 — (vote *Vote) Copy() */
int cmt_vote_copy(const cmt_vote_t *vote, cmt_vote_t *out)
{
    if (vote == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = *vote;                                                /* :178 */
    return CMT_OK;
}

/* cometbft@v0.38.26 types/vote.go:223-240 — verifyAndReturnProto() and
 * (vote *Vote) Verify(). One function here: the proto the reference
 * returns IS the vote. */
int cmt_vote_verify(const uint8_t *chain_id, size_t chain_id_len,
                    const cmt_vote_t *vote,
                    const uint8_t pubkey[CMT_PB_PUBKEY_LEN])
{
    uint8_t addr[CMT_ADDRESS_SIZE];
    uint8_t sb[CMT_VOTE_SIGN_BYTES_MAX];
    size_t  sb_len;
    int     rc;

    if (vote == NULL || pubkey == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_pubkey_address(pubkey, addr);                       /* :224 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (vote->validator_address_len != (size_t)CMT_ADDRESS_SIZE ||
        memcmp(addr, vote->validator_address,
               (size_t)CMT_ADDRESS_SIZE) != 0) {
        return CMT_REJECT;        /* :225 ErrVoteInvalidValidatorAddress  */
    }
    rc = cmt_vote_sign_bytes(chain_id, chain_id_len, vote, sb, sizeof(sb),
                             &sb_len);                           /* :228 */
    if (rc != CMT_OK) {
        return rc;
    }
    /* INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07: the verifier
     * reads `signature_len` bytes out of a fixed array, so the struct's own
     * length is checked against that array before the read. Go's Signature
     * is a slice and carries its own bound. */
    if (vote->signature_len > sizeof(vote->signature)) {
        return CMT_FAULT;
    }
    if (qgp_dsa87_verify(vote->signature, vote->signature_len, sb, sb_len,
                         pubkey) != 0) {
        return CMT_REJECT;                /* :229 ErrVoteInvalidSignature */
    }
    return CMT_OK;
}

/* cometbft@v0.38.26 types/vote.go:242-263 — VerifyVoteAndExtension() */
int cmt_vote_verify_vote_and_extension(const uint8_t *chain_id,
                                       size_t chain_id_len,
                                       const cmt_vote_t *vote,
                                       const uint8_t pubkey[CMT_PB_PUBKEY_LEN],
                                       uint8_t *scratch, size_t scratch_cap)
{
    size_t ext_len;
    int    rc;

    rc = cmt_vote_verify(chain_id, chain_id_len, vote, pubkey);  /* :247 */
    if (rc != CMT_OK) {
        return rc;
    }
    /* :252 — extension signatures are verified for NON-NIL PRECOMMITS
     * only. `ProtoBlockIDIsNil` on the vote's own BlockID. */
    if (vote->type != (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT ||
        cmt_proto_block_id_is_nil(&vote->block_id)) {
        return CMT_OK;
    }
    if (vote->extension_signature_len == 0u) {
        return CMT_REJECT;                                       /* :253-255 */
    }
    rc = cmt_vote_extension_sign_bytes(chain_id, chain_id_len, vote,
                                       scratch, scratch_cap, &ext_len);
    if (rc != CMT_OK) {                                          /* :257 */
        return rc;
    }
    /* INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07 — see
     * cmt_vote_verify: the length is checked against the array it indexes. */
    if (vote->extension_signature_len > sizeof(vote->extension_signature)) {
        return CMT_FAULT;
    }
    if (qgp_dsa87_verify(vote->extension_signature,
                         vote->extension_signature_len,
                         scratch, ext_len, pubkey) != 0) {
        return CMT_REJECT;                /* :259 ErrVoteInvalidSignature */
    }
    return CMT_OK;
}

/* cometbft@v0.38.26 types/vote.go:265-277 — VerifyExtension() */
int cmt_vote_verify_extension(const uint8_t *chain_id, size_t chain_id_len,
                              const cmt_vote_t *vote,
                              const uint8_t pubkey[CMT_PB_PUBKEY_LEN],
                              uint8_t *scratch, size_t scratch_cap)
{
    size_t ext_len;
    int    rc;

    if (vote == NULL || pubkey == NULL) {
        return CMT_FAULT;
    }
    /* :268-270 — a prevote or a nil precommit is accepted WITHOUT any
     * check. This function proves nothing about such a vote. */
    if (vote->type != (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT ||
        cmt_block_id_is_zero(&vote->block_id)) {
        return CMT_OK;
    }
    rc = cmt_vote_extension_sign_bytes(chain_id, chain_id_len, vote,
                                       scratch, scratch_cap, &ext_len);
    if (rc != CMT_OK) {                                          /* :272 */
        return rc;
    }
    /* INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07 — see
     * cmt_vote_verify: the length is checked against the array it indexes. */
    if (vote->extension_signature_len > sizeof(vote->extension_signature)) {
        return CMT_FAULT;
    }
    if (qgp_dsa87_verify(vote->extension_signature,
                         vote->extension_signature_len,
                         scratch, ext_len, pubkey) != 0) {
        return CMT_REJECT;                                       /* :274 */
    }
    return CMT_OK;
}

/* cometbft@v0.38.26 types/vote.go:279-357 — (vote *Vote) ValidateBasic() */
int cmt_vote_validate_basic(const cmt_vote_t *vote)
{
    bool is_zero;

    if (vote == NULL) {
        return CMT_FAULT;
    }
    if (!cmt_is_vote_type_valid(vote->type)) {
        return CMT_REJECT;                                       /* :283-285 */
    }
    if (vote->height <= 0) {
        return CMT_REJECT;                                       /* :287-289 */
    }
    if (vote->round < 0) {
        return CMT_REJECT;                                       /* :291-293 */
    }
    /* :295 — "Timestamp validation is subtle and handled elsewhere." */
    if (cmt_block_id_validate_basic(&vote->block_id) != CMT_OK) {
        return CMT_REJECT;                                       /* :297-299 */
    }
    is_zero = cmt_block_id_is_zero(&vote->block_id);
    if (!is_zero && !cmt_block_id_is_complete(&vote->block_id)) {
        return CMT_REJECT;                                       /* :303-305 */
    }
    /* :307-312 — crypto.AddressSize 20 → CMT_ADDRESS_SIZE 32. */
    if (vote->validator_address_len != (size_t)CMT_ADDRESS_SIZE) {
        return CMT_REJECT;
    }
    if (vote->validator_index < 0) {
        return CMT_REJECT;                                       /* :313-315 */
    }
    if (vote->signature_len == 0u) {
        return CMT_REJECT;                                       /* :316-318 */
    }
    if (vote->signature_len > (size_t)CMT_MAX_SIGNATURE_SIZE) {
        return CMT_REJECT;                                       /* :320-322 */
    }
    /* :324-337 — extensions belong to non-nil precommits ONLY. */
    if (vote->type != (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT || is_zero) {
        if (vote->extension.len > 0u) {
            return CMT_REJECT;                                   /* :328-333 */
        }
        if (vote->extension_signature_len > 0u) {
            return CMT_REJECT;                                   /* :334-336 */
        }
    }
    if (vote->type == (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT && !is_zero) {
        if (vote->extension_signature_len >
            (size_t)CMT_MAX_SIGNATURE_SIZE) {
            return CMT_REJECT;                                   /* :343-345 */
        }
        /* :347-353 — the signature can only be REQUIRED when there is
         * something in the extension, because we cannot tell from the vote
         * alone whether extensions are enabled. */
        if (vote->extension_signature_len == 0u &&
            vote->extension.len != 0u) {
            return CMT_REJECT;                                   /* :351-353 */
        }
    }
    return CMT_OK;
}

/* cometbft@v0.38.26 types/vote.go:359-373 — (vote *Vote) EnsureExtension() */
int cmt_vote_ensure_extension(const cmt_vote_t *vote)
{
    if (vote == NULL) {
        return CMT_FAULT;
    }
    if (vote->type != (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT) {
        return CMT_OK;                                           /* :363-365 */
    }
    if (cmt_block_id_is_zero(&vote->block_id)) {
        return CMT_OK;                                           /* :366-368 */
    }
    if (vote->extension_signature_len > 0u) {
        return CMT_OK;                                           /* :369-371 */
    }
    return CMT_REJECT;                        /* :372 ErrVoteExtensionAbsent */
}

/* cometbft@v0.38.26 types/vote.go:412-458 — SignAndCheckVote().
 * The signer is the host's; see cmt_vote.h for why its shape mirrors the
 * reference's PrivValidator.SignVote rather than a plain byte signer. */
int cmt_sign_and_check_vote(cmt_vote_t *vote, cmt_sign_vote_fn sign,
                            void *ctx,
                            const uint8_t *chain_id, size_t chain_id_len,
                            bool extensions_enabled, bool *recoverable)
{
    cmt_pb_vote_t v;
    bool          is_precommit;
    bool          is_nil;
    bool          ext_signature;
    int           rc;

    if (vote == NULL || sign == NULL || recoverable == NULL) {
        return CMT_FAULT;
    }
    *recoverable = false;
    v  = *vote;                                                  /* :421 */
    rc = sign(ctx, chain_id, chain_id_len, &v);                  /* :422 */
    if (rc != CMT_OK) {
        /* :423-426 — "failing to sign a vote has always been a
         * recoverable error, this function keeps it that way." */
        *recoverable = true;
        return rc;
    }
    /* INVARIANT 7495d337: the signer is the HOST's code and its lengths
     * are checked before they drive a copy. Go's slice assignment could
     * not overrun; a C memcpy can. */
    if (v.signature_len > (size_t)CMT_PB_SIG_MAX ||
        v.extension_signature_len > (size_t)CMT_PB_SIG_MAX) {
        return CMT_REJECT;
    }
    memcpy(vote->signature, v.signature, v.signature_len);       /* :427 */
    vote->signature_len = v.signature_len;

    is_precommit  = vote->type == (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT; /* :429 */
    if (!is_precommit && extensions_enabled) {
        return CMT_REJECT;              /* :430-433 non-recoverable      */
    }
    is_nil        = cmt_block_id_is_zero(&vote->block_id);       /* :435 */
    ext_signature = v.extension_signature_len > 0u;              /* :436 */

    if (ext_signature && (!is_precommit || is_nil)) {
        return CMT_REJECT;              /* :439-442 non-recoverable      */
    }
    vote->extension_signature_len = 0u;                          /* :444 */
    if (extensions_enabled) {                                    /* :445 */
        if (!ext_signature && is_precommit && !is_nil) {
            return CMT_REJECT;          /* :447-450 non-recoverable      */
        }
        memcpy(vote->extension_signature, v.extension_signature,
               v.extension_signature_len);                       /* :452 */
        vote->extension_signature_len = v.extension_signature_len;
    }
    /* :455 — THE TIMESTAMP THE SIGNER RETURNED WINS. This is the
     * reference's single clock-touching step in a vote's life. */
    vote->timestamp = v.timestamp;
    *recoverable = true;                             /* :457 `true, nil` */
    return CMT_OK;                                               /* :457 */
}
