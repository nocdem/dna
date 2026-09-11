/**
 * @file shared/dnac/cmt_privval.c
 * @brief cometbft @709fd12b `privval/file.go`'s signing logic in C — see
 *        cmt_privval.h for the contract, the host boundary and the
 *        taşınmadı list.
 *
 * Every function carries the `// cometbft@709fd12b <file>:<from>-<to>`
 * line of the Go function it ports.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_privval.h"

#include <stdlib.h>
#include <string.h>

/* ══ protoio.UnmarshalDelimited ═══════════════════════════════════════
 * cometbft@709fd12b libs/protoio/reader.go:104-107 `UnmarshalDelimited`,
 * which is `NewDelimitedReader(bytes.NewReader(data), len(data)).ReadMsg`
 * — the ReadMsg of :67-95.
 *
 * The rules that matter, from those lines: the uvarint length is read from
 * the front (:69); a length past the native int range is refused (:78-80);
 * a length greater than maxSize, which UnmarshalDelimited sets to
 * len(data), is refused (:81-83); then exactly that many bytes are read
 * (:89) and unmarshalled (:94). TRAILING BYTES AFTER THE MESSAGE ARE
 * IGNORED — ReadMsg stops at the declared length and UnmarshalDelimited
 * looks no further.
 *
 * This is the inverse of cmt_pb_marshal_delimited (cmt_pb.h) and is
 * private here because privval is the only ported caller.
 * ══════════════════════════════════════════════════════════════════════ */
static int read_delimited(const uint8_t *data, size_t len,
                          const uint8_t **body, size_t *body_len)
{
    size_t   off = 0;
    uint64_t l;

    if (data == NULL) {
        return CMT_REJECT;
    }
    if (cmt_pb_get_uvarint(data, len, &off, &l) != CMT_OK) {
        return CMT_REJECT;                                   /* :69-73 */
    }
    if (l > (uint64_t)(len - off)) {
        /* Both :81-83 (length > maxSize == len(data)) and :89's ReadFull
         * failure collapse into this one check. */
        return CMT_REJECT;
    }
    *body     = data + off;
    *body_len = (size_t)l;
    return CMT_OK;                                           /* :94 */
}

/* ══ voteToStep ═══════════════════════════════════════════════════════ */

/* cometbft@709fd12b privval/file.go:33-42 — voteToStep() */
int cmt_vote_to_step(const cmt_pb_vote_t *vote, int8_t *out)
{
    if (vote == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (vote->type == (int32_t)CMT_PB_MSG_TYPE_PREVOTE) {
        *out = CMT_STEP_PREVOTE;                             /* :35-36 */
        return CMT_OK;
    }
    if (vote->type == (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT) {
        *out = CMT_STEP_PRECOMMIT;                           /* :37-38 */
        return CMT_OK;
    }
    /* :39-41 the reference PANICS. CMT_FAULT under the panic rule
     * (atlas-dec-d5e766defde138eb6dd02e5b81e735a8 rev 4): the vote handed
     * to a signer is never a peer's — the state machine builds it itself
     * (consensus/state.go:2385-2392) and every one of the ten call sites
     * of `signAddVote` passes a literal PrevoteType or PrecommitType
     * (state.go:1351, 1358, 1368, 1394, 1402, 1472, 1502, 1517, 1538,
     * 1560). A third type here is this node's own invariant broken, so it
     * is node-local and fail-stop, not a message to refuse. The remote
     * signer (privval/signer_requestHandler.go:56), the only caller that
     * could carry a foreign vote, is outside this port by pin rev 6. */
    return CMT_FAULT;
}

/* ══ FilePVLastSignState ══════════════════════════════════════════════ */

/* cometbft@709fd12b privval/file.go:85-91 —
 * (lss *FilePVLastSignState) reset() */
int cmt_lss_reset(cmt_lss_t *lss)
{
    if (lss == NULL) {
        return CMT_FAULT;
    }
    lss->height         = 0;                                 /* :86 */
    lss->round          = 0;                                 /* :87 */
    lss->step           = CMT_STEP_NONE;                     /* :88 */
    lss->has_signature  = false;                             /* :89 nil */
    lss->signature_len  = 0;
    lss->has_sign_bytes = false;                             /* :90 nil */
    lss->sign_bytes_len = 0;
    memset(lss->signature, 0, sizeof(lss->signature));
    memset(lss->sign_bytes, 0, sizeof(lss->sign_bytes));
    return CMT_OK;
}

/* cometbft@709fd12b privval/file.go:100-132 —
 * (lss *FilePVLastSignState) CheckHRS() */
int cmt_lss_check_hrs(const cmt_lss_t *lss, int64_t height, int32_t round,
                      int8_t step, bool *out_same_hrs)
{
    if (lss == NULL || out_same_hrs == NULL) {
        return CMT_FAULT;
    }
    *out_same_hrs = false;

    if (lss->height > height) {
        return CMT_REJECT;                 /* :102-104 height regression */
    }
    if (lss->height == height) {                             /* :106 */
        if (lss->round > round) {
            return CMT_REJECT;             /* :107-109 round regression  */
        }
        if (lss->round == round) {                           /* :111 */
            if (lss->step > step) {
                return CMT_REJECT;         /* :112-119 step regression   */
            }
            if (lss->step == step) {                         /* :120 */
                if (lss->has_sign_bytes) {                   /* :121 */
                    if (!lss->has_signature) {
                        /* :122-124 — the reference PANICS. This node's own
                         * state contradicting itself; it must stop, not
                         * answer. */
                        return CMT_FAULT;
                    }
                    *out_same_hrs = true;                    /* :125 */
                    return CMT_OK;
                }
                return CMT_REJECT;         /* :127 "no SignBytes found"  */
            }
        }
    }
    return CMT_OK;                                           /* :131 */
}

/* ══ FilePV ═══════════════════════════════════════════════════════════ */

/* cometbft@709fd12b privval/file.go:256-258 — (pv *FilePV) GetPubKey() */
int cmt_pv_get_pub_key(const cmt_file_pv_t *pv,
                       uint8_t out[CMT_PB_PUBKEY_LEN])
{
    if (pv == NULL || out == NULL) {
        return CMT_FAULT;
    }
    memcpy(out, pv->pub_key, (size_t)CMT_PB_PUBKEY_LEN);     /* :257 */
    return CMT_OK;
}

/* cometbft@709fd12b privval/file.go:413-422 — (pv *FilePV) saveSigned() */
int cmt_pv_save_signed(cmt_file_pv_t *pv, int64_t height, int32_t round,
                       int8_t step, const uint8_t *sign_bytes,
                       size_t sign_bytes_len, const uint8_t *sig,
                       size_t sig_len)
{
    if (pv == NULL || sign_bytes == NULL || sig == NULL) {
        return CMT_FAULT;
    }
    /* Go's slices carry their own bound; here the bound is explicit
     * (INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07). */
    if (sign_bytes_len > (size_t)CMT_PV_SIGN_BYTES_MAX ||
        sig_len > (size_t)CMT_MAX_SIGNATURE_SIZE) {
        return CMT_REJECT;
    }
    pv->last_sign_state.height = height;                     /* :416 */
    pv->last_sign_state.round  = round;                      /* :417 */
    pv->last_sign_state.step   = step;                       /* :418 */

    memcpy(pv->last_sign_state.signature, sig, sig_len);     /* :419 */
    pv->last_sign_state.signature_len = sig_len;
    pv->last_sign_state.has_signature = true;

    memcpy(pv->last_sign_state.sign_bytes, sign_bytes,
           sign_bytes_len);                                  /* :420 */
    pv->last_sign_state.sign_bytes_len = sign_bytes_len;
    pv->last_sign_state.has_sign_bytes = true;

    if (pv->save_last_sign_state == NULL) {
        return CMT_FAULT;
    }
    /* :421 — lss.Save(). The reference panics inside Save on failure; the
     * host reports it and the caller must not use the signature. */
    if (pv->save_last_sign_state(pv->save_ctx,
                                 &pv->last_sign_state) != CMT_OK) {
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* ══ the timestamp-only comparisons ═══════════════════════════════════ */

/* `proto.Equal` over two CanonicalVote messages (privval/file.go:445),
 * written out field by field.
 *
 * NOTE one difference from Go's proto.Equal that cannot arise here: it
 * also compares UNKNOWN fields, and this port's decoder skips them without
 * keeping them. Both inputs are sign bytes THIS node produced with this
 * port's own encoder, which never writes an unknown field, so the two
 * agree on every input that reaches this function. */
static bool canonical_vote_equal(const cmt_pb_canonical_vote_t *a,
                                 const cmt_pb_canonical_vote_t *b)
{
    if (a->type != b->type || a->height != b->height ||
        a->round != b->round) {
        return false;
    }
    if (a->has_block_id != b->has_block_id) {
        return false;
    }
    if (a->has_block_id) {
        if (a->block_id.hash_len != b->block_id.hash_len ||
            memcmp(a->block_id.hash, b->block_id.hash,
                   a->block_id.hash_len) != 0) {
            return false;
        }
        if (a->block_id.part_set_header.total !=
                b->block_id.part_set_header.total ||
            a->block_id.part_set_header.hash_len !=
                b->block_id.part_set_header.hash_len ||
            memcmp(a->block_id.part_set_header.hash,
                   b->block_id.part_set_header.hash,
                   a->block_id.part_set_header.hash_len) != 0) {
            return false;
        }
    }
    if (a->timestamp.seconds != b->timestamp.seconds ||
        a->timestamp.nanos != b->timestamp.nanos) {
        return false;
    }
    if (a->chain_id_len != b->chain_id_len ||
        memcmp(a->chain_id, b->chain_id, a->chain_id_len) != 0) {
        return false;
    }
    return true;
}

/* The same over two CanonicalProposal messages (privval/file.go:465). */
static bool canonical_proposal_equal(const cmt_pb_canonical_proposal_t *a,
                                     const cmt_pb_canonical_proposal_t *b)
{
    if (a->type != b->type || a->height != b->height ||
        a->round != b->round || a->pol_round != b->pol_round) {
        return false;
    }
    if (a->has_block_id != b->has_block_id) {
        return false;
    }
    if (a->has_block_id) {
        if (a->block_id.hash_len != b->block_id.hash_len ||
            memcmp(a->block_id.hash, b->block_id.hash,
                   a->block_id.hash_len) != 0) {
            return false;
        }
        if (a->block_id.part_set_header.total !=
                b->block_id.part_set_header.total ||
            a->block_id.part_set_header.hash_len !=
                b->block_id.part_set_header.hash_len ||
            memcmp(a->block_id.part_set_header.hash,
                   b->block_id.part_set_header.hash,
                   a->block_id.part_set_header.hash_len) != 0) {
            return false;
        }
    }
    if (a->timestamp.seconds != b->timestamp.seconds ||
        a->timestamp.nanos != b->timestamp.nanos) {
        return false;
    }
    if (a->chain_id_len != b->chain_id_len ||
        memcmp(a->chain_id, b->chain_id, a->chain_id_len) != 0) {
        return false;
    }
    return true;
}

/* cometbft@709fd12b privval/file.go:430-446 —
 * checkVotesOnlyDifferByTimestamp() */
int cmt_check_votes_only_differ_by_timestamp(const uint8_t *last_sign_bytes,
                                             size_t last_len,
                                             const uint8_t *new_sign_bytes,
                                             size_t new_len,
                                             cmt_time_t now,
                                             cmt_time_t *out_ts,
                                             bool *out_ok)
{
    cmt_pb_canonical_vote_t last_vote;
    cmt_pb_canonical_vote_t new_vote;
    const uint8_t          *body;
    size_t                  body_len;

    if (last_sign_bytes == NULL || new_sign_bytes == NULL ||
        out_ts == NULL || out_ok == NULL) {
        return CMT_FAULT;
    }
    /* :432-434 — the reference PANICS when LastSignBytes will not decode.
     * Local state, so CMT_FAULT. */
    if (read_delimited(last_sign_bytes, last_len, &body,
                       &body_len) != CMT_OK) {
        return CMT_FAULT;
    }
    if (cmt_pb_canonical_vote_unmarshal(body, body_len,
                                        &last_vote) != CMT_OK) {
        return CMT_FAULT;
    }
    /* :435-437 — likewise for the bytes this node just built. */
    if (read_delimited(new_sign_bytes, new_len, &body,
                       &body_len) != CMT_OK) {
        return CMT_FAULT;
    }
    if (cmt_pb_canonical_vote_unmarshal(body, body_len,
                                        &new_vote) != CMT_OK) {
        return CMT_FAULT;
    }

    *out_ts = last_vote.timestamp;                           /* :439 */
    /* :441-443 — both timestamps are set to the SAME value, so the
     * comparison that follows ignores them. `now` is the caller's single
     * clock read (clock POLICY); its value cannot change the result. */
    last_vote.timestamp = now;                               /* :442 */
    new_vote.timestamp  = now;                               /* :443 */
    *out_ok = canonical_vote_equal(&new_vote, &last_vote);   /* :445 */
    return CMT_OK;
}

/* cometbft@709fd12b privval/file.go:450-466 —
 * checkProposalsOnlyDifferByTimestamp() */
int cmt_check_proposals_only_differ_by_timestamp(
        const uint8_t *last_sign_bytes, size_t last_len,
        const uint8_t *new_sign_bytes, size_t new_len, cmt_time_t now,
        cmt_time_t *out_ts, bool *out_ok)
{
    cmt_pb_canonical_proposal_t last_proposal;
    cmt_pb_canonical_proposal_t new_proposal;
    const uint8_t              *body;
    size_t                      body_len;

    if (last_sign_bytes == NULL || new_sign_bytes == NULL ||
        out_ts == NULL || out_ok == NULL) {
        return CMT_FAULT;
    }
    if (read_delimited(last_sign_bytes, last_len, &body,
                       &body_len) != CMT_OK) {
        return CMT_FAULT;                                    /* :452-454 */
    }
    if (cmt_pb_canonical_proposal_unmarshal(body, body_len,
                                            &last_proposal) != CMT_OK) {
        return CMT_FAULT;
    }
    if (read_delimited(new_sign_bytes, new_len, &body,
                       &body_len) != CMT_OK) {
        return CMT_FAULT;                                    /* :455-457 */
    }
    if (cmt_pb_canonical_proposal_unmarshal(body, body_len,
                                            &new_proposal) != CMT_OK) {
        return CMT_FAULT;
    }

    *out_ts = last_proposal.timestamp;                       /* :459 */
    last_proposal.timestamp = now;                           /* :462 */
    new_proposal.timestamp  = now;                           /* :463 */
    *out_ok = canonical_proposal_equal(&new_proposal, &last_proposal);
    return CMT_OK;                                           /* :465 */
}

/* ══ signVote ═════════════════════════════════════════════════════════ */

/* cometbft@709fd12b privval/file.go:308-368 — (pv *FilePV) signVote().
 *
 * NOTE on :311: the reference takes a VALUE copy of the last-sign state
 * (`lss := pv.LastSignState`). A pointer is used here because nothing
 * mutates that state between :311 and the last read of it: the only writer
 * is `saveSigned` at :363, which runs on the path where `lss` is never
 * read again. */
int cmt_pv_sign_vote(cmt_file_pv_t *pv, const uint8_t *chain_id,
                     size_t chain_id_len, cmt_pb_vote_t *vote)
{
    const cmt_lss_t *lss;
    uint8_t          sign_bytes[CMT_VOTE_SIGN_BYTES_MAX];
    size_t           sign_bytes_len = 0;
    uint8_t          ext_sig[CMT_MAX_SIGNATURE_SIZE];
    size_t           ext_sig_len = 0;
    bool             have_ext_sig = false;
    uint8_t          sig[CMT_MAX_SIGNATURE_SIZE];
    size_t           sig_len = 0;
    int64_t          height;
    int32_t          round;
    int8_t           step;
    bool             same_hrs = false;
    int              rc;

    if (pv == NULL || vote == NULL || chain_id == NULL ||
        pv->raw_sign == NULL) {
        return CMT_FAULT;
    }
    height = vote->height;                                   /* :309 */
    round  = vote->round;
    rc = cmt_vote_to_step(vote, &step);                      /* :309 */
    if (rc != CMT_OK) {
        return rc;
    }
    lss = &pv->last_sign_state;                              /* :311 */

    rc = cmt_lss_check_hrs(lss, height, round, step, &same_hrs);
    if (rc != CMT_OK) {
        return rc;                                           /* :313-316 */
    }

    rc = cmt_vote_sign_bytes(chain_id, chain_id_len, vote, sign_bytes,
                             sizeof(sign_bytes), &sign_bytes_len);
    if (rc != CMT_OK) {
        return rc;                                           /* :318 */
    }

    /* :325-334 — the extension signature is ALWAYS re-made for a non-nil
     * precommit, because an application may have produced a different
     * extension; every other vote may carry no extension at all. */
    if (vote->type == (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT &&
        !cmt_proto_block_id_is_nil(&vote->block_id)) {       /* :326 */
        uint8_t *ext_bytes;
        size_t   ext_cap;
        size_t   ext_len = 0;

        /* cmt_vote_extension_sign_bytes needs 64 + 11 + the extension's
         * own length (cmt_vote.h); the extension is unbounded application
         * data, so the buffer is transient heap. */
        ext_cap = 64u + 11u + vote->extension.len;
        ext_bytes = (uint8_t *)malloc(ext_cap);
        if (ext_bytes == NULL) {
            return CMT_FAULT;
        }
        rc = cmt_vote_extension_sign_bytes(chain_id, chain_id_len, vote,
                                           ext_bytes, ext_cap,
                                           &ext_len);        /* :327 */
        if (rc == CMT_OK) {
            rc = pv->raw_sign(pv->sign_ctx, ext_bytes, ext_len, ext_sig,
                              &ext_sig_len);                 /* :328 */
        }
        free(ext_bytes);
        if (rc != CMT_OK) {
            return rc;                                       /* :329-331 */
        }
        if (ext_sig_len > (size_t)CMT_MAX_SIGNATURE_SIZE) {
            return CMT_FAULT;              /* a signer that overran */
        }
        have_ext_sig = true;
    } else if (vote->extension.len > 0u) {                   /* :332 */
        return CMT_REJECT;   /* :333 "unexpected vote extension" */
    }

    if (same_hrs) {                                          /* :341 */
        int reuse_rc = CMT_OK;

        if (lss->has_sign_bytes &&
            sign_bytes_len == lss->sign_bytes_len &&
            memcmp(sign_bytes, lss->sign_bytes, sign_bytes_len) == 0) {
            /* :342-343 — identical sign bytes: reuse the signature. */
            memcpy(vote->signature, lss->signature, lss->signature_len);
            vote->signature_len = lss->signature_len;
        } else {
            cmt_time_t ts;
            cmt_time_t now;
            bool       only_ts = false;

            if (pv->now == NULL) {
                return CMT_FAULT;
            }
            /* file.go:441 — the ONE clock read of this function, made
             * where the reference makes it. */
            if (pv->now(pv->now_ctx, &now) != CMT_OK) {
                return CMT_FAULT;
            }
            rc = cmt_check_votes_only_differ_by_timestamp(
                     lss->sign_bytes, lss->sign_bytes_len, sign_bytes,
                     sign_bytes_len, now, &ts, &only_ts);    /* :344 */
            if (rc != CMT_OK) {
                return rc;
            }
            if (only_ts) {
                vote->timestamp = ts;                        /* :347 */
                memcpy(vote->signature, lss->signature,
                       lss->signature_len);                  /* :348 */
                vote->signature_len = lss->signature_len;
            } else {
                reuse_rc = CMT_REJECT;     /* :350 "conflicting data" */
            }
        }
        /* :353 — the extension signature is written even when the branch
         * above is about to report the conflict. The reference's order. */
        if (have_ext_sig) {
            memcpy(vote->extension_signature, ext_sig, ext_sig_len);
            vote->extension_signature_len = ext_sig_len;
        } else {
            vote->extension_signature_len = 0;               /* extSig nil */
        }
        return reuse_rc;                                     /* :355 */
    }

    /* :358-362 — it passed the checks; sign the vote. */
    rc = pv->raw_sign(pv->sign_ctx, sign_bytes, sign_bytes_len, sig,
                      &sig_len);
    if (rc != CMT_OK) {
        return rc;                                           /* :360-362 */
    }
    if (sig_len > (size_t)CMT_MAX_SIGNATURE_SIZE) {
        return CMT_FAULT;
    }
    rc = cmt_pv_save_signed(pv, height, round, step, sign_bytes,
                            sign_bytes_len, sig, sig_len);   /* :363 */
    if (rc != CMT_OK) {
        return rc;
    }
    memcpy(vote->signature, sig, sig_len);                   /* :364 */
    vote->signature_len = sig_len;
    if (have_ext_sig) {                                      /* :365 */
        memcpy(vote->extension_signature, ext_sig, ext_sig_len);
        vote->extension_signature_len = ext_sig_len;
    } else {
        vote->extension_signature_len = 0;
    }
    return CMT_OK;                                           /* :367 */
}

/* ══ signProposal ═════════════════════════════════════════════════════ */

/* cometbft@709fd12b privval/file.go:373-410 —
 * (pv *FilePV) signProposal() */
int cmt_pv_sign_proposal(cmt_file_pv_t *pv, const uint8_t *chain_id,
                         size_t chain_id_len, cmt_pb_proposal_t *proposal)
{
    const cmt_lss_t *lss;
    uint8_t          sign_bytes[CMT_PROPOSAL_SIGN_BYTES_MAX];
    size_t           sign_bytes_len = 0;
    uint8_t          sig[CMT_MAX_SIGNATURE_SIZE];
    size_t           sig_len = 0;
    int64_t          height;
    int32_t          round;
    int8_t           step;
    bool             same_hrs = false;
    int              rc;

    if (pv == NULL || proposal == NULL || chain_id == NULL ||
        pv->raw_sign == NULL) {
        return CMT_FAULT;
    }
    height = proposal->height;                               /* :374 */
    round  = proposal->round;
    step   = CMT_STEP_PROPOSE;                               /* :374 */
    lss    = &pv->last_sign_state;                           /* :376 */

    rc = cmt_lss_check_hrs(lss, height, round, step, &same_hrs);
    if (rc != CMT_OK) {
        return rc;                                           /* :378-381 */
    }

    rc = cmt_proposal_sign_bytes(chain_id, chain_id_len, proposal,
                                 sign_bytes, sizeof(sign_bytes),
                                 &sign_bytes_len);           /* :383 */
    if (rc != CMT_OK) {
        return rc;
    }

    if (same_hrs) {                                          /* :390 */
        if (lss->has_sign_bytes &&
            sign_bytes_len == lss->sign_bytes_len &&
            memcmp(sign_bytes, lss->sign_bytes, sign_bytes_len) == 0) {
            memcpy(proposal->signature, lss->signature,
                   lss->signature_len);                      /* :391-392 */
            proposal->signature_len = lss->signature_len;
            return CMT_OK;                                   /* :399 */
        } else {
            cmt_time_t ts;
            cmt_time_t now;
            bool       only_ts = false;

            if (pv->now == NULL) {
                return CMT_FAULT;
            }
            /* file.go:461 — the ONE clock read of this function. */
            if (pv->now(pv->now_ctx, &now) != CMT_OK) {
                return CMT_FAULT;
            }
            rc = cmt_check_proposals_only_differ_by_timestamp(
                     lss->sign_bytes, lss->sign_bytes_len, sign_bytes,
                     sign_bytes_len, now, &ts, &only_ts);    /* :393 */
            if (rc != CMT_OK) {
                return rc;
            }
            if (only_ts) {
                proposal->timestamp = ts;                    /* :394 */
                memcpy(proposal->signature, lss->signature,
                       lss->signature_len);                  /* :395 */
                proposal->signature_len = lss->signature_len;
                return CMT_OK;                               /* :399 */
            }
            return CMT_REJECT;             /* :397 "conflicting data" */
        }
    }

    /* :402-406 — it passed the checks; sign the proposal. */
    rc = pv->raw_sign(pv->sign_ctx, sign_bytes, sign_bytes_len, sig,
                      &sig_len);
    if (rc != CMT_OK) {
        return rc;                                           /* :404-406 */
    }
    if (sig_len > (size_t)CMT_MAX_SIGNATURE_SIZE) {
        return CMT_FAULT;
    }
    rc = cmt_pv_save_signed(pv, height, round, step, sign_bytes,
                            sign_bytes_len, sig, sig_len);   /* :407 */
    if (rc != CMT_OK) {
        return rc;
    }
    memcpy(proposal->signature, sig, sig_len);               /* :408 */
    proposal->signature_len = sig_len;
    return CMT_OK;                                           /* :409 */
}

/* ══ the PrivValidator interface methods ══════════════════════════════ */

/* cometbft@709fd12b privval/file.go:262-267 — (pv *FilePV) SignVote().
 * The reference only wraps the error text; there is nothing else to do. */
int cmt_pv_sign_vote_iface(cmt_file_pv_t *pv, const uint8_t *chain_id,
                           size_t chain_id_len, cmt_pb_vote_t *vote)
{
    return cmt_pv_sign_vote(pv, chain_id, chain_id_len, vote);  /* :263 */
}

/* cometbft@709fd12b privval/file.go:271-276 —
 * (pv *FilePV) SignProposal() */
int cmt_pv_sign_proposal_iface(cmt_file_pv_t *pv, const uint8_t *chain_id,
                               size_t chain_id_len,
                               cmt_pb_proposal_t *proposal)
{
    return cmt_pv_sign_proposal(pv, chain_id, chain_id_len, proposal);
}                                                            /* :272 */

/* ══ adapters onto the R1 callback shapes ═════════════════════════════ */

/* The `cmt_sign_vote_fn` of cmt_vote.h:332-333, so a FilePV can be handed
 * to cmt_sign_and_check_vote (cmt_vote.h:351) — the reference's own
 * layering, state.go signAddVote → types.SignAndCheckVote →
 * PrivValidator.SignVote → FilePV.signVote. */
int cmt_pv_sign_vote_adapter(void *ctx, const uint8_t *chain_id,
                             size_t chain_id_len, cmt_pb_vote_t *v)
{
    return cmt_pv_sign_vote_iface((cmt_file_pv_t *)ctx, chain_id,
                                  chain_id_len, v);
}

int cmt_pv_sign_proposal_adapter(void *ctx, const uint8_t *chain_id,
                                 size_t chain_id_len, cmt_pb_proposal_t *p)
{
    return cmt_pv_sign_proposal_iface((cmt_file_pv_t *)ctx, chain_id,
                                      chain_id_len, p);
}
